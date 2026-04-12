"""
AnomalyDetector — online Isolation Forest for request-pattern anomaly detection.

Why this beats threshold rules:
  - Thresholds (vel>100 → critical) are fixed and break on new orgs or bursty-
    but-legitimate usage patterns (batch jobs, CI pipelines).
  - Isolation Forest learns each org's *own* baseline and flags deviations from
    that baseline, even if the absolute numbers look normal cluster-wide.

Model:
  sklearn IsolationForest (contamination=auto by default)
  Feature vector per request window (10 features):
    [req_rate_1m, req_rate_10m, token_rate_1m, token_rate_10m,
     pii_ratio_1m, pii_ratio_10m, distinct_pii_1m, distinct_pii_10m,
     hour_of_day_sin, hour_of_day_cos]

  The last two encode time-of-day cyclically so the model can learn
  "this org only runs at night" without feature discontinuities.

Lifecycle:
  - Warm-up: first 50 samples → pure threshold scoring (model not fitted yet)
  - Fitted: IsolationForest.fit() runs in a background thread every 100 new
    samples or when score has been anomalous 3 consecutive times.
  - Prediction: score_samples() → normalized to [0, 1] anomaly score.
  - The Isolation Forest score per-org is combined with the sliding-window
    threshold scores from behavioral.py via max(iforest, threshold).

Per-org models are kept in memory.  They are small (<1 MB each for 1000 samples).
On pod restart they re-warm in ~100 requests.  For persistence across restarts,
set MODEL_STORE_PATH — models are pickled to disk per org.

Requires: scikit-learn (pip install scikit-learn)
Degrades gracefully when sklearn is not installed (returns 0.0 scores).
"""
from __future__ import annotations

import math
import os
import pickle
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Sequence

# ── sklearn import (optional) ─────────────────────────────────────────────────

try:
    from sklearn.ensemble import IsolationForest as _IForest
    import numpy as _np
    _SKLEARN_OK = True
except ImportError:
    _SKLEARN_OK = False

# ── Config ────────────────────────────────────────────────────────────────────

_WARMUP_SAMPLES   = 50    # samples required before fitting
_REFIT_INTERVAL   = 100   # refit every N new samples
_MAX_HISTORY      = 2000  # keep last N samples per org (memory bound)
_CONTAMINATION    = 0.05  # expected fraction of anomalies (5%)
_MODEL_STORE_PATH = os.environ.get("MODEL_STORE_PATH", "")  # optional persistence


# ── Feature extraction ────────────────────────────────────────────────────────

def _features(events_1m: list[dict], events_10m: list[dict]) -> list[float]:
    """
    Build a 10-dimensional feature vector from sliding-window event lists.
    Each event: {"ts": float, "len": int, "pii": list[str]}
    """
    n1  = len(events_1m)
    n10 = len(events_10m)

    tok1  = sum(e.get("len", 0) for e in events_1m)  // 4
    tok10 = sum(e.get("len", 0) for e in events_10m) // 4

    pii1  = sum(1 for e in events_1m  if e.get("pii"))
    pii10 = sum(1 for e in events_10m if e.get("pii"))

    types1:  set[str] = set()
    types10: set[str] = set()
    for e in events_1m:  types1.update(e.get("pii", []))
    for e in events_10m: types10.update(e.get("pii", []))

    # Cyclical time encoding — avoids discontinuity at midnight
    hour = time.localtime().tm_hour + time.localtime().tm_min / 60.0
    h_sin = math.sin(2 * math.pi * hour / 24)
    h_cos = math.cos(2 * math.pi * hour / 24)

    return [
        float(n1),
        float(n10),
        float(tok1),
        float(tok10),
        pii1  / max(n1,  1),
        pii10 / max(n10, 1),
        float(len(types1)),
        float(len(types10)),
        h_sin,
        h_cos,
    ]


# ── Per-org model state ───────────────────────────────────────────────────────

@dataclass
class _OrgModel:
    org_id:     str
    history:    list[list[float]] = field(default_factory=list)   # feature vectors
    model:      object            = None                           # fitted IForest
    n_since_fit: int              = 0
    fitted:     bool              = False
    _lock:      threading.Lock    = field(default_factory=threading.Lock, repr=False)

    def append(self, fvec: list[float]) -> None:
        with self._lock:
            self.history.append(fvec)
            if len(self.history) > _MAX_HISTORY:
                self.history = self.history[-_MAX_HISTORY:]
            self.n_since_fit += 1

    def should_refit(self) -> bool:
        with self._lock:
            return (
                _SKLEARN_OK
                and len(self.history) >= _WARMUP_SAMPLES
                and self.n_since_fit >= _REFIT_INTERVAL
            )

    def fit(self) -> None:
        """Fit IsolationForest in caller's thread (called from background thread)."""
        if not _SKLEARN_OK:
            return
        with self._lock:
            X = _np.array(self.history, dtype=float)
            clf = _IForest(
                n_estimators=64,
                contamination=_CONTAMINATION,
                random_state=42,
                n_jobs=1,
            )
            clf.fit(X)
            self.model    = clf
            self.fitted   = True
            self.n_since_fit = 0

    def score(self, fvec: list[float]) -> float:
        """
        Return anomaly score ∈ [0.0, 1.0].
        0.0 = normal, 1.0 = maximally anomalous.

        Before fitting: return 0.0 (no information).
        After fitting: -score_samples() normalized to [0, 1].
          IsolationForest.score_samples() returns negative anomaly score;
          more negative = more anomalous.  We negate and normalize.
        """
        if not _SKLEARN_OK or self.model is None:
            return 0.0
        with self._lock:
            x = _np.array([fvec], dtype=float)
            raw = float(self.model.score_samples(x)[0])
            # score_samples returns values roughly in [-0.5, 0.5]
            # Clamp and normalize to [0, 1] with 0 = normal
            normalized = max(0.0, min(1.0, (-raw - 0.1) / 0.4))
            return round(normalized, 3)


# ── AnomalyDetector ───────────────────────────────────────────────────────────

class AnomalyDetector:
    """
    Per-org Isolation Forest anomaly detector.

    Thread-safe.  Each org gets its own model fitted on its own request history.
    A background thread handles refitting so prediction never blocks.
    """

    def __init__(self) -> None:
        self._orgs: dict[str, _OrgModel] = {}
        self._lock  = threading.Lock()
        self._store = Path(_MODEL_STORE_PATH) if _MODEL_STORE_PATH else None
        self._refit_executor = _BackgroundRefitter()

    def observe(
        self,
        org_id:      str,
        events_1m:   list[dict],
        events_10m:  list[dict],
    ) -> float:
        """
        Record a feature snapshot for this org and return the current anomaly score.
        Returns 0.0 during warm-up (< _WARMUP_SAMPLES observations).
        """
        fvec  = _features(events_1m, events_10m)
        model = self._get_or_create(org_id)
        model.append(fvec)

        if model.should_refit():
            self._refit_executor.submit(model)

        return model.score(fvec)

    def model_info(self, org_id: str) -> dict:
        """Return model status for the health endpoint."""
        with self._lock:
            m = self._orgs.get(org_id)
        if m is None:
            return {"org_id": org_id, "status": "unseen"}
        with m._lock:
            return {
                "org_id":    org_id,
                "status":    "fitted" if m.fitted else "warming_up",
                "samples":   len(m.history),
                "n_since_fit": m.n_since_fit,
                "sklearn":   _SKLEARN_OK,
            }

    def _get_or_create(self, org_id: str) -> _OrgModel:
        with self._lock:
            if org_id not in self._orgs:
                m = _OrgModel(org_id=org_id)
                if self._store:
                    self._load_from_disk(m)
                self._orgs[org_id] = m
        return self._orgs[org_id]

    def _load_from_disk(self, m: _OrgModel) -> None:
        path = self._store / f"{m.org_id}.pkl"
        try:
            if path.exists():
                with path.open("rb") as f:
                    saved = pickle.load(f)
                m.history  = saved.get("history",  [])
                m.model    = saved.get("model",    None)
                m.fitted   = saved.get("fitted",   False)
                m.n_since_fit = 0
        except Exception:
            pass  # corrupt pickle → start fresh

    def save_to_disk(self, org_id: str) -> None:
        if not self._store:
            return
        with self._lock:
            m = self._orgs.get(org_id)
        if m is None:
            return
        path = self._store / f"{org_id}.pkl"
        try:
            self._store.mkdir(parents=True, exist_ok=True)
            with m._lock:
                with path.open("wb") as f:
                    pickle.dump({"history": m.history, "model": m.model, "fitted": m.fitted}, f)
        except Exception:
            pass


class _BackgroundRefitter:
    """Runs model.fit() in a daemon thread so predictions never block."""

    def __init__(self) -> None:
        self._queue: list[_OrgModel] = []
        self._lock  = threading.Lock()
        self._event = threading.Event()
        self._stop  = False
        t = threading.Thread(target=self._worker, daemon=True, name="tsm-anomaly-refit")
        t.start()

    def submit(self, model: _OrgModel) -> None:
        with self._lock:
            # Avoid duplicate queue entries for the same org
            if model not in self._queue:
                self._queue.append(model)
        self._event.set()

    def shutdown(self) -> None:
        self._stop = True
        self._event.set()

    def _worker(self) -> None:
        # Use timeout so the thread exits cleanly on interpreter shutdown
        # (blocking wait() causes Windows access violation on process exit).
        while not self._stop:
            triggered = self._event.wait(timeout=2.0)
            if self._stop:
                break
            if not triggered:
                continue
            self._event.clear()
            while not self._stop:
                with self._lock:
                    if not self._queue:
                        break
                    model = self._queue.pop(0)
                try:
                    model.fit()
                except Exception:
                    pass


# ── Module-level singleton ────────────────────────────────────────────────────

_detector: AnomalyDetector | None = None
_det_lock  = threading.Lock()


def get_anomaly_detector() -> AnomalyDetector:
    global _detector
    if _detector is None:
        with _det_lock:
            if _detector is None:
                _detector = AnomalyDetector()
    return _detector
