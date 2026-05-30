#!/usr/bin/env python3
"""
TSM BGP Route Controller — ExaBGP process API.

This is the process that ExaBGP calls to get route announcements.
ExaBGP reads stdout line-by-line; we write ANNOUNCE/WITHDRAW commands.

Architecture:
  - TSM node announces AI provider CIDR prefixes via BGP
  - When the node is healthy: ANNOUNCE all AI CIDRs → traffic routes here
  - When the node is degraded: WITHDRAW prefixes → BGP reconverges, traffic
    fails over to other TSM nodes (or reaches AI providers directly if no other
    node exists — we fail OPEN, not closed)
  - Health is determined by local checks: dataplane up, Redis reachable,
    disk not full, CPU not pegged

ExaBGP config (exabgp.conf):
  process tsm-controller {
      run /opt/tsm/routing/bgp/exabgp_process.py;
      encoder json;
  }
  neighbor 192.168.1.1 {
      router-id 10.0.0.1;
      local-address 10.0.0.1;
      local-as 65000;
      peer-as 65001;
      family { ipv4 unicast; }
      process tsm-controller;
  }

Usage:
  exabgp exabgp.conf
  # OR standalone test:
  python3 exabgp_process.py --dry-run
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import socket
import subprocess
import sys
import time
import threading
import urllib.request
import urllib.error
from typing import Optional

# ── AI Provider CIDR Prefixes ─────────────────────────────────────────────────
# These are the ranges we announce. Traffic destined for these CIDRs will route
# through TSM nodes when our BGP announcements are preferred.
#
# IMPORTANT: Only announce ranges where TSM nodes are the CORRECT next-hop.
# Never announce ranges you don't control in production BGP sessions.
# These should go through a dedicated TSM ASN with upstream peering agreements.

AI_CIDRS: list[str] = [
    # Cloudflare (OpenAI CDN)
    "104.18.0.0/16",
    "104.19.0.0/16",
    "104.20.0.0/16",
    "104.21.0.0/16",
    "162.158.0.0/15",
    "198.41.128.0/17",
    # AWS (Anthropic, AWS Bedrock, SageMaker)
    "3.208.0.0/12",
    "34.192.0.0/10",   # us-east-1
    "52.0.0.0/11",
    "54.208.0.0/13",
    "13.32.0.0/15",    # CloudFront
    "13.224.0.0/14",   # CloudFront
    # Azure OpenAI
    "20.33.0.0/16",
    "20.36.0.0/14",
    "40.64.0.0/10",
    "52.224.0.0/11",
    # Google Vertex AI / Gemini
    "34.64.0.0/10",
    "34.128.0.0/10",
    "35.186.0.0/17",
    # Mistral AI
    "51.75.64.0/18",
    "51.210.0.0/16",
    # Cohere
    "44.195.0.0/16",
    # Perplexity AI
    "35.187.0.0/17",
]

# ── BGP community tags ────────────────────────────────────────────────────────
# These are attached to our route announcements.
# Peers can use these for traffic engineering.

LOCAL_PREF   = 200         # Higher than default (100) → prefer TSM path
COMMUNITY    = "65000:100" # TSM AI-filtered traffic community
MED          = 10          # Metric for path selection

# ── Config ────────────────────────────────────────────────────────────────────

DATAPLANE_HEALTH_URL = os.environ.get("TSM_DATAPLANE_URL", "http://127.0.0.1:8080/health")
REDIS_HOST           = os.environ.get("TSM_REDIS_HOST", "127.0.0.1")
REDIS_PORT           = int(os.environ.get("TSM_REDIS_PORT", "6379"))
HEALTH_INTERVAL_S    = int(os.environ.get("TSM_BGP_HEALTH_INTERVAL", "10"))
WITHDRAW_ON_DEGRADED = os.environ.get("TSM_BGP_WITHDRAW_DEGRADED", "true").lower() == "true"

# Next-hop to announce. Must be this node's BGP-visible address.
NEXT_HOP = os.environ.get("TSM_BGP_NEXT_HOP", socket.gethostbyname(socket.gethostname()))


# ── Health checks ─────────────────────────────────────────────────────────────

def check_dataplane() -> tuple[bool, str]:
    """Check if the Rust dataplane is healthy."""
    try:
        req = urllib.request.urlopen(DATAPLANE_HEALTH_URL, timeout=3)
        data = json.loads(req.read())
        if data.get("status") in ("healthy", "ok", "degraded"):
            return True, data.get("status", "ok")
        return False, f"bad status: {data.get('status')}"
    except urllib.error.URLError as e:
        return False, f"dataplane unreachable: {e}"
    except Exception as e:
        return False, str(e)


def check_redis() -> tuple[bool, str]:
    """Check if Redis is reachable with a PING command."""
    try:
        s = socket.create_connection((REDIS_HOST, REDIS_PORT), timeout=2)
        s.sendall(b"*1\r\n$4\r\nPING\r\n")
        resp = s.recv(128)
        s.close()
        if b"PONG" in resp:
            return True, "pong"
        return False, f"unexpected: {resp[:40]}"
    except Exception as e:
        return False, str(e)


def check_disk() -> tuple[bool, str]:
    """Warn if disk is >90% full (ClickHouse / audit logs at risk)."""
    try:
        st = os.statvfs("/")
        used_pct = 100 * (1 - st.f_bavail / st.f_blocks)
        if used_pct > 90:
            return False, f"disk {used_pct:.0f}% full"
        return True, f"disk {used_pct:.0f}%"
    except Exception as e:
        return False, str(e)


def overall_health() -> tuple[bool, dict]:
    """Aggregate all health checks. Returns (is_healthy, detail_dict)."""
    dp_ok,    dp_msg    = check_dataplane()
    redis_ok, redis_msg = check_redis()
    disk_ok,  disk_msg  = check_disk()

    details = {
        "dataplane": {"ok": dp_ok,    "msg": dp_msg},
        "redis":     {"ok": redis_ok, "msg": redis_msg},
        "disk":      {"ok": disk_ok,  "msg": disk_msg},
    }

    # Healthy if dataplane is up. Redis being down is degraded but not fatal.
    # Disk being full is fatal (we'd lose audit logs).
    healthy = dp_ok and disk_ok
    return healthy, details


# ── ExaBGP announcement builders ─────────────────────────────────────────────

def announce_route(cidr: str) -> str:
    """Build an ExaBGP ANNOUNCE command for one CIDR."""
    return (
        f"announce route {cidr} "
        f"next-hop {NEXT_HOP} "
        f"local-preference {LOCAL_PREF} "
        f"community {COMMUNITY} "
        f"med {MED}"
    )


def withdraw_route(cidr: str) -> str:
    """Build an ExaBGP WITHDRAW command for one CIDR."""
    return f"withdraw route {cidr} next-hop {NEXT_HOP}"


def send(msg: str) -> None:
    """Write a command to ExaBGP (stdout) and flush immediately."""
    print(msg, flush=True)


# ── Route state machine ───────────────────────────────────────────────────────

class RouteController:
    def __init__(self, dry_run: bool = False):
        self.dry_run        = dry_run
        self.announced: set[str] = set()
        self.healthy        = False
        self._lock          = threading.Lock()
        self._stop          = threading.Event()

    def announce_all(self) -> None:
        for cidr in AI_CIDRS:
            if cidr not in self.announced:
                cmd = announce_route(cidr)
                if self.dry_run:
                    print(f"[DRY] {cmd}", file=sys.stderr)
                else:
                    send(cmd)
                self.announced.add(cidr)
        print(f"[bgp] announced {len(self.announced)} AI CIDR prefixes via BGP",
              file=sys.stderr, flush=True)

    def withdraw_all(self) -> None:
        for cidr in list(self.announced):
            cmd = withdraw_route(cidr)
            if self.dry_run:
                print(f"[DRY] {cmd}", file=sys.stderr)
            else:
                send(cmd)
            self.announced.discard(cidr)
        print("[bgp] withdrew all AI CIDR prefixes — traffic will bypass TSM",
              file=sys.stderr, flush=True)

    def health_loop(self) -> None:
        """Background thread: check health and adjust BGP announcements."""
        while not self._stop.is_set():
            try:
                is_healthy, details = overall_health()

                with self._lock:
                    was_healthy = self.healthy
                    self.healthy = is_healthy

                if is_healthy and not was_healthy:
                    print(f"[bgp] node HEALTHY — announcing routes: {details}",
                          file=sys.stderr, flush=True)
                    self.announce_all()

                elif not is_healthy and was_healthy and WITHDRAW_ON_DEGRADED:
                    print(f"[bgp] node DEGRADED — withdrawing routes: {details}",
                          file=sys.stderr, flush=True)
                    self.withdraw_all()

                elif not is_healthy:
                    print(f"[bgp] still degraded: {details}",
                          file=sys.stderr, flush=True)

            except Exception as e:
                print(f"[bgp] health loop error: {e}", file=sys.stderr, flush=True)

            self._stop.wait(HEALTH_INTERVAL_S)

    def start(self) -> None:
        # Initial health check
        is_healthy, details = overall_health()
        self.healthy = is_healthy

        if is_healthy:
            print(f"[bgp] startup HEALTHY: {details}", file=sys.stderr, flush=True)
            self.announce_all()
        else:
            print(f"[bgp] startup DEGRADED — not announcing routes: {details}",
                  file=sys.stderr, flush=True)

        # Background health monitor
        t = threading.Thread(target=self.health_loop, daemon=True)
        t.start()

        # ExaBGP keeps us alive by reading stdin. Block until EOF.
        try:
            for line in sys.stdin:
                line = line.strip()
                if line:
                    self._handle_exabgp_message(line)
        except (KeyboardInterrupt, EOFError):
            pass

        self._stop.set()
        self.withdraw_all()

    def _handle_exabgp_message(self, line: str) -> None:
        """Handle JSON messages from ExaBGP (peer state changes, etc.)."""
        try:
            msg = json.loads(line)
            msg_type = msg.get("type", "")
            neighbor = msg.get("neighbor", {}).get("address", {}).get("peer", "?")

            if msg_type == "state":
                state = msg.get("neighbor", {}).get("state", "")
                print(f"[bgp] neighbor {neighbor} state → {state}",
                      file=sys.stderr, flush=True)
                if state == "up" and self.healthy:
                    self.announce_all()
                elif state in ("down", "idle"):
                    # Neighbor went down; routes will be withdrawn by BGP FSM
                    self.announced.clear()

            elif msg_type == "notification":
                print(f"[bgp] notification from {neighbor}: {msg}",
                      file=sys.stderr, flush=True)

        except json.JSONDecodeError:
            pass  # Not all ExaBGP output is JSON


# ── Prefix file generation (for BIRD / FRR alternative) ─────────────────────

def generate_bird_config(output_path: str) -> None:
    """Generate a BIRD2 BGP configuration file for the same announcements."""
    lines = [
        "# TSM AI Firewall — BIRD2 BGP configuration",
        "# Generated by exabgp_process.py",
        "",
        "protocol static tsm_ai_routes {",
        "    ipv4;",
    ]
    for cidr in AI_CIDRS:
        lines.append(f"    route {cidr} via {NEXT_HOP};")
    lines.extend([
        "}",
        "",
        "protocol bgp tsm_upstream {",
        f"    local as 65000;",
        f"    neighbor as 65001;",
        "    ipv4 {",
        "        import none;",
        "        export where proto = \"tsm_ai_routes\";",
        "    };",
        "}",
    ])
    with open(output_path, "w") as f:
        f.write("\n".join(lines) + "\n")
    print(f"[bgp] wrote BIRD2 config to {output_path}", file=sys.stderr)


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="TSM ExaBGP route controller")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print commands without sending to ExaBGP")
    parser.add_argument("--generate-bird", metavar="PATH",
                        help="Generate BIRD2 config and exit")
    parser.add_argument("--health-check", action="store_true",
                        help="Run health checks and exit with 0/1")
    args = parser.parse_args()

    if args.generate_bird:
        generate_bird_config(args.generate_bird)
        return

    if args.health_check:
        ok, details = overall_health()
        print(json.dumps({"healthy": ok, "details": details}, indent=2))
        sys.exit(0 if ok else 1)

    controller = RouteController(dry_run=args.dry_run)

    # Graceful shutdown on SIGTERM
    def _shutdown(sig, frame):
        print("\n[bgp] SIGTERM — withdrawing routes and exiting", file=sys.stderr)
        controller.withdraw_all()
        sys.exit(0)

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT,  _shutdown)

    controller.start()


if __name__ == "__main__":
    main()
