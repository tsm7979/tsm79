"""
Unit tests for detector.tokenizer — cryptographic PII tokenizer.

Coverage targets:
  - Token format and uniqueness
  - Deduplication (same value → same token)
  - Round-trip: tokenize then detokenize restores original
  - Span-based tokenization (start/end offsets)
  - Regex-based tokenization
  - TTL expiry: expired entries are not restored
  - Vault eviction: expired entries are pruned
  - Vault clear
  - HMAC tag (mac_token)
  - Multi-threaded safety
  - Singleton get_tokenizer()
  - Redis backend (patched)
"""

from __future__ import annotations

import re
import sys
import threading
import time
import unittest
from unittest.mock import MagicMock, patch

# ── Import the module under test ──────────────────────────────────────────────
# Tokenizer has no heavy ML dependencies — import directly.
from detector.tokenizer import (
    Tokenizer,
    _TOKEN_RE,
    _TOKEN_PREFIX,
    _DEFAULT_TTL_S,
    get_tokenizer,
)


class TestTokenFormat(unittest.TestCase):
    """Token structure must match tsm_tok_<16 hex chars>."""

    def setUp(self):
        self.tok = Tokenizer()

    def test_token_prefix(self):
        _, vid = self.tok.tokenize("SSN: 123-45-6789", [{"start": 5, "end": 16, "type": "SSN"}])
        # Get the token from the vault
        token = next(iter(self.tok._vault))
        self.assertTrue(token.startswith("tsm_tok_"))

    def test_token_length(self):
        self.tok.tokenize("SSN: 123-45-6789", [{"start": 5, "end": 16, "type": "SSN"}])
        token = next(iter(self.tok._vault))
        # "tsm_tok_" (8) + 16 hex chars = 24 chars total
        self.assertEqual(len(token), 24)

    def test_token_hex_chars_only(self):
        self.tok.tokenize("SSN: 123-45-6789", [{"start": 5, "end": 16, "type": "SSN"}])
        token = next(iter(self.tok._vault))
        hex_part = token[len(_TOKEN_PREFIX):]
        self.assertTrue(all(c in "0123456789abcdef" for c in hex_part))

    def test_token_regex_matches(self):
        self.tok.tokenize("SSN: 123-45-6789", [{"start": 5, "end": 16, "type": "SSN"}])
        token = next(iter(self.tok._vault))
        self.assertIsNotNone(_TOKEN_RE.fullmatch(token))

    def test_token_uniqueness(self):
        """Two different values get two different tokens."""
        tok = Tokenizer()
        tok.tokenize("val1", [{"start": 0, "end": 4, "type": "A"}])
        tok2 = Tokenizer()
        tok2.tokenize("val2", [{"start": 0, "end": 4, "type": "A"}])
        t1 = next(iter(tok._vault))
        t2 = next(iter(tok2._vault))
        self.assertNotEqual(t1, t2)


class TestDeduplication(unittest.TestCase):
    """Same value always maps to same token within a Tokenizer instance."""

    def test_same_value_same_token(self):
        tok = Tokenizer()
        text1 = "SSN: 123-45-6789"
        text2 = "Also: 123-45-6789"
        _, _ = tok.tokenize(text1, [{"start": 5, "end": 16, "type": "SSN"}])
        _, _ = tok.tokenize(text2, [{"start": 6, "end": 17, "type": "SSN"}])
        tokens = list(tok._vault.keys())
        self.assertEqual(len(tokens), 1, "Duplicate value must produce one token")

    def test_different_values_different_tokens(self):
        tok = Tokenizer()
        tok.tokenize("A: 111-22-3333", [{"start": 3, "end": 14, "type": "SSN"}])
        tok.tokenize("B: 444-55-6666", [{"start": 3, "end": 14, "type": "SSN"}])
        # Two distinct values → two tokens
        self.assertEqual(len(tok._vault), 2)


class TestSpanBasedTokenization(unittest.TestCase):
    def setUp(self):
        self.tok = Tokenizer()

    def test_single_span_replaced(self):
        text = "Hello, my SSN is 123-45-6789 please help."
        tokenized, _ = self.tok.tokenize(text, [{"start": 17, "end": 28, "type": "SSN"}])
        self.assertNotIn("123-45-6789", tokenized)
        self.assertIn("tsm_tok_", tokenized)

    def test_surrounding_text_preserved(self):
        text = "Hello, my SSN is 123-45-6789 please help."
        tokenized, _ = self.tok.tokenize(text, [{"start": 17, "end": 28, "type": "SSN"}])
        self.assertIn("Hello, my SSN is", tokenized)
        self.assertIn("please help.", tokenized)

    def test_multiple_spans_all_replaced(self):
        text = "SSN: 111-11-1111 CC: 4111111111111111"
        findings = [
            {"start": 5,  "end": 16, "type": "SSN"},
            {"start": 21, "end": 37, "type": "CREDIT_CARD"},
        ]
        tokenized, _ = self.tok.tokenize(text, findings)
        self.assertNotIn("111-11-1111", tokenized)
        self.assertNotIn("4111111111111111", tokenized)
        self.assertEqual(tokenized.count("tsm_tok_"), 2)

    def test_invalid_span_skipped(self):
        """Out-of-range or inverted spans are silently skipped."""
        text = "Hello"
        tokenized, _ = self.tok.tokenize(text, [{"start": -1, "end": 3, "type": "X"}])
        self.assertEqual(tokenized, text)

    def test_returns_vault_id(self):
        _, vault_id = self.tok.tokenize("secret: 123", [{"start": 8, "end": 11, "type": "NUM"}])
        self.assertIsInstance(vault_id, str)
        self.assertEqual(len(vault_id), 16)  # secrets.token_hex(8)


class TestRegexBasedTokenization(unittest.TestCase):
    def test_regex_tokenize(self):
        tok = Tokenizer()
        ssn_re = re.compile(r"\d{3}-\d{2}-\d{4}")
        tokenized, vault_id = tok.tokenize_regex(
            "My SSN is 123-45-6789.",
            [(ssn_re, "SSN")],
        )
        self.assertNotIn("123-45-6789", tokenized)
        self.assertIn("tsm_tok_", tokenized)
        self.assertIsNotNone(vault_id)

    def test_regex_multiple_matches(self):
        tok = Tokenizer()
        email_re = re.compile(r"[\w.+-]+@[\w-]+\.[a-z]{2,}")
        text = "Contact alice@example.com or bob@test.org"
        tokenized, _ = tok.tokenize_regex(text, [(email_re, "EMAIL")])
        self.assertNotIn("alice@example.com", tokenized)
        self.assertNotIn("bob@test.org", tokenized)


class TestDetokenize(unittest.TestCase):
    def test_round_trip(self):
        tok = Tokenizer()
        original = "My SSN is 123-45-6789 and CC is 4111111111111111"
        findings = [
            {"start": 10, "end": 21, "type": "SSN"},
            {"start": 32, "end": 48, "type": "CREDIT_CARD"},
        ]
        tokenized, vault_id = tok.tokenize(original, findings)
        restored, restorations = tok.detokenize(tokenized, vault_id)
        self.assertEqual(restored, original)
        self.assertEqual(len(restorations), 2)
        self.assertTrue(all(r["restored"] for r in restorations))

    def test_unknown_token_left_in_place(self):
        tok = Tokenizer()
        text = "Here is tsm_tok_0000000000000000 which is unknown."
        restored, restorations = tok.detokenize(text)
        self.assertIn("tsm_tok_0000000000000000", restored)
        self.assertEqual(restorations, [])

    def test_no_tokens_returns_original(self):
        tok = Tokenizer()
        text = "No tokens in this string."
        restored, _ = tok.detokenize(text)
        self.assertEqual(restored, text)

    def test_restoration_metadata(self):
        tok = Tokenizer()
        text = "SSN: 999-99-9999"
        tokenized, vid = tok.tokenize(text, [{"start": 5, "end": 16, "type": "SSN"}])
        _, restorations = tok.detokenize(tokenized, vid)
        self.assertEqual(len(restorations), 1)
        r = restorations[0]
        self.assertIn("token", r)
        self.assertIn("pii_type", r)
        self.assertEqual(r["pii_type"], "SSN")
        self.assertTrue(r["restored"])

    def test_detokenize_without_vault_id(self):
        """Detokenize still works without vault_id (global vault scan)."""
        tok = Tokenizer()
        text = "Value: 123-45-6789"
        tokenized, _ = tok.tokenize(text, [{"start": 7, "end": 18, "type": "SSN"}])
        restored, _ = tok.detokenize(tokenized)   # no vault_id
        self.assertEqual(restored, text)


class TestTTLExpiry(unittest.TestCase):
    def _force_expire_all(self, tok: Tokenizer) -> None:
        """Backdate all vault entries so they are guaranteed expired."""
        with tok._lock:
            for entry in tok._vault.values():
                # Set created_at far in the past so is_expired() returns True
                entry.created_at = time.monotonic() - entry.ttl_s - 1.0

    def test_expired_token_not_restored(self):
        """An expired vault entry must not be restored during detokenize."""
        tok = Tokenizer(ttl_s=1.0)
        text = "SSN: 123-45-6789"
        tokenized, vid = tok.tokenize(text, [{"start": 5, "end": 16, "type": "SSN"}])
        self._force_expire_all(tok)
        restored, restorations = tok.detokenize(tokenized, vid)
        # Expired entry → token is left in place, NOT substituted back
        self.assertIn("tsm_tok_", restored)
        self.assertEqual(restorations, [])

    def test_expired_entries_evicted(self):
        tok = Tokenizer(ttl_s=1.0)
        tok.tokenize("val", [{"start": 0, "end": 3, "type": "X"}])
        self._force_expire_all(tok)
        tok._evict_expired()
        self.assertEqual(len(tok._vault), 0)
        self.assertEqual(len(tok._dedup), 0)


class TestVaultManagement(unittest.TestCase):
    def test_vault_size(self):
        tok = Tokenizer()
        tok.tokenize("a: 111", [{"start": 3, "end": 6, "type": "X"}])
        tok.tokenize("b: 222", [{"start": 3, "end": 6, "type": "X"}])
        self.assertEqual(tok.vault_size(), 2)

    def test_clear_empties_vault_and_dedup(self):
        tok = Tokenizer()
        tok.tokenize("secret", [{"start": 0, "end": 6, "type": "X"}])
        tok.clear()
        self.assertEqual(tok.vault_size(), 0)
        self.assertEqual(len(tok._dedup), 0)


class TestHMAC(unittest.TestCase):
    def test_mac_token_with_key(self):
        tok = Tokenizer(hmac_key=b"test-secret-key")
        mac = tok.mac_token("tsm_tok_abcd12340000ffff", "123-45-6789")
        self.assertIsInstance(mac, str)
        self.assertEqual(len(mac), 16)  # truncated to 16 hex chars

    def test_mac_token_without_key(self):
        tok = Tokenizer()  # no hmac_key
        mac = tok.mac_token("tsm_tok_abcd12340000ffff", "123-45-6789")
        self.assertEqual(mac, "")

    def test_mac_token_deterministic(self):
        key = b"consistent-key"
        tok1 = Tokenizer(hmac_key=key)
        tok2 = Tokenizer(hmac_key=key)
        t = "tsm_tok_1234567890abcdef"
        v = "secret-value"
        self.assertEqual(tok1.mac_token(t, v), tok2.mac_token(t, v))

    def test_mac_token_different_keys_differ(self):
        t = "tsm_tok_1234567890abcdef"
        v = "secret-value"
        self.assertNotEqual(
            Tokenizer(hmac_key=b"key-a").mac_token(t, v),
            Tokenizer(hmac_key=b"key-b").mac_token(t, v),
        )


class TestThreadSafety(unittest.TestCase):
    def test_concurrent_tokenize(self):
        """100 threads tokenizing distinct values — no crashes, correct count."""
        tok = Tokenizer()
        errors: list[Exception] = []

        def worker(i: int):
            try:
                tok.tokenize(f"value-{i}", [{"start": 0, "end": len(f"value-{i}"), "type": "X"}])
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(100)]
        for t in threads: t.start()
        for t in threads: t.join()

        self.assertEqual(errors, [])
        self.assertEqual(tok.vault_size(), 100)

    def test_concurrent_detokenize(self):
        """Detokenize from multiple threads returns correct results."""
        tok = Tokenizer()
        text = "SSN: 111-22-3333"
        tokenized, vid = tok.tokenize(text, [{"start": 5, "end": 16, "type": "SSN"}])
        results: list[str] = []
        lock = threading.Lock()

        def worker():
            restored, _ = tok.detokenize(tokenized, vid)
            with lock:
                results.append(restored)

        threads = [threading.Thread(target=worker) for _ in range(50)]
        for t in threads: t.start()
        for t in threads: t.join()

        self.assertTrue(all(r == text for r in results))


class TestRedisFallback(unittest.TestCase):
    """Verify Redis save/load path with a mocked redis client."""

    def _make_redis_mock(self):
        """Return a mock redis client with in-memory setex/get."""
        store: dict[str, str] = {}
        mock = MagicMock()

        def _setex(key, ttl, value):
            store[key] = value

        def _get(key):
            return store.get(key)

        mock.setex.side_effect = _setex
        mock.get.side_effect = _get
        mock.ping.return_value = True
        return mock

    def test_save_and_load_from_redis(self):
        mock_redis = self._make_redis_mock()
        tok = Tokenizer(redis_url="redis://fake", ttl_s=3600)
        tok._redis = mock_redis

        text = "SSN: 123-45-6789"
        tokenized, vid = tok.tokenize(text, [{"start": 5, "end": 16, "type": "SSN"}])
        token = next(iter(tok._vault))

        # Simulate vault miss: clear in-memory vault
        tok._vault.clear()
        tok._dedup.clear()

        # Detokenize should fall back to Redis
        restored, restorations = tok.detokenize(tokenized, vid)
        self.assertEqual(restored, text)
        self.assertTrue(restorations[0]["restored"])

    def test_redis_save_called(self):
        mock_redis = self._make_redis_mock()
        tok = Tokenizer(redis_url="redis://fake", ttl_s=60)
        tok._redis = mock_redis

        tok.tokenize("email: x@y.com", [{"start": 7, "end": 14, "type": "EMAIL"}])
        mock_redis.setex.assert_called_once()


class TestSingleton(unittest.TestCase):
    def test_get_tokenizer_returns_same_instance(self):
        t1 = get_tokenizer()
        t2 = get_tokenizer()
        self.assertIs(t1, t2)

    def test_get_tokenizer_is_tokenizer(self):
        self.assertIsInstance(get_tokenizer(), Tokenizer)


if __name__ == "__main__":
    unittest.main()
