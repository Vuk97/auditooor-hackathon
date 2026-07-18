"""Tests for ``tools/lib/hackerman_cve_verification.py``.

Covers:

* ``DiskCache`` load/put/get/prune semantics + TTL expiry + tombstones
* ``verify_cve_id`` / ``verify_ghsa_id`` short-circuit on cache hits
* offline-mode envelope when ``HACKERMAN_VERIFY_OFFLINE=1``
* invalid-id rejection (no network call)
* ``attribution_matches_repo`` mirrors sweep tool semantics
  (strong-token match, weak-token-only, no-overlap, empty repo)
* ``pre_emit_check``:
    - no-claims fast path
    - not-found -> fail
    - mismatched product -> fail
    - weak-match-only -> fail (non-strict) / ValueError (strict)
    - blocked-offline -> fail with blocked: reason
    - verified path emits ``verified:...`` and method label

Tests stub out ``_fetch_nvd`` / ``_fetch_ghsa`` rather than hit the live
APIs so they remain fast and hermetic.
"""

from __future__ import annotations

import importlib.util
import json
import os
import tempfile
import time
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
LIB_PATH = REPO_ROOT / "tools" / "lib" / "hackerman_cve_verification.py"


def _load_lib():
    import sys
    name = "_hackerman_cve_verification_under_test"
    spec = importlib.util.spec_from_file_location(name, str(LIB_PATH))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


# ----- fixture advisory bodies (shape matches sweep tool's evidence shape) ---

NVD_LND_BODY = {
    "id": "CVE-2024-38359",
    "descriptions": [
        {"lang": "en", "value": "LND lightning network node onion bomb DoS."},
    ],
    "configurations": [
        {"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:a:lightningnetwork:lnd:*:*:*:*:*:*:*:*"}]}]}
    ],
    "references": [
        {"url": "https://github.com/lightningnetwork/lnd/security/advisories/GHSA-9gxx-58q6-42p7"}
    ],
}

# Same advisory body but used to test misattribution: target_repo will be ethereum/go-ethereum.
NVD_LND_BODY_FOR_MISMATCH = NVD_LND_BODY

GHSA_LND_BODY = {
    "ghsa_id": "GHSA-9gxx-58q6-42p7",
    "summary": "LND onion bomb resource exhaustion",
    "vulnerabilities": [
        {"package": {"ecosystem": "go", "name": "github.com/lightningnetwork/lnd"}}
    ],
    "references": [{"url": "https://example.com/advisory"}],
}

NVD_WEAK_TOKEN_BODY = {
    "id": "CVE-2026-99999",
    "descriptions": [
        {"lang": "en",
         "value": "btcd before 0.24.0 mishandles chain consensus rules; org-x is affected."}
    ],
    "references": [],
}


class DiskCacheTests(unittest.TestCase):
    def setUp(self) -> None:
        self.lib = _load_lib()
        self.tmp = tempfile.TemporaryDirectory()
        self.cache_path = Path(self.tmp.name) / "cache.jsonl"

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_put_then_get_fresh(self):
        c = self.lib.DiskCache(path=self.cache_path, ttl_days=7)
        c.put("cve", "CVE-2024-38359", NVD_LND_BODY)
        hit, payload = c.get("cve", "CVE-2024-38359")
        self.assertTrue(hit)
        self.assertEqual(payload["id"], "CVE-2024-38359")

    def test_get_normalises_cve_to_upper(self):
        c = self.lib.DiskCache(path=self.cache_path, ttl_days=7)
        c.put("cve", "cve-2024-38359", NVD_LND_BODY)
        hit, payload = c.get("cve", "CVE-2024-38359")
        self.assertTrue(hit)
        self.assertEqual(payload["id"], "CVE-2024-38359")

    def test_get_miss_unknown_id(self):
        c = self.lib.DiskCache(path=self.cache_path, ttl_days=7)
        hit, payload = c.get("cve", "CVE-9999-9999999")
        self.assertFalse(hit)
        self.assertIsNone(payload)

    def test_tombstone_is_cache_hit(self):
        c = self.lib.DiskCache(path=self.cache_path, ttl_days=7)
        c.put("cve", "CVE-1900-0001", None)
        hit, payload = c.get("cve", "CVE-1900-0001")
        self.assertTrue(hit, "tombstone must register as cache hit")
        self.assertIsNone(payload)

    def test_ttl_expiry(self):
        c = self.lib.DiskCache(path=self.cache_path, ttl_days=7)
        # Write a row by hand with an old timestamp
        old = time.time() - (8 * 86400)
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        with self.cache_path.open("w", encoding="utf-8") as fp:
            fp.write(json.dumps({
                "kind": "cve", "id": "CVE-2024-38359",
                "fetched_at": old, "response": NVD_LND_BODY,
            }) + "\n")
        c2 = self.lib.DiskCache(path=self.cache_path, ttl_days=7)
        hit, payload = c2.get("cve", "CVE-2024-38359")
        self.assertFalse(hit, "row older than TTL must be a miss")

    def test_prune_keeps_only_fresh_rows(self):
        c = self.lib.DiskCache(path=self.cache_path, ttl_days=7)
        c.put("cve", "CVE-2024-38359", NVD_LND_BODY)
        c.put("ghsa", "GHSA-9gxx-58q6-42p7", GHSA_LND_BODY)
        # forcibly inject a stale row
        old = time.time() - (60 * 86400)
        with self.cache_path.open("a", encoding="utf-8") as fp:
            fp.write(json.dumps({
                "kind": "cve", "id": "CVE-2000-0001",
                "fetched_at": old, "response": {"id": "CVE-2000-0001"},
            }) + "\n")
        # New cache reloads from disk, prune should NOT keep the stale row.
        c2 = self.lib.DiskCache(path=self.cache_path, ttl_days=7)
        kept = c2.prune()
        self.assertEqual(kept, 2)


class VerifyApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.lib = _load_lib()
        self.tmp = tempfile.TemporaryDirectory()
        self.cache = self.lib.DiskCache(path=Path(self.tmp.name) / "cache.jsonl", ttl_days=7)
        # Save module-level patch points
        self._orig_fetch_nvd = self.lib._fetch_nvd
        self._orig_fetch_ghsa = self.lib._fetch_ghsa
        self._orig_offline = os.environ.get("HACKERMAN_VERIFY_OFFLINE")
        if "HACKERMAN_VERIFY_OFFLINE" in os.environ:
            del os.environ["HACKERMAN_VERIFY_OFFLINE"]

    def tearDown(self) -> None:
        self.lib._fetch_nvd = self._orig_fetch_nvd
        self.lib._fetch_ghsa = self._orig_fetch_ghsa
        if self._orig_offline is None:
            os.environ.pop("HACKERMAN_VERIFY_OFFLINE", None)
        else:
            os.environ["HACKERMAN_VERIFY_OFFLINE"] = self._orig_offline
        self.tmp.cleanup()

    # ----- invalid IDs do not touch the network -----

    def test_invalid_cve_returns_invalid_envelope(self):
        called: list[str] = []
        self.lib._fetch_nvd = lambda cve_id: (called.append(cve_id) or (None, "hit"))
        env = self.lib.verify_cve_id("not-a-cve", cache=self.cache)
        self.assertEqual(env["__verification__"]["status"], "invalid-id")
        self.assertEqual(called, [])

    def test_invalid_ghsa_returns_invalid_envelope(self):
        called: list[str] = []
        self.lib._fetch_ghsa = lambda gid: (called.append(gid) or (None, "hit"))
        env = self.lib.verify_ghsa_id("not-a-ghsa", cache=self.cache)
        self.assertEqual(env["__verification__"]["status"], "invalid-id")
        self.assertEqual(called, [])

    # ----- live -> cache -> hit path -----

    def test_verify_cve_live_then_cache(self):
        calls = []
        def fake(cve_id):
            calls.append(cve_id)
            return NVD_LND_BODY, "hit"
        self.lib._fetch_nvd = fake
        env1 = self.lib.verify_cve_id("CVE-2024-38359", cache=self.cache)
        self.assertEqual(env1["__verification__"]["status"], "hit")
        self.assertEqual(env1["__verification__"]["source"], "nvd-live")
        # Second call must hit cache, not network
        env2 = self.lib.verify_cve_id("CVE-2024-38359", cache=self.cache)
        self.assertEqual(env2["__verification__"]["status"], "cache-hit")
        self.assertEqual(env2["__verification__"]["source"], "nvd-cache")
        self.assertEqual(calls, ["CVE-2024-38359"])

    def test_verify_ghsa_live_then_cache(self):
        calls = []
        def fake(gid):
            calls.append(gid)
            return GHSA_LND_BODY, "hit"
        self.lib._fetch_ghsa = fake
        env1 = self.lib.verify_ghsa_id("GHSA-9gxx-58q6-42p7", cache=self.cache)
        self.assertEqual(env1["__verification__"]["status"], "hit")
        env2 = self.lib.verify_ghsa_id("GHSA-9gxx-58q6-42p7", cache=self.cache)
        self.assertEqual(env2["__verification__"]["status"], "cache-hit")
        self.assertEqual(calls, ["GHSA-9gxx-58q6-42p7"])

    # ----- not-found gets tombstoned -----

    def test_not_found_is_tombstoned(self):
        calls = []
        def fake(cve_id):
            calls.append(cve_id)
            return None, "not-found"
        self.lib._fetch_nvd = fake
        env1 = self.lib.verify_cve_id("CVE-9999-9999999", cache=self.cache)
        self.assertEqual(env1["__verification__"]["status"], "not-found")
        env2 = self.lib.verify_cve_id("CVE-9999-9999999", cache=self.cache)
        self.assertEqual(env2["__verification__"]["status"], "cache-tombstone")
        self.assertEqual(calls, ["CVE-9999-9999999"])

    # ----- offline mode -----

    def test_offline_mode_short_circuits_network(self):
        # Use the real _fetch_nvd; offline-mode is checked INSIDE _fetch_nvd
        # before any urlopen call, so the env-var flip is the real assertion.
        os.environ["HACKERMAN_VERIFY_OFFLINE"] = "1"
        env = self.lib.verify_cve_id("CVE-2024-38359", cache=self.cache)
        self.assertEqual(env["__verification__"]["status"], "blocked-offline")
        # And subsequent calls remain blocked (offline mode does NOT cache).
        env2 = self.lib.verify_cve_id("CVE-2024-38359", cache=self.cache)
        self.assertEqual(env2["__verification__"]["status"], "blocked-offline")


class AttributionMatchTests(unittest.TestCase):
    def setUp(self) -> None:
        self.lib = _load_lib()

    def test_strong_token_match(self):
        ok, reason = self.lib.attribution_matches_repo(NVD_LND_BODY, "lightningnetwork/lnd")
        self.assertTrue(ok, reason)
        self.assertTrue(reason.startswith("match:"))

    def test_no_token_overlap(self):
        ok, reason = self.lib.attribution_matches_repo(NVD_LND_BODY, "vyperlang/vyper")
        self.assertFalse(ok)
        self.assertEqual(reason, "no-token-overlap")

    def test_weak_token_only(self):
        ok, reason = self.lib.attribution_matches_repo(NVD_WEAK_TOKEN_BODY, "coredao-org/core-chain")
        self.assertFalse(ok, reason)
        self.assertTrue(reason.startswith("weak-match-only:"), reason)

    def test_empty_target_repo(self):
        ok, reason = self.lib.attribution_matches_repo(NVD_LND_BODY, "")
        self.assertFalse(ok)
        self.assertEqual(reason, "empty-target-repo")

    def test_empty_advisory(self):
        ok, reason = self.lib.attribution_matches_repo({"__verification__": {"status": "not-found"}}, "lightningnetwork/lnd")
        self.assertFalse(ok)
        self.assertEqual(reason, "no-advisory-body")


class PreEmitCheckTests(unittest.TestCase):
    def setUp(self) -> None:
        self.lib = _load_lib()
        self.tmp = tempfile.TemporaryDirectory()
        self.cache = self.lib.DiskCache(path=Path(self.tmp.name) / "cache.jsonl", ttl_days=7)
        self._orig_fetch_nvd = self.lib._fetch_nvd
        self._orig_fetch_ghsa = self.lib._fetch_ghsa

    def tearDown(self) -> None:
        self.lib._fetch_nvd = self._orig_fetch_nvd
        self.lib._fetch_ghsa = self._orig_fetch_ghsa
        self.tmp.cleanup()

    # ----- no-claim record passes through -----

    def test_no_claims_passes(self):
        record = {
            "record_id": "critical:cantina:40209:abc",
            "target_repo": "some-protocol/contracts",
            "attacker_action_sequence": "reentrancy in withdraw path",
        }
        ok, reason = self.lib.pre_emit_check(record, strict=False, cache=self.cache)
        self.assertTrue(ok)
        self.assertEqual(reason, "no-claims")

    # ----- verified path -----

    def test_verified_cve_then_ghsa(self):
        self.lib._fetch_nvd = lambda c: (NVD_LND_BODY, "hit")
        self.lib._fetch_ghsa = lambda g: (GHSA_LND_BODY, "hit")
        record = {
            "record_id": "findings-go:lnd",
            "target_repo": "lightningnetwork/lnd",
            "source_audit_ref": "findings-go:reference/findings_go.jsonl:lnd-CVE-2024-38359",
            "attacker_action_sequence": "CVE-2024-38359 and GHSA-9gxx-58q6-42p7 share the LND onion bomb.",
        }
        ok, reason = self.lib.pre_emit_check(record, strict=False, cache=self.cache)
        self.assertTrue(ok, reason)
        self.assertTrue(reason.startswith("verified:2"), reason)

    # ----- not-found is a hard fail -----

    def test_not_found_fails(self):
        self.lib._fetch_nvd = lambda c: (None, "not-found")
        record = {
            "record_id": "vyper_cve:fab-1",
            "target_repo": "vyperlang/vyper",
            "attacker_action_sequence": "Fabricated CVE-2022-37937 vyper saturating math."
        }
        ok, reason = self.lib.pre_emit_check(record, strict=False, cache=self.cache)
        self.assertFalse(ok)
        self.assertIn("not-found:CVE-2022-37937", reason)

    def test_not_found_strict_raises(self):
        self.lib._fetch_nvd = lambda c: (None, "not-found")
        record = {
            "record_id": "vyper_cve:fab-2",
            "target_repo": "vyperlang/vyper",
            "attacker_action_sequence": "CVE-2099-99999 fabricated."
        }
        with self.assertRaises(ValueError) as ctx:
            self.lib.pre_emit_check(record, strict=True, cache=self.cache)
        self.assertIn("not-found", str(ctx.exception))

    # ----- mismatched product is a hard fail -----

    def test_mismatched_product_fails(self):
        self.lib._fetch_nvd = lambda c: (NVD_LND_BODY, "hit")
        record = {
            "record_id": "findings-go:wrong-repo",
            "target_repo": "ethereum/go-ethereum",
            "attacker_action_sequence": "Alleging CVE-2024-38359 affects go-ethereum (wrong)."
        }
        ok, reason = self.lib.pre_emit_check(record, strict=False, cache=self.cache)
        self.assertFalse(ok)
        self.assertIn("mismatched:CVE-2024-38359", reason)

    # ----- weak-match-only is a fail -----

    def test_weak_match_only_fails(self):
        self.lib._fetch_nvd = lambda c: (NVD_WEAK_TOKEN_BODY, "hit")
        record = {
            "record_id": "bridge:weak",
            "target_repo": "coredao-org/core-chain",
            "attacker_action_sequence": "CVE-2026-99999 weak-token only overlap."
        }
        ok, reason = self.lib.pre_emit_check(record, strict=False, cache=self.cache)
        self.assertFalse(ok)
        self.assertIn("weak-match:CVE-2026-99999", reason)

    # ----- network blocked is a fail (but distinct reason class) -----

    def test_blocked_offline_fails_with_blocked_reason(self):
        os.environ["HACKERMAN_VERIFY_OFFLINE"] = "1"
        try:
            record = {
                "record_id": "findings-go:offline",
                "target_repo": "lightningnetwork/lnd",
                "attacker_action_sequence": "CVE-2024-38359 LND onion bomb."
            }
            ok, reason = self.lib.pre_emit_check(record, strict=False, cache=self.cache)
            self.assertFalse(ok)
            self.assertIn("blocked:CVE-2024-38359", reason)
            self.assertIn("blocked-offline", reason)
        finally:
            os.environ.pop("HACKERMAN_VERIFY_OFFLINE", None)

    # ----- missing target_repo on a record with a CVE claim is also a fail -----

    def test_missing_target_repo_fails(self):
        self.lib._fetch_nvd = lambda c: (NVD_LND_BODY, "hit")
        record = {
            "record_id": "findings-go:no-repo",
            # target_repo missing
            "attacker_action_sequence": "CVE-2024-38359 cited but no target_repo."
        }
        ok, reason = self.lib.pre_emit_check(record, strict=False, cache=self.cache)
        self.assertFalse(ok)
        self.assertIn("missing-target-repo", reason)

    # ----- nested string fields (eg cross_language_analogues) get scanned -----

    def test_nested_string_claim_is_extracted(self):
        self.lib._fetch_nvd = lambda c: (None, "not-found")
        record = {
            "record_id": "findings-go:nested",
            "target_repo": "lightningnetwork/lnd",
            "cross_language_analogues": [
                {"target_language": "rust", "pattern_translation": "see CVE-2024-38359 analogue in rust LDK."}
            ],
        }
        ok, reason = self.lib.pre_emit_check(record, strict=False, cache=self.cache)
        self.assertFalse(ok, "CVE buried in nested list[dict] must still be extracted")
        self.assertIn("not-found:CVE-2024-38359", reason)


class UnverifiedShapeTagsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.lib = _load_lib()

    def test_canonical_shape_tags_exposed(self):
        tags = set(self.lib.UNVERIFIED_SHAPE_TAGS)
        self.assertIn("UNVERIFIED-NOT-FOUND", tags)
        self.assertIn("UNVERIFIED-MISMATCHED-PRODUCT", tags)
        self.assertIn("UNVERIFIED-WEAK-MATCH", tags)
        self.assertIn("UNVERIFIED-BLOCKED-NO-NETWORK", tags)
        self.assertIn("UNVERIFIED-FABRICATED", tags)


if __name__ == "__main__":
    unittest.main()
