#!/usr/bin/env python3
# <!-- r36-rebuttal: lane L37-AUDIT-DONE-GUARD registered via agent-pathspec-register.py -->
"""P52 - Tamper-evident marker (canary + signature/hash chain) guard tests.

The signature block lives on the completion marker (.audit_logs/audit_completion.json,
schema auditooor.audit_completion.v1). audit-done-guard.py verifies it ADVISORY and
runs a canary. Verification is behind AUDITOOOR_MARKER_TAMPER_STRICT (default OFF):

  * flag UNSET  -> the verify/canary NEVER change done/fail_gates; they only
                   attach a read-only `tamper_advisory` block (regression: verdict
                   == baseline).
  * flag SET    -> a SIGNED-but-FORGED marker (chain digest mismatch) blocks the
                   done claim with fail-marker-forged-verdict. A legit strict:false
                   run is HONEST and does NOT trip. An UNSIGNED marker (older
                   markers / write-order) never blocks.

This file pins:
  A. legit strict:false run -> no trip (strict:false is HONEST, advisory-clean).
  B. forged-but-plausible marker -> FORGED_VERDICT fires (only under strict env).
  C. regression: flag-unset done verdict == baseline (advisory-only, no new gate).
  D. canary: verify actually catches a doctored block (tamper-detection, not
     just verdict parsing).
"""
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

_TOOLS = Path(__file__).resolve().parent.parent


def _load(name, rel):
    spec = importlib.util.spec_from_file_location(name, str(_TOOLS / rel))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


GUARD = _load("adg_tamper", "audit-done-guard.py")
MARKER = _load("acm_tamper", "audit-completion-marker.py")


def _ws() -> Path:
    ws = Path(tempfile.mkdtemp())
    (ws / ".auditooor").mkdir()
    return ws


def _pass_marker(ws: Path, *, strict: bool = True) -> None:
    (ws / ".auditooor" / "audit_complete_last_result.json").write_text(
        json.dumps({"verdict": "pass-audit-complete", "strict": strict}),
        encoding="utf-8",
    )


def _paste_ready(ws: Path) -> None:
    (ws / "submissions" / "paste_ready").mkdir(parents=True, exist_ok=True)
    (ws / "submissions" / "paste_ready" / "finding.md").write_text(
        "a finding", encoding="utf-8"
    )


def _write_signed_completion_marker(ws: Path, *, forge: bool = False,
                                     verdict: str = "pass-audit-complete") -> dict:
    """Write .audit_logs/audit_completion.json carrying a tamper_signature block.
    If forge=True, edit a bound field (verdict) WITHOUT recomputing the chain
    digest so verification must flag it (FORGED_VERDICT)."""
    inv = [{"path": rel, "size": 1, "sha256": "0" * 64}
           for rel in MARKER._SELF_DEF_FILES]
    sig = MARKER.compute_marker_signature(
        verdict=verdict,
        repo_root=_TOOLS.parent,
        toolchain_hash="unknown",  # tolerate; guard's current enforcer differs
        toolchain_inventory=inv,
        workspace_state_hash="w",
        nonce="fixed-nonce",
    )
    if forge:
        sig = dict(sig)
        sig["verdict"] = "pass-audit-complete-FORGED"  # stale digest now
    payload = {
        "schema": MARKER.SCHEMA,
        "completed_at": 0.0,
        "commit_sha": "abc1234",
        "tamper_signature": sig,
    }
    d = ws / ".audit_logs"
    d.mkdir(parents=True, exist_ok=True)
    (d / "audit_completion.json").write_text(json.dumps(payload), encoding="utf-8")
    return sig


class TestTamperAdvisoryReadsMarker(unittest.TestCase):
    """The advisory verify reads the completion marker's signature block and
    records verify_ok / signed / canary_ok WITHOUT ever blocking (advisory)."""

    def test_advisory_flags_forged_marker(self):
        ws = _ws()
        _write_signed_completion_marker(ws, forge=True)
        tv = GUARD._tamper_advisory(ws)
        self.assertTrue(tv["signed"])
        self.assertFalse(tv["verify_ok"])  # forgery caught
        self.assertIn("chain-digest-mismatch", tv["reasons"])
        self.assertTrue(tv["canary_ok"])  # canary healthy regardless

    def test_advisory_clean_on_legit_marker(self):
        ws = _ws()
        _write_signed_completion_marker(ws, forge=False)
        tv = GUARD._tamper_advisory(ws)
        self.assertTrue(tv["signed"])
        self.assertTrue(tv["verify_ok"])
        self.assertTrue(tv["canary_ok"])

    def test_advisory_unsigned_marker_not_flagged(self):
        ws = _ws()
        d = ws / ".audit_logs"
        d.mkdir(parents=True, exist_ok=True)
        (d / "audit_completion.json").write_text(
            json.dumps({"schema": MARKER.SCHEMA, "completed_at": 0.0}),
            encoding="utf-8",
        )
        tv = GUARD._tamper_advisory(ws)
        self.assertFalse(tv["signed"])  # unsigned = not a tamper
        self.assertIn("marker-unsigned", tv["reasons"])


class TestStrictDecision(unittest.TestCase):
    """The advisory-vs-strict split (single source of truth). Case A/B."""

    def _tv(self, **kw):
        base = {"signed": True, "verify_ok": True, "canary_ok": True,
                "reasons": []}
        base.update(kw)
        return base

    def test_default_off_does_not_block(self):
        # default-OFF (graduation to default-ON was REVERTED 2026-07-03: the enforcer
        # hash over the whole toolchain tree is not stable across a make run, so a
        # legit regenerated marker false-positived). Env UNSET -> no block.
        tv = self._tv(verify_ok=False, reasons=["chain-digest-mismatch"])
        block, gates, _ = GUARD._tamper_strict_verdict(tv, env={})
        self.assertFalse(block)
        self.assertEqual(gates, [])

    def test_opt_in_blocks_forged_marker(self):
        # explicit opt-IN (MARKER_TAMPER_STRICT=1) still hard-blocks a forged signed marker.
        tv = self._tv(verify_ok=False, reasons=["chain-digest-mismatch"])
        block, gates, _ = GUARD._tamper_strict_verdict(tv, env={"AUDITOOOR_MARKER_TAMPER_STRICT": "1"})
        self.assertTrue(block)
        self.assertIn("fail-marker-forged-verdict", gates)

    def test_flag_set_forged_signed_marker_blocks(self):
        # Case B: signed + verify_ok False -> FORGED_VERDICT under strict env.
        tv = self._tv(verify_ok=False, reasons=["chain-digest-mismatch"])
        block, gates, reason = GUARD._tamper_strict_verdict(
            tv, env={GUARD.MARKER_TAMPER_STRICT_ENV: "1"})
        self.assertTrue(block)
        self.assertIn("fail-marker-forged-verdict", gates)
        self.assertIn("FORGED_VERDICT", reason)

    def test_flag_set_unsigned_marker_does_not_block(self):
        # An unsigned marker is NOT a forgery even under strict env.
        tv = self._tv(signed=False, verify_ok=None, reasons=["marker-unsigned"])
        block, gates, _ = GUARD._tamper_strict_verdict(
            tv, env={GUARD.MARKER_TAMPER_STRICT_ENV: "1"})
        self.assertFalse(block)
        self.assertEqual(gates, [])

    def test_flag_set_legit_marker_does_not_block(self):
        tv = self._tv()
        block, gates, _ = GUARD._tamper_strict_verdict(
            tv, env={GUARD.MARKER_TAMPER_STRICT_ENV: "1"})
        self.assertFalse(block)

    def test_flag_set_failed_canary_blocks(self):
        tv = self._tv(canary_ok=False, reasons=["canary-did-not-catch-forgery"])
        block, gates, reason = GUARD._tamper_strict_verdict(
            tv, env={GUARD.MARKER_TAMPER_STRICT_ENV: "1"})
        self.assertTrue(block)
        self.assertIn("fail-marker-canary", gates)


class TestStrictFalseIsHonest(unittest.TestCase):
    """Case A: a legit strict:false audit-complete run is HONEST - the guard
    short-circuits at 'NOT under STRICT=1' BEFORE the tamper block, so it is
    never a tamper verdict. Uses the authoritative-marker path directly (no
    intermediate gates involved: the strict:false check fires early)."""

    def test_strict_false_marker_short_circuits_as_honest(self):
        ws = _ws()
        _pass_marker(ws, strict=False)
        _paste_ready(ws)
        os.environ[GUARD.MARKER_TAMPER_STRICT_ENV] = "1"
        try:
            r = GUARD.evaluate(ws, ttl_hours=6)
        finally:
            os.environ.pop(GUARD.MARKER_TAMPER_STRICT_ENV, None)
        self.assertFalse(r["done"])
        self.assertIn("NOT under STRICT=1", r["reason"])
        self.assertNotIn("forged", str(r.get("fail_gates", [])).lower())
        self.assertNotIn("tamper", str(r.get("fail_gates", [])).lower())


class TestFlagUnsetRegressionBaseline(unittest.TestCase):
    """Case C (integration): flag-unset verdict/fail_gates on a REAL sample ws
    == the pre-build baseline captured in /tmp/qna-build-baselines/P52.txt.
    Proves the advisory build added NO new blocking gate to the guard contract."""

    _BASELINE = Path("/tmp/qna-build-baselines/P52.txt")
    _SAMPLES = {
        "/Users/wolf/audits/near-intents": {
            "done": False,
            "fail_gates": ["fail-hollow-not-genuinely-audited",
                           "fail-cross-function-uncovered"],
        },
        "/Users/wolf/audits/strata": {
            "done": False,
            "fail_gates": ["fail-completeness-matrix-uncovered-cells"],
        },
    }

    def test_flag_unset_matches_baseline(self):
        os.environ.pop(GUARD.MARKER_TAMPER_STRICT_ENV, None)
        any_ran = False
        for ws_str, expected in self._SAMPLES.items():
            ws = Path(ws_str)
            if not ws.is_dir():
                continue  # sample ws not present on this host; skip
            any_ran = True
            r = GUARD.evaluate(ws, ttl_hours=6)
            self.assertEqual(r["done"], expected["done"], ws_str)
            self.assertEqual(sorted(r.get("fail_gates", [])),
                             sorted(expected["fail_gates"]), ws_str)
            # A failing ws never reaches the tamper block -> no advisory attached.
            self.assertNotIn("tamper_advisory", r)
        if not any_ran:
            self.skipTest("no P52 sample workspaces present on this host")


class TestCanaryCatchesForgery(unittest.TestCase):
    """Case D: the canary exercises tamper-DETECTION, not just verdict parse."""

    def test_canary_ok_true_on_healthy_verifier(self):
        ws = _ws()
        adv = GUARD._tamper_advisory(ws)
        self.assertTrue(adv["canary_ok"],
                        "canary must confirm the verifier rejects a doctored block")


class TestAdvisoryMarkerWarningSurfacing(unittest.TestCase):
    """Enforcement-gap P52 (2026-07-03): in DEFAULT (flag-unset) mode a genuinely
    FORGED signed marker used to pass SILENTLY - the tamper_advisory dict was
    attached but nobody read it. _marker_tamper_warning surfaces a LOUD warning
    for a real tamper without hard-blocking (the block stays opt-in via the env),
    so the #1 sin is never silent yet a parked audit is never retroactively red-ed."""

    def test_forged_signed_marker_warns(self):
        tv = {"signed": True, "verify_ok": False, "canary_ok": True,
              "reasons": ["chain-digest-mismatch"]}
        w = GUARD._marker_tamper_warning(tv)
        self.assertIsNotNone(w)
        self.assertTrue(any("FORGED_VERDICT" in r for r in w["reasons"]))

    def test_broken_canary_warns(self):
        tv = {"signed": False, "verify_ok": None, "canary_ok": False,
              "reasons": ["canary-did-not-catch-forgery"]}
        w = GUARD._marker_tamper_warning(tv)
        self.assertIsNotNone(w)
        self.assertTrue(any("canary" in r for r in w["reasons"]))

    def test_unsigned_marker_never_warns(self):
        # a legacy / write-order unsigned marker is NOT a tamper -> no warning
        tv = {"signed": False, "verify_ok": None, "canary_ok": True,
              "reasons": ["marker-unsigned"]}
        self.assertIsNone(GUARD._marker_tamper_warning(tv))

    def test_legit_signed_marker_never_warns(self):
        tv = {"signed": True, "verify_ok": True, "canary_ok": True, "reasons": []}
        self.assertIsNone(GUARD._marker_tamper_warning(tv))

    def test_lib_unavailable_never_warns(self):
        # _tamper_advisory returns canary_ok=None (not False) on lib import failure
        tv = {"signed": None, "verify_ok": None, "canary_ok": None,
              "reasons": ["completion-marker-lib-unavailable"]}
        self.assertIsNone(GUARD._marker_tamper_warning(tv))

    def test_warning_is_advisory_by_default(self):
        # by default (env unset) the surfacing must NOT block, yet still emit the loud
        # advisory warning (the #1-sin surfacing survives even in default advisory mode).
        tv = {"signed": True, "verify_ok": False, "canary_ok": True, "reasons": ["x"]}
        block, gates, _ = GUARD._tamper_strict_verdict(tv, env={})
        self.assertFalse(block)
        self.assertEqual(gates, [])
        self.assertIsNotNone(GUARD._marker_tamper_warning(tv))  # but still loud


def _load_completeness_check():
    return _load("acc_resign", "audit-completeness-check.py")


class TestResultWriteResignsMarker(unittest.TestCase):
    """FIX-AUDIT-COMPLETE-MARKER: the result-writer (audit-completeness-check.py)
    re-signs the completion marker IN THE SAME STEP as the authoritative
    audit_complete_last_result.json write, so the signed marker never goes stale
    and the guard's advisory marker-tamper check stops emitting a false
    FORGED_VERDICT. Genuine forgery (a signed block with a bound field edited so
    the chain digest no longer recomputes) MUST still flag - the fix is a
    re-sign of a legit marker, not a weakening of tamper detection."""

    def test_resign_via_fixed_path_no_forged_verdict(self):
        # Simulate a genuine audit-complete result write: write the authoritative
        # verdict, then re-sign the completion marker via the SAME helper the
        # fixed result-writer uses (audit-completeness-check._load_completion_marker_lib).
        ws = _ws()
        _pass_marker(ws)  # writes .auditooor/audit_complete_last_result.json (verdict=pass)
        acc = _load_completeness_check()
        acm = acc._load_completion_marker_lib()
        self.assertIsNotNone(acm)  # the fixed writer can load the marker lib
        acm.write_marker(ws, repo_root=_TOOLS.parent)
        tv = GUARD._tamper_advisory(ws)
        self.assertTrue(tv["signed"])
        self.assertTrue(tv["verify_ok"])  # re-signed marker verifies
        self.assertEqual(tv["verdict"], "pass-audit-complete")
        w = GUARD._marker_tamper_warning(tv)
        self.assertIsNone(w)  # NO false FORGED_VERDICT after the in-step re-sign

    def test_hand_forged_marker_still_flags_forged_verdict(self):
        # A hand-edited / forged SIGNED marker (bound field changed, chain digest
        # stale) MUST still flag FORGED_VERDICT - tamper detection is NOT weakened.
        ws = _ws()
        _write_signed_completion_marker(ws, forge=True)
        tv = GUARD._tamper_advisory(ws)
        self.assertTrue(tv["signed"])
        self.assertFalse(tv["verify_ok"])
        w = GUARD._marker_tamper_warning(tv)
        self.assertIsNotNone(w)
        self.assertTrue(any("FORGED_VERDICT" in r for r in w["reasons"]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
