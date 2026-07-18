#!/usr/bin/env python3
"""Tests for self-dead-end-recall-check.py (block re-litigating our own disproofs)."""
import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path

TOOL = Path(__file__).resolve().parent.parent / "self-dead-end-recall-check.py"
_spec = importlib.util.spec_from_file_location("sde", TOOL)
sde = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sde)


class TestSelfDeadEnd(unittest.TestCase):
    def setUp(self):
        self._orig_kde = sde.KDE
        self._tmp = tempfile.TemporaryDirectory()
        sde.KDE = Path(self._tmp.name) / "known_dead_ends.jsonl"
        self.ws = Path(self._tmp.name)
        (self.ws / "SCOPE.md").write_text("- Audit pin for this workspace: `abc123def4567890`\n")

    def tearDown(self):
        sde.KDE = self._orig_kde
        self._tmp.cleanup()

    def _draft(self, text):
        p = self.ws / "d.md"
        p.write_text(text)
        return p

    def test_promote_then_block(self):
        marker = self.ws / "results.md"
        marker.write_text("<!-- sv-falsifies: direct loss of receiver funds in cooperative exit "
                          "| axis:victim-recovery | recovery:transfer_handler.go:3488 -->\n")
        out = sde.promote(marker, self.ws)
        self.assertEqual(len(out["written"]), 1)
        self.assertEqual(out["target_pin"], "abc123def4567890")
        # re-claiming draft at the same pin is blocked
        d = self._draft("# Direct loss of receiver funds in Spark cooperative exit\n- Severity: CRITICAL\n"
                        "The receiver suffers direct loss of funds.\n")
        v = sde.gate(d, self.ws, strict=True)
        self.assertEqual(v["verdict"], "fail-blocked-self-dead-end")

    def test_promote_refuses_without_pin(self):
        (self.ws / "SCOPE.md").unlink()
        marker = self.ws / "results.md"
        marker.write_text("<!-- sv-falsifies: x claim | axis:victim-recovery | recovery:a.go:1 -->\n")
        out = sde.promote(marker, self.ws)
        self.assertEqual(len(out["written"]), 0)
        self.assertEqual(len(out["skipped"]), 1)

    def test_pass_no_self_dead_ends(self):
        d = self._draft("# Some claim\n- Severity: HIGH\nloss of funds.\n")
        self.assertEqual(sde.gate(d, self.ws, strict=True)["verdict"], "pass-no-self-dead-ends")

    def test_rebuttal_overrides(self):
        sde.KDE.write_text(json.dumps({"dead_end_class": "self-source-verification-falsification",
            "falsified_claim": "direct loss of receiver funds cooperative exit",
            "recovery_path_cited": "x.go:1", "sv_record_id": "SV4", "target_pin": "abc123def4567890"}) + "\n")
        d = self._draft("# Direct loss of receiver funds cooperative exit\n- Severity: CRITICAL\n"
                        "loss of funds for receiver.\nself-dead-end-rebuttal: pin advanced, gap re-introduced by PR #999\n")
        self.assertEqual(sde.gate(d, self.ws, strict=True)["verdict"], "ok-rebuttal")

    def test_extension_distinct_passes(self):
        sde.KDE.write_text(json.dumps({"dead_end_class": "self-source-verification-falsification",
            "falsified_claim": "direct loss of receiver funds cooperative exit",
            "recovery_path_cited": "x.go:1", "sv_record_id": "SV4", "target_pin": "abc123def4567890"}) + "\n")
        d = self._draft("# Direct loss of receiver funds cooperative exit\n- Severity: CRITICAL\n"
                        "loss of funds; the new attack defeats the previously-found recovery path.\n")
        self.assertEqual(sde.gate(d, self.ws, strict=True)["verdict"], "pass-extension-distinct")

    def test_different_pin_not_blocked(self):
        sde.KDE.write_text(json.dumps({"dead_end_class": "self-source-verification-falsification",
            "falsified_claim": "direct loss of receiver funds cooperative exit",
            "recovery_path_cited": "x.go:1", "sv_record_id": "SV4", "target_pin": "999999999999"}) + "\n")
        d = self._draft("# Direct loss of receiver funds cooperative exit\n- Severity: CRITICAL\nloss of funds.\n")
        self.assertEqual(sde.gate(d, self.ws, strict=True)["verdict"], "pass-no-match")

    # --- P46: unpinned-DRAFT advisory (Phase-1 only) ------------------------------------
    # An UNPINNED/DRAFT self-dead-end record blocks a *pinned* workspace via the
    # `not r.get("target_pin")` escape at line ~98 (CASE A in the baseline). The block may be
    # stale post-repin. P46 adds an ADVISORY-ONLY note behind AUDITOOOR_DEAD_END_EXPIRY_STRICT
    # (default OFF); the verdict/rc must stay byte-identical when the flag is unset.
    _UNPINNED_DRAFT_REC = {"dead_end_class": "self-source-verification-falsification",
        "falsified_claim": "direct loss of receiver funds cooperative exit",
        "recovery_path_cited": "x.go:1", "sv_record_id": "SV4"}  # NOTE: no target_pin (DRAFT)

    def _run_env(self, env_value):
        """Invoke gate() with AUDITOOOR_DEAD_END_EXPIRY_STRICT set/cleared, restoring after."""
        orig = os.environ.get("AUDITOOOR_DEAD_END_EXPIRY_STRICT")
        try:
            if env_value is None:
                os.environ.pop("AUDITOOOR_DEAD_END_EXPIRY_STRICT", None)
            else:
                os.environ["AUDITOOOR_DEAD_END_EXPIRY_STRICT"] = env_value
            d = self._draft("# Direct loss of receiver funds cooperative exit\n"
                            "- Severity: CRITICAL\nloss of funds.\n")
            return sde.gate(d, self.ws, strict=True)
        finally:
            if orig is None:
                os.environ.pop("AUDITOOOR_DEAD_END_EXPIRY_STRICT", None)
            else:
                os.environ["AUDITOOOR_DEAD_END_EXPIRY_STRICT"] = orig

    def test_p46_case_a_flag_unset_byte_identical_baseline(self):
        # CASE A, flag UNSET: verdict must remain fail-blocked-self-dead-end (baseline
        # P46.txt) and NO advisory key may appear -> default output byte-identical to pre-P46.
        sde.KDE.write_text(json.dumps(self._UNPINNED_DRAFT_REC) + "\n")
        out = self._run_env(None)
        self.assertEqual(out["verdict"], "fail-blocked-self-dead-end")
        self.assertNotIn("unpinned_draft_advisory", out)

    def test_p46_case_a_flag_set_advisory_added_verdict_unchanged(self):
        # CASE A, flag SET: verdict STILL fail-blocked (Phase-1 never flips the block),
        # but an additive advisory note is present.
        sde.KDE.write_text(json.dumps(self._UNPINNED_DRAFT_REC) + "\n")
        out = self._run_env("1")
        self.assertEqual(out["verdict"], "fail-blocked-self-dead-end")
        self.assertIn("unpinned_draft_advisory", out)
        self.assertIn("stale post-repin", out["unpinned_draft_advisory"])

    def test_p46_case_c_pinned_same_token_no_advisory(self):
        # CASE C control: a PINNED record at the same pin is a genuine re-litigation; the
        # advisory must NOT fire even with the flag set, and the verdict is unchanged.
        sde.KDE.write_text(json.dumps({**self._UNPINNED_DRAFT_REC,
            "target_pin": "abc123def4567890"}) + "\n")
        out = self._run_env("1")
        self.assertEqual(out["verdict"], "fail-blocked-self-dead-end")
        self.assertNotIn("unpinned_draft_advisory", out)


if __name__ == "__main__":
    unittest.main()
