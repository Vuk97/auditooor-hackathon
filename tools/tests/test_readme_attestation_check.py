#!/usr/bin/env python3
# <!-- r36-rebuttal: lane FEAT-README-ATTESTATION-GATE registered in .auditooor/agent_pathspec.json -->
"""Guard tests for tools/readme-attestation-check.py - the forced per-step
README attestation gate (wired into audit-done-guard so a "done" claim requires
a faithful verbatim quote of every EXECUTED runbook step).

Non-vacuous pins (all 4 required by the brief):
  (a) a completed/executed step with NO attestation -> verify FAIL;
  (b) + a faithful VERBATIM attestation -> PASS;
  (c) + a PARAPHRASED attestation (real text reworded) -> FAIL (proves the gate
      checks VERBATIM faithfulness, not mere row presence);
  (d) + a non-empty readme_attestation_rebuttal.md -> warn / PASS (waiver).

Plus a boundedness pin: a workspace with ZERO executed steps -> PASS (no
false-fail on a fresh workspace), and a sanity pin that the reused step-ran
signal is the conformance gate's status=='done'.
"""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parent.parent / "readme-attestation-check.py"


def _load():
    spec = importlib.util.spec_from_file_location("readme_attestation_check", _TOOL)
    m = importlib.util.module_from_spec(spec)
    sys.modules["readme_attestation_check"] = m
    spec.loader.exec_module(m)
    return m


# A minimal manifest with ONE mechanical step: it "executes" iff MARKER.md
# exists (the conformance gate reports status=='done' on a pure artifact_checks
# pass with attestation_required=false). This lets us control execution + the
# canonical text deterministically.
_MANIFEST = {
    "_schema_version": "test.v1",
    "waiver_file": ".auditooor/readme_step_waivers.txt",
    "steps": [
        {
            "step_id": "t-run",
            "label": "executable step",
            "class": "mechanical",
            "required": True,
            "language_filter": None,
            "what_must_be_done": (
                "Run python3 tools/example-step.py --ws <ws> and confirm it "
                "wrote MARKER.md with the canonical summary block."
            ),
            "how_to_verify_done": {
                "artifact_checks": [{"type": "file_exists", "path": "MARKER.md"}],
                "attestation_required": False,
            },
        },
    ],
}


class ReadmeAttestationGateTest(unittest.TestCase):
    def setUp(self):
        self.m = _load()
        self.tmp = Path(tempfile.mkdtemp())
        (self.tmp / ".auditooor").mkdir(parents=True, exist_ok=True)
        self.manifest = self.tmp / "manifest.json"
        self.manifest.write_text(json.dumps(_MANIFEST), encoding="utf-8")
        self.mpath = str(self.manifest)

    # -- helpers ----------------------------------------------------------

    def _make_step_executed(self):
        """Satisfy the step's artifact_checks so conformance reports status=='done'
        (the reused step-ran signal)."""
        (self.tmp / "MARKER.md").write_text("done\n", encoding="utf-8")

    def _canonical(self):
        step = _MANIFEST["steps"][0]
        what = step["what_must_be_done"]
        how = json.dumps(step["how_to_verify_done"], sort_keys=True, ensure_ascii=False)
        return what, how

    def _write_attestation(self, what, how):
        row = {
            "schema": "auditooor.readme_step_attestation.v1",
            "step_id": "t-run",
            "attested_what_must_be_done": what,
            "attested_how_to_verify_done": how,
        }
        p = self.tmp / ".auditooor" / "readme_step_attestations.jsonl"
        with p.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")

    def _verify(self):
        return self.m.verify(self.tmp, manifest_path=self.mpath)

    # -- (sanity) reused step-ran signal ---------------------------------

    def test_executed_signal_is_conformance_done(self):
        """The set of 'executed' steps is exactly conformance status=='done'."""
        # Before the artifact exists, the step is NOT executed -> none to attest.
        executed_before, _ = self.m._executed_step_ids(self.tmp, self.mpath)
        self.assertNotIn("t-run", executed_before)
        self._make_step_executed()
        executed_after, _ = self.m._executed_step_ids(self.tmp, self.mpath)
        self.assertIn("t-run", executed_after,
                      "a step whose artifact_checks pass must be counted executed")

    # -- boundedness: fresh ws (no executed steps) does NOT false-fail ----

    def test_no_executed_steps_passes(self):
        r = self._verify()
        self.assertTrue(r["attestation_pass"],
                        "a workspace with zero executed steps must NOT false-fail")
        self.assertEqual(r["executed_step_ids"], [])

    # -- (a) executed step + NO attestation -> FAIL ----------------------

    def test_a_executed_without_attestation_fails(self):
        self._make_step_executed()
        r = self._verify()
        self.assertFalse(r["attestation_pass"], "executed step with no attestation must FAIL")
        self.assertIn("t-run", r["failing_step_ids"])
        self.assertEqual(r["verdict"], "fail-readme-attestation-missing")

    # -- (b) executed step + faithful verbatim attestation -> PASS -------

    def test_b_faithful_verbatim_attestation_passes(self):
        self._make_step_executed()
        what, how = self._canonical()
        self._write_attestation(what, how)
        r = self._verify()
        self.assertTrue(r["attestation_pass"],
                        f"faithful verbatim attestation must PASS: {r.get('per_step')}")
        self.assertEqual(r["failing_step_ids"], [])
        self.assertEqual(r["verdict"], "pass-readme-attestation")

    # -- (c) executed step + PARAPHRASED attestation -> FAIL -------------

    def test_c_paraphrased_attestation_fails(self):
        """Reword the canonical what_must_be_done (same meaning, different words).
        A presence-only gate would PASS this; the verbatim gate must FAIL it."""
        self._make_step_executed()
        _what, how = self._canonical()
        paraphrase = (
            "Execute the example step script for the workspace and double-check "
            "that it produced the marker file containing the standard summary."
        )
        # Sanity: the paraphrase is genuinely different from the canonical text.
        canon_what = _MANIFEST["steps"][0]["what_must_be_done"]
        self.assertNotEqual(self.m._normalize(paraphrase), self.m._normalize(canon_what))
        self._write_attestation(paraphrase, how)  # how is faithful; what is reworded
        r = self._verify()
        self.assertFalse(r["attestation_pass"],
                         "a paraphrased what_must_be_done must FAIL (not mere presence)")
        self.assertIn("t-run", r["failing_step_ids"])
        per = {s["step_id"]: s for s in r["per_step"]}
        self.assertEqual(per["t-run"]["status"], "paraphrase-mismatch")

    # -- (d) executed step + waiver -> warn / PASS -----------------------

    def test_d_waiver_downgrades_to_warn_pass(self):
        self._make_step_executed()  # executed, and NO attestation -> would fail
        (self.tmp / ".auditooor" / "readme_attestation_rebuttal.md").write_text(
            "Operator accepts the missing verbatim attestation for this "
            "one-off engagement; the runbook was read out-of-band.\n",
            encoding="utf-8")
        r = self._verify()
        self.assertTrue(r["attestation_pass"], "a non-empty waiver must downgrade to warn/PASS")
        self.assertTrue(r["waived"])
        self.assertEqual(r["verdict"], "warn-readme-attestation-waived")

    def test_d_blank_waiver_does_not_pass(self):
        """A whitespace-only rebuttal file is treated as ABSENT (no free pass)."""
        self._make_step_executed()
        (self.tmp / ".auditooor" / "readme_attestation_rebuttal.md").write_text(
            "   \n\t\n", encoding="utf-8")
        r = self._verify()
        self.assertFalse(r["attestation_pass"], "a blank waiver must NOT bypass the gate")
        self.assertFalse(r["waived"])

    # -- attest writer requires faithful AGENT-SUPPLIED text, then passes -

    def test_attest_writer_roundtrips_to_pass(self):
        self._make_step_executed()
        what, how = self._canonical()
        row = self.m.attest(self.tmp, "t-run", what, how, manifest_path=self.mpath)
        self.assertEqual(row["schema"], "auditooor.readme_step_attestation.v1")
        self.assertTrue(row.get("ts_unset"), "writer leaves ts unset for the caller to stamp")
        r = self._verify()
        self.assertTrue(r["attestation_pass"],
                        f"--attest output must satisfy --verify: {r.get('per_step')}")

    # -- (concern 5) writer REFUSES to auto-fill: no text -> AttestationError

    def test_attest_without_text_refuses(self):
        """The headline bypass: --attest with no agent-supplied text must REFUSE
        to write (it must NOT auto-copy the canonical text). Otherwise an agent
        could attest every step without ever reading the runbook."""
        self._make_step_executed()
        with self.assertRaises(self.m.AttestationError):
            self.m.attest(self.tmp, "t-run", None, None, manifest_path=self.mpath)
        # And nothing was written -> verify still FAILs (no silent green).
        r = self._verify()
        self.assertFalse(r["attestation_pass"],
                         "a refused attest must leave the step still failing")

    def test_attest_with_paraphrase_refuses(self):
        """The writer validates the supplied text with the SAME match as verify;
        a paraphrase is refused at write time, not silently written."""
        self._make_step_executed()
        _what, how = self._canonical()
        paraphrase = "Run the example script and verify the marker file landed."
        with self.assertRaises(self.m.AttestationError):
            self.m.attest(self.tmp, "t-run", paraphrase, how, manifest_path=self.mpath)

    def test_attest_with_truncated_quote_refuses(self):
        """A truncated quote (a short prefix of the canonical) is rejected by the
        writer too (the na-in-nc direction was removed from _faithful_match)."""
        self._make_step_executed()
        what, how = self._canonical()
        truncated = what.split(" and ")[0]  # short prefix, genuine substring
        self.assertTrue(truncated and truncated in what and len(truncated) < len(what))
        with self.assertRaises(self.m.AttestationError):
            self.m.attest(self.tmp, "t-run", truncated, how, manifest_path=self.mpath)

    # -- (truncation) a truncated quote written directly must FAIL verify -

    def test_truncated_quote_fails_verify(self):
        """Pin the match-direction fix at the verify layer: a quote that is a
        SHORT substring of the canonical (the old na-in-nc pass) must FAIL."""
        self._make_step_executed()
        _what, how = self._canonical()
        canon_what = _MANIFEST["steps"][0]["what_must_be_done"]
        truncated = canon_what.split(" and ")[0]
        self.assertTrue(truncated in canon_what and len(truncated) < len(canon_what))
        self._write_attestation(truncated, how)  # write the raw truncated row
        r = self._verify()
        self.assertFalse(r["attestation_pass"],
                         "a truncated substring quote must FAIL verify (no na-in-nc pass)")
        per = {s["step_id"]: s for s in r["per_step"]}
        self.assertEqual(per["t-run"]["status"], "paraphrase-mismatch")

    def test_full_canonical_wrapped_in_prose_passes_verify(self):
        """The allowed containment direction (FULL canonical present, wrapped in
        surrounding quotes/prose) must still PASS - boundedness, no over-fail."""
        self._make_step_executed()
        what, how = self._canonical()
        wrapped = f'I read: "{what}" - confirmed.'
        self._write_attestation(wrapped, how)
        r = self._verify()
        self.assertTrue(r["attestation_pass"],
                        f"full canonical wrapped in prose must PASS: {r.get('per_step')}")


class AuditDoneGuardWiringTest(unittest.TestCase):
    """Pin that audit-done-guard imports + calls the attestation gate (wiring)."""

    def test_done_guard_references_attestation_check(self):
        guard = (_TOOL.parent / "audit-done-guard.py").read_text(encoding="utf-8")
        self.assertIn("readme-attestation-check.py", guard,
                      "audit-done-guard must wire in the attestation gate")
        self.assertIn("readme-attestation-missing", guard,
                      "audit-done-guard must emit the fail-readme-attestation fail line")


if __name__ == "__main__":
    unittest.main(verbosity=2)
