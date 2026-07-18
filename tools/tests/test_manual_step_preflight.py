# <!-- r36-rebuttal: lane manual-step-preflight registered via agent-pathspec-register.py -->
"""manual-step-preflight: pre-flight read-ack + grounded-attestation enforcement
for the README runbook's MANUAL steps (2026-07-02).

Guarantees:
 - render surfaces the FULL step text and writes a read-ack marker bound to the
   exact step-text hash.
 - check PASSES a grounded attestation (read_ack==sha + preflight marker + an
   evidence_ref that exists).
 - a LEGACY attestation (no read_ack) is advisory (warn, rc 0) but FAILS strict.
 - a DRIFTED read_ack (step text changed) FAILS strict (re-forces a read).
 - an UNGROUNDED evidence_ref (file absent) FAILS strict.
 - dispatch-setup lists the parallelizable manual steps.
"""
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parent.parent / "manual-step-preflight.py"


def _load():
    spec = importlib.util.spec_from_file_location("manual_step_preflight", _TOOL)
    m = importlib.util.module_from_spec(spec)
    sys.modules["manual_step_preflight"] = m
    spec.loader.exec_module(m)
    return m


MOD = _load()

_MANIFEST = {"steps": [
    {"step_id": "step-0b", "label": "Author SCOPE.md", "class": "manual-judgment",
     "what_must_be_done": "Author SCOPE.md with exact in-scope repos.",
     "how_to_verify_done": {"attestation_required": True,
                            "artifact_checks": [{"type": "file_nonempty", "path": "SCOPE.md"}]},
     "drift_note": ""},
    {"step_id": "step-0d", "label": "Clone src", "class": "manual",
     "what_must_be_done": "Clone each repo at its pin.",
     "how_to_verify_done": {"attestation_required": True, "artifact_checks": []},
     "drift_note": ""},
    {"step_id": "step-1", "label": "make audit", "class": "mechanical",
     "what_must_be_done": "run make audit",
     "how_to_verify_done": {"attestation_required": False, "artifact_checks": []},
     "drift_note": ""},
]}


# These tests exercise the GROUNDING lane (read-ack / evidence). The schema-strict
# lane now defaults ON under AUDITOOOR_L37_STRICT, so clear it (plus the named
# schema envs) to isolate the grounding-verdict assertions from a strict runner env.
_GROUNDING_ISOLATION_ENVS = (
    "AUDITOOOR_MANUAL_STEP_STRICT", "AUDITOOOR_L37_STRICT",
    "AUDITOOOR_ATTEST_SCHEMA_STRICT", "AUDITOOOR_ATTEST_SELFHEAL",
)


class ManualStepPreflightTest(unittest.TestCase):
    def setUp(self):
        self._saved_env = {e: os.environ.pop(e, None) for e in _GROUNDING_ISOLATION_ENVS}
        self.ws = Path(tempfile.mkdtemp())
        (self.ws / ".auditooor" / "attestations").mkdir(parents=True)

    def tearDown(self):
        for e, v in getattr(self, "_saved_env", {}).items():
            if v is not None:
                os.environ[e] = v
            else:
                os.environ.pop(e, None)

    def _sha(self, sid):
        return MOD._step_text_sha(MOD._canonical_step(_MANIFEST, sid))

    def _write_att(self, sid, att):
        (self.ws / ".auditooor" / "attestations" / f"{sid}.json").write_text(
            json.dumps(att), encoding="utf-8")

    def test_render_surfaces_full_text_and_writes_marker(self):
        r = MOD.render(self.ws, "step-0b", _MANIFEST)
        self.assertTrue(r["ok"])
        self.assertIn("in-scope repos", r["what_must_be_done"])
        marker = json.loads((self.ws / ".auditooor" / "attestations" / ".preflight"
                             / "step-0b.json").read_text())
        self.assertEqual(marker["step_text_sha"], self._sha("step-0b"))

    def test_grounded_attestation_passes(self):
        MOD.render(self.ws, "step-0b", _MANIFEST)  # writes the marker
        (self.ws / "SCOPE.md").write_text("real scope", encoding="utf-8")
        # a genuinely grounded attestation also carries the base schema fields
        # (completed_at / attested_by / summary) - the schema-validate gate now
        # requires them, so the fixture reflects a real, complete attestation.
        self._write_att("step-0b", {"read_ack": self._sha("step-0b"),
                                    "evidence_refs": ["SCOPE.md"], "summary": "did it",
                                    "completed_at": "2026-01-01T00:00:00Z",
                                    "attested_by": "operator"})
        # step-0d has no attestation -> not our concern (presence gate handles it)
        r = MOD.check(self.ws, _MANIFEST)
        self.assertEqual(r["verdict"], "pass-manual-steps-grounded")

    def test_legacy_attestation_advisory_but_strict_fails(self):
        self._write_att("step-0b", {"summary": "old-style", "completed_at": "2026-01-01"})
        self.assertEqual(MOD.check(self.ws, _MANIFEST)["verdict"], "warn-manual-step-ungrounded")
        os.environ["AUDITOOOR_MANUAL_STEP_STRICT"] = "1"
        try:
            self.assertEqual(MOD.check(self.ws, _MANIFEST)["verdict"], "fail-manual-step-ungrounded")
        finally:
            os.environ.pop("AUDITOOOR_MANUAL_STEP_STRICT", None)

    def test_drifted_read_ack_fails_strict(self):
        MOD.render(self.ws, "step-0b", _MANIFEST)
        (self.ws / "SCOPE.md").write_text("real", encoding="utf-8")
        self._write_att("step-0b", {"read_ack": "deadbeefdeadbeef",  # stale hash
                                    "evidence_refs": ["SCOPE.md"],
                                    "completed_at": "2026-01-01T00:00:00Z",
                                    "attested_by": "operator", "summary": "s"})
        os.environ["AUDITOOOR_MANUAL_STEP_STRICT"] = "1"
        try:
            r = MOD.check(self.ws, _MANIFEST)
            self.assertEqual(r["verdict"], "fail-manual-step-ungrounded")
            self.assertTrue(any("drift" in p or "re-read" in p
                                for f in r["findings"] for p in f["problems"]))
        finally:
            os.environ.pop("AUDITOOOR_MANUAL_STEP_STRICT", None)

    def test_ungrounded_evidence_fails_strict(self):
        MOD.render(self.ws, "step-0b", _MANIFEST)
        self._write_att("step-0b", {"read_ack": self._sha("step-0b"),
                                    "evidence_refs": ["NOPE_missing.md"],
                                    "completed_at": "2026-01-01T00:00:00Z",
                                    "attested_by": "operator", "summary": "s"})
        os.environ["AUDITOOOR_MANUAL_STEP_STRICT"] = "1"
        try:
            self.assertEqual(MOD.check(self.ws, _MANIFEST)["verdict"], "fail-manual-step-ungrounded")
        finally:
            os.environ.pop("AUDITOOOR_MANUAL_STEP_STRICT", None)

    def test_no_attestation_not_flagged(self):
        # absence is the existing presence-gate's job; preflight-check stays silent.
        self.assertEqual(MOD.check(self.ws, _MANIFEST)["verdict"], "pass-manual-steps-grounded")

    def test_mechanical_step_never_required(self):
        self.assertNotIn("step-1", [s["step_id"] for s in MOD._manual_attest_steps(_MANIFEST)])

    def test_dispatch_setup_lists_parallelizable(self):
        r = MOD.dispatch_setup(self.ws, _MANIFEST)
        ids = [p["step_id"] for p in r["parallelizable_steps"]]
        self.assertIn("step-0d", ids)          # in _PARALLEL_SETUP
        self.assertNotIn("step-0b", ids)       # not parallelizable


if __name__ == "__main__":
    unittest.main(verbosity=2)
