# <!-- r36-rebuttal: lane enf-laneD-g2 registered via agent-pathspec-register.py -->
"""manual-step-preflight G2 (id26): schema-validate BEFORE preflight-grounding.

Evidence: NUVA .auditooor/attestations/step-1b.json was regenerated WITHOUT the
schema-required `attested_by` field, so a required attestation field silently
went missing and the preflight `check()` accepted it as a mere "legacy"
grounding note. This gate adds a schema-validate step that runs BEFORE the
read-ack/evidence grounding check so a missing required field is CAUGHT.

Guarantees:
 - an attestation missing `attested_by` -> FLAGGED (schema_findings non-empty),
   verdict warn-attestation-schema-invalid by default (advisory-first).
 - a complete attestation -> passes the schema gate.
 - default (no env) is advisory WARN; AUDITOOOR_ATTEST_SCHEMA_STRICT=1 hard-fails
   (rc 1 path); the existing AUDITOOOR_MANUAL_STEP_STRICT also hard-fails schema.
 - AUDITOOOR_ATTEST_SELFHEAL re-stamps a missing attested_by from run context so
   the file is repaired in place (never silently accepted, never overwrites a
   real value).
 - the required-fields set is sourced from the manifest attestation_format
   (single source of truth), not a rebuilt constant.
 - the shared helper attestation_schema_missing_fields lives in
   readme-conformance-check and is reused (no schema duplication).
"""
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

_TOOLS = Path(__file__).resolve().parent.parent
_PREFLIGHT = _TOOLS / "manual-step-preflight.py"
_CONFORMANCE = _TOOLS / "readme-conformance-check.py"


def _load(path, modname):
    spec = importlib.util.spec_from_file_location(modname, path)
    m = importlib.util.module_from_spec(spec)
    sys.modules[modname] = m
    spec.loader.exec_module(m)
    return m


MOD = _load(_PREFLIGHT, "manual_step_preflight_g2")
CONF = _load(_CONFORMANCE, "readme_conformance_check_g2")

# Mirrors the shape of the real step-1b manual attest-required step: the manifest
# declares attestation_format.required_fields_always (the base schema) + the
# step's own attestation_fields.
_MANIFEST = {
    "attestation_format": {
        "required_fields_always": ["completed_at", "attested_by", "summary"],
        "attested_by_values": ["operator", "claude-operator-verified"],
    },
    "steps": [
        {"step_id": "step-1b", "label": "Fork-prune", "class": "manual",
         "what_must_be_done": "Author SCOPE.md ## Fork Bases; prune forks.",
         "how_to_verify_done": {"attestation_required": True,
                                "attestation_path": ".auditooor/attestations/step-1b.json",
                                "attestation_fields": ["completed_at", "forks_pruned",
                                                       "forks_kept_conservative"],
                                "artifact_checks": []},
         "drift_note": ""},
        {"step_id": "step-1", "label": "make audit", "class": "mechanical",
         "what_must_be_done": "run make audit",
         "how_to_verify_done": {"attestation_required": False, "artifact_checks": []},
         "drift_note": ""},
    ],
}

_ENVS = ("AUDITOOOR_MANUAL_STEP_STRICT", "AUDITOOOR_ATTEST_SCHEMA_STRICT",
         "AUDITOOOR_ATTEST_SELFHEAL", "AUDITOOOR_L37_STRICT")


class SchemaValidateBeforePreflightTest(unittest.TestCase):
    def setUp(self):
        for e in _ENVS:
            os.environ.pop(e, None)
        self.ws = Path(tempfile.mkdtemp())
        (self.ws / ".auditooor" / "attestations").mkdir(parents=True)

    def tearDown(self):
        for e in _ENVS:
            os.environ.pop(e, None)

    def _write_att(self, sid, att):
        (self.ws / ".auditooor" / "attestations" / f"{sid}.json").write_text(
            json.dumps(att), encoding="utf-8")

    def _read_att(self, sid):
        return json.loads((self.ws / ".auditooor" / "attestations" / f"{sid}.json").read_text())

    def _ground(self, sid, extra):
        """Write a grounding-clean attestation (read_ack + evidence) merged with
        `extra`, so the top-line verdict isolates the SCHEMA branch (not the
        legacy/ungrounded branch)."""
        (self.ws / "SCOPE.md").write_text("scope", encoding="utf-8")
        MOD.render(self.ws, sid, _MANIFEST)
        base = {"read_ack": MOD._step_text_sha(MOD._canonical_step(_MANIFEST, sid)),
                "evidence_refs": ["SCOPE.md"]}
        base.update(extra)
        self._write_att(sid, base)

    # --- the NUVA drop: missing attested_by is NEVER silently accepted -------

    def test_missing_attested_by_is_flagged_not_silently_accepted(self):
        # exactly the NUVA step-1b.json shape: completed_at + step fields, NO
        # attested_by/summary. It is ALSO legacy (no read_ack/evidence), so the
        # historical grounding verdict is preserved (never-retro-red) BUT the
        # schema miss MUST surface in schema_findings (never-false-pass).
        self._write_att("step-1b", {"completed_at": "2026-07-03T12:07:27Z",
                                    "forks_pruned": [], "forks_kept_conservative": [],
                                    "note": "no upstream fork"})
        r = MOD.check(self.ws, _MANIFEST)
        # never-false-pass: schema issue is always exposed
        self.assertTrue(r["schema_advisory"])
        sf = {f["step_id"]: f["missing_fields"] for f in r["schema_findings"]}
        self.assertIn("step-1b", sf)
        self.assertIn("attested_by", sf["step-1b"])
        self.assertIn("summary", sf["step-1b"])
        # never silently a clean pass
        self.assertNotEqual(r["verdict"], "pass-manual-steps-grounded")

    def test_schema_only_broken_grounding_clean_yields_schema_warn(self):
        # grounding-clean but attested_by dropped -> the schema branch owns the
        # top-line verdict (advisory warn).
        self._ground("step-1b", {"completed_at": "2026-07-03T12:07:27Z",
                                  "summary": "pruned no forks",
                                  "forks_pruned": [], "forks_kept_conservative": []})
        r = MOD.check(self.ws, _MANIFEST)
        self.assertEqual(r["verdict"], "warn-attestation-schema-invalid")
        self.assertIn("attested_by", r["schema_findings"][0]["missing_fields"])

    # --- a complete attestation passes the schema gate ----------------------

    def test_complete_attestation_passes_schema(self):
        self._write_att("step-1b", {
            "completed_at": "2026-07-03T12:07:27Z",
            "attested_by": "operator",
            "summary": "pruned no forks - all first-party",
            "forks_pruned": [], "forks_kept_conservative": [],
            "read_ack": MOD._step_text_sha(MOD._canonical_step(_MANIFEST, "step-1b")),
            "evidence_refs": ["SCOPE.md"],
        })
        (self.ws / "SCOPE.md").write_text("scope", encoding="utf-8")
        MOD.render(self.ws, "step-1b", _MANIFEST)  # write current read-ack marker
        r = MOD.check(self.ws, _MANIFEST)
        self.assertEqual(r["schema_findings"], [])
        self.assertEqual(r["verdict"], "pass-manual-steps-grounded")

    # --- advisory-first: default WARN, named env hard-fails -----------------

    def test_default_is_advisory_warn(self):
        # grounding-clean so the schema branch owns the top-line; default env ->
        # advisory warn (not a hard fail).
        self._ground("step-1b", {"completed_at": "x", "summary": "s",
                                 "forks_pruned": [], "forks_kept_conservative": []})
        self.assertEqual(MOD.check(self.ws, _MANIFEST)["verdict"],
                         "warn-attestation-schema-invalid")

    def test_schema_strict_env_hard_fails(self):
        # Case 3 (explicit-on): the named env truthy blocks on schema (L37 irrelevant).
        self._write_att("step-1b", {"completed_at": "x", "forks_pruned": []})
        os.environ["AUDITOOOR_ATTEST_SCHEMA_STRICT"] = "1"
        r = MOD.check(self.ws, _MANIFEST)
        self.assertEqual(r["verdict"], "fail-attestation-schema-invalid")

    # --- graduated: default-ON under the L37 strict umbrella -----------------

    def test_default_under_l37_hard_fails(self):
        # Case 1 (default-under-L37): X unset, AUDITOOOR_L37_STRICT set -> hard-fail
        # (what `make audit-complete STRICT=1` exports). No explicit schema env.
        self._write_att("step-1b", {"completed_at": "x", "forks_pruned": []})
        os.environ.pop("AUDITOOOR_ATTEST_SCHEMA_STRICT", None)
        os.environ["AUDITOOOR_L37_STRICT"] = "1"
        r = MOD.check(self.ws, _MANIFEST)
        self.assertTrue(r["schema_strict"])
        self.assertEqual(r["verdict"], "fail-attestation-schema-invalid")

    def test_explicit_opt_out_even_under_l37_is_advisory(self):
        # Case 2 (opt-out): explicit AUDITOOOR_ATTEST_SCHEMA_STRICT=0 disables the
        # hard-fail even when L37_STRICT is set - the escape hatch. Grounding-clean
        # so the schema branch owns the top-line (advisory warn, not fail).
        self._ground("step-1b", {"completed_at": "x", "summary": "s",
                                 "forks_pruned": [], "forks_kept_conservative": []})
        os.environ["AUDITOOOR_L37_STRICT"] = "1"
        os.environ["AUDITOOOR_ATTEST_SCHEMA_STRICT"] = "0"
        r = MOD.check(self.ws, _MANIFEST)
        self.assertFalse(r["schema_strict"])
        self.assertEqual(r["verdict"], "warn-attestation-schema-invalid")

    def test_non_strict_advisory_both_unset(self):
        # Case 4 (non-strict-advisory): X unset AND L37 unset -> advisory warn
        # (byte-identical to the historical default; a library caller never breaks).
        self._ground("step-1b", {"completed_at": "x", "summary": "s",
                                 "forks_pruned": [], "forks_kept_conservative": []})
        os.environ.pop("AUDITOOOR_ATTEST_SCHEMA_STRICT", None)
        os.environ.pop("AUDITOOOR_L37_STRICT", None)
        r = MOD.check(self.ws, _MANIFEST)
        self.assertFalse(r["schema_strict"])
        self.assertEqual(r["verdict"], "warn-attestation-schema-invalid")

    def test_manual_step_strict_env_does_not_change_schema_to_fail(self):
        # AUDITOOOR_MANUAL_STEP_STRICT is the GROUNDING-strict knob; it must NOT
        # be repurposed to hard-fail a schema miss (that needs the named schema
        # env). On a legacy+schema-broken attestation it keeps its historical
        # grounding fail verdict; schema still surfaces in schema_findings.
        self._write_att("step-1b", {"completed_at": "x", "forks_pruned": []})
        os.environ["AUDITOOOR_MANUAL_STEP_STRICT"] = "1"
        r = MOD.check(self.ws, _MANIFEST)
        self.assertEqual(r["verdict"], "fail-manual-step-ungrounded")
        self.assertTrue(r["schema_advisory"])  # never-false-pass still holds

    # --- optional self-heal repairs the attested_by drop --------------------

    def test_selfheal_restamps_missing_attested_by(self):
        # only attested_by missing -> self-heal repairs it in place
        att = {"completed_at": "2026-07-03T12:07:27Z", "summary": "did it",
               "forks_pruned": [], "forks_kept_conservative": []}
        self._write_att("step-1b", att)
        os.environ["AUDITOOOR_ATTEST_SELFHEAL"] = "1"
        r = MOD.check(self.ws, _MANIFEST, now="2026-07-03T13:00:00Z")
        self.assertIn("step-1b", r["healed"])
        self.assertEqual(r["schema_findings"], [])  # attested_by no longer missing
        on_disk = self._read_att("step-1b")
        self.assertEqual(on_disk["attested_by"], "claude-operator-verified")

    def test_selfheal_does_not_overwrite_existing_attested_by(self):
        att = {"completed_at": "x", "attested_by": "operator", "summary": "s",
               "forks_pruned": []}
        self._write_att("step-1b", att)
        os.environ["AUDITOOOR_ATTEST_SELFHEAL"] = "1"
        MOD.check(self.ws, _MANIFEST)
        self.assertEqual(self._read_att("step-1b")["attested_by"], "operator")  # untouched

    def test_selfheal_off_by_default_does_not_mutate(self):
        att = {"completed_at": "x", "summary": "s", "forks_pruned": []}
        self._write_att("step-1b", att)
        MOD.check(self.ws, _MANIFEST)  # no SELFHEAL env
        self.assertNotIn("attested_by", self._read_att("step-1b"))  # byte-identical field-set

    # --- schema single-source-of-truth reuse --------------------------------

    def test_required_fields_sourced_from_manifest(self):
        # helper reads attestation_format.required_fields_always, not a rebuilt const
        self.assertEqual(CONF.required_fields_always(_MANIFEST),
                         ["completed_at", "attested_by", "summary"])
        # fallback when manifest omits it
        self.assertEqual(CONF.required_fields_always({}),
                         list(CONF._FALLBACK_REQUIRED_FIELDS_ALWAYS))

    def test_shared_helper_reused_by_preflight(self):
        # the preflight delegates to the conformance helper (no schema dup). obj
        # carries both step fields so only the base fields are missing.
        step = MOD._canonical_step(_MANIFEST, "step-1b")
        obj = {"completed_at": "x", "forks_pruned": [], "forks_kept_conservative": []}
        missing = MOD._schema_missing_fields(obj, step, _MANIFEST)
        self.assertEqual(sorted(missing), ["attested_by", "summary"])
        # and the delegated helper is defined in readme-conformance-check (the
        # single source of truth), not re-implemented in the preflight module.
        helper_fn = MOD._load_schema_helper().attestation_schema_missing_fields
        self.assertTrue(helper_fn.__code__.co_filename.endswith("readme-conformance-check.py"))
        self.assertEqual(helper_fn.__code__.co_filename,
                         CONF.attestation_schema_missing_fields.__code__.co_filename)

    # --- no-attestation still not our concern (unchanged behavior) ----------

    def test_no_attestation_still_passes(self):
        self.assertEqual(MOD.check(self.ws, _MANIFEST)["verdict"],
                         "pass-manual-steps-grounded")


if __name__ == "__main__":
    unittest.main(verbosity=2)
