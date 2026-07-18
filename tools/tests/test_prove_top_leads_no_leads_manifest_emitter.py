#!/usr/bin/env python3
"""test_prove_top_leads_no_leads_manifest_emitter.py

Regression for tools/prove-top-leads-no-leads-manifest.py (2026-07-04, NUVA):
the completeness gate accepts a no-leads manifest as the honest-0 path for
prove-top-leads, but nothing PRODUCED it (only validators read it). This test
locks the new real producer:

  * REFUSES (exit 1, no file) when the queue is non-empty and the prefiling-stress
    producer does NOT confirm all-terminal - it cannot fabricate.
  * EMITS a manifest for a non-empty PROCESSED queue when the un-fakeable
    prefiling corroboration is present, and that emitted manifest PASSES the
    completeness validator (_valid_prove_top_leads_no_leads_manifest).
  * EMITS for a genuinely EMPTY queue.
"""
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

_TOOLS = Path(__file__).resolve().parents[1]
_EMITTER = _TOOLS / "prove-top-leads-no-leads-manifest.py"
_VALIDATOR_TOOL = _TOOLS / "audit-completeness-check.py"

_SCHEMA = "auditooor.prove_top_leads_no_leads.v1"
_ALL_TERMINAL_PREFILING = {"top_n": 10, "rows_assessed": 0, "terminal_rows_skipped": 134}


def _load_validator():
    spec = importlib.util.spec_from_file_location("acc_validator", _VALIDATOR_TOOL)
    m = importlib.util.module_from_spec(spec)
    sys.modules["acc_validator"] = m
    try:
        spec.loader.exec_module(m)
    except Exception:
        pass
    return m


def _load_envelope_tool():
    spec = importlib.util.spec_from_file_location(
        "no_leads_emitter_envelope", _TOOLS / "zero-day-proof-envelope-verify.py",
    )
    m = importlib.util.module_from_spec(spec)
    sys.modules["no_leads_emitter_envelope"] = m
    spec.loader.exec_module(m)
    return m


def _typed_queue(envelope_tool, terminal):
    parent = ["zdo-no-leads", "zdr-no-leads"]
    row = {
        "lead_id": "zdpq-no-leads",
        "obligation_id": parent[0],
        "revision_id": parent[1],
        "proof_status": "disproved",
        "zero_day_proof_projection": {
            "schema": "auditooor.zero_day_proof_queue_projection.v1",
            "freeze_receipt_id": "a" * 64,
            "freeze_input_fingerprint": "b" * 64,
            "obligation_source_row_sha256": "c" * 64,
            "parent_ids": parent,
            "selection_ordinal": 1,
            "question_evidence": [{"question_id": "q0", "axis": "asset_invariant"}],
        },
        "zero_day_proof_admission": {
            "freeze_receipt_id": "a" * 64,
            "input_fingerprint": "b" * 64,
            "obligation_source_row_sha256": "c" * 64,
            "parent_ids": parent,
        },
    }
    payload = {
        "schema": "auditooor.exploit_queue.v1",
        "queue_role": "proof_tasks",
        "queue": [row],
        "entries": [],
        "zero_day_proof_admission": {
            "schema": "auditooor.zero_day_proof_admission.v1",
            "queue_role": "proof_tasks",
            "admission_id": "zdpa_" + "d" * 64,
            "input_queue_sha256": "e" * 64,
            "freeze_receipt_id": "a" * 64,
            "freeze_input_fingerprint": "b" * 64,
            "admitted_count": 1,
            "admitted_parents": [{"obligation_id": parent[0], "revision_id": parent[1]}],
        },
    }
    if terminal:
        entry = envelope_tool.build_envelope(payload)["entries"][0]
        row["terminal_join"] = {
            "schema": "auditooor.zero_day_proof_terminal_verdict.v1",
            "parent_ids": entry["parent_ids"],
            "envelope_id": entry["envelope_id"],
            "evidence_ref": "src/NoLeads.sol:42",
        }
    return payload


def _ws(queue_rows, prefiling=None, typed_queue=None):
    d = Path(tempfile.mkdtemp())
    a = d / ".auditooor"
    a.mkdir()
    q = {"queue": [{"i": i} for i in range(queue_rows)]}
    (a / "exploit_queue.json").write_text(json.dumps(q))
    (a / "exploit_queue.source_mined.json").write_text(json.dumps(q))
    if typed_queue is not None:
        typed_path = a / "exploit_queue.zero_day_admitted.json"
        typed_path.write_text(json.dumps(typed_queue))
        try:
            _load_envelope_tool().materialize(
                d, typed_path, a / "zero_day_proof_envelope.json",
            )
        except RuntimeError:
            # Malformed typed-queue tests intentionally have no valid envelope.
            pass
    if prefiling is not None:
        (a / "prove_top_leads_prefiling_stress_test.json").write_text(json.dumps(prefiling))
    return d


def _run(ws, extra=None):
    cmd = [sys.executable, str(_EMITTER), "--workspace", str(ws), "--json"]
    if extra:
        cmd += extra
    return subprocess.run(cmd, capture_output=True, text=True)


class TestNoLeadsManifestEmitter(unittest.TestCase):
    def setUp(self):
        self.m = _load_validator()

    def _manifest_path(self, ws):
        return ws / ".auditooor" / "prove_top_leads_no_leads.json"

    def test_refuses_without_prefiling_corroboration(self):
        ws = _ws(7814, prefiling={"top_n": 5, "rows_assessed": 5, "terminal_rows_skipped": 10})
        cp = _run(ws)
        self.assertEqual(cp.returncode, 1, cp.stderr)
        self.assertFalse(self._manifest_path(ws).is_file(),
                         "must NOT write a manifest when it cannot corroborate")

    def test_refuses_when_prefiling_absent(self):
        ws = _ws(7814, prefiling=None)
        cp = _run(ws)
        self.assertEqual(cp.returncode, 1, cp.stderr)
        self.assertFalse(self._manifest_path(ws).is_file())

    def test_emits_and_validator_accepts_nonempty_all_terminal(self):
        ws = _ws(7814, prefiling=_ALL_TERMINAL_PREFILING)
        cp = _run(ws)
        self.assertEqual(cp.returncode, 0, cp.stderr)
        path = self._manifest_path(ws)
        self.assertTrue(path.is_file(), "emitter must write the manifest")
        obj = json.loads(path.read_text())
        self.assertEqual(obj["schema"], _SCHEMA)
        self.assertIs(obj["no_leads"], True)
        self.assertIs(obj["all_top_leads_terminal"], True)
        # The emitted manifest must PASS the real completeness validator.
        self.assertTrue(self.m._valid_prove_top_leads_no_leads_manifest(ws, path),
                        "emitted manifest must satisfy the completeness validator")

    def test_emits_for_empty_queue(self):
        ws = _ws(0)
        cp = _run(ws)
        self.assertEqual(cp.returncode, 0, cp.stderr)
        path = self._manifest_path(ws)
        self.assertTrue(path.is_file())
        self.assertTrue(self.m._valid_prove_top_leads_no_leads_manifest(ws, path))

    def test_declared_counts_match_live_queue(self):
        ws = _ws(7814, prefiling=_ALL_TERMINAL_PREFILING)
        cp = _run(ws)
        self.assertEqual(cp.returncode, 0, cp.stderr)
        obj = json.loads(self._manifest_path(ws).read_text())
        self.assertEqual(obj["current_queue_rows"][".auditooor/exploit_queue.json"], 7814)
        self.assertEqual(
            obj["current_queue_rows"][".auditooor/exploit_queue.source_mined.json"], 7814)

    def test_refuses_typed_terminal_status_without_exact_terminal_record(self):
        ws = _ws(1, prefiling=_ALL_TERMINAL_PREFILING,
                 typed_queue=_typed_queue(_load_envelope_tool(), terminal=False))
        cp = _run(ws)
        self.assertEqual(cp.returncode, 1, cp.stderr)
        self.assertIn("typed_terminal_record_missing_or_mismatched", cp.stderr)
        self.assertFalse(self._manifest_path(ws).is_file())

    def test_refuses_malformed_typed_queue_even_when_legacy_queues_are_empty(self):
        ws = _ws(0, typed_queue={"queue": []})
        cp = _run(ws)
        self.assertEqual(cp.returncode, 1, cp.stderr)
        self.assertIn("typed_proof_queue_missing_admission", cp.stderr)
        self.assertFalse(self._manifest_path(ws).is_file())

    def test_emits_only_when_typed_rows_have_exact_terminal_records(self):
        ws = _ws(1, prefiling=_ALL_TERMINAL_PREFILING,
                 typed_queue=_typed_queue(_load_envelope_tool(), terminal=True))
        cp = _run(ws)
        self.assertEqual(cp.returncode, 0, cp.stderr)
        path = self._manifest_path(ws)
        self.assertTrue(self.m._valid_prove_top_leads_no_leads_manifest(ws, path))
        binding = json.loads(path.read_text())["typed_terminal_binding"]
        self.assertEqual(binding["entry_count"], 1)
        self.assertTrue(binding["all_entries_exact_terminal"])

    def test_refuses_when_persisted_envelope_is_stale_after_queue_mutation(self):
        ws = _ws(1, prefiling=_ALL_TERMINAL_PREFILING,
                 typed_queue=_typed_queue(_load_envelope_tool(), terminal=True))
        queue_path = ws / ".auditooor" / "exploit_queue.zero_day_admitted.json"
        payload = json.loads(queue_path.read_text())
        payload["queue"][0]["zero_day_proof_projection"]["selection_ordinal"] = 2
        queue_path.write_text(json.dumps(payload))
        cp = _run(ws)
        self.assertEqual(cp.returncode, 1, cp.stderr)
        self.assertIn("typed_proof_envelope_invalid", cp.stderr)
        self.assertFalse(self._manifest_path(ws).is_file())


if __name__ == "__main__":
    unittest.main()
