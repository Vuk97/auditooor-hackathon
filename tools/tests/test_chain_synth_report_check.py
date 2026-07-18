import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


TOOL = Path(__file__).resolve().parents[1] / "chain-synth-report-check.py"
SPEC = importlib.util.spec_from_file_location("chain_synth_report_check", TOOL)
csr = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules["chain_synth_report_check"] = csr
SPEC.loader.exec_module(csr)


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _write_manifest(
    ws: Path,
    *,
    run_id: str = "auditrun-1",
    stage: str = "post-coverage-chain-synth",
    timestamp: str = "2026-05-31T10:00:00Z",
) -> Path:
    path = ws / ".auditooor" / "audit_run_full_manifest.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    rows = [
        {
            "schema": "auditooor.audit_run_full_manifest.v1",
            "event": "start",
            "run_id": run_id,
            "timestamp_utc": "2026-05-31T09:59:00Z",
        },
        {
            "schema": "auditooor.audit_run_full_manifest.v1",
            "event": "stage-start",
            "run_id": run_id,
            "stage": stage,
            "timestamp_utc": timestamp,
        },
    ]
    path.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")
    return path


def _report_payload(
    ws: Path,
    *,
    run_id: str = "auditrun-1",
    stage: str = "post-coverage-chain-synth",
    status: str = "complete",
    generated_at: str = "2026-05-31T10:01:00Z",
    matched_templates=1,
    broken_invariant_ids=None,
    proof_obligations=1,
    extra_fields: dict | None = None,
) -> dict:
    if broken_invariant_ids is None:
        broken_invariant_ids = ["INV-A"]
    payload = {
        "schema": "auditooor.chain_synthesis_report.v1",
        "generated_at": generated_at,
        "workspace": str(ws.resolve()),
        "audit_run_id": run_id,
        "stage": stage,
        "status": status,
        "matched_templates": matched_templates,
        "proof_obligations": proof_obligations,
        "broken_invariant_ids": broken_invariant_ids,
        "input_counts": {
            "current_queue_leads": 1,
            "broken_invariant_ids": len(broken_invariant_ids),
            "matched_templates": (
                matched_templates
                if isinstance(matched_templates, int)
                else len(matched_templates)
            ),
            "proof_obligations": proof_obligations,
        },
        "input_fingerprints": {
            "exploit_queue": {"path": ".auditooor/exploit_queue.json", "exists": True},
        },
    }
    if extra_fields:
        payload.update(extra_fields)
    return payload


def _write_report(ws: Path, name: str, payload: dict) -> Path:
    path = ws / ".auditooor" / name
    _write_json(path, payload)
    return path


class TestValidateChainSynthReport(unittest.TestCase):
    def _validate(self, ws: Path, **kwargs):
        manifest = kwargs.pop("manifest", ws / ".auditooor" / "audit_run_full_manifest.jsonl")
        return csr.validate(
            workspace=ws,
            run_id=kwargs.pop("run_id", "auditrun-1"),
            stage=kwargs.pop("stage", "post-coverage-chain-synth"),
            manifest_path=manifest,
        )

    def test_complete_report_passes(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "ws"
            _write_manifest(ws)
            report_path = _write_report(
                ws,
                "chain_synthesis_2026-05-31.json",
                _report_payload(ws),
            )

            result = self._validate(ws)

            self.assertTrue(result["ok"], result)
            self.assertEqual(result["verdict"], "pass-chain-synth-report-valid")
            self.assertEqual(Path(result["report_path"]), report_path.resolve())
            self.assertEqual(result["report_status"], "complete")

    def test_complete_with_dispatch_errors_passes(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "ws"
            _write_manifest(ws)
            _write_report(
                ws,
                "chain_synthesis_2026-05-31.json",
                _report_payload(ws, status="complete-with-dispatch-errors"),
            )

            result = self._validate(ws)

            self.assertTrue(result["ok"], result)
            self.assertEqual(result["report_status"], "complete-with-dispatch-errors")

    def test_complete_requires_proof_obligations(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "ws"
            _write_manifest(ws)
            _write_report(
                ws,
                "chain_synthesis_2026-05-31.json",
                _report_payload(ws, proof_obligations=0),
            )

            result = self._validate(ws)

            self.assertFalse(result["ok"])
            self.assertEqual(result["verdict"], "fail-complete-without-proof-obligations")

    def test_post_coverage_chain_synth_requires_exploit_queue_fingerprint_exists(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "ws"
            _write_manifest(ws)
            payload = _report_payload(ws)
            payload["input_fingerprints"]["exploit_queue"]["exists"] = False
            _write_report(ws, "chain_synthesis_2026-05-31.json", payload)

            result = self._validate(ws)

            self.assertFalse(result["ok"])
            self.assertEqual(result["verdict"], "fail-missing-current-exploit-queue")

    def test_post_coverage_chain_synth_requires_current_queue_leads(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "ws"
            _write_manifest(ws)
            payload = _report_payload(ws)
            payload["input_counts"]["current_queue_leads"] = 0
            _write_report(ws, "chain_synthesis_2026-05-31.json", payload)

            result = self._validate(ws)

            self.assertFalse(result["ok"])
            self.assertEqual(result["verdict"], "fail-empty-current-exploit-queue")

    def test_current_exploit_queue_requirement_is_stage_specific(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "ws"
            _write_manifest(ws, stage="other-chain-synth-stage")
            payload = _report_payload(ws, stage="other-chain-synth-stage")
            payload["input_counts"]["current_queue_leads"] = 0
            payload["input_fingerprints"]["exploit_queue"]["exists"] = False
            _write_report(ws, "chain_synthesis_2026-05-31.json", payload)

            result = self._validate(ws, stage="other-chain-synth-stage")

            self.assertTrue(result["ok"], result)

    def test_blocked_missing_hop_evidence_requires_template_match(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "ws"
            _write_manifest(ws)
            _write_report(
                ws,
                "chain_synthesis_2026-05-31.json",
                _report_payload(
                    ws,
                    status="blocked-missing-hop-evidence",
                    matched_templates=2,
                    proof_obligations=1,
                ),
            )
            self.assertTrue(self._validate(ws)["ok"])

            _write_report(
                ws,
                "chain_synthesis_2026-06-01.json",
                _report_payload(
                    ws,
                    status="blocked-missing-hop-evidence",
                    matched_templates=0,
                    generated_at="2026-05-31T10:02:00Z",
                ),
            )
            result = self._validate(ws)
            self.assertFalse(result["ok"])
            self.assertEqual(result["verdict"], "fail-blocked-without-template-match")

    def test_blocked_missing_hop_evidence_requires_proof_obligations_or_non_applicable(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "ws"
            _write_manifest(ws)
            _write_report(
                ws,
                "chain_synthesis_2026-05-31.json",
                _report_payload(
                    ws,
                    status="blocked-missing-hop-evidence",
                    matched_templates=2,
                    proof_obligations=0,
                ),
            )

            result = self._validate(ws)
            self.assertFalse(result["ok"])
            self.assertEqual(result["verdict"], "fail-blocked-without-proof-obligations")

            _write_report(
                ws,
                "chain_synthesis_2026-06-01.json",
                _report_payload(
                    ws,
                    status="blocked-missing-hop-evidence",
                    matched_templates=2,
                    proof_obligations=0,
                    generated_at="2026-05-31T10:02:00Z",
                    extra_fields={
                        "blocked_chains": [
                            {"template_id": "GCT-1", "verdict": "pass-not-applicable"}
                        ]
                    },
                ),
            )

            result = self._validate(ws)
            self.assertTrue(result["ok"], result)

    def test_blocked_single_detector_restatement_is_not_accepted(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "ws"
            _write_manifest(ws)
            _write_report(
                ws,
                "chain_synthesis_2026-05-31.json",
                _report_payload(
                    ws,
                    status="blocked-missing-hop-evidence",
                    matched_templates=1,
                    proof_obligations=0,
                    extra_fields={
                        "blocked_chains": [
                            {
                                "template_id": "GCT-SINGLE",
                                "composition_support": ["single-detector-restatement"],
                            }
                        ]
                    },
                ),
            )

            result = self._validate(ws)

            self.assertFalse(result["ok"])
            self.assertEqual(result["verdict"], "fail-single-detector-restatement")

    def test_no_template_matches_requires_broken_invariant_ids(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "ws"
            _write_manifest(ws)
            _write_report(
                ws,
                "chain_synthesis_2026-05-31.json",
                _report_payload(
                    ws,
                    status="no-template-matches",
                    matched_templates=0,
                    broken_invariant_ids=["INV-A"],
                ),
            )
            self.assertTrue(self._validate(ws)["ok"])

            _write_report(
                ws,
                "chain_synthesis_2026-06-01.json",
                _report_payload(
                    ws,
                    status="no-template-matches",
                    matched_templates=0,
                    broken_invariant_ids=[],
                    generated_at="2026-05-31T10:02:00Z",
                ),
            )
            result = self._validate(ws)
            self.assertFalse(result["ok"])
            self.assertEqual(result["verdict"], "fail-no-template-matches-without-invariants")

    def test_rejects_explicit_failure_statuses(self):
        statuses = [
            "no-invariant-ids",
            "dry-run",
            "batch-generation-failed",
            "dispatch-failed",
            "dispatch-no-successful-narratives",
        ]
        for status in statuses:
            with self.subTest(status=status):
                with tempfile.TemporaryDirectory() as td:
                    ws = Path(td) / "ws"
                    _write_manifest(ws)
                    _write_report(
                        ws,
                        "chain_synthesis_2026-05-31.json",
                        _report_payload(ws, status=status),
                    )

                    result = self._validate(ws)

                    self.assertFalse(result["ok"])
                    self.assertEqual(result["verdict"], f"fail-status-{status}")

    def test_rejects_stale_report_before_stage_start(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "ws"
            _write_manifest(ws, timestamp="2026-05-31T10:00:00Z")
            _write_report(
                ws,
                "chain_synthesis_2026-05-31.json",
                _report_payload(ws, generated_at="2026-05-31T09:59:59Z"),
            )

            result = self._validate(ws)

            self.assertFalse(result["ok"])
            self.assertEqual(result["verdict"], "fail-stale-report")

    def test_rejects_missing_report(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "ws"
            _write_manifest(ws)

            result = self._validate(ws)

            self.assertFalse(result["ok"])
            self.assertEqual(result["verdict"], "fail-missing-report")

    def test_validates_required_identity_and_observability_fields(self):
        cases = [
            ("schema", "wrong.schema", "fail-schema-mismatch"),
            ("workspace", "/tmp/not-this-workspace", "fail-workspace-mismatch"),
            ("audit_run_id", "auditrun-other", "fail-run-id-mismatch"),
            ("stage", "chain-synth", "fail-stage-mismatch"),
            ("input_counts", {}, "fail-missing-input-counts"),
            ("input_fingerprints", {}, "fail-missing-input-fingerprints"),
        ]
        for field, value, verdict in cases:
            with self.subTest(field=field):
                with tempfile.TemporaryDirectory() as td:
                    ws = Path(td) / "ws"
                    _write_manifest(ws)
                    payload = _report_payload(ws)
                    payload[field] = value
                    _write_report(ws, "chain_synthesis_2026-05-31.json", payload)

                    result = self._validate(ws)

                    self.assertFalse(result["ok"])
                    self.assertEqual(result["verdict"], verdict)

    def test_selects_latest_report_by_generated_at(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "ws"
            _write_manifest(ws)
            older = _write_report(
                ws,
                "chain_synthesis_2026-06-02.json",
                _report_payload(ws, status="dry-run", generated_at="2026-05-31T10:01:00Z"),
            )
            newer = _write_report(
                ws,
                "chain_synthesis_2026-05-31.json",
                _report_payload(ws, status="complete", generated_at="2026-05-31T10:02:00Z"),
            )
            os.utime(older, (newer.stat().st_mtime + 20, newer.stat().st_mtime + 20))

            result = self._validate(ws)

            self.assertTrue(result["ok"], result)
            self.assertEqual(Path(result["report_path"]), newer.resolve())

    def test_cli_json_exit_codes(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "ws"
            _write_manifest(ws)
            _write_report(ws, "chain_synthesis_2026-05-31.json", _report_payload(ws))

            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--workspace",
                    str(ws),
                    "--run-id",
                    "auditrun-1",
                    "--stage",
                    "post-coverage-chain-synth",
                    "--json",
                ],
                capture_output=True,
                text=True,
            )

            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads(proc.stdout)
            self.assertEqual(payload["verdict"], "pass-chain-synth-report-valid")
