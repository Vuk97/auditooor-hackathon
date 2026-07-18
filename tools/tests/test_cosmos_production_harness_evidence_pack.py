"""Tests for cosmos-production-harness-evidence-pack."""

from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "cosmos_production_harness_evidence_pack",
    ROOT / "tools" / "cosmos-production-harness-evidence-pack.py",
)
mod = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mod)  # type: ignore[union-attr]


def _marker(event: str, **fields) -> dict[str, object]:
    payload: dict[str, object] = {"schema": mod.RUNTIME_EVENT_SCHEMA, "event": event}
    payload.update(fields)
    payload["_source_log"] = "/tmp/stdout.log"
    payload["_source_line"] = 1
    return payload


def _write_exec_record(*, network: bool = False, complete: bool = True) -> Path:
    root = Path(tempfile.mkdtemp(prefix="cosmos_evidence_pack_"))
    stdout = root / "stdout.log"
    stderr = root / "stderr.log"
    stdout.write_text("ok\n", encoding="utf-8")
    stderr.write_text("", encoding="utf-8")

    events = [
        _marker(
            "app_profile",
            app_chain="dydx",
            db_backend="GoLevelDB",
            data_dir=str(root / "db"),
            private_state_injection=False,
        ),
        _marker("block_execution", height=4, finalize_block=True, commit=True, app_hash="abc"),
        _marker(
            "restart_check",
            restarted=True,
            same_data_dir=True,
            post_restart_assertion="state survived restart",
        ),
        _marker("impact_assertion", assertion="candidate invariant", observed="violated"),
    ]
    required_events = ["app_profile", "block_execution", "restart_check", "impact_assertion"]
    if network:
        required_events.append("network_profile")
        events.append(_marker("network_profile", validator_count=4))
    if not complete:
        events = [event for event in events if event["event"] != "restart_check"]

    events_path = root / "runtime_observation_events.json"
    events_path.write_text(
        json.dumps(
            {
                "schema": "auditooor.cosmos_production_harness_runtime_events.v1",
                "events": events,
                "required_events": required_events,
                "missing_events": [] if complete else ["restart_check"],
                "invalid_events": [],
                "parse_errors": [],
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    record = {
        "schema": "auditooor.cosmos_production_harness_exec.v1",
        "candidate_id": "lead-runtime",
        "workspace": str(root),
        "workspace_commit": "abc123",
        "runtime_proof_claimed": False,
        "preflight": {"phase_a_ready": True, "execution_allowed": True},
        "execution": {
            "status": "pass",
            "command": "go test ./... -run TestRuntime -count=1",
            "cwd": str(root),
            "stdout_path": str(stdout),
            "stderr_path": str(stderr),
        },
        "runtime_observation_guard": {
            "status": "pass" if complete else "fail",
            "required_events": required_events,
            "events_path": str(events_path),
        },
    }
    record_path = root / "cosmos_production_harness_exec.json"
    record_path.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    return record_path


class CosmosProductionHarnessEvidencePackTests(unittest.TestCase):
    def test_complete_single_validator_record_passes_triager_matrix(self):
        record_path = _write_exec_record()
        pack, code = mod.build_evidence_pack(record_path)

        self.assertEqual(code, 0)
        self.assertEqual(pack["verdict"], "complete_runtime_marker_pack")
        self.assertEqual(pack["failed_required_rows"], [])
        rows = {row["id"]: row["status"] for row in pack["triager_rows"]}
        self.assertEqual(rows["multi_validator_liveness"], "not_applicable")
        self.assertEqual(rows["real_backend"], "pass")
        self.assertEqual(rows["restart_behavior"], "pass")
        self.assertEqual(rows["exact_repro_metadata"], "pass")

    def test_network_record_requires_validator_profile(self):
        record_path = _write_exec_record(network=True)
        pack, code = mod.build_evidence_pack(record_path)

        self.assertEqual(code, 0)
        rows = {row["id"]: row for row in pack["triager_rows"]}
        self.assertEqual(rows["multi_validator_liveness"]["status"], "pass")
        self.assertEqual(rows["multi_validator_liveness"]["evidence"]["validator_count"], 4)

    def test_missing_restart_is_reported_as_incomplete(self):
        record_path = _write_exec_record(complete=False)
        pack, code = mod.build_evidence_pack(record_path)

        self.assertEqual(code, 1)
        self.assertEqual(pack["verdict"], "incomplete")
        self.assertIn("restart_behavior", pack["failed_required_rows"])
        self.assertIn("runtime_guard", pack["failed_required_rows"])

    def test_markdown_renders_triager_rows(self):
        record_path = _write_exec_record()
        pack, _code = mod.build_evidence_pack(record_path)
        md = mod.render_markdown(pack)

        self.assertIn("Triager Ask Matrix", md)
        self.assertIn("`real_block_execution_path`", md)
        self.assertIn("Boundary:", md)


if __name__ == "__main__":
    unittest.main()
