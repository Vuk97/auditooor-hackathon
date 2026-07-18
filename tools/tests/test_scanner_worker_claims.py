"""Tests for scanner-worker-claims.py."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "scanner-worker-claims.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location("scanner_worker_claims", TOOL)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


MOD = _load_tool()


class ScannerWorkerClaimsTests(unittest.TestCase):
    def test_update_registry_marks_completed_and_adds_active_assignments(self) -> None:
        payload = {
            "schema": "auditooor.scanner_worker_active_claims.v1",
            "active_claims": [
                {"agent_id": "old-a", "row_id": "closed_row", "status": "active"},
                {"agent_id": "old-b", "row_id": "still_active", "status": "active"},
            ],
        }

        updated, missing = MOD.update_registry(
            payload,
            completed=["closed-row"],
            activations=[("agent-c", "new_row")],
            updated_at="2026-05-06T00:00:00Z",
        )

        self.assertEqual(missing, [])
        by_row = {row["row_id"]: row for row in updated["active_claims"]}
        self.assertEqual(by_row["closed_row"]["status"], "completed")
        self.assertEqual(by_row["still_active"]["status"], "active")
        self.assertEqual(by_row["new_row"]["agent_id"], "agent-c")
        self.assertEqual(by_row["new_row"]["status"], "active")
        self.assertEqual(updated["summary"], {"active": 2, "completed": 1})

    def test_missing_completion_fails_unless_allowed(self) -> None:
        payload = {"active_claims": []}

        _updated, missing = MOD.update_registry(
            payload,
            completed=["missing_row"],
            activations=[],
            updated_at="2026-05-06T00:00:00Z",
        )

        self.assertEqual(missing, ["missing_row"])

        payload = {"active_claims": []}
        updated, missing = MOD.update_registry(
            payload,
            completed=["missing_row"],
            activations=[],
            updated_at="2026-05-06T00:00:00Z",
            allow_missing_complete=True,
        )
        self.assertEqual(missing, ["missing_row"])
        self.assertEqual(updated["active_claims"][0]["status"], "completed")

    def test_cli_stdout_does_not_rewrite_source(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            claims = Path(tmp) / "claims.json"
            claims.write_text(
                json.dumps({"active_claims": [{"agent_id": "a1", "row_id": "row_one", "status": "active"}]}),
                encoding="utf-8",
            )
            before = claims.read_text(encoding="utf-8")

            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--claims",
                    str(claims),
                    "--complete",
                    "row_one",
                    "--activate",
                    "a2=row_two",
                    "--updated-at",
                    "2026-05-06T00:00:00Z",
                ],
                check=True,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            payload = json.loads(proc.stdout)

            self.assertEqual(claims.read_text(encoding="utf-8"), before)
            self.assertEqual(payload["summary"], {"active": 1, "completed": 1})

    def test_cli_in_place_rewrites_registry(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            claims = Path(tmp) / "claims.json"
            claims.write_text(
                json.dumps({"active_claims": [{"agent_id": "a1", "row_id": "row_one", "status": "active"}]}),
                encoding="utf-8",
            )

            subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--claims",
                    str(claims),
                    "--complete",
                    "row_one",
                    "--activate",
                    "a2=row_two",
                    "--updated-at",
                    "2026-05-06T00:00:00Z",
                    "--in-place",
                ],
                check=True,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            payload = json.loads(claims.read_text(encoding="utf-8"))

            self.assertEqual(payload["summary"], {"active": 1, "completed": 1})
            self.assertEqual(payload["active_claims"][0]["status"], "completed")


if __name__ == "__main__":
    unittest.main()
