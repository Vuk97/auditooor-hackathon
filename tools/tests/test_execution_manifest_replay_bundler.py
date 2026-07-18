from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "execution-manifest-replay-bundler.py"


def _import():
    spec = importlib.util.spec_from_file_location("execution_manifest_replay_bundler_test", str(TOOL))
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def _fixtures(ws: Path) -> None:
    _family_fixture(ws, "resource_consumption", "imo-critical-resource-consumption-01")


def _family_fixture(ws: Path, family: str, candidate: str) -> None:
    manifest_path = ws / "poc_execution" / candidate / "execution_manifest.json"
    stdout_path = manifest_path.parent / "command_001.stdout.log"
    stderr_path = manifest_path.parent / "command_001.stderr.log"
    run_path = ws / "poc-tests" / candidate / "run_harness.sh"
    run_path.parent.mkdir(parents=True)
    run_path.write_text("#!/usr/bin/env bash\nexit 2\n", encoding="utf-8")
    stdout_path.parent.mkdir(parents=True)
    stdout_path.write_text("blocked_missing_target_project", encoding="utf-8")
    stderr_path.write_text("", encoding="utf-8")
    _write_json(
        manifest_path,
        {
            "candidate_id": candidate,
            "final_result": "blocked_path",
            "impact_assertion": "not_demonstrated",
            "commands_attempted": [
                {
                    "command": str(run_path),
                    "cwd": str(ws),
                    "exit_code": 2,
                    "status": "fail",
                    "stdout_path": str(stdout_path),
                    "stderr_path": str(stderr_path),
                }
            ],
        },
    )
    _write_json(
        ws / ".auditooor" / "execution_manifest_terminal_blockers_fi" / f"{family}.json",
        {"family": family, "row_count": 1, "rows": [{"candidate_id": candidate, "path": str(manifest_path)}]},
    )


class ExecutionManifestReplayBundlerTests(unittest.TestCase):
    def test_build_bundle_accepts_replayable_blocked_scaffold_without_promoting(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _fixtures(ws)
            payload = mod.build_bundle(ws, "resource_consumption")

        self.assertEqual(payload["row_count"], 1)
        self.assertEqual(payload["accepted_blocked_count"], 1)
        self.assertFalse(payload["promotion_allowed"])
        row = payload["rows"][0]
        self.assertEqual(row["accepted_blocked_status"], "accepted_blocked_missing_target_project")
        self.assertIn("run_harness.sh", row["replay_command"])
        self.assertFalse(row["promotion_allowed"])
        self.assertIn("RESULT=needs_human", row["required_next_commands"][1])

    def test_render_markdown_keeps_proof_boundary_visible(self) -> None:
        mod = _import()
        payload = {
            "family": "resource_consumption",
            "proof_boundary": "no proof",
            "row_count": 1,
            "accepted_blocked_count": 1,
            "needs_manual_review_count": 0,
            "promotion_allowed": False,
            "rows": [
                {
                    "candidate_id": "imo-critical-resource-consumption-01",
                    "accepted_blocked_status": "accepted_blocked_missing_target_project",
                    "latest_exit_code": 2,
                    "replay_command": "cd /tmp/ws && ./run_harness.sh",
                }
            ],
        }
        md = mod.render_markdown(payload)
        self.assertIn("Execution Manifest Replay Bundle", md)
        self.assertIn("Accepted blocked replay rows", md)
        self.assertIn("without `RESULT=proved`", md)

    def test_batch_discovers_non_task_manifest_families_and_writes_outputs(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _family_fixture(ws, "asset_custody", "imo-critical-asset-custody-01")
            _family_fixture(ws, "signature_replay", "imo-critical-signature-replay-01")
            _write_json(
                ws / ".auditooor" / "execution_manifest_terminal_blockers_fi" / "task_forge_execution.json",
                {"family": "task_forge_execution", "rows": [{"task_id": "priority-5"}]},
            )
            families = mod.discover_replay_families(ws)
            payload = mod.build_batch(ws, families)
            self.assertEqual(families, ["asset_custody", "signature_replay"])
            self.assertEqual(payload["family_count"], 2)
            self.assertEqual(payload["row_count"], 2)
            self.assertEqual(payload["accepted_blocked_count"], 2)
            self.assertTrue((ws / ".auditooor" / "execution_manifest_replay_bundle_asset_custody.json").exists())


if __name__ == "__main__":
    unittest.main()
