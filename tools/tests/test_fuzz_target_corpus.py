from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from tools.lib import fuzz_target_corpus as ftc


_GIT = next(
    (candidate for candidate in ("/usr/bin/git", "/opt/homebrew/bin/git") if Path(candidate).exists()),
    "git",
)

FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures" / "fuzz_target_corpus"


SAMPLE_RESULTS = {
    "schema": "auditooor.fuzz_campaign_results.v1",
    "lane": "lane-HYPERBRIDGE-FUZZ-CAMPAIGN",
    "workspace": "hyperbridge",
    "fuzz_targets": [
        {
            "id": "T1",
            "name": "ScaleCodec.decodeUintCompact",
            "tool": "Foundry forge fuzz",
            "verdict": "HOLDS",
            "invariant": "no panic/truncation for any valid SCALE encoding",
            "result": "6/6 PASS",
            "fileable_finding": False,
            "test_dir": "/tmp/ws/poc-tests/fuzz-scale-codec",
            "forge_path": "/tmp/ws/src/hyperbridge/evm/tests/foundry/FuzzScaleCodec.t.sol",
        },
        {
            "id": "T3",
            "name": "VWAPOracle.recordSpread / spread()",
            "tool": "Foundry forge fuzz",
            "verdict": "VIOLATED",
            "invariant": "spread() always in [-10000,+10000]",
            "result": "INVARIANT VIOLATED. 5/7 PASS, 2 FAIL.",
            "fileable_finding": True,
            "title_candidate": "VWAPOracle.spread() returns unbounded values for cross-decimal token fills",
            "invariants_violated": ["INV-BND-004", "INV-BND-008"],
            "forge_path": "/tmp/ws/src/hyperbridge/evm/tests/foundry/FuzzVWAPOracle.t.sol",
        },
        {
            "id": "T5",
            "name": "pallet-bandwidth purchase/credit arithmetic",
            "tool": "Rust proptest",
            "verdict": "HOLDS (with FOT overcredit observation)",
            "invariant": "credited months <= actually-received tokens / tier_price",
            "result": "8/8 tests PASS",
            "fileable_finding": False,
            "observations": ["FOT OVERCREDIT: vulnerable point lives in BandwidthManager.sol."],
            "cargo_path": "/tmp/ws/poc-tests/fuzz-pallet-bandwidth/fuzz_bandwidth_arithmetic.rs",
        },
    ],
    "compose_queue_updates": {
        "DRILL-4_update": "Recommend escalating to DRILL-4 for downstream consumer validation."
    },
}


def _git(args: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["PATH"] = str(Path(_GIT).parent) + os.pathsep + env.get("PATH", "")
    env.update(
        {
            "GIT_AUTHOR_NAME": "test",
            "GIT_AUTHOR_EMAIL": "test@example.invalid",
            "GIT_COMMITTER_NAME": "test",
            "GIT_COMMITTER_EMAIL": "test@example.invalid",
        }
    )
    return subprocess.run(
        [_GIT, *args],
        cwd=str(cwd),
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )


class FuzzTargetCorpusTests(unittest.TestCase):
    def test_extract_rows_maps_t1_t3_t5_fields(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fuzz_target_rows_") as raw:
            root = Path(raw)
            ws = root / "ws"
            (ws / "src" / "hyperbridge" / "evm" / "tests" / "foundry").mkdir(parents=True)
            (ws / "poc-tests" / "fuzz-pallet-bandwidth").mkdir(parents=True)
            (ws / "src" / "hyperbridge" / "evm" / "tests" / "foundry" / "FuzzScaleCodec.t.sol").write_text("// t1\n", encoding="utf-8")
            (ws / "src" / "hyperbridge" / "evm" / "tests" / "foundry" / "FuzzVWAPOracle.t.sol").write_text("// t3\n", encoding="utf-8")
            (ws / "poc-tests" / "fuzz-pallet-bandwidth" / "fuzz_bandwidth_arithmetic.rs").write_text("// t5\n", encoding="utf-8")
            _git(["init", "-q"], ws)
            _git(["add", "."], ws)
            _git(["commit", "-q", "--no-verify", "-m", "init"], ws)

            payload = json.loads(json.dumps(SAMPLE_RESULTS).replace("/tmp/ws", str(ws)))
            rows = ftc.extract_fuzz_target_rows(payload, root / "fuzz_results.json", ws="hyperbridge")

            self.assertEqual([row["target_id"] for row in rows], ["T1", "T3", "T5"])
            self.assertEqual(rows[0]["harness_type"], "foundry-forge")
            self.assertEqual(rows[1]["invariant_violated_in_run"], "INV-BND-004; INV-BND-008")
            self.assertIn("DRILL-4", rows[1]["recommendation"])
            self.assertEqual(rows[2]["harness_type"], "rust-proptest")
            self.assertTrue(all(row["last_run_sha"] for row in rows))
            self.assertTrue(all(row["verification_tier"] == "tier-2-verified-public-archive" for row in rows))

    def test_emit_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fuzz_target_emit_") as raw:
            root = Path(raw)
            out = root / "audit" / "corpus_tags" / "hyperbridge" / "fuzz_targets.jsonl"
            rows = [
                {
                    "schema_version": ftc.SCHEMA_VERSION,
                    "workspace": "hyperbridge",
                    "source_lane": "lane-HYPERBRIDGE-FUZZ-CAMPAIGN",
                    "source_artifact": "reports/x/fuzz_results.json",
                    "target_id": "T3",
                    "target_name": "VWAPOracle.recordSpread / spread()",
                    "target_path": "/tmp/ws/FuzzVWAPOracle.t.sol",
                    "harness_type": "foundry-forge",
                    "invariant_violated_in_run": "INV-BND-004; INV-BND-008",
                    "last_run_sha": "a" * 40,
                    "recommendation": "escalate",
                    "verification_tier": "tier-2-verified-public-archive",
                    "verdict": "VIOLATED",
                    "fileable_finding": True,
                }
            ]
            first = ftc.emit_fuzz_targets(out, rows)
            second = ftc.emit_fuzz_targets(out, rows)
            self.assertEqual(first["rows_appended"], 1)
            self.assertEqual(second["rows_appended"], 0)
            lines = out.read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(lines), 1)

    def test_discover_latest_results_for_workspace(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fuzz_target_discover_") as raw:
            root = Path(raw)
            old_dir = root / "reports" / "v3_iter_2026-05-24" / "lane_HYPERBRIDGE_FUZZ_CAMPAIGN"
            new_dir = root / "reports" / "v3_iter_2026-05-25" / "lane_HYPERBRIDGE_FUZZ_CAMPAIGN"
            old_dir.mkdir(parents=True)
            new_dir.mkdir(parents=True)
            (old_dir / "fuzz_results.json").write_text(json.dumps(SAMPLE_RESULTS), encoding="utf-8")
            newer = dict(SAMPLE_RESULTS)
            newer["generated_at_utc"] = "2026-05-25T17:30:00Z"
            (new_dir / "fuzz_results.json").write_text(json.dumps(newer), encoding="utf-8")
            latest = ftc.discover_latest_fuzz_results(root, "hyperbridge")
            self.assertEqual(latest, new_dir / "fuzz_results.json")

    def test_discover_latest_results_uses_workspace_local_fixture(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fuzz_target_workspace_") as raw:
            root = Path(raw)
            workspace = root / "spark"
            target = workspace / "src" / "fuzz" / "FuzzSparkMinimal.t.sol"
            results_dir = workspace / "fuzz_runs" / "20260525T120000Z"
            results_dir.mkdir(parents=True)
            target.parent.mkdir(parents=True)
            target.write_text("// spark fixture target\n", encoding="utf-8")
            _git(["init", "-q"], workspace)
            _git(["add", "."], workspace)
            _git(["commit", "-q", "--no-verify", "-m", "init"], workspace)
            (results_dir / "fuzz_results.json").write_text(
                (FIXTURE_DIR / "spark_minimal_fuzz_results.json").read_text(
                    encoding="utf-8"
                ),
                encoding="utf-8",
            )
            latest = ftc.discover_latest_fuzz_results(root, str(workspace))
            self.assertEqual(latest, results_dir / "fuzz_results.json")

    def test_discover_accepts_workspace_local_legacy_results_without_identity_fields(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fuzz_target_legacy_workspace_") as raw:
            root = Path(raw)
            workspace = root / "spark"
            results_dir = workspace / "fuzz_runs" / "legacy"
            results_dir.mkdir(parents=True)
            legacy_payload = dict(SAMPLE_RESULTS)
            legacy_payload.pop("lane", None)
            legacy_payload.pop("workspace", None)
            (results_dir / "fuzz_results.json").write_text(
                json.dumps(legacy_payload),
                encoding="utf-8",
            )

            latest = ftc.discover_latest_fuzz_results(root, str(workspace))
            self.assertEqual(latest, results_dir / "fuzz_results.json")

    def test_cli_no_input_fails_without_workspace_results_and_passes_with_fixture(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fuzz_target_cli_") as raw:
            root = Path(raw)
            empty_workspace = root / "empty-spark"
            empty_workspace.mkdir()

            rc, payload, _ = _run_cli(root, empty_workspace, None)
            self.assertEqual(rc, 1, msg=payload)
            self.assertEqual(payload["verdict"], "fail-no-input")

            workspace = root / "spark"
            target = workspace / "src" / "fuzz" / "FuzzSparkMinimal.t.sol"
            results_dir = workspace / "fuzz_runs" / "20260525T120000Z"
            results_dir.mkdir(parents=True)
            target.parent.mkdir(parents=True)
            target.write_text("// spark fixture target\n", encoding="utf-8")
            _git(["init", "-q"], workspace)
            _git(["add", "."], workspace)
            _git(["commit", "-q", "--no-verify", "-m", "init"], workspace)
            (results_dir / "fuzz_results.json").write_text(
                (FIXTURE_DIR / "spark_minimal_fuzz_results.json").read_text(
                    encoding="utf-8"
                ),
                encoding="utf-8",
            )

            rc, payload, _ = _run_cli(root, workspace, None)
            self.assertEqual(rc, 0, msg=payload)
            self.assertEqual(payload["verdict"], "pass")
            self.assertEqual(payload["workspace"], "spark")
            self.assertEqual(payload["targets_found"], 1)
            self.assertEqual(payload["rows_appended"], 1)
            self.assertEqual(payload["input"], str(results_dir / "fuzz_results.json"))
            out_path = Path(payload["path"])
            self.assertTrue(out_path.is_file())
            self.assertIn("audit/corpus_tags/spark/fuzz_targets.jsonl", str(out_path))

    def test_makefile_wires_fuzz_quick(self) -> None:
        root = Path(__file__).resolve().parents[2]
        makefile = (root / "Makefile").read_text(encoding="utf-8")
        self.assertIn("fuzz-quick:", makefile)
        self.assertIn("fuzz-quick-test:", makefile)
        self.assertIn("tools/fuzz-target-corpus.py", makefile)


def _run_cli(repo_root: Path, workspace: Path, input_path: Path | None) -> tuple[int, dict, str]:
    cmd = [
        "python3",
        str(Path(__file__).resolve().parents[2] / "tools" / "fuzz-target-corpus.py"),
        "--workspace",
        str(workspace),
        "--repo-root",
        str(repo_root),
        "--json",
    ]
    if input_path is not None:
        cmd.extend(["--input", str(input_path)])
    out = subprocess.run(cmd, capture_output=True, text=True, check=False)
    try:
        payload = json.loads(out.stdout)
    except json.JSONDecodeError:
        payload = {"_raw": out.stdout, "_stderr": out.stderr}
    return out.returncode, payload, out.stderr


if __name__ == "__main__":
    unittest.main()
