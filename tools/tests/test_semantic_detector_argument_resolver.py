from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "semantic-detector-argument-resolver.py"


def _write_tasks(ws: Path) -> None:
    audit_dir = ws / ".auditooor"
    audit_dir.mkdir(parents=True)
    fixture_root = ws / "detectors" / "fixtures"
    for slug, idx in (
        ("implemented_pattern", "001"),
        ("pattern_only", "002"),
        ("missing_detector", "003"),
        ("extract_failed", "004"),
    ):
        row_dir = fixture_root / slug
        row_dir.mkdir(parents=True)
        (row_dir / f"ssi-fix-{idx}_positive.sol").write_text("contract Positive {}\n", encoding="utf-8")
        (row_dir / f"ssi-fix-{idx}_clean.sol").write_text("contract Clean {}\n", encoding="utf-8")
        argument = slug.replace("_", "-")
        (row_dir / f"ssi-fix-{idx}_manifest.json").write_text(
            json.dumps(
                {
                    "schema": "auditooor.semantic_fixture_materialization.v1",
                    "queue_id": f"SSI-Q-{idx}",
                    "argv": [
                        "python3",
                        "tools/p1-fixture-extractor.py",
                        "--pattern",
                        argument,
                    ],
                    "source_pattern_path": str(ws / "detectors" / "_specs" / "drafts_solodit" / f"{argument}.yaml"),
                    "detector_slug": slug,
                }
            ),
            encoding="utf-8",
        )

    rows = []
    for slug, idx, terminal_state in (
        ("implemented_pattern", "001", "terminal_cannot_run_dependency_preflight"),
        ("pattern_only", "002", "terminal_cannot_run_dependency_preflight"),
        ("missing_detector", "003", "terminal_cannot_run_dependency_preflight"),
        ("extract_failed", "004", "terminal_extraction_failed"),
    ):
        argument = slug.replace("_", "-")
        row_dir = fixture_root / slug
        rows.append(
            {
                "queue_id": f"SSI-Q-{idx}",
                "inventory_id": f"SSI-{idx}",
                "terminal_state": terminal_state,
                "source_component": f"detectors/_specs/drafts_solodit/{argument}.yaml",
                "suggested_detector_slug": slug,
                "positive_fixture_path": str(row_dir / f"ssi-fix-{idx}_positive.sol"),
                "clean_fixture_path": str(row_dir / f"ssi-fix-{idx}_clean.sol"),
                "smoke_record_path": str(row_dir / f"ssi-fix-{idx}_smoke.json"),
                "fixture_manifest_path": str(row_dir / f"ssi-fix-{idx}_manifest.json"),
                "dependency_preflight": {
                    "detector_argument_inference": {
                        "ok": False,
                        "argument": argument,
                        "inference": {
                            "argument": argument,
                            "source": "manifest_argv_pattern",
                            "confidence": "high",
                        },
                    }
                },
            }
        )
    (audit_dir / "semantic_fixture_smoke_tasks.json").write_text(
        json.dumps({"schema": "auditooor.semantic_fixture_smoke_tasks.v1", "rows": rows}),
        encoding="utf-8",
    )

    detector_dir = ws / "detectors" / "wave_test"
    detector_dir.mkdir(parents=True)
    (detector_dir / "implemented_pattern.py").write_text(
        'class ImplementedPattern:\n    ARGUMENT = "implemented-pattern"\n',
        encoding="utf-8",
    )
    pattern_dir = ws / "detectors" / "_specs" / "drafts_solodit"
    pattern_dir.mkdir(parents=True)
    (pattern_dir / "pattern-only.yaml").write_text("id: pattern-only\n", encoding="utf-8")


def _run(*args: Path | str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(arg) for arg in args],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


class SemanticDetectorArgumentResolverTest(unittest.TestCase):
    def test_resolver_wires_only_exact_detector_matches(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write_tasks(ws)
            proc = _run(sys.executable, TOOL, "--workspace", ws)
            self.assertEqual(proc.returncode, 0, proc.stderr or proc.stdout)
            payload = json.loads((ws / ".auditooor" / "semantic_detector_argument_resolver.json").read_text())
            self.assertEqual(payload["schema"], "auditooor.semantic_detector_argument_resolver.v1")
            self.assertEqual(payload["processed_count"], 4)
            self.assertEqual(payload["smoke_execution_wired_count"], 1)
            self.assertEqual(payload["terminal_detector_argument_blocker_count"], 2)
            self.assertEqual(payload["terminal_extraction_failed_count"], 1)
            rows = {row["queue_id"]: row for row in payload["rows"]}
            self.assertEqual(rows["SSI-Q-001"]["resolution"], "smoke_execution_wired_existing_detector")
            self.assertIn("detectors/run_custom.py", rows["SSI-Q-001"]["smoke_commands"]["positive"])
            self.assertEqual(rows["SSI-Q-002"]["resolution"], "terminal_pattern_without_detector_implementation")
            self.assertEqual(rows["SSI-Q-003"]["resolution"], "terminal_missing_detector_implementation")
            self.assertEqual(rows["SSI-Q-004"]["resolution"], "terminal_extraction_failed_detector_argument_unresolved")
            self.assertFalse(payload["promotion_allowed"])
            self.assertTrue(all(row["submission_posture"] == "NOT_SUBMIT_READY" for row in payload["rows"]))

    def test_limit_bounds_processed_rows_for_large_closure_batches(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write_tasks(ws)
            proc = _run(sys.executable, TOOL, "--workspace", ws, "--limit", "2")
            self.assertEqual(proc.returncode, 0, proc.stderr or proc.stdout)
            payload = json.loads((ws / ".auditooor" / "semantic_detector_argument_resolver.json").read_text())
            self.assertEqual(payload["limit"], 2)
            self.assertEqual(payload["processed_count"], 2)
            self.assertEqual(payload["source_row_count"], 2)

    def test_generated_detector_fixture_pair_unblocks_materialized_detector(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write_tasks(ws)
            semantic_dir = ws / "detectors" / "fixtures" / "implemented_pattern"
            for path in semantic_dir.glob("*.sol"):
                path.unlink()
            generated_dir = ws / "detectors" / "test_fixtures"
            generated_dir.mkdir(parents=True)
            (generated_dir / "implemented_pattern_vulnerable.sol").write_text(
                "contract GeneratedPositive {}\n",
                encoding="utf-8",
            )
            (generated_dir / "implemented_pattern_clean.sol").write_text(
                "contract GeneratedClean {}\n",
                encoding="utf-8",
            )

            proc = _run(sys.executable, TOOL, "--workspace", ws, "--limit", "1")
            self.assertEqual(proc.returncode, 0, proc.stderr or proc.stdout)
            payload = json.loads((ws / ".auditooor" / "semantic_detector_argument_resolver.json").read_text())
            row = payload["rows"][0]
            self.assertEqual(row["resolution"], "smoke_execution_wired_existing_detector")
            self.assertEqual(row["fixture_pair_source"], "generated_detector_fixture_pair")
            self.assertIn("detectors/test_fixtures/implemented_pattern_vulnerable.sol", row["smoke_commands"]["positive"])


if __name__ == "__main__":
    unittest.main()
