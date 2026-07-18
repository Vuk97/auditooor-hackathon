from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "rust-detector-coverage.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location("rust_detector_coverage", TOOL)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules["rust_detector_coverage"] = module
    spec.loader.exec_module(module)
    return module


MOD = _load_tool()


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(text).strip() + "\n", encoding="utf-8")


class RustDetectorCoverageTests(unittest.TestCase):
    def test_build_inventory_defaults_to_latest_compatible_scanner_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(root / "tools" / "rust-detect.py", "def main(): return 0")
            _write(
                root / "Makefile",
                """
                rust-fixture-detector:
                \t@python3 tools/rust-detect.py --only "$(DETECTOR)"
                """,
            )
            _write(root / "detectors" / "rust_wave1" / "fresh_case.py", "def run(*args, **kwargs): return []")
            fixtures = root / "detectors" / "rust_wave1" / "test_fixtures"
            _write(fixtures / "test_detectors.sh", "DETECTORS=()\n")
            _write(fixtures / "fresh_case_positive.rs", "fn positive() {}")
            _write(fixtures / "fresh_case_negative.rs", "fn negative() {}")
            _write(
                root / "reports" / "scanner_wiring_truth_inventory_2026-05-05.json",
                """
                {
                  "schema": "auditooor.scanner_wiring_truth_inventory.v1",
                  "rows": [
                    {
                      "scanner_id": "fresh_case",
                      "source_paths": ["detectors/rust_wave1/fresh_case.py"],
                      "wiring_status": "rust_source_shape_only",
                      "proof_status": "source_shape_only",
                      "blockers": ["stale_blocker"]
                    }
                  ]
                }
                """,
            )
            _write(
                root / "reports" / "scanner_wiring_truth_inventory_2026-05-08.json",
                """
                {
                  "schema": "auditooor.scanner_wiring_truth_inventory.v1",
                  "rows": [
                    {
                      "scanner_id": "fresh_case",
                      "source_paths": ["detectors/rust_wave1/fresh_case.py"],
                      "wiring_status": "wired_verified",
                      "proof_status": "detector_and_fixture_pair_present",
                      "blockers": []
                    }
                  ]
                }
                """,
            )
            _write(
                root / "reports" / "scanner_wiring_burndown_queue_2026-05-05.json",
                """
                {
                  "schema": "auditooor.scanner_wiring_burndown_queue.v1",
                  "actions": [{"scanner_id": "fresh_case", "backend": "rust", "rank": 1, "priority_score": 11}]
                }
                """,
            )
            _write(
                root / "reports" / "scanner_wiring_burndown_queue_2026-05-08.json",
                """
                {
                  "schema": "auditooor.scanner_wiring_burndown_queue.v1",
                  "actions": [{"scanner_id": "fresh_case", "backend": "rust", "rank": 3, "priority_score": 33}]
                }
                """,
            )

            payload = MOD.build_inventory(root, top_n=5)
            row = {item["detector_id"]: item for item in payload["per_detector"]}["fresh_case"]

            self.assertEqual(payload["scanner_inputs"]["truth_report"], "reports/scanner_wiring_truth_inventory_2026-05-08.json")
            self.assertEqual(payload["scanner_inputs"]["burndown_report"], "reports/scanner_wiring_burndown_queue_2026-05-08.json")
            self.assertFalse(payload["scanner_inputs"]["refreshed_from_repo"])
            self.assertEqual(row["truth_inventory_wiring_status"], "wired_verified")
            self.assertEqual(row["truth_inventory_proof_status"], "detector_and_fixture_pair_present")
            self.assertEqual(row["burndown_rank"], 3)
            self.assertEqual(row["burndown_priority_score"], 33)

    def test_build_inventory_explicit_scanner_inputs_take_precedence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(root / "tools" / "rust-detect.py", "def main(): return 0")
            _write(root / "detectors" / "rust_wave1" / "explicit_case.py", "def run(*args, **kwargs): return []")
            fixtures = root / "detectors" / "rust_wave1" / "test_fixtures"
            _write(fixtures / "test_detectors.sh", "DETECTORS=()\n")
            _write(fixtures / "explicit_case_positive.rs", "fn positive() {}")
            _write(fixtures / "explicit_case_negative.rs", "fn negative() {}")
            stale_truth = root / "reports" / "scanner_wiring_truth_inventory_2026-05-05.json"
            latest_truth = root / "reports" / "scanner_wiring_truth_inventory_2026-05-08.json"
            stale_burndown = root / "reports" / "scanner_wiring_burndown_queue_2026-05-05.json"
            latest_burndown = root / "reports" / "scanner_wiring_burndown_queue_2026-05-08.json"
            _write(
                stale_truth,
                """
                {
                  "schema": "auditooor.scanner_wiring_truth_inventory.v1",
                  "rows": [
                    {
                      "scanner_id": "explicit_case",
                      "source_paths": ["detectors/rust_wave1/explicit_case.py"],
                      "wiring_status": "explicit_status",
                      "proof_status": "explicit_proof",
                      "blockers": ["explicit_blocker"]
                    }
                  ]
                }
                """,
            )
            _write(
                latest_truth,
                """
                {
                  "schema": "auditooor.scanner_wiring_truth_inventory.v1",
                  "rows": [
                    {
                      "scanner_id": "explicit_case",
                      "source_paths": ["detectors/rust_wave1/explicit_case.py"],
                      "wiring_status": "latest_status",
                      "proof_status": "latest_proof",
                      "blockers": []
                    }
                  ]
                }
                """,
            )
            _write(
                stale_burndown,
                """
                {
                  "schema": "auditooor.scanner_wiring_burndown_queue.v1",
                  "actions": [{"scanner_id": "explicit_case", "backend": "rust", "rank": 2, "priority_score": 22}]
                }
                """,
            )
            _write(
                latest_burndown,
                """
                {
                  "schema": "auditooor.scanner_wiring_burndown_queue.v1",
                  "actions": [{"scanner_id": "explicit_case", "backend": "rust", "rank": 8, "priority_score": 88}]
                }
                """,
            )

            payload = MOD.build_inventory(
                root,
                truth_report=stale_truth,
                burndown_report=stale_burndown,
                top_n=5,
            )
            row = {item["detector_id"]: item for item in payload["per_detector"]}["explicit_case"]

            self.assertEqual(payload["scanner_inputs"]["truth_report"], "reports/scanner_wiring_truth_inventory_2026-05-05.json")
            self.assertEqual(payload["scanner_inputs"]["burndown_report"], "reports/scanner_wiring_burndown_queue_2026-05-05.json")
            self.assertEqual(row["truth_inventory_wiring_status"], "explicit_status")
            self.assertEqual(row["truth_inventory_proof_status"], "explicit_proof")
            self.assertEqual(row["truth_inventory_blockers"], ["explicit_blocker"])
            self.assertEqual(row["burndown_rank"], 2)
            self.assertEqual(row["burndown_priority_score"], 22)

    def test_build_inventory_surfaces_truncated_truth_warning(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(root / "tools" / "rust-detect.py", "def main(): return 0")
            _write(root / "detectors" / "rust_wave1" / "truncated_case.py", "def run(*args, **kwargs): return []")
            fixtures = root / "detectors" / "rust_wave1" / "test_fixtures"
            _write(fixtures / "test_detectors.sh", "DETECTORS=()\n")
            _write(fixtures / "truncated_case_positive.rs", "fn positive() {}")
            _write(fixtures / "truncated_case_negative.rs", "fn negative() {}")
            _write(
                root / "reports" / "scanner_wiring_truth_inventory_2026-05-08.json",
                """
                {
                  "schema": "auditooor.scanner_wiring_truth_inventory.v1",
                  "truncated": true,
                  "item_count": 1,
                  "total_row_count": 100,
                  "rows": [
                    {
                      "scanner_id": "truncated_case",
                      "source_paths": ["detectors/rust_wave1/truncated_case.py"],
                      "wiring_status": "wired_verified",
                      "proof_status": "detector_and_fixture_pair_present",
                      "blockers": []
                    }
                  ]
                }
                """,
            )
            _write(
                root / "reports" / "scanner_wiring_burndown_queue_2026-05-08.json",
                """
                {
                  "schema": "auditooor.scanner_wiring_burndown_queue.v1",
                  "actions": [{"scanner_id": "truncated_case", "backend": "rust", "rank": 1, "priority_score": 1}]
                }
                """,
            )

            payload = MOD.build_inventory(root, top_n=5)

            self.assertTrue(payload["scanner_inputs"]["truth_inventory_truncated"])
            self.assertEqual(payload["scanner_inputs"]["truth_inventory_total_row_count"], 100)
            self.assertEqual(payload["scanner_inputs"]["truth_inventory_item_count"], 1)
            self.assertIn("scanner truth inventory is truncated", payload["scanner_inputs"]["warnings"][0])

    def test_build_inventory_refreshes_scanner_inputs_from_repo(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(root / "tools" / "rust-detect.py", "def main(): return 0")
            _write(
                root / "Makefile",
                """
                rust-fixture-detector:
                \t@python3 tools/rust-detect.py --only "$(DETECTOR)"
                """,
            )
            _write(root / "detectors" / "rust_wave1" / "live_case.py", "def run(*args, **kwargs): return []")
            fixtures = root / "detectors" / "rust_wave1" / "test_fixtures"
            _write(fixtures / "test_detectors.sh", "DETECTORS=()\n")
            _write(fixtures / "live_case_positive.rs", "fn positive() {}")
            _write(fixtures / "live_case_negative.rs", "fn negative() {}")
            _write(
                root / "reports" / "scanner_wiring_truth_inventory_2026-05-05.json",
                """
                {
                  "schema": "auditooor.scanner_wiring_truth_inventory.v1",
                  "rows": [
                    {
                      "scanner_id": "live_case",
                      "source_paths": ["detectors/rust_wave1/live_case.py"],
                      "wiring_status": "stale_status",
                      "proof_status": "stale_proof",
                      "blockers": ["stale_blocker"]
                    }
                  ]
                }
                """,
            )
            _write(
                root / "tools" / "scanner-wiring-truth-inventory.py",
                """
                def build_inventory(repo_root, limit=None):
                    return {
                        "schema": "auditooor.scanner_wiring_truth_inventory.v1",
                        "limit": limit,
                        "rows": [
                            {
                                "scanner_id": "live_case",
                                "source_paths": ["detectors/rust_wave1/live_case.py"],
                                "wiring_status": "rust_source_shape_only",
                                "proof_status": "source_shape_only",
                                "blockers": ["live_blocker"]
                            }
                        ],
                    }
                """,
            )
            _write(
                root / "tools" / "scanner-wiring-burndown.py",
                """
                def build_burndown_queue(inventory, action_limit=0, per_lane_limit=0):
                    return {
                        "schema": "auditooor.scanner_wiring_burndown_queue.v1",
                        "actions": [
                            {
                                "scanner_id": "live_case",
                                "backend": "rust",
                                "rank": 9,
                                "priority_score": 123
                            }
                        ],
                    }
                """,
            )

            payload = MOD.build_inventory(root, refresh_scanner_inputs=True, live_inventory_limit=7, top_n=5)
            row = {item["detector_id"]: item for item in payload["per_detector"]}["live_case"]

            self.assertEqual(payload["scanner_inputs"]["truth_report"], f"live:{root.resolve()}")
            self.assertEqual(payload["scanner_inputs"]["burndown_report"], f"live:{root.resolve()}")
            self.assertTrue(payload["scanner_inputs"]["refreshed_from_repo"])
            self.assertEqual(payload["scanner_inputs"]["live_inventory_limit"], 7)
            self.assertEqual(row["truth_inventory_wiring_status"], "rust_source_shape_only")
            self.assertIn("live_blocker", row["truth_inventory_blockers"])
            self.assertEqual(row["burndown_rank"], 9)
            self.assertEqual(row["burndown_priority_score"], 123)

    def test_build_inventory_counts_fixture_and_runner_gaps(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(root / "tools" / "rust-detect.py", "def main(): return 0")
            _write(root / "tools" / "inventory-smoke-rust.py", "def main(): return 0")
            _write(
                root / "Makefile",
                """
                rust-fixture-detector:
                \t@python3 tools/rust-detect.py --only "$(DETECTOR)"

                inventory-smoke-detector:
                \t@python3 tools/inventory-smoke-test.py --detector "$(DETECTOR)"
                """,
            )
            _write(
                root / "detectors" / "rust_wave1" / "test_fixtures" / "test_detectors.sh",
                """
                DETECTORS=(
                  top_ok
                )
                """,
            )
            _write(root / "detectors" / "rust_wave1" / "top_ok.py", "def run(*args, **kwargs): return []")
            _write(root / "detectors" / "rust_wave1" / "draft_gap.py", "def run(*args, **kwargs): return []")
            _write(
                root / "detectors" / "rust_wave1" / "r76_stablecoin_rust" / "nested_gap.py",
                "def run(*args, **kwargs): return []",
            )
            _write(
                root / "reports" / "scanner_wiring_truth_inventory_2026-05-05.json",
                """
                {
                  "rows": [
                    {
                      "scanner_id": "draft_gap",
                      "source_paths": ["detectors/rust_wave1/draft_gap.py"],
                      "wiring_status": "rust_source_shape_only",
                      "proof_status": "source_shape_only",
                      "blockers": ["positive_or_vulnerable_fixture_missing"]
                    }
                  ]
                }
                """,
            )
            _write(
                root / "reports" / "scanner_wiring_burndown_queue_2026-05-05.json",
                """
                {
                  "actions": [
                    {
                      "scanner_id": "draft_gap",
                      "backend": "rust",
                      "priority_score": 300,
                      "rank": 7
                    }
                  ]
                }
                """,
            )
            fixtures = root / "detectors" / "rust_wave1" / "test_fixtures"
            (fixtures / "top_ok_positive.rs").write_text("fn positive() {}\n", encoding="utf-8")
            (fixtures / "top_ok_negative.rs").write_text("fn negative() {}\n", encoding="utf-8")

            payload = MOD.build_inventory(root, top_n=5)

            self.assertEqual(payload["detector_count"]["total"], 3)
            self.assertEqual(payload["detector_count"]["top_level_loader_visible"], 2)
            self.assertEqual(payload["detector_count"]["nested_outside_current_loader"], 0)
            self.assertEqual(payload["fixture_count"]["fixture_pairs"], 1)
            self.assertEqual(payload["missing_fixture"]["count"], 2)
            self.assertEqual(payload["runner_status"]["single_detector_loader_missing_count"], 0)
            self.assertEqual(payload["runner_status"]["inventory_smoke_rust_supported_count"], 3)
            self.assertEqual(payload["runner_status"]["full_regression_script_missing_count"], 2)
            self.assertFalse(payload["runner_status"]["inventory_smoke_make_target"]["rust_applicable"])

            rows = {row["detector_id"]: row for row in payload["per_detector"]}
            self.assertTrue(rows["top_ok"]["fixture_pair_present"])
            self.assertFalse(rows["top_ok"]["missing_runner_hook"])
            self.assertTrue(rows["nested_gap"]["nested_detector"])
            self.assertTrue(rows["nested_gap"]["selectable_via_rust_detect_only"])
            self.assertTrue(rows["nested_gap"]["selectable_via_inventory_smoke_rust"])
            self.assertTrue(rows["nested_gap"]["missing_runner_hook"])
            self.assertEqual(rows["draft_gap"]["truth_inventory_wiring_status"], "rust_source_shape_only")
            self.assertEqual(rows["draft_gap"]["burndown_priority_score"], 300)

    def test_cli_writes_json_and_markdown_without_rust_inventory_make_command(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(root / "tools" / "rust-detect.py", "def main(): return 0")
            _write(root / "tools" / "inventory-smoke-rust.py", "def main(): return 0")
            _write(
                root / "Makefile",
                """
                rust-fixture-detector:
                \t@python3 tools/rust-detect.py --only "$(DETECTOR)"

                inventory-smoke-detector:
                \t@python3 tools/inventory-smoke-test.py --detector "$(DETECTOR)"
                """,
            )
            _write(
                root / "detectors" / "rust_wave1" / "test_fixtures" / "test_detectors.sh",
                """
                DETECTORS=(
                  stable_ok
                )
                """,
            )
            _write(root / "detectors" / "rust_wave1" / "stable_ok.py", "def run(*args, **kwargs): return []")
            _write(
                root / "detectors" / "rust_wave1" / "test_fixtures" / "stable_ok_positive.rs",
                "fn positive() {}",
            )
            _write(
                root / "detectors" / "rust_wave1" / "test_fixtures" / "stable_ok_negative.rs",
                "fn negative() {}",
            )

            json_out = root / "out" / "coverage.json"
            md_out = root / "out" / "coverage.md"
            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    str(root),
                    "--json-out",
                    str(json_out),
                    "--md-out",
                    str(md_out),
                    "--top",
                    "1",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads(json_out.read_text(encoding="utf-8"))
            self.assertEqual(payload["schema"], "auditooor.rust_detector_coverage.v1")
            markdown = md_out.read_text(encoding="utf-8")
            self.assertIn("make rust-fixture-detector DETECTOR=stable_ok", markdown)
            self.assertNotIn("make inventory-smoke-detector DETECTOR=stable_ok", markdown)

    def test_report_backed_regression_does_not_claim_helper_coverage_without_per_detector_rows(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(root / "tools" / "rust-detect.py", "def main(): return 0")
            _write(root / "tools" / "inventory-smoke-rust.py", "def main(): return 0")
            _write(root / "tools" / "rust-fixture-regression-list.py", "def main(): return 0")
            _write(
                root / "Makefile",
                """
                rust-fixture-detector:
                \t@python3 tools/rust-detect.py --only "$(DETECTOR)"
                """,
            )
            _write(
                root / "detectors" / "rust_wave1" / "test_fixtures" / "test_detectors.sh",
                """
                DETECTORS=(
                  statically_listed
                )

                if [[ -f "$TOOLS/rust-fixture-regression-list.py" ]]; then
                  while IFS= read -r det; do
                    [[ -n "$det" ]] && DETECTORS+=("$det")
                  done < <(python3 "$TOOLS/rust-fixture-regression-list.py" \
                      --repo "$HERE/../../.." \
                      --report "$HERE/../../../reports/rust_detector_coverage_2026-05-05.json")
                fi
                """,
            )
            for detector in ("statically_listed", "helper_backed_gap"):
                _write(root / "detectors" / "rust_wave1" / f"{detector}.py", "def run(*args, **kwargs): return []")
                _write(
                    root / "detectors" / "rust_wave1" / "test_fixtures" / f"{detector}_positive.rs",
                    "fn positive() {}",
                )
                _write(
                    root / "detectors" / "rust_wave1" / "test_fixtures" / f"{detector}_negative.rs",
                    "fn negative() {}",
                )
            _write(
                root / "reports" / "scanner_wiring_truth_inventory_2026-05-05.json",
                '{"rows": []}',
            )
            _write(
                root / "reports" / "scanner_wiring_burndown_queue_2026-05-05.json",
                '{"actions": []}',
            )
            _write(
                root / "reports" / "rust_detector_coverage_2026-05-05.json",
                """
                {
                  "missing_runner_hook": {
                    "detectors": [
                      {
                        "detector_id": "helper_backed_gap",
                        "fixture_pair_present": true,
                        "nested_detector": false,
                        "detector_group": "rust_wave1"
                      }
                    ]
                  }
                }
                """,
            )

            payload = MOD.build_inventory(root, top_n=5)
            rows = {row["detector_id"]: row for row in payload["per_detector"]}

            self.assertTrue(payload["runner_status"]["full_regression_uses_report_backed_list"])
            self.assertEqual(payload["runner_status"]["full_regression_script_covered_count"], 1)
            self.assertEqual(payload["runner_status"]["full_regression_script_missing_count"], 1)
            self.assertTrue(rows["statically_listed"]["listed_in_full_regression_script"])
            self.assertFalse(rows["helper_backed_gap"]["listed_in_full_regression_script"])
            self.assertIn(
                "detectors/rust_wave1/test_fixtures/test_detectors.sh does not list or dynamically include this detector",
                rows["helper_backed_gap"]["runner_gaps"],
            )

    def test_fixture_backed_nested_rows_normalize_stale_truth_fixture_blockers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(root / "tools" / "rust-detect.py", "def main(): return 0")
            _write(root / "tools" / "inventory-smoke-rust.py", "def main(): return 0")
            _write(
                root / "Makefile",
                """
                rust-fixture-detector:
                \t@python3 tools/rust-detect.py --only "$(DETECTOR)"
                """,
            )
            _write(
                root / "detectors" / "rust_wave1" / "r76_stablecoin_rust" / "nested_gap.py",
                "def run(*args, **kwargs): return []",
            )
            fixtures = root / "detectors" / "rust_wave1" / "test_fixtures"
            _write(fixtures / "test_detectors.sh", "DETECTORS=()\n")
            _write(fixtures / "nested_gap_positive.rs", "fn positive() {}")
            _write(fixtures / "nested_gap_negative.rs", "fn negative() {}")
            _write(
                root / "reports" / "scanner_wiring_truth_inventory_2026-05-05.json",
                """
                {
                  "rows": [
                    {
                      "scanner_id": "nested_gap",
                      "source_paths": ["detectors/rust_wave1/r76_stablecoin_rust/nested_gap.py"],
                      "wiring_status": "rust_source_shape_only",
                      "proof_status": "rust_detector_without_fixture_pair",
                      "blockers": [
                        "clean_or_negative_fixture_missing",
                        "positive_or_vulnerable_fixture_missing",
                        "rust_runtime_semantics_unverified"
                      ]
                    }
                  ]
                }
                """,
            )
            _write(
                root / "reports" / "scanner_wiring_burndown_queue_2026-05-05.json",
                '{"actions": []}',
            )

            payload = MOD.build_inventory(root, top_n=5)
            row = {item["detector_id"]: item for item in payload["per_detector"]}["nested_gap"]

            self.assertTrue(row["fixture_pair_present"])
            self.assertTrue(row["selectable_via_rust_detect_only"])
            self.assertEqual(
                row["truth_inventory_proof_status"],
                "fixture_pair_present_but_runner_unverified",
            )
            self.assertNotIn("clean_or_negative_fixture_missing", row["truth_inventory_blockers"])
            self.assertNotIn("positive_or_vulnerable_fixture_missing", row["truth_inventory_blockers"])
            self.assertNotIn("rust_subdirectory_loader_unreachable", row["truth_inventory_blockers"])
            self.assertIn("rust_runtime_semantics_unverified", row["truth_inventory_blockers"])


if __name__ == "__main__":
    unittest.main()
