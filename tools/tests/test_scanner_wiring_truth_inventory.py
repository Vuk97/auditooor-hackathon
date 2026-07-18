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
TOOL = ROOT / "tools" / "scanner-wiring-truth-inventory.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location("scanner_wiring_truth_inventory", TOOL)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules["scanner_wiring_truth_inventory"] = module
    spec.loader.exec_module(module)
    return module


MOD = _load_tool()


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(text).strip() + "\n", encoding="utf-8")


class ScannerWiringTruthInventoryTests(unittest.TestCase):
    def test_dsl_only_pattern_is_blocked_and_unverified(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(
                root / "reference" / "patterns.dsl.r1" / "alias-check.yaml",
                """
                pattern: alias-check
                backend: solidity
                match:
                  - function.body_contains_regex: msg.sender
                """,
            )

            payload = MOD.build_inventory(root, limit=20)
            rows = {row["pattern_id"]: row for row in payload["rows"] if row["pattern_id"]}
            row = rows["alias-check"]
            self.assertEqual(row["evidence_kind"], "dsl_yaml")
            self.assertEqual(row["wiring_status"], "dsl_only_or_unverified")
            self.assertEqual(row["proof_status"], "no_detector_or_fixture_evidence")
            self.assertIn("detector_file_missing", row["blockers"])
            self.assertEqual(row["backend"], "solidity")

    def test_detector_with_positive_and_clean_fixture_is_verified(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(
                root / "detectors" / "rust_wave1" / "abi_mismatch.py",
                """
                from __future__ import annotations

                def run(tree, source: bytes, filepath: str):
                    return []
                """,
            )
            _write(root / "detectors" / "_fixtures" / "abi_mismatch" / "case_vulnerable.rs", "fn vulnerable() {}")
            _write(root / "detectors" / "_fixtures" / "abi_mismatch" / "case_clean.rs", "fn clean() {}")
            _write(root / "tools" / "rust-detect.py", "def main(): return 0")

            payload = MOD.build_inventory(root, limit=20)
            rows = {row["scanner_id"]: row for row in payload["rows"] if row["scanner_id"]}
            row = rows["abi_mismatch"]
            self.assertEqual(row["wiring_status"], "wired_verified")
            self.assertEqual(row["proof_status"], "detector_and_fixture_pair_present")
            self.assertEqual(row["blockers"], [])
            self.assertTrue(any(path.endswith("case_vulnerable.rs") for path in row["source_paths"]))
            self.assertTrue(any(path.endswith("case_clean.rs") for path in row["source_paths"]))

    def test_dsl_with_matching_verified_detector_is_not_marked_fake_from_exploit_prose(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(
                root / "reference" / "patterns.dsl" / "can-withdraw-uses-entry-price.yaml",
                """
                pattern: can-withdraw-uses-entry-price
                source: cantina/synthetic-asset-class
                match:
                  - function.body_contains_regex: fake receipt
                help: "A fake receipt in exploit prose is not quarantine metadata."
                """,
            )
            _write(
                root / "detectors" / "wave17" / "can_withdraw_uses_entry_price.py",
                """
                from slither.detectors.abstract_detector import AbstractDetector
                class Detector(AbstractDetector):
                    ARGUMENT = "can-withdraw-uses-entry-price"
                """,
            )
            _write(root / "patterns" / "fixtures" / "can-withdraw-uses-entry-price_vuln.sol", "contract Bad {}")
            _write(root / "patterns" / "fixtures" / "can-withdraw-uses-entry-price_clean.sol", "contract Good {}")

            payload = MOD.build_inventory(root, limit=20)
            rows = [
                row
                for row in payload["rows"]
                if row["pattern_id"] == "can-withdraw-uses-entry-price"
            ]
            self.assertEqual(len(rows), 1)
            row = rows[0]
            self.assertEqual(row["evidence_kind"], "dsl_yaml_with_detector_fixture_pair")
            self.assertEqual(row["wiring_status"], "wired_verified")
            self.assertEqual(row["proof_status"], "detector_and_fixture_pair_present")
            self.assertEqual(row["backend"], "solidity")
            self.assertEqual(row["blockers"], [])
            self.assertTrue(any(path.endswith("can_withdraw_uses_entry_price.py") for path in row["source_paths"]))
            self.assertTrue(any(path.endswith("can-withdraw-uses-entry-price_vuln.sol") for path in row["source_paths"]))

    def test_dsl_requires_explicit_fake_marker_for_quarantine(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(
                root / "reference" / "patterns.dsl" / "fake-receipt-race.yaml",
                """
                pattern: fake-receipt-race
                help: "Exploit uses a fake receipt, but this is not scanner quarantine proof."
                """,
            )
            _write(
                root / "reference" / "patterns.dsl" / "explicit-fake.yaml",
                """
                pattern: explicit-fake
                status: suspect
                help: "Explicit scanner wiring marker."
                """,
            )

            payload = MOD.build_inventory(root, limit=20)
            rows = {row["pattern_id"]: row for row in payload["rows"] if row["pattern_id"]}
            self.assertEqual(rows["fake-receipt-race"]["wiring_status"], "dsl_only_or_unverified")
            self.assertEqual(rows["explicit-fake"]["wiring_status"], "in_dsl_fake_suspect")

    def test_nested_detector_test_fixtures_are_indexed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(
                root / "detectors" / "rust_wave1" / "nested_case.py",
                """
                from __future__ import annotations

                def run(tree, source: bytes, filepath: str):
                    return []
                """,
            )
            _write(root / "detectors" / "rust_wave1" / "test_fixtures" / "nested_case_positive.rs", "fn positive() {}")
            _write(root / "detectors" / "rust_wave1" / "test_fixtures" / "nested_case_negative.rs", "fn negative() {}")

            payload = MOD.build_inventory(root, limit=20)
            rows = {row["scanner_id"]: row for row in payload["rows"] if row["scanner_id"]}
            row = rows["nested_case"]
            self.assertEqual(row["wiring_status"], "wired_verified")
            self.assertEqual(row["blockers"], [])
            self.assertTrue(any(path.endswith("nested_case_positive.rs") for path in row["source_paths"]))
            self.assertTrue(any(path.endswith("nested_case_negative.rs") for path in row["source_paths"]))

    def test_legacy_broken_fixture_roots_are_indexed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(
                root / "detectors" / "wave17" / "legacy_case.py",
                """
                from slither.detectors.abstract_detector import AbstractDetector
                class Detector(AbstractDetector):
                    ARGUMENT = "legacy-case"
                """,
            )
            _write(root / "detectors" / "wave14_broken" / "legacy_case_vulnerable.sol", "contract Bad {}")
            _write(root / "detectors" / "wave14_broken" / "legacy_case_clean.sol", "contract Good {}")

            payload = MOD.build_inventory(root, limit=20)
            rows = {row["scanner_id"]: row for row in payload["rows"] if row["scanner_id"]}
            row = rows["legacy_case"]
            self.assertEqual(row["wiring_status"], "wired_verified")
            self.assertEqual(row["proof_status"], "detector_and_fixture_pair_present")
            self.assertEqual(row["blockers"], [])
            self.assertTrue(any(path.endswith("wave14_broken/legacy_case_vulnerable.sol") for path in row["source_paths"]))
            self.assertTrue(any(path.endswith("wave14_broken/legacy_case_clean.sol") for path in row["source_paths"]))

    def test_graveyard_detector_duplicate_does_not_override_live_verified_detector(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(
                root / "reference" / "patterns.dsl" / "duplicate-case.yaml",
                """
                pattern: duplicate-case
                backend: solidity
                """,
            )
            _write(
                root / "detectors" / "wave17" / "duplicate_case.py",
                """
                from slither.detectors.abstract_detector import AbstractDetector
                class Detector(AbstractDetector):
                    ARGUMENT = "duplicate-case"
                """,
            )
            _write(
                root / "detectors" / "wave_graveyard" / "wave13_broken" / "duplicate_case.py",
                """
                from slither.detectors.abstract_detector import AbstractDetector
                class Detector(AbstractDetector):
                    ARGUMENT = "duplicate-case"
                """,
            )
            _write(root / "detectors" / "fixtures" / "duplicate_case" / "positive.sol", "contract Bad {}")
            _write(root / "detectors" / "fixtures" / "duplicate_case" / "clean.sol", "contract Good {}")

            payload = MOD.build_inventory(root, limit=50)
            detector_rows = [
                row for row in payload["rows"] if row["scanner_id"] == "duplicate_case"
            ]
            dsl_row = next(row for row in payload["rows"] if row["pattern_id"] == "duplicate-case")
            live_row = next(
                row for row in detector_rows if any(path == "detectors/wave17/duplicate_case.py" for path in row["source_paths"])
            )
            graveyard_row = next(
                row
                for row in detector_rows
                if any(path == "detectors/wave_graveyard/wave13_broken/duplicate_case.py" for path in row["source_paths"])
            )

            self.assertEqual(live_row["wiring_status"], "wired_verified")
            self.assertEqual(graveyard_row["wiring_status"], "quarantined_fake")
            self.assertIn("graveyard_or_broken_path_present", graveyard_row["blockers"])
            self.assertEqual(dsl_row["wiring_status"], "wired_verified")
            self.assertIn("detectors/wave17/duplicate_case.py", dsl_row["source_paths"])
            self.assertNotIn("detectors/wave_graveyard/wave13_broken/duplicate_case.py", dsl_row["source_paths"])

    def test_live_wave17_detector_wins_over_same_id_graveyard_detector_smoke_binding(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cases = [
                "erc20permit-auth-replay-protection",
                "erc4626-deposit-math-drift",
            ]

            for pattern_id in cases:
                with self.subTest(pattern_id=pattern_id):
                    file_stem = pattern_id.replace("-", "_")
                    _write(
                        root / "reference" / "patterns.dsl" / f"{pattern_id}.yaml",
                        f"""
                        pattern: {pattern_id}
                        backend: solidity
                        """,
                    )
                    _write(
                        root / "detectors" / "wave17" / f"{file_stem}.py",
                        f"""
                        from slither.detectors.abstract_detector import AbstractDetector
                        class Detector(AbstractDetector):
                            ARGUMENT = "{pattern_id}"
                        """,
                    )
                    _write(
                        root
                        / "detectors"
                        / "wave_graveyard"
                        / "wave13_broken"
                        / f"{file_stem}.py",
                        f"""
                        from slither.detectors.abstract_detector import AbstractDetector
                        class Detector(AbstractDetector):
                            ARGUMENT = "{pattern_id}"
                        """,
                    )
                    fixture_dir = root / "detectors" / "fixtures" / file_stem
                    _write(fixture_dir / "vuln.sol", "contract Vuln {}")
                    _write(fixture_dir / "clean.sol", "contract Clean {}")
                    _write(
                        fixture_dir / "smoke.json",
                        f"""
                        {{
                          "schema": "auditooor.scanner_wiring_row_smoke.v1",
                          "status": "passed_vulnerable_clean_smoke",
                          "pattern": "{pattern_id}",
                          "detector_path": "detectors/wave_graveyard/wave13_broken/{file_stem}.py",
                          "positive_fixture": "vuln.sol",
                          "clean_fixture": "clean.sol"
                        }}
                        """,
                    )

            payload = MOD.build_inventory(root, limit=80)
            for pattern_id in cases:
                scanner_id = pattern_id.replace("-", "_")
                live_row = next(
                    row
                    for row in payload["rows"]
                    if row["scanner_id"] == scanner_id and any("wave17" in path for path in row["source_paths"])
                )
                graveyard_row = next(
                    row
                    for row in payload["rows"]
                    if row["scanner_id"] == scanner_id and any("wave_graveyard" in path for path in row["source_paths"])
                )

                self.assertEqual(live_row["wiring_status"], "wired_verified")
                self.assertEqual(live_row["proof_status"], "detector_and_fixture_pair_present")
                self.assertFalse(
                    any("wave_graveyard" in path for path in live_row["source_paths"]),
                    f"Expected live row to avoid graveyard source path for {scanner_id}",
                )
                self.assertEqual(graveyard_row["wiring_status"], "quarantined_fake")
                self.assertIn("graveyard_or_broken_path_present", graveyard_row["blockers"])

                dsl_row = next(row for row in payload["rows"] if row["pattern_id"] == pattern_id)
                self.assertEqual(dsl_row["wiring_status"], "wired_verified")
                self.assertEqual(dsl_row["proof_status"], "detector_and_fixture_pair_present")
                self.assertTrue(any("detectors/wave17" in path for path in dsl_row["source_paths"]))
                self.assertFalse(any("wave_graveyard" in path for path in dsl_row["source_paths"]))

    def test_smoke_backed_nested_positive_and_clean_directories_count_as_fixture_pair(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(
                root / "detectors" / "go_wave1" / "evmos_bank_send_to_blocklisted_module_account.py",
                """
                def run_text(source, filepath): return []
                """,
            )
            _write(
                root / "detectors" / "fixtures" / "evmos_bank_send_to_blocklisted_module_account" / "positive" / "go.mod",
                "module positive\n",
            )
            _write(
                root / "detectors" / "fixtures" / "evmos_bank_send_to_blocklisted_module_account" / "clean" / "go.mod",
                "module clean\n",
            )
            _write(
                root / "detectors" / "fixtures" / "evmos_bank_send_to_blocklisted_module_account" / "smoke.json",
                """
                {
                  "positive_fixture_path": "detectors/fixtures/evmos_bank_send_to_blocklisted_module_account/positive",
                  "clean_fixture_path": "detectors/fixtures/evmos_bank_send_to_blocklisted_module_account/clean"
                }
                """,
            )

            payload = MOD.build_inventory(root, limit=20)
            rows = {row["scanner_id"]: row for row in payload["rows"] if row["scanner_id"]}
            row = rows["evmos_bank_send_to_blocklisted_module_account"]
            self.assertEqual(row["wiring_status"], "wired_verified")
            self.assertEqual(row["proof_status"], "detector_and_fixture_pair_present")
            self.assertEqual(row["blockers"], [])
            self.assertIn(
                "detectors/fixtures/evmos_bank_send_to_blocklisted_module_account/positive/go.mod",
                row["source_paths"],
            )
            self.assertIn(
                "detectors/fixtures/evmos_bank_send_to_blocklisted_module_account/clean/go.mod",
                row["source_paths"],
            )

    def test_smoke_json_fixture_pointers_rescue_neutral_fixture_filenames(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(
                root / "detectors" / "wave17" / "neutral_case.py",
                """
                from slither.detectors.abstract_detector import AbstractDetector
                class Detector(AbstractDetector):
                    ARGUMENT = "neutral-case"
                """,
            )
            fixture_dir = root / "detectors" / "fixtures" / "neutral_case"
            _write(fixture_dir / "alpha.sol", "contract Alpha {}")
            _write(fixture_dir / "beta.sol", "contract Beta {}")
            _write(
                fixture_dir / "smoke.json",
                """
                {
                  "positive_fixture": "alpha.sol",
                  "clean_fixture": "beta.sol"
                }
                """,
            )

            payload = MOD.build_inventory(root, limit=20)
            rows = {row["scanner_id"]: row for row in payload["rows"] if row["scanner_id"]}
            row = rows["neutral_case"]
            self.assertEqual(row["wiring_status"], "wired_verified")
            self.assertEqual(row["proof_status"], "detector_and_fixture_pair_present")
            self.assertEqual(row["blockers"], [])
            self.assertIn("detectors/fixtures/neutral_case/alpha.sol", row["source_paths"])
            self.assertIn("detectors/fixtures/neutral_case/beta.sol", row["source_paths"])

    def test_closure_report_smoke_record_rescues_nonstandard_fixture_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(
                root / "detectors" / "wave17" / "report_backed_case.py",
                """
                # generated detector draft
                def run(tree, source: bytes, filepath: str):
                    return []
                """,
            )
            fixture_dir = root / "workspace_local_fixtures" / "report_backed_case"
            _write(fixture_dir / "left.sol", "contract Left {}")
            _write(fixture_dir / "right.sol", "contract Right {}")
            _write(
                fixture_dir / "smoke.json",
                """
                {
                  "schema": "auditooor.scanner_wiring_row_smoke.v1",
                  "status": "passed_vulnerable_clean_smoke",
                  "detector_path": "detectors/wave17/report_backed_case.py"
                }
                """,
            )
            _write(
                root / "reports" / "scanner_quarantine_closure_report_backed_case_2026-05-07.json",
                """
                {
                  "selected_row": "report_backed_case",
                  "closed": [
                    {
                      "row_id": "report_backed_case",
                      "detector": "detectors/wave17/report_backed_case.py",
                      "smoke_record": "workspace_local_fixtures/report_backed_case/smoke.json",
                      "fixture_pair": {
                        "vulnerable": "workspace_local_fixtures/report_backed_case/left.sol",
                        "clean": "workspace_local_fixtures/report_backed_case/right.sol"
                      }
                    }
                  ]
                }
                """,
            )

            payload = MOD.build_inventory(root, limit=20)
            rows = {row["scanner_id"]: row for row in payload["rows"] if row["scanner_id"]}
            row = rows["report_backed_case"]
            self.assertEqual(row["wiring_status"], "wired_verified")
            self.assertEqual(row["proof_status"], "detector_and_fixture_pair_present")
            self.assertEqual(row["blockers"], [])
            self.assertIn("workspace_local_fixtures/report_backed_case/left.sol", row["source_paths"])
            self.assertIn("workspace_local_fixtures/report_backed_case/right.sol", row["source_paths"])
            self.assertIn("workspace_local_fixtures/report_backed_case/smoke.json", row["source_paths"])

    def test_smoke_sidecar_metadata_rescues_nonstandard_fixture_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(
                root / "detectors" / "wave17" / "sidecar_bound_case.py",
                """
                # generated detector draft
                def run(tree, source: bytes, filepath: str):
                    return []
                """,
            )
            fixture_dir = root / "detectors" / "fixtures" / "row_123"
            _write(fixture_dir / "left.sol", "contract Left {}")
            _write(fixture_dir / "right.sol", "contract Right {}")
            _write(
                fixture_dir / "smoke.json",
                """
                {
                  "schema": "auditooor.scanner_wiring_row_smoke.v1",
                  "status": "passed_vulnerable_clean_smoke",
                  "pattern": "sidecar-bound-case",
                  "detector_path": "detectors/wave17/sidecar_bound_case.py",
                  "positive_fixture": "left.sol",
                  "clean_fixture": "right.sol",
                  "positive_hits": 1,
                  "clean_hits": 0,
                  "coverage_claim": "detector_fixture_smoke_only",
                  "promotion_allowed": false
                }
                """,
            )

            payload = MOD.build_inventory(root, limit=20)
            rows = {row["scanner_id"]: row for row in payload["rows"] if row["scanner_id"]}
            row = rows["sidecar_bound_case"]
            self.assertEqual(row["wiring_status"], "wired_verified")
            self.assertEqual(row["proof_status"], "detector_and_fixture_pair_present")
            self.assertEqual(row["blockers"], [])
            self.assertIn("detectors/fixtures/row_123/left.sol", row["source_paths"])
            self.assertIn("detectors/fixtures/row_123/right.sol", row["source_paths"])
            self.assertIn("detectors/fixtures/row_123/smoke.json", row["source_paths"])

    def test_manifest_sidecar_follows_smoke_record_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(
                root / "detectors" / "wave17" / "manifest_bound_case.py",
                """
                def run(tree, source: bytes, filepath: str):
                    return []
                """,
            )
            fixture_dir = root / "detectors" / "fixtures" / "row_456"
            _write(fixture_dir / "left.sol", "contract Left {}")
            _write(fixture_dir / "right.sol", "contract Right {}")
            _write(
                fixture_dir / "case_smoke.json",
                """
                {
                  "status": "passed_vulnerable_clean_smoke",
                  "pattern": "manifest-bound-case",
                  "detector_path": "detectors/wave17/manifest_bound_case.py",
                  "positive_fixture": "left.sol",
                  "clean_fixture": "right.sol"
                }
                """,
            )
            _write(
                fixture_dir / "case_manifest.json",
                """
                {
                  "schema": "auditooor.semantic_fixture_materialization.v1",
                  "pattern": "manifest-bound-case",
                  "detector_path": "detectors/wave17/manifest_bound_case.py",
                  "smoke_record_path": "detectors/fixtures/row_456/case_smoke.json"
                }
                """,
            )

            payload = MOD.build_inventory(root, limit=20)
            rows = {row["scanner_id"]: row for row in payload["rows"] if row["scanner_id"]}
            row = rows["manifest_bound_case"]
            self.assertEqual(row["wiring_status"], "wired_verified")
            self.assertEqual(row["proof_status"], "detector_and_fixture_pair_present")
            self.assertEqual(row["blockers"], [])
            self.assertIn("detectors/fixtures/row_456/case_manifest.json", row["source_paths"])
            self.assertIn("detectors/fixtures/row_456/case_smoke.json", row["source_paths"])
            self.assertIn("detectors/fixtures/row_456/left.sol", row["source_paths"])
            self.assertIn("detectors/fixtures/row_456/right.sol", row["source_paths"])

    def test_smoke_sidecar_metadata_does_not_cross_bind_other_detector(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(
                root / "detectors" / "wave17" / "sidecar_bound_case.py",
                """
                def run(tree, source: bytes, filepath: str):
                    return []
                """,
            )
            fixture_dir = root / "detectors" / "fixtures" / "row_123"
            _write(fixture_dir / "left.sol", "contract Left {}")
            _write(fixture_dir / "right.sol", "contract Right {}")
            _write(
                fixture_dir / "smoke.json",
                """
                {
                  "schema": "auditooor.scanner_wiring_row_smoke.v1",
                  "status": "passed_vulnerable_clean_smoke",
                  "pattern": "different-case",
                  "detector_path": "detectors/wave17/different_case.py",
                  "positive_fixture": "left.sol",
                  "clean_fixture": "right.sol"
                }
                """,
            )

            payload = MOD.build_inventory(root, limit=20)
            rows = {row["scanner_id"]: row for row in payload["rows"] if row["scanner_id"]}
            row = rows["sidecar_bound_case"]
            self.assertEqual(row["wiring_status"], "generated_no_fixture")
            self.assertEqual(row["proof_status"], "detector_without_fixture_pair")
            self.assertIn("positive_or_vulnerable_fixture_missing", row["blockers"])
            self.assertIn("clean_or_negative_fixture_missing", row["blockers"])

    def test_smoke_sidecar_metadata_requires_passing_status(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(
                root / "detectors" / "wave17" / "failing_smoke_case.py",
                """
                def run(tree, source: bytes, filepath: str):
                    return []
                """,
            )
            fixture_dir = root / "detectors" / "fixtures" / "row_123"
            _write(fixture_dir / "left.sol", "contract Left {}")
            _write(fixture_dir / "right.sol", "contract Right {}")
            _write(
                fixture_dir / "smoke.json",
                """
                {
                  "status": "failed_clean_hits",
                  "pattern": "failing-smoke-case",
                  "detector_path": "detectors/wave17/failing_smoke_case.py",
                  "positive_fixture": "left.sol",
                  "clean_fixture": "right.sol"
                }
                """,
            )

            payload = MOD.build_inventory(root, limit=20)
            rows = {row["scanner_id"]: row for row in payload["rows"] if row["scanner_id"]}
            row = rows["failing_smoke_case"]
            self.assertEqual(row["wiring_status"], "generated_no_fixture")
            self.assertIn("positive_or_vulnerable_fixture_missing", row["blockers"])
            self.assertIn("clean_or_negative_fixture_missing", row["blockers"])

    def test_smoke_sidecar_metadata_ignores_broken_wave_sidecars(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(
                root / "detectors" / "wave17" / "broken_sidecar_case.py",
                """
                def run(tree, source: bytes, filepath: str):
                    return []
                """,
            )
            fixture_dir = root / "detectors" / "wave13_broken"
            _write(fixture_dir / "left.sol", "contract Left {}")
            _write(fixture_dir / "right.sol", "contract Right {}")
            _write(
                fixture_dir / "broken_sidecar_case_smoke.json",
                """
                {
                  "status": "passed_vulnerable_clean_smoke",
                  "pattern": "broken-sidecar-case",
                  "detector_path": "detectors/wave17/broken_sidecar_case.py",
                  "positive_fixture": "left.sol",
                  "clean_fixture": "right.sol"
                }
                """,
            )

            payload = MOD.build_inventory(root, limit=20)
            rows = {row["scanner_id"]: row for row in payload["rows"] if row["scanner_id"]}
            row = rows["broken_sidecar_case"]
            self.assertEqual(row["wiring_status"], "generated_no_fixture")
            self.assertIn("positive_or_vulnerable_fixture_missing", row["blockers"])
            self.assertIn("clean_or_negative_fixture_missing", row["blockers"])

    def test_quarantine_detector_is_fake_not_wired(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(
                root
                / "detectors"
                / "wave14"
                / "_quarantine_in_dsl_regex_trick_2026-05-04"
                / "fake_guard.py",
                """
                # fake regex trick row
                def run(tree, source: bytes, filepath: str):
                    return []
                """,
            )

            payload = MOD.build_inventory(root, limit=20)
            quarantine = [
                row
                for row in payload["rows"]
                if "fake_guard.py" in " ".join(row["source_paths"])
            ]
            self.assertTrue(quarantine)
            self.assertTrue(all(row["wiring_status"] == "quarantined_fake" for row in quarantine))
            self.assertTrue(any("detector_must_not_count_as_wired" in row["blockers"] for row in quarantine))

    def test_rust_detector_without_fixture_is_source_shape_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(
                root / "detectors" / "rust_wave1" / "trait_cfg_shape.py",
                """
                # Rust source-shape heuristic only; runtime cfg and trait dispatch are unverified.
                def run(tree, source: bytes, filepath: str):
                    return []
                """,
            )
            _write(root / "tools" / "rust-source-graph.py", "def main(): return 0")

            payload = MOD.build_inventory(root, limit=20)
            rows = {row["scanner_id"]: row for row in payload["rows"] if row["scanner_id"]}
            row = rows["trait_cfg_shape"]
            self.assertEqual(row["backend"], "rust")
            self.assertEqual(row["wiring_status"], "rust_source_shape_only")
            self.assertEqual(row["proof_status"], "source_shape_only")
            self.assertIn("rust_runtime_semantics_unverified", row["blockers"])
            self.assertIn("source_shape_only", row["blockers"])

    def test_slither_artifact_with_rust_canonical_yaml_is_source_shape_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(
                root / "reference" / "patterns.dsl" / "return-amount-zero.yaml",
                """
                pattern: return-amount-zero
                backend: rust
                status: documentation-only
                match:
                  - function.body_contains_regex: consumed_offer
                """,
            )
            _write(
                root / "detectors" / "wave17" / "return_amount_zero.py",
                """
                from slither.detectors.abstract_detector import AbstractDetector
                class Detector(AbstractDetector):
                    ARGUMENT = "return-amount-zero"
                """,
            )

            payload = MOD.build_inventory(root, limit=20)
            rows = {row["scanner_id"]: row for row in payload["rows"] if row["scanner_id"]}
            row = rows["return_amount_zero"]
            self.assertEqual(row["backend"], "rust")
            self.assertEqual(row["wiring_status"], "rust_source_shape_only")
            self.assertEqual(row["proof_status"], "source_shape_only")
            self.assertIn("canonical_backend_mismatch_with_detector_path", row["blockers"])
            self.assertIn("source_shape_only", row["blockers"])
            self.assertIn("reference/patterns.dsl/return-amount-zero.yaml", row["source_paths"])

    def test_go_and_python_backend_executors_use_lang_detect_signals(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(root / "tools" / "lang-detect.py", "def main(): return 0")
            _write(root / "detectors" / "go_wave1" / "proof_of_life.py", "def run(engine, filepath): return []")
            _write(root / "detectors" / "go_wave1" / "test_fixtures" / "test_detectors.sh", "#!/usr/bin/env bash\n")
            _write(root / "detectors" / "python_wave1" / "proof_of_life.py", "def run(engine, filepath): return []")
            _write(root / "detectors" / "python_wave1" / "test_fixtures" / "test_detectors.sh", "#!/usr/bin/env bash\n")

            payload = MOD.build_inventory(root, limit=20)
            rows = {row["scanner_id"]: row for row in payload["rows"] if row["scanner_id"].endswith("-backend-executor")}

            go_row = rows["go-backend-executor"]
            self.assertEqual(go_row["wiring_status"], "unknown")
            self.assertEqual(go_row["proof_status"], "executor_signal_present_not_detector_proof")
            self.assertIn("tools/lang-detect.py", go_row["source_paths"])
            self.assertIn("detectors/go_wave1/test_fixtures/test_detectors.sh", go_row["source_paths"])
            self.assertIn("--lang go", go_row["suggested_next_action"])

            python_row = rows["python-backend-executor"]
            self.assertEqual(python_row["wiring_status"], "unknown")
            self.assertEqual(python_row["proof_status"], "executor_signal_present_not_detector_proof")
            self.assertIn("tools/lang-detect.py", python_row["source_paths"])
            self.assertIn("detectors/python_wave1/test_fixtures/test_detectors.sh", python_row["source_paths"])
            self.assertIn("--lang python", python_row["suggested_next_action"])

    def test_move_backend_gap_is_fail_closed_not_runnable_support(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(root / "tools" / "lang-detect.py", "def main(): return 0")
            _write(
                root / "detectors" / "move_wave2" / "inflation_attack_zero_stake.py",
                """
                def run_text(source, filepath): return []
                """,
            )
            _write(root / "detectors" / "move_wave2" / "test_fixtures" / "inflation_attack_zero_stake_vulnerable.move", "module bad {}")
            _write(root / "detectors" / "move_wave2" / "test_fixtures" / "inflation_attack_zero_stake_clean.move", "module good {}")
            _write(root / "docs" / "CROSS_LANGUAGE_DETECTORS.md", "lang-detect loads move_wave1")
            _write(root / "docs" / "POLYGLOT_WAVE2_2026-05-04.md", "move_wave2 detector notes")

            payload = MOD.build_inventory(root, limit=20)
            rows = {row["scanner_id"]: row for row in payload["rows"] if row["scanner_id"]}
            row = rows["move-backend-executor"]
            self.assertEqual(row["wiring_status"], "backend_executor_gap_fail_closed")
            self.assertEqual(row["proof_status"], "no_shared_backend_executor_fail_closed")
            self.assertEqual(row["memory_priority"], 45)
            self.assertIn("move_shared_backend_executor_absent", row["blockers"])
            self.assertIn("detectors/move_wave2/inflation_attack_zero_stake.py", row["source_paths"])
            self.assertIn("fail closed", row["suggested_next_action"])

    def test_cli_writes_deterministic_limited_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out = root / "out" / "ledger.json"
            for name in ("a", "b", "c"):
                _write(root / "reference" / "patterns.dsl" / f"{name}.yaml", f"pattern: {name}")

            proc = subprocess.run(
                [sys.executable, str(TOOL), str(root), "--json-out", str(out), "--limit", "2"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(proc.stdout, "")
            payload = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(payload["schema"], "auditooor.scanner_wiring_truth_inventory.v1")
            self.assertEqual(payload["limit"], 2)
            self.assertEqual(payload["item_count"], 2)
            self.assertTrue(payload["truncated"])
            self.assertEqual([row["pattern_id"] for row in payload["rows"]], ["a", "b"])


if __name__ == "__main__":
    unittest.main()
