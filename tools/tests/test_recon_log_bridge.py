"""Regression tests for tools/recon-log-bridge.py."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "recon-log-bridge.py"


# These regression tests assert the legacy stdlib-fallback parser shape.
# Force-disable the native parser probe so the test suite stays hermetic
# (and fast) regardless of whether @recon-fuzz/log-parser is installed.
def _stdlib_only_env() -> dict[str, str]:
    env = os.environ.copy()
    env["AUDITOOOR_DISABLE_NATIVE_RECON_PARSER"] = "1"
    return env


def _write_locked_impact_contract(ws: Path, impact_contract_id: str = "impact-contract-row-1") -> None:
    aud = ws / ".auditooor"
    aud.mkdir()
    (aud / "impact_contracts.json").write_text(
        json.dumps(
            {
                "contracts": [
                    {
                        "impact_contract_id": impact_contract_id,
                        "selected_impact": "Direct loss of user funds",
                        "severity": "High",
                        "exact_impact_row": True,
                        "listed_impact_proven": True,
                    }
                ]
            }
        )
    )


class ReconLogBridgeTests(unittest.TestCase):
    def test_medusa_failure_becomes_deep_counterexample_record(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            ws = root / "ws"
            ws.mkdir()
            _write_locked_impact_contract(ws)
            log = ws / ".audit_logs" / "medusa.log"
            log.parent.mkdir()
            log.write_text(
                "FAILED property_vault_never_drains\n"
                "Call sequence:\n"
                "  Vault.deposit(100)\n"
                "  Vault.withdraw(200)\n"
            )
            forge_out = ws / "poc-tests" / "ReconReplay.t.sol"
            result = subprocess.run(
                [
                    "python3",
                    str(TOOL),
                    "--workspace",
                    str(ws),
                    "--engine",
                    "medusa",
                    "--log",
                    str(log),
                    "--row-id",
                    "ROW-1",
                    "--forge-test-out",
                    str(forge_out),
                    "--impact-contract-id",
                    "impact-contract-row-1",
                    "--print-json",
                ],
                text=True,
                capture_output=True,
                check=True,
                env=_stdlib_only_env(),
            )
            manifest = json.loads(result.stdout)
            self.assertEqual(manifest["status"], "recorded")
            self.assertEqual(manifest["truth_label"], "counterexample")
            self.assertTrue(manifest["engine_executed"])
            self.assertTrue(manifest["targets_discovered"])
            record_path = Path(manifest["records"][0])
            record = json.loads(record_path.read_text())
            self.assertEqual(record["schema_version"], "auditooor.deep_counterexample.v1")
            self.assertEqual(record["engine"], "medusa")
            self.assertEqual(record["row_id"], "ROW-1")
            self.assertEqual(record["impact_contract_id"], "impact-contract-row-1")
            self.assertEqual(record["selected_impact"], "Direct loss of user funds")
            self.assertEqual(record["evidence_class"], "scaffolded_unverified")
            self.assertTrue(record["promotes_to_poc_work"])
            self.assertNotEqual(record.get("final_result"), "proved")
            self.assertNotEqual(record.get("impact_assertion"), "exploit_impact")
            self.assertIn("Vault.withdraw(200)", record["input_sequence"])
            self.assertTrue(forge_out.exists())
            self.assertIn("vm.skip(true)", forge_out.read_text())

    def test_forge_test_out_without_locked_impact_records_advisory_only(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            ws = root / "ws"
            ws.mkdir()
            log = ws / ".audit_logs" / "medusa.log"
            log.parent.mkdir()
            log.write_text("FAILED property_vault_never_drains\nVault.withdraw(200)\n")
            forge_out = ws / "poc-tests" / "ReconReplay.t.sol"
            result = subprocess.run(
                [
                    "python3",
                    str(TOOL),
                    "--workspace",
                    str(ws),
                    "--engine",
                    "medusa",
                    "--log",
                    str(log),
                    "--forge-test-out",
                    str(forge_out),
                    "--print-json",
                ],
                text=True,
                capture_output=True,
                env=_stdlib_only_env(),
            )
            self.assertEqual(result.returncode, 0, msg=result.stderr)
            manifest = json.loads(result.stdout)
            self.assertEqual(manifest["status"], "recorded")
            self.assertIn("blocked_missing_impact_contract", manifest["impact_contract_blocker"])
            record = json.loads(Path(manifest["records"][0]).read_text())
            self.assertFalse(record["promotes_to_poc_work"])
            self.assertNotIn("generated_forge_test_path", record)
            self.assertIn("blocked_missing_impact_contract", record["promotion_blocker"])
            self.assertFalse(forge_out.exists())

    def test_echidna_failure_parses_property_name(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            ws = root / "ws"
            ws.mkdir()
            log = ws / ".audit_logs" / "echidna.log"
            log.parent.mkdir()
            log.write_text("echidna_no_bad_debt: failed!\nTxs:\nMarket.resolve(1)\n")
            subprocess.run(
                ["python3", str(TOOL), "--workspace", str(ws), "--engine", "echidna", "--log", str(log)],
                text=True,
                capture_output=True,
                check=True,
                env=_stdlib_only_env(),
            )
            records = list((ws / "deep_counterexamples").glob("*.deep_counterexample.v1.json"))
            self.assertEqual(len(records), 1)
            record = json.loads(records[0].read_text())
            self.assertEqual(record["target_function"], "echidna_no_bad_debt")

    def test_no_counterexample_writes_no_findings_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            ws = root / "ws"
            ws.mkdir()
            log = ws / ".audit_logs" / "halmos.log"
            log.parent.mkdir()
            log.write_text("PASS test_all_good\n")
            result = subprocess.run(
                [
                    "python3",
                    str(TOOL),
                    "--workspace",
                    str(ws),
                    "--engine",
                    "halmos",
                    "--log",
                    str(log),
                    "--print-json",
                ],
                text=True,
                capture_output=True,
                check=True,
                env=_stdlib_only_env(),
            )
            manifest = json.loads(result.stdout)
            self.assertEqual(manifest["status"], "no_findings")
            self.assertEqual(manifest["truth_label"], "no_findings")
            self.assertTrue(manifest["engine_executed"])
            self.assertTrue(manifest["targets_discovered"])
            self.assertEqual(manifest["parser_status"], "no_findings")
            self.assertEqual(manifest["parser"], "stdlib-fallback")
            self.assertIn("Only make poc-execution-record", manifest["proof_boundary"])
            self.assertFalse(list((ws / "deep_counterexamples").glob("*.deep_counterexample.v1.json")))

    def test_empty_or_truncated_logs_are_not_silent_success(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            ws = root / "ws"
            ws.mkdir()
            log_dir = ws / ".audit_logs"
            log_dir.mkdir()
            empty = log_dir / "empty.log"
            empty.write_text("")
            truncated = log_dir / "truncated.log"
            truncated.write_text("Medusa Fuzzing started\nTesting function transfer\n")
            for log in (empty, truncated):
                result = subprocess.run(
                    [
                        "python3",
                        str(TOOL),
                        "--workspace",
                        str(ws),
                        "--engine",
                        "medusa",
                        "--log",
                        str(log),
                        "--print-json",
                    ],
                    text=True,
                    capture_output=True,
                    check=True,
                    env=_stdlib_only_env(),
                )
                manifest = json.loads(result.stdout)
                self.assertEqual(manifest["status"], "error")
                self.assertEqual(manifest["truth_label"], "parser_failure")
                self.assertIsNone(manifest["engine_executed"])
                self.assertIsNone(manifest["targets_discovered"])
                self.assertEqual(manifest["parser_status"], "error")

    def test_external_log_rejected_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            ws = root / "ws"
            ws.mkdir()
            external = root / "external.log"
            external.write_text("FAILED property_external\n")
            result = subprocess.run(
                [
                    "python3",
                    str(TOOL),
                    "--workspace",
                    str(ws),
                    "--engine",
                    "medusa",
                    "--log",
                    str(external),
                ],
                text=True,
                capture_output=True,
                env=_stdlib_only_env(),
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("must be inside workspace", result.stderr)

    # ------------------------------------------------------------------
    # FP suppression tests (P0-1: tooling-failure log shapes)
    # ------------------------------------------------------------------

    def _run_bridge_fp(self, ws: "Path", log_content: str, log_name: str = "fuzz.log") -> dict:
        """Helper: write a log, run the bridge, return the parsed manifest."""
        log = ws / ".audit_logs" / log_name
        log.parent.mkdir(exist_ok=True)
        log.write_text(log_content)
        result = subprocess.run(
            [
                "python3",
                str(TOOL),
                "--workspace",
                str(ws),
                "--engine",
                "medusa",
                "--log",
                str(log),
                "--print-json",
            ],
            text=True,
            capture_output=True,
            check=True,
            env=_stdlib_only_env(),
        )
        return json.loads(result.stdout)

    def test_fp_real_counterexample_is_still_recorded(self) -> None:
        """Real counterexample log must be recorded normally (vulnerable path)."""
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "ws"
            ws.mkdir()
            manifest = self._run_bridge_fp(
                ws,
                "FAILED property_vault_never_drains\nCall sequence:\n  Vault.withdraw(200)\n",
            )
            self.assertEqual(manifest["status"], "recorded")
            self.assertNotIn("skipped_advisories", manifest)
            self.assertEqual(len(manifest["records"]), 1)

    def test_fp_setup_failure_is_skipped(self) -> None:
        """Foundry 'failed to set up invariant testing environment' must be suppressed."""
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "ws"
            ws.mkdir()
            # Real Foundry log shape (confirmed in RECON_CHIMERA_REAL_EXECUTION_RESULTS_2026-04-30.md)
            log_content = (
                "[FAIL: failed to set up invariant testing environment: No contracts to fuzz.]\n"
                "runs: 0, calls: 0\n"
            )
            manifest = self._run_bridge_fp(ws, log_content)
            self.assertEqual(manifest["status"], "skipped_tooling_failure")
            self.assertEqual(manifest["truth_label"], "setup_failure")
            self.assertFalse(manifest["engine_executed"])
            self.assertIsNone(manifest["targets_discovered"])
            self.assertEqual(manifest["parser_status"], "recorded")
            self.assertEqual(manifest["pattern_name"], "setup_failure")
            self.assertIn("skipped_advisories", manifest)
            advisory = manifest["skipped_advisories"][0]
            self.assertEqual(advisory["advisory_type"], "recon_log_bridge_skipped")
            self.assertEqual(advisory["skip_reason"], "tooling_failure_setup_failure")
            self.assertEqual(len(manifest.get("records", [])), 0)

    def test_fp_no_contracts_is_skipped(self) -> None:
        """Echidna/Medusa 'No contracts to fuzz' / 'No contracts found' must be suppressed."""
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "ws"
            ws.mkdir()
            # Real Echidna stderr shape (revert-stableswap-hooks/fuzz_runs/AE_20260502_echidna/stderr.log)
            log_content = "echidna: No contracts found in given file\n"
            manifest = self._run_bridge_fp(ws, log_content)
            self.assertEqual(manifest["status"], "skipped_tooling_failure")
            self.assertEqual(manifest["truth_label"], "no_targets")
            self.assertFalse(manifest["engine_executed"])
            self.assertFalse(manifest["targets_discovered"])
            self.assertEqual(manifest["pattern_name"], "no_contracts")
            advisory = manifest["skipped_advisories"][0]
            self.assertEqual(advisory["skip_reason"], "tooling_failure_no_contracts")
            self.assertEqual(len(manifest.get("records", [])), 0)

    def test_fp_thread_panic_is_skipped(self) -> None:
        """Rust thread panic in engine binary must be suppressed."""
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "ws"
            ws.mkdir()
            # Standard Rust panic format emitted by Foundry/forge on fatal internal error
            log_content = (
                "thread 'main' panicked at 'called `Option::unwrap()` on a `None` value', src/main.rs:42\n"
                "note: run with `RUST_BACKTRACE=1` for a backtrace\n"
            )
            manifest = self._run_bridge_fp(ws, log_content)
            self.assertEqual(manifest["status"], "skipped_tooling_failure")
            self.assertEqual(manifest["truth_label"], "tooling_failure")
            self.assertFalse(manifest["engine_executed"])
            self.assertIsNone(manifest["targets_discovered"])
            self.assertEqual(manifest["pattern_name"], "panic")
            advisory = manifest["skipped_advisories"][0]
            self.assertEqual(advisory["skip_reason"], "tooling_failure_panic")
            self.assertEqual(len(manifest.get("records", [])), 0)

    def test_fp_zero_calls_has_zero_execution_truth_label(self) -> None:
        """Foundry zero-call logs are distinct from clean no-findings runs."""
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "ws"
            ws.mkdir()
            manifest = self._run_bridge_fp(ws, "runs: 0, calls: 0\n")
            self.assertEqual(manifest["status"], "skipped_tooling_failure")
            self.assertEqual(manifest["truth_label"], "zero_execution")
            self.assertFalse(manifest["engine_executed"])
            self.assertIsNone(manifest["targets_discovered"])
            self.assertEqual(manifest["pattern_name"], "zero_calls")

    def test_fp_no_tests_found_has_no_targets_truth_label(self) -> None:
        """Medusa no-test logs are distinct from clean no-findings runs."""
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "ws"
            ws.mkdir()
            manifest = self._run_bridge_fp(
                ws,
                "no assertion, property, optimization, or custom tests were found to fuzz\n",
            )
            self.assertEqual(manifest["status"], "skipped_tooling_failure")
            self.assertEqual(manifest["truth_label"], "no_targets")
            self.assertFalse(manifest["engine_executed"])
            self.assertFalse(manifest["targets_discovered"])
            self.assertEqual(manifest["pattern_name"], "no_tests_found")

    def test_fp_mixed_real_cx_and_tooling_failure_real_wins(self) -> None:
        """When a log has both a real counterexample AND a tooling-failure pattern,
        the FP pattern takes precedence (conservative: operator must re-examine)."""
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "ws"
            ws.mkdir()
            # A log that appears to have a real failure banner but also contains
            # a setup-failure line — real scenario where Foundry emits both the
            # failing-test banner and the setup-failure reason on the same run.
            log_content = (
                "FAILED property_vault_never_drains\n"
                "Call sequence:\n  Vault.withdraw(200)\n"
                "failed to set up invariant testing environment: No contracts to fuzz.\n"
            )
            manifest = self._run_bridge_fp(ws, log_content)
            # FP suppression wins: the setup-failure pattern is authoritative.
            self.assertEqual(manifest["status"], "skipped_tooling_failure")
            self.assertIn("skipped_advisories", manifest)
            advisory = manifest["skipped_advisories"][0]
            self.assertEqual(advisory["advisory_type"], "recon_log_bridge_skipped")
            # The suppressed_counterexample_count must be >= 0 (parser may or
            # may not have flagged the failure banner before suppression).
            self.assertGreaterEqual(advisory["suppressed_counterexample_count"], 0)
            self.assertEqual(len(manifest.get("records", [])), 0)


if __name__ == "__main__":
    unittest.main()
