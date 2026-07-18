#!/usr/bin/env python3
"""
test_spark_regtest_harness.py — S4 smoke tests for tools/spark-regtest-harness.sh

Covers (no daemon spawned):
  * --help exits 0 and emits usage text
  * --check exits 0 (prerequisites present) or exits 1 with a clear MISSING line
    when bitcoind is absent; neither case should crash unexpectedly
  * Script is executable and contains mandatory idempotency / teardown guard lines
"""
from __future__ import annotations

import os
import subprocess
import sys
import unittest

_SCRIPT = os.path.join(
    os.path.dirname(__file__), "..", "spark-regtest-harness.sh"
)


class TestSparkRegtestHarnessScriptShape(unittest.TestCase):
    """Verify the script has the mandatory structural components."""

    def test_script_exists(self) -> None:
        self.assertTrue(os.path.isfile(_SCRIPT), f"Script not found: {_SCRIPT}")

    def test_script_is_executable(self) -> None:
        self.assertTrue(os.access(_SCRIPT, os.X_OK), f"Script is not executable: {_SCRIPT}")

    def _read_script(self) -> str:
        with open(_SCRIPT, encoding="utf-8") as f:
            return f.read()

    def test_idempotency_guard_present(self) -> None:
        content = self._read_script()
        self.assertIn("already running", content, "Idempotency guard text missing from script")

    def test_teardown_mode_present(self) -> None:
        content = self._read_script()
        self.assertIn("teardown", content, "Teardown mode missing from script")

    def test_state_json_emission_present(self) -> None:
        content = self._read_script()
        self.assertIn("regtest_state.json", content, "State JSON output path missing from script")

    def test_mine_blocks_present(self) -> None:
        content = self._read_script()
        self.assertIn("MINE_BLOCKS", content, "MINE_BLOCKS constant missing from script")

    def test_rpc_user_env_override_present(self) -> None:
        content = self._read_script()
        self.assertIn("BITCOIN_RPC_USER", content, "BITCOIN_RPC_USER env override missing")


class TestSparkRegtestHarnessHelp(unittest.TestCase):
    """--help must exit 0 and emit usage."""

    def test_help_exits_zero(self) -> None:
        result = subprocess.run(
            ["bash", _SCRIPT, "--help"],
            capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(
            result.returncode, 0,
            f"--help exited {result.returncode}; stderr={result.stderr[:200]}",
        )

    def test_help_mentions_spark_regtest(self) -> None:
        result = subprocess.run(
            ["bash", _SCRIPT, "--help"],
            capture_output=True, text=True, timeout=10,
        )
        combined = result.stdout + result.stderr
        self.assertIn(
            "regtest", combined.lower(),
            "--help output does not mention regtest",
        )


class TestSparkRegtestHarnessCheckMode(unittest.TestCase):
    """--check must not crash, and must produce parseable output."""

    def test_check_mode_produces_output(self) -> None:
        result = subprocess.run(
            ["bash", _SCRIPT, "--check"],
            capture_output=True, text=True, timeout=30,
        )
        combined = result.stdout + result.stderr
        # Must emit at least one PASS or MISSING line — not a silent crash.
        has_signal = ("PASS" in combined or "MISSING" in combined or "WARN" in combined)
        self.assertTrue(
            has_signal,
            f"--check produced no PASS/MISSING/WARN output (rc={result.returncode}).\n"
            f"stdout={result.stdout[:300]}\nstderr={result.stderr[:300]}",
        )

    def test_check_mode_does_not_spawn_daemon(self) -> None:
        """--check must exit before any bitcoind spawn attempt."""
        result = subprocess.run(
            ["bash", _SCRIPT, "--check"],
            capture_output=True, text=True, timeout=30,
        )
        combined = result.stdout + result.stderr
        # The script must NOT emit "Spawning bitcoind" in --check mode.
        self.assertNotIn(
            "Spawning bitcoind", combined,
            "--check mode appears to be spawning a daemon (should not)",
        )

    def test_check_without_ws_does_not_crash(self) -> None:
        """--check does not require WS and must not crash with rc=2."""
        result = subprocess.run(
            ["bash", _SCRIPT, "--check"],
            capture_output=True, text=True, timeout=30,
        )
        self.assertNotEqual(
            result.returncode, 2,
            "--check exited 2 (usage error) — WS should not be required for check mode",
        )


class TestSparkRegtestHarnessMakefileParity(unittest.TestCase):
    """Verify the Makefile contains the expected targets and help entries."""

    def _read_makefile(self) -> str:
        makefile = os.path.join(
            os.path.dirname(__file__), "..", "..", "Makefile"
        )
        with open(makefile, encoding="utf-8") as f:
            return f.read()

    def test_spark_regtest_harness_target_present(self) -> None:
        content = self._read_makefile()
        self.assertIn("spark-regtest-harness:", content, "spark-regtest-harness target missing from Makefile")

    def test_spark_regtest_teardown_target_present(self) -> None:
        content = self._read_makefile()
        self.assertIn("spark-regtest-teardown:", content, "spark-regtest-teardown target missing from Makefile")

    def test_spark_regtest_harness_test_target_present(self) -> None:
        content = self._read_makefile()
        self.assertIn("spark-regtest-harness-test:", content, "spark-regtest-harness-test target missing from Makefile")

    def test_phony_declarations_present(self) -> None:
        content = self._read_makefile()
        self.assertIn("spark-regtest-harness", content, "spark-regtest-harness missing from .PHONY")
        self.assertIn("spark-regtest-teardown", content, "spark-regtest-teardown missing from .PHONY")

    def test_help_entry_present(self) -> None:
        content = self._read_makefile()
        self.assertIn("spark-regtest-harness WS=", content, "spark-regtest-harness help entry missing")

    def test_l29_disc6_reference_present(self) -> None:
        content = self._read_makefile()
        self.assertIn("L29-Disc-6", content, "L29-Disc-6 cross-reference missing from Makefile comment")


if __name__ == "__main__":
    unittest.main()
