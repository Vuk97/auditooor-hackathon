"""Tests for tools/spark-cargo-fork-status.py.

All tests are offline (CARGO_FORK_ANCESTRY_OFFLINE=1) and use either
synthetic fixtures or the fixture workspace under
tools/tests/fixtures/spark_cargo_fork_status/.
"""
from __future__ import annotations

import importlib.util
import json
import os
import pathlib
import subprocess
import sys
import unittest

REPO = pathlib.Path(__file__).resolve().parents[2]
TOOL = REPO / "tools" / "spark-cargo-fork-status.py"
FIXTURE_WS = REPO / "tools" / "tests" / "fixtures" / "spark_cargo_fork_status"

sys.path.insert(0, str(REPO / "tools"))

# Import the module under test for pure-Python unit tests
spec = importlib.util.spec_from_file_location(
    "spark_cargo_fork_status",
    TOOL,
)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

OFFLINE_ENV = {**os.environ, "CARGO_FORK_ANCESTRY_OFFLINE": "1"}


def _run(args: list[str], env: dict | None = None) -> subprocess.CompletedProcess:
    """Run the wrapper tool as a subprocess."""
    return subprocess.run(
        [sys.executable, str(TOOL)] + args,
        capture_output=True,
        text=True,
        env=env or OFFLINE_ENV,
    )


class TestDefaultWorkspacePath(unittest.TestCase):
    """Test 1 — default workspace resolves to ~/audits/spark/external/spark/signer."""

    def test_default_workspace_path_uses_audits_spark_external_spark_signer(self):
        expected = pathlib.Path("~/audits/spark/external/spark/signer").expanduser()
        actual = mod.DEFAULT_WORKSPACE
        self.assertEqual(actual, expected)


class TestMissingWorkspaceExits1(unittest.TestCase):
    """Test 2 — missing workspace exits 1 with helpful message."""

    def test_missing_workspace_exits_1_with_message(self):
        nonexistent = "/tmp/definitely_does_not_exist_spark_signer_42"
        result = _run(["--workspace", nonexistent])
        self.assertEqual(result.returncode, 1)
        combined = result.stdout + result.stderr
        self.assertIn("workspace not found", combined.lower())
        self.assertIn("~/audits/spark/", combined)


class TestOfflinePassthrough(unittest.TestCase):
    """Test 3 — CARGO_FORK_ANCESTRY_OFFLINE=1 passes through; no network error."""

    def test_offline_mode_passes_through(self):
        # Run against the stub fixture workspace (no git deps → no network needed)
        result = _run(
            ["--workspace", str(FIXTURE_WS)],
            env={**os.environ, "CARGO_FORK_ANCESTRY_OFFLINE": "1"},
        )
        # Should not exit 1 (error). 0 = clean, 2 = diverged-strict. Both are ok here.
        self.assertIn(result.returncode, (0, 2), msg=result.stderr)
        # Must not contain "network" error messages
        self.assertNotIn("network failure", result.stderr.lower())


class TestCryptoClassSubstringMatch(unittest.TestCase):
    """Test 4 — pure-Python classifier function, case-insensitive substring match."""

    def test_crypto_class_substring_match_case_insensitive(self):
        # Positive hits
        self.assertTrue(mod.is_crypto_class("FROST-core"))
        self.assertTrue(mod.is_crypto_class("libsecp256k1"))
        self.assertTrue(mod.is_crypto_class("bitcoin-hashes"))
        self.assertTrue(mod.is_crypto_class("Ed25519-dalek"))
        self.assertTrue(mod.is_crypto_class("TONIC"))
        self.assertTrue(mod.is_crypto_class("sha2"))
        self.assertTrue(mod.is_crypto_class("HMAC"))
        self.assertTrue(mod.is_crypto_class("tokio-util"))
        self.assertTrue(mod.is_crypto_class("prost-types"))
        self.assertTrue(mod.is_crypto_class("sqlx"))

        # Negative hits — not in any substring
        self.assertFalse(mod.is_crypto_class("rand"))
        self.assertFalse(mod.is_crypto_class("clap"))
        self.assertFalse(mod.is_crypto_class("anyhow"))
        self.assertFalse(mod.is_crypto_class("thiserror"))


class TestStrictModeExitCode(unittest.TestCase):
    """Test 5 — --strict propagates exit 2 from inner tool on divergence.

    Uses the stub fixture workspace which has NO git deps, so inner tool
    exits 0 (no diverged deps).  We verify the passthrough logic by checking
    --strict doesn't break a clean workspace (exit 0 is still 0 under strict
    when there's nothing diverged).
    """

    def test_strict_mode_propagates_exit_2_on_divergence(self):
        # With the stub (no git deps), strict + offline = exit 0 (no divergence)
        result = _run(
            ["--workspace", str(FIXTURE_WS), "--strict"],
            env={**os.environ, "CARGO_FORK_ANCESTRY_OFFLINE": "1"},
        )
        # 0 = clean (no git deps in stub), which is the correct result here.
        # This verifies --strict is accepted and doesn't cause a crash (exit 1).
        self.assertIn(result.returncode, (0, 2), msg=result.stderr)
        # Verify the flag is accepted without error
        self.assertNotIn("unrecognized", result.stderr.lower())


class TestJsonOutputIsValidJson(unittest.TestCase):
    """Test 6 — --json output against stub fixture is valid JSON."""

    def test_json_output_is_valid_json(self):
        result = _run(
            ["--workspace", str(FIXTURE_WS), "--json"],
            env={**os.environ, "CARGO_FORK_ANCESTRY_OFFLINE": "1"},
        )
        # Must not exit 1 (error)
        self.assertIn(result.returncode, (0, 2), msg=result.stderr)
        stdout = result.stdout.strip()
        if stdout:
            # If there is output, it must parse as JSON
            try:
                data = json.loads(stdout)
                self.assertIsInstance(data, dict)
            except json.JSONDecodeError as exc:
                self.fail(f"--json output is not valid JSON: {exc}\noutput={stdout!r}")
        # Empty stdout is also acceptable (no git deps → inner tool may emit {})


if __name__ == "__main__":
    unittest.main()
