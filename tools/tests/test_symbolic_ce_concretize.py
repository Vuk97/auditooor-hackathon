#!/usr/bin/env python3
"""W5-D2 — tests for the `--concretize` mode of `tools/symbolic-ce-to-forge.py`.

The concretize mode upgrades the tool from an advisory skipped-scaffold to
a real CE-to-executable-PoC concretizer: it renders a runnable Foundry
test, invokes `forge test`, and records a PASS/FAIL verdict into an
`auditooor.ce_replay_result.v1` artifact.

Tests:

  1. `test_eip55_checksum_known_vectors`
     The bundled pure-python keccak-256 + EIP-55 checksummer matches the
     canonical EIP-55 reference vectors. This is load-bearing: Solidity
     >=0.8 rejects non-checksummed address literals, so a wrong keccak
     would silently break every concretized test that has an address.

  2. `test_concretize_renders_executable_test`
     Running `--concretize` on the fixture CE writes an executable test
     file (no commented-out calls, real `cut.withdraw(...)`, real
     `assertTrue(...)`) and a `ce_replay_result.json` verdict artifact.

  3. `test_concretize_forge_run_reproduces_or_skips`
     If `forge` is on PATH, the verdict is `reproduced` (the fixture CE
     is a genuine over-withdraw exploit and the assert holds) with
     `forge_exit_code == 0`. If `forge` is absent, the verdict is
     `skipped` / `forge-unavailable`. Either outcome is a PASS — the
     concretizer must be forge-graceful so CI never requires forge.

  4. `test_concretize_skips_gracefully_when_forge_disabled`
     With `AUDITOOOR_DEEP_SKIP_FORGE=1` the run step is skipped
     (`status: skipped`, `reason: forge-unavailable`) and exit code 0,
     even on a host where `forge` is installed.

  5. `test_concretize_missing_assertions_is_structured_error`
     A CE that lacks `assertions` (and is not `expect_revert`) must
     fail with a structured `cannot-run` / `concretize-input-incomplete`
     reason and a non-zero exit — not a traceback.
"""
from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "symbolic-ce-to-forge.py"
FIX = ROOT / "tools" / "tests" / "fixtures" / "ce_concretize"
CE_FIXTURE = FIX / "ce_vault_overwithdraw.json"
FORGE_PROJECT = FIX / "forge_project"


def _load_tool_module():
    """Import symbolic-ce-to-forge.py as a module (hyphenated filename)."""
    spec = importlib.util.spec_from_file_location("ce_to_forge", TOOL)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _run(*args, env=None):
    full_env = dict(os.environ)
    if env:
        full_env.update(env)
    return subprocess.run(
        [sys.executable, str(TOOL), *args],
        capture_output=True,
        text=True,
        env=full_env,
    )


class TestCeConcretize(unittest.TestCase):
    def test_eip55_checksum_known_vectors(self):
        """Pure-python keccak + EIP-55 matches the spec reference vectors."""
        mod = _load_tool_module()
        # keccak256("") canonical digest.
        self.assertEqual(
            mod._keccak256(b"").hex(),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        )
        # EIP-55 reference vectors (from the EIP-55 spec text).
        cases = {
            "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed":
                "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
            "0xfb6916095ca1df60bb79ce92ce3ea74c37c5d359":
                "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
            "0x000000000000000000000000000000000000dead":
                "0x000000000000000000000000000000000000dEaD",
        }
        for lower, checksummed in cases.items():
            self.assertEqual(mod.eip55_checksum(lower), checksummed)

    def test_concretize_renders_executable_test(self):
        """--concretize emits a runnable test + verdict artifact."""
        self.assertTrue(CE_FIXTURE.exists(), f"missing fixture: {CE_FIXTURE}")
        with tempfile.TemporaryDirectory() as td:
            # Copy the fixture project so the test/ + out/ writes are
            # isolated from the committed fixture tree.
            proj = Path(td) / "forge_project"
            shutil.copytree(FORGE_PROJECT, proj)
            out = proj / "test" / "ConcretizedCE_run.t.sol"
            result_json = Path(td) / "verdict.json"
            res = _run(
                "--concretize",
                "--input", str(CE_FIXTURE),
                "--output", str(out),
                "--project-root", str(proj),
                "--result-json", str(result_json),
            )
            self.assertIn(res.returncode, (0, 3), res.stderr)
            self.assertTrue(out.exists(), "concretizer did not write test file")
            emitted = out.read_text()
            # Executable shape — no scaffold breadcrumbs.
            self.assertIn("cut.withdraw(", emitted)
            self.assertNotIn("// cut.withdraw", emitted)
            self.assertIn("assertTrue(", emitted)
            self.assertIn("EXECUTABLE — auto-generated", emitted)
            # Verdict artifact exists and is schema-stamped.
            self.assertTrue(result_json.exists())
            verdict = json.loads(result_json.read_text())
            self.assertEqual(
                verdict["schema_version"], "auditooor.ce_replay_result.v1"
            )
            self.assertIn(
                verdict["status"],
                ("reproduced", "not-reproduced", "skipped", "error"),
            )

    def test_concretize_forge_run_reproduces_or_skips(self):
        """With forge present the fixture CE reproduces; else it skips."""
        with tempfile.TemporaryDirectory() as td:
            proj = Path(td) / "forge_project"
            shutil.copytree(FORGE_PROJECT, proj)
            out = proj / "test" / "ConcretizedCE_run.t.sol"
            result_json = Path(td) / "verdict.json"
            res = _run(
                "--concretize",
                "--input", str(CE_FIXTURE),
                "--output", str(out),
                "--project-root", str(proj),
                "--result-json", str(result_json),
            )
            verdict = json.loads(result_json.read_text())
            if shutil.which("forge") is None:
                self.assertEqual(verdict["status"], "skipped")
                self.assertEqual(verdict["reason"], "forge-unavailable")
                self.assertEqual(res.returncode, 0)
            else:
                # The fixture Vault.withdraw has a genuine over-credit bug;
                # the CE assertion (balanceOf > deposited) holds, so the
                # generated test PASSES and the verdict is `reproduced`.
                self.assertEqual(
                    verdict["status"],
                    "reproduced",
                    f"forge present but CE not reproduced: {verdict}",
                )
                self.assertEqual(verdict["forge_exit_code"], 0)
                self.assertEqual(res.returncode, 0)

    def test_concretize_skips_gracefully_when_forge_disabled(self):
        """AUDITOOOR_DEEP_SKIP_FORGE=1 forces a skipped verdict + exit 0."""
        with tempfile.TemporaryDirectory() as td:
            proj = Path(td) / "forge_project"
            shutil.copytree(FORGE_PROJECT, proj)
            out = proj / "test" / "ConcretizedCE_run.t.sol"
            result_json = Path(td) / "verdict.json"
            res = _run(
                "--concretize",
                "--input", str(CE_FIXTURE),
                "--output", str(out),
                "--project-root", str(proj),
                "--result-json", str(result_json),
                env={"AUDITOOOR_DEEP_SKIP_FORGE": "1"},
            )
            self.assertEqual(res.returncode, 0, res.stderr)
            verdict = json.loads(result_json.read_text())
            self.assertEqual(verdict["status"], "skipped")
            self.assertEqual(verdict["reason"], "forge-unavailable")
            # Even when the run is skipped, the executable test is rendered.
            self.assertTrue(out.exists())

    def test_concretize_missing_assertions_is_structured_error(self):
        """A CE with no assertions / no expect_revert → structured error."""
        ce_doc = {
            "schema_version": 1,
            "_generated_at": "2026-05-16T00:00:00+00:00",
            "counterexamples": [
                {
                    "contract_under_test": "src/Vault.sol",
                    "cut_name": "Vault",
                    "values": {},
                    "call_sequence": [
                        {"fn": "withdraw", "args": []}
                    ],
                }
            ],
        }
        with tempfile.TemporaryDirectory() as td:
            inp = Path(td) / "ce_bad.json"
            inp.write_text(json.dumps(ce_doc))
            out = Path(td) / "test" / "x.t.sol"
            res = _run(
                "--concretize",
                "--input", str(inp),
                "--output", str(out),
            )
            self.assertNotEqual(res.returncode, 0, res.stdout)
            self.assertNotIn("Traceback", res.stderr)
            err_lines = [ln for ln in res.stderr.splitlines() if ln.strip()]
            self.assertTrue(err_lines, "expected a cannot-run JSON on stderr")
            payload = json.loads(err_lines[-1])
            self.assertEqual(payload.get("status"), "cannot-run")
            self.assertEqual(
                payload.get("reason"), "concretize-input-incomplete"
            )


if __name__ == "__main__":
    unittest.main()
