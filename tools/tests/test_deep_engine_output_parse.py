#!/usr/bin/env python3
"""Hermetic smoke tests for tools/deep-engine-output-parse.py (LANE W4.5).

These exercise the runner-artifact -> structured-findings integration
WITHOUT requiring halmos/medusa/echidna to be installed: each test fabricates
the ``auditooor.deep_engine_artifact.v1`` JSON the runner scripts would write,
then asserts the parser normalizes it into ``auditooor.deep_engine_findings.v1``.
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "deep-engine-output-parse.py"


def _write_artifact(ws: Path, engine: str, payload: dict) -> None:
    art_dir = ws / ".auditooor" / engine
    art_dir.mkdir(parents=True, exist_ok=True)
    base = {"schema_version": "auditooor.deep_engine_artifact.v1", "engine": engine}
    base.update(payload)
    (art_dir / "artifact.json").write_text(
        json.dumps(base, indent=2, sort_keys=True), encoding="utf-8"
    )


def _run(ws: Path) -> dict:
    out = ws / ".auditooor" / "deep-engine-findings" / "findings.json"
    proc = subprocess.run(
        [sys.executable, str(TOOL), "--workspace", str(ws), "--output", str(out)],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, f"rc={proc.returncode} stderr={proc.stderr}"
    return json.loads(out.read_text(encoding="utf-8"))


class DeepEngineOutputParseTest(unittest.TestCase):
    def test_empty_workspace_well_formed(self) -> None:
        """No runner artifacts -> empty but schema-valid findings file."""
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            data = _run(ws)
        self.assertEqual(data["schema_version"], "auditooor.deep_engine_findings.v1")
        self.assertEqual(data["engine_count"], 3)
        self.assertEqual(data["counterexample_count"], 0)
        self.assertEqual(data["not_run_count"], 3)
        self.assertFalse(data["has_counterexample"])
        for f in data["findings"]:
            self.assertEqual(f["verdict"], "not_run")
            self.assertFalse(f["artifact_present"])

    def test_counterexample_detected_from_stdout(self) -> None:
        """A halmos artifact with a failing property -> verdict=counterexample."""
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _write_artifact(
                ws,
                "halmos",
                {
                    "status": "ok",
                    "engine_rc": 0,
                    "command": "halmos",
                    "stdout": (
                        "Running symbolic tests\n"
                        "[FAIL] check_invariant_solvency() counterexample: "
                        "Vault.withdraw(200)\n"
                    ),
                    "stderr": "",
                },
            )
            data = _run(ws)
        self.assertTrue(data["has_counterexample"])
        self.assertEqual(data["counterexample_count"], 1)
        halmos = next(f for f in data["findings"] if f["engine"] == "halmos")
        self.assertEqual(halmos["verdict"], "counterexample")
        self.assertIn("Vault.withdraw(200)", halmos["input_sequence"])

    def test_tooling_failure_not_counted_as_counterexample(self) -> None:
        """Medusa 'no tests found' -> verdict=tooling_failure, NOT counterexample."""
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _write_artifact(
                ws,
                "medusa",
                {
                    "status": "engine-error",
                    "engine_rc": 1,
                    "command": "medusa",
                    "stdout": (
                        "no assertion, property, optimization, or custom "
                        "tests were found to fuzz"
                    ),
                    "stderr": "",
                },
            )
            data = _run(ws)
        self.assertEqual(data["counterexample_count"], 0)
        self.assertEqual(data["tooling_failure_count"], 1)
        medusa = next(f for f in data["findings"] if f["engine"] == "medusa")
        self.assertEqual(medusa["verdict"], "tooling_failure")
        self.assertEqual(medusa["tooling_failure_pattern"], "no_tests_found")

    def test_echidna_no_tests_found_in_abi_is_tooling_failure(self) -> None:
        """Echidna 'No tests found in ABI' is a harness gap, not a counterexample."""
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _write_artifact(
                ws,
                "echidna",
                {
                    "status": "engine-error",
                    "engine_rc": 1,
                    "command": "echidna .",
                    "stdout": "Analyzing contract: contracts/Vault.sol:Vault\n",
                    "stderr": "echidna: No tests found in ABI. If you are using assert(), use --test-mode assertion\n",
                },
            )
            data = _run(ws)
        self.assertEqual(data["counterexample_count"], 0)
        self.assertEqual(data["tooling_failure_count"], 1)
        echidna = next(f for f in data["findings"] if f["engine"] == "echidna")
        self.assertEqual(echidna["verdict"], "tooling_failure")
        self.assertEqual(echidna["tooling_failure_pattern"], "no_tests_found")

    def test_medusa_missing_target_contract_is_tooling_failure(self) -> None:
        """Medusa target-selection errors are harness gaps, not counterexamples."""
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _write_artifact(
                ws,
                "medusa",
                {
                    "status": "engine-error",
                    "engine_rc": 6,
                    "command": "medusa fuzz --compilation-target .",
                    "stdout": "Failed to initialize the test chain\nerror\n- specify target contract(s)\n",
                    "stderr": "",
                },
            )
            data = _run(ws)
        self.assertEqual(data["counterexample_count"], 0)
        self.assertEqual(data["tooling_failure_count"], 1)
        medusa = next(f for f in data["findings"] if f["engine"] == "medusa")
        self.assertEqual(medusa["verdict"], "tooling_failure")
        self.assertEqual(medusa["tooling_failure_pattern"], "no_target_contract")

    def test_skipped_engine_marked_not_run(self) -> None:
        """A tool-unavailable runner artifact -> verdict=not_run, exit 0."""
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _write_artifact(
                ws,
                "echidna",
                {"status": "tool-unavailable", "reason": "echidna not found on PATH"},
            )
            data = _run(ws)
        echidna = next(f for f in data["findings"] if f["engine"] == "echidna")
        self.assertEqual(echidna["verdict"], "not_run")
        self.assertEqual(data["counterexample_count"], 0)

    def test_clean_run_no_findings(self) -> None:
        """An engine that ran cleanly -> verdict=no_findings."""
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _write_artifact(
                ws,
                "halmos",
                {
                    "status": "ok",
                    "engine_rc": 0,
                    "command": "halmos",
                    "stdout": "Running symbolic tests\nAll properties passed.\n",
                    "stderr": "",
                },
            )
            data = _run(ws)
        halmos = next(f for f in data["findings"] if f["engine"] == "halmos")
        self.assertEqual(halmos["verdict"], "no_findings")
        self.assertEqual(data["no_findings_count"], 1)


    def test_engine_error_unlinked_libraries_is_tooling_failure(self) -> None:
        """Echidna unlinked-library compile failure -> tooling_failure, never a
        counterexample. Anchor: Aztec criterion-i 2026-05-29 - the error text
        contains the word 'error' which previously tripped the keyword path."""
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _write_artifact(
                ws,
                "echidna",
                {
                    "status": "engine-error",
                    "engine_rc": 1,
                    "command": "echidna .",
                    "stdout": "Compiling target... Done!\n",
                    "stderr": (
                        "Error: Unlinked libraries detected in bytecode of "
                        "contract ZKPassportHelper.sol:ZKPassportHelper\n"
                        "CallStack (from HasCallStack):\n  error, called\n"
                    ),
                },
            )
            data = _run(ws)
        echidna = next(f for f in data["findings"] if f["engine"] == "echidna")
        self.assertEqual(echidna["verdict"], "tooling_failure")
        self.assertEqual(data["counterexample_count"], 0)

    def test_engine_error_crytic_abi_parse_not_clean_negative(self) -> None:
        """Medusa crytic-compile ABI-parse failure (rc=6) must NOT be reported as
        a clean no_findings. Anchor: Aztec criterion-i 2026-05-29 - a crashed
        engine that never fuzzed must be a tooling_failure, not a passed run."""
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _write_artifact(
                ws,
                "medusa",
                {
                    "status": "engine-error",
                    "engine_rc": 6,
                    "command": "medusa fuzz --compilation-target .",
                    "stdout": (
                        "Compiling targets with crytic-compile\n"
                        "error Failed to compile target\n"
                        "unable to parse ABI for contract 'InputsExtractor'\n"
                    ),
                    "stderr": "",
                },
            )
            data = _run(ws)
        medusa = next(f for f in data["findings"] if f["engine"] == "medusa")
        self.assertEqual(medusa["verdict"], "tooling_failure")
        self.assertEqual(data["no_findings_count"], 0)
        self.assertEqual(data["counterexample_count"], 0)

    def test_halmos_all_pass_symbolic_is_clean_negative(self) -> None:
        """A fully-passing halmos run ('N passed; 0 failed', all [PASS], no
        [FAIL]/Counterexample) is a clean negative, NOT a counterexample, even
        though inlined source/lint excerpts contain words like 'require' and the
        '0 failed' summary tail contains the substring 'failed'. Anchor: Aztec
        criterion-i 2026-05-29 real halmos artifact."""
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _write_artifact(
                ws,
                "halmos",
                {
                    "status": "ok",
                    "engine_rc": 0,
                    "command": "halmos",
                    "stdout": (
                        "Running 4 tests for test/fuzz/CheckpointSymbolic.t.sol\n"
                        "[PASS] check_slot_round_deterministic(uint256)\n"
                        "[PASS] check_add_sub_inverse(uint256,uint256)\n"
                        "Symbolic test result: 4 passed; 0 failed; time: 0.38s\n"
                        "// require(block.timestamp >= GATED_UNTIL, GateIsClosed())\n"
                    ),
                    "stderr": "",
                },
            )
            data = _run(ws)
        halmos = next(f for f in data["findings"] if f["engine"] == "halmos")
        self.assertEqual(halmos["verdict"], "no_findings")
        self.assertEqual(data["counterexample_count"], 0)
        self.assertEqual(data["no_findings_count"], 1)

    def test_bad_workspace_exits_nonzero(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(TOOL), "--workspace", "/nonexistent/ws/xyz"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 2)


if __name__ == "__main__":
    unittest.main()
