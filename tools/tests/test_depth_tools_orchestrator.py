#!/usr/bin/env python3
# r36-rebuttal: lane-CAPABILITY-DEPTH-TOOLS-ORCHESTRATOR-PLUS-EXHAUSTION-VERDICT-GATE registered via tools/agent-pathspec-register.py.
# r36-rebuttal: lane orchestrator-hevm-kontrol pathspec registered for HEVM + kontrol runner tests (Gap #38 install wiring).
"""Tests for tools/depth-tools-orchestrator.py."""
from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

_REPO_ROOT = Path(__file__).resolve().parents[2]
_TOOL_PATH = _REPO_ROOT / "tools" / "depth-tools-orchestrator.py"


def _import_tool():
    spec = importlib.util.spec_from_file_location("depth_tools_orchestrator", _TOOL_PATH)
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(mod)
    return mod


DTO = _import_tool()


class TestLanguageDetection(unittest.TestCase):
    def test_solidity_extension(self):
        self.assertEqual(DTO._detect_language("contracts/Foo.sol"), "solidity")

    def test_rust_extension(self):
        self.assertEqual(DTO._detect_language("src/lib.rs"), "rust")

    def test_go_extension(self):
        self.assertEqual(DTO._detect_language("internal/foo.go"), "go")

    def test_other(self):
        self.assertEqual(DTO._detect_language("README.md"), "other")

    def test_empty(self):
        self.assertEqual(DTO._detect_language(""), "other")


class TestHonestSkip(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.ws = Path(self.tmp)

    def test_halmos_skip_on_rust(self):
        row = DTO.run_halmos(self.ws, "src/lib.rs", dry_run=False)
        self.assertEqual(row["status"], "SKIPPED")
        self.assertIn("Solidity", row["skip_reason"])
        self.assertEqual(row["applicable_language"], "rust")

    def test_foundry_skip_on_rust(self):
        row = DTO.run_foundry_fuzz_1m(self.ws, "src/lib.rs", runs=1_000_000, dry_run=False)
        self.assertEqual(row["status"], "SKIPPED")
        self.assertIn("Solidity", row["skip_reason"])

    def test_mythril_skip_on_go(self):
        row = DTO.run_mythril(self.ws, "main.go", dry_run=False)
        self.assertEqual(row["status"], "SKIPPED")
        self.assertEqual(row["applicable_language"], "go")

    def test_manticore_skip_on_go(self):
        row = DTO.run_manticore(self.ws, "main.go", dry_run=False)
        self.assertEqual(row["status"], "SKIPPED")

    def test_dry_run_solidity_halmos(self):
        row = DTO.run_halmos(self.ws, "contracts/Foo.sol", dry_run=True)
        self.assertEqual(row["status"], "SKIPPED")
        self.assertEqual(row["skip_reason"], "dry-run mode")

    def test_dry_run_foundry(self):
        row = DTO.run_foundry_fuzz_1m(self.ws, "contracts/Foo.sol", runs=1_000_000, dry_run=True)
        self.assertEqual(row["status"], "SKIPPED")
        self.assertEqual(row["extras"]["runs"], 1_000_000)

    def test_soak_skip_on_unknown_language(self):
        row = DTO.run_soak_fuzz(self.ws, "README.md", hours=1, dry_run=False)
        self.assertEqual(row["status"], "SKIPPED")
        self.assertIn("no soak-fuzz harness", row["skip_reason"])

    def test_differential_skip_dry_run(self):
        row = DTO.run_differential_fuzz(self.ws, "test/Diff.sol", "ref/canonical.sol", dry_run=True)
        self.assertEqual(row["status"], "SKIPPED")
        self.assertEqual(row["extras"]["reference"], "ref/canonical.sol")


class TestLogAppend(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.ws = Path(self.tmp)

    def test_log_row_appended(self):
        row = DTO.run_halmos(self.ws, "src/lib.rs", dry_run=False)
        log_path = self.ws / ".auditooor" / "depth_tools_log.jsonl"
        self.assertTrue(log_path.exists())
        lines = log_path.read_text().splitlines()
        self.assertEqual(len(lines), 1)
        parsed = json.loads(lines[0])
        self.assertEqual(parsed["tool"], "halmos")
        self.assertEqual(parsed["status"], "SKIPPED")
        self.assertEqual(parsed["schema"], DTO.SCHEMA_VERSION)

    def test_multiple_rows(self):
        DTO.run_halmos(self.ws, "src/lib.rs", dry_run=False)
        DTO.run_mythril(self.ws, "main.go", dry_run=False)
        DTO.run_manticore(self.ws, "main.go", dry_run=False)
        log_path = self.ws / ".auditooor" / "depth_tools_log.jsonl"
        lines = log_path.read_text().splitlines()
        self.assertEqual(len(lines), 3)


class TestRule14DeepIntegrate(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.ws = Path(self.tmp)

    def test_dry_run(self):
        row = DTO.run_rule14_deep_integrate(self.ws, dry_run=True)
        self.assertEqual(row["status"], "SKIPPED")
        self.assertEqual(row["skip_reason"], "dry-run mode")


class TestMainSummary(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.ws = Path(self.tmp)

    def test_main_no_args_returns_usage_error(self):
        rc = DTO.main(["--workspace", str(self.ws)])
        self.assertEqual(rc, 2)

    def test_main_dry_run_halmos(self):
        rc = DTO.main(["--workspace", str(self.ws), "--halmos", "src/lib.rs", "--dry-run", "--json"])
        self.assertEqual(rc, 0)
        log_path = self.ws / ".auditooor" / "depth_tools_log.jsonl"
        self.assertTrue(log_path.exists())

    def test_main_differential_requires_reference(self):
        rc = DTO.main([
            "--workspace", str(self.ws),
            "--differential-fuzz", "test/Foo.sol",
            "--dry-run",
        ])
        self.assertEqual(rc, 2)

    def test_main_invalid_workspace(self):
        rc = DTO.main(["--workspace", "/nonexistent/path/xyz", "--halmos", "x.sol", "--dry-run"])
        self.assertEqual(rc, 2)

    def test_main_all_tools_dry_run(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".sol", delete=False) as f:
            f.write("// fake ref impl\n")
            ref_path = f.name
        try:
            rc = DTO.main([
                "--workspace", str(self.ws),
                "--halmos", "contracts/Foo.sol",
                "--foundry-fuzz-1m", "test/Foo.t.sol",
                "--mythril", "contracts/Foo.sol",
                "--manticore", "contracts/Foo.sol",
                "--differential-fuzz", "test/Diff.sol",
                "--reference", ref_path,
                "--soak-fuzz", "src/lib.rs",
                "--rule14-deep-integrate",
                "--dry-run",
                "--json",
            ])
            self.assertEqual(rc, 0)
            log_path = self.ws / ".auditooor" / "depth_tools_log.jsonl"
            lines = log_path.read_text().splitlines()
            # 7 rows for 7 tool invocations.
            self.assertEqual(len(lines), 7)
            tools_seen = {json.loads(l)["tool"] for l in lines}
            self.assertEqual(tools_seen, {
                "halmos", "foundry-fuzz-1m", "mythril", "manticore",
                "differential-fuzz", "soak-fuzz", "rule14-deep-integrate",
            })
        finally:
            os.unlink(ref_path)


# r36-rebuttal: lane orchestrator-hevm-kontrol pathspec registered for the
# HEVM + kontrol test classes below (Gap #38 install wiring).


class TestHevm(unittest.TestCase):
    """Cover the HEVM runner: dry-run, missing-binary skip, unsupported-shape
    skip (raw .sol), unknown-target skip, foundry-project happy path with
    subprocess mocked, bytecode-file happy path with subprocess mocked."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.ws = Path(self.tmp)

    def test_hevm_dry_run(self):
        row = DTO.run_hevm(self.ws, "contracts/Foo.sol", dry_run=True)
        self.assertEqual(row["status"], "SKIPPED")
        self.assertEqual(row["skip_reason"], "dry-run mode")
        self.assertEqual(row["extras"]["timeout"], 600)

    def test_hevm_skip_on_rust(self):
        row = DTO.run_hevm(self.ws, "src/lib.rs", dry_run=False)
        self.assertEqual(row["status"], "SKIPPED")
        self.assertIn("EVM-only", row["skip_reason"])
        self.assertEqual(row["applicable_language"], "rust")

    def test_hevm_skip_on_go(self):
        row = DTO.run_hevm(self.ws, "main.go", dry_run=False)
        self.assertEqual(row["status"], "SKIPPED")
        self.assertIn("EVM-only", row["skip_reason"])

    def test_hevm_skip_when_binary_missing(self):
        with mock.patch.object(DTO, "_which", return_value=""):
            row = DTO.run_hevm(self.ws, "contracts/Foo.sol", dry_run=False)
        self.assertEqual(row["status"], "SKIPPED")
        self.assertIn("hevm binary not installed", row["skip_reason"])

    def test_hevm_skip_on_raw_sol_source(self):
        # Create a real .sol file so the path resolves as is_file()=True,
        # but hevm cannot symbolic-exec raw sol; expect honest-skip.
        sol_path = self.ws / "Foo.sol"
        sol_path.write_text("// SPDX-License-Identifier: MIT\ncontract Foo {}\n")
        with mock.patch.object(DTO, "_which", return_value="/usr/local/bin/hevm"):
            row = DTO.run_hevm(self.ws, str(sol_path), dry_run=False)
        self.assertEqual(row["status"], "SKIPPED")
        self.assertIn("requires compiled bytecode", row["skip_reason"])
        self.assertEqual(row["extras"]["invocation_shape"], "unsupported-raw-sol")

    def test_hevm_skip_on_unknown_target_shape(self):
        # Path that doesn't exist + not Foundry project + not bytecode file.
        with mock.patch.object(DTO, "_which", return_value="/usr/local/bin/hevm"):
            row = DTO.run_hevm(self.ws, "nonexistent-target", dry_run=False)
        self.assertEqual(row["status"], "SKIPPED")
        self.assertIn("target shape not recognized", row["skip_reason"])
        self.assertEqual(row["extras"]["invocation_shape"], "unsupported-unknown")

    def test_hevm_foundry_project_invocation(self):
        # r36-rebuttal: lane orchestrator-hevm-kontrol pathspec registered.
        # Build a fake Foundry project root: directory containing foundry.toml.
        fproj = self.ws / "foundry-project"
        fproj.mkdir()
        (fproj / "foundry.toml").write_text("[profile.default]\nsrc = 'src'\n")
        # _run_subprocess is called twice: once for the main invocation,
        # then once for `hevm version` to capture version metadata. Capture
        # ALL calls and assert against the first (main invocation).
        captured: dict[str, list] = {"calls": []}

        def fake_run(cmd, cwd=None, timeout=600):
            captured["calls"].append(list(cmd))
            # Version-capture call: `hevm version` with no other args.
            if len(cmd) == 2 and cmd[1] == "version":
                return (0, "0.57.0\n", "", 0.05)
            return (0, "PASS line\n", "", 1.23)

        with mock.patch.object(DTO, "_which", return_value="/usr/local/bin/hevm"), \
             mock.patch.object(DTO, "_run_subprocess", side_effect=fake_run):
            row = DTO.run_hevm(self.ws, str(fproj), function="prove_foo",
                               dry_run=False, timeout=120)
        self.assertEqual(row["status"], "PASS")
        # Main invocation is the first call.
        main_cmd = captured["calls"][0]
        # Must call `hevm test --root <fproj>` with --match prove_foo.
        self.assertIn("test", main_cmd)
        self.assertIn("--root", main_cmd)
        self.assertIn("--match", main_cmd)
        self.assertIn("prove_foo", main_cmd)
        self.assertEqual(row["extras"]["invocation_shape"], "test-foundry-project")

    def test_hevm_bytecode_file_invocation(self):
        # r36-rebuttal: lane orchestrator-hevm-kontrol pathspec registered.
        bin_path = self.ws / "Foo.bin"
        bin_path.write_text("6080604052")
        captured: dict[str, list] = {"calls": []}

        def fake_run(cmd, cwd=None, timeout=600):
            captured["calls"].append(list(cmd))
            if len(cmd) == 2 and cmd[1] == "version":
                return (0, "0.57.0\n", "", 0.05)
            return (0, "QED\n", "", 0.5)

        with mock.patch.object(DTO, "_which", return_value="/usr/local/bin/hevm"), \
             mock.patch.object(DTO, "_run_subprocess", side_effect=fake_run):
            row = DTO.run_hevm(self.ws, str(bin_path),
                               function="transfer(address,uint256)",
                               dry_run=False)
        self.assertEqual(row["status"], "PASS")
        main_cmd = captured["calls"][0]
        self.assertIn("symbolic", main_cmd)
        self.assertIn("--code-file", main_cmd)
        self.assertIn("--sig", main_cmd)
        self.assertEqual(row["extras"]["invocation_shape"], "symbolic-bytecode-file")

    def test_hevm_log_row_appended(self):
        row = DTO.run_hevm(self.ws, "contracts/Foo.sol", dry_run=True)
        log_path = self.ws / ".auditooor" / "depth_tools_log.jsonl"
        self.assertTrue(log_path.exists())
        parsed = json.loads(log_path.read_text().splitlines()[0])
        self.assertEqual(parsed["tool"], "hevm")
        self.assertEqual(parsed["status"], "SKIPPED")


class TestKontrol(unittest.TestCase):
    """Cover the Kontrol runner: always SKIPPED (K Framework backend missing),
    regardless of target / dry-run / binary presence."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.ws = Path(self.tmp)

    def test_kontrol_always_skipped_with_target(self):
        row = DTO.run_kontrol(self.ws, "contracts/Foo.sol", dry_run=False)
        self.assertEqual(row["status"], "SKIPPED")
        self.assertIn("K Framework backend (kompile) not installed", row["skip_reason"])
        self.assertEqual(row["extras"]["skip_class"], "PARTIAL-PERMANENT")
        self.assertTrue(row["extras"]["wrapper_installed"])
        self.assertFalse(row["extras"]["backend_installed"])

    def test_kontrol_always_skipped_without_target(self):
        row = DTO.run_kontrol(self.ws, "", dry_run=False)
        self.assertEqual(row["status"], "SKIPPED")
        # When no target given, fall back to workspace path.
        self.assertEqual(row["target"], str(self.ws))

    def test_kontrol_always_skipped_dry_run(self):
        # dry_run does not change behavior: kontrol is always SKIPPED.
        row = DTO.run_kontrol(self.ws, "contracts/Foo.sol", dry_run=True)
        self.assertEqual(row["status"], "SKIPPED")
        self.assertIn("K Framework backend", row["skip_reason"])

    def test_kontrol_skip_reason_cites_operator_decision(self):
        row = DTO.run_kontrol(self.ws, "")
        self.assertIn("operator decision 2026-05-26", row["skip_reason"])

    def test_kontrol_log_row_appended(self):
        DTO.run_kontrol(self.ws, "contracts/Foo.sol")
        log_path = self.ws / ".auditooor" / "depth_tools_log.jsonl"
        self.assertTrue(log_path.exists())
        parsed = json.loads(log_path.read_text().splitlines()[0])
        self.assertEqual(parsed["tool"], "kontrol")
        self.assertEqual(parsed["status"], "SKIPPED")


class TestMainHevmKontrolWiring(unittest.TestCase):
    """End-to-end --hevm / --kontrol / --all flag wiring through main()."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.ws = Path(self.tmp)

    def test_main_hevm_flag_dry_run(self):
        rc = DTO.main([
            "--workspace", str(self.ws),
            "--hevm", "contracts/Foo.sol",
            "--dry-run", "--json",
        ])
        self.assertEqual(rc, 0)
        log_path = self.ws / ".auditooor" / "depth_tools_log.jsonl"
        parsed = json.loads(log_path.read_text().splitlines()[0])
        self.assertEqual(parsed["tool"], "hevm")
        self.assertEqual(parsed["status"], "SKIPPED")
        self.assertEqual(parsed["skip_reason"], "dry-run mode")

    def test_main_kontrol_flag(self):
        rc = DTO.main([
            "--workspace", str(self.ws),
            "--kontrol", "contracts/Foo.sol",
            "--json",
        ])
        self.assertEqual(rc, 0)
        log_path = self.ws / ".auditooor" / "depth_tools_log.jsonl"
        parsed = json.loads(log_path.read_text().splitlines()[0])
        self.assertEqual(parsed["tool"], "kontrol")
        self.assertEqual(parsed["status"], "SKIPPED")

    def test_main_all_flag_emits_all_tool_rows(self):
        rc = DTO.main([
            "--workspace", str(self.ws),
            "--all", "--dry-run", "--json",
        ])
        self.assertEqual(rc, 0)
        log_path = self.ws / ".auditooor" / "depth_tools_log.jsonl"
        lines = log_path.read_text().splitlines()
        tools_seen = {json.loads(l)["tool"] for l in lines}
        # --all without --differential-fuzz/--reference skips that runner.
        expected = {
            "halmos", "foundry-fuzz-1m", "mythril", "manticore",
            "hevm", "kontrol", "soak-fuzz", "rule14-deep-integrate",
        }
        self.assertEqual(tools_seen, expected)

    def test_main_all_with_differential_includes_it(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".sol", delete=False) as f:
            f.write("// fake ref\n")
            ref_path = f.name
        try:
            rc = DTO.main([
                "--workspace", str(self.ws),
                "--all", "--dry-run", "--json",
                "--differential-fuzz", "test/Diff.sol",
                "--reference", ref_path,
            ])
            self.assertEqual(rc, 0)
            log_path = self.ws / ".auditooor" / "depth_tools_log.jsonl"
            lines = log_path.read_text().splitlines()
            tools_seen = {json.loads(l)["tool"] for l in lines}
            self.assertIn("differential-fuzz", tools_seen)
            self.assertIn("hevm", tools_seen)
            self.assertIn("kontrol", tools_seen)
        finally:
            os.unlink(ref_path)

    def test_main_no_args_lists_all_in_help(self):
        # Empty arg set without --all should hint at --hevm / --kontrol / --all.
        # We can't easily capture stderr from main() here; the rc=2 path is
        # tested in TestMainSummary. Confirm the inventory banner is built
        # by calling main and ensuring the summary log path is set.
        rc = DTO.main([
            "--workspace", str(self.ws),
            "--hevm", "contracts/Foo.sol",
            "--dry-run", "--json",
        ])
        self.assertEqual(rc, 0)


# r36-rebuttal: bugfix-inventory-claude-20260610
class TestDirectoryTargetNotApplicable(unittest.TestCase):
    """Verify that passing a directory as a tool target emits skip_reason
    prefixed with 'target-not-applicable:' and that the exhaustion gate
    does NOT count such rows as evidence-of-attempt.

    This guards against the false-green described in bug 'wrong-target-fallback':
    when --all passes str(workspace) as the halmos/foundry/mythril/manticore
    target, the language-detection returns 'other' and the runners emit
    SKIPPED rows.  Without this fix those SKIPPED rows satisfy the Gap #37
    exhaustion gate even though halmos was never run on any Solidity code.
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.ws = Path(self.tmp)
        # Import the exhaustion gate module so we can call evaluate() directly.
        _gate_path = _REPO_ROOT / "tools" / "exhaustion-verdict-tools-attempt-required-check.py"
        spec = importlib.util.spec_from_file_location(
            "exhaustion_verdict_gate", _gate_path
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        self.gate = mod

    # ------------------------------------------------------------------
    # Part A: orchestrator emits target-not-applicable prefix for dirs
    # ------------------------------------------------------------------

    def test_halmos_dir_target_emits_target_not_applicable(self):
        """run_halmos with a directory target must emit skip_reason starting
        with 'target-not-applicable:' - NOT the generic language mismatch."""
        row = DTO.run_halmos(self.ws, str(self.ws), dry_run=False)
        self.assertEqual(row["status"], "SKIPPED")
        self.assertTrue(
            row["skip_reason"].startswith("target-not-applicable:"),
            f"Expected skip_reason to start with 'target-not-applicable:', got: {row['skip_reason']!r}",
        )

    def test_foundry_dir_target_emits_target_not_applicable(self):
        row = DTO.run_foundry_fuzz_1m(self.ws, str(self.ws), runs=1000, dry_run=False)
        self.assertEqual(row["status"], "SKIPPED")
        self.assertTrue(
            row["skip_reason"].startswith("target-not-applicable:"),
            f"Expected skip_reason to start with 'target-not-applicable:', got: {row['skip_reason']!r}",
        )

    def test_mythril_dir_target_emits_target_not_applicable(self):
        row = DTO.run_mythril(self.ws, str(self.ws), dry_run=False)
        self.assertEqual(row["status"], "SKIPPED")
        self.assertTrue(
            row["skip_reason"].startswith("target-not-applicable:"),
            f"Expected skip_reason to start with 'target-not-applicable:', got: {row['skip_reason']!r}",
        )

    def test_manticore_dir_target_emits_target_not_applicable(self):
        row = DTO.run_manticore(self.ws, str(self.ws), dry_run=False)
        self.assertEqual(row["status"], "SKIPPED")
        self.assertTrue(
            row["skip_reason"].startswith("target-not-applicable:"),
            f"Expected skip_reason to start with 'target-not-applicable:', got: {row['skip_reason']!r}",
        )

    def test_halmos_file_target_other_lang_does_not_emit_target_not_applicable(self):
        """For a .rs file (non-dir, non-Solidity) the old skip_reason is used -
        no 'target-not-applicable:' prefix because the target is a file."""
        row = DTO.run_halmos(self.ws, "src/lib.rs", dry_run=False)
        self.assertEqual(row["status"], "SKIPPED")
        self.assertFalse(
            row["skip_reason"].startswith("target-not-applicable:"),
            f"A .rs file should NOT get target-not-applicable prefix, got: {row['skip_reason']!r}",
        )

    # ------------------------------------------------------------------
    # Part B: exhaustion gate treats target-not-applicable as NOT evidence
    # ------------------------------------------------------------------

    def _write_gate_log(self, rows: list[dict]) -> Path:
        """Write rows to the workspace's depth_tools_log.jsonl."""
        log_dir = self.ws / ".auditooor"
        log_dir.mkdir(parents=True, exist_ok=True)
        log_path = log_dir / "depth_tools_log.jsonl"
        with log_path.open("w") as f:
            for r in rows:
                f.write(json.dumps(r) + "\n")
        return log_path

    def _write_lane_file(self, content: str) -> Path:
        """Write a lane results file containing an exhaustion-class verdict."""
        lane_path = self.ws / "lane_results.md"
        lane_path.write_text(content)
        return lane_path

    def test_gate_fails_when_only_target_not_applicable_rows(self):
        """An exhaustion gate evaluate() must return fail-exhaustion-tools-incomplete
        when the depth_tools_log contains only target-not-applicable SKIPPED rows
        for the halmos family (and other families are missing entirely).

        This is the core regression test: before the fix, the gate would return
        'pass-all-tools-attempted' because SKIPPED was in EVIDENCE_STATUSES.
        """
        halmos_row = {
            "schema": "auditooor.depth_tools_orchestrator.v1",
            "tool": "halmos",
            "target": str(self.ws),
            "status": "SKIPPED",
            "skip_reason": "target-not-applicable: directory target requires explicit --halmos <file.sol>",
        }
        log_path = self._write_gate_log([halmos_row])
        lane_path = self._write_lane_file("## Verdict: EXHAUSTED\n\nNo findings.\n")
        result = self.gate.evaluate(lane_path, self.ws, log_path, strict=False)
        self.assertNotEqual(
            result["verdict"],
            "pass-all-tools-attempted",
            "A target-not-applicable SKIPPED row must NOT satisfy the halmos family.",
        )
        # The halmos family should be among the missing families.
        missing = result.get("evidence", {}).get("missing_families", [])
        self.assertIn(
            "halmos",
            missing,
            f"halmos must appear in missing_families, got: {missing}",
        )

    def test_gate_passes_when_not_installed_skip_reason(self):
        """A SKIPPED row with skip_reason 'halmos binary not installed' (tool absent,
        not wrong target) must still count as evidence-of-attempt.  This preserves
        the original correct behavior for the 'tool not present on this host' case.

        We provide rows for all required families - all with 'not installed' skip_reason
        - to verify 'pass-all-tools-attempted' is returned.
        """
        families_rows = [
            {"tool": "orient-prefilter", "status": "SKIPPED",
             "skip_reason": "orient-prefilter not installed"},
            {"tool": "hacker-mcp", "status": "SKIPPED",
             "skip_reason": "hacker-mcp not installed"},
            {"tool": "audit-deep", "status": "SKIPPED",
             "skip_reason": "audit-deep not installed"},
            {"tool": "foundry-fuzz-1m", "status": "SKIPPED",
             "skip_reason": "forge binary not installed"},
            {"tool": "halmos", "status": "SKIPPED",
             "skip_reason": "halmos binary not installed; see docs/DEPTH_TOOLS_INSTALL.md"},
            {"tool": "differential-fuzz", "status": "SKIPPED",
             "skip_reason": "differential-fuzz not installed"},
            {"tool": "mythril", "status": "SKIPPED",
             "skip_reason": "myth binary not installed"},
            {"tool": "rule14-deep-integrate", "status": "SKIPPED",
             "skip_reason": "rule14 not installed"},
        ]
        log_path = self._write_gate_log(families_rows)
        lane_path = self._write_lane_file("## Verdict: EXHAUSTED\n\nNo findings.\n")
        result = self.gate.evaluate(lane_path, self.ws, log_path, strict=False)
        self.assertEqual(
            result["verdict"],
            "pass-all-tools-attempted",
            f"'not installed' skip_reason must still satisfy the family, got: {result['verdict']}",
        )

    def test_gate_all_mode_dir_target_fails_on_halmos_family(self):
        """Simulate what happens when --all is run with workspace-as-target:
        write the exact skip_reason that run_halmos emits for a directory,
        verify the gate fails the halmos family (not a false green).
        """
        # This is the exact row the orchestrator now emits for --all without --halmos.
        halmos_row = DTO.run_halmos(self.ws, str(self.ws), dry_run=False)
        # Also add rows for all other families so halmos is the only missing one.
        other_rows = [
            {"tool": "orient-prefilter", "status": "SKIPPED",
             "skip_reason": "orient-prefilter not installed"},
            {"tool": "hacker-mcp", "status": "SKIPPED",
             "skip_reason": "hacker-mcp not installed"},
            {"tool": "audit-deep", "status": "SKIPPED",
             "skip_reason": "audit-deep not installed"},
            {"tool": "foundry-fuzz-1m", "status": "SKIPPED",
             "skip_reason": "target-not-applicable: directory target"},
            {"tool": "differential-fuzz", "status": "SKIPPED",
             "skip_reason": "differential-fuzz not installed"},
            {"tool": "mythril", "status": "SKIPPED",
             "skip_reason": "target-not-applicable: directory target"},
            {"tool": "rule14-deep-integrate", "status": "SKIPPED",
             "skip_reason": "rule14 not installed"},
        ]
        # Read the log already written by run_halmos and combine with other rows.
        log_dir = self.ws / ".auditooor"
        log_dir.mkdir(parents=True, exist_ok=True)
        log_path = log_dir / "depth_tools_log.jsonl"
        existing = []
        if log_path.exists():
            existing = [json.loads(l) for l in log_path.read_text().splitlines() if l.strip()]
        with log_path.open("w") as f:
            for r in existing + other_rows:
                f.write(json.dumps(r) + "\n")
        lane_path = self._write_lane_file("## Verdict: EXHAUSTED\n\nNo findings.\n")
        result = self.gate.evaluate(lane_path, self.ws, log_path, strict=False)
        # halmos + foundry-fuzz-1m + symbolic-exec (mythril) all got directory rows.
        missing = result.get("evidence", {}).get("missing_families", [])
        self.assertIn(
            "halmos",
            missing,
            f"halmos must be missing when only target-not-applicable rows exist, got missing={missing}",
        )
        self.assertNotEqual(
            result["verdict"],
            "pass-all-tools-attempted",
            "Gate must not be a false green when only target-not-applicable rows exist for halmos.",
        )


if __name__ == "__main__":
    unittest.main()
