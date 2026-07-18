#!/usr/bin/env python3
"""Tests for tools/scan_skip_remediation.py + the closeout / orchestrator
wiring (P2-3 / handover #17).

Covers:

  1. Pure parsing — synthetic logs of every error-class shape produce the
     expected (module, error_class, hint) row.
  2. Aggregation — top-N truncation is deterministic; by-tool / by-class
     counts are computed correctly.
  3. Strict-mode promotion (``REQUIRE_NO_SCAN_SKIPS``) — closeout
     promotes WARN to FAIL when rows exceed the threshold.
  4. End-to-end — orchestrator manifest writer embeds rows; closeout
     reads them and surfaces examples in the human reason and the
     ``audit_closeout_manifest.json`` machine summary.

Stdlib only, hermetic via ``tempfile.TemporaryDirectory``.
"""
from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SCAN_SKIP_PATH = REPO_ROOT / "tools" / "scan_skip_remediation.py"
ORCH_PATH = REPO_ROOT / "tools" / "workspace-scan-orchestrator.py"
CLOSEOUT_PATH = REPO_ROOT / "tools" / "audit-closeout-check.py"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None, f"could not load {path}"
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


SKIP = _load("scan_skip_remediation_under_test", SCAN_SKIP_PATH)
ORCH = _load("workspace_scan_orchestrator_under_test", ORCH_PATH)
CLOSEOUT = _load("audit_closeout_check_under_test", CLOSEOUT_PATH)


# Synthetic log fixtures. Each fixture mimics the real shape emitted by
# the corresponding tool — see tools/scan-per-module.sh and
# detectors/run_custom.py for the canonical formats.

SOLC_VERSION_LOG = """\
[orch] running run_custom.py on workspace
=== module: vault.sol ===
Error: no compiler version matches in pragma solidity ^0.8.20
crytic-compile failed
"""

MISSING_REMAPPING_LOG = """\
=== Running detector on src/Vault.sol
ParserError: Source "@openzeppelin/contracts/token/ERC20/IERC20.sol" not found
"""

PARSER_ERROR_LOG = """\
=== module: BadFile.sol ===
ParserError: Expected ';' but got identifier in src/BadFile.sol:42:18
"""

UNKNOWN_LOG = """\
=== module: weird.sol ===
some unparseable diagnostic that we don't recognise
"""

SCAN_RUNNER_FAILED_LOG = """\
=== module: tricky.sol (FAILED exit=2, see custom-detectors-errors.log) ===
"""


# ---- pure parser tests ------------------------------------------------------


class ParseLogTextTest(unittest.TestCase):
    def test_solc_version_mismatch_emits_install_hint(self) -> None:
        rows = SKIP.parse_log_text(
            SOLC_VERSION_LOG,
            tool="run_custom.py",
            log_path="/tmp/run_custom.log",
            default_module="run_custom.py",
        )
        # We expect one solc-version-mismatch row (deduped per module/class).
        classes = [r.error_class for r in rows]
        self.assertIn("solc-version-mismatch", classes)
        sv = next(r for r in rows if r.error_class == "solc-version-mismatch")
        self.assertEqual(sv.module, "vault.sol")
        self.assertIn("solc-select install 0.8.20", sv.hint)
        self.assertIn("solc-select use 0.8.20", sv.hint)
        self.assertEqual(sv.tool, "run_custom.py")
        self.assertEqual(sv.log_path, "/tmp/run_custom.log")

    def test_missing_remapping_emits_remappings_hint(self) -> None:
        rows = SKIP.parse_log_text(
            MISSING_REMAPPING_LOG,
            tool="apply-queries.sh",
            default_module="apply-queries.sh",
        )
        # Both ParserError and the file-not-found pattern appear; we
        # only require the missing-remapping class to be present.
        classes = [r.error_class for r in rows]
        self.assertIn("missing-remapping", classes)
        mr = next(r for r in rows if r.error_class == "missing-remapping")
        # Module marker comes from "=== Running detector on src/Vault.sol".
        self.assertEqual(mr.module, "src/Vault.sol")
        self.assertIn("remappings.txt", mr.hint)
        self.assertIn("@openzeppelin", mr.hint)

    def test_parser_error_includes_file_line(self) -> None:
        rows = SKIP.parse_log_text(
            PARSER_ERROR_LOG,
            tool="slither",
            default_module="slither",
        )
        pe = next(r for r in rows if r.error_class == "parser-error")
        self.assertEqual(pe.module, "BadFile.sol")
        self.assertIn("src/BadFile.sol:42:18", pe.hint)
        self.assertIn("upgrade pragma", pe.hint)

    def test_unknown_error_class_yields_no_row(self) -> None:
        # The placeholder is only emitted when we *know* the scan failed
        # (a tool status of SKIPPED) but no recognised pattern matched.
        # Unrelated junk text must not produce false-positive rows.
        rows = SKIP.parse_log_text(
            UNKNOWN_LOG, tool="run_custom.py", default_module="run_custom.py"
        )
        self.assertEqual(rows, [])

    def test_synthesize_unknown_emits_placeholder_hint(self) -> None:
        row = SKIP.synthesize_unknown(
            tool="run_custom.py",
            module="weird.sol",
            log_path="/tmp/run_custom.log",
            excerpt="some unparseable diagnostic",
        )
        self.assertEqual(row.error_class, "unknown")
        self.assertIn("unknown — see scan log", row.hint)
        self.assertIn("/tmp/run_custom.log", row.hint)

    def test_scan_runner_failed_pattern(self) -> None:
        rows = SKIP.parse_log_text(
            SCAN_RUNNER_FAILED_LOG,
            tool="run_custom.py",
            default_module="run_custom.py",
        )
        # The scan-runner-failed class fires; module is "tricky.sol".
        sf = next(r for r in rows if r.error_class == "scan-runner-failed")
        self.assertEqual(sf.module, "tricky.sol")
        self.assertIn("non-zero exit", sf.hint)

    def test_dedup_same_module_same_class(self) -> None:
        # Same module + same class repeated = ONE row.
        text = SOLC_VERSION_LOG + "\n" + SOLC_VERSION_LOG
        rows = SKIP.parse_log_text(text, tool="run_custom.py")
        solc = [r for r in rows if r.error_class == "solc-version-mismatch"]
        self.assertEqual(len(solc), 1)

    def test_empty_text_returns_empty(self) -> None:
        self.assertEqual(SKIP.parse_log_text("", tool="x"), [])
        self.assertEqual(SKIP.parse_log_text(None, tool="x"), [])  # type: ignore[arg-type]


# ---- aggregation -----------------------------------------------------------


class AggregateTest(unittest.TestCase):
    def test_top_n_truncates_deterministically(self) -> None:
        rows = [
            SKIP.SkipRow(tool="b", module="m", error_class="parser-error",
                         error_excerpt="x", hint="h"),
            SKIP.SkipRow(tool="a", module="m", error_class="parser-error",
                         error_excerpt="x", hint="h"),
            SKIP.SkipRow(tool="a", module="n", error_class="parser-error",
                         error_excerpt="x", hint="h"),
        ]
        agg = SKIP.aggregate(rows, top_n=2)
        self.assertEqual(agg["row_count"], 3)
        self.assertEqual(agg["top_n"], 2)
        self.assertEqual(len(agg["rows"]), 2)
        # Sort key is (tool, error_class, module). Tool "a" rows come first.
        self.assertEqual(agg["rows"][0]["tool"], "a")
        self.assertEqual(agg["rows"][0]["module"], "m")
        self.assertEqual(agg["rows"][1]["tool"], "a")
        self.assertEqual(agg["rows"][1]["module"], "n")
        self.assertEqual(agg["by_tool"], {"a": 2, "b": 1})
        self.assertEqual(agg["by_error_class"], {"parser-error": 3})
        self.assertEqual(
            agg["schema_version"], "auditooor.scan_skip_remediation.v1"
        )

    def test_render_markdown_table(self) -> None:
        rows = [
            SKIP.SkipRow(tool="slither", module="X.sol",
                         error_class="solc-version-mismatch",
                         error_excerpt="...", hint="solc-select install 0.8.20"),
        ]
        md = SKIP.render_markdown_table(rows)
        self.assertIn("| tool | module | error class | remediation hint |", md)
        self.assertIn("`slither`", md)
        self.assertIn("`X.sol`", md)
        self.assertIn("solc-select install 0.8.20", md)

    def test_render_markdown_empty(self) -> None:
        self.assertEqual(SKIP.render_markdown_table([]), "")

    def test_pipe_in_cell_is_escaped(self) -> None:
        rows = [
            SKIP.SkipRow(tool="t|ool", module="m|od", error_class="c",
                         error_excerpt="x", hint="h"),
        ]
        md = SKIP.render_markdown_table(rows)
        # Backslash-escaped pipes are safe markdown.
        self.assertIn("t\\|ool", md)
        self.assertIn("m\\|od", md)


# ---- strict-mode promotion --------------------------------------------------


class PromoteToFailTest(unittest.TestCase):
    def test_no_strict_mode_returns_false(self) -> None:
        rows = [SKIP.SkipRow("a", "b", "c", "d", "e")]
        self.assertFalse(SKIP.promote_to_fail(rows, require_no_skips=False))

    def test_strict_mode_default_threshold_zero(self) -> None:
        # Strict mode + 1 row = FAIL (default threshold=0).
        rows = [SKIP.SkipRow("a", "b", "c", "d", "e")]
        self.assertTrue(SKIP.promote_to_fail(rows, require_no_skips=True))

    def test_strict_mode_threshold_above_count(self) -> None:
        rows = [SKIP.SkipRow("a", "b", "c", "d", "e")]
        # Threshold 5; 1 row -> not failed.
        self.assertFalse(
            SKIP.promote_to_fail(rows, require_no_skips=True, threshold=5)
        )

    def test_strict_mode_strict_count_arg(self) -> None:
        # Pass an integer count instead of an iterable.
        self.assertTrue(SKIP.promote_to_fail(7, require_no_skips=True, threshold=5))
        self.assertFalse(SKIP.promote_to_fail(3, require_no_skips=True, threshold=5))

    def test_env_variable_picks_up_strict_mode(self) -> None:
        rows = [SKIP.SkipRow("a", "b", "c", "d", "e")]
        prev = os.environ.get("REQUIRE_NO_SCAN_SKIPS")
        try:
            os.environ["REQUIRE_NO_SCAN_SKIPS"] = "1"
            self.assertTrue(SKIP.promote_to_fail(rows))
        finally:
            if prev is None:
                os.environ.pop("REQUIRE_NO_SCAN_SKIPS", None)
            else:
                os.environ["REQUIRE_NO_SCAN_SKIPS"] = prev


# ---- orchestrator wiring ----------------------------------------------------


class OrchestratorWiringTest(unittest.TestCase):
    """Smoke-test that the orchestrator's helpers round-trip the same
    parser used in the closeout. Doesn't actually invoke the slither
    backend — we feed canned text to ``collect_skip_remediation``.
    """

    def test_collect_skip_remediation_returns_rows(self) -> None:
        tool_logs = {
            "detectors/run_custom.py": SOLC_VERSION_LOG,
            "tools/apply-queries.sh": MISSING_REMAPPING_LOG,
        }
        tool_log_paths = {
            "detectors/run_custom.py": "/tmp/run_custom.log",
            "tools/apply-queries.sh": "/tmp/apply_queries.log",
        }
        agg = ORCH.collect_skip_remediation(tool_logs, tool_log_paths)
        self.assertGreater(agg["row_count"], 0)
        self.assertEqual(
            agg["schema_version"], "auditooor.scan_skip_remediation.v1"
        )
        # Both tools represented.
        self.assertIn("detectors/run_custom.py", agg["by_tool"])
        self.assertIn("tools/apply-queries.sh", agg["by_tool"])

    def test_write_environment_manifest_embeds_rows(self) -> None:
        with tempfile.TemporaryDirectory(prefix="orch-") as tmp:
            out = Path(tmp)
            ws = Path(tmp)
            tool_status = {
                "detectors/run_custom.py": "RC=2",
                "tools/apply-queries.sh": "OK",
            }
            tool_logs = {
                "detectors/run_custom.py": SOLC_VERSION_LOG,
                "tools/apply-queries.sh": "",
            }
            tool_log_paths = {
                "detectors/run_custom.py": str(out / "run_custom.log"),
            }
            path = ORCH.write_environment_manifest(
                out_dir=out, workspace=ws, langs={"sol"},
                tool_status=tool_status, tool_logs=tool_logs,
                tool_log_paths=tool_log_paths,
            )
            payload = json.loads(path.read_text(encoding="utf-8"))
            self.assertIn("skipped_modules", payload)
            sm = payload["skipped_modules"]
            self.assertEqual(
                sm["schema_version"],
                "auditooor.scan_skip_remediation.v1",
            )
            self.assertGreaterEqual(sm["row_count"], 1)
            # The hint must mention the install command.
            joined = " ".join(r.get("hint", "") for r in sm["rows"])
            self.assertIn("solc-select install", joined)

    def test_scan_report_contains_remediation_table(self) -> None:
        with tempfile.TemporaryDirectory(prefix="orch-") as tmp:
            out = Path(tmp)
            ws = Path(tmp)
            tool_status = {"detectors/run_custom.py": "RC=2"}
            tool_logs = {"detectors/run_custom.py": SOLC_VERSION_LOG}
            tool_log_paths = {"detectors/run_custom.py": str(out / "run_custom.log")}
            skipped_counts = ORCH.skipped_compilation_counts(tool_status, tool_logs)
            skip_rem = ORCH.collect_skip_remediation(tool_logs, tool_log_paths)
            report_path = ORCH.write_report(
                out, ws, hits=[], tool_status=tool_status,
                skipped_counts=skipped_counts, skip_remediation=skip_rem,
            )
            text = report_path.read_text(encoding="utf-8")
            self.assertIn("## Skipped modules — remediation hints", text)
            self.assertIn("solc-select install 0.8.20", text)
            self.assertIn("| tool | module | error class | remediation hint |", text)


# ---- closeout integration ---------------------------------------------------


def _scaffold_minimal_with_skip_manifest(ws: Path, *, rows: list[dict]) -> None:
    """Write just enough for ``check_detector_environment`` to read the
    manifest. The other closeout checks aren't exercised here; we want
    to inspect the detector-environment row in isolation.
    """
    payload = {
        "schema_version": "auditooor.detector_environment.v1",
        "workspace": str(ws),
        "languages_detected": ["sol"],
        "platform": "test",
        "versions": {
            "python": "test",
            "slither": "missing",
            "solc": "missing",
            "solc-select": "missing",
        },
        "tool_status": {"detectors/run_custom.py": "SKIPPED (no .sol)"},
        "skipped_compilation_counts": {
            "skipped_tools": 0,
            "compile_failure_markers": 0,
            "modules_failed": 0,
            "total": 0,
        },
        "skipped_modules": {
            "schema_version": "auditooor.scan_skip_remediation.v1",
            "row_count": len(rows),
            "top_n": min(len(rows), 5),
            "by_error_class": {},
            "by_tool": {},
            "rows": rows,
        },
    }
    (ws / "detector_environment_manifest.json").write_text(
        json.dumps(payload) + "\n", encoding="utf-8"
    )


class CloseoutIntegrationTest(unittest.TestCase):
    def _example_rows(self) -> list[dict]:
        return [
            {
                "tool": "detectors/run_custom.py",
                "module": "vault.sol",
                "error_class": "solc-version-mismatch",
                "error_excerpt": "Error: no compiler version matches",
                "hint": (
                    "run `solc-select install 0.8.20 && solc-select use 0.8.20` "
                    "(detected from `vault.sol`); rerun the scan after install"
                ),
                "log_path": "/tmp/run_custom.log",
            },
        ]

    def test_check_detector_environment_warns_with_examples(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-") as tmp:
            ws = Path(tmp)
            _scaffold_minimal_with_skip_manifest(ws, rows=self._example_rows())
            row = CLOSEOUT.check_detector_environment(ws)
            self.assertEqual(row.status, CLOSEOUT.WARN)
            # The reason must surface the human-readable example.
            self.assertIn("vault.sol", row.reason)
            self.assertIn("solc-select install 0.8.20", row.reason)
            self.assertIn("examples:", row.reason)
            self.assertEqual(
                row.detail["skip_remediation"]["row_count"], 1
            )
            self.assertGreaterEqual(
                len(row.detail["skip_remediation_examples"]), 1
            )

    def test_check_detector_environment_passes_when_no_rows(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-") as tmp:
            ws = Path(tmp)
            _scaffold_minimal_with_skip_manifest(ws, rows=[])
            row = CLOSEOUT.check_detector_environment(ws)
            self.assertEqual(row.status, CLOSEOUT.PASS)
            self.assertEqual(row.detail["skip_remediation"]["row_count"], 0)

    def test_strict_mode_promotes_to_fail(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-") as tmp:
            ws = Path(tmp)
            _scaffold_minimal_with_skip_manifest(ws, rows=self._example_rows())
            prev = os.environ.get("REQUIRE_NO_SCAN_SKIPS")
            try:
                os.environ["REQUIRE_NO_SCAN_SKIPS"] = "1"
                row = CLOSEOUT.check_detector_environment(ws)
                self.assertEqual(row.status, CLOSEOUT.FAIL)
                self.assertIn("REQUIRE_NO_SCAN_SKIPS=1", row.reason)
                self.assertTrue(row.detail["require_no_scan_skips"])
                self.assertEqual(row.detail["require_no_scan_skips_threshold"], 0)
            finally:
                if prev is None:
                    os.environ.pop("REQUIRE_NO_SCAN_SKIPS", None)
                else:
                    os.environ["REQUIRE_NO_SCAN_SKIPS"] = prev

    def test_strict_mode_threshold_above_count_stays_warn(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-") as tmp:
            ws = Path(tmp)
            _scaffold_minimal_with_skip_manifest(ws, rows=self._example_rows())
            prev_r = os.environ.get("REQUIRE_NO_SCAN_SKIPS")
            prev_t = os.environ.get("REQUIRE_NO_SCAN_SKIPS_THRESHOLD")
            try:
                os.environ["REQUIRE_NO_SCAN_SKIPS"] = "1"
                # 1 row, threshold=5 -> stay WARN.
                os.environ["REQUIRE_NO_SCAN_SKIPS_THRESHOLD"] = "5"
                row = CLOSEOUT.check_detector_environment(ws)
                self.assertEqual(row.status, CLOSEOUT.WARN)
            finally:
                for k, v in (
                    ("REQUIRE_NO_SCAN_SKIPS", prev_r),
                    ("REQUIRE_NO_SCAN_SKIPS_THRESHOLD", prev_t),
                ):
                    if v is None:
                        os.environ.pop(k, None)
                    else:
                        os.environ[k] = v

    def test_machine_summary_carries_examples(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-") as tmp:
            ws = Path(tmp)
            _scaffold_minimal_with_skip_manifest(ws, rows=self._example_rows())
            row = CLOSEOUT.check_detector_environment(ws)
            results = [row]
            machine = CLOSEOUT._detector_environment_manifest_summary(results)
            self.assertIsNotNone(machine)
            self.assertIn("skip_remediation_examples", machine)
            self.assertGreaterEqual(len(machine["skip_remediation_examples"]), 1)
            # Examples must read like "<tool> skipped <module> (<class>); ...".
            self.assertIn("skipped vault.sol", machine["skip_remediation_examples"][0])

    def test_human_format_indents_examples_under_detector_environment(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-") as tmp:
            ws = Path(tmp)
            _scaffold_minimal_with_skip_manifest(ws, rows=self._example_rows())
            row = CLOSEOUT.check_detector_environment(ws)
            text = CLOSEOUT._format_human([row])
            self.assertIn("- detectors/run_custom.py skipped vault.sol", text)
            self.assertIn("solc-select install 0.8.20", text)


if __name__ == "__main__":
    unittest.main()
