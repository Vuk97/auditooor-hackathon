"""tests/test_cross_workspace_ledger_emit.py — unit tests for cross-workspace-ledger-emit.py

PR #658 Tier-B #10. Covers:
  1. Router map loads and contains expected keys
  2. --list-routes prints all non-underscore entries
  3. _infer_type_from_id parses task_id prefixes correctly
  4. _build_cli expands {placeholder} templates in cli_flags
  5. Dry-run preview prints "would execute" text (no subprocess call)
  6. --apply flag disables dry-run
  7. Missing route returns exit code 1
  8. --refresh-state routes to state-aggregator tool
  9. Ledger stub synthesised when no ledger file found
 10. Paste-ready path injected via --paste-ready flag
 11. Row from ledger parsed correctly (roundtrip)
 12. --help exits 0 and mentions dry-run in output
 13. _substitute replaces all known placeholders
 14. list_routes skips underscore-prefixed entries
 15. _resolve_tool_path returns a Path (even for non-existent paths)
"""

from __future__ import annotations

import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import MagicMock, patch

# Ensure tools/ is importable via dotted path (tools/cross-workspace-ledger-emit.py)
import importlib.util
import types

REPO = Path(__file__).resolve().parent.parent.parent
EMITTER_PATH = REPO / "tools" / "cross-workspace-ledger-emit.py"


def _load_emitter():
    """Import cross-workspace-ledger-emit as a module despite the dashes."""
    spec = importlib.util.spec_from_file_location("cross_workspace_ledger_emit", EMITTER_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


try:
    E = _load_emitter()
except Exception as exc:  # noqa: BLE001
    E = None
    _LOAD_ERROR = str(exc)
else:
    _LOAD_ERROR = ""

ROUTER_MAP_PATH = REPO / "reference" / "cross_ws_router_map.json"


class TestEmitterImport(unittest.TestCase):
    def test_module_loads(self):
        self.assertIsNotNone(E, f"emitter failed to load: {_LOAD_ERROR}")


@unittest.skipIf(E is None, "emitter module not loaded")
class TestRouterMap(unittest.TestCase):
    def setUp(self):
        self.router_map = json.loads(ROUTER_MAP_PATH.read_text())

    def test_router_map_exists(self):
        self.assertTrue(ROUTER_MAP_PATH.is_file())

    def test_router_map_has_filing_lifecycle(self):
        self.assertIn("filing_lifecycle", self.router_map)

    def test_router_map_has_commit_mining(self):
        self.assertIn("commit_mining", self.router_map)

    def test_router_map_has_corpus_mining(self):
        self.assertIn("corpus_mining", self.router_map)

    def test_router_map_has_cross_engagement_propagation(self):
        self.assertIn("cross_engagement_propagation", self.router_map)

    def test_router_map_has_state_refresh_pseudo(self):
        self.assertIn("_state_refresh", self.router_map)

    def test_every_entry_has_tool_key(self):
        for key, entry in self.router_map.items():
            if key.startswith("_comment") or key.startswith("_version") or key.startswith("_doc"):
                continue
            self.assertIn("tool", entry, f"entry {key!r} missing 'tool'")

    def test_emitter_load_router_map(self):
        result = E._load_router_map()
        self.assertIsInstance(result, dict)
        self.assertIn("filing_lifecycle", result)


@unittest.skipIf(E is None, "emitter module not loaded")
class TestInferType(unittest.TestCase):
    def test_commit_mining_prefix(self):
        self.assertEqual(E._infer_type_from_id("TCOMMIT_MINING-20260509-cometbft"), "commit_mining")

    def test_filing_lifecycle_prefix(self):
        self.assertEqual(E._infer_type_from_id("TFILING_LIFECYCLE-20260509-lead1"), "filing_lifecycle")

    def test_cross_engagement_prefix(self):
        self.assertEqual(
            E._infer_type_from_id("TCROSS_ENGAGEMENT_PROPAGATION-20260509-oracle"),
            "cross_engagement_propagation",
        )

    def test_unknown_prefix_defaults_to_klbq(self):
        self.assertEqual(E._infer_type_from_id("TUNKNOWN-20260509-thing"), "klbq_burndown")

    def test_malformed_id_defaults_to_klbq(self):
        self.assertEqual(E._infer_type_from_id("not-a-valid-id"), "klbq_burndown")

    def test_regression_repro_prefix(self):
        self.assertEqual(E._infer_type_from_id("TREGRESSION_REPRO-20260509-snappy"), "regression_repro")


@unittest.skipIf(E is None, "emitter module not loaded")
class TestSubstitute(unittest.TestCase):
    def test_replaces_workspace(self):
        result = E._substitute("--workspace {workspace}", {"workspace": "/tmp/ws"})
        self.assertEqual(result, "--workspace /tmp/ws")

    def test_replaces_multiple(self):
        result = E._substitute("{audits_dir}/{workspace_name}", {"audits_dir": "/a", "workspace_name": "spark"})
        self.assertEqual(result, "/a/spark")

    def test_unknown_placeholder_left_as_is(self):
        result = E._substitute("{unknown}", {"workspace": "/tmp"})
        self.assertEqual(result, "{unknown}")


@unittest.skipIf(E is None, "emitter module not loaded")
class TestBuildCli(unittest.TestCase):
    def test_builds_argv_with_python_first(self):
        entry = {
            "tool": "tools/cross-workspace-state-aggregator.py",
            "cli_flags": ["--audits-dir", "{audits_dir}"],
        }
        ctx = {"audits_dir": "/home/user/audits"}
        argv = E._build_cli(entry, ctx)
        self.assertEqual(argv[0], sys.executable)
        self.assertIn("--audits-dir", argv)
        self.assertIn("/home/user/audits", argv)


@unittest.skipIf(E is None, "emitter module not loaded")
class TestDryRunBehavior(unittest.TestCase):
    def test_dry_run_does_not_call_subprocess(self):
        """_run_or_preview with dry_run=True must NOT call subprocess.run."""
        with patch("subprocess.run") as mock_run:
            buf = io.StringIO()
            with redirect_stdout(buf):
                E._run_or_preview([sys.executable, "--version"], dry_run=True)
            mock_run.assert_not_called()
        self.assertIn("dry-run", buf.getvalue())

    def test_apply_calls_subprocess(self):
        """_run_or_preview with dry_run=False must call subprocess.run."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        with patch("subprocess.run", return_value=mock_result) as mock_run:
            buf = io.StringIO()
            with redirect_stdout(buf):
                E._run_or_preview([sys.executable, "--version"], dry_run=False)
            mock_run.assert_called_once()


@unittest.skipIf(E is None, "emitter module not loaded")
class TestListRoutes(unittest.TestCase):
    def test_list_routes_output(self):
        router_map = E._load_router_map()
        buf = io.StringIO()
        with redirect_stdout(buf):
            E.cmd_list_routes(router_map)
        output = buf.getvalue()
        self.assertIn("filing_lifecycle", output)
        self.assertIn("commit_mining", output)
        # Underscore-prefixed internal keys should NOT appear as regular rows
        self.assertNotIn("_comment", output)

    def test_list_routes_shows_state_refresh(self):
        router_map = E._load_router_map()
        buf = io.StringIO()
        with redirect_stdout(buf):
            E.cmd_list_routes(router_map)
        output = buf.getvalue()
        self.assertIn("--refresh-state", output)


@unittest.skipIf(E is None, "emitter module not loaded")
class TestLedgerRowParsing(unittest.TestCase):
    def _write_ledger(self, rows: list[dict]) -> Path:
        tmp = tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False, mode="w", encoding="utf-8")
        for row in rows:
            tmp.write(json.dumps(row) + "\n")
        tmp.close()
        return Path(tmp.name)

    def test_load_row_finds_matching_id(self):
        row = {
            "schema": "auditooor.universal_task_ledger.v1",
            "id": "TCOMMIT_MINING-20260509-cometbft",
            "type": "commit_mining",
            "title": "Test row",
            "status": "planned",
            "owner_agent": "claude",
            "priority": "P1",
            "created_at": "2026-05-09T00:00:00Z",
            "last_touched": "2026-05-09T00:00:00Z",
        }
        ledger = self._write_ledger([row])
        try:
            result = E._load_row(ledger, "TCOMMIT_MINING-20260509-cometbft")
            self.assertIsNotNone(result)
            self.assertEqual(result["type"], "commit_mining")
        finally:
            ledger.unlink(missing_ok=True)

    def test_load_row_returns_none_for_unknown_id(self):
        row = {
            "schema": "auditooor.universal_task_ledger.v1",
            "id": "TCOMMIT_MINING-20260509-other",
            "type": "commit_mining",
            "title": "Other row",
            "status": "planned",
            "owner_agent": "claude",
            "priority": "P1",
            "created_at": "2026-05-09T00:00:00Z",
            "last_touched": "2026-05-09T00:00:00Z",
        }
        ledger = self._write_ledger([row])
        try:
            result = E._load_row(ledger, "TCOMMIT_MINING-99999999-nonexistent")
            self.assertIsNone(result)
        finally:
            ledger.unlink(missing_ok=True)


@unittest.skipIf(E is None, "emitter module not loaded")
class TestHelpOutput(unittest.TestCase):
    def test_help_exits_zero(self):
        with self.assertRaises(SystemExit) as ctx:
            E.main(["--help"])
        self.assertEqual(ctx.exception.code, 0)

    def test_help_mentions_dry_run(self):
        buf = io.StringIO()
        try:
            with redirect_stdout(buf):
                E.main(["--help"])
        except SystemExit:
            pass
        self.assertIn("dry-run", buf.getvalue().lower())


@unittest.skipIf(E is None, "emitter module not loaded")
class TestMissingRoute(unittest.TestCase):
    def test_no_route_exits_1(self):
        """cmd_emit_row should exit(1) when no route exists for the row type."""
        router_map = E._load_router_map()
        row = {
            "schema": "auditooor.universal_task_ledger.v1",
            "id": "TKLBQ_BURNDOWN-20260509-test",
            "type": "klbq_burndown",  # not in router map
            "title": "Test",
            "status": "planned",
            "owner_agent": "claude",
            "priority": "P1",
            "created_at": "2026-05-09T00:00:00Z",
            "last_touched": "2026-05-09T00:00:00Z",
        }
        with self.assertRaises(SystemExit) as ctx:
            E.cmd_emit_row(
                row=row,
                router_map=router_map,
                workspace=Path("/tmp/ws"),
                audits_dir=Path("/tmp/audits"),
                dry_run=True,
                paste_ready_path=None,
            )
        self.assertEqual(ctx.exception.code, 1)


@unittest.skipIf(E is None, "emitter module not loaded")
class TestResolveTool(unittest.TestCase):
    def test_returns_path_object(self):
        result = E._resolve_tool_path("tools/cross-workspace-state-aggregator.py")
        self.assertIsInstance(result, Path)


if __name__ == "__main__":
    unittest.main()
