#!/usr/bin/env python3
"""Tests for tools/pillar-refresh-daily.py."""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "pillar-refresh-daily.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("pillar_refresh_daily", TOOL)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["pillar_refresh_daily"] = mod
    spec.loader.exec_module(mod)
    return mod


MOD = _load_module()


def _seed_workspace(path: Path, *, with_generated: bool = False) -> None:
    path.mkdir(parents=True, exist_ok=True)
    (path / ".auditooor").mkdir()
    (path / "engage_report.md").write_text("# Engage\n", encoding="utf-8")
    (path / "INTAKE_BASELINE.json").write_text(json.dumps({"file_extension_counts": {".sol": 5}}), encoding="utf-8")
    if with_generated:
        (path / ".auditooor" / "generated_invariants.json").write_text("{}", encoding="utf-8")


class PillarRefreshDailyTests(unittest.TestCase):
    def test_discover_workspaces_requires_two_markers(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _seed_workspace(root / "alpha")
            (root / "too-thin").mkdir()
            (root / "too-thin" / "engage_report.md").write_text("# one marker\n", encoding="utf-8")
            discovered = MOD.discover_workspaces(root)
            self.assertEqual(discovered, [(root / "alpha").resolve()])

    def test_parse_workspace_args_supports_names_and_commas(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _seed_workspace(root / "alpha")
            _seed_workspace(root / "beta")
            parsed = MOD.parse_workspace_args(["alpha,beta"], root)
            self.assertEqual(parsed, [(root / "alpha").resolve(), (root / "beta").resolve()])

    def test_dry_run_plans_live_report_and_safe_invariant_index(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            ws = root / "alpha"
            _seed_workspace(ws, with_generated=True)
            row = MOD.refresh_workspace(
                ws,
                dry_run=True,
                top_n=7,
                write_invariants=False,
                strict_live_target=False,
            )
            self.assertEqual(row["status"], "planned")
            by_name = {step["name"]: step for step in row["steps"]}
            self.assertIn("live-target-report", by_name)
            self.assertIn("invariant-index", by_name)
            self.assertIn("--dry-run", by_name["invariant-index"]["command"])
            self.assertIn("--json", by_name["invariant-index"]["command"])
            self.assertIn("invariant-discovery-adoption", by_name)
            self.assertFalse((ws / "docs" / "LIVE_TARGET_REPORT.md").exists())

    def test_write_invariants_removes_dry_run_modifier(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "alpha"
            _seed_workspace(ws)
            row = MOD.refresh_workspace(
                ws,
                dry_run=True,
                top_n=50,
                write_invariants=True,
                strict_live_target=True,
            )
            inv = {step["name"]: step for step in row["steps"]}["invariant-index"]
            self.assertNotIn("--dry-run", inv["command"])
            self.assertIn("explicit --write-invariants enabled", inv["note"])
            live = {step["name"]: step for step in row["steps"]}["live-target-report"]
            self.assertIn("--strict", live["command"])

    def test_run_refresh_global_steps_are_planned_in_dry_run(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _seed_workspace(root / "alpha")
            args = Namespace(
                audits_root=str(root),
                workspaces=[],
                report_dir=str(root / "reports"),
                top_n=50,
                dry_run=True,
                write_invariants=False,
                strict_live_target=False,
            )
            payload = MOD.run_refresh(args)
            self.assertEqual(payload["schema"], MOD.SCHEMA)
            self.assertEqual(payload["status"], "planned")
            self.assertEqual(payload["workspace_count"], 1)
            global_names = {step["name"] for step in payload["global_steps"]}
            self.assertIn("anti-pattern-catalog-validate", global_names)
            self.assertIn("operator-action-tracker-json", global_names)
            self.assertIn("operator-action-tracker-markdown", global_names)
            self.assertIn("v3-daily-status-snapshot-json", global_names)
            self.assertIn("v3-daily-status-snapshot-markdown", global_names)
            self.assertFalse((root / "reports").exists())


if __name__ == "__main__":
    unittest.main()
