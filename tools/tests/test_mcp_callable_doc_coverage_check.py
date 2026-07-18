#!/usr/bin/env python3
"""Focused tests for tools/mcp-callable-doc-coverage-check.py."""

from __future__ import annotations

import importlib.util
import json
import pathlib
import subprocess
import sys
import tempfile
import textwrap
import unittest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
TOOL = REPO_ROOT / "tools" / "mcp-callable-doc-coverage-check.py"


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "mcp_callable_doc_coverage_check", TOOL
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class TestDocCallableCoverageBuildReport(unittest.TestCase):
    """Validate core extraction and diff logic."""

    def setUp(self):
        self.mod = _load_module()
        self.tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tmp.name)
        self.doc = self.root / "callables.md"
        self.inventory = self.root / "inventory.json"

    def tearDown(self):
        self.tmp.cleanup()

    def _write_doc(self, text: str) -> None:
        self.doc.write_text(textwrap.dedent(text).strip(), encoding="utf-8")

    def _write_inventory(self, payload: object, *, jsonl: bool = False) -> None:
        if jsonl:
            if isinstance(payload, list):
                self.inventory.write_text(
                    "\n".join(json.dumps(row) for row in payload),
                    encoding="utf-8",
                )
            else:
                raise TypeError("jsonl tests should pass list payload")
            return
        self.inventory.write_text(json.dumps(payload), encoding="utf-8")

    def test_doc_coverage_exact_match(self):
        self._write_doc(
            """
            ### `vault_alpha`

            ### `vault_beta`

            ### `vault_gamma`
            """
        )
        self._write_inventory(
            [
                {"name": "vault_alpha"},
                {"name": "vault_beta"},
                {"name": "vault_gamma"},
            ]
        )
        report = self.mod.build_report(
            doc_path=self.doc,
            inventory_path=self.inventory,
            strict=False,
        )
        self.assertEqual(report["overall"], "pass")
        self.assertEqual(report["missing_in_doc"], [])
        self.assertEqual(report["extra_in_doc"], [])
        self.assertEqual(report["coverage_pct"], 100.0)

    def test_doc_missing_inventory_callable(self):
        self._write_doc(
            """
            ### `vault_alpha`

            ### `vault_beta`
            """
        )
        self._write_inventory(
            [
                {"name": "vault_alpha"},
                {"name": "vault_beta"},
                {"name": "vault_gamma"},
            ]
        )
        report = self.mod.build_report(
            doc_path=self.doc,
            inventory_path=self.inventory,
            strict=False,
        )
        self.assertEqual(report["overall"], "fail")
        self.assertEqual(report["missing_in_doc"], [{"callable": "vault_gamma"}])

    def test_extra_callables_warned_without_strict(self):
        self._write_doc(
            """
            ### `vault_alpha`

            ### `vault_beta`

            ### `vault_gamma`

            ### `vault_delta`
            """
        )
        self._write_inventory(
            [
                {"name": "vault_alpha"},
                {"name": "vault_beta"},
                {"name": "vault_gamma"},
            ]
        )
        report = self.mod.build_report(
            doc_path=self.doc,
            inventory_path=self.inventory,
            strict=False,
        )
        self.assertEqual(report["overall"], "pass")
        self.assertEqual(report["extra_in_doc"], [{"callable": "vault_delta", "line": 7}])
        self.assertEqual(len(report["warnings"]), 1)
        self.assertEqual(report["warnings"][0]["count"], 1)

    def test_extra_callables_fail_in_strict(self):
        self._write_doc(
            """
            ### `vault_alpha`

            ### `vault_beta`

            ### `vault_delta`
            """
        )
        self._write_inventory(
            [
                {"name": "vault_alpha"},
                {"name": "vault_beta"},
            ]
        )
        report = self.mod.build_report(
            doc_path=self.doc,
            inventory_path=self.inventory,
            strict=True,
        )
        self.assertEqual(report["overall"], "fail")
        self.assertEqual(report["extra_in_doc"], [{"callable": "vault_delta", "line": 5}])
        self.assertEqual(
            report["errors"],
            [{"type": "extra-callable-documentation", "count": 1}],
        )


class TestLoadFixtureInventory(unittest.TestCase):
    def setUp(self):
        self.mod = _load_module()
        self.tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_jsonl_inventory_parsed_by_name_field(self):
        path = self.root / "inventory.jsonl"
        rows = [
            {"name": "vault_alpha"},
            {"name": "vault_beta"},
        ]
        path.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
        self.assertEqual(
            self.mod.load_fixture_inventory(path),
            ["vault_alpha", "vault_beta"],
        )


class TestCLI(unittest.TestCase):
    """Run the script directly with focused flags."""

    def test_cli_json_output_exit_zero_when_covered(self):
        with tempfile.TemporaryDirectory() as td:
            td_path = pathlib.Path(td)
            doc = td_path / "doc.md"
            doc.write_text(
                "### `vault_alpha`\n### `vault_beta`\n",
                encoding="utf-8",
            )
            inv = td_path / "inventory.json"
            inv.write_text(
                json.dumps([{"name": "vault_alpha"}, {"name": "vault_beta"}]),
                encoding="utf-8",
            )

            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--doc-path",
                    str(doc),
                    "--inventory-path",
                    str(inv),
                    "--json",
                ],
                capture_output=True,
                text=True,
                timeout=20,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads(proc.stdout)
            self.assertEqual(payload["overall"], "pass")


if __name__ == "__main__":
    unittest.main()
