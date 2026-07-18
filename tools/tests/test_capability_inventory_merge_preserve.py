#!/usr/bin/env python3
"""Regression tests for the merge-preserve behaviour of capability-inventory-build.py.

Root-cause guard for the silent-de-registration class: a capability registered by
direct-appending a rich row to reference/capability_inventory.jsonl used to be
wiped by any `capability-inventory-build.py` regen (write_jsonl overwrites), and
the wiring-integrity checker stayed green because a dropped cap falls into
"unknown", not "orphan". build_inventory() now merge-preserves manually-registered
rich rows the build does not reproduce (guarded on on-disk existence). These tests
pin that mechanism so a future overwrite-regression fails loudly.
"""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
BUILD = REPO / "tools" / "capability-inventory-build.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("cap_inv_build", BUILD)
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(mod)
    return mod


MOD = _load_module()


class IsPreservableRichRowTest(unittest.TestCase):
    def test_rich_row_with_existing_tool_is_preservable(self):
        row = {
            "id": "custom-rich-cap",
            "outputs": [".auditooor/x.jsonl"],
            "consumers": ["tools/auto-coverage-closer.py"],
            "file_paths": ["tools/audit-deep.sh"],
        }
        self.assertTrue(MOD._is_preservable_rich_row(row))

    def test_auto_derived_id_is_not_preserved(self):
        # CAP-tool-* / CAP-make-* etc. are reproduced by the build; never preserved.
        for cid in ("CAP-tool-foo", "CAP-make-bar", "CAP-mcp-baz", "CAP-rule-qux", "CAP-hook-x"):
            row = {"id": cid, "outputs": ["x.jsonl"], "file_paths": ["tools/audit-deep.sh"]}
            self.assertFalse(MOD._is_preservable_rich_row(row), cid)

    def test_row_without_wiring_is_not_preserved(self):
        row = {"id": "custom-cap", "outputs": [], "consumers": [], "file_paths": ["tools/audit-deep.sh"]}
        self.assertFalse(MOD._is_preservable_rich_row(row))

    def test_deleted_tool_row_is_dropped(self):
        # On-disk existence guard: a stale row for a removed tool must NOT survive.
        row = {
            "id": "custom-cap",
            "outputs": ["x.jsonl"],
            "consumers": ["tools/auto-coverage-closer.py"],
            "file_paths": ["tools/this-tool-does-not-exist-zzz.py"],
        }
        self.assertFalse(MOD._is_preservable_rich_row(row))

    def test_test_only_file_paths_are_not_enough(self):
        row = {
            "id": "custom-cap",
            "outputs": ["x.jsonl"],
            "file_paths": ["tools/tests/test_something.py"],
        }
        self.assertFalse(MOD._is_preservable_rich_row(row))


class BuildInventoryMergePreserveTest(unittest.TestCase):
    def test_synthetic_rich_row_survives_a_build(self):
        synthetic = {
            "id": "zz-merge-preserve-probe",
            "name": "probe",
            "category": "python-tool",
            "outputs": [".auditooor/probe.jsonl"],
            "consumers": ["tools/auto-coverage-closer.py"],
            "file_paths": ["tools/audit-deep.sh"],
            "inputs": ["synthetic-input"],
            "status": "landed",
            "known_bugs": [],
        }
        orig = MOD._load_existing_inventory
        MOD._load_existing_inventory = lambda: [synthetic]
        try:
            caps, _flows = MOD.build_inventory()
            ids = {c["id"] for c in caps}
            self.assertIn(
                "zz-merge-preserve-probe", ids,
                "a non-reproduced rich row with an existing tool file must be merge-preserved",
            )
            preserved = next(c for c in caps if c["id"] == "zz-merge-preserve-probe")
            self.assertIn("preserved-across-regen", preserved.get("notes", ""))
        finally:
            MOD._load_existing_inventory = orig

    def test_synthetic_deleted_tool_row_is_dropped_by_build(self):
        stale = {
            "id": "zz-stale-deleted-tool-probe",
            "name": "stale",
            "category": "python-tool",
            "outputs": [".auditooor/probe.jsonl"],
            "consumers": ["tools/auto-coverage-closer.py"],
            "file_paths": ["tools/removed-tool-zzz.py"],
            "inputs": ["x"],
            "status": "landed",
            "known_bugs": [],
        }
        orig = MOD._load_existing_inventory
        MOD._load_existing_inventory = lambda: [stale]
        try:
            caps, _flows = MOD.build_inventory()
            ids = {c["id"] for c in caps}
            self.assertNotIn("zz-stale-deleted-tool-probe", ids)
        finally:
            MOD._load_existing_inventory = orig


if __name__ == "__main__":
    unittest.main()
