from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


TOOL = Path(__file__).resolve().parents[1] / "awareness-source-inventory.py"
SPEC = importlib.util.spec_from_file_location("awareness_source_inventory", TOOL)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)
PIN = "commit:abc"


class AwarenessSourceInventoryTest(unittest.TestCase):
    def catalog(self, sources: list[dict]) -> dict:
        return {
            "schema": MODULE.SCHEMA,
            "audit_pin": PIN,
            "coverage": {kind: {"status": "complete"} for kind in MODULE.SOURCE_KINDS},
            "sources": sources,
        }

    def test_compiles_stable_exact_inventory(self) -> None:
        catalog = self.catalog([
            {"source_id": "issue-2", "source_kind": "issue", "source_ref": "https://example/2", "pin_binding": PIN},
            {"source_id": "audit-1", "source_kind": "prior_audit", "source_ref": "prior_audits/a.md", "pin_binding": PIN},
        ])
        self.assertEqual(["audit-1", "issue-2"], [row["source_id"] for row in MODULE.compile_expected_sources(catalog, PIN)])

    def test_rejects_duplicate_or_wrong_pin_discovery_rows(self) -> None:
        catalog = self.catalog([
            {"source_id": "same", "source_kind": "commit", "source_ref": "https://example/1", "pin_binding": PIN},
            {"source_id": "same", "source_kind": "commit", "source_ref": "https://example/2", "pin_binding": PIN},
        ])
        with self.assertRaisesRegex(MODULE.InventoryError, "id_invalid"):
            MODULE.compile_expected_sources(catalog, PIN)
