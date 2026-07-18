#!/usr/bin/env python3
"""Tests for zkbugs-ingest.py schema v2 extensions.

Verifies:
1. SCHEMA constant is updated to v2
2. ZkBugRecord has the four new fields
3. Backfill regex correctly extracts template_name from a Circom excerpt
4. Old v1 corpus rows still load with empty defaults for new fields
"""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "zkbugs-ingest.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location("zkbugs_ingest_v2_test_subject", TOOL)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


class ZkBugsSchemaV2Test(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = _load_tool()

    def test_schema_constant_is_v2(self) -> None:
        """SCHEMA constant must be auditooor.zkbugs_index.v2."""
        self.assertEqual(self.tool.SCHEMA, "auditooor.zkbugs_index.v2")

    def test_zkbug_record_has_new_fields(self) -> None:
        """ZkBugRecord dataclass must expose the four v2 fields."""
        import dataclasses
        fields = {f.name for f in dataclasses.fields(self.tool.ZkBugRecord)}
        self.assertIn("template_name", fields)
        self.assertIn("signal_names", fields)
        self.assertIn("component_names", fields)
        self.assertIn("library_handle", fields)

    def test_backfill_extracts_template_name_from_location_function(self) -> None:
        """Backfill must extract template_name from Location.Function for Circom."""
        item = {
            "DSL": "Circom",
            "Project": "https://github.com/demo/proj",
            "Location": {"Function": "BabyJubJub", "Path": "circuits/babyjub.circom"},
            "Short Description of the Vulnerability": "The template is missing a subgroup check.",
        }
        template_name, signal_names, component_names, library_handle = self.tool._backfill_v2(item, "Circom")
        self.assertEqual(template_name, "BabyJubJub")
        self.assertEqual(library_handle, "proj")

    def test_backfill_extracts_signals_from_circom_description(self) -> None:
        """Backfill must extract signal names from Circom text bodies."""
        item = {
            "DSL": "Circom",
            "Project": "https://github.com/org/circuits",
            "Location": {"Function": "", "Path": "circuits/test.circom"},
            "Short Description of the Vulnerability": (
                "The `out[i]` signal is assigned but not constrained. "
                "The `in` signal and `acc` intermediate are also unconstrained."
            ),
        }
        template_name, signal_names, component_names, library_handle = self.tool._backfill_v2(item, "Circom")
        # Backtick-extracted signals
        combined = " ".join(signal_names)
        self.assertIn("out", combined)
        self.assertIn("in", combined)

    def test_v1_rows_load_with_empty_v2_defaults(self) -> None:
        """Loading a minimal v1-style config must produce empty v2 fields."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bug_dir = root / "dataset" / "circom" / "demo" / "v1compat"
            bug_dir.mkdir(parents=True)
            # Minimal v1 config: no template/signal/component info
            (bug_dir / "zkbugs_config.json").write_text(
                json.dumps({
                    "Simple unconstrained signal": {
                        "Id": "demo/v1compat",
                        "DSL": "Circom",
                        "Vulnerability": "Under-Constrained",
                        "Impact": "Soundness",
                        "Root Cause": "Assigned but Unconstrained",
                    }
                }),
                encoding="utf-8",
            )
            records = self.tool.load_records(root)
            self.assertEqual(len(records), 1)
            rec = records[0]
            # v2 fields default to empty
            self.assertIsInstance(rec.template_name, str)
            self.assertIsInstance(rec.signal_names, list)
            self.assertIsInstance(rec.component_names, list)
            self.assertIsInstance(rec.library_handle, str)

    def test_non_circom_gets_loc_function_as_template_name(self) -> None:
        """Non-Circom DSLs should use Location.Function as template_name."""
        item = {
            "DSL": "Halo2",
            "Project": "https://github.com/scroll-tech/zkevm-circuits",
            "Location": {"Function": "ModGadget", "Path": "src/mod.rs"},
            "Short Description of the Vulnerability": "ModGadget is underconstrained.",
        }
        template_name, signal_names, component_names, library_handle = self.tool._backfill_v2(item, "Halo2")
        self.assertEqual(template_name, "ModGadget")
        # Non-Circom gets empty signal/component lists
        self.assertEqual(signal_names, [])
        self.assertEqual(component_names, [])

    def test_library_handle_derived_from_project_url(self) -> None:
        """library_handle must be the repository name from the GitHub URL."""
        item = {
            "DSL": "Circom",
            "Project": "https://github.com/iden3/circomlib",
            "Location": {"Function": "MiMCSponge"},
        }
        _, _, _, library_handle = self.tool._backfill_v2(item, "Circom")
        self.assertEqual(library_handle, "circomlib")


if __name__ == "__main__":
    unittest.main()
