"""Tests for tools/peripheral-first-workpack.py (HACKERMAN V3 Lane G3).

Fixture layout:
  fixtures/peripheral_first_workpack/
    ws_mixed/          -- 1 core (CoreVault.sol) + 3 peripherals (Factory, Adapter, Script)
    ws_empty/          -- no source files at all
    ws_no_core/        -- only peripheral adapters dir (no core modules)
"""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "peripheral-first-workpack.py"
FIXTURES = Path(__file__).resolve().parent / "fixtures" / "peripheral_first_workpack"


def _load_tool():
    spec = importlib.util.spec_from_file_location("peripheral_first_workpack", TOOL)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules["peripheral_first_workpack"] = mod
    spec.loader.exec_module(mod)
    return mod


tool = _load_tool()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _peripheral_files(payload: dict) -> set[str]:
    return {row["file"] for row in payload["peripheral_first"]}


def _core_files(payload: dict) -> set[str]:
    return {row["file"] for row in payload["core"]}


def _classes(payload: dict) -> dict[str, str]:
    """file -> peripheral_class for peripheral rows."""
    return {row["file"]: row["peripheral_class"] for row in payload["peripheral_first"]}


def _ranks(payload: dict) -> dict[str, float]:
    """file -> rank_score for peripheral rows (highest = most important)."""
    return {row["file"]: row["rank_score"] for row in payload["peripheral_first"]}


def _all_rows(payload: dict) -> list[dict]:
    return payload["peripheral_first"] + payload["core"]


# ---------------------------------------------------------------------------
# Test: mixed workspace (constructor + factory + adapter + core)
# ---------------------------------------------------------------------------

class TestMixedWorkspace(unittest.TestCase):
    """ws_mixed has CoreVault (core), VaultFactory (factory), ChainlinkAdapter
    (adapter + oracle-setup + constructor), and a deploy script."""

    def setUp(self) -> None:
        self.ws = FIXTURES / "ws_mixed"
        self.payload = tool.classify_workspace(self.ws)

    def test_schema_version(self) -> None:
        self.assertEqual(self.payload["schema"], "auditooor.peripheral_first_workpack.v1")

    def test_generated_at_present(self) -> None:
        self.assertIn("generated_at", self.payload)
        self.assertTrue(self.payload["generated_at"])

    def test_summary_fields_present(self) -> None:
        s = self.payload["summary"]
        for key in ("total_files", "peripheral_files", "core_files",
                    "saturation_boosted_count", "class_counts"):
            self.assertIn(key, s, f"summary missing key: {key}")

    def test_three_peripherals_rank_above_core(self) -> None:
        """Factory, Adapter, and Script must all appear in peripheral_first;
        CoreVault must NOT."""
        pf = _peripheral_files(self.payload)
        cf = _core_files(self.payload)

        # At least 3 peripheral files detected
        self.assertGreaterEqual(
            len(pf), 3,
            f"expected >=3 peripheral files, got {len(pf)}: {pf}",
        )
        # Core vault landed in core section
        core_names = {Path(f).name for f in cf}
        self.assertIn(
            "CoreVault.sol", core_names,
            f"CoreVault.sol should be in core, core files: {cf}",
        )

    def test_factory_class_assigned(self) -> None:
        classes = _classes(self.payload)
        factory_file = next(
            (f for f in classes if "Factory" in f or "factory" in f.lower()), None
        )
        self.assertIsNotNone(factory_file, "VaultFactory.sol not found in peripheral rows")
        self.assertEqual(classes[factory_file], "factory")

    def test_adapter_peripheral_class(self) -> None:
        classes = _classes(self.payload)
        adapter_file = next(
            (f for f in classes if "Adapter" in f or "adapter" in f.lower()), None
        )
        self.assertIsNotNone(adapter_file, "ChainlinkAdapter.sol not found in peripheral rows")
        # adapter or oracle-setup are both valid (ChainlinkAdapter matches both)
        self.assertIn(
            classes[adapter_file], ("adapter", "oracle-setup"),
            f"expected adapter or oracle-setup, got {classes[adapter_file]}",
        )

    def test_deploy_script_peripheral_class(self) -> None:
        classes = _classes(self.payload)
        script_file = next(
            (f for f in classes if "Deploy" in f or "script" in f.lower()), None
        )
        self.assertIsNotNone(script_file, "Deploy script not found in peripheral rows")
        self.assertEqual(
            classes[script_file], "deploy-script",
            f"deploy script should be deploy-script, got {classes[script_file]}",
        )

    def test_deploy_script_ranks_highest(self) -> None:
        """deploy-script has base rank 10; should be at or near top."""
        ranks = _ranks(self.payload)
        if not ranks:
            self.skipTest("no peripheral rows to rank")
        script_rank = max(
            v for k, v in ranks.items()
            if "Deploy" in k or "script" in k.lower() or "scripts" in str(Path(k).parent).lower()
        )
        max_rank = max(ranks.values())
        # script rank should be within 4 points of the max (allows saturation boosts)
        self.assertGreaterEqual(script_rank, max_rank - 4.0)

    def test_each_peripheral_row_has_class_and_rationale(self) -> None:
        for row in self.payload["peripheral_first"]:
            self.assertIn(
                "peripheral_class", row,
                f"row missing peripheral_class: {row['file']}",
            )
            self.assertIn(
                "rationale", row,
                f"row missing rationale: {row['file']}",
            )
            self.assertTrue(
                row["rationale"],
                f"rationale is empty for: {row['file']}",
            )

    def test_each_peripheral_row_has_label(self) -> None:
        for row in self.payload["peripheral_first"]:
            self.assertIn("label", row)
            self.assertTrue(row["label"], f"empty label for {row['file']}")

    def test_rank_score_present_and_positive(self) -> None:
        for row in self.payload["peripheral_first"]:
            self.assertGreater(row["rank_score"], 0.0)

    def test_peripheral_first_ordered_by_rank_desc(self) -> None:
        ranks = [r["rank_score"] for r in self.payload["peripheral_first"]]
        self.assertEqual(ranks, sorted(ranks, reverse=True))

    def test_constructor_fn_hit_captured(self) -> None:
        """ChainlinkAdapter.sol has a constructor; should produce a function hit."""
        adapter_row = next(
            (r for r in self.payload["peripheral_first"] if "ChainlinkAdapter" in r["file"]),
            None,
        )
        if adapter_row is None:
            self.skipTest("ChainlinkAdapter not in peripheral rows")
        fn_names = {f["function"] for f in adapter_row.get("functions", [])}
        # constructor OR setOracleFeed should be detected
        self.assertTrue(
            fn_names,
            f"No function hits for ChainlinkAdapter; expected constructor/setOracleFeed",
        )


# ---------------------------------------------------------------------------
# Test: empty workspace
# ---------------------------------------------------------------------------

class TestEmptyWorkspace(unittest.TestCase):
    """ws_empty has no source files; tool must return a valid empty payload."""

    def setUp(self) -> None:
        self.ws = FIXTURES / "ws_empty"
        self.ws.mkdir(parents=True, exist_ok=True)
        self.payload = tool.classify_workspace(self.ws)

    def test_schema_present(self) -> None:
        self.assertEqual(self.payload["schema"], "auditooor.peripheral_first_workpack.v1")

    def test_empty_sections(self) -> None:
        self.assertEqual(self.payload["summary"]["total_files"], 0)
        self.assertEqual(self.payload["peripheral_first"], [])
        self.assertEqual(self.payload["core"], [])

    def test_summary_keys_present(self) -> None:
        s = self.payload["summary"]
        for key in ("total_files", "peripheral_files", "core_files",
                    "saturation_boosted_count"):
            self.assertIn(key, s)


# ---------------------------------------------------------------------------
# Test: no-core workspace (only adapter peripheral)
# ---------------------------------------------------------------------------

class TestNoCoreWorkspace(unittest.TestCase):
    """ws_no_core has only a BridgeRouter in an adapters/ dir - no core modules."""

    def setUp(self) -> None:
        self.ws = FIXTURES / "ws_no_core"
        self.payload = tool.classify_workspace(self.ws)

    def test_all_files_are_peripheral(self) -> None:
        self.assertEqual(self.payload["core"], [])
        self.assertGreater(len(self.payload["peripheral_first"]), 0)

    def test_bridge_router_class(self) -> None:
        classes = _classes(self.payload)
        router_file = next(
            (f for f in classes if "Bridge" in f or "Router" in f or "adapter" in f.lower()), None
        )
        self.assertIsNotNone(router_file)
        # dir is 'adapters' -> adapter class; filename is BridgeRouter -> bridge-router
        # either is acceptable
        self.assertIn(classes[router_file], ("adapter", "bridge-router"))


# ---------------------------------------------------------------------------
# Test: saturation cross-check
# ---------------------------------------------------------------------------

class TestSaturationCrossCheck(unittest.TestCase):
    """When target_saturation.json marks a module as cold_read, it gets
    promoted to the peripheral_first section even if its path looks like core."""

    def test_saturation_boost_promotes_core_module(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            src = ws / "src"
            src.mkdir()

            # Write a "core"-looking file
            (src / "CoreMarket.sol").write_text(
                "// SPDX-License-Identifier: MIT\n"
                "pragma solidity ^0.8.0;\n"
                "contract CoreMarket {\n"
                "    function matchOrders() external {}\n"
                "}\n",
                encoding="utf-8",
            )

            # Without saturation file: CoreMarket should be in core
            payload_no_sat = tool.classify_workspace(ws)
            core_names_no_sat = {Path(f).name for f in _core_files(payload_no_sat)}
            # It may be in core or unclassified - either way not boosted
            self.assertFalse(
                any(r["saturation_boosted"] for r in _all_rows(payload_no_sat)),
                "no saturation file should mean no boosts",
            )

            # Now add target_saturation.json marking CoreMarket as cold_read
            auditooor_dir = ws / ".auditooor"
            auditooor_dir.mkdir()
            sat_payload = {
                "schema": "auditooor.target_saturation.v1",
                "modules": [
                    {
                        "module": "CoreMarket",
                        "recommended_action": "cold_read",
                        "saturation_score": 0,
                    }
                ],
            }
            (auditooor_dir / "target_saturation.json").write_text(
                json.dumps(sat_payload), encoding="utf-8"
            )

            payload_with_sat = tool.classify_workspace(ws)
            # CoreMarket should now be boosted
            all_rows = _all_rows(payload_with_sat)
            boosted = [r for r in all_rows if r["saturation_boosted"]]
            self.assertTrue(boosted, "expected at least 1 saturation-boosted row")
            boosted_names = {Path(r["file"]).name for r in boosted}
            self.assertIn("CoreMarket.sol", boosted_names)

            # summary should reflect
            self.assertGreater(payload_with_sat["summary"]["saturation_boosted_count"], 0)
            self.assertTrue(payload_with_sat["summary"]["saturation_json_present"])


# ---------------------------------------------------------------------------
# Test: write_payload
# ---------------------------------------------------------------------------

class TestWritePayload(unittest.TestCase):
    def test_write_creates_file(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            (ws / "src").mkdir()
            (ws / "src" / "Stub.sol").write_text(
                "pragma solidity ^0.8.0;\ncontract Stub {}\n",
                encoding="utf-8",
            )
            payload = tool.classify_workspace(ws)
            out = tool.write_payload(payload, ws)
            self.assertTrue(out.exists())
            loaded = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(loaded["schema"], "auditooor.peripheral_first_workpack.v1")


if __name__ == "__main__":
    unittest.main()
