"""
Tests for tools/state-config-diff.py (G1 live state/config diff runner).
Schema: auditooor.state_config_diff.v1

All tests are OFFLINE-SAFE: no network calls are made.
Run with: python3 -m unittest tools.tests.test_state_config_diff -v
"""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

# ---------------------------------------------------------------------------
# Load tool as a module
# ---------------------------------------------------------------------------
TOOL_PATH = Path(__file__).resolve().parents[1] / "state-config-diff.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location("state_config_diff", TOOL_PATH)
    assert spec and spec.loader, f"Cannot load {TOOL_PATH}"
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


TOOL = _load_tool()
FIXTURES = Path(__file__).resolve().parent / "fixtures" / "state_config_diff"


def _build(ws_name: str, **kwargs) -> dict:
    ws = FIXTURES / ws_name
    if not ws.is_dir():
        raise FileNotFoundError(f"Fixture workspace missing: {ws}")
    return TOOL.build_state_config_diff(ws, **kwargs)


# ---------------------------------------------------------------------------
# Schema / structural tests
# ---------------------------------------------------------------------------

class TestSchema(unittest.TestCase):
    def test_schema_field_present(self):
        result = _build("ws_basic")
        self.assertEqual(result["schema"], "auditooor.state_config_diff.v1")

    def test_schema_version_is_string_1(self):
        result = _build("ws_basic")
        self.assertEqual(result["schema_version"], "1")

    def test_offline_safe_flag(self):
        result = _build("ws_basic")
        self.assertIs(result["offline_safe"], True)

    def test_generated_at_iso(self):
        result = _build("ws_basic")
        ts = result["generated_at"]
        self.assertIn("T", ts)
        self.assertTrue(ts.endswith("Z"), f"Bad timestamp: {ts}")

    def test_required_top_level_keys(self):
        result = _build("ws_basic")
        required = {
            "schema", "schema_version", "workspace", "generated_at",
            "mode", "assets_total", "assets_with_probes",
            "total_divergences", "offline_safe", "note", "assets",
        }
        missing = required - set(result.keys())
        self.assertFalse(missing, f"Missing top-level keys: {missing}")


# ---------------------------------------------------------------------------
# Mode A: read-plan emit (no probes present)
# ---------------------------------------------------------------------------

class TestReadPlanMode(unittest.TestCase):
    def test_mode_is_read_plan_when_no_probes(self):
        result = _build("ws_basic")
        self.assertEqual(result["mode"], "read_plan")

    def test_assets_extracted_from_scope(self):
        result = _build("ws_basic")
        # ws_basic scope.json has 2 assets (VaultProxy on Polygon, LendingPool on Ethereum)
        self.assertEqual(result["assets_total"], 2)

    def test_read_plan_items_present(self):
        result = _build("ws_basic")
        for asset_entry in result["assets"]:
            self.assertGreater(
                len(asset_entry["read_plan"]), 0,
                f"Empty read_plan for {asset_entry['name']}"
            )

    def test_read_plan_item_has_pinned_cmd(self):
        result = _build("ws_basic")
        for asset_entry in result["assets"]:
            for item in asset_entry["read_plan"]:
                self.assertIn("pinned_cmd", item)
                self.assertGreater(len(item["pinned_cmd"]), 0)

    def test_read_plan_item_has_block(self):
        result = _build("ws_basic")
        for asset_entry in result["assets"]:
            for item in asset_entry["read_plan"]:
                self.assertIn("block", item)

    def test_pinned_cmd_contains_address(self):
        result = _build("ws_basic")
        for asset_entry in result["assets"]:
            addr = asset_entry["address"]
            for item in asset_entry["read_plan"]:
                cmd = item["pinned_cmd"]
                self.assertTrue(
                    addr.lower() in cmd.lower() or addr in cmd,
                    f"Address not in cmd: {cmd}"
                )

    def test_chain_id_inferred_from_scope_url(self):
        result = _build("ws_basic")
        names = {a["name"]: a for a in result["assets"]}
        # VaultProxy -> polygonscan.com -> chain_id 137
        self.assertEqual(names["VaultProxy"]["chain_id"], 137)
        # LendingPool -> etherscan.io -> chain_id 1
        self.assertEqual(names["LendingPool"]["chain_id"], 1)

    def test_no_divergences_in_read_plan_mode(self):
        result = _build("ws_basic")
        for asset_entry in result["assets"]:
            self.assertEqual(asset_entry["divergence_count"], 0)

    def test_no_probe_coverage_in_read_plan_mode(self):
        result = _build("ws_basic")
        for asset_entry in result["assets"]:
            self.assertIs(asset_entry["probe_coverage"], False)

    def test_block_override_propagates(self):
        result = _build("ws_basic", block=19_000_000)
        for asset_entry in result["assets"]:
            for item in asset_entry["read_plan"]:
                self.assertTrue(
                    "19000000" in str(item["block"]) or item["block"] == 19_000_000,
                    f"Block not propagated: {item['block']}"
                )

    def test_categories_override_restricts_items(self):
        result = _build("ws_basic", categories_override=["proxy"])
        for asset_entry in result["assets"]:
            for item in asset_entry["read_plan"]:
                self.assertEqual(item["category"], "proxy")

    def test_eip1967_impl_slot_present_in_proxy_items(self):
        result = _build("ws_basic", categories_override=["proxy"])
        slot_values = set()
        for asset_entry in result["assets"]:
            for item in asset_entry["read_plan"]:
                if "slot" in item:
                    slot_values.add(item["slot"])
        impl_slot = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
        self.assertIn(impl_slot, slot_values)


# ---------------------------------------------------------------------------
# Mode B: probe-diff (probes present + divergence detected)
# ---------------------------------------------------------------------------

class TestProbeDiffMode(unittest.TestCase):
    def test_mode_is_probe_diff_when_probes_exist(self):
        result = _build("ws_divergence")
        self.assertEqual(result["mode"], "probe_diff")

    def test_divergence_detected(self):
        result = _build("ws_divergence")
        self.assertTrue(
            result["exploit_queue_seeds"],
            "Expected at least one exploit_queue_seed"
        )

    def test_exploit_queue_seed_schema(self):
        result = _build("ws_divergence")
        for seed in result["exploit_queue_seeds"]:
            self.assertEqual(seed["schema"], "auditooor.exploit_queue_seed.v1")
            self.assertIn("address", seed)
            self.assertIn("divergence_class", seed)
            self.assertIn("evidence_cmd", seed)
            self.assertIn("severity_hint", seed)

    def test_implementation_mismatch_is_exploit_seed(self):
        result = _build("ws_divergence")
        classes = {s["divergence_class"] for s in result["exploit_queue_seeds"]}
        self.assertIn("implementation_mismatch", classes, f"Got classes: {classes}")

    def test_exploit_seed_references_pinned_cmd(self):
        result = _build("ws_divergence")
        for seed in result["exploit_queue_seeds"]:
            cmd = seed.get("evidence_cmd", "")
            self.assertTrue(
                "cast" in cmd or "rpc" in cmd.lower() or len(cmd) > 10,
                f"evidence_cmd looks wrong: {cmd}"
            )

    def test_matching_values_not_flagged_as_divergence(self):
        result = _build("ws_divergence")
        classes = {s["divergence_class"] for s in result["exploit_queue_seeds"]}
        # admin_address matches in the probe -> should NOT be flagged
        self.assertNotIn(
            "admin_mismatch", classes,
            f"admin_mismatch should not be flagged (values match): {classes}"
        )


# ---------------------------------------------------------------------------
# Mode B: probe-diff (no divergence -- benign control)
# ---------------------------------------------------------------------------

class TestBenignControl(unittest.TestCase):
    def test_no_divergence_when_all_match(self):
        result = _build("ws_benign")
        # paused=false expected and actual -> no exploit seeds
        self.assertEqual(result["exploit_queue_seeds"], [])

    def test_benign_controls_summary_empty_when_no_divergence(self):
        result = _build("ws_benign")
        self.assertEqual(result["benign_controls_summary"], [])

    def test_total_divergences_is_zero_when_all_match(self):
        result = _build("ws_benign")
        self.assertEqual(result["total_divergences"], 0)


# ---------------------------------------------------------------------------
# Output file / CLI modes
# ---------------------------------------------------------------------------

class TestCLI(unittest.TestCase):
    def test_json_stdout_mode(self):
        ws = FIXTURES / "ws_basic"
        import io
        captured = io.StringIO()
        original_stdout = sys.stdout
        sys.stdout = captured
        try:
            ret = TOOL.main(["--workspace", str(ws), "--json", "--no-file"])
        finally:
            sys.stdout = original_stdout
        self.assertEqual(ret, 0)
        data = json.loads(captured.getvalue())
        self.assertEqual(data["schema"], "auditooor.state_config_diff.v1")

    def test_diff_only_mode(self):
        ws = FIXTURES / "ws_divergence"
        import io
        captured = io.StringIO()
        original_stdout = sys.stdout
        sys.stdout = captured
        try:
            ret = TOOL.main(["--workspace", str(ws), "--diff-only", "--no-file"])
        finally:
            sys.stdout = original_stdout
        self.assertEqual(ret, 0)
        data = json.loads(captured.getvalue())
        self.assertIn("exploit_queue_seeds", data)
        self.assertIn("benign_controls_summary", data)

    def test_nonexistent_workspace_returns_2(self):
        ret = TOOL.main(["--workspace", "/nonexistent/workspace/path/xyz", "--no-file"])
        self.assertEqual(ret, 2)

    def test_writes_file_to_auditooor_dir(self):
        ws = FIXTURES / "ws_basic"
        with tempfile.TemporaryDirectory() as tmpdir:
            out = Path(tmpdir) / "state_config_diff.json"
            ret = TOOL.main(["--workspace", str(ws), "--out", str(out)])
            self.assertEqual(ret, 0)
            self.assertTrue(out.exists(), f"Output file not created: {out}")
            data = json.loads(out.read_text())
            self.assertEqual(data["schema"], "auditooor.state_config_diff.v1")


# ---------------------------------------------------------------------------
# Offline safety: no subprocess calls triggered
# ---------------------------------------------------------------------------

class TestOfflineSafety(unittest.TestCase):
    def test_no_subprocess_in_read_plan_mode(self):
        import subprocess as sp

        def _fail_run(*args, **kwargs):
            raise AssertionError(f"Unexpected subprocess call in offline mode: {args}")

        with patch.object(sp, "run", side_effect=_fail_run):
            result = _build("ws_basic")
        self.assertEqual(result["mode"], "read_plan")

    def test_no_subprocess_in_probe_diff_mode(self):
        import subprocess as sp

        def _fail_run(*args, **kwargs):
            raise AssertionError(f"Unexpected subprocess call in offline mode: {args}")

        with patch.object(sp, "run", side_effect=_fail_run):
            result = _build("ws_divergence")
        self.assertEqual(result["mode"], "probe_diff")


# ---------------------------------------------------------------------------
# Address extraction helpers
# ---------------------------------------------------------------------------

class TestAddressExtraction(unittest.TestCase):
    def test_is_address_valid(self):
        self.assertTrue(TOOL._is_address("0xA1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1"))

    def test_is_address_invalid_short(self):
        self.assertFalse(TOOL._is_address("0xabc"))

    def test_is_address_invalid_no_prefix(self):
        self.assertFalse(TOOL._is_address("aAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaA"))

    def test_chain_id_inferred_polygon(self):
        cid = TOOL._infer_chain_id_from_url("https://polygonscan.com/address/0x1234")
        self.assertEqual(cid, 137)

    def test_chain_id_inferred_ethereum(self):
        cid = TOOL._infer_chain_id_from_url("https://etherscan.io/address/0x1234")
        self.assertEqual(cid, 1)

    def test_chain_id_unknown_returns_none(self):
        cid = TOOL._infer_chain_id_from_url("https://unknown-explorer.example.com/address/0x1234")
        self.assertIsNone(cid)

    def test_default_rpc_polygon(self):
        rpc = TOOL._default_rpc(137)
        self.assertIn("polygon", rpc.lower())

    def test_default_rpc_unknown_chain(self):
        rpc = TOOL._default_rpc(99999)
        self.assertEqual(rpc, "${RPC_URL}")


# ---------------------------------------------------------------------------
# Divergence classification unit tests
# ---------------------------------------------------------------------------

class TestDivergenceClassification(unittest.TestCase):
    def _make_div(self, divergence_class: str, expected: str, actual: str) -> dict:
        return {
            "item_id": f"test__{divergence_class}",
            "category": "proxy",
            "label": "test label",
            "address": "0xCcCcCcCcCcCcCcCcCcCcCcCcCcCcCcCcCcCcCcCc",
            "expect_key": "test_key",
            "expected_value": expected,
            "actual_value": actual,
            "divergence_class": divergence_class,
            "pinned_cmd": "cast storage 0xCcCc... 0x3608... --rpc-url https://example.com --block 20000000",
            "probe_file": "test.json",
        }

    def test_implementation_mismatch_is_exploit_seed(self):
        div = self._make_div(
            "implementation_mismatch",
            "0x1111111111111111111111111111111111111111",
            "0x2222222222222222222222222222222222222222",
        )
        classified = TOOL._classify_divergence(div)
        self.assertEqual(classified["divergence_type"], "exploit_queue_seed")
        self.assertEqual(classified["severity_hint"], "high")
        self.assertIsNotNone(classified["exploit_queue_row"])

    def test_owner_mismatch_is_exploit_seed(self):
        div = self._make_div("owner_mismatch", "0xAAA...", "0xBBB...")
        classified = TOOL._classify_divergence(div)
        self.assertEqual(classified["divergence_type"], "exploit_queue_seed")

    def test_oracle_mismatch_is_exploit_seed(self):
        div = self._make_div("oracle_mismatch", "0xAAA...", "0xBBB...")
        classified = TOOL._classify_divergence(div)
        self.assertEqual(classified["divergence_type"], "exploit_queue_seed")

    def test_unexpected_paused_is_benign(self):
        div = self._make_div("unexpected_paused_state", "false", "true")
        classified = TOOL._classify_divergence(div)
        self.assertEqual(classified["divergence_type"], "benign_control")
        self.assertIsNone(classified["exploit_queue_row"])

    def test_unexpected_frozen_is_benign(self):
        div = self._make_div("unexpected_frozen_state", "false", "true")
        classified = TOOL._classify_divergence(div)
        self.assertEqual(classified["divergence_type"], "benign_control")

    def test_missing_sequencer_feed_is_exploit_seed(self):
        div = self._make_div("missing_sequencer_feed", "0xFeed...", "0x0000000000000000000000000000000000000000")
        classified = TOOL._classify_divergence(div)
        self.assertEqual(classified["divergence_type"], "exploit_queue_seed")

    def test_exploit_queue_row_has_required_fields(self):
        div = self._make_div("implementation_mismatch", "0x111...", "0x222...")
        classified = TOOL._classify_divergence(div)
        row = classified["exploit_queue_row"]
        required = {"schema", "source", "title", "address", "divergence_class",
                    "expected_value", "actual_value", "evidence_cmd", "severity_hint"}
        missing = required - set(row.keys())
        self.assertFalse(missing, f"Missing exploit_queue_row fields: {missing}")
        self.assertEqual(row["schema"], "auditooor.exploit_queue_seed.v1")
        self.assertEqual(row["source"], "state_config_diff")


if __name__ == "__main__":
    unittest.main()
