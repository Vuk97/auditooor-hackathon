"""Wave-14 tests: ranker attack-class required-primitive negative-evidence filter.

Audit anchor: audit/postmortems/wave14-ranker-file-level-fp-2026-05-11.md.
The filter caps confidence when zero required primitives appear in a target
function's calls_made + signature haystack, preventing the file-level
shape-hash collapse FP (e.g., ante.go scoring 0.91 fee-redirect with zero
bankKeeper.SendCoins calls).
"""
from __future__ import annotations

import importlib.util
import os
import sys
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
RANKER_PATH = REPO_ROOT / "tools" / "ranker.py"
PRIMITIVES_YAML = REPO_ROOT / "reference" / "attack_class_required_primitives.yaml"


def _load_ranker():
    name = "_ranker_w14_pf"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, str(RANKER_PATH))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


class PrimitivesYamlLoaderTests(unittest.TestCase):
    def setUp(self) -> None:
        os.environ["RANKER_PREDICTION_LOG_DISABLED"] = "1"
        self.ranker = _load_ranker()
        self.cfg = self.ranker.load_attack_class_primitives(PRIMITIVES_YAML)

    def test_yaml_file_exists(self) -> None:
        self.assertTrue(PRIMITIVES_YAML.exists(), f"missing {PRIMITIVES_YAML}")

    def test_loader_returns_enabled(self) -> None:
        self.assertTrue(self.cfg["enabled"])

    def test_default_cap_is_three_tenths(self) -> None:
        self.assertAlmostEqual(self.cfg["default_cap"], 0.30, places=4)

    def test_fee_redirect_registered(self) -> None:
        self.assertIn("fee-redirect", self.cfg["by_class"])
        regexes = self.cfg["by_class"]["fee-redirect"]["regexes"]
        self.assertGreater(len(regexes), 0)

    def test_blocked_addr_bypass_registered(self) -> None:
        self.assertIn("blocked-addr-bypass", self.cfg["by_class"])

    def test_admin_bypass_registered(self) -> None:
        self.assertIn("admin-bypass", self.cfg["by_class"])


class FilterCappingTests(unittest.TestCase):
    def setUp(self) -> None:
        os.environ["RANKER_PREDICTION_LOG_DISABLED"] = "1"
        self.ranker = _load_ranker()
        self.cfg = self.ranker.load_attack_class_primitives(PRIMITIVES_YAML)

    def test_caps_fee_redirect_with_no_primitives(self) -> None:
        rows = [
            {"attack_class": "fee-redirect", "confidence": 0.91, "score": 1.2},
        ]
        target = {
            "function_name": "AnteHandle",
            "function_signature": "func (d AnteDecorator) AnteHandle(ctx sdk.Context, tx sdk.Tx, simulate bool, next sdk.AnteHandler)",
            "calls_made": ["next", "ctx.Logger", "sdk.UnwrapSDKContext"],
            "guards_detected": [],
        }
        out = self.ranker.apply_attack_class_primitive_filter(
            rows, target, primitives_cfg=self.cfg
        )
        self.assertEqual(out[0]["confidence"], 0.30)
        self.assertTrue(out[0].get("primitive_filter_applied"))
        self.assertAlmostEqual(out[0]["primitive_filter_prior_confidence"], 0.91)

    def test_no_cap_when_primitive_present(self) -> None:
        rows = [
            {"attack_class": "fee-redirect", "confidence": 0.85, "score": 1.0},
        ]
        target = {
            "function_name": "RegisterAffiliate",
            "function_signature": "func (k msgServer) RegisterAffiliate(ctx context.Context, msg *types.MsgRegisterAffiliate)",
            "calls_made": [
                "bankKeeper.SendCoinsFromModuleToAccount",
                "k.k.SetAffiliate",
            ],
            "guards_detected": [],
        }
        out = self.ranker.apply_attack_class_primitive_filter(
            rows, target, primitives_cfg=self.cfg
        )
        self.assertEqual(out[0]["confidence"], 0.85)
        self.assertFalse(out[0].get("primitive_filter_applied", False))

    def test_admin_bypass_capped_when_no_authority_reference(self) -> None:
        rows = [
            {"attack_class": "admin-bypass", "confidence": 0.80, "score": 0.9},
        ]
        target = {
            "function_name": "NoAuthFunc",
            "function_signature": "func NoAuthFunc(x int) int",
            "calls_made": ["fmt.Println"],
            "guards_detected": [],
        }
        out = self.ranker.apply_attack_class_primitive_filter(
            rows, target, primitives_cfg=self.cfg
        )
        self.assertLessEqual(out[0]["confidence"], 0.30)
        self.assertTrue(out[0]["primitive_filter_applied"])

    def test_admin_bypass_capped_on_allowlisted_keeper_path_without_authority(self) -> None:
        rows = [
            {"attack_class": "admin-bypass", "confidence": 0.91, "score": 1.4},
        ]
        target = {
            "file_path": "external/v4-chain/protocol/x/clob/keeper/deleveraging.go",
            "function_name": "CanDeleverageSubaccount",
            "function_signature": "func (k Keeper) CanDeleverageSubaccount(ctx sdk.Context) bool",
            "calls_made": ["k.GetPerpetual", "k.GetSubaccount"],
            "guards_detected": [],
        }
        out = self.ranker.apply_attack_class_primitive_filter(
            rows, target, primitives_cfg=self.cfg
        )
        self.assertEqual(out[0]["confidence"], 0.30)
        self.assertTrue(out[0]["primitive_filter_applied"])

    def test_omission_allowlist_still_protects_affiliate_blocked_addr_shape(self) -> None:
        rows = [
            {"attack_class": "blocked-addr-bypass", "confidence": 0.85, "score": 1.0},
        ]
        target = {
            "file_path": "external/v4-chain/protocol/x/affiliates/keeper/msg_server.go",
            "function_name": "RegisterAffiliate",
            "function_signature": "func (k msgServer) RegisterAffiliate(ctx context.Context, msg *types.MsgRegisterAffiliate)",
            "calls_made": ["k.SetAffiliate"],
            "guards_detected": [],
        }
        out = self.ranker.apply_attack_class_primitive_filter(
            rows, target, primitives_cfg=self.cfg
        )
        self.assertEqual(out[0]["confidence"], 0.85)
        self.assertFalse(out[0].get("primitive_filter_applied", False))

    def test_admin_bypass_not_capped_when_authority_reference_present(self) -> None:
        rows = [
            {"attack_class": "admin-bypass", "confidence": 0.75, "score": 0.85},
        ]
        target = {
            "function_name": "UpdateAffiliateTiers",
            "function_signature": "func (k msgServer) UpdateAffiliateTiers(ctx context.Context, msg *types.MsgUpdateAffiliateTiers)",
            "calls_made": ["k.k.GetAuthority", "k.k.SetTiers"],
            "guards_detected": ["authority-check"],
        }
        out = self.ranker.apply_attack_class_primitive_filter(
            rows, target, primitives_cfg=self.cfg
        )
        self.assertEqual(out[0]["confidence"], 0.75)
        self.assertFalse(out[0].get("primitive_filter_applied", False))

    def test_prior_only_s2_rows_are_capped_below_default_mindset_threshold(self) -> None:
        rows = [
            {
                "attack_class": "access-control-missing-modifier",
                "confidence": 0.91,
                "score": 7.6,
                "scorer_hits": 1,
                "evidence": [{"scorer": "S2", "bug_class": "access-control"}],
            },
            {
                "attack_class": "admin-bypass",
                "confidence": 0.82,
                "score": 1.0,
                "scorer_hits": 2,
                "evidence": [{"scorer": "S1"}, {"scorer": "S2"}],
            },
        ]
        out = self.ranker.apply_prior_only_filter(rows)
        self.assertEqual(out[0]["confidence"], 0.35)
        self.assertTrue(out[0]["prior_only_filter_applied"])
        self.assertEqual(out[1]["confidence"], 0.82)
        self.assertFalse(out[1].get("prior_only_filter_applied", False))

    def test_context_only_s2_s5_rows_are_capped(self) -> None:
        rows = [
            {
                "attack_class": "upstream-fix-not-backported",
                "confidence": 0.91,
                "score": 0.8,
                "scorer_hits": 2,
                "evidence": [
                    {"scorer": "S2", "bug_class": "missing-hardening"},
                    {"scorer": "S5", "bug_class": "fork-divergence-blocksync-gap"},
                ],
            },
            {
                "attack_class": "goroutine-deadlock",
                "confidence": 0.57,
                "score": 0.1,
                "scorer_hits": 1,
                "evidence": [{"scorer": "S4", "rule_id": "RULE_GO_CHANNEL_NO_BUFFER_RACE"}],
            },
        ]
        out = self.ranker.apply_prior_only_filter(rows)
        self.assertEqual(out[0]["confidence"], 0.35)
        self.assertTrue(out[0]["prior_only_filter_applied"])
        self.assertEqual(out[1]["confidence"], 0.57)
        self.assertFalse(out[1].get("prior_only_filter_applied", False))

    def test_unrelated_attack_class_passes_through(self) -> None:
        # Attack class NOT in the primitives yaml must be left alone.
        rows = [
            {"attack_class": "timestamp-manipulation", "confidence": 0.55, "score": 0.6},
        ]
        target = {
            "function_name": "AnteHandle",
            "function_signature": "func (d AnteDecorator) AnteHandle(ctx sdk.Context, tx sdk.Tx)",
            "calls_made": [],
            "guards_detected": [],
        }
        out = self.ranker.apply_attack_class_primitive_filter(
            rows, target, primitives_cfg=self.cfg
        )
        self.assertEqual(out[0]["confidence"], 0.55)
        self.assertFalse(out[0].get("primitive_filter_applied", False))

    def test_blocked_addr_bypass_capped_on_ante_decorator(self) -> None:
        # The empirical anchor case: an ante-decorator function with NO
        # bankKeeper / BlockedAddr primitive should be capped on
        # blocked-addr-bypass.
        rows = [
            {"attack_class": "blocked-addr-bypass", "confidence": 0.91, "score": 1.4},
        ]
        target = {
            "function_name": "AnteHandle",
            "function_signature": "func (d AuthenticatorDecorator) AnteHandle(ctx sdk.Context, tx sdk.Tx, simulate bool, next sdk.AnteHandler)",
            "calls_made": ["next", "sdk.UnwrapSDKContext", "d.authenticatorKeeper.Get"],
            "guards_detected": [],
        }
        out = self.ranker.apply_attack_class_primitive_filter(
            rows, target, primitives_cfg=self.cfg
        )
        self.assertEqual(out[0]["confidence"], 0.30)
        self.assertTrue(out[0]["primitive_filter_applied"])

    def test_idempotent(self) -> None:
        rows = [
            {"attack_class": "fee-redirect", "confidence": 0.91, "score": 1.2},
        ]
        target = {"calls_made": ["next"], "guards_detected": []}
        first = self.ranker.apply_attack_class_primitive_filter(
            rows, target, primitives_cfg=self.cfg
        )
        first_conf = first[0]["confidence"]
        second = self.ranker.apply_attack_class_primitive_filter(
            first, target, primitives_cfg=self.cfg
        )
        self.assertEqual(second[0]["confidence"], first_conf)

    def test_disabled_config_passes_through(self) -> None:
        rows = [
            {"attack_class": "fee-redirect", "confidence": 0.91, "score": 1.2},
        ]
        target = {"calls_made": [], "guards_detected": []}
        disabled_cfg = {"enabled": False, "default_cap": 0.30, "by_class": {}}
        out = self.ranker.apply_attack_class_primitive_filter(
            rows, target, primitives_cfg=disabled_cfg
        )
        self.assertEqual(out[0]["confidence"], 0.91)
        self.assertFalse(out[0].get("primitive_filter_applied", False))


if __name__ == "__main__":
    unittest.main()
