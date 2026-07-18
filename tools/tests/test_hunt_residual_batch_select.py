"""Lane G (SEI 2026-07-05): residual-hitting batch selector ranks plan batches by how
many gate ``queued_not_scanned`` units their function_anchors target.

Rationale: ``make hunt-scoped`` emits batches in BUILDER order (Solidity example
contracts front-loaded, in-scope crown-jewel Go scattered high), so index/path-grep
selection credits ~0 to the residual. This selector matches batch anchors to residual
units on (basename, fn) - the residual worker queue's own key - so the top-K batches are
exactly the ones the gate still wants scanned.
"""
import importlib.util
import unittest
from pathlib import Path

_spec = importlib.util.spec_from_file_location(
    "hrbs", str(Path(__file__).resolve().parents[1] / "hunt-residual-batch-select.py")
)
hrbs = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(hrbs)


class ResidualBatchSelectTest(unittest.TestCase):
    def test_residual_keys_relpath_fn_key(self):
        units = [
            "src/sei-chain/precompiles/bank/bank.go::SendNative",
            "Box.sol",  # file-only -> ignored (no ::)
            "src/sei-chain/x/evm/keeper/keeper.go::SetBalance",
        ]
        keys = hrbs._residual_keys(units, [])
        self.assertIn(("src/sei-chain/precompiles/bank/bank.go", "SendNative"), keys)
        self.assertIn(("src/sei-chain/x/evm/keeper/keeper.go", "SetBalance"), keys)
        self.assertEqual(len(keys), 2)

    def test_legacy_versions_are_distinct_keys_no_collision(self):
        # the whole point: legacy/vNNN copies must NOT collapse to one basename key
        units = [
            "src/sei-chain/precompiles/gov/gov.go::deposit",
            "src/sei-chain/precompiles/gov/legacy/v620/gov.go::deposit",
            "src/sei-chain/precompiles/gov/legacy/v640/gov.go::deposit",
        ]
        keys = hrbs._residual_keys(units, [])
        self.assertEqual(len(keys), 3)

    def test_prefer_canonical_skips_legacy(self):
        units = [
            "src/sei-chain/precompiles/gov/gov.go::deposit",
            "src/sei-chain/precompiles/gov/legacy/v620/gov.go::deposit",
        ]
        keys = hrbs._residual_keys(units, [], prefer_canonical=True)
        self.assertEqual(keys, {("src/sei-chain/precompiles/gov/gov.go", "deposit")})

    def test_anchor_and_residual_share_key_across_abs_and_rel(self):
        residual = hrbs._residual_keys(
            ["src/sei-chain/x/evm/keeper/keeper.go::SetBalance"], []
        )
        anchor = hrbs._batch_anchor_keys(
            '**function_anchor**: {"file": "/Users/w/audits/sei/src/sei-chain/x/evm/keeper/keeper.go", "fn": "SetBalance"}'
        )
        self.assertTrue(residual & anchor)

    def test_residual_keys_domain_filter(self):
        units = [
            "src/sei-chain/precompiles/bank/bank.go::SendNative",
            "src/sei-chain/sei-tendermint/p2p/router.go::AddAddrs",
        ]
        keys = hrbs._residual_keys(units, ["precompiles/"])
        self.assertEqual(keys, {("src/sei-chain/precompiles/bank/bank.go", "SendNative")})

    def test_batch_anchor_keys_both_formats(self):
        # rendered form (absolute path with /src/ -> normalized to src/ suffix)
        rendered = '**function_anchor**: {"file": "/x/src/sei-chain/x/evm/keeper/keeper.go", "fn": "SetBalance"}'
        keys = hrbs._batch_anchor_keys(rendered)
        self.assertIn(("src/sei-chain/x/evm/keeper/keeper.go", "SetBalance"), keys)
        # raw json task form, no /src/ -> basename fallback
        raw = '"function_anchor": {"file": "a/bank.go", "start_line": 1, "fn": "SendNative"}'
        keys2 = hrbs._batch_anchor_keys(raw)
        self.assertIn(("bank.go", "SendNative"), keys2)

    def test_intersection_ranks_hitting_batch(self):
        res = hrbs._residual_keys(
            ["src/sei-chain/x/evm/keeper/keeper.go::SetBalance"], []
        )
        hit_batch = '**function_anchor**: {"file": "/w/src/sei-chain/x/evm/keeper/keeper.go", "fn": "SetBalance"}'
        miss_batch = '**function_anchor**: {"file": "/w/src/sei-chain/contracts/Box.sol", "fn": "retrieve"}'
        self.assertTrue(hrbs._batch_anchor_keys(hit_batch) & res)
        self.assertFalse(hrbs._batch_anchor_keys(miss_batch) & res)


if __name__ == "__main__":
    unittest.main()
