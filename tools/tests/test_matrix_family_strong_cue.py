#!/usr/bin/env python3
"""Regression: _detect_protocol_families claims a protocol family ONLY when a
discriminating cue is present, not on generic DeFi tokens alone. An ERC-4626 CDO whose
source mentions collateral/swap/lock/mint (all incidental) must NOT be tagged
bridge_lock_mint / cdp_liquity / amm_constant_product (which would fabricate a
family-invariant completeness denominator). A real Liquity CDP / AMM / bridge still tags."""
import importlib.util
import tempfile
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_MOD = _HERE.parent / "completeness-matrix-build.py"
_spec = importlib.util.spec_from_file_location("cmb_strong_cue", _MOD)
_m = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_m)


class TestFamilyStrongCue(unittest.TestCase):
    def _ws(self, body: str) -> Path:
        ws = Path(tempfile.mkdtemp())
        p = ws / "src" / "X.sol"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body)
        return ws

    def test_generic_tokens_do_not_claim_family(self):
        # ERC-4626 CDO surface: collateral/debt (strategy adapter), swap (swap adapter),
        # lock/mint (cooldown + ERC20). Generic only -> NO family claimed.
        ws = self._ws(
            "contract StrataCDO { function deposit() external { /* collateral debt */ }\n"
            "  function exit() external { /* swap reserve */ }\n"
            "  function cooldown() external { /* lock */ } function mint() external {} }"
        )
        self.assertEqual(_m._detect_protocol_families(ws), [])

    def test_real_liquity_cdp_still_tagged(self):
        ws = self._ws("contract TroveManager { /* trove icr mcr collateral debt liquidate */ "
                      "uint icr; uint mcr; }")
        self.assertIn("cdp_liquity", _m._detect_protocol_families(ws))

    def test_real_amm_still_tagged(self):
        ws = self._ws("contract Pair { function getAmountOut() external {} "
                      "function addLiquidity() external {} /* constant product reserve swap */ }")
        self.assertIn("amm_constant_product", _m._detect_protocol_families(ws))

    def test_real_bridge_still_tagged(self):
        ws = self._ws("contract Bridge { /* cross-chain relayer lock mint attestation */ "
                      "function relay() external {} }")
        self.assertIn("bridge_lock_mint", _m._detect_protocol_families(ws))


    def test_vendored_dep_does_not_claim_family(self):
        # in-scope manifest lists only a CDO contract; a vendored OZ crosschain lib in the
        # tree must NOT claim bridge_lock_mint (family derived from in-scope source only).
        ws = Path(tempfile.mkdtemp())
        (ws / "src").mkdir(parents=True, exist_ok=True)
        (ws / "src" / "Cdo.sol").write_text("contract Cdo { function deposit() external {} }")
        vend = ws / "src" / "lib" / "openzeppelin" / "crosschain"
        vend.mkdir(parents=True, exist_ok=True)
        (vend / "CrossChainEnabled.sol").write_text(
            "contract CrossChainEnabled { /* cross-chain relayer bridge attestation lock mint */ }")
        aud = ws / ".auditooor"
        aud.mkdir(parents=True, exist_ok=True)
        (aud / "inscope_units.jsonl").write_text('{"file": "src/Cdo.sol", "function": "deposit"}\n')
        self.assertEqual(_m._detect_protocol_families(ws), [])


if __name__ == "__main__":
    unittest.main()
