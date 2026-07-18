#!/usr/bin/env python3
"""Tests for tools/economic-invariant-detectors.py.

Validation strategy:
  * GENERICITY is asserted two ways: (1) a no-hardcoding grep over the tool body
    confirms zero morpho-midnight paths / function names / finding ids / contract
    names live in the tool; (2) a synthetic generic fixture workspace (NOT
    morpho) exercises every detector so the tool is proven to work on ANY source.
  * The morpho-midnight ANCHOR is validated only if that workspace is present on
    the host; otherwise the anchor test is skipped (the tool body stays clean).

All morpho specifics live HERE, never in the tool body.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
TOOL = REPO / "tools" / "economic-invariant-detectors.py"
MORPHO_WS = Path("/Users/wolf/audits/morpho-midnight")


def _run(workspace: str, extra: list[str] | None = None) -> dict:
    cmd = [sys.executable, str(TOOL), "--workspace", workspace, "--json"]
    if extra:
        cmd += extra
    out = subprocess.run(cmd, capture_output=True, text=True)
    assert out.returncode == 0, f"rc={out.returncode} stderr={out.stderr}"
    return json.loads(out.stdout)


class TestNoHardcoding(unittest.TestCase):
    """The tool body must contain NO morpho-midnight specifics (genericity)."""

    def test_no_workspace_hardcode(self):
        body = TOOL.read_text(encoding="utf-8")
        # Hardcodes that would tie the tool to the morpho-midnight workspace.
        # Note: generic Solidity idiom substrings inside REGEX pattern tables
        # (e.g. a "supply[_A-Z]?[Cc]ollateral" entry-name pattern) are NOT a
        # hardcode - they apply to any lending protocol. The mandate forbids
        # workspace PATHS, target contract FILENAMES, the audit PIN, and our
        # internal finding IDs.
        forbidden = [
            "morpho-midnight",
            "/Users/wolf/audits",
            "Midnight.sol",
            "7538c438",
            "EQ-001", "EQ-002", "EQ-003",
            "liquidatorGate",   # morpho-specific symbol
        ]
        for tok in forbidden:
            self.assertNotIn(
                tok, body, f"tool body must not hardcode '{tok}' (genericity mandate)"
            )

    def test_has_schema_and_env_hooks(self):
        body = TOOL.read_text(encoding="utf-8")
        self.assertIn("auditooor.economic_invariant_detectors.v1", body)
        # env-extensible pattern tables
        for hook in (
            "AUDITOOOR_ECON_DEBT_SINK_PATTERNS",
            "AUDITOOOR_ECON_ORACLE_CALL_PATTERNS",
            "AUDITOOOR_ECON_LIQUIDATE_PATTERNS",
        ):
            self.assertIn(hook, body, f"missing env hook {hook}")


class TestGenericFixture(unittest.TestCase):
    """A synthetic NON-morpho lending contract exercising every detector."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="econ_fixture_")
        src = Path(cls.tmp) / "src" / "src"
        src.mkdir(parents=True)
        # A made-up lending protocol - no morpho names anywhere.
        (src / "GenericLend.sol").write_text(
            """
pragma solidity ^0.8.0;
interface IPriceFeed { function price() external view returns (uint256); }

contract GenericLend {
    struct Loan { uint256 debt; uint256 collateral; }
    mapping(address => Loan) public loans;
    uint256 public totalLiquidity;   // shared withdrawable pool
    uint256 public lossFactor;

    // DET-1: borrow writes debt with NO min-floor guard.
    function openLoan(address who, uint256 amount) external {
        loans[who].debt += amount;
    }

    // DET-4a: deposit path coupled to a live oracle.
    function depositCollateral(address who, uint256 amt, address feed) external {
        uint256 p = IPriceFeed(feed).price();
        loans[who].collateral += amt * p;
    }

    // DET-2 + DET-3 + DET-4b: liquidation loops oracles, socializes loss,
    // allows partial close, no full-close gate, no floor.
    function liquidatePosition(address who, address[] calldata feeds) external {
        uint256 maxDebt;
        for (uint256 i = 0; i < feeds.length; i++) {
            uint256 px = IPriceFeed(feeds[i]).price();
            maxDebt += px;
        }
        uint256 badDebt = loans[who].debt - maxDebt;
        lossFactor = lossFactor + badDebt;       // socialize
        loans[who].debt -= maxDebt / 2;          // partial close -> residual dust
        loans[who].collateral -= 1;
    }

    // DET-5: withdraw gated on shared pool.
    function withdraw(address who, uint256 amount) external {
        require(amount <= totalLiquidity, "no liquidity");
        totalLiquidity -= amount;
    }

    // A SUPPRESSED case: borrow WITH a min-debt floor -> DET-1 must NOT fire.
    function openLoanSafe(address who, uint256 amount) external {
        require(amount >= MIN_DEBT, "dust");
        loans[who].debt += amount;
    }
    uint256 constant MIN_DEBT = 1e18;
}
""",
            encoding="utf-8",
        )
        cls.res = _run(cls.tmp)

    def _dets(self):
        return {h["detector"] for h in self.res["hits"]}

    def test_det1_dust_floor_fires(self):
        self.assertTrue(
            any("DET-1" in d for d in self._dets()), "DET-1 dust-floor must fire"
        )

    def test_det2_residual_fires(self):
        self.assertTrue(any("DET-2" in d for d in self._dets()))

    def test_det3_socialization_fires(self):
        self.assertTrue(any("DET-3" in d for d in self._dets()))

    def test_det4_oracle_liveness_fires(self):
        self.assertTrue(
            any("DET-4" in d for d in self._dets()),
            "DET-4 oracle-liveness (supply-coupled or in-loop) must fire",
        )

    def test_det5_withdraw_liveness_fires(self):
        self.assertTrue(any("DET-5" in d for d in self._dets()))

    def test_floor_suppression(self):
        # openLoanSafe carries a MIN_DEBT floor -> must NOT appear as a DET-1 hit.
        bad = [
            h for h in self.res["hits"]
            if h["function"] == "openLoanSafe" and "DET-1" in h["detector"]
        ]
        self.assertEqual(bad, [], "min-floor guard must suppress DET-1")

    def test_env_hook_extends_table(self):
        # A bespoke debt idiom that the builtin table misses, added via env.
        tmp2 = tempfile.mkdtemp(prefix="econ_env_")
        s = Path(tmp2) / "src"
        s.mkdir(parents=True)
        (s / "X.sol").write_text(
            "contract X { function f() external { weirdLedger += 1; } }\n",
            encoding="utf-8",
        )
        env = dict(os.environ)
        env["AUDITOOOR_ECON_DEBT_SINK_PATTERNS"] = r"\bweirdLedger\b"
        out = subprocess.run(
            [sys.executable, str(TOOL), "--workspace", tmp2, "--json"],
            capture_output=True, text=True, env=env,
        )
        self.assertEqual(out.returncode, 0)
        d = json.loads(out.stdout)
        self.assertTrue(
            any("DET-1" in h["detector"] for h in d["hits"]),
            "env-extended debt pattern must drive a DET-1 hit",
        )


class TestGracefulDegrade(unittest.TestCase):
    def test_empty_workspace(self):
        tmp = tempfile.mkdtemp(prefix="econ_empty_")
        res = _run(tmp)
        self.assertEqual(res["hit_count"], 0)
        self.assertEqual(res["verdict"], "no-economic-invariant-smell")

    def test_missing_workspace_errors(self):
        out = subprocess.run(
            [sys.executable, str(TOOL), "--workspace", "/nope/does/not/exist", "--json"],
            capture_output=True, text=True,
        )
        self.assertEqual(out.returncode, 2)


@unittest.skipUnless(
    (MORPHO_WS / "src" / "src" / "Midnight.sol").is_file(),
    "morpho-midnight anchor workspace not present on host",
)
class TestMorphoAnchor(unittest.TestCase):
    """The TRST-M-3 / Cantina-3.1.1 / 3.1.2 anchors we scored ZERO on."""

    @classmethod
    def setUpClass(cls):
        cls.res = _run(str(MORPHO_WS))

    def _hits_for(self, fn):
        return {h["detector"] for h in self.res["hits"] if h["function"] == fn}

    def test_dust_anchor_on_liquidate(self):
        # TRST-M-3 + Cantina 3.1.1: dust-debt unprofitable to liquidate.
        dets = self._hits_for("liquidate")
        self.assertTrue(any("DET-1" in d for d in dets), "DET-1 must flag liquidate")
        self.assertTrue(any("DET-2" in d for d in dets), "DET-2 residual must flag liquidate")

    def test_dust_anchor_on_supply_collateral(self):
        dets = self._hits_for("supplyCollateral")
        self.assertTrue(any("DET-1" in d for d in dets), "DET-1 must flag supplyCollateral")

    def test_oracle_liveness_anchor(self):
        # Cantina 3.1.2 family: looped oracle read bricks liquidation.
        dets = self._hits_for("liquidate")
        self.assertTrue(
            any("DET-4" in d for d in dets),
            "DET-4 oracle-liveness must flag the looped price() read in liquidate",
        )

    def test_nonzero_total(self):
        self.assertGreater(self.res["hit_count"], 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
