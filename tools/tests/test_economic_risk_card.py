#!/usr/bin/env python3
"""PR 111 — Economic Risk Card offline unit tests.

No network, no forge/slither/halmos subprocess. Only invokes the tool under
test via the current Python interpreter.
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "economic-risk-card.py"


SIX_SIGNAL_SRC = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IChainlinkAggregator {
    function latestAnswer() external view returns (int256);
    function latestRoundData() external view returns (
        uint80, int256, uint256, uint256, uint80
    );
}

contract AllSignals {
    address public owner;
    address public treasury;
    uint256 public feeRate;
    uint256 public totalSupply;

    modifier onlyOwner() { require(msg.sender == owner, "!owner"); _; }

    constructor(address _owner, address _treasury) {
        owner = _owner;
        treasury = _treasury;
        feeRate = 50;
    }

    function setFeeRate(uint256 f) external onlyOwner { feeRate = f; }
    function setTreasury(address t) external onlyOwner { treasury = t; }
    function pause() external onlyOwner {}

    function liquidate(address victim) external {
        uint256 price = IChainlinkAggregator(address(0)).latestAnswer() > 0
            ? uint256(IChainlinkAggregator(address(0)).latestAnswer())
            : 0;
        // no staleness check — consumes latestAnswer directly
        price;
        victim;
    }

    function flashLoan(uint256 amount) external { amount; }

    function swap(address a, uint256 amountIn, address b) external {
        // no protection: fires the sandwich heuristic
        a; amountIn; b;
    }

    function mint(address to, uint256 amount) external {
        totalSupply += amount;
        to; // attacker-controlled amount, no supply cap in this file
    }

    function burn(address from, uint256 amount) external {
        totalSupply -= amount;
        from;
    }

    function collectFee() external {
        uint256 fee = feeRate;
        // feeRecipient handled elsewhere — identifier present via treasury
        fee;
    }
}
"""

LIQ_ONLY_SRC = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// No oracle/governance/fee/mint/swap identifiers — liquidation signal only.
contract LiqOnly {
    uint256 public collateral;

    function liquidate(address victim) external {
        // bare path — no oracle call in this file
        collateral = 0;
        victim;
    }
}
"""


def _make_ws(td: Path, files: dict[str, str]) -> Path:
    ws = td / "ws"
    (ws / "src").mkdir(parents=True, exist_ok=True)
    for rel, body in files.items():
        full = ws / "src" / rel
        full.parent.mkdir(parents=True, exist_ok=True)
        full.write_text(body)
    return ws


def _run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(TOOL), *args],
        capture_output=True,
        text=True,
    )


class TestEconomicRiskCard(unittest.TestCase):
    def test_empty_workspace_writes_minimal_card_with_skip_banner(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "empty"
            ws.mkdir()
            res = _run(str(ws))
            self.assertEqual(res.returncode, 0, res.stderr)
            card = (ws / "ECONOMIC_RISK_CARD.md").read_text()
            self.assertIn("HYPOTHESIS-GENERATING", card)
            self.assertIn("SKIP:", card)
            self.assertIn("no Solidity source found", card)
            # every section still present
            for title in [
                "Liquidation cascade",
                "Sandwich / MEV",
                "Governance concentration",
                "Token-supply pressure",
                "Fee path",
                "Oracle dependency",
            ]:
                self.assertIn(title, card)

    def test_all_six_signals_populate_every_section(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _make_ws(Path(td), {"AllSignals.sol": SIX_SIGNAL_SRC})
            res = _run(str(ws))
            self.assertEqual(res.returncode, 0, res.stderr)
            card = (ws / "ECONOMIC_RISK_CARD.md").read_text()
            # every section must have at least one "Hypothesis" block.
            # sections headers are "\n## 1." ... "\n## 6." — match on \n
            # prefix so we don't get confused by "### Hypothesis" H3s.
            for n in range(1, 7):
                idx = card.find(f"\n## {n}.")
                self.assertGreaterEqual(idx, 0, f"section {n} missing")
                # find next top-level section ("\n## ")
                end = card.find("\n## ", idx + 5)
                body = card[idx:end] if end > 0 else card[idx:]
                self.assertIn(
                    "### Hypothesis", body,
                    f"section {n} has no Hypothesis block:\n{body[:400]}",
                )
                self.assertNotIn("no candidate found", body)
            # disclaimer is at the top
            self.assertLess(card.find("HYPOTHESIS-GENERATING"),
                            card.find("\n## 1."))

    def test_only_liquidation_signal_other_sections_say_no_candidate(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _make_ws(Path(td), {"LiqOnly.sol": LIQ_ONLY_SRC})
            res = _run(str(ws))
            self.assertEqual(res.returncode, 0, res.stderr)
            card = (ws / "ECONOMIC_RISK_CARD.md").read_text()
            # liquidation has at least one hypothesis
            liq_idx = card.find("\n## 1.")
            sandwich_idx = card.find("\n## 2.")
            liq_body = card[liq_idx:sandwich_idx]
            self.assertIn("### Hypothesis", liq_body)
            # sections 2..6 should say "no candidate found" (not blank).
            for n in range(2, 7):
                idx = card.find(f"\n## {n}.")
                end = card.find("\n## ", idx + 5)
                body = card[idx:end] if end > 0 else card[idx:]
                self.assertIn(
                    "no candidate found", body,
                    f"section {n} should explicitly say 'no candidate found'",
                )

    def test_contract_filter(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _make_ws(Path(td), {
                "AllSignals.sol": SIX_SIGNAL_SRC,
                "LiqOnly.sol": LIQ_ONLY_SRC,
            })
            res = _run(str(ws), "--contract", "LiqOnly")
            self.assertEqual(res.returncode, 0, res.stderr)
            card = (ws / "ECONOMIC_RISK_CARD.md").read_text()
            # AllSignals content should be absent, LiqOnly should show up.
            self.assertIn("LiqOnly.sol", card)
            self.assertNotIn("AllSignals.sol", card)
            # sandwich section should have no candidate since LiqOnly has no swap
            idx = card.find("\n## 2.")
            end = card.find("\n## 3.")
            body = card[idx:end]
            self.assertIn("no candidate found", body)

    def test_dry_run_does_not_write_file(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _make_ws(Path(td), {"AllSignals.sol": SIX_SIGNAL_SRC})
            res = _run(str(ws), "--dry-run")
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertFalse((ws / "ECONOMIC_RISK_CARD.md").exists(),
                             "dry-run must not write output")
            self.assertIn("plan", res.stdout)
            self.assertIn("NOT writing output", res.stdout)

    def test_json_out_and_disclaimer_in_both(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _make_ws(Path(td), {"AllSignals.sol": SIX_SIGNAL_SRC})
            json_out = Path(td) / "card.json"
            md_out = Path(td) / "CARD.md"
            res = _run(str(ws), "--out", str(md_out),
                       "--json-out", str(json_out))
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertTrue(md_out.exists())
            self.assertTrue(json_out.exists())
            card = md_out.read_text()
            data = json.loads(json_out.read_text())
            # both carry the HYPOTHESIS-GENERATING disclaimer.
            self.assertIn("HYPOTHESIS-GENERATING", card)
            self.assertIn("HYPOTHESIS-GENERATING", data["disclaimer"])
            self.assertEqual(data["schema_version"], 1)
            slugs = [s["slug"] for s in data["sections"]]
            self.assertEqual(slugs, [
                "liquidation-cascade",
                "sandwich-mev",
                "governance-concentration",
                "token-supply-pressure",
                "fee-path",
                "oracle-dependency",
            ])
            # disclaimer block appears at top of the Markdown (before ## 1.)
            self.assertLess(card.find("HYPOTHESIS-GENERATING"),
                            card.find("\n## 1."))


if __name__ == "__main__":
    unittest.main(verbosity=2)
