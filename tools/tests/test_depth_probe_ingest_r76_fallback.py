#!/usr/bin/env python3
"""Guard test: depth-probe-ingest R76 token-overlap fallback + asym key passthrough.

Regression (optimism, every workspace): the strict contiguous-substring R76 match
dropped LEGITIMATE asymmetry/guard verdicts whenever the agent's code_excerpt drifted
cosmetically from source (whitespace, modifier order, multi-line signature quoted on
one line). Those drops left candidate gaps undisposed -> a FALSE depth-pending that had
to be hand-patched. The fallback must accept a cosmetically-drifted excerpt that is
genuinely co-located at the cited line, while STILL rejecting a fabricated excerpt
(anti-hallucination). Asymmetry verdicts keyed by candidate_gap_id (no guard_id) must
also survive ingest with their candidate_gap_id + file_lines preserved.
"""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parent.parent / "depth-probe-ingest.py"
_spec = importlib.util.spec_from_file_location("dpi_r76", _TOOL)
dpi = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(dpi)


_SOL = """\
// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

contract StandardBridge {
    function bridgeERC20(
        address _localToken,
        address _remoteToken,
        uint256 _amount,
        uint32 _minGasLimit,
        bytes calldata _extraData
    )
        public
        virtual
        onlyEOA
    {
        _initiateBridgeERC20(_localToken, _remoteToken, msg.sender, msg.sender, _amount);
    }
}
"""


class R76FallbackTest(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        (self.root / "src").mkdir(parents=True, exist_ok=True)
        self.rel = "src/StandardBridge.sol"
        (self.root / self.rel).write_text(_SOL, encoding="utf-8")

    def _grep(self, excerpt, line):
        return dpi._r76_grep(excerpt, f"{self.rel}:{line}", self.root, {})

    def test_contiguous_verbatim_passes(self):
        # a verbatim line from source -> strict contiguous path
        self.assertTrue(self._grep("_initiateBridgeERC20(_localToken, _remoteToken", 16))

    def test_cosmetic_modifier_variant_passes_via_fallback(self):
        # the dominant real case: agent quotes the signature collapsed, dropping the
        # `public virtual` lines. NOT a contiguous substring, but every distinctive
        # token is co-located at the cited line -> fallback must accept.
        excerpt = "function bridgeERC20(address _localToken, address _remoteToken, uint256 _amount, uint32 _minGasLimit, bytes calldata _extraData) onlyEOA {"
        self.assertTrue(self._grep(excerpt, 5))

    def test_fabricated_excerpt_fails(self):
        # distinctive tokens that do NOT appear at the cited site -> still rejected.
        excerpt = "function withdrawTreasury(address attackerVault, uint256 stolenFunds) onlyOwner { selfdestruct(payable(attackerVault)); }"
        self.assertFalse(self._grep(excerpt, 5))

    def test_few_distinctive_tokens_no_fallback(self):
        # <4 distinctive tokens -> no overlap match (can't trust a 1-2 token anchor)
        excerpt = "onlyEOA returns bool"
        self.assertFalse(self._grep(excerpt, 5))

    def test_wrong_file_line_window_fails(self):
        # genuine tokens but cited far from where they live: window misses them.
        # (file has ~22 lines; cite line 200 -> window [170,230] is empty -> fail)
        excerpt = "function bridgeERC20(address _localToken, address _remoteToken, uint256 _amount, uint32 _minGasLimit, bytes calldata _extraData) onlyEOA {"
        self.assertFalse(self._grep(excerpt, 200))


class AsymKeyPassthroughTest(unittest.TestCase):
    def test_candidate_gap_id_record_ingests_and_preserves_identity(self):
        ws = Path(tempfile.mkdtemp())
        (ws / ".auditooor").mkdir(parents=True, exist_ok=True)
        (ws / "src").mkdir(parents=True, exist_ok=True)
        (ws / "src" / "A.sol").write_text(_SOL, encoding="utf-8")
        # an asymmetry verdict keyed by candidate_gap_id (NO guard_id), carrying the
        # file_lines pair - exactly the asym probe shape.
        probe = {
            "candidate_gap_id": "ASYM-deadbeef0001",
            "file_lines": ["src/A.sol:5", "src/A.sol:16"],
            "file_line": "src/A.sol:5",
            "gap_found": False,
            "why_no_gap_or_exploit": "bridgeERC20 onlyEOA; pairing validated downstream in _initiateBridgeERC20. By-design sibling. No gap.",
            "code_excerpt": "function bridgeERC20(address _localToken, address _remoteToken, uint256 _amount, uint32 _minGasLimit, bytes calldata _extraData) onlyEOA {",
            "probe_source": "residual-asym",
        }
        probes_path = ws / ".auditooor" / "probe.jsonl"
        probes_path.write_text(json.dumps(probe) + "\n", encoding="utf-8")
        out = ws / ".auditooor" / "asymmetry_probes.jsonl"
        res = dpi.ingest(ws, probes_path, ws, None, True, output_path=out)
        rows = [json.loads(l) for l in out.read_text().splitlines() if l.strip()]
        match = [r for r in rows if r.get("candidate_gap_id") == "ASYM-deadbeef0001"]
        self.assertEqual(len(match), 1, "asym verdict keyed by candidate_gap_id was dropped")
        self.assertEqual(match[0].get("file_lines"), ["src/A.sol:5", "src/A.sol:16"],
                         "file_lines pair not preserved -> cert cannot match the sibling row")


if __name__ == "__main__":
    unittest.main()
