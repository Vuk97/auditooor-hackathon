#!/usr/bin/env python3
"""CAP-021 predicate coverage tests for L2 and Substrate domain IDs."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_TOOL_PATH = _HERE.parent / "live-target-intelligence-report.py"
_SPEC = importlib.util.spec_from_file_location(
    "live_target_intelligence_report", _TOOL_PATH
)
_LTIR = importlib.util.module_from_spec(_SPEC)
assert _SPEC is not None and _SPEC.loader is not None
_SPEC.loader.exec_module(_LTIR)


class Cap021PredicateCoverageTest(unittest.TestCase):
    """CAP-021 focused TP/FP coverage for INV-L2-* and INV-SUB-* predicates."""

    def _semantic(self, inv_id: str, source: str) -> list[str]:
        return _LTIR._semantic_p1_matches(
            "cap021-domain",
            matched_p1=[inv_id],
            file_line="src/Cap021.sol:1",
            snippet="",
            source_context=source,
            source_contract_context=source,
        )

    def test_inv_l2_001_true_positive(self) -> None:
        source = """
        contract RollupIngress {
          function forceInclusion(bytes32 txHash) external {
            pendingTxs.push(txHash);
            // no max-delay guard present
          }
        }
        """
        self.assertEqual(self._semantic("INV-L2-001", source), ["INV-L2-001"])

    def test_inv_l2_001_false_positive(self) -> None:
        source = """
        contract RollupIngress {
          function enqueueL2Tx(bytes32 txHash) external {
            require(block.number <= txIndex + maxDelayBlocks, "too old");
            pendingTxs.push(txHash);
          }
        }
        """
        self.assertEqual(self._semantic("INV-L2-001", source), [])

    def test_inv_l2_002_true_positive(self) -> None:
        source = """
        contract OutputOracle {
          function proveBlock(bytes32 outputRoot) external {
            outputRoot = outputRoot;
            latestProposal = outputRoot;
          }
        }
        """
        self.assertEqual(self._semantic("INV-L2-002", source), ["INV-L2-002"])

    def test_inv_l2_002_false_positive(self) -> None:
        source = """
        contract OutputOracle {
          function submitOutput(bytes32 outputRoot, bytes calldata proof) external {
            require(verifier.verifyProof(proof), "bad proof");
            outputRoot = outputRoot;
          }
        }
        """
        self.assertEqual(self._semantic("INV-L2-002", source), [])

    def test_inv_l2_003_true_positive(self) -> None:
        source = """
        contract FaultDispute {
          function confirmOutput(address proposer, bytes32 outputRoot, uint64 outputTimestamp) external {
            confirmed[proposer] = outputRoot;
          }
        }
        """
        self.assertEqual(self._semantic("INV-L2-003", source), ["INV-L2-003"])

    def test_inv_l2_003_false_positive(self) -> None:
        source = """
        contract FaultDispute {
          function confirmOutput(OutputProposal memory outputProposal) external {
            require(block.timestamp >= outputProposal.timestamp + CHALLENGE_PERIOD, "challenge still open");
            confirmed = true;
          }
        }
        """
        self.assertEqual(self._semantic("INV-L2-003", source), [])

    def test_inv_l2_004_true_positive(self) -> None:
        source = """
        contract L2OutputOracle {
          function proveBlock() external {}
          function submitOutput() external {}
          function confirmOutput() external {}
        }
        """
        self.assertEqual(self._semantic("INV-L2-004", source), ["INV-L2-004"])

    def test_inv_l2_004_false_positive(self) -> None:
        source = """
        contract L2OutputOracle {
          function proveBlock() external {}
          function forceWithdraw(address user) external {}
          function confirmOutput() external {}
        }
        """
        self.assertEqual(self._semantic("INV-L2-004", source), [])

    def test_inv_sub_001_true_positive(self) -> None:
        source = r"""
        #[pallet::weight(10_000)]
        pub fn submit_tx(origin: OriginFor<T>, txs: Vec<u8>) -> DispatchResult {
          let mut i = 0;
          while i < txs.len() {
            i += 1;
          }
          Ok(())
        }
        """
        self.assertEqual(self._semantic("INV-SUB-001", source), ["INV-SUB-001"])

    def test_inv_sub_001_false_positive(self) -> None:
        source = r"""
        #[pallet::weight(T::DbWeight::get().reads(1))]
        pub fn submit_tx(origin: OriginFor<T>, txs: Vec<u8>) -> DispatchResult {
          let mut i = 0;
          while i < txs.len() {
            i += 1;
          }
          Ok(())
        }
        """
        self.assertEqual(self._semantic("INV-SUB-001", source), [])

    def test_inv_sub_002_true_positive(self) -> None:
        source = """
        impl<T: Config> Pallet<T> {
          pub fn fork_choice(voter: u32, candidate: u32) -> bool {
            candidate > voter
          }
        }
        """
        self.assertEqual(self._semantic("INV-SUB-002", source), ["INV-SUB-002"])

    def test_inv_sub_002_false_positive(self) -> None:
        source = """
        impl<T: Config> Pallet<T> {
          pub fn fork_choice(last_finalized_block: u32, voter: u32, candidate: u32) -> bool {
            if last_finalized_block > voter {
              return false;
            }
            candidate > voter
          }
        }
        """
        self.assertEqual(self._semantic("INV-SUB-002", source), [])

    def test_inv_sub_003_true_positive(self) -> None:
        source = """
        impl<T: Config> Pallet<T> {
          pub fn collate_block(header: HeaderFor<T>) -> DispatchResult {
            let _ = header.parent_hash;
            Ok(())
          }
        }
        """
        self.assertEqual(self._semantic("INV-SUB-003", source), ["INV-SUB-003"])

    def test_inv_sub_003_false_positive(self) -> None:
        source = """
        impl<T: Config> Pallet<T> {
          pub fn collate_block(header: HeaderFor<T>) -> DispatchResult {
            let _ = header.parent_hash;
            validate_block(header)?;
            Ok(())
          }
        }
        """
        self.assertEqual(self._semantic("INV-SUB-003", source), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)

