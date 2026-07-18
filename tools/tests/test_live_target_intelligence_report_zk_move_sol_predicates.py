#!/usr/bin/env python3
"""CAP-021 predicate coverage tests for ZK / Move / Solana invariant IDs."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


_HERE = Path(__file__).resolve().parent
_TOOL_PATH = _HERE.parent / "live-target-intelligence-report.py"
_spec = importlib.util.spec_from_file_location(
    "live_target_intelligence_report", _TOOL_PATH
)
assert _spec is not None and _spec.loader is not None
_LTIR = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_LTIR)


class Cap021ZkMoveSolPredicateCoverageTest(unittest.TestCase):
    """CAP-021 focused TP/FP fixtures for INV-ZK, INV-MOVE, INV-SOL."""

    def _semantic(self, inv_id: str, source: str) -> list[str]:
        return _LTIR._semantic_p1_matches(
            "zk-move-sol-pid",
            matched_p1=[inv_id],
            file_line="src/predicate_case.sol:1",
            snippet=source[:120],
            source_context=source,
            source_contract_context=source,
        )

    def test_inv_zk_001_true_positive(self) -> None:
        source = """
        function compute(input) {
          signal a;
          signal b;
          signal c;
          a <== b + c;
        }
        """
        self.assertEqual(self._semantic("INV-ZK-001", source), ["INV-ZK-001"])

    def test_inv_zk_001_false_positive(self) -> None:
        source = """
        function compute(input) {
          signal a;
          signal b;
          a <== b;
          b <== 1;
          a === 123;
          b === a;
        }
        """
        self.assertEqual(self._semantic("INV-ZK-001", source), [])

    def test_inv_zk_002_true_positive(self) -> None:
        source = """
        circuit main() {
          var y;
          y <-- 5;
        }
        """
        self.assertEqual(self._semantic("INV-ZK-002", source), ["INV-ZK-002"])

    def test_inv_zk_002_false_positive(self) -> None:
        source = """
        circuit main() {
          var y;
          y <-- 5;
          y === 5;
        }
        """
        self.assertEqual(self._semantic("INV-ZK-002", source), [])

    def test_inv_zk_003_true_positive(self) -> None:
        source = """
        struct Ceremony {
          tau: Vec<u8>,
        }

        function setup() {
          let tau = tau::load_srs();
          transcript.add_to_batch(tau);
        }
        """
        self.assertEqual(self._semantic("INV-ZK-003", source), ["INV-ZK-003"])

    def test_inv_zk_003_false_positive(self) -> None:
        source = """
        function setup() {
          let tau = tau::load_srs();
          let clean = shred(tau);
          assert(clean);
        }
        """
        self.assertEqual(self._semantic("INV-ZK-003", source), [])

    def test_inv_move_001_true_positive(self) -> None:
        source = """
        module test::m {
          use aptos_framework::account;

          public entry fun open(addr: address, seed: vector<u8>) {
            let _resource_signer = account::create_resource_account(@0x1, seed, addr);
          }
        }
        """
        self.assertEqual(self._semantic("INV-MOVE-001", source), ["INV-MOVE-001"])

    def test_inv_move_001_false_positive(self) -> None:
        source = """
        module test::m {
          use aptos_framework::account;
          use std::signer;

          public entry fun open(s: &signer, addr: address, seed: vector<u8>) {
            let owner = signer::address_of(s);
            assert!(signer::address_of(s) == owner, 42);
            let _resource_signer = account::create_resource_account(owner, seed, owner);
          }
        }
        """
        self.assertEqual(self._semantic("INV-MOVE-001", source), [])

    def test_inv_move_002_true_positive(self) -> None:
        source = """
        module test::m {
          struct User has key, store {
            cap: Capability<SignerCapability>,
          }
        }
        """
        self.assertEqual(self._semantic("INV-MOVE-002", source), ["INV-MOVE-002"])

    def test_inv_move_002_false_positive(self) -> None:
        source = """
        module test::m {
          struct User has key, store {
            cap_id: u64,
          }
        }
        """
        self.assertEqual(self._semantic("INV-MOVE-002", source), [])

    def test_inv_move_003_true_positive(self) -> None:
        source = """
        module test::m {
          public fun add(parent: address, user_key: vector<u8>, value: u64) {
            dof::add(parent, user_key, value);
          }
        }
        """
        self.assertEqual(self._semantic("INV-MOVE-003", source), ["INV-MOVE-003"])

    def test_inv_move_003_false_positive(self) -> None:
        source = """
        module test::m {
          public fun add(parent: address, user_key: vector<u8>, value: u64) {
            dof::add(parent, sha3_256(user_key), value);
          }
        }
        """
        self.assertEqual(self._semantic("INV-MOVE-003", source), [])

    def test_inv_sol_001_true_positive(self) -> None:
        source = """
        pub fn derive(p: Pubkey, user: Pubkey) -> (Pubkey, u8) {
          let (a, _)= Pubkey::find_program_address(&[b"vault"], &p);
          let (b, _)= Pubkey::find_program_address(&[b"vault"], &p);
          (a, 0)
        }
        """
        self.assertEqual(self._semantic("INV-SOL-001", source), ["INV-SOL-001"])

    def test_inv_sol_001_false_positive(self) -> None:
        source = """
        pub fn derive(p: Pubkey, user: Pubkey, index: u64) -> (Pubkey, u8) {
          Pubkey::find_program_address(&[b"vault", user.as_ref(), index.to_le_bytes().as_ref()], &p)
        }
        """
        self.assertEqual(self._semantic("INV-SOL-001", source), [])

    def test_inv_sol_002_true_positive(self) -> None:
        source = """
        pub fn mint(ctx: Context<MintCtx>) -> ProgramResult {
          let ix = system_instruction::transfer(...);
          invoke_signed(&ix, ctx.accounts.to_account_info(), signer_seeds)
        }
        """
        self.assertEqual(self._semantic("INV-SOL-002", source), ["INV-SOL-002"])

    def test_inv_sol_002_false_positive(self) -> None:
        source = """
        pub fn mint(ctx: Context<MintCtx>) -> ProgramResult {
          require_keys_eq!(ctx.accounts.authority.key(), &crate::ID);
          let ix = system_instruction::transfer(...);
          invoke_signed(&ix, ctx.accounts.to_account_info(), signer_seeds)
        }
        """
        self.assertEqual(self._semantic("INV-SOL-002", source), [])

    def test_inv_sol_003_true_positive(self) -> None:
        source = """
        pub fn claim(ctx: Context<ClaimCtx>) -> ProgramResult {
          let clock = Clock::get()?;
          let slot_now = clock.slot;
          if slot_now > 1_000 {
            // stale check missing
          }
        }
        """
        self.assertEqual(self._semantic("INV-SOL-003", source), ["INV-SOL-003"])

    def test_inv_sol_003_false_positive(self) -> None:
        source = """
        pub fn claim(ctx: Context<ClaimCtx>) -> ProgramResult {
          let clock = Clock::get()?;
          require!(clock.slot >= self.last_update_slot - STALENESS_THRESHOLD, ErrorCode::Stale);
          let _ = clock.slot;
        }
        """
        self.assertEqual(self._semantic("INV-SOL-003", source), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
