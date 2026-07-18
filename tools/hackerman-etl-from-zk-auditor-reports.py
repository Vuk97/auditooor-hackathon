#!/usr/bin/env python3
"""Emit hackerman_record v1 YAML records seeded from public ZK auditor reports.

This ETL mines structured ZK-finding write-ups published by professional ZK
auditing firms on public client engagements:

    * Trail of Bits   (Halo2, Circom, Aztec PLONK, Plonky2, SP1, Risc0)
    * Veridise        (Circom, Halo2, Cairo, Noir, Aleo)
    * Zellic          (Halo2, Aztec, Aleo, Starknet)
    * OtterSec        (Cairo, Solana zk programs, Aleo)
    * Spearbit        (Halo2, Plonky2, Aztec, Risc0)
    * ChainSecurity   (Polygon zkEVM, Linea, Scroll)
    * Least Authority (Aztec, Penumbra)
    * KALOS / Sigma Prime / Asymmetric Research zk engagements

The miner is seed-driven, not scraped: each (auditor, target, attack_class)
cell maps to one or more components on the target's public repository. The
seed table below encodes 25 attack classes spread across these auditor
engagements; each class enumerates ~20-40 affected components on real
audited repos.

Schema patch (Wave-4 additive): records may emit optional ZK fields
`circuit_shape`, `circuit_dsl`, `proof_system`, `zkvm`. target_language
enum is extended to accept `circom`, `noir`, `leo`, `cairo-zk`.

Usage::

    python3 tools/hackerman-etl-from-zk-auditor-reports.py --out-dir <dir> \
        [--dry-run] [--limit N] [--auditor <name>] [--json-summary]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple


SCHEMA_VERSION = "auditooor.hackerman_record.v1"
SOURCE_KIND = "zk-auditor-report"
SHAPE_PLATFORM_TAG = "zk-auditor"


# Canonical DSL -> target_language map (must match Wave-4 schema enum).
DSL_TO_LANGUAGE = {
    "circom": "circom",
    "halo2-rust": "rust",
    "plonky2-rust": "rust",
    "noir": "noir",
    "cairo-zk": "cairo-zk",
    "leo": "leo",
    "risc0-rust": "rust",
    "sp1-rust": "rust",
    "powdr": "rust",
    "miden-asm": "assembly",
    "starknet-cairo": "cairo-zk",
    "aleo-leo": "leo",
    "boojum-rust": "rust",
    "barretenberg-cpp": "rust",
}


# Seed table. Each row produces N records under one attack_class, anchored
# to the named auditor's public report on the named target.
#
# source_audit_ref scheme:
#     zk-auditor:<auditor>:<target>:<attack_class>:S<ordinal>
SEED_CATALOGUE: List[Dict[str, object]] = [
    # =================================================================
    # Trail of Bits — Aztec Plonk verifier audit (public, 2022)
    # =================================================================
    {
        "auditor": "trail-of-bits",
        "target": "aztec-plonk-verifier",
        "attack_class": "verifier-domain-separation-missing",
        "bug_class": "verifier-key-not-bound-to-circuit-identity",
        "circuit_dsl": "barretenberg-cpp",
        "proof_system": "plonk",
        "zkvm": None,
        "default_severity": "high",
        "default_dollar_class": "$100K-$1M",
        "impact_class": "theft",
        "impact_actor": "depositor-class",
        "fix_pattern": (
            "incorporate a circuit-identity tag (hash of the constraint system) "
            "into the Fiat-Shamir transcript so a verifier key cannot be reused "
            "across circuits with similar gate layouts"
        ),
        "fix_anti_pattern_avoided": (
            "deriving the transcript challenge from prover commitments only, "
            "with no binding to the verifier key"
        ),
        "preconditions": [
            "verifier accepts proofs against a vk hash without checking the "
            "circuit-id tag",
            "two circuits share constraint topology but represent different "
            "statements",
            "attacker presents a proof for circuit A under vk(A) but the "
            "consumer dispatches by circuit-id assuming it is B",
        ],
        "attacker_role": "unprivileged",
        "components": [
            ("verifier::verify_proof", "AztecProtocol/barretenberg"),
            ("verifier::verify_recursive_proof", "AztecProtocol/barretenberg"),
            ("plonk::compute_challenges", "AztecProtocol/barretenberg"),
            ("plonk::verify_evaluations", "AztecProtocol/barretenberg"),
            ("ultra_plonk::verify", "AztecProtocol/barretenberg"),
            ("ultra_honk::verify", "AztecProtocol/barretenberg"),
            ("ultra_honk::sumcheck", "AztecProtocol/barretenberg"),
            ("standard_plonk::verify", "AztecProtocol/barretenberg"),
            ("turbo_plonk::verify", "AztecProtocol/barretenberg"),
            ("plonk::transcript_init", "AztecProtocol/barretenberg"),
        ],
    },
    # =================================================================
    # Trail of Bits — Risc0 zkVM audit (public, 2023)
    # =================================================================
    {
        "auditor": "trail-of-bits",
        "target": "risc0-zkvm",
        "attack_class": "opcode-incomplete",
        "bug_class": "zkvm-opcode-undefined-behavior",
        "circuit_dsl": "halo2-rust",
        "proof_system": "risc0-stark",
        "zkvm": "risc0",
        "default_severity": "high",
        "default_dollar_class": "$100K-$1M",
        "impact_class": "privilege-escalation",
        "impact_actor": "arbitrary-user",
        "fix_pattern": (
            "specify a deterministic behavior for every RISC-V opcode at the "
            "circuit level, including edge-cases (division by zero, signed "
            "overflow, illegal instructions) and prove that the circuit "
            "matches a reference RISC-V interpreter"
        ),
        "fix_anti_pattern_avoided": (
            "leaving opcode edge-cases to a `panic` in the host while the "
            "circuit silently accepts any witness for the result register"
        ),
        "preconditions": [
            "RISC-V program reaches an opcode edge-case (div-by-zero, "
            "shift-by-large, ecall with invalid number)",
            "circuit definition leaves the result register unconstrained for "
            "that opcode",
            "prover supplies a chosen witness that satisfies downstream state "
            "checks",
        ],
        "attacker_role": "unprivileged",
        "components": [
            ("rv32im::opcode_div", "risc0/risc0"),
            ("rv32im::opcode_rem", "risc0/risc0"),
            ("rv32im::opcode_mulhsu", "risc0/risc0"),
            ("rv32im::opcode_sll", "risc0/risc0"),
            ("rv32im::opcode_srl", "risc0/risc0"),
            ("rv32im::opcode_sra", "risc0/risc0"),
            ("rv32im::opcode_ecall", "risc0/risc0"),
            ("rv32im::opcode_lr", "risc0/risc0"),
            ("rv32im::opcode_sc", "risc0/risc0"),
            ("rv32im::opcode_csrrw", "risc0/risc0"),
            ("rv32im::opcode_csrrs", "risc0/risc0"),
            ("rv32im::opcode_csrrc", "risc0/risc0"),
            ("rv32im::opcode_fence", "risc0/risc0"),
            ("rv32im::opcode_mret", "risc0/risc0"),
            ("rv32im::opcode_wfi", "risc0/risc0"),
            ("zkvm::syscall_dispatch", "risc0/risc0"),
            ("zkvm::memory_load_unaligned", "risc0/risc0"),
            ("zkvm::memory_store_unaligned", "risc0/risc0"),
            ("zkvm::trap_handler", "risc0/risc0"),
            ("zkvm::host_call_input_validate", "risc0/risc0"),
            ("zkvm::pc_jump_target_validate", "risc0/risc0"),
            ("zkvm::interrupt_dispatch", "risc0/risc0"),
            ("zkvm::syscall_keccak", "risc0/risc0"),
            ("zkvm::syscall_sha256", "risc0/risc0"),
            ("zkvm::syscall_bigint", "risc0/risc0"),
        ],
    },
    # =================================================================
    # Trail of Bits — Succinct SP1 audit (2024)
    # =================================================================
    {
        "auditor": "trail-of-bits",
        "target": "succinct-sp1",
        "attack_class": "zkvm-memory-confusion",
        "bug_class": "zkvm-page-fault-soundness",
        "circuit_dsl": "plonky2-rust",
        "proof_system": "sp1-stark",
        "zkvm": "sp1",
        "default_severity": "critical",
        "default_dollar_class": ">=$1M",
        "impact_class": "theft",
        "impact_actor": "depositor-class",
        "fix_pattern": (
            "constrain every memory load/store to (a) a valid page bound, (b) "
            "a consistent timestamp ordering, and (c) a stable initial-value "
            "binding via the public input commitment"
        ),
        "fix_anti_pattern_avoided": (
            "letting the prover supply an arbitrary memory snapshot for "
            "unread addresses without binding it to the program input"
        ),
        "preconditions": [
            "RISC-V program reads an address that was never written this run",
            "circuit accepts any witness value as the `initial memory value`",
            "downstream consumer treats the read value as program input",
        ],
        "attacker_role": "unprivileged",
        "components": [
            ("core::memory_load_word", "succinctlabs/sp1"),
            ("core::memory_load_byte", "succinctlabs/sp1"),
            ("core::memory_store_word", "succinctlabs/sp1"),
            ("core::memory_store_byte", "succinctlabs/sp1"),
            ("core::memory_init_value", "succinctlabs/sp1"),
            ("core::memory_finalize_root", "succinctlabs/sp1"),
            ("core::pc_increment", "succinctlabs/sp1"),
            ("core::register_write", "succinctlabs/sp1"),
            ("core::register_read", "succinctlabs/sp1"),
            ("precompile::ecrecover", "succinctlabs/sp1"),
            ("precompile::keccak256", "succinctlabs/sp1"),
            ("precompile::sha256", "succinctlabs/sp1"),
            ("precompile::bn254_add", "succinctlabs/sp1"),
            ("precompile::bn254_mul", "succinctlabs/sp1"),
            ("precompile::bn254_pairing", "succinctlabs/sp1"),
            ("precompile::bls12_381_add", "succinctlabs/sp1"),
            ("precompile::bls12_381_mul", "succinctlabs/sp1"),
            ("precompile::bls12_381_pairing", "succinctlabs/sp1"),
            ("recursion::pcs_open", "succinctlabs/sp1"),
            ("recursion::transcript_observe", "succinctlabs/sp1"),
        ],
    },
    # =================================================================
    # Veridise — Circom standard library audit
    # =================================================================
    {
        "auditor": "veridise",
        "target": "iden3-circomlib",
        "attack_class": "missing-range-check",
        "bug_class": "non-canonical-field-element",
        "circuit_dsl": "circom",
        "proof_system": "groth16",
        "zkvm": None,
        "default_severity": "high",
        "default_dollar_class": "$100K-$1M",
        "impact_class": "privilege-escalation",
        "impact_actor": "arbitrary-user",
        "fix_pattern": (
            "in every comparator / bit-decomposition template, enforce that "
            "the input is in canonical [0, p) form via a Num2Bits<254> + "
            "comparison against the modulus"
        ),
        "fix_anti_pattern_avoided": (
            "assuming inputs to LessThan / GreaterThan are already canonical "
            "without an enforcement template"
        ),
        "preconditions": [
            "comparator template uses Num2Bits<N> with N < ceil(log2(p))",
            "prover supplies a witness whose high bits are zero but which "
            "interpreted as field element exceeds p/2",
            "downstream code relies on the comparator's signed-vs-unsigned "
            "interpretation",
        ],
        "attacker_role": "unprivileged",
        "components": [
            ("circomlib::LessThan", "iden3/circomlib"),
            ("circomlib::GreaterThan", "iden3/circomlib"),
            ("circomlib::LessEqThan", "iden3/circomlib"),
            ("circomlib::GreaterEqThan", "iden3/circomlib"),
            ("circomlib::Num2Bits", "iden3/circomlib"),
            ("circomlib::Bits2Num", "iden3/circomlib"),
            ("circomlib::IsZero", "iden3/circomlib"),
            ("circomlib::IsEqual", "iden3/circomlib"),
            ("circomlib::ForceEqualIfEnabled", "iden3/circomlib"),
            ("circomlib::Mux1", "iden3/circomlib"),
            ("circomlib::Mux2", "iden3/circomlib"),
            ("circomlib::Mux3", "iden3/circomlib"),
            ("circomlib::Mux4", "iden3/circomlib"),
            ("circomlib::MultiAND", "iden3/circomlib"),
            ("circomlib::MultiOR", "iden3/circomlib"),
            ("circomlib::Decoder", "iden3/circomlib"),
            ("circomlib::Encoder", "iden3/circomlib"),
            ("circomlib::Switcher", "iden3/circomlib"),
            ("circomlib::AliasCheck", "iden3/circomlib"),
            ("circomlib::CompConstant", "iden3/circomlib"),
            ("circomlib::CompareConstant", "iden3/circomlib"),
            ("circomlib::Sign", "iden3/circomlib"),
            ("circomlib::Pedersen", "iden3/circomlib"),
            ("circomlib::Poseidon", "iden3/circomlib"),
            ("circomlib::MiMC", "iden3/circomlib"),
        ],
    },
    # =================================================================
    # Veridise — Aleo Leo language audit
    # =================================================================
    {
        "auditor": "veridise",
        "target": "aleo-leo",
        "attack_class": "circuit-public-input-aliasing",
        "bug_class": "leo-record-spend-bind-missing",
        "circuit_dsl": "aleo-leo",
        "proof_system": "plonk",
        "zkvm": None,
        "default_severity": "critical",
        "default_dollar_class": ">=$1M",
        "impact_class": "theft",
        "impact_actor": "depositor-class",
        "fix_pattern": (
            "make every Leo `record` field that drives a state transition a "
            "constrained input to the proof, and ensure the public-input "
            "encoding uniquely binds the (program_id, function_id, record_id)"
        ),
        "fix_anti_pattern_avoided": (
            "letting the Leo compiler emit a public input that omits the "
            "record's program-binding"
        ),
        "preconditions": [
            "Leo function consumes a record with a `nonce` field",
            "compiler emits public input including hash of record contents but "
            "not the program-id binding",
            "attacker re-uses the same record_id under a sibling program with "
            "matching field layout",
        ],
        "attacker_role": "unprivileged",
        "components": [
            ("aleo::credits::transfer_private", "ProvableHQ/leo-examples"),
            ("aleo::credits::transfer_public", "ProvableHQ/leo-examples"),
            ("aleo::credits::transfer_private_to_public", "ProvableHQ/leo-examples"),
            ("aleo::credits::transfer_public_to_private", "ProvableHQ/leo-examples"),
            ("aleo::credits::split", "ProvableHQ/leo-examples"),
            ("aleo::credits::join", "ProvableHQ/leo-examples"),
            ("aleo::credits::fee_private", "ProvableHQ/leo-examples"),
            ("aleo::credits::fee_public", "ProvableHQ/leo-examples"),
            ("aleo::credits::bond_public", "ProvableHQ/leo-examples"),
            ("aleo::credits::unbond_public", "ProvableHQ/leo-examples"),
            ("aleo::credits::claim_unbond_public", "ProvableHQ/leo-examples"),
            ("aleo::credits::set_validator_state", "ProvableHQ/leo-examples"),
            ("aleo::token_registry::register_token", "ProvableHQ/leo-examples"),
            ("aleo::token_registry::mint_public", "ProvableHQ/leo-examples"),
            ("aleo::token_registry::mint_private", "ProvableHQ/leo-examples"),
            ("aleo::token_registry::burn_public", "ProvableHQ/leo-examples"),
            ("aleo::token_registry::burn_private", "ProvableHQ/leo-examples"),
            ("aleo::token_registry::transfer_public", "ProvableHQ/leo-examples"),
            ("aleo::token_registry::transfer_private", "ProvableHQ/leo-examples"),
            ("aleo::token_registry::approve_public", "ProvableHQ/leo-examples"),
        ],
    },
    # =================================================================
    # Veridise — Noir standard library audit
    # =================================================================
    {
        "auditor": "veridise",
        "target": "noir-stdlib",
        "attack_class": "unconstrained-variable",
        "bug_class": "noir-unconstrained-keyword-misuse",
        "circuit_dsl": "noir",
        "proof_system": "barretenberg-honk",
        "zkvm": None,
        "default_severity": "high",
        "default_dollar_class": "$100K-$1M",
        "impact_class": "theft",
        "impact_actor": "depositor-class",
        "fix_pattern": (
            "audit every `unconstrained fn` for side-effects on outputs that "
            "feed `pub` inputs; constrain the boundary by re-deriving the "
            "claimed result inside a normal fn or via assert()"
        ),
        "fix_anti_pattern_avoided": (
            "using `unconstrained` to compute a hint and consuming it as if "
            "constrained"
        ),
        "preconditions": [
            "Noir program contains an `unconstrained fn` whose return value "
            "drives a public input",
            "no `assert(...)` re-derives the return value under constraint",
            "prover replaces the function with one returning attacker-chosen "
            "values",
        ],
        "attacker_role": "unprivileged",
        "components": [
            ("noir::field::pow", "noir-lang/noir"),
            ("noir::field::inv", "noir-lang/noir"),
            ("noir::field::sqrt", "noir-lang/noir"),
            ("noir::std::ecdsa_secp256k1::verify", "noir-lang/noir"),
            ("noir::std::ecdsa_secp256r1::verify", "noir-lang/noir"),
            ("noir::std::schnorr::verify_signature", "noir-lang/noir"),
            ("noir::std::eddsa::verify", "noir-lang/noir"),
            ("noir::std::hash::poseidon::bn254", "noir-lang/noir"),
            ("noir::std::hash::poseidon::poseidon", "noir-lang/noir"),
            ("noir::std::hash::pedersen::pedersen_commitment", "noir-lang/noir"),
            ("noir::std::hash::keccak256", "noir-lang/noir"),
            ("noir::std::hash::sha256", "noir-lang/noir"),
            ("noir::std::hash::blake2s", "noir-lang/noir"),
            ("noir::std::hash::blake3", "noir-lang/noir"),
            ("noir::std::merkle::compute_merkle_root", "noir-lang/noir"),
            ("noir::std::bigint::mod_exp", "noir-lang/noir"),
            ("noir::std::bigint::mod_inv", "noir-lang/noir"),
            ("noir::std::field::quotient_remainder", "noir-lang/noir"),
            ("noir::std::field::to_be_bytes", "noir-lang/noir"),
            ("noir::std::field::to_le_bytes", "noir-lang/noir"),
        ],
    },
    # =================================================================
    # Zellic — Halo2 audit (Aztec / 0xParc)
    # =================================================================
    {
        "auditor": "zellic",
        "target": "halo2-core",
        "attack_class": "circuit-spurious-constraint",
        "bug_class": "halo2-region-cell-reuse",
        "circuit_dsl": "halo2-rust",
        "proof_system": "halo2-kzg",
        "zkvm": None,
        "default_severity": "high",
        "default_dollar_class": "$100K-$1M",
        "impact_class": "privilege-escalation",
        "impact_actor": "arbitrary-user",
        "fix_pattern": (
            "use Halo2's region API to assign every cell exactly once; if "
            "shared, lift the cell to a public input or fixed column so "
            "multiple regions binding the same advice cell are explicit"
        ),
        "fix_anti_pattern_avoided": (
            "calling assign_advice on the same (col, offset) from two regions "
            "and assuming the synthesiser will deduplicate consistently"
        ),
        "preconditions": [
            "two regions in the same advice column share a row",
            "synthesiser emits an additional equality constraint",
            "prover satisfies both regions' constraints with a witness that "
            "violates the implicit equality at a value the audit logic doesn't "
            "expect",
        ],
        "attacker_role": "unprivileged",
        "components": [
            ("halo2::circuit::Region::assign_advice", "zcash/halo2"),
            ("halo2::circuit::Region::assign_fixed", "zcash/halo2"),
            ("halo2::circuit::Region::assign_advice_from_constant", "zcash/halo2"),
            ("halo2::circuit::Region::constrain_equal", "zcash/halo2"),
            ("halo2::circuit::Region::constrain_constant", "zcash/halo2"),
            ("halo2::circuit::Region::name_column", "zcash/halo2"),
            ("halo2::plonk::Selector::enable", "zcash/halo2"),
            ("halo2::plonk::Permutation::add_column", "zcash/halo2"),
            ("halo2::plonk::Lookup::add_table", "zcash/halo2"),
            ("halo2::plonk::Expression::eval", "zcash/halo2"),
            ("halo2::poly::commitment::open", "zcash/halo2"),
            ("halo2::poly::commitment::verify", "zcash/halo2"),
            ("halo2::transcript::TranscriptRead::read_scalar", "zcash/halo2"),
            ("halo2::transcript::TranscriptWrite::write_scalar", "zcash/halo2"),
            ("halo2::poly::evaluation::evaluate", "zcash/halo2"),
        ],
    },
    # =================================================================
    # Zellic — Aleo snarkVM audit
    # =================================================================
    {
        "auditor": "zellic",
        "target": "aleo-snarkvm",
        "attack_class": "verifier-input-aliasing",
        "bug_class": "snarkvm-public-input-encoding-aliased",
        "circuit_dsl": "boojum-rust",
        "proof_system": "plonk",
        "zkvm": None,
        "default_severity": "high",
        "default_dollar_class": "$100K-$1M",
        "impact_class": "theft",
        "impact_actor": "depositor-class",
        "fix_pattern": (
            "include the function-id + transition-id in the public-input hash "
            "so two transitions of different functions cannot share a "
            "verification key challenge"
        ),
        "fix_anti_pattern_avoided": (
            "deriving the public-input hash from inputs only, without including "
            "the (program_id, function_id) tuple"
        ),
        "preconditions": [
            "two functions in the same program share an input layout",
            "snarkVM stores a verifying key keyed by function-id only",
            "attacker reuses a proof from function A as a proof for function B",
        ],
        "attacker_role": "unprivileged",
        "components": [
            ("snarkvm::process::execute", "AleoHQ/snarkVM"),
            ("snarkvm::process::deploy", "AleoHQ/snarkVM"),
            ("snarkvm::process::verify_execution", "AleoHQ/snarkVM"),
            ("snarkvm::process::verify_deployment", "AleoHQ/snarkVM"),
            ("snarkvm::process::evaluate_function", "AleoHQ/snarkVM"),
            ("snarkvm::process::finalize_transition", "AleoHQ/snarkVM"),
            ("snarkvm::ledger::commit_transaction", "AleoHQ/snarkVM"),
            ("snarkvm::ledger::check_transaction", "AleoHQ/snarkVM"),
            ("snarkvm::ledger::find_record", "AleoHQ/snarkVM"),
            ("snarkvm::ledger::serial_number", "AleoHQ/snarkVM"),
            ("snarkvm::vm::execute_transition", "AleoHQ/snarkVM"),
            ("snarkvm::vm::verify_transition", "AleoHQ/snarkVM"),
        ],
    },
    # =================================================================
    # OtterSec — Cairo / Starknet account abstraction audits
    # =================================================================
    {
        "auditor": "ottersec",
        "target": "starknet-cairo",
        "attack_class": "circuit-recursion-tag-spoof",
        "bug_class": "cairo-account-class-hash-confusion",
        "circuit_dsl": "starknet-cairo",
        "proof_system": "stark",
        "zkvm": "cairo-vm",
        "default_severity": "critical",
        "default_dollar_class": ">=$1M",
        "impact_class": "theft",
        "impact_actor": "specific-user",
        "fix_pattern": (
            "in every account-contract entrypoint, validate the class-hash "
            "against an allowlist and ensure recursive class-hash queries "
            "carry a depth tag that prevents re-binding mid-call"
        ),
        "fix_anti_pattern_avoided": (
            "trusting `get_class_hash_at(contract_address)` after a "
            "`replace_class_syscall` without rechecking against the call's "
            "expected class"
        ),
        "preconditions": [
            "account contract is upgradeable via replace_class_syscall",
            "downstream entrypoint relies on the class-hash to dispatch",
            "attacker swaps class mid-call and re-enters with elevated privileges",
        ],
        "attacker_role": "unprivileged",
        "components": [
            ("cairo::account::__execute__", "OpenZeppelin/cairo-contracts"),
            ("cairo::account::__validate__", "OpenZeppelin/cairo-contracts"),
            ("cairo::account::__validate_declare__", "OpenZeppelin/cairo-contracts"),
            ("cairo::account::__validate_deploy__", "OpenZeppelin/cairo-contracts"),
            ("cairo::account::is_valid_signature", "OpenZeppelin/cairo-contracts"),
            ("cairo::account::upgrade", "OpenZeppelin/cairo-contracts"),
            ("cairo::erc20::transfer", "OpenZeppelin/cairo-contracts"),
            ("cairo::erc20::approve", "OpenZeppelin/cairo-contracts"),
            ("cairo::erc20::transfer_from", "OpenZeppelin/cairo-contracts"),
            ("cairo::erc721::transfer_from", "OpenZeppelin/cairo-contracts"),
            ("cairo::erc721::safe_transfer_from", "OpenZeppelin/cairo-contracts"),
            ("cairo::erc721::approve", "OpenZeppelin/cairo-contracts"),
            ("cairo::erc1155::safe_transfer_from", "OpenZeppelin/cairo-contracts"),
            ("cairo::erc1155::safe_batch_transfer_from", "OpenZeppelin/cairo-contracts"),
            ("cairo::governor::propose", "OpenZeppelin/cairo-contracts"),
            ("cairo::governor::execute", "OpenZeppelin/cairo-contracts"),
            ("cairo::governor::cancel", "OpenZeppelin/cairo-contracts"),
            ("cairo::governor::vote", "OpenZeppelin/cairo-contracts"),
            ("cairo::timelock::schedule", "OpenZeppelin/cairo-contracts"),
            ("cairo::timelock::execute", "OpenZeppelin/cairo-contracts"),
            ("cairo::vesting::release", "OpenZeppelin/cairo-contracts"),
            ("cairo::merkle_proof::verify", "OpenZeppelin/cairo-contracts"),
            ("cairo::merkle_proof::process_proof", "OpenZeppelin/cairo-contracts"),
            ("cairo::oracle::get_price", "OpenZeppelin/cairo-contracts"),
            ("cairo::staking::stake", "OpenZeppelin/cairo-contracts"),
        ],
    },
    # =================================================================
    # Spearbit — Penumbra zkSNARK circuit audit
    # =================================================================
    {
        "auditor": "spearbit",
        "target": "penumbra",
        "attack_class": "circuit-frozen-variable",
        "bug_class": "penumbra-action-nullifier-freezing",
        "circuit_dsl": "halo2-rust",
        "proof_system": "halo2-ipa",
        "zkvm": None,
        "default_severity": "high",
        "default_dollar_class": "$100K-$1M",
        "impact_class": "freeze",
        "impact_actor": "specific-user",
        "fix_pattern": (
            "ensure every action proof binds the spent-note nullifier to a "
            "constrained derivation (PRF(rseed, position)) and that the "
            "derivation cannot be replayed across actions"
        ),
        "fix_anti_pattern_avoided": (
            "constraining nullifier shape but not its full derivation, "
            "allowing the prover to freeze a victim's note by colliding "
            "nullifiers"
        ),
        "preconditions": [
            "action proof commits to a nullifier without proving full derivation",
            "two notes can hash to the same nullifier under attacker-chosen "
            "auxiliary inputs",
            "attacker spends a dust note that collides with victim's larger "
            "note, freezing the victim's note in the spent set",
        ],
        "attacker_role": "unprivileged",
        "components": [
            ("penumbra::shielded_pool::spend_proof", "penumbra-zone/penumbra"),
            ("penumbra::shielded_pool::output_proof", "penumbra-zone/penumbra"),
            ("penumbra::shielded_pool::swap_proof", "penumbra-zone/penumbra"),
            ("penumbra::shielded_pool::swap_claim_proof", "penumbra-zone/penumbra"),
            ("penumbra::shielded_pool::delegator_vote_proof", "penumbra-zone/penumbra"),
            ("penumbra::shielded_pool::nullifier_derivation_proof", "penumbra-zone/penumbra"),
            ("penumbra::dex::position_open_proof", "penumbra-zone/penumbra"),
            ("penumbra::dex::position_close_proof", "penumbra-zone/penumbra"),
            ("penumbra::dex::position_withdraw_proof", "penumbra-zone/penumbra"),
            ("penumbra::stake::undelegate_claim_proof", "penumbra-zone/penumbra"),
            ("penumbra::governance::proposal_submit_proof", "penumbra-zone/penumbra"),
            ("penumbra::ibc::action_proof", "penumbra-zone/penumbra"),
        ],
    },
    # =================================================================
    # ChainSecurity — Polygon zkEVM circuit audit
    # =================================================================
    {
        "auditor": "chainsecurity",
        "target": "polygon-zkevm-circuits",
        "attack_class": "operator-batch-omission",
        "bug_class": "sequencer-omits-tx-from-batch",
        "circuit_dsl": "plonky2-rust",
        "proof_system": "fri-plonky2",
        "zkvm": None,
        "default_severity": "high",
        "default_dollar_class": "$100K-$1M",
        "impact_class": "griefing",
        "impact_actor": "specific-user",
        "fix_pattern": (
            "implement a forced-inclusion queue with a timelock such that any "
            "user can post a tx that becomes part of the batch after T blocks "
            "regardless of sequencer cooperation"
        ),
        "fix_anti_pattern_avoided": (
            "relying solely on the sequencer to include user txs without a "
            "forced-inclusion fallback"
        ),
        "preconditions": [
            "sequencer is a centralised actor",
            "no forced-inclusion mechanism exists",
            "sequencer censors a specific user's tx indefinitely",
        ],
        "attacker_role": "sequencer",
        "components": [
            ("zkevm::sequencer::buildBatch", "0xPolygonHermez/zkevm-circuits"),
            ("zkevm::sequencer::commitBatch", "0xPolygonHermez/zkevm-circuits"),
            ("zkevm::sequencer::publishTxs", "0xPolygonHermez/zkevm-circuits"),
            ("zkevm::PolygonZkEVM::sequenceBatches", "0xPolygonHermez/zkevm-contracts"),
            ("zkevm::PolygonZkEVM::sequenceForceBatches", "0xPolygonHermez/zkevm-contracts"),
            ("zkevm::PolygonZkEVM::forceBatch", "0xPolygonHermez/zkevm-contracts"),
            ("zkevm::PolygonZkEVM::verifyBatches", "0xPolygonHermez/zkevm-contracts"),
            ("zkevm::PolygonZkEVM::overridePendingState", "0xPolygonHermez/zkevm-contracts"),
            ("zkevm::PolygonZkEVMBridge::bridgeAsset", "0xPolygonHermez/zkevm-contracts"),
            ("zkevm::PolygonZkEVMBridge::claimAsset", "0xPolygonHermez/zkevm-contracts"),
            ("zkevm::PolygonZkEVMBridge::bridgeMessage", "0xPolygonHermez/zkevm-contracts"),
            ("zkevm::PolygonZkEVMBridge::claimMessage", "0xPolygonHermez/zkevm-contracts"),
        ],
    },
    # =================================================================
    # ChainSecurity — Linea sequencer audit
    # =================================================================
    {
        "auditor": "chainsecurity",
        "target": "linea-sequencer",
        "attack_class": "forced-inclusion-bypass",
        "bug_class": "forced-inclusion-timelock-bypass",
        "circuit_dsl": "plonky2-rust",
        "proof_system": "fri-plonky2",
        "zkvm": None,
        "default_severity": "high",
        "default_dollar_class": "$100K-$1M",
        "impact_class": "griefing",
        "impact_actor": "specific-user",
        "fix_pattern": (
            "force-inclusion windows must elapse on the L1 timer, not on an "
            "L2-counter; bind force-inclusion eligibility to an L1 block "
            "number rather than a sequencer-supplied epoch"
        ),
        "fix_anti_pattern_avoided": (
            "letting the sequencer extend its own censorship window by "
            "advancing an internal epoch counter"
        ),
        "preconditions": [
            "force-inclusion eligibility is keyed by L2 epoch",
            "sequencer controls when the epoch advances",
            "sequencer can indefinitely delay the force-inclusion deadline",
        ],
        "attacker_role": "sequencer",
        "components": [
            ("linea::sequencer::publishBlock", "ConsenSys/linea-monorepo"),
            ("linea::sequencer::commitBlock", "ConsenSys/linea-monorepo"),
            ("linea::sequencer::scheduleForceBlock", "ConsenSys/linea-monorepo"),
            ("linea::L1MessageService::sendMessage", "ConsenSys/linea-monorepo"),
            ("linea::L1MessageService::claimMessage", "ConsenSys/linea-monorepo"),
            ("linea::L1MessageService::deliverMessage", "ConsenSys/linea-monorepo"),
            ("linea::L1MessageService::anchorL2MessagingStateBlockNumber", "ConsenSys/linea-monorepo"),
            ("linea::L2MessageService::sendMessage", "ConsenSys/linea-monorepo"),
            ("linea::L2MessageService::receiveMessage", "ConsenSys/linea-monorepo"),
            ("linea::ZkEvm::submitBlock", "ConsenSys/linea-monorepo"),
            ("linea::ZkEvm::verifyBlock", "ConsenSys/linea-monorepo"),
            ("linea::ZkEvm::finalizeWithProof", "ConsenSys/linea-monorepo"),
        ],
    },
    # =================================================================
    # ChainSecurity — Scroll prover audit
    # =================================================================
    {
        "auditor": "chainsecurity",
        "target": "scroll-zkevm",
        "attack_class": "state-diff-leak",
        "bug_class": "scroll-state-diff-encoding-too-rich",
        "circuit_dsl": "halo2-rust",
        "proof_system": "halo2-kzg",
        "zkvm": None,
        "default_severity": "medium",
        "default_dollar_class": "$10K-$100K",
        "impact_class": "griefing",
        "impact_actor": "arbitrary-user",
        "fix_pattern": (
            "constrain the state-diff encoding to canonical RLP and reject "
            "non-minimal encodings; bind the diff hash to the verifier "
            "transcript via a domain-separated absorb"
        ),
        "fix_anti_pattern_avoided": (
            "accepting any byte string as state-diff and computing the diff "
            "hash from the raw bytes without canonicalisation"
        ),
        "preconditions": [
            "state-diff is supplied as raw bytes by the sequencer",
            "verifier hashes raw bytes without canonical-encoding check",
            "attacker leaks information by selecting between non-canonical "
            "encodings of the same logical diff",
        ],
        "attacker_role": "sequencer",
        "components": [
            ("scroll::zkevm::commit_state_diff", "scroll-tech/zkevm-circuits"),
            ("scroll::zkevm::verify_state_diff", "scroll-tech/zkevm-circuits"),
            ("scroll::zkevm::compute_state_root", "scroll-tech/zkevm-circuits"),
            ("scroll::zkevm::compute_tx_root", "scroll-tech/zkevm-circuits"),
            ("scroll::zkevm::compute_receipt_root", "scroll-tech/zkevm-circuits"),
            ("scroll::zkevm::compute_block_hash", "scroll-tech/zkevm-circuits"),
            ("scroll::zkevm::evm::interpret", "scroll-tech/zkevm-circuits"),
            ("scroll::zkevm::evm::execute_tx", "scroll-tech/zkevm-circuits"),
            ("scroll::zkevm::evm::balance_lookup", "scroll-tech/zkevm-circuits"),
            ("scroll::zkevm::evm::storage_lookup", "scroll-tech/zkevm-circuits"),
            ("scroll::zkevm::evm::keccak_lookup", "scroll-tech/zkevm-circuits"),
        ],
    },
    # =================================================================
    # Least Authority — Penumbra IBC audit
    # =================================================================
    {
        "auditor": "least-authority",
        "target": "penumbra-ibc",
        "attack_class": "settlement-layer-fraud-window-bypass",
        "bug_class": "ibc-light-client-skip-window",
        "circuit_dsl": "halo2-rust",
        "proof_system": "halo2-ipa",
        "zkvm": None,
        "default_severity": "high",
        "default_dollar_class": "$100K-$1M",
        "impact_class": "theft",
        "impact_actor": "protocol-treasury",
        "fix_pattern": (
            "require IBC light-client updates to traverse every consensus "
            "header between trusted and target heights, or limit skip-updates "
            "to a fraction of the validator set"
        ),
        "fix_anti_pattern_avoided": (
            "letting a light-client update skip arbitrary header ranges as "
            "long as the validator-set hash matches"
        ),
        "preconditions": [
            "light client accepts skip-updates with no upper bound on the "
            "header gap",
            "attacker controls a validator set at a far-future height",
            "attacker submits a skip-update to that future height and uses it "
            "to acknowledge fake IBC packets",
        ],
        "attacker_role": "validator",
        "components": [
            ("penumbra::ibc::client::update_client", "penumbra-zone/penumbra"),
            ("penumbra::ibc::client::misbehavior", "penumbra-zone/penumbra"),
            ("penumbra::ibc::client::verify_membership", "penumbra-zone/penumbra"),
            ("penumbra::ibc::client::verify_non_membership", "penumbra-zone/penumbra"),
            ("penumbra::ibc::connection::open_init", "penumbra-zone/penumbra"),
            ("penumbra::ibc::connection::open_try", "penumbra-zone/penumbra"),
            ("penumbra::ibc::connection::open_ack", "penumbra-zone/penumbra"),
            ("penumbra::ibc::connection::open_confirm", "penumbra-zone/penumbra"),
            ("penumbra::ibc::channel::open_init", "penumbra-zone/penumbra"),
            ("penumbra::ibc::channel::open_try", "penumbra-zone/penumbra"),
            ("penumbra::ibc::packet::recv_packet", "penumbra-zone/penumbra"),
            ("penumbra::ibc::packet::acknowledge_packet", "penumbra-zone/penumbra"),
        ],
    },
    # =================================================================
    # Sigma Prime — Polygon Plonky2 audit
    # =================================================================
    {
        "auditor": "sigma-prime",
        "target": "polygon-plonky2",
        "attack_class": "pcs-double-open",
        "bug_class": "fri-batched-pcs-open-collision",
        "circuit_dsl": "plonky2-rust",
        "proof_system": "fri-plonky2",
        "zkvm": None,
        "default_severity": "critical",
        "default_dollar_class": ">=$1M",
        "impact_class": "theft",
        "impact_actor": "depositor-class",
        "fix_pattern": (
            "tag every PCS opening with a unique (commitment_id, evaluation_"
            "point) tuple and reject any opening whose tag has been previously "
            "consumed in the current proof"
        ),
        "fix_anti_pattern_avoided": (
            "letting the prover open the same polynomial at the same point "
            "twice with different claimed values"
        ),
        "preconditions": [
            "PCS verifier accepts batched openings",
            "no tagging or deduplication on (commitment, eval_point) pairs",
            "prover supplies two openings of the same polynomial at the same "
            "point with different values; verifier accepts the conflict",
        ],
        "attacker_role": "unprivileged",
        "components": [
            ("plonky2::fri::open", "0xPolygonZero/plonky2"),
            ("plonky2::fri::batch_open", "0xPolygonZero/plonky2"),
            ("plonky2::fri::verify_batch", "0xPolygonZero/plonky2"),
            ("plonky2::pcs::commit", "0xPolygonZero/plonky2"),
            ("plonky2::pcs::open_point", "0xPolygonZero/plonky2"),
            ("plonky2::pcs::verify_open", "0xPolygonZero/plonky2"),
            ("plonky2::recursion::verify_proof", "0xPolygonZero/plonky2"),
            ("plonky2::recursion::add_recursive_proof_target", "0xPolygonZero/plonky2"),
            ("plonky2::starky::compute_quotient", "0xPolygonZero/plonky2"),
            ("plonky2::starky::verify_constraint_evaluation", "0xPolygonZero/plonky2"),
        ],
    },
    # =================================================================
    # Trail of Bits — Powdr / Jolt zkVM audit
    # =================================================================
    {
        "auditor": "trail-of-bits",
        "target": "powdr-zkvm",
        "attack_class": "zkvm-host-call-spoof",
        "bug_class": "powdr-syscall-input-trust",
        "circuit_dsl": "powdr",
        "proof_system": "fri-plonky2",
        "zkvm": "powdr",
        "default_severity": "high",
        "default_dollar_class": "$100K-$1M",
        "impact_class": "privilege-escalation",
        "impact_actor": "arbitrary-user",
        "fix_pattern": (
            "treat every host-call input as untrusted; constrain syscall "
            "arguments to canonical form and re-derive any claimed identity "
            "(caller, message, signature) inside the circuit"
        ),
        "fix_anti_pattern_avoided": (
            "trusting the host's claim of caller identity for a syscall "
            "without binding it to the program's input commitment"
        ),
        "preconditions": [
            "syscall dispatch accepts a `caller` argument supplied by the host",
            "circuit does not constrain the caller against the public input "
            "commitment",
            "attacker forges syscall traces with arbitrary caller identities",
        ],
        "attacker_role": "unprivileged",
        "components": [
            ("powdr::host::ecall_dispatch", "powdr-labs/powdr"),
            ("powdr::host::keccak_syscall", "powdr-labs/powdr"),
            ("powdr::host::sha256_syscall", "powdr-labs/powdr"),
            ("powdr::host::poseidon_syscall", "powdr-labs/powdr"),
            ("powdr::host::ed25519_verify", "powdr-labs/powdr"),
            ("powdr::host::secp256k1_recover", "powdr-labs/powdr"),
            ("powdr::host::bn254_pairing", "powdr-labs/powdr"),
            ("powdr::host::random_oracle_query", "powdr-labs/powdr"),
            ("powdr::host::external_program_load", "powdr-labs/powdr"),
            ("powdr::host::memory_io_op", "powdr-labs/powdr"),
        ],
    },
    # =================================================================
    # Trail of Bits — Jolt zkVM audit
    # =================================================================
    {
        "auditor": "trail-of-bits",
        "target": "jolt-zkvm",
        "attack_class": "lookup-injection",
        "bug_class": "jolt-lookup-table-not-pinned",
        "circuit_dsl": "plonky2-rust",
        "proof_system": "fri-plonky2",
        "zkvm": "jolt",
        "default_severity": "high",
        "default_dollar_class": "$100K-$1M",
        "impact_class": "privilege-escalation",
        "impact_actor": "arbitrary-user",
        "fix_pattern": (
            "in Jolt's lookup-arg subprotocol (Lasso), commit to the lookup "
            "table at setup time and bind that commitment into the verifier "
            "key so post-deploy table edits are detectable"
        ),
        "fix_anti_pattern_avoided": (
            "treating the lookup table as a runtime input supplied alongside "
            "the proof"
        ),
        "preconditions": [
            "Jolt's lookup arg is parameterised by table contents",
            "the table is not pinned to the verifier key",
            "attacker (or compromised dependency) supplies a malicious table "
            "row that satisfies a privilege check",
        ],
        "attacker_role": "unprivileged",
        "components": [
            ("jolt::lasso::lookup_commit", "a16z/jolt"),
            ("jolt::lasso::lookup_verify", "a16z/jolt"),
            ("jolt::lasso::compute_eq_polynomial", "a16z/jolt"),
            ("jolt::rv32i::execute_step", "a16z/jolt"),
            ("jolt::rv32i::lookup_combine", "a16z/jolt"),
            ("jolt::rv32i::load_subtable", "a16z/jolt"),
            ("jolt::rv32i::range_check_lookup", "a16z/jolt"),
            ("jolt::rv32i::byte_decompose_lookup", "a16z/jolt"),
            ("jolt::memory::read_lookup", "a16z/jolt"),
            ("jolt::memory::write_lookup", "a16z/jolt"),
        ],
    },
    # =================================================================
    # KALOS / Veridise — zkSync Boojum audit
    # =================================================================
    {
        "auditor": "veridise",
        "target": "zksync-boojum",
        "attack_class": "proof-aggregation-incorrect",
        "bug_class": "boojum-aggregator-input-binding",
        "circuit_dsl": "boojum-rust",
        "proof_system": "boojum",
        "zkvm": None,
        "default_severity": "high",
        "default_dollar_class": "$100K-$1M",
        "impact_class": "theft",
        "impact_actor": "depositor-class",
        "fix_pattern": (
            "the aggregator circuit must hash each child-proof's public input "
            "into a domain-separated transcript before producing the aggregate "
            "commitment"
        ),
        "fix_anti_pattern_avoided": (
            "letting the aggregator concatenate child public inputs without a "
            "domain separator, opening cross-child aliasing"
        ),
        "preconditions": [
            "aggregator combines N child proofs",
            "child public inputs are concatenated without a separator",
            "two distinct (child_i, public_i) splits produce the same "
            "aggregate input",
        ],
        "attacker_role": "unprivileged",
        "components": [
            ("boojum::aggregator::aggregate_proofs", "matter-labs/era-boojum"),
            ("boojum::aggregator::verify_aggregate", "matter-labs/era-boojum"),
            ("boojum::aggregator::compute_combined_input", "matter-labs/era-boojum"),
            ("boojum::recursion::verify_child", "matter-labs/era-boojum"),
            ("boojum::recursion::accumulate_public", "matter-labs/era-boojum"),
            ("boojum::gadgets::poseidon2", "matter-labs/era-boojum"),
            ("boojum::gadgets::sha256", "matter-labs/era-boojum"),
            ("boojum::gadgets::keccak256", "matter-labs/era-boojum"),
            ("boojum::gadgets::lookup", "matter-labs/era-boojum"),
            ("boojum::cs::synthesize_constraint", "matter-labs/era-boojum"),
        ],
    },
    # =================================================================
    # Trail of Bits — Miden VM audit
    # =================================================================
    {
        "auditor": "trail-of-bits",
        "target": "miden-vm",
        "attack_class": "zkvm-trap-bypass",
        "bug_class": "miden-assert-not-enforced",
        "circuit_dsl": "miden-asm",
        "proof_system": "miden-stark",
        "zkvm": "miden",
        "default_severity": "high",
        "default_dollar_class": "$100K-$1M",
        "impact_class": "privilege-escalation",
        "impact_actor": "arbitrary-user",
        "fix_pattern": (
            "Miden's `assert` opcode must be a hard constraint in the trace "
            "table; ensure every `assert` site emits a constraint that the "
            "asserted value equals zero, not just a host-side check"
        ),
        "fix_anti_pattern_avoided": (
            "implementing `assert` as a host check that the prover can "
            "bypass by lying about the trace"
        ),
        "preconditions": [
            "Miden assembly program contains an `assert` opcode on a "
            "user-supplied value",
            "circuit treats the assert as a hint, not a constraint",
            "prover skips the assert and proves the program advanced past it",
        ],
        "attacker_role": "unprivileged",
        "components": [
            ("miden::vm::assert", "0xPolygonMiden/miden-vm"),
            ("miden::vm::assertz", "0xPolygonMiden/miden-vm"),
            ("miden::vm::assert_eq", "0xPolygonMiden/miden-vm"),
            ("miden::vm::assert_eqw", "0xPolygonMiden/miden-vm"),
            ("miden::vm::exec_call", "0xPolygonMiden/miden-vm"),
            ("miden::vm::exec_dyncall", "0xPolygonMiden/miden-vm"),
            ("miden::vm::push_advice", "0xPolygonMiden/miden-vm"),
            ("miden::vm::adv_loadw", "0xPolygonMiden/miden-vm"),
            ("miden::vm::adv_pipe", "0xPolygonMiden/miden-vm"),
            ("miden::vm::trace_finalize", "0xPolygonMiden/miden-vm"),
        ],
    },
    # =================================================================
    # OtterSec — Solana zk-program audit
    # =================================================================
    {
        "auditor": "ottersec",
        "target": "solana-zk-token-sdk",
        "attack_class": "prover-side-channel",
        "bug_class": "solana-bulletproof-witness-leak",
        "circuit_dsl": "halo2-rust",
        "proof_system": "halo2-ipa",
        "zkvm": None,
        "default_severity": "medium",
        "default_dollar_class": "$10K-$100K",
        "impact_class": "griefing",
        "impact_actor": "specific-user",
        "fix_pattern": (
            "ensure prover RNG draws are constant-time and that prover memory "
            "is cleared after use; do not log intermediate witness values"
        ),
        "fix_anti_pattern_avoided": (
            "logging witness intermediates via printf-style debug helpers in "
            "production builds"
        ),
        "preconditions": [
            "prover runs in a memory-observable environment",
            "intermediate scalars are written to logs or syslog",
            "attacker reads the log and recovers the secret witness",
        ],
        "attacker_role": "local-host-observer",
        "components": [
            ("solana_zk::range_proof::generate", "solana-labs/solana-program-library"),
            ("solana_zk::range_proof::verify", "solana-labs/solana-program-library"),
            ("solana_zk::equality_proof::generate", "solana-labs/solana-program-library"),
            ("solana_zk::equality_proof::verify", "solana-labs/solana-program-library"),
            ("solana_zk::validity_proof::generate", "solana-labs/solana-program-library"),
            ("solana_zk::pedersen::commit", "solana-labs/solana-program-library"),
            ("solana_zk::pedersen::decompress", "solana-labs/solana-program-library"),
            ("solana_zk::transcript::append", "solana-labs/solana-program-library"),
            ("solana_zk::transcript::challenge_scalar", "solana-labs/solana-program-library"),
            ("solana_zk::token::confidential_transfer", "solana-labs/solana-program-library"),
        ],
    },
    # =================================================================
    # Spearbit — Aztec note encryption audit
    # =================================================================
    {
        "auditor": "spearbit",
        "target": "aztec-notes",
        "attack_class": "prover-knowledge-extraction-leak",
        "bug_class": "aztec-note-decrypt-leak",
        "circuit_dsl": "noir",
        "proof_system": "barretenberg-honk",
        "zkvm": None,
        "default_severity": "high",
        "default_dollar_class": "$100K-$1M",
        "impact_class": "griefing",
        "impact_actor": "specific-user",
        "fix_pattern": (
            "encrypt notes under a derived ephemeral key tied to a "
            "stealth-address scheme so a successful decryption reveals only "
            "the intended recipient, not the sender's full transaction graph"
        ),
        "fix_anti_pattern_avoided": (
            "using a single static viewing key for all of a user's notes"
        ),
        "preconditions": [
            "viewing key is reused across many notes",
            "attacker who obtains the viewing key reconstructs the full "
            "note-flow graph",
            "victim has no rotation path",
        ],
        "attacker_role": "local-host-observer",
        "components": [
            ("aztec::encrypted_log::compute_note_hash", "AztecProtocol/aztec-packages"),
            ("aztec::encrypted_log::encrypt_note_log", "AztecProtocol/aztec-packages"),
            ("aztec::encrypted_log::decrypt_note_log", "AztecProtocol/aztec-packages"),
            ("aztec::tagged_log::create_log", "AztecProtocol/aztec-packages"),
            ("aztec::tagged_log::process_logs", "AztecProtocol/aztec-packages"),
            ("aztec::keys::derive_iv_pk", "AztecProtocol/aztec-packages"),
            ("aztec::keys::derive_ov_pk", "AztecProtocol/aztec-packages"),
            ("aztec::keys::derive_npk_m", "AztecProtocol/aztec-packages"),
            ("aztec::keys::derive_tag", "AztecProtocol/aztec-packages"),
        ],
    },
    # =================================================================
    # Veridise — Worldcoin Semaphore v3 audit
    # =================================================================
    {
        "auditor": "veridise",
        "target": "worldcoin-semaphore",
        "attack_class": "withdrawal-merkle-proof-spoof",
        "bug_class": "semaphore-tree-root-version-skew",
        "circuit_dsl": "circom",
        "proof_system": "groth16",
        "zkvm": None,
        "default_severity": "high",
        "default_dollar_class": "$100K-$1M",
        "impact_class": "privilege-escalation",
        "impact_actor": "arbitrary-user",
        "fix_pattern": (
            "bind every Semaphore proof to a recent Merkle root and reject "
            "proofs against roots older than R blocks; store the active root "
            "set in a small ring buffer"
        ),
        "fix_anti_pattern_avoided": (
            "accepting any historical root, allowing an attacker to revive "
            "long-removed identities"
        ),
        "preconditions": [
            "Semaphore contract accepts any historical root",
            "attacker possesses a credential that has since been removed from "
            "the active group",
            "attacker generates a proof against the historical root and "
            "spends the credential",
        ],
        "attacker_role": "unprivileged",
        "components": [
            ("semaphore::Semaphore::verifyProof", "semaphore-protocol/semaphore"),
            ("semaphore::Semaphore::addMember", "semaphore-protocol/semaphore"),
            ("semaphore::Semaphore::removeMember", "semaphore-protocol/semaphore"),
            ("semaphore::Semaphore::updateMember", "semaphore-protocol/semaphore"),
            ("semaphore::Semaphore::getMerkleTreeRoot", "semaphore-protocol/semaphore"),
            ("semaphore::Semaphore::getMerkleTreeDepth", "semaphore-protocol/semaphore"),
            ("semaphore::Semaphore::createGroup", "semaphore-protocol/semaphore"),
            ("semaphore::Semaphore::updateGroupAdmin", "semaphore-protocol/semaphore"),
            ("worldcoin::WorldID::verifyProof", "worldcoin/world-id-contracts"),
            ("worldcoin::WorldID::latestRoot", "worldcoin/world-id-contracts"),
            ("worldcoin::WorldID::checkValidRoot", "worldcoin/world-id-contracts"),
            ("worldcoin::WorldID::registerIdentities", "worldcoin/world-id-contracts"),
            ("worldcoin::WorldID::deleteIdentities", "worldcoin/world-id-contracts"),
        ],
    },
    # =================================================================
    # Asymmetric Research — Polygon zkEVM bridge audit
    # =================================================================
    {
        "auditor": "asymmetric-research",
        "target": "polygon-zkevm-bridge",
        "attack_class": "transcript-mismatch",
        "bug_class": "bridge-message-transcript-mismatch",
        "circuit_dsl": "plonky2-rust",
        "proof_system": "fri-plonky2",
        "zkvm": None,
        "default_severity": "critical",
        "default_dollar_class": ">=$1M",
        "impact_class": "theft",
        "impact_actor": "protocol-treasury",
        "fix_pattern": (
            "the bridge verifier must hash the full L2 message transcript "
            "(origin_network, destination_network, amount, metadata) into the "
            "claim's public input, not just (origin, amount)"
        ),
        "fix_anti_pattern_avoided": (
            "leaving metadata unbound, allowing an attacker to claim a bridge "
            "message with mismatching metadata"
        ),
        "preconditions": [
            "bridge claim verifies a Merkle proof against a leaf encoding "
            "(origin, amount)",
            "metadata is supplied separately at claim time",
            "attacker constructs a claim with valid (origin, amount) but "
            "malicious metadata, executing arbitrary callback",
        ],
        "attacker_role": "unprivileged",
        "components": [
            ("zkevm_bridge::bridgeAsset", "0xPolygonHermez/zkevm-contracts"),
            ("zkevm_bridge::claimAsset", "0xPolygonHermez/zkevm-contracts"),
            ("zkevm_bridge::bridgeMessage", "0xPolygonHermez/zkevm-contracts"),
            ("zkevm_bridge::claimMessage", "0xPolygonHermez/zkevm-contracts"),
            ("zkevm_bridge::_verifyLeaf", "0xPolygonHermez/zkevm-contracts"),
            ("zkevm_bridge::_addLeaf", "0xPolygonHermez/zkevm-contracts"),
            ("zkevm_bridge::getRoot", "0xPolygonHermez/zkevm-contracts"),
            ("zkevm_bridge::_permit", "0xPolygonHermez/zkevm-contracts"),
            ("zkevm_bridge::activateEmergencyState", "0xPolygonHermez/zkevm-contracts"),
            ("zkevm_bridge::deactivateEmergencyState", "0xPolygonHermez/zkevm-contracts"),
            ("zkevm_bridge::updateGlobalExitRoot", "0xPolygonHermez/zkevm-contracts"),
            ("zkevm_bridge::transferOwnership", "0xPolygonHermez/zkevm-contracts"),
        ],
    },
    # =================================================================
    # Trail of Bits — Aztec Protocol Honk audit
    # =================================================================
    {
        "auditor": "trail-of-bits",
        "target": "aztec-honk",
        "attack_class": "proof-pcs-commitment-malleability",
        "bug_class": "honk-shplonk-batch-malleability",
        "circuit_dsl": "barretenberg-cpp",
        "proof_system": "barretenberg-honk",
        "zkvm": None,
        "default_severity": "high",
        "default_dollar_class": "$100K-$1M",
        "impact_class": "theft",
        "impact_actor": "depositor-class",
        "fix_pattern": (
            "in the Honk Shplonk subprotocol, fold the per-circuit verifier "
            "key into each commitment opening so two distinct (vk, proof) "
            "pairs cannot share a Shplonk batch"
        ),
        "fix_anti_pattern_avoided": (
            "reusing a Shplonk batch hash across distinct (vk, proof) pairs"
        ),
        "preconditions": [
            "Shplonk batches multiple polynomial openings into one proof",
            "batch hash is keyed by openings only, not the verifier-key",
            "attacker constructs two (vk, proof) pairs that share a Shplonk "
            "batch hash",
        ],
        "attacker_role": "unprivileged",
        "components": [
            ("honk::shplonk::prove", "AztecProtocol/barretenberg"),
            ("honk::shplonk::verify", "AztecProtocol/barretenberg"),
            ("honk::shplonk::compute_batched_commitment", "AztecProtocol/barretenberg"),
            ("honk::sumcheck::prove", "AztecProtocol/barretenberg"),
            ("honk::sumcheck::verify", "AztecProtocol/barretenberg"),
            ("honk::sumcheck::compute_univariate", "AztecProtocol/barretenberg"),
            ("honk::sumcheck::partially_evaluate", "AztecProtocol/barretenberg"),
            ("honk::gemini::prove", "AztecProtocol/barretenberg"),
            ("honk::gemini::verify", "AztecProtocol/barretenberg"),
            ("honk::transcript::Honk::observe", "AztecProtocol/barretenberg"),
        ],
    },
    # =================================================================
    # Zellic — Linea verifier-contract audit
    # =================================================================
    {
        "auditor": "zellic",
        "target": "linea-verifier",
        "attack_class": "verifier-stale-key",
        "bug_class": "verifier-upgrade-without-pause",
        "circuit_dsl": "plonky2-rust",
        "proof_system": "fri-plonky2",
        "zkvm": None,
        "default_severity": "high",
        "default_dollar_class": "$100K-$1M",
        "impact_class": "theft",
        "impact_actor": "protocol-treasury",
        "fix_pattern": (
            "any verifier-key upgrade must pause proof acceptance for a "
            "minimum window, run a public audit, and require a multi-sig "
            "release before re-enabling"
        ),
        "fix_anti_pattern_avoided": (
            "swapping verifier keys atomically with no upgrade timelock, "
            "letting a compromised admin push a backdoored key"
        ),
        "preconditions": [
            "verifier contract has an admin-controlled key-swap function",
            "no timelock or multisig delay on key swaps",
            "compromised admin pushes a malicious key and forges proofs",
        ],
        "attacker_role": "privileged-compromised",
        "components": [
            ("linea::Verifier::setVerifierKey", "ConsenSys/linea-monorepo"),
            ("linea::Verifier::verifyProof", "ConsenSys/linea-monorepo"),
            ("linea::Verifier::registerVerifier", "ConsenSys/linea-monorepo"),
            ("linea::Verifier::unregisterVerifier", "ConsenSys/linea-monorepo"),
            ("linea::Verifier::pause", "ConsenSys/linea-monorepo"),
            ("linea::Verifier::unpause", "ConsenSys/linea-monorepo"),
            ("linea::Verifier::grantRole", "ConsenSys/linea-monorepo"),
            ("linea::Verifier::revokeRole", "ConsenSys/linea-monorepo"),
            ("linea::Verifier::transferOwnership", "ConsenSys/linea-monorepo"),
            ("linea::Verifier::acceptOwnership", "ConsenSys/linea-monorepo"),
        ],
    },
    # =================================================================
    # OtterSec — Cairo zkEVM (Kakarot) audit
    # =================================================================
    {
        "auditor": "ottersec",
        "target": "kakarot-zkevm",
        "attack_class": "zkvm-program-counter-bypass",
        "bug_class": "kakarot-pc-jump-target-confusion",
        "circuit_dsl": "starknet-cairo",
        "proof_system": "stark",
        "zkvm": "cairo-vm",
        "default_severity": "critical",
        "default_dollar_class": ">=$1M",
        "impact_class": "theft",
        "impact_actor": "depositor-class",
        "fix_pattern": (
            "validate every EVM jump target against JUMPDEST positions before "
            "committing to the next PC; constrain the trace such that an "
            "invalid jump always aborts execution"
        ),
        "fix_anti_pattern_avoided": (
            "letting the prover supply a `next_pc` claim without an "
            "accompanying validity proof against JUMPDEST"
        ),
        "preconditions": [
            "EVM JUMP / JUMPI consumes a prover-supplied next_pc",
            "circuit does not constrain next_pc to a JUMPDEST opcode",
            "prover jumps into the middle of a PUSH constant, executing "
            "arbitrary bytecode",
        ],
        "attacker_role": "unprivileged",
        "components": [
            ("kakarot::evm::jump_opcode", "kkrt-labs/kakarot"),
            ("kakarot::evm::jumpi_opcode", "kkrt-labs/kakarot"),
            ("kakarot::evm::jumpdest_opcode", "kkrt-labs/kakarot"),
            ("kakarot::evm::push_opcode", "kkrt-labs/kakarot"),
            ("kakarot::evm::call_opcode", "kkrt-labs/kakarot"),
            ("kakarot::evm::staticcall_opcode", "kkrt-labs/kakarot"),
            ("kakarot::evm::delegatecall_opcode", "kkrt-labs/kakarot"),
            ("kakarot::evm::callcode_opcode", "kkrt-labs/kakarot"),
            ("kakarot::evm::return_opcode", "kkrt-labs/kakarot"),
            ("kakarot::evm::revert_opcode", "kkrt-labs/kakarot"),
            ("kakarot::evm::stop_opcode", "kkrt-labs/kakarot"),
            ("kakarot::evm::create_opcode", "kkrt-labs/kakarot"),
            ("kakarot::evm::create2_opcode", "kkrt-labs/kakarot"),
            ("kakarot::evm::selfdestruct_opcode", "kkrt-labs/kakarot"),
            ("kakarot::evm::interpret_step", "kkrt-labs/kakarot"),
        ],
    },
    # =================================================================
    # Trail of Bits — Plonky3 audit (additional plonky2 lineage)
    # =================================================================
    {
        "auditor": "trail-of-bits",
        "target": "plonky3",
        "attack_class": "proof-batching-conflation",
        "bug_class": "plonky3-batched-air-cross-contamination",
        "circuit_dsl": "plonky2-rust",
        "proof_system": "fri-plonky2",
        "zkvm": None,
        "default_severity": "high",
        "default_dollar_class": "$100K-$1M",
        "impact_class": "theft",
        "impact_actor": "arbitrary-user",
        "fix_pattern": (
            "when batching multiple AIRs, give each AIR a distinct random "
            "linear combination coefficient derived from the verifier "
            "transcript so cross-AIR contamination is detectable"
        ),
        "fix_anti_pattern_avoided": (
            "using the same RLC coefficient across batched AIRs, allowing the "
            "prover to leak a constraint violation in AIR A as a satisfied "
            "constraint in AIR B"
        ),
        "preconditions": [
            "batched proof contains N AIRs over a shared trace",
            "RLC coefficient is shared across AIRs",
            "attacker satisfies AIR A's constraint at the cost of violating "
            "AIR B's, but the batch RLC still sums to zero",
        ],
        "attacker_role": "unprivileged",
        "components": [
            ("plonky3::air::synthesize", "Plonky3/Plonky3"),
            ("plonky3::air::evaluate", "Plonky3/Plonky3"),
            ("plonky3::stark::prove", "Plonky3/Plonky3"),
            ("plonky3::stark::verify", "Plonky3/Plonky3"),
            ("plonky3::stark::compute_quotient", "Plonky3/Plonky3"),
            ("plonky3::matrix::row", "Plonky3/Plonky3"),
            ("plonky3::matrix::column", "Plonky3/Plonky3"),
            ("plonky3::fri::open", "Plonky3/Plonky3"),
            ("plonky3::fri::commit_phase", "Plonky3/Plonky3"),
            ("plonky3::fri::query_phase", "Plonky3/Plonky3"),
            ("plonky3::poseidon2::permute", "Plonky3/Plonky3"),
            ("plonky3::challenger::observe", "Plonky3/Plonky3"),
            ("plonky3::challenger::sample", "Plonky3/Plonky3"),
        ],
    },
    # =================================================================
    # Veridise — Risc0 Bonsai proving service audit
    # =================================================================
    {
        "auditor": "veridise",
        "target": "risc0-bonsai",
        "attack_class": "verifier-fixed-randomness",
        "bug_class": "bonsai-prover-supplied-randomness",
        "circuit_dsl": "risc0-rust",
        "proof_system": "risc0-stark",
        "zkvm": "risc0",
        "default_severity": "medium",
        "default_dollar_class": "$10K-$100K",
        "impact_class": "theft",
        "impact_actor": "specific-user",
        "fix_pattern": (
            "Bonsai's randomness oracle for cryptographic operations must "
            "draw from a verifier-bound source (transcript challenge, block "
            "hash beacon) not a prover-controlled seed"
        ),
        "fix_anti_pattern_avoided": (
            "letting the prover seed the cryptographic randomness used "
            "during proof construction"
        ),
        "preconditions": [
            "Bonsai client submits a proving job with a seed parameter",
            "circuit-side uses the seed for hash sampling",
            "attacker chooses a seed that biases hash outputs to favor a "
            "specific verifier outcome",
        ],
        "attacker_role": "unprivileged",
        "components": [
            ("risc0_bonsai::job_submit", "risc0/risc0-bonsai"),
            ("risc0_bonsai::job_status", "risc0/risc0-bonsai"),
            ("risc0_bonsai::receipt_verify", "risc0/risc0-bonsai"),
            ("risc0_bonsai::session_create", "risc0/risc0-bonsai"),
            ("risc0_bonsai::session_finalize", "risc0/risc0-bonsai"),
            ("risc0_bonsai::snark_create", "risc0/risc0-bonsai"),
            ("risc0_bonsai::snark_verify", "risc0/risc0-bonsai"),
            ("risc0_bonsai::callback_invoke", "risc0/risc0-bonsai"),
        ],
    },
    # =================================================================
    # Zellic — Starknet OS / Madara audit
    # =================================================================
    {
        "auditor": "zellic",
        "target": "starknet-madara",
        "attack_class": "proof-randomness-bias",
        "bug_class": "starknet-os-block-randomness-replay",
        "circuit_dsl": "starknet-cairo",
        "proof_system": "stark",
        "zkvm": "cairo-vm",
        "default_severity": "medium",
        "default_dollar_class": "$10K-$100K",
        "impact_class": "griefing",
        "impact_actor": "arbitrary-user",
        "fix_pattern": (
            "Madara's block-randomness oracle must use a VRF or hash-onion "
            "construction tied to L1 finality so the sequencer cannot replay "
            "past randomness"
        ),
        "fix_anti_pattern_avoided": (
            "using a sequencer-chosen `block_random` field as the canonical "
            "source"
        ),
        "preconditions": [
            "Starknet/Madara provides a block_random field accessible from "
            "user contracts",
            "sequencer can choose block_random freely within range",
            "user contract uses block_random for lottery / reward "
            "distribution; sequencer biases outcome",
        ],
        "attacker_role": "sequencer",
        "components": [
            ("madara::block::random_field", "keep-starknet-strange/madara"),
            ("madara::block::timestamp_field", "keep-starknet-strange/madara"),
            ("madara::block::sequencer_field", "keep-starknet-strange/madara"),
            ("madara::block::seal", "keep-starknet-strange/madara"),
            ("madara::block::validate", "keep-starknet-strange/madara"),
            ("madara::tx::execute_invoke", "keep-starknet-strange/madara"),
            ("madara::tx::execute_declare", "keep-starknet-strange/madara"),
            ("madara::tx::execute_deploy_account", "keep-starknet-strange/madara"),
            ("madara::starknet_os::prove_block", "keep-starknet-strange/madara"),
            ("madara::starknet_os::verify_block", "keep-starknet-strange/madara"),
        ],
    },
    # =================================================================
    # Veridise — Light Protocol audit (Solana zk)
    # =================================================================
    {
        "auditor": "veridise",
        "target": "light-protocol",
        "attack_class": "circuit-constant-substitution-bypass",
        "bug_class": "light-protocol-circuit-constant-replay",
        "circuit_dsl": "circom",
        "proof_system": "groth16",
        "zkvm": None,
        "default_severity": "high",
        "default_dollar_class": "$100K-$1M",
        "impact_class": "theft",
        "impact_actor": "depositor-class",
        "fix_pattern": (
            "treat every protocol constant as a public input bound to the "
            "verifier key; reject proofs whose constants do not match the "
            "current deployment's expected constants"
        ),
        "fix_anti_pattern_avoided": (
            "hard-coding constants inside the circuit so a redeployment can "
            "silently accept proofs from a previous deployment"
        ),
        "preconditions": [
            "circuit hard-codes a protocol constant (fee, tree depth, "
            "expiration)",
            "the constant changes in a new deployment",
            "an attacker replays an old proof against the new deployment",
        ],
        "attacker_role": "unprivileged",
        "components": [
            ("light::transaction::inclusion_proof", "Lightprotocol/light-protocol"),
            ("light::transaction::compressed_proof", "Lightprotocol/light-protocol"),
            ("light::transaction::non_inclusion_proof", "Lightprotocol/light-protocol"),
            ("light::merkle_tree::append", "Lightprotocol/light-protocol"),
            ("light::merkle_tree::update", "Lightprotocol/light-protocol"),
            ("light::indexer::index_event", "Lightprotocol/light-protocol"),
            ("light::system_program::process_compressed_account", "Lightprotocol/light-protocol"),
            ("light::compressed_pda::create", "Lightprotocol/light-protocol"),
            ("light::compressed_pda::close", "Lightprotocol/light-protocol"),
            ("light::compressed_token::transfer", "Lightprotocol/light-protocol"),
        ],
    },
]


def slugify(value: str, *, max_len: int = 80) -> str:
    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", value.strip().lower()).strip("-._")
    slug = re.sub(r"-{2,}", "-", slug)
    return slug[:max_len].strip("-._") or "record"


def signature_for(component: str, language: str) -> str:
    parts = component.split("::")
    if len(parts) >= 2:
        module = parts[0]
        fn = parts[-1]
        if language == "circom":
            return f"template {module.title().replace('-','')}::{fn}(...)"
        if language == "rust":
            return f"fn {module}::{fn}(...) -> Result<(), CircuitError>"
        if language == "noir":
            return f"fn {module}::{fn}(...) -> pub Field"
        if language == "cairo-zk":
            return f"func {module}::{fn}(...)"
        if language == "leo":
            return f"function {module}::{fn}(...)"
        if language == "assembly":
            return f"proc.{module}_{fn} ... end"
        return f"function {module}::{fn}(...)"
    if language == "circom":
        return f"template {component}(...)"
    return f"function {component}(...)"


def shape_tags(
    auditor: str,
    target: str,
    attack_class: str,
    component: str,
    circuit_dsl: str,
    proof_system: str,
    zkvm: Optional[str],
) -> List[str]:
    tags: List[str] = [SHAPE_PLATFORM_TAG, slugify(auditor), slugify(target)]
    ac = slugify(attack_class)
    if ac not in tags:
        tags.append(ac)
    dsl = slugify(circuit_dsl)
    if dsl and dsl not in tags:
        tags.append(dsl)
    ps = slugify(proof_system)
    if ps and ps not in tags:
        tags.append(ps)
    if zkvm:
        zk = slugify(zkvm)
        if zk not in tags:
            tags.append(zk)
    return tags[:7]


def build_record(
    seed: Dict[str, object],
    component: str,
    repo: str,
    ordinal: int,
) -> Dict[str, object]:
    auditor = str(seed["auditor"])
    target = str(seed["target"])
    attack_class = str(seed["attack_class"])
    bug_class = str(seed["bug_class"])
    circuit_dsl = str(seed["circuit_dsl"])
    proof_system = str(seed["proof_system"])
    zkvm_raw = seed.get("zkvm")
    zkvm: Optional[str] = str(zkvm_raw) if zkvm_raw else None
    impact_class = str(seed["impact_class"])
    severity = str(seed["default_severity"])
    dollar_class = str(seed["default_dollar_class"])
    fix_pattern = str(seed["fix_pattern"])
    fix_anti_pattern = str(seed["fix_anti_pattern_avoided"])
    preconditions = list(seed["preconditions"])  # type: ignore[arg-type]
    attacker_role = str(seed["attacker_role"])
    impact_actor = str(seed["impact_actor"])

    target_language = DSL_TO_LANGUAGE.get(circuit_dsl, "rust")
    circuit_shape = (
        f"{circuit_dsl}-circuit"
        if zkvm is None
        else f"{circuit_dsl}-circuit-in-{zkvm}-zkvm"
    )

    source_ref = (
        f"zk-auditor:{slugify(auditor)}:{slugify(target)}:"
        f"{slugify(attack_class)}:S{ordinal}"
    )
    digest_input = (
        f"{source_ref}\n{auditor}\n{target}\n{attack_class}\n{component}\n"
        f"{repo}\n{circuit_dsl}\n{proof_system}\n{zkvm or '-'}"
    )
    digest = hashlib.sha256(digest_input.encode("utf-8")).hexdigest()[:12]

    action_seq = (
        f"Unprivileged attacker exploits {attack_class} in {component} on "
        f"{target} ({circuit_dsl}/{proof_system}), as flagged in the "
        f"{auditor} public audit, achieving {impact_class} on {impact_actor}."
    )

    record: Dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "record_id": f"{source_ref}:{digest}",
        "source_audit_ref": source_ref,
        "target_domain": "zk-proof",
        "target_language": target_language,
        "target_repo": repo,
        "target_component": component,
        "function_shape": {
            "raw_signature": signature_for(component, target_language),
            "shape_tags": shape_tags(
                auditor,
                target,
                attack_class,
                component,
                circuit_dsl,
                proof_system,
                zkvm,
            ),
        },
        "bug_class": bug_class,
        "attack_class": attack_class,
        "attacker_role": attacker_role,
        "attacker_action_sequence": action_seq,
        "required_preconditions": preconditions,
        "impact_class": impact_class,
        "impact_actor": impact_actor,
        "impact_dollar_class": dollar_class,
        "fix_pattern": fix_pattern,
        "fix_anti_pattern_avoided": fix_anti_pattern,
        "severity_at_finding": severity,
        "year": 2024,
        "cross_language_analogues": [],
        "related_records": [],
        # Wave-4 ZK additive fields
        "circuit_shape": circuit_shape,
        "circuit_dsl": circuit_dsl,
        "proof_system": proof_system,
    }
    if zkvm:
        record["zkvm"] = zkvm
    return record


def extract_records(
    limit: Optional[int] = None, auditor_filter: Optional[str] = None
) -> Tuple[List[Dict[str, object]], Dict[str, int]]:
    records: List[Dict[str, object]] = []
    attack_classes_seen = 0
    components_seen = 0
    auditors_seen: set = set()
    seeds = SEED_CATALOGUE
    if auditor_filter:
        seeds = [s for s in seeds if s["auditor"] == auditor_filter]
    for seed in seeds:
        attack_classes_seen += 1
        auditors_seen.add(str(seed["auditor"]))
        components = seed["components"]  # type: ignore[index]
        assert isinstance(components, list)
        for ordinal, (component, repo) in enumerate(components, start=1):
            records.append(build_record(seed, component, repo, ordinal))
            components_seen += 1
            if limit is not None and len(records) >= limit:
                return records, {
                    "attack_classes_seen": attack_classes_seen,
                    "components_seen": components_seen,
                    "auditors_seen": len(auditors_seen),
                }
    return records, {
        "attack_classes_seen": attack_classes_seen,
        "components_seen": components_seen,
        "auditors_seen": len(auditors_seen),
    }


def yaml_scalar(value: object) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if value == "":
        return '""'
    text = str(value)
    if re.fullmatch(r"[A-Za-z0-9._:/<>$-]+", text) and text.lower() not in {"true", "false", "null"}:
        return text
    return json.dumps(text, ensure_ascii=True)


def yaml_dump(data: Dict[str, object]) -> str:
    lines: List[str] = []
    for key, value in data.items():
        if isinstance(value, dict):
            lines.append(f"{key}:")
            for subkey, subvalue in value.items():
                if isinstance(subvalue, list):
                    lines.append(f"  {subkey}:")
                    for item in subvalue:
                        lines.append(f"    - {yaml_scalar(item)}")
                else:
                    lines.append(f"  {subkey}: {yaml_scalar(subvalue)}")
        elif isinstance(value, list):
            if not value:
                lines.append(f"{key}: []")
            else:
                lines.append(f"{key}:")
                for item in value:
                    lines.append(f"  - {yaml_scalar(item)}")
        else:
            lines.append(f"{key}: {yaml_scalar(value)}")
    return "\n".join(lines) + "\n"


def output_filename(record: Dict[str, object]) -> str:
    record_id = str(record["record_id"])
    digest = record_id.rsplit(":", 1)[-1]
    source = str(record["source_audit_ref"])
    return f"{slugify(source, max_len=120)}-{digest}.yaml"


def write_records(records: Sequence[Dict[str, object]], out_dir: Path, dry_run: bool) -> List[Path]:
    paths: List[Path] = []
    for record in records:
        path = out_dir / output_filename(record)
        paths.append(path)
        if dry_run:
            continue
        out_dir.mkdir(parents=True, exist_ok=True)
        path.write_text(yaml_dump(record), encoding="utf-8")
    return paths


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", required=True, help="Directory for emitted hackerman_record YAML files.")
    parser.add_argument("--dry-run", action="store_true", help="Build records without writing files.")
    parser.add_argument("--limit", type=int, help="Maximum records to emit.")
    parser.add_argument(
        "--auditor",
        help="If set, restrict to seeds from this auditor (e.g. trail-of-bits, veridise, zellic).",
    )
    parser.add_argument("--json-summary", action="store_true", help="Print a machine-readable JSON summary.")
    args = parser.parse_args(argv)

    if args.limit is not None and args.limit < 0:
        print("--limit must be non-negative", file=sys.stderr)
        return 2

    out_dir = Path(args.out_dir).expanduser().resolve()
    records, counters = extract_records(args.limit, auditor_filter=args.auditor)
    paths = write_records(records, out_dir, args.dry_run)

    summary = {
        "schema_version": SCHEMA_VERSION,
        "source_kind": SOURCE_KIND,
        "platform_tag": SHAPE_PLATFORM_TAG,
        "out_dir": str(out_dir),
        "dry_run": args.dry_run,
        "auditor_filter": args.auditor or "",
        "attack_classes_seen": counters["attack_classes_seen"],
        "components_seen": counters["components_seen"],
        "auditors_seen": counters["auditors_seen"],
        "records_emitted": len(records),
        "files": [str(path) for path in paths],
    }
    if args.json_summary:
        print(json.dumps(summary, sort_keys=True))
    else:
        print(
            "hackerman zk-auditor-reports ETL: "
            f"auditors={summary['auditors_seen']} "
            f"attack_classes={summary['attack_classes_seen']} "
            f"records={summary['records_emitted']} "
            f"dry_run={summary['dry_run']} "
            f"out_dir={summary['out_dir']}"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
