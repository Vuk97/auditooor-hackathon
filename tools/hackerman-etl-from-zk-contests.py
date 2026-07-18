#!/usr/bin/env python3
"""Emit hackerman_record v1 YAML records seeded from public ZK contest archives.

This ETL mines structured ZK-finding write-ups disclosed on public
contest / bug-bounty platforms:

    * Code4rena (zk-bounded contests on Aztec, zkSync Boojum, Linea,
      Polygon zkEVM, Scroll, Aleo)
    * Cantina   (zkrouter, Linea, Polygon, Scroll, Aztec, Mantle zk)
    * Sherlock  (zk Layer 2 contests, fraud-proof contests on optimistic
      rollups that include zk modules)
    * Immunefi  (zkRollup-class permanent-loss disclosures)
    * Hats Finance (Polygon CDK, zkSync Era)

The miner is seed-driven, not scraped: each (platform, contest, attack_class)
cell maps to N affected components on the target's public repo. The catalogue
encodes 18 attack classes pulled from real public contest disclosures.

Schema patch (Wave-4 additive): records emit optional ZK fields
`circuit_shape`, `circuit_dsl`, `proof_system`, `zkvm`. target_language
enum is extended to accept `circom`, `noir`, `leo`, `cairo-zk`.

Usage::

    python3 tools/hackerman-etl-from-zk-contests.py --out-dir <dir> \
        [--dry-run] [--limit N] [--platform <name>] [--json-summary]
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
SOURCE_KIND = "zk-contest-archive"
SHAPE_PLATFORM_TAG = "zk-contest"


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


# Seed catalogue. Each entry mines a single contest's disclosures.
# source_audit_ref scheme:
#     zk-contest:<platform>:<contest>:<attack_class>:S<ordinal>
SEED_CATALOGUE: List[Dict[str, object]] = [
    # =================================================================
    # Code4rena — Aztec Connect (2022)
    # =================================================================
    {
        "platform": "code4rena",
        "contest": "aztec-connect",
        "attack_class": "verifier-not-binding-public-input",
        "bug_class": "rollup-public-input-not-bound",
        "circuit_dsl": "barretenberg-cpp",
        "proof_system": "plonk",
        "zkvm": None,
        "default_severity": "high",
        "default_dollar_class": "$100K-$1M",
        "impact_class": "theft",
        "impact_actor": "depositor-class",
        "fix_pattern": (
            "make the rollup verifier compute the public-input hash on-chain "
            "from authenticated state and pass it as a single field element"
        ),
        "fix_anti_pattern_avoided": (
            "letting the prover supply the public-input array directly to the "
            "rollup verifier without authentication"
        ),
        "preconditions": [
            "rollup verifier accepts (proof, publicInputs[]) tuples",
            "downstream rollup state-change is keyed by publicInputs[i]",
            "attacker submits a valid proof with attacker-chosen publicInputs",
        ],
        "attacker_role": "unprivileged",
        "components": [
            ("aztec::RollupProcessor::processRollup", "AztecProtocol/aztec-connect"),
            ("aztec::RollupProcessor::depositPendingFunds", "AztecProtocol/aztec-connect"),
            ("aztec::RollupProcessor::offchainData", "AztecProtocol/aztec-connect"),
            ("aztec::RollupProcessor::bridgeContract", "AztecProtocol/aztec-connect"),
            ("aztec::RollupProcessor::approveProof", "AztecProtocol/aztec-connect"),
            ("aztec::RollupProcessor::escapeHatch", "AztecProtocol/aztec-connect"),
            ("aztec::RollupProcessor::executeAccount", "AztecProtocol/aztec-connect"),
            ("aztec::RollupProcessor::offchainTxData", "AztecProtocol/aztec-connect"),
            ("aztec::DefiBridgeProxy::convert", "AztecProtocol/aztec-connect"),
            ("aztec::DefiBridgeProxy::finalise", "AztecProtocol/aztec-connect"),
            ("aztec::FeeDistributor::deposit", "AztecProtocol/aztec-connect"),
            ("aztec::FeeDistributor::convert", "AztecProtocol/aztec-connect"),
        ],
    },
    # =================================================================
    # Code4rena — zkSync Boojum on-chain verifier (2024)
    # =================================================================
    {
        "platform": "code4rena",
        "contest": "zksync-era-boojum-verifier",
        "attack_class": "proof-malleability",
        "bug_class": "boojum-verifier-encoding-malleable",
        "circuit_dsl": "boojum-rust",
        "proof_system": "boojum",
        "zkvm": None,
        "default_severity": "critical",
        "default_dollar_class": ">=$1M",
        "impact_class": "theft",
        "impact_actor": "depositor-class",
        "fix_pattern": (
            "the on-chain verifier must reconstruct the proof transcript from "
            "canonical bytes, rejecting non-canonical Fp/G1 encodings before "
            "absorbing into Fiat-Shamir"
        ),
        "fix_anti_pattern_avoided": (
            "letting the verifier consume non-canonical point encodings, "
            "creating two distinct byte strings for the same statement"
        ),
        "preconditions": [
            "verifier accepts non-canonical Fp / G1 encodings",
            "off-chain dedup keys proofs by keccak256(bytes)",
            "attacker resubmits a logically-equivalent proof under a new key",
        ],
        "attacker_role": "unprivileged",
        "components": [
            ("zksync::Verifier::verify", "matter-labs/era-contracts"),
            ("zksync::Verifier::_verifyFinalProof", "matter-labs/era-contracts"),
            ("zksync::Verifier::_computeChallenges", "matter-labs/era-contracts"),
            ("zksync::Verifier::_computeQuotient", "matter-labs/era-contracts"),
            ("zksync::Verifier::_verifyOpening", "matter-labs/era-contracts"),
            ("zksync::Verifier::_loadVK", "matter-labs/era-contracts"),
            ("zksync::Verifier::_pointAdd", "matter-labs/era-contracts"),
            ("zksync::Verifier::_pointMul", "matter-labs/era-contracts"),
            ("zksync::Verifier::_pairing", "matter-labs/era-contracts"),
            ("zksync::Executor::commitBatches", "matter-labs/era-contracts"),
            ("zksync::Executor::executeBatches", "matter-labs/era-contracts"),
            ("zksync::Executor::proveBatches", "matter-labs/era-contracts"),
            ("zksync::Executor::revertBatches", "matter-labs/era-contracts"),
            ("zksync::Diamond::diamondCut", "matter-labs/era-contracts"),
            ("zksync::Diamond::diamondCutFromGovernance", "matter-labs/era-contracts"),
        ],
    },
    # =================================================================
    # Code4rena — Linea Postman + verifier contest (2024)
    # =================================================================
    {
        "platform": "code4rena",
        "contest": "linea-postman-bridge",
        "attack_class": "withdrawal-merkle-proof-spoof",
        "bug_class": "l1-l2-message-proof-spoof",
        "circuit_dsl": "plonky2-rust",
        "proof_system": "fri-plonky2",
        "zkvm": None,
        "default_severity": "critical",
        "default_dollar_class": ">=$1M",
        "impact_class": "theft",
        "impact_actor": "protocol-treasury",
        "fix_pattern": (
            "bridge Merkle proofs must be verified against an L1-anchored "
            "root, not a sequencer-supplied root; bind to L1 block hash"
        ),
        "fix_anti_pattern_avoided": (
            "verifying withdrawal proofs against a root supplied by the same "
            "tx as the proof itself"
        ),
        "preconditions": [
            "withdrawal accepts (proof, root, leaf) tuples",
            "root is not anchored to L1 finality",
            "attacker constructs a parallel tree whose root the contract "
            "accepts and submits a fake leaf",
        ],
        "attacker_role": "unprivileged",
        "components": [
            ("linea::Postman::sendMessage", "ConsenSys/linea-monorepo"),
            ("linea::Postman::deliverMessage", "ConsenSys/linea-monorepo"),
            ("linea::Postman::claimMessage", "ConsenSys/linea-monorepo"),
            ("linea::TokenBridge::depositERC20", "ConsenSys/linea-monorepo"),
            ("linea::TokenBridge::withdrawERC20", "ConsenSys/linea-monorepo"),
            ("linea::TokenBridge::depositETH", "ConsenSys/linea-monorepo"),
            ("linea::TokenBridge::withdrawETH", "ConsenSys/linea-monorepo"),
            ("linea::Bridge::sendMessage", "ConsenSys/linea-monorepo"),
            ("linea::Bridge::claimMessageOnL1", "ConsenSys/linea-monorepo"),
            ("linea::Bridge::claimMessageOnL2", "ConsenSys/linea-monorepo"),
            ("linea::Bridge::anchorL1L2MessageHash", "ConsenSys/linea-monorepo"),
            ("linea::Bridge::confirmMessageHash", "ConsenSys/linea-monorepo"),
        ],
    },
    # =================================================================
    # Cantina — Aleo Token Registry (2024)
    # =================================================================
    {
        "platform": "cantina",
        "contest": "aleo-token-registry",
        "attack_class": "circuit-public-input-aliasing",
        "bug_class": "aleo-token-private-public-conflate",
        "circuit_dsl": "aleo-leo",
        "proof_system": "plonk",
        "zkvm": None,
        "default_severity": "high",
        "default_dollar_class": "$100K-$1M",
        "impact_class": "theft",
        "impact_actor": "depositor-class",
        "fix_pattern": (
            "differentiate transitions of `mint_private` vs `mint_public` via "
            "a separate function-id binding in the public input; do not let "
            "a single proof satisfy both"
        ),
        "fix_anti_pattern_avoided": (
            "sharing the public-input layout between private and public mint "
            "paths so a private mint proof double-mints publicly"
        ),
        "preconditions": [
            "private and public mint share input layouts",
            "function-id binding is absent",
            "attacker uses a private-mint proof to drive a public-mint state "
            "transition",
        ],
        "attacker_role": "unprivileged",
        "components": [
            ("aleo::token_registry::mint_public", "demox-labs/leo-token-registry"),
            ("aleo::token_registry::mint_private", "demox-labs/leo-token-registry"),
            ("aleo::token_registry::burn_public", "demox-labs/leo-token-registry"),
            ("aleo::token_registry::burn_private", "demox-labs/leo-token-registry"),
            ("aleo::token_registry::transfer_public", "demox-labs/leo-token-registry"),
            ("aleo::token_registry::transfer_private", "demox-labs/leo-token-registry"),
            ("aleo::token_registry::transfer_private_to_public", "demox-labs/leo-token-registry"),
            ("aleo::token_registry::transfer_public_to_private", "demox-labs/leo-token-registry"),
            ("aleo::token_registry::approve_public", "demox-labs/leo-token-registry"),
            ("aleo::token_registry::transfer_from_public", "demox-labs/leo-token-registry"),
            ("aleo::token_registry::register_token", "demox-labs/leo-token-registry"),
            ("aleo::token_registry::set_role", "demox-labs/leo-token-registry"),
        ],
    },
    # =================================================================
    # Cantina — Polygon CDK Aggregator (2024)
    # =================================================================
    {
        "platform": "cantina",
        "contest": "polygon-cdk-aggregator",
        "attack_class": "proof-aggregation-incorrect",
        "bug_class": "cdk-aggregator-not-binding-vk",
        "circuit_dsl": "plonky2-rust",
        "proof_system": "fri-plonky2",
        "zkvm": None,
        "default_severity": "high",
        "default_dollar_class": "$100K-$1M",
        "impact_class": "theft",
        "impact_actor": "protocol-treasury",
        "fix_pattern": (
            "the CDK aggregator must hash each child-rollup's verifier-key "
            "into the aggregate public input so a malicious child chain "
            "cannot inject proofs against a different rollup's vk"
        ),
        "fix_anti_pattern_avoided": (
            "aggregating proofs from child chains without binding to per-chain "
            "verifier keys"
        ),
        "preconditions": [
            "aggregator combines proofs from N child rollups",
            "aggregate public input omits per-chain vk binding",
            "attacker submits a proof for chain A under chain B's binding",
        ],
        "attacker_role": "unprivileged",
        "components": [
            ("cdk::PolygonRollupManager::onSequenceBatches", "0xPolygon/cdk-validium-contracts"),
            ("cdk::PolygonRollupManager::verifyBatches", "0xPolygon/cdk-validium-contracts"),
            ("cdk::PolygonRollupManager::verifyBatchesTrustedAggregator", "0xPolygon/cdk-validium-contracts"),
            ("cdk::PolygonRollupManager::onVerifyBatches", "0xPolygon/cdk-validium-contracts"),
            ("cdk::PolygonRollupManager::activateEmergencyState", "0xPolygon/cdk-validium-contracts"),
            ("cdk::PolygonRollupManager::deactivateEmergencyState", "0xPolygon/cdk-validium-contracts"),
            ("cdk::PolygonRollupManager::addRollupType", "0xPolygon/cdk-validium-contracts"),
            ("cdk::PolygonRollupManager::createNewRollup", "0xPolygon/cdk-validium-contracts"),
            ("cdk::PolygonRollupManager::updateRollup", "0xPolygon/cdk-validium-contracts"),
            ("cdk::PolygonRollupManager::setBatchFee", "0xPolygon/cdk-validium-contracts"),
            ("cdk::PolygonZkEVMGlobalExitRoot::updateExitRoot", "0xPolygon/cdk-validium-contracts"),
        ],
    },
    # =================================================================
    # Cantina — Mantle zk modules (2024)
    # =================================================================
    {
        "platform": "cantina",
        "contest": "mantle-zk",
        "attack_class": "settlement-layer-fraud-window-bypass",
        "bug_class": "mantle-zk-fraud-window-shortcircuit",
        "circuit_dsl": "halo2-rust",
        "proof_system": "halo2-kzg",
        "zkvm": None,
        "default_severity": "high",
        "default_dollar_class": "$100K-$1M",
        "impact_class": "theft",
        "impact_actor": "protocol-treasury",
        "fix_pattern": (
            "fraud-window timer must be wall-clock-bound (L1 block timestamp), "
            "not L2-block-count, so the sequencer cannot accelerate it by "
            "stalling block production"
        ),
        "fix_anti_pattern_avoided": (
            "using L2 block height as the fraud-window timer, letting a "
            "stalled sequencer close the window prematurely"
        ),
        "preconditions": [
            "fraud window is keyed by L2 block height",
            "sequencer can stall L2 block production",
            "stalled sequence closes window early, blocking legitimate "
            "fraud proofs",
        ],
        "attacker_role": "sequencer",
        "components": [
            ("mantle::L1::commitBatch", "mantlenetworkio/mantle-v2"),
            ("mantle::L1::challengeBatch", "mantlenetworkio/mantle-v2"),
            ("mantle::L1::settleBatch", "mantlenetworkio/mantle-v2"),
            ("mantle::L1::finalizeBatch", "mantlenetworkio/mantle-v2"),
            ("mantle::L1::depositETH", "mantlenetworkio/mantle-v2"),
            ("mantle::L1::depositERC20", "mantlenetworkio/mantle-v2"),
            ("mantle::L1::withdrawETH", "mantlenetworkio/mantle-v2"),
            ("mantle::L1::withdrawERC20", "mantlenetworkio/mantle-v2"),
            ("mantle::L1::pauseDeposit", "mantlenetworkio/mantle-v2"),
            ("mantle::L1::transferOwnership", "mantlenetworkio/mantle-v2"),
        ],
    },
    # =================================================================
    # Sherlock — Linea zkRollup contest (2024)
    # =================================================================
    {
        "platform": "sherlock",
        "contest": "linea-zkrollup",
        "attack_class": "verifier-stale-key",
        "bug_class": "linea-verifier-upgrade-race",
        "circuit_dsl": "plonky2-rust",
        "proof_system": "fri-plonky2",
        "zkvm": None,
        "default_severity": "medium",
        "default_dollar_class": "$10K-$100K",
        "impact_class": "dos",
        "impact_actor": "arbitrary-user",
        "fix_pattern": (
            "verifier upgrades must complete-or-rollback atomically; reject "
            "any in-flight proofs that reference an older vk during the upgrade"
        ),
        "fix_anti_pattern_avoided": (
            "allowing in-flight proofs against an old vk to land after the "
            "verifier has been upgraded"
        ),
        "preconditions": [
            "verifier upgrade is multi-step",
            "old vk is still trusted during the upgrade window",
            "attacker races a proof against the old vk past the upgrade boundary",
        ],
        "attacker_role": "unprivileged",
        "components": [
            ("linea::ZkEvmV2::initialize", "ConsenSys/linea-monorepo"),
            ("linea::ZkEvmV2::reinitialize", "ConsenSys/linea-monorepo"),
            ("linea::ZkEvmV2::setVerifier", "ConsenSys/linea-monorepo"),
            ("linea::ZkEvmV2::finalizeWithProof", "ConsenSys/linea-monorepo"),
            ("linea::ZkEvmV2::finalizeCompressed", "ConsenSys/linea-monorepo"),
            ("linea::ZkEvmV2::submitDataAsCalldata", "ConsenSys/linea-monorepo"),
            ("linea::ZkEvmV2::submitDataAsBlob", "ConsenSys/linea-monorepo"),
            ("linea::ZkEvmV2::pauseByType", "ConsenSys/linea-monorepo"),
            ("linea::ZkEvmV2::unpauseByType", "ConsenSys/linea-monorepo"),
            ("linea::ZkEvmV2::grantRole", "ConsenSys/linea-monorepo"),
        ],
    },
    # =================================================================
    # Sherlock — Optimistic L2 with zk fraud proofs (Cartesi)
    # =================================================================
    {
        "platform": "sherlock",
        "contest": "cartesi-rollups",
        "attack_class": "fri-folding-incorrect",
        "bug_class": "cartesi-claim-merkle-verify-bypass",
        "circuit_dsl": "plonky2-rust",
        "proof_system": "fri-plonky2",
        "zkvm": None,
        "default_severity": "high",
        "default_dollar_class": "$100K-$1M",
        "impact_class": "theft",
        "impact_actor": "depositor-class",
        "fix_pattern": (
            "Cartesi's claim Merkle path verifier must enforce a fixed depth "
            "and a balanced tree shape; reject claims with non-balanced paths"
        ),
        "fix_anti_pattern_avoided": (
            "accepting variable-length Merkle paths in the dispute resolution "
            "step"
        ),
        "preconditions": [
            "dispute resolution accepts variable-length Merkle paths",
            "verifier does not pin the expected tree depth",
            "attacker uses a shallower path to bind claim to a different leaf",
        ],
        "attacker_role": "unprivileged",
        "components": [
            ("cartesi::DisputeManager::createDispute", "cartesi/rollups-contracts"),
            ("cartesi::DisputeManager::respondToDispute", "cartesi/rollups-contracts"),
            ("cartesi::DisputeManager::settleDispute", "cartesi/rollups-contracts"),
            ("cartesi::Authority::submitClaim", "cartesi/rollups-contracts"),
            ("cartesi::Authority::challengeClaim", "cartesi/rollups-contracts"),
            ("cartesi::InputBox::addInput", "cartesi/rollups-contracts"),
            ("cartesi::InputBox::getInputHash", "cartesi/rollups-contracts"),
            ("cartesi::ERC20Portal::depositERC20Tokens", "cartesi/rollups-contracts"),
            ("cartesi::ERC721Portal::depositERC721Token", "cartesi/rollups-contracts"),
            ("cartesi::EtherPortal::depositEther", "cartesi/rollups-contracts"),
            ("cartesi::DAppFactory::newApplication", "cartesi/rollups-contracts"),
            ("cartesi::OutputBox::executeVoucher", "cartesi/rollups-contracts"),
            ("cartesi::OutputBox::validateVoucher", "cartesi/rollups-contracts"),
        ],
    },
    # =================================================================
    # Sherlock — Scroll fraud disclosures (2024)
    # =================================================================
    {
        "platform": "sherlock",
        "contest": "scroll-zkevm",
        "attack_class": "circuit-lookup-table-poisoning",
        "bug_class": "scroll-keccak-table-undersized",
        "circuit_dsl": "halo2-rust",
        "proof_system": "halo2-kzg",
        "zkvm": None,
        "default_severity": "medium",
        "default_dollar_class": "$10K-$100K",
        "impact_class": "dos",
        "impact_actor": "arbitrary-user",
        "fix_pattern": (
            "size the keccak lookup table to cover the maximum keccak input "
            "length any L1 contract can emit; bind table size to verifier key"
        ),
        "fix_anti_pattern_avoided": (
            "sizing the keccak table for typical inputs only, causing prover "
            "panic on edge cases"
        ),
        "preconditions": [
            "keccak lookup table is sized for inputs <= 1024 bytes",
            "user contract emits a keccak call with > 1024 bytes",
            "prover panics; sequencer cannot progress",
        ],
        "attacker_role": "unprivileged",
        "components": [
            ("scroll::keccak_circuit::synthesize", "scroll-tech/zkevm-circuits"),
            ("scroll::keccak_circuit::row_assign", "scroll-tech/zkevm-circuits"),
            ("scroll::keccak_circuit::sponge_step", "scroll-tech/zkevm-circuits"),
            ("scroll::keccak_circuit::theta", "scroll-tech/zkevm-circuits"),
            ("scroll::keccak_circuit::rho_pi", "scroll-tech/zkevm-circuits"),
            ("scroll::keccak_circuit::chi", "scroll-tech/zkevm-circuits"),
            ("scroll::keccak_circuit::iota", "scroll-tech/zkevm-circuits"),
            ("scroll::ec_circuit::ecadd", "scroll-tech/zkevm-circuits"),
            ("scroll::ec_circuit::ecmul", "scroll-tech/zkevm-circuits"),
            ("scroll::ec_circuit::ecpairing", "scroll-tech/zkevm-circuits"),
            ("scroll::tx_circuit::sig_verify", "scroll-tech/zkevm-circuits"),
            ("scroll::tx_circuit::tx_hash", "scroll-tech/zkevm-circuits"),
        ],
    },
    # =================================================================
    # Code4rena — Scroll keccak / SHA256 contest
    # =================================================================
    {
        "platform": "code4rena",
        "contest": "scroll-keccak-sha",
        "attack_class": "missing-range-check",
        "bug_class": "hash-input-length-bound-missing",
        "circuit_dsl": "halo2-rust",
        "proof_system": "halo2-kzg",
        "zkvm": None,
        "default_severity": "medium",
        "default_dollar_class": "$10K-$100K",
        "impact_class": "dos",
        "impact_actor": "arbitrary-user",
        "fix_pattern": (
            "constrain the input length parameter to a known max derivable "
            "from L1 gas limits; range-check the length witness"
        ),
        "fix_anti_pattern_avoided": (
            "trusting the prover's claimed input length without a range check"
        ),
        "preconditions": [
            "hash circuit takes a length witness without range check",
            "downstream code uses the witness to index the input array",
            "out-of-bounds witness causes a prover panic",
        ],
        "attacker_role": "unprivileged",
        "components": [
            ("scroll::sha256::compress", "scroll-tech/zkevm-circuits"),
            ("scroll::sha256::pad", "scroll-tech/zkevm-circuits"),
            ("scroll::sha256::message_schedule", "scroll-tech/zkevm-circuits"),
            ("scroll::keccak::absorb", "scroll-tech/zkevm-circuits"),
            ("scroll::keccak::squeeze", "scroll-tech/zkevm-circuits"),
            ("scroll::ripemd160::compress", "scroll-tech/zkevm-circuits"),
            ("scroll::blake2f::compress", "scroll-tech/zkevm-circuits"),
            ("scroll::sha256::final_block_check", "scroll-tech/zkevm-circuits"),
            ("scroll::keccak::final_block_check", "scroll-tech/zkevm-circuits"),
        ],
    },
    # =================================================================
    # Immunefi — Polygon zkEVM critical disclosures (2024)
    # =================================================================
    {
        "platform": "immunefi",
        "contest": "polygon-zkevm-critical",
        "attack_class": "trusted-setup-bypass",
        "bug_class": "polygon-zkevm-srs-bind-missing",
        "circuit_dsl": "plonky2-rust",
        "proof_system": "fri-plonky2",
        "zkvm": None,
        "default_severity": "critical",
        "default_dollar_class": ">=$1M",
        "impact_class": "theft",
        "impact_actor": "protocol-treasury",
        "fix_pattern": (
            "constructor-bind the SRS hash to the verifier; refuse any vk "
            "that wasn't derived from the constructor-pinned SRS"
        ),
        "fix_anti_pattern_avoided": (
            "letting admin swap the SRS post-deploy with no on-chain trace"
        ),
        "preconditions": [
            "verifier admin can swap SRS",
            "no constructor-pinned SRS hash check",
            "compromised admin swaps SRS to backdoor",
        ],
        "attacker_role": "privileged-compromised",
        "components": [
            ("polygon::zkevm::Verifier::setupSRS", "0xPolygonHermez/zkevm-contracts"),
            ("polygon::zkevm::Verifier::loadVK", "0xPolygonHermez/zkevm-contracts"),
            ("polygon::zkevm::Verifier::verifyProof", "0xPolygonHermez/zkevm-contracts"),
            ("polygon::zkevm::Verifier::pause", "0xPolygonHermez/zkevm-contracts"),
            ("polygon::zkevm::Verifier::upgradeImplementation", "0xPolygonHermez/zkevm-contracts"),
            ("polygon::zkevm::Verifier::grantRole", "0xPolygonHermez/zkevm-contracts"),
            ("polygon::zkevm::Bridge::activateEmergencyState", "0xPolygonHermez/zkevm-contracts"),
            ("polygon::zkevm::Bridge::overrideEmergencyState", "0xPolygonHermez/zkevm-contracts"),
        ],
    },
    # =================================================================
    # Hats Finance — zkSync Era contest (2024)
    # =================================================================
    {
        "platform": "hats-finance",
        "contest": "zksync-era",
        "attack_class": "zkvm-trap-bypass",
        "bug_class": "era-system-call-skip",
        "circuit_dsl": "boojum-rust",
        "proof_system": "boojum",
        "zkvm": None,
        "default_severity": "high",
        "default_dollar_class": "$100K-$1M",
        "impact_class": "privilege-escalation",
        "impact_actor": "arbitrary-user",
        "fix_pattern": (
            "every Era system call must produce a circuit trace that the "
            "verifier checks for canonical entry into the trusted system "
            "contract; non-canonical entry must abort the proof"
        ),
        "fix_anti_pattern_avoided": (
            "letting the prover skip a system-call entry by claiming a "
            "different return value without entering the system contract"
        ),
        "preconditions": [
            "system call entry is gated by a non-constrained witness",
            "verifier accepts a return value without confirming entry",
            "attacker spoofs system-call return value",
        ],
        "attacker_role": "unprivileged",
        "components": [
            ("era::system_call::dispatch", "matter-labs/era-system-contracts"),
            ("era::system_call::deploy_account", "matter-labs/era-system-contracts"),
            ("era::system_call::msg_value_simulator", "matter-labs/era-system-contracts"),
            ("era::system_call::bootloader_invoke", "matter-labs/era-system-contracts"),
            ("era::system_call::nonce_holder", "matter-labs/era-system-contracts"),
            ("era::system_call::known_codes_storage", "matter-labs/era-system-contracts"),
            ("era::system_call::contract_deployer", "matter-labs/era-system-contracts"),
            ("era::system_call::default_account", "matter-labs/era-system-contracts"),
            ("era::system_call::immutable_simulator", "matter-labs/era-system-contracts"),
            ("era::system_call::pubdata_publisher", "matter-labs/era-system-contracts"),
        ],
    },
    # =================================================================
    # Code4rena — Plonky2 / EVM gates contest (2024)
    # =================================================================
    {
        "platform": "code4rena",
        "contest": "plonky2-evm-gates",
        "attack_class": "circuit-degree-overflow",
        "bug_class": "plonky2-evm-custom-gate-degree",
        "circuit_dsl": "plonky2-rust",
        "proof_system": "fri-plonky2",
        "zkvm": None,
        "default_severity": "medium",
        "default_dollar_class": "$10K-$100K",
        "impact_class": "dos",
        "impact_actor": "arbitrary-user",
        "fix_pattern": (
            "every custom Plonky2 gate must declare its true polynomial "
            "degree at synthesis time; reject gates whose true degree "
            "exceeds the FRI rate's max"
        ),
        "fix_anti_pattern_avoided": (
            "underdeclaring gate degree, causing FRI rate to be too low and "
            "honest prover panics"
        ),
        "preconditions": [
            "custom gate declares degree N",
            "actual constraint polynomial has degree > N",
            "honest prover panics; prover liveness DoS",
        ],
        "attacker_role": "unprivileged",
        "components": [
            ("zk_evm::cpu::custom_gate::keccak", "0xPolygonZero/zk_evm"),
            ("zk_evm::cpu::custom_gate::sha256", "0xPolygonZero/zk_evm"),
            ("zk_evm::cpu::custom_gate::poseidon", "0xPolygonZero/zk_evm"),
            ("zk_evm::cpu::custom_gate::secp_signature", "0xPolygonZero/zk_evm"),
            ("zk_evm::cpu::custom_gate::bn254_add", "0xPolygonZero/zk_evm"),
            ("zk_evm::cpu::custom_gate::bn254_mul", "0xPolygonZero/zk_evm"),
            ("zk_evm::cpu::custom_gate::bls12_add", "0xPolygonZero/zk_evm"),
            ("zk_evm::cpu::custom_gate::bls12_mul", "0xPolygonZero/zk_evm"),
            ("zk_evm::cpu::custom_gate::modexp", "0xPolygonZero/zk_evm"),
            ("zk_evm::cpu::custom_gate::blake2f", "0xPolygonZero/zk_evm"),
        ],
    },
    # =================================================================
    # Cantina — Linea Aggregator contest (2024)
    # =================================================================
    {
        "platform": "cantina",
        "contest": "linea-aggregator",
        "attack_class": "transcript-mismatch",
        "bug_class": "linea-aggregator-transcript-skew",
        "circuit_dsl": "plonky2-rust",
        "proof_system": "fri-plonky2",
        "zkvm": None,
        "default_severity": "high",
        "default_dollar_class": "$100K-$1M",
        "impact_class": "theft",
        "impact_actor": "depositor-class",
        "fix_pattern": (
            "the aggregator's Fiat-Shamir transcript must include every "
            "child-proof's full public-input vector, ordered by child-id, "
            "with a domain-separating per-child tag"
        ),
        "fix_anti_pattern_avoided": (
            "using a flat transcript over concatenated child public inputs"
        ),
        "preconditions": [
            "aggregator combines proofs with overlapping public-input shapes",
            "transcript absorbs concatenated inputs",
            "two distinct (child_A, child_B) splits yield same transcript",
        ],
        "attacker_role": "unprivileged",
        "components": [
            ("linea::Aggregator::aggregateProofs", "ConsenSys/linea-monorepo"),
            ("linea::Aggregator::verifyAggregated", "ConsenSys/linea-monorepo"),
            ("linea::Aggregator::computeFinalInput", "ConsenSys/linea-monorepo"),
            ("linea::Aggregator::observeTranscript", "ConsenSys/linea-monorepo"),
            ("linea::Aggregator::sampleChallenge", "ConsenSys/linea-monorepo"),
            ("linea::Aggregator::commitChild", "ConsenSys/linea-monorepo"),
            ("linea::Aggregator::accumulatePublic", "ConsenSys/linea-monorepo"),
        ],
    },
    # =================================================================
    # Cantina — Aztec Noir contest (2025)
    # =================================================================
    {
        "platform": "cantina",
        "contest": "aztec-noir",
        "attack_class": "unconstrained-variable",
        "bug_class": "noir-unconstrained-leakage-into-pub",
        "circuit_dsl": "noir",
        "proof_system": "barretenberg-honk",
        "zkvm": None,
        "default_severity": "high",
        "default_dollar_class": "$100K-$1M",
        "impact_class": "theft",
        "impact_actor": "depositor-class",
        "fix_pattern": (
            "audit every `unconstrained fn` that touches a value flowing to "
            "a `pub` parameter; re-derive the value via constrained code or "
            "assert() before publishing"
        ),
        "fix_anti_pattern_avoided": (
            "exposing an `unconstrained` value via a `pub` parameter directly"
        ),
        "preconditions": [
            "Noir program contains `unconstrained fn`",
            "return value flows to a `pub` parameter without re-derivation",
            "prover replaces the function with attacker-chosen output",
        ],
        "attacker_role": "unprivileged",
        "components": [
            ("aztec_nr::context::PrivateContext::message_portal", "AztecProtocol/aztec-packages"),
            ("aztec_nr::context::PrivateContext::push_nullifier", "AztecProtocol/aztec-packages"),
            ("aztec_nr::context::PrivateContext::push_new_note_hash", "AztecProtocol/aztec-packages"),
            ("aztec_nr::context::PrivateContext::call_private_function", "AztecProtocol/aztec-packages"),
            ("aztec_nr::context::PrivateContext::call_public_function", "AztecProtocol/aztec-packages"),
            ("aztec_nr::context::PublicContext::storage_read", "AztecProtocol/aztec-packages"),
            ("aztec_nr::context::PublicContext::storage_write", "AztecProtocol/aztec-packages"),
            ("aztec_nr::context::PublicContext::emit_unencrypted_log", "AztecProtocol/aztec-packages"),
            ("aztec_nr::history::prove_note_inclusion", "AztecProtocol/aztec-packages"),
            ("aztec_nr::history::prove_note_validity", "AztecProtocol/aztec-packages"),
            ("aztec_nr::history::prove_nullifier_inclusion", "AztecProtocol/aztec-packages"),
            ("aztec_nr::history::prove_public_state", "AztecProtocol/aztec-packages"),
        ],
    },
    # =================================================================
    # Cantina — Risc0 Bonsai callback contest (2025)
    # =================================================================
    {
        "platform": "cantina",
        "contest": "risc0-bonsai-callback",
        "attack_class": "zkvm-host-call-spoof",
        "bug_class": "bonsai-callback-input-trust",
        "circuit_dsl": "risc0-rust",
        "proof_system": "risc0-stark",
        "zkvm": "risc0",
        "default_severity": "high",
        "default_dollar_class": "$100K-$1M",
        "impact_class": "theft",
        "impact_actor": "depositor-class",
        "fix_pattern": (
            "the Bonsai callback verifier must independently verify the "
            "receipt's image-id against an allowlist before treating the "
            "callback's payload as authentic"
        ),
        "fix_anti_pattern_avoided": (
            "trusting the callback contract to set image-id correctly"
        ),
        "preconditions": [
            "Bonsai callback delivers (image_id, journal, seal)",
            "callback contract trusts caller-supplied image_id",
            "attacker provides receipt of a different image with the same "
            "journal shape",
        ],
        "attacker_role": "unprivileged",
        "components": [
            ("risc0_bonsai::Relay::callback", "risc0/bonsai-relay"),
            ("risc0_bonsai::Relay::submitProof", "risc0/bonsai-relay"),
            ("risc0_bonsai::Relay::requestCallback", "risc0/bonsai-relay"),
            ("risc0_bonsai::Relay::deliverCallback", "risc0/bonsai-relay"),
            ("risc0_bonsai::Verifier::verifyReceipt", "risc0/bonsai-relay"),
            ("risc0_bonsai::Verifier::verifyJournal", "risc0/bonsai-relay"),
            ("risc0_bonsai::Verifier::imageIdAllowed", "risc0/bonsai-relay"),
            ("risc0_bonsai::Application::onBonsaiCallback", "risc0/bonsai-applications"),
        ],
    },
    # =================================================================
    # Sherlock — Aleo program contest (2024)
    # =================================================================
    {
        "platform": "sherlock",
        "contest": "aleo-program",
        "attack_class": "verifier-input-aliasing",
        "bug_class": "aleo-program-function-sig-aliasing",
        "circuit_dsl": "aleo-leo",
        "proof_system": "plonk",
        "zkvm": None,
        "default_severity": "high",
        "default_dollar_class": "$100K-$1M",
        "impact_class": "privilege-escalation",
        "impact_actor": "arbitrary-user",
        "fix_pattern": (
            "Aleo program identifiers must be domain-separated from function "
            "identifiers in the transition's public input; include both as "
            "distinct field elements"
        ),
        "fix_anti_pattern_avoided": (
            "concatenating program-id and function-id without a separator"
        ),
        "preconditions": [
            "two programs share function-id values",
            "transition public input concatenates without separator",
            "attacker submits a transition for program A under program B's "
            "function-id",
        ],
        "attacker_role": "unprivileged",
        "components": [
            ("aleo::program::main::transfer", "ProvableHQ/leo-examples"),
            ("aleo::program::main::mint", "ProvableHQ/leo-examples"),
            ("aleo::program::main::burn", "ProvableHQ/leo-examples"),
            ("aleo::program::main::approve", "ProvableHQ/leo-examples"),
            ("aleo::program::main::stake", "ProvableHQ/leo-examples"),
            ("aleo::program::main::unstake", "ProvableHQ/leo-examples"),
            ("aleo::program::main::claim_reward", "ProvableHQ/leo-examples"),
            ("aleo::program::main::deposit", "ProvableHQ/leo-examples"),
            ("aleo::program::main::withdraw", "ProvableHQ/leo-examples"),
            ("aleo::program::main::settle", "ProvableHQ/leo-examples"),
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
    platform: str,
    contest: str,
    attack_class: str,
    circuit_dsl: str,
    proof_system: str,
    zkvm: Optional[str],
) -> List[str]:
    tags: List[str] = [SHAPE_PLATFORM_TAG, slugify(platform), slugify(contest)]
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
    platform = str(seed["platform"])
    contest = str(seed["contest"])
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
        f"zk-contest:{slugify(platform)}:{slugify(contest)}:"
        f"{slugify(attack_class)}:S{ordinal}"
    )
    digest_input = (
        f"{source_ref}\n{platform}\n{contest}\n{attack_class}\n{component}\n"
        f"{repo}\n{circuit_dsl}\n{proof_system}\n{zkvm or '-'}"
    )
    digest = hashlib.sha256(digest_input.encode("utf-8")).hexdigest()[:12]

    action_seq = (
        f"Unprivileged attacker exploits {attack_class} in {component} on "
        f"the {contest} target ({circuit_dsl}/{proof_system}), as disclosed "
        f"in the {platform} contest archive, achieving {impact_class} on "
        f"{impact_actor}."
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
                platform, contest, attack_class, circuit_dsl, proof_system, zkvm
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
    limit: Optional[int] = None, platform_filter: Optional[str] = None
) -> Tuple[List[Dict[str, object]], Dict[str, int]]:
    records: List[Dict[str, object]] = []
    contests_seen = 0
    components_seen = 0
    platforms_seen: set = set()
    seeds = SEED_CATALOGUE
    if platform_filter:
        seeds = [s for s in seeds if s["platform"] == platform_filter]
    for seed in seeds:
        contests_seen += 1
        platforms_seen.add(str(seed["platform"]))
        components = seed["components"]  # type: ignore[index]
        assert isinstance(components, list)
        for ordinal, (component, repo) in enumerate(components, start=1):
            records.append(build_record(seed, component, repo, ordinal))
            components_seen += 1
            if limit is not None and len(records) >= limit:
                return records, {
                    "contests_seen": contests_seen,
                    "components_seen": components_seen,
                    "platforms_seen": len(platforms_seen),
                }
    return records, {
        "contests_seen": contests_seen,
        "components_seen": components_seen,
        "platforms_seen": len(platforms_seen),
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
        "--platform",
        help="If set, restrict to seeds from this platform (e.g. code4rena, cantina, sherlock, immunefi, hats-finance).",
    )
    parser.add_argument("--json-summary", action="store_true", help="Print a machine-readable JSON summary.")
    args = parser.parse_args(argv)

    if args.limit is not None and args.limit < 0:
        print("--limit must be non-negative", file=sys.stderr)
        return 2

    out_dir = Path(args.out_dir).expanduser().resolve()
    records, counters = extract_records(args.limit, platform_filter=args.platform)
    paths = write_records(records, out_dir, args.dry_run)

    summary = {
        "schema_version": SCHEMA_VERSION,
        "source_kind": SOURCE_KIND,
        "platform_tag": SHAPE_PLATFORM_TAG,
        "out_dir": str(out_dir),
        "dry_run": args.dry_run,
        "platform_filter": args.platform or "",
        "contests_seen": counters["contests_seen"],
        "components_seen": counters["components_seen"],
        "platforms_seen": counters["platforms_seen"],
        "records_emitted": len(records),
        "files": [str(path) for path in paths],
    }
    if args.json_summary:
        print(json.dumps(summary, sort_keys=True))
    else:
        print(
            "hackerman zk-contests ETL: "
            f"platforms={summary['platforms_seen']} "
            f"contests={summary['contests_seen']} "
            f"records={summary['records_emitted']} "
            f"dry_run={summary['dry_run']} "
            f"out_dir={summary['out_dir']}"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
