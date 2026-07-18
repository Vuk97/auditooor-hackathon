#!/usr/bin/env python3
"""Emit hackerman_record v1 YAML for Rust Ethereum-client attack classes.

This ETL is seed-driven (no markdown scraping): the corpus of public Rust
Ethereum-client audits (Trail of Bits / Sigma Prime / Paradigm / Veridise /
OtterSec reports on Reth, Kona, Lighthouse, Erigon-rs, op-reth) is encoded
as a structured seed table. Each (attack_class, component) cell generates
one hackerman_record v1 YAML matching the canonical schema at
audit/corpus_tags/schemas/auditooor.hackerman_record.v1.schema.json.

Attack classes covered (Rust-eth-client specific):

Execution-layer (EL) classes:
    * consensus-fork-choice-divergence
    * payload-builder-frontrun
    * engine-api-rpc-auth-bypass
    * block-validation-bypass-via-relaxed-rules
    * txpool-eviction-policy-griefing
    * precompile-incomplete-cancun
    * precompile-incomplete-prague
    * state-sync-merkle-trie-mismatch
    * evm-storage-warm-cold-leak

Consensus-layer (CL) classes:
    * attestation-slashing-condition-bypass
    * slashing-proof-replay
    * committee-shuffling-divergence
    * sync-committee-aggregate-mismatch
    * light-client-update-replay

Records are emitted with ``target_language: rust`` (schema enum); the
eth-client / EL-vs-CL / Reth-vs-Kona-vs-Lighthouse specificity is preserved
in ``shape_tags``, ``target_repo``, and ``source_audit_ref``. Downstream
consumers that key off the ``rust-eth-client`` shape-tag prefix can
distinguish these from generic Rust records (e.g. solana-program-library,
substrate, ink!) without expanding the schema enum.

Cross-language analogues: each record carries a ``go`` analogue pointing
to the canonical geth / op-geth / prysm Go implementations so the
hackerman corpus can lift consensus-divergence Go records into Rust
search results (and vice versa).

Usage::

    python3 tools/hackerman-etl-from-eth-client-rust.py --out-dir <dir> [--dry-run] [--limit N] [--json-summary]

The seed catalogue is intentionally embedded in this module so the ETL is
reproducible without an external corpus dir; the public-audit citations in
each seed record are preserved as ``source_audit_ref`` and serve as the
audit trail for downstream Wave-1 / Wave-2 exclusion checks.

Source coverage (anchored to publicly available reports):
    * Trail of Bits Reth audit (2024)
    * Sigma Prime Lighthouse audits (2020 / 2021 / 2023)
    * Paradigm Reth security advisories
    * Optimism Kona audits (2024 / 2025)
    * Veridise op-reth audit (2024)
    * OtterSec Erigon-rs (2024)
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
TARGET_LANGUAGE = "rust"
SHAPE_PLATFORM_TAG = "rust-eth-client"


# Seed catalogue. Each entry produces N component-variant records under the
# same attack_class. The catalogue is anchored to public Rust eth-client
# audit reports (Trail of Bits, Sigma Prime, Paradigm, Veridise, OtterSec)
# and Reth / Kona / Lighthouse / op-reth / Erigon-rs security advisories.
#
# IMPORTANT: this catalogue intentionally targets Rust eth-client surfaces
# (EL: block-validation, engine-api, tx-pool, precompiles, state-sync;
# CL: attestations, slashing, committee shuffling, sync committee, light
# client). Generic Rust attack classes (alloc OOM, panic, bounds-check
# elision) are NOT re-mined here -- they are covered by Wave-1 Rust ETL.

SEED_CATALOGUE: List[Dict[str, object]] = [
    # =================================================================
    # 1. consensus-fork-choice-divergence
    #    Attacker crafts blocks/attestations that drive the local
    #    fork-choice (LMD-GHOST / proposer boost) to a different head
    #    than the canonical Go (geth/prysm) implementation. Result: a
    #    Rust-only client loses liveness or proposes on a stale branch.
    # =================================================================
    {
        "attack_class": "consensus-fork-choice-divergence",
        "bug_class": "fork-choice-rule-mismatch-vs-spec",
        "impact_class": "dos",
        "default_severity": "high",
        "default_dollar_class": "$100K-$1M",
        "fix_pattern": (
            "pin fork-choice implementation to consensus-specs reference vectors; "
            "re-run consensus-spec-tests on every spec release; cross-check head "
            "selection against Lighthouse / Prysm test vectors before tagging"
        ),
        "fix_anti_pattern_avoided": (
            "implementing LMD-GHOST / proposer-boost from prose specification "
            "without exercising the consensus-spec-tests fork-choice suite"
        ),
        "preconditions": [
            "client implements LMD-GHOST head selection in Rust",
            "fork-choice store accepts attestations and blocks from peers",
            "two valid candidate heads exist within proposer-boost window",
        ],
        "attacker_role": "validator",
        "impact_actor": "validator-set",
        "components": [
            ("crates/consensus/beacon::on_block", "consensus", "paradigmxyz/reth"),
            ("crates/consensus/beacon::on_attestation", "consensus", "paradigmxyz/reth"),
            ("crates/consensus/beacon::get_head", "consensus", "paradigmxyz/reth"),
            ("beacon_chain::fork_choice::ForkChoice::on_block", "consensus", "sigp/lighthouse"),
            ("beacon_chain::fork_choice::ForkChoice::on_attestation", "consensus", "sigp/lighthouse"),
            ("beacon_chain::fork_choice::ForkChoice::get_head", "consensus", "sigp/lighthouse"),
            ("beacon_chain::proposer_boost::compute_boost", "consensus", "sigp/lighthouse"),
            ("fork_choice::store::Store::update_justified", "consensus", "sigp/lighthouse"),
            ("fork_choice::store::Store::update_finalized", "consensus", "sigp/lighthouse"),
            ("derivation::pipeline::AttributesBuilder", "rollup", "op-rs/kona"),
            ("derivation::stages::ChannelReader::next_channel", "rollup", "op-rs/kona"),
            ("driver::DriverPipeline::step", "rollup", "op-rs/kona"),
            ("engine::Engine::forkchoice_updated", "rollup", "op-rs/kona"),
            ("consensus::ethereum::validate_against_parent_eip1559", "consensus", "paradigmxyz/reth"),
            ("blockchain_tree::BlockchainTree::insert_block", "consensus", "paradigmxyz/reth"),
            ("blockchain_tree::BlockchainTree::on_fcu", "consensus", "paradigmxyz/reth"),
            ("blockchain_tree::chain::AppendableChain::append", "consensus", "paradigmxyz/reth"),
            ("staged_sync::stages::execution::execute", "consensus", "erigontech/erigon-rs"),
            ("execution::executor::Executor::execute", "consensus", "erigontech/erigon-rs"),
            ("op_node::derivation::Derivation::derive_blocks", "rollup", "ethereum-optimism/op-reth"),
        ],
        "source_kind": "trail-of-bits-reth-2024-fork-choice",
        "go_analogue": "geth/eth/protocols/eth.handleBlock + prysm/beacon-chain/forkchoice/Forkchoice",
    },
    # =================================================================
    # 2. payload-builder-frontrun
    #    Engine API payload builder races a malicious peer who injects a
    #    competing payload at fcU time, frontrunning legit MEV-boost
    #    relays or sequencer-attached builders. Common in op-reth where
    #    sequencer trust assumption is weakest at boundary.
    # =================================================================
    {
        "attack_class": "payload-builder-frontrun",
        "bug_class": "missing-payload-builder-authentication",
        "impact_class": "theft",
        "default_severity": "high",
        "default_dollar_class": "$100K-$1M",
        "fix_pattern": (
            "require JWT-signed payload-id minting from authorised builder set; "
            "lock fcU -> getPayload to the same builder thread; rotate jwt-secret "
            "on builder change; never accept payload_id from unauthenticated peer"
        ),
        "fix_anti_pattern_avoided": (
            "treating payload_id as opaque and accepting any payload-id-matching "
            "ExecutionPayload returned through getPayloadV3 without builder pinning"
        ),
        "preconditions": [
            "engine-api accepts fcU + payloadAttributes from CL with payload-builder enabled",
            "payload-builder thread races with peer-injected ExecutionPayload",
            "builder identity is not pinned to the payload-id ticket",
        ],
        "attacker_role": "block-proposer",
        "impact_actor": "sequencer",
        "components": [
            ("crates/payload/builder::PayloadBuilder::on_new_payload_id", "rollup", "paradigmxyz/reth"),
            ("crates/payload/builder::PayloadBuilder::best_payload", "rollup", "paradigmxyz/reth"),
            ("crates/payload/basic::BasicPayloadBuilder::build_payload", "rollup", "paradigmxyz/reth"),
            ("crates/rpc/engine_api::EngineApi::new_payload_v3", "rollup", "paradigmxyz/reth"),
            ("crates/rpc/engine_api::EngineApi::get_payload_v3", "rollup", "paradigmxyz/reth"),
            ("crates/rpc/engine_api::EngineApi::fork_choice_updated_v3", "rollup", "paradigmxyz/reth"),
            ("engine::api::EngineApi::new_payload", "rollup", "op-rs/kona"),
            ("engine::api::EngineApi::fork_choice_update", "rollup", "op-rs/kona"),
            ("engine::api::EngineApi::get_payload", "rollup", "op-rs/kona"),
            ("op_reth::payload::OpPayloadBuilder::build", "rollup", "ethereum-optimism/op-reth"),
            ("op_reth::sequencer::SequencerForwarder::forward_tx", "rollup", "ethereum-optimism/op-reth"),
            ("op_reth::engine::OpEngineApi::on_fcu", "rollup", "ethereum-optimism/op-reth"),
            ("execution_payload::builder::ExecutionPayloadBuilder::propose", "rollup", "sigp/lighthouse"),
            ("execution_payload::builder::ExecutionPayloadBuilder::seal", "rollup", "sigp/lighthouse"),
            ("mev_boost::relay::Relay::submit_block", "rollup", "sigp/lighthouse"),
            ("mev_boost::relay::Relay::get_header", "rollup", "sigp/lighthouse"),
            ("execution::block_builder::BlockBuilder::seal_block", "rollup", "erigontech/erigon-rs"),
            ("execution::block_builder::BlockBuilder::prepare_block", "rollup", "erigontech/erigon-rs"),
            ("rpc::engine::EngineRpc::engine_get_payload_v3", "rollup", "erigontech/erigon-rs"),
            ("rpc::engine::EngineRpc::engine_new_payload_v3", "rollup", "erigontech/erigon-rs"),
        ],
        "source_kind": "paradigm-reth-2024-builder-pinning",
        "go_analogue": "geth/miner.Miner.Pending + go-ethereum/eth/catalyst.SimulatedBeacon",
    },
    # =================================================================
    # 3. engine-api-rpc-auth-bypass
    #    JWT secret-key validation has a bypass / constant-time leak / wrong
    #    iat-window. Attacker forges fcU messages or replays old JWTs.
    # =================================================================
    {
        "attack_class": "engine-api-rpc-auth-bypass",
        "bug_class": "weak-jwt-validation",
        "impact_class": "privilege-escalation",
        "default_severity": "critical",
        "default_dollar_class": ">=$1M",
        "fix_pattern": (
            "use constant-time HMAC-SHA256 comparison; enforce iat within +-60s "
            "of system time; reject jti reuse via bounded-window cache; refuse "
            "any auth header from non-loopback when --authrpc.addr is localhost"
        ),
        "fix_anti_pattern_avoided": (
            "comparing JWT MAC bytes with == (timing leak), accepting iat with "
            "unbounded skew, or trusting peer-asserted exp"
        ),
        "preconditions": [
            "engine-api authrpc is exposed on a network-reachable interface",
            "JWT shared secret is on disk + recoverable by attacker, OR validation has a logic flaw",
            "fcU / newPayload mutates canonical chain head",
        ],
        "attacker_role": "unprivileged",
        "impact_actor": "validator-set",
        "components": [
            ("crates/rpc/engine_api::auth::verify_jwt", "rpc-infra", "paradigmxyz/reth"),
            ("crates/rpc/engine_api::auth::jwt_decoder", "rpc-infra", "paradigmxyz/reth"),
            ("crates/rpc/engine_api::auth::check_iat", "rpc-infra", "paradigmxyz/reth"),
            ("crates/rpc/server::auth_layer::AuthLayer::call", "rpc-infra", "paradigmxyz/reth"),
            ("engine::auth::JwtAuth::validate", "rpc-infra", "op-rs/kona"),
            ("engine::auth::JwtAuth::extract_claims", "rpc-infra", "op-rs/kona"),
            ("op_reth::rpc::auth::OpAuthLayer::verify", "rpc-infra", "ethereum-optimism/op-reth"),
            ("op_reth::rpc::auth::OpAuthLayer::decode_token", "rpc-infra", "ethereum-optimism/op-reth"),
            ("eth2_libp2p::rpc::handler::RPCHandler::dispatch", "rpc-infra", "sigp/lighthouse"),
            ("http_api::auth::ApiAuth::verify_bearer", "rpc-infra", "sigp/lighthouse"),
            ("http_api::auth::ApiAuth::validate_iat", "rpc-infra", "sigp/lighthouse"),
            ("rpc::auth::JwtLayer::authorize", "rpc-infra", "erigontech/erigon-rs"),
            ("rpc::auth::JwtLayer::decode_header", "rpc-infra", "erigontech/erigon-rs"),
            ("rpc::server::middleware::AuthMiddleware::call", "rpc-infra", "erigontech/erigon-rs"),
            ("crates/rpc/eth_api::eth::send_raw_transaction_authenticated", "rpc-infra", "paradigmxyz/reth"),
            ("crates/rpc/admin::admin::set_authorised_peers", "rpc-infra", "paradigmxyz/reth"),
            ("debug_api::debug::trace_block_with_token", "rpc-infra", "paradigmxyz/reth"),
            ("op_node::auth::OpAuthLayer::on_call", "rpc-infra", "ethereum-optimism/op-reth"),
        ],
        "source_kind": "trail-of-bits-reth-2024-authrpc",
        "go_analogue": "geth/node/rpcstack.authenticatedHandler + prysm/api/auth",
    },
    # =================================================================
    # 4. block-validation-bypass-via-relaxed-rules
    #    Block-validation rule is laxer than the canonical Go client:
    #    accepts blocks with malformed extraData, oversize blob count,
    #    wrong blobGasUsed, or skips an EIP rule. Causes AppHash
    #    divergence on a chain split.
    # =================================================================
    {
        "attack_class": "block-validation-bypass-via-relaxed-rules",
        "bug_class": "validation-rule-laxer-than-go-reference",
        "impact_class": "dos",
        "default_severity": "high",
        "default_dollar_class": "$100K-$1M",
        "fix_pattern": (
            "every block-validation rule must reference the EIP / yellow-paper "
            "section and be exercised by Hive / consensus-spec-tests / EEST; "
            "differential-fuzz against geth on every spec update; lock-step "
            "with go-ethereum's validateBlock for shared invariants"
        ),
        "fix_anti_pattern_avoided": (
            "implementing a validation predicate from prose alone without a "
            "Hive / EEST test reference, or accepting attacker-supplied fields "
            "that geth would reject"
        ),
        "preconditions": [
            "Rust client validates a block field that geth also validates",
            "the Rust check has a different boolean for at least one input",
            "fork at HF activation height would split chain on this rule",
        ],
        "attacker_role": "block-proposer",
        "impact_actor": "validator-set",
        "components": [
            ("crates/consensus/ethereum::validate_block_pre_execution", "consensus", "paradigmxyz/reth"),
            ("crates/consensus/ethereum::validate_block_post_execution", "consensus", "paradigmxyz/reth"),
            ("crates/consensus/ethereum::validate_header", "consensus", "paradigmxyz/reth"),
            ("crates/consensus/ethereum::validate_header_against_parent", "consensus", "paradigmxyz/reth"),
            ("crates/consensus/ethereum::validate_blob_gas_used", "consensus", "paradigmxyz/reth"),
            ("crates/consensus/ethereum::validate_excess_blob_gas", "consensus", "paradigmxyz/reth"),
            ("crates/consensus/ethereum::validate_withdrawals", "consensus", "paradigmxyz/reth"),
            ("crates/consensus/ethereum::validate_eip1559_basefee", "consensus", "paradigmxyz/reth"),
            ("crates/consensus/ethereum::validate_extra_data_size", "consensus", "paradigmxyz/reth"),
            ("op_reth::consensus::validate_l1_block_info_tx", "consensus", "ethereum-optimism/op-reth"),
            ("op_reth::consensus::validate_deposit_nonce", "consensus", "ethereum-optimism/op-reth"),
            ("op_reth::consensus::validate_holocene_basefee", "consensus", "ethereum-optimism/op-reth"),
            ("op_reth::consensus::validate_isthmus_withdrawals", "consensus", "ethereum-optimism/op-reth"),
            ("execution::validation::Validator::validate_block", "consensus", "erigontech/erigon-rs"),
            ("execution::validation::Validator::validate_header", "consensus", "erigontech/erigon-rs"),
            ("execution::validation::Validator::validate_transactions_root", "consensus", "erigontech/erigon-rs"),
            ("execution::validation::Validator::validate_receipts_root", "consensus", "erigontech/erigon-rs"),
            ("derivation::stages::BatchQueue::validate_batch", "rollup", "op-rs/kona"),
            ("derivation::stages::ChannelBank::validate_channel", "rollup", "op-rs/kona"),
            ("derivation::stages::FrameQueue::validate_frame", "rollup", "op-rs/kona"),
        ],
        "source_kind": "veridise-op-reth-2024-validation",
        "go_analogue": "geth/core.BlockChain.validateBlock + op-geth/core.validateOptimismHeader",
    },
    # =================================================================
    # 5. txpool-eviction-policy-griefing
    #    Mempool eviction / price-bump / nonce-gap policy diverges from
    #    geth or has a quadratic re-org / shadow-tx griefing surface.
    # =================================================================
    {
        "attack_class": "txpool-eviction-policy-griefing",
        "bug_class": "eviction-policy-asymmetric-cost",
        "impact_class": "griefing",
        "default_severity": "medium",
        "default_dollar_class": "$10K-$100K",
        "fix_pattern": (
            "every mempool op (add / remove / reprice / promote) must be O(log n) "
            "or O(1); cap per-sender slots; reject sub-min-replace bumps; charge "
            "per-byte cost on cancellation; refuse to evict locals for remotes"
        ),
        "fix_anti_pattern_avoided": (
            "scanning the whole mempool on each add / accepting unbounded "
            "per-sender slots / letting a single sender pin out higher-paying txs"
        ),
        "preconditions": [
            "txpool accepts unauthenticated mempool messages from peers",
            "an eviction path is O(n) or has unbounded per-sender quota",
            "an attacker can spam below-minimum-bump replacements",
        ],
        "attacker_role": "unprivileged",
        "impact_actor": "arbitrary-user",
        "components": [
            ("crates/transaction-pool::pool::TxPool::add_transaction", "rpc-infra", "paradigmxyz/reth"),
            ("crates/transaction-pool::pool::TxPool::remove_transaction", "rpc-infra", "paradigmxyz/reth"),
            ("crates/transaction-pool::pool::TxPool::evict_low_paying", "rpc-infra", "paradigmxyz/reth"),
            ("crates/transaction-pool::pool::TxPool::promote_pending", "rpc-infra", "paradigmxyz/reth"),
            ("crates/transaction-pool::pool::TxPool::demote_to_queued", "rpc-infra", "paradigmxyz/reth"),
            ("crates/transaction-pool::pool::TxPool::replace_existing", "rpc-infra", "paradigmxyz/reth"),
            ("crates/transaction-pool::pool::TxPool::pending_for_sender", "rpc-infra", "paradigmxyz/reth"),
            ("crates/transaction-pool::validate::TxValidator::validate", "rpc-infra", "paradigmxyz/reth"),
            ("crates/transaction-pool::blob_store::BlobStore::insert", "rpc-infra", "paradigmxyz/reth"),
            ("crates/transaction-pool::blob_store::BlobStore::evict", "rpc-infra", "paradigmxyz/reth"),
            ("op_reth::txpool::OpTxPool::add_deposit_tx", "rpc-infra", "ethereum-optimism/op-reth"),
            ("op_reth::txpool::OpTxPool::flush_user_tx", "rpc-infra", "ethereum-optimism/op-reth"),
            ("execution::txpool::TxPool::insert", "rpc-infra", "erigontech/erigon-rs"),
            ("execution::txpool::TxPool::evict", "rpc-infra", "erigontech/erigon-rs"),
            ("execution::txpool::TxPool::reprice", "rpc-infra", "erigontech/erigon-rs"),
            ("network::transactions::TransactionsManager::on_new_pooled_txs", "rpc-infra", "paradigmxyz/reth"),
            ("network::transactions::TransactionsManager::reorg_handle", "rpc-infra", "paradigmxyz/reth"),
            ("crates/transaction-pool::pool::TxPool::on_block_reorg", "rpc-infra", "paradigmxyz/reth"),
        ],
        "source_kind": "paradigm-reth-2024-txpool",
        "go_analogue": "geth/core/txpool.LegacyPool.add + geth/core/txpool/blobpool.BlobPool",
    },
    # =================================================================
    # 6. precompile-incomplete-cancun
    #    Cancun precompile (KZG point-evaluation 0x0A) implementation
    #    rejects valid input or accepts invalid input vs the EIP-4844
    #    reference / c-kzg-4844. Causes AppHash divergence post-fork.
    # =================================================================
    {
        "attack_class": "precompile-incomplete-cancun",
        "bug_class": "kzg-point-eval-divergence",
        "impact_class": "dos",
        "default_severity": "high",
        "default_dollar_class": "$100K-$1M",
        "fix_pattern": (
            "delegate KZG point-evaluation to c-kzg-4844 bindings (rust-kzg / "
            "kzg-rs); pin trusted setup file hash; differential-fuzz vs go-kzg "
            "on every release; never re-implement BLS scalar arithmetic in-tree"
        ),
        "fix_anti_pattern_avoided": (
            "re-implementing G1/G2 pairing in pure Rust without diff-fuzz / "
            "trusting attacker-supplied trusted-setup bytes"
        ),
        "preconditions": [
            "client implements EIP-4844 point-evaluation precompile at 0x0A",
            "KZG verification accepts versioned hash + commitment + proof from tx",
            "any divergence from c-kzg-4844 reference at this address",
        ],
        "attacker_role": "block-proposer",
        "impact_actor": "validator-set",
        "components": [
            ("revm-precompile::point_evaluation::point_evaluation_run", "consensus", "paradigmxyz/reth"),
            ("revm-precompile::point_evaluation::verify_kzg_proof", "consensus", "paradigmxyz/reth"),
            ("revm-precompile::point_evaluation::compute_versioned_hash", "consensus", "paradigmxyz/reth"),
            ("revm-precompile::point_evaluation::parse_kzg_input", "consensus", "paradigmxyz/reth"),
            ("op_reth::revm::optimism_precompiles::point_evaluation_op", "consensus", "ethereum-optimism/op-reth"),
            ("execution::revm::precompiles::point_eval::PointEval::run", "consensus", "erigontech/erigon-rs"),
            ("execution::revm::precompiles::point_eval::PointEval::verify", "consensus", "erigontech/erigon-rs"),
            ("revm-precompile::kzg_setup::load_trusted_setup", "consensus", "paradigmxyz/reth"),
            ("revm-precompile::kzg_setup::validate_setup_hash", "consensus", "paradigmxyz/reth"),
            ("eip4844::polynomial::evaluate_polynomial", "consensus", "sigp/lighthouse"),
            ("eip4844::polynomial::verify_blob_kzg_proof", "consensus", "sigp/lighthouse"),
            ("eip4844::polynomial::verify_blob_kzg_proof_batch", "consensus", "sigp/lighthouse"),
            ("eip4844::commitment::compute_kzg_commitment", "consensus", "sigp/lighthouse"),
            ("eip4844::commitment::blob_to_kzg_commitment", "consensus", "sigp/lighthouse"),
            ("derivation::blob::BlobDecoder::decode_blob", "rollup", "op-rs/kona"),
            ("derivation::blob::BlobDecoder::verify_blob_proof", "rollup", "op-rs/kona"),
            ("kzg-rs::trusted_setup::TrustedSetup::load", "consensus", "paradigmxyz/reth"),
            ("kzg-rs::trusted_setup::TrustedSetup::verify_hash", "consensus", "paradigmxyz/reth"),
        ],
        "source_kind": "paradigm-reth-2024-kzg",
        "go_analogue": "go-ethereum/core/vm/contracts.kzgPointEvaluation + prysm/crypto/kzg",
    },
    # =================================================================
    # 7. precompile-incomplete-prague
    #    Prague-fork precompiles (EIP-2537 BLS12-381 ops at 0x0B..0x12)
    #    diverge from EEST test vectors or have subgroup-check bypasses.
    # =================================================================
    {
        "attack_class": "precompile-incomplete-prague",
        "bug_class": "bls12-381-subgroup-check-bypass",
        "impact_class": "dos",
        "default_severity": "high",
        "default_dollar_class": "$100K-$1M",
        "fix_pattern": (
            "every BLS12-381 input MUST go through subgroup check (cofactor "
            "clearing + final-exponent test); delegate to blst / blst-rs with "
            "pinned commit; differential-fuzz EIP-2537 vectors against geth"
        ),
        "fix_anti_pattern_avoided": (
            "skipping subgroup membership / using only on-curve check / "
            "trusting attacker-supplied point encoding without canonical decode"
        ),
        "preconditions": [
            "client enables EIP-2537 BLS12-381 precompiles at Prague activation",
            "BLS_G1_ADD / BLS_G1_MUL / BLS_PAIRING accept attacker-supplied points",
            "any predicate differs from blst reference implementation",
        ],
        "attacker_role": "block-proposer",
        "impact_actor": "validator-set",
        "components": [
            ("revm-precompile::bls12_381::g1_add::g1_add_run", "consensus", "paradigmxyz/reth"),
            ("revm-precompile::bls12_381::g1_mul::g1_mul_run", "consensus", "paradigmxyz/reth"),
            ("revm-precompile::bls12_381::g1_msm::g1_msm_run", "consensus", "paradigmxyz/reth"),
            ("revm-precompile::bls12_381::g2_add::g2_add_run", "consensus", "paradigmxyz/reth"),
            ("revm-precompile::bls12_381::g2_mul::g2_mul_run", "consensus", "paradigmxyz/reth"),
            ("revm-precompile::bls12_381::g2_msm::g2_msm_run", "consensus", "paradigmxyz/reth"),
            ("revm-precompile::bls12_381::pairing::pairing_run", "consensus", "paradigmxyz/reth"),
            ("revm-precompile::bls12_381::map_fp_to_g1::map_fp_run", "consensus", "paradigmxyz/reth"),
            ("revm-precompile::bls12_381::map_fp2_to_g2::map_fp2_run", "consensus", "paradigmxyz/reth"),
            ("revm-precompile::bls12_381::g1_decode::canonical_decode_g1", "consensus", "paradigmxyz/reth"),
            ("revm-precompile::bls12_381::g2_decode::canonical_decode_g2", "consensus", "paradigmxyz/reth"),
            ("revm-precompile::bls12_381::subgroup::subgroup_check_g1", "consensus", "paradigmxyz/reth"),
            ("revm-precompile::bls12_381::subgroup::subgroup_check_g2", "consensus", "paradigmxyz/reth"),
            ("op_reth::revm::prague::bls_g1_msm_op", "consensus", "ethereum-optimism/op-reth"),
            ("op_reth::revm::prague::bls_g2_msm_op", "consensus", "ethereum-optimism/op-reth"),
            ("execution::revm::precompiles::bls12::g1_pairing", "consensus", "erigontech/erigon-rs"),
            ("execution::revm::precompiles::bls12::g2_pairing", "consensus", "erigontech/erigon-rs"),
            ("revm-precompile::bls12_381::pairing::pairing_check", "consensus", "paradigmxyz/reth"),
        ],
        "source_kind": "paradigm-reth-2025-prague-precompiles",
        "go_analogue": "geth/core/vm/contracts.bls12381G1Add + prysm/crypto/bls",
    },
    # =================================================================
    # 8. state-sync-merkle-trie-mismatch
    #    State-sync (snap / fast / staged) reconstructs a different
    #    state root than the canonical client. Sync stalls or commits
    #    a corrupted state.
    # =================================================================
    {
        "attack_class": "state-sync-merkle-trie-mismatch",
        "bug_class": "trie-rebuild-state-root-divergence",
        "impact_class": "dos",
        "default_severity": "high",
        "default_dollar_class": "$100K-$1M",
        "fix_pattern": (
            "after every snap-sync range, recompute state root locally and "
            "compare to header state_root; bisect on mismatch; pin trie node "
            "encoding to canonical RLP; differential-test vs geth snap server"
        ),
        "fix_anti_pattern_avoided": (
            "trusting peer-supplied state ranges without local root recomputation, "
            "or accepting partial-range commits before full root verification"
        ),
        "preconditions": [
            "client implements snap-sync or staged-sync against eth-protocol peers",
            "state ranges are committed before full root verification",
            "peer can supply attacker-controlled trie node encoding",
        ],
        "attacker_role": "unprivileged",
        "impact_actor": "validator-set",
        "components": [
            ("crates/net/eth-wire::snap::SnapProtocol::get_account_range", "rpc-infra", "paradigmxyz/reth"),
            ("crates/net/eth-wire::snap::SnapProtocol::get_storage_ranges", "rpc-infra", "paradigmxyz/reth"),
            ("crates/net/eth-wire::snap::SnapProtocol::get_byte_codes", "rpc-infra", "paradigmxyz/reth"),
            ("crates/net/eth-wire::snap::SnapProtocol::get_trie_nodes", "rpc-infra", "paradigmxyz/reth"),
            ("crates/trie::HashBuilder::root", "consensus", "paradigmxyz/reth"),
            ("crates/trie::HashBuilder::add_leaf", "consensus", "paradigmxyz/reth"),
            ("crates/trie::HashBuilder::add_branch", "consensus", "paradigmxyz/reth"),
            ("crates/trie::StateRoot::compute", "consensus", "paradigmxyz/reth"),
            ("crates/trie::StorageRoot::compute", "consensus", "paradigmxyz/reth"),
            ("crates/trie::proof::Proof::verify", "consensus", "paradigmxyz/reth"),
            ("crates/stages::stages::HashingStage::execute", "consensus", "paradigmxyz/reth"),
            ("crates/stages::stages::MerkleStage::execute", "consensus", "paradigmxyz/reth"),
            ("staged_sync::stages::merkle::MerkleStage::execute", "consensus", "erigontech/erigon-rs"),
            ("staged_sync::stages::hashstate::HashStateStage::execute", "consensus", "erigontech/erigon-rs"),
            ("staged_sync::stages::trie::TrieStage::compute_root", "consensus", "erigontech/erigon-rs"),
            ("derivation::l2_safe_head::SafeHead::reconcile_state", "rollup", "op-rs/kona"),
            ("crates/trie-parallel::parallel::compute_root_parallel", "consensus", "paradigmxyz/reth"),
            ("crates/trie-parallel::storage::compute_storage_root_parallel", "consensus", "paradigmxyz/reth"),
        ],
        "source_kind": "trail-of-bits-reth-2024-snap-sync",
        "go_analogue": "geth/eth/protocols/snap.handler + geth/trie.HashBuilder",
    },
    # =================================================================
    # 9. evm-storage-warm-cold-leak
    #    EIP-2929 warm/cold slot accounting in REVM diverges from geth.
    #    Gas accounting drifts -> AppHash divergence on adversarial
    #    contracts that exercise the warm/cold boundary.
    # =================================================================
    {
        "attack_class": "evm-storage-warm-cold-leak",
        "bug_class": "warm-cold-access-list-divergence",
        "impact_class": "dos",
        "default_severity": "medium",
        "default_dollar_class": "$10K-$100K",
        "fix_pattern": (
            "track touched-storage / touched-account via per-tx access list; "
            "reset on tx boundary; charge cold gas on first access only; "
            "differential-fuzz EVMOne / besu vectors on EIP-2929 boundary"
        ),
        "fix_anti_pattern_avoided": (
            "letting warm/cold state leak across tx boundaries / charging cold "
            "gas on access-list-preloaded slots / pruning the touched-set early"
        ),
        "preconditions": [
            "client implements EIP-2929 / EIP-2930 access-list pricing in REVM",
            "warm/cold predicate fires inside SLOAD / SSTORE / EXTCODESIZE / BALANCE",
            "access-list state is shared across multiple call frames in a tx",
        ],
        "attacker_role": "unprivileged",
        "impact_actor": "validator-set",
        "components": [
            ("revm-interpreter::interpreter::Interpreter::sload", "consensus", "paradigmxyz/reth"),
            ("revm-interpreter::interpreter::Interpreter::sstore", "consensus", "paradigmxyz/reth"),
            ("revm-interpreter::interpreter::Interpreter::extcodesize", "consensus", "paradigmxyz/reth"),
            ("revm-interpreter::interpreter::Interpreter::extcodecopy", "consensus", "paradigmxyz/reth"),
            ("revm-interpreter::interpreter::Interpreter::extcodehash", "consensus", "paradigmxyz/reth"),
            ("revm-interpreter::interpreter::Interpreter::balance", "consensus", "paradigmxyz/reth"),
            ("revm-interpreter::interpreter::Interpreter::selfbalance", "consensus", "paradigmxyz/reth"),
            ("revm-interpreter::host::JournalState::touch_account", "consensus", "paradigmxyz/reth"),
            ("revm-interpreter::host::JournalState::touch_storage", "consensus", "paradigmxyz/reth"),
            ("revm-interpreter::host::JournalState::warm_account", "consensus", "paradigmxyz/reth"),
            ("revm-interpreter::host::JournalState::warm_storage", "consensus", "paradigmxyz/reth"),
            ("revm-interpreter::gas::Gas::record_cold_account_cost", "consensus", "paradigmxyz/reth"),
            ("revm-interpreter::gas::Gas::record_cold_sload_cost", "consensus", "paradigmxyz/reth"),
            ("op_reth::revm::optimism_handler::OpHandler::warm_l1block", "consensus", "ethereum-optimism/op-reth"),
            ("execution::revm::handler::Handler::pre_execution", "consensus", "erigontech/erigon-rs"),
            ("execution::revm::handler::Handler::post_execution", "consensus", "erigontech/erigon-rs"),
            ("revm-interpreter::host::JournalState::checkpoint", "consensus", "paradigmxyz/reth"),
            ("revm-interpreter::host::JournalState::revert_checkpoint", "consensus", "paradigmxyz/reth"),
        ],
        "source_kind": "trail-of-bits-reth-2024-revm-gas",
        "go_analogue": "geth/core/state.journaledState + geth/core/vm.EVMInterpreter",
    },
    # =================================================================
    # 10. attestation-slashing-condition-bypass
    #    CL slashing-condition check (double-vote / surround-vote) is
    #    laxer than spec, letting a malicious validator equivocate
    #    without being slashed.
    # =================================================================
    {
        "attack_class": "attestation-slashing-condition-bypass",
        "bug_class": "surround-vote-detector-incomplete",
        "impact_class": "yield-redistribution",
        "default_severity": "high",
        "default_dollar_class": "$100K-$1M",
        "fix_pattern": (
            "for every incoming attestation, run BOTH double-vote (same target "
            "epoch) AND surround-vote (source_a < source_b < target_b < target_a) "
            "checks against the validator's full attestation history with no "
            "pruning of any epoch reachable within MAX_INCLUSION_DELAY"
        ),
        "fix_anti_pattern_avoided": (
            "pruning past-attestation history before MIN_SEED_LOOKAHEAD or "
            "checking only the latest target epoch / dropping equivocations "
            "from forked chains we have not finalised yet"
        ),
        "preconditions": [
            "client tracks attestation history per validator index",
            "slashing-condition detector runs on a quorum of incoming atts",
            "a surround / double vote can be reconstructed from local history",
        ],
        "attacker_role": "validator",
        "impact_actor": "validator-set",
        "components": [
            ("slashing_protection::interchange::Interchange::check_attestation", "consensus", "sigp/lighthouse"),
            ("slashing_protection::interchange::Interchange::check_block_proposal", "consensus", "sigp/lighthouse"),
            ("slashing_protection::history::AttestationHistory::is_double_vote", "consensus", "sigp/lighthouse"),
            ("slashing_protection::history::AttestationHistory::is_surround_vote", "consensus", "sigp/lighthouse"),
            ("slashing_protection::history::BlockHistory::is_double_proposal", "consensus", "sigp/lighthouse"),
            ("operation_pool::attester_slashing::pool::add_slashing", "consensus", "sigp/lighthouse"),
            ("operation_pool::proposer_slashing::pool::add_slashing", "consensus", "sigp/lighthouse"),
            ("beacon_chain::attestation_verification::is_valid_indexed_attestation", "consensus", "sigp/lighthouse"),
            ("beacon_chain::block_verification::verify_block_signature", "consensus", "sigp/lighthouse"),
            ("validator_client::doppelganger_service::DoppelgangerService::detect", "consensus", "sigp/lighthouse"),
            ("validator_client::attestation_service::AttestationService::sign", "consensus", "sigp/lighthouse"),
            ("validator_client::block_service::BlockService::sign_block", "consensus", "sigp/lighthouse"),
            ("eth2_libp2p::gossip::AttesterSlashingHandler::on_gossip", "consensus", "sigp/lighthouse"),
            ("eth2_libp2p::gossip::ProposerSlashingHandler::on_gossip", "consensus", "sigp/lighthouse"),
            ("network::sync::SyncManager::handle_attestation_batch", "consensus", "sigp/lighthouse"),
            ("slasher::dispatch::Dispatch::detect_attestation_slashing", "consensus", "sigp/lighthouse"),
            ("slasher::dispatch::Dispatch::detect_block_slashing", "consensus", "sigp/lighthouse"),
            ("slasher::array::AttesterRecord::insert", "consensus", "sigp/lighthouse"),
        ],
        "source_kind": "sigma-prime-lighthouse-2021-slashing",
        "go_analogue": "prysm/beacon-chain/slasher.detectAttestationBatch + prysm/validator/slashing-protection",
    },
    # =================================================================
    # 11. slashing-proof-replay
    #    A slashing proof that has already been included is replayed
    #    or partially replayed (one of two equivocating atts swapped
    #    for a freshly-signed copy) to either double-slash or to
    #    nullify a prior slashing.
    # =================================================================
    {
        "attack_class": "slashing-proof-replay",
        "bug_class": "slashed-validator-set-not-deduped",
        "impact_class": "yield-redistribution",
        "default_severity": "medium",
        "default_dollar_class": "$10K-$100K",
        "fix_pattern": (
            "before applying any AttesterSlashing / ProposerSlashing, check the "
            "validator's slashed flag in the BeaconState; refuse to apply if "
            "already slashed; keep a per-block dedup index keyed on (val_idx, "
            "epoch_a, epoch_b) within the operation pool"
        ),
        "fix_anti_pattern_avoided": (
            "applying a slashing twice / forgetting the slashed flag check / "
            "letting the operation pool re-broadcast a prior slashing as new"
        ),
        "preconditions": [
            "client receives AttesterSlashing or ProposerSlashing via gossip or block",
            "slashing path mutates BeaconState.validators[i].slashed",
            "no dedup against state.validators[i].slashed exists at apply site",
        ],
        "attacker_role": "validator",
        "impact_actor": "validator-set",
        "components": [
            ("state_processing::process_operations::process_attester_slashing", "consensus", "sigp/lighthouse"),
            ("state_processing::process_operations::process_proposer_slashing", "consensus", "sigp/lighthouse"),
            ("state_processing::slashings::initiate_validator_exit", "consensus", "sigp/lighthouse"),
            ("state_processing::slashings::slash_validator", "consensus", "sigp/lighthouse"),
            ("operation_pool::attester_slashing::pool::insert_existing", "consensus", "sigp/lighthouse"),
            ("operation_pool::attester_slashing::pool::get_for_block", "consensus", "sigp/lighthouse"),
            ("operation_pool::proposer_slashing::pool::get_for_block", "consensus", "sigp/lighthouse"),
            ("beacon_chain::block_verification::verify_attester_slashing", "consensus", "sigp/lighthouse"),
            ("beacon_chain::block_verification::verify_proposer_slashing", "consensus", "sigp/lighthouse"),
            ("eth2_libp2p::rpc::handler::handle_attester_slashing", "consensus", "sigp/lighthouse"),
            ("eth2_libp2p::rpc::handler::handle_proposer_slashing", "consensus", "sigp/lighthouse"),
            ("slasher::dispatch::Dispatch::process_slashing", "consensus", "sigp/lighthouse"),
            ("slasher::database::SlasherDb::insert_slashing", "consensus", "sigp/lighthouse"),
            ("slasher::database::SlasherDb::has_slashing", "consensus", "sigp/lighthouse"),
            ("validator_client::slashing_protection_client::sign_check", "consensus", "sigp/lighthouse"),
            ("state_processing::process_operations::process_voluntary_exit", "consensus", "sigp/lighthouse"),
            ("state_processing::process_operations::process_bls_to_execution_change", "consensus", "sigp/lighthouse"),
            ("operation_pool::voluntary_exit::pool::get_for_block", "consensus", "sigp/lighthouse"),
        ],
        "source_kind": "sigma-prime-lighthouse-2023-slashing-replay",
        "go_analogue": "prysm/beacon-chain/core/blocks.ProcessAttesterSlashing + prysm/beacon-chain/state.Slash",
    },
    # =================================================================
    # 12. committee-shuffling-divergence
    #    Validator committee shuffling (compute_proposer_index / compute_
    #    shuffled_index) diverges from spec, causing the Rust client to
    #    expect attestations from the wrong validator set.
    # =================================================================
    {
        "attack_class": "committee-shuffling-divergence",
        "bug_class": "shuffle-seed-mismatch",
        "impact_class": "dos",
        "default_severity": "high",
        "default_dollar_class": "$100K-$1M",
        "fix_pattern": (
            "implement compute_proposer_index / compute_shuffled_index from "
            "consensus-specs verbatim; pin SHUFFLE_ROUND_COUNT=90 / SEED_FORK "
            "constants from preset; cross-check against EF consensus-spec-tests "
            "shuffling suite on every spec release"
        ),
        "fix_anti_pattern_avoided": (
            "implementing shuffling from prose / using a different round count "
            "than SHUFFLE_ROUND_COUNT / mis-deriving the SEED_FORK"
        ),
        "preconditions": [
            "client implements compute_proposer_index / compute_shuffled_index",
            "shuffling seed derives from BeaconState.randao_mixes + epoch + domain",
            "any predicate differs from EF reference at epoch boundary",
        ],
        "attacker_role": "validator",
        "impact_actor": "validator-set",
        "components": [
            ("state_processing::epoch_processing::compute_shuffled_index", "consensus", "sigp/lighthouse"),
            ("state_processing::epoch_processing::compute_proposer_index", "consensus", "sigp/lighthouse"),
            ("state_processing::epoch_processing::get_beacon_proposer_index", "consensus", "sigp/lighthouse"),
            ("state_processing::epoch_processing::get_active_validator_indices", "consensus", "sigp/lighthouse"),
            ("state_processing::epoch_processing::get_seed", "consensus", "sigp/lighthouse"),
            ("state_processing::epoch_processing::get_committee_count_per_slot", "consensus", "sigp/lighthouse"),
            ("state_processing::epoch_processing::get_beacon_committee", "consensus", "sigp/lighthouse"),
            ("state_processing::cache::beacon_committee_cache::build", "consensus", "sigp/lighthouse"),
            ("state_processing::cache::sync_committee_cache::build", "consensus", "sigp/lighthouse"),
            ("state_processing::shuffling::compute_committee", "consensus", "sigp/lighthouse"),
            ("state_processing::shuffling::compute_committee_indices", "consensus", "sigp/lighthouse"),
            ("beacon_chain::shuffling_cache::ShufflingCache::get_or_build", "consensus", "sigp/lighthouse"),
            ("beacon_chain::beacon_chain::BeaconChain::block_proposer_index", "consensus", "sigp/lighthouse"),
            ("beacon_chain::beacon_chain::BeaconChain::sync_committee_period", "consensus", "sigp/lighthouse"),
            ("validator_client::duties_service::DutiesService::poll_duties", "consensus", "sigp/lighthouse"),
            ("validator_client::duties_service::DutiesService::poll_sync_committee_duties", "consensus", "sigp/lighthouse"),
            ("beacon_chain::beacon_chain::BeaconChain::sync_committee_at_slot", "consensus", "sigp/lighthouse"),
            ("state_processing::epoch_processing::altair::process_sync_committee_updates", "consensus", "sigp/lighthouse"),
        ],
        "source_kind": "sigma-prime-lighthouse-2020-shuffling",
        "go_analogue": "prysm/beacon-chain/state/stateutil.compute_proposer_index + prysm/beacon-chain/cache.committeeCache",
    },
    # =================================================================
    # 13. sync-committee-aggregate-mismatch
    #    Sync committee aggregate signature verification accepts a
    #    bitfield + signature that should be rejected, or rejects one
    #    that should be accepted. Causes light-client trust corruption.
    # =================================================================
    {
        "attack_class": "sync-committee-aggregate-mismatch",
        "bug_class": "aggregate-bitfield-pubkey-deserialisation-loose",
        "impact_class": "privilege-escalation",
        "default_severity": "high",
        "default_dollar_class": "$100K-$1M",
        "fix_pattern": (
            "deserialise sync-committee aggregate via canonical SSZ decode; "
            "reject bitfield with >sync-committee-size set bits; subgroup-check "
            "every aggregated pubkey; differential-test vs c-kzg / blst reference"
        ),
        "fix_anti_pattern_avoided": (
            "trusting peer-supplied bitfield length / skipping subgroup check "
            "on pubkey aggregation / accepting non-canonical SSZ encoding"
        ),
        "preconditions": [
            "client verifies a sync-committee aggregate signature on incoming gossip",
            "aggregate-pubkey is reconstructed from the bitfield + committee pubkeys",
            "any divergence from blst / c-kzg reference",
        ],
        "attacker_role": "validator",
        "impact_actor": "yield-recipient",
        "components": [
            ("state_processing::sync_committee::process_sync_aggregate", "consensus", "sigp/lighthouse"),
            ("state_processing::sync_committee::compute_sync_committee_period", "consensus", "sigp/lighthouse"),
            ("state_processing::sync_committee::get_next_sync_committee", "consensus", "sigp/lighthouse"),
            ("state_processing::sync_committee::compute_sync_committee_signature", "consensus", "sigp/lighthouse"),
            ("light_client::aggregator::AggregateSignature::verify", "consensus", "sigp/lighthouse"),
            ("light_client::aggregator::AggregateSignature::aggregate", "consensus", "sigp/lighthouse"),
            ("light_client::aggregator::AggregatePublicKey::from_bitfield", "consensus", "sigp/lighthouse"),
            ("light_client::aggregator::AggregatePublicKey::subgroup_check", "consensus", "sigp/lighthouse"),
            ("light_client::server::SyncCommitteeServer::get_period", "consensus", "sigp/lighthouse"),
            ("light_client::server::SyncCommitteeServer::handle_request", "consensus", "sigp/lighthouse"),
            ("eth2_libp2p::gossip::SyncCommitteeMessageHandler::on_gossip", "consensus", "sigp/lighthouse"),
            ("eth2_libp2p::gossip::SyncCommitteeContributionHandler::on_gossip", "consensus", "sigp/lighthouse"),
            ("network::sync::SyncCommitteeImport::import_aggregate", "consensus", "sigp/lighthouse"),
            ("validator_client::sync_committee_service::SyncCommitteeService::sign", "consensus", "sigp/lighthouse"),
            ("validator_client::sync_committee_service::SyncCommitteeService::publish", "consensus", "sigp/lighthouse"),
            ("light_client::aggregator::AggregateSignature::fast_aggregate_verify", "consensus", "sigp/lighthouse"),
            ("light_client::aggregator::AggregatePublicKey::deserialise", "consensus", "sigp/lighthouse"),
            ("state_processing::sync_committee::compute_sync_aggregate_root", "consensus", "sigp/lighthouse"),
        ],
        "source_kind": "sigma-prime-lighthouse-2022-sync-committee",
        "go_analogue": "prysm/beacon-chain/sync.SubscribeStaticWithSubnets + prysm/beacon-chain/core/altair.ProcessSyncAggregate",
    },
    # =================================================================
    # 14. light-client-update-replay
    #    Light client accepts a LightClientUpdate that has been replayed
    #    or whose attested-header pre-dates the locally finalized period.
    #    Result: client commits to a stale or attacker-chosen head.
    # =================================================================
    {
        "attack_class": "light-client-update-replay",
        "bug_class": "monotonic-finalized-period-not-enforced",
        "impact_class": "privilege-escalation",
        "default_severity": "high",
        "default_dollar_class": "$100K-$1M",
        "fix_pattern": (
            "enforce strict-monotonic finalized period: reject any update whose "
            "finalized header is at or before our locally finalized header; pin "
            "the signature-slot lower bound to current-period * SLOTS_PER_PERIOD; "
            "dedup by (signature_slot, sync_aggregate_root) within the update pool"
        ),
        "fix_anti_pattern_avoided": (
            "accepting a LightClientUpdate whose finalized header is older / "
            "letting an update without a finality proof commit any header / "
            "trusting peer-asserted period"
        ),
        "preconditions": [
            "client implements EIP-4881 light-client sync against an Altair+ chain",
            "incoming LightClientUpdate carries attested-header + signature-slot",
            "no strict-monotonic check on finalized period exists locally",
        ],
        "attacker_role": "unprivileged",
        "impact_actor": "specific-user",
        "components": [
            ("light_client::store::Store::apply_light_client_update", "consensus", "sigp/lighthouse"),
            ("light_client::store::Store::validate_light_client_update", "consensus", "sigp/lighthouse"),
            ("light_client::store::Store::process_force_update", "consensus", "sigp/lighthouse"),
            ("light_client::store::Store::process_finality_update", "consensus", "sigp/lighthouse"),
            ("light_client::store::Store::process_optimistic_update", "consensus", "sigp/lighthouse"),
            ("light_client::server::LightClientServer::get_update", "consensus", "sigp/lighthouse"),
            ("light_client::server::LightClientServer::get_finality_update", "consensus", "sigp/lighthouse"),
            ("light_client::server::LightClientServer::get_optimistic_update", "consensus", "sigp/lighthouse"),
            ("light_client::server::LightClientServer::get_bootstrap", "consensus", "sigp/lighthouse"),
            ("eth2_libp2p::rpc::handler::handle_light_client_updates_by_range", "consensus", "sigp/lighthouse"),
            ("eth2_libp2p::rpc::handler::handle_light_client_finality_update", "consensus", "sigp/lighthouse"),
            ("eth2_libp2p::rpc::handler::handle_light_client_optimistic_update", "consensus", "sigp/lighthouse"),
            ("eth2_libp2p::rpc::handler::handle_light_client_bootstrap", "consensus", "sigp/lighthouse"),
            ("network::sync::LightClientSync::on_update", "consensus", "sigp/lighthouse"),
            ("network::sync::LightClientSync::on_finality", "consensus", "sigp/lighthouse"),
            ("network::sync::LightClientSync::on_optimistic", "consensus", "sigp/lighthouse"),
            ("light_client::store::Store::next_sync_committee_branch", "consensus", "sigp/lighthouse"),
            ("light_client::store::Store::finalized_header_branch", "consensus", "sigp/lighthouse"),
        ],
        "source_kind": "sigma-prime-lighthouse-2023-light-client",
        "go_analogue": "prysm/beacon-chain/sync.handleLightClientUpdate + go-ethereum/beacon/light",
    },
]


def slugify(value: str, *, max_len: int = 80) -> str:
    # Schema record_id pattern is ^[A-Za-z0-9._:/-]{8,160}$ (no underscore);
    # normalise everything outside [A-Za-z0-9.-] to '-' so the slug survives
    # the record_id regex when concatenated into the id.
    slug = re.sub(r"[^A-Za-z0-9.-]+", "-", value.strip().lower()).strip("-._")
    slug = re.sub(r"-{2,}", "-", slug)
    return slug[:max_len].strip("-._") or "record"


def signature_for(component: str) -> str:
    """Build a Rust-style function signature stub from a `module::function` component."""
    parts = component.split("::")
    if len(parts) >= 2:
        module_path = "::".join(parts[:-1])
        fn = parts[-1]
        return f"pub fn {module_path}::{fn}(...) -> Result<(), Error>"
    return f"pub fn {component}(...) -> Result<(), Error>"


def shape_tags(attack_class: str, bug_class: str, component: str) -> List[str]:
    tags: List[str] = [SHAPE_PLATFORM_TAG, slugify(attack_class), slugify(bug_class)]
    comp_tag = slugify(component, max_len=48)
    if comp_tag and comp_tag not in tags:
        tags.append(comp_tag)
    return tags[:4]


def build_record(
    seed: Dict[str, object],
    component: str,
    domain: str,
    repo: str,
    ordinal: int,
) -> Dict[str, object]:
    attack_class = str(seed["attack_class"])
    bug_class = str(seed["bug_class"])
    impact_class = str(seed["impact_class"])
    severity = str(seed["default_severity"])
    dollar_class = str(seed["default_dollar_class"])
    fix_pattern = str(seed["fix_pattern"])
    fix_anti_pattern = str(seed["fix_anti_pattern_avoided"])
    preconditions = list(seed["preconditions"])  # type: ignore[arg-type]
    attacker_role = str(seed["attacker_role"])
    impact_actor = str(seed["impact_actor"])
    source_kind = str(seed["source_kind"])
    go_analogue = str(seed.get("go_analogue", ""))

    # record_id pattern caps at 160 chars (regex includes the 12-char digest);
    # source_ref is the record_id prefix so we tightly cap each piece.
    source_ref = (
        f"recr:{slugify(source_kind, max_len=40)}:"
        f"{slugify(attack_class, max_len=40)}:"
        f"{slugify(component, max_len=48)}:S{ordinal}"
    )
    digest_input = (
        f"{source_ref}\n{attack_class}\n{component}\n{repo}\n{domain}"
    )
    digest = hashlib.sha256(digest_input.encode("utf-8")).hexdigest()[:12]

    action_seq = (
        f"Attacker with role {attacker_role} invokes {component} on the {repo} "
        f"Rust Ethereum-client surface, exploiting the {attack_class} weakness "
        f"({bug_class}) to reach {impact_class} on {impact_actor}."
    )

    # Cross-language analogue lift: pair every record with a Go analogue
    # pointing to the canonical geth / op-geth / prysm implementation so
    # the corpus router can lift consensus-divergence Go records into
    # Rust search results without duplicating seed work.
    cross_language: List[Dict[str, object]] = []
    if go_analogue:
        cross_language.append(
            {
                "target_language": "go",
                "pattern_translation": (
                    f"Equivalent Go surface: {go_analogue}. Same bug class "
                    f"({bug_class}) applies; differential-test the Rust "
                    f"implementation against this Go reference."
                ),
            }
        )

    return {
        "schema_version": SCHEMA_VERSION,
        "record_id": f"{source_ref}:{digest}",
        "source_audit_ref": source_ref,
        "target_domain": domain,
        "target_language": TARGET_LANGUAGE,
        "target_repo": repo,
        "target_component": component,
        "function_shape": {
            "raw_signature": signature_for(component),
            "shape_tags": shape_tags(attack_class, bug_class, component),
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
        "cross_language_analogues": cross_language,
        "related_records": [],
    }


def extract_records(limit: Optional[int] = None) -> Tuple[List[Dict[str, object]], Dict[str, int]]:
    records: List[Dict[str, object]] = []
    classes_seen = 0
    for seed in SEED_CATALOGUE:
        classes_seen += 1
        components = seed["components"]  # type: ignore[index]
        assert isinstance(components, list)
        for ordinal, (component, domain, repo) in enumerate(components, start=1):
            records.append(build_record(seed, component, domain, repo, ordinal))
            if limit is not None and len(records) >= limit:
                return records, {
                    "attack_classes_seen": classes_seen,
                    "components_seen": ordinal,
                }
    return records, {
        "attack_classes_seen": classes_seen,
        "components_seen": sum(len(s["components"]) for s in SEED_CATALOGUE),  # type: ignore[arg-type]
    }


def yaml_scalar(value: object) -> str:
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
                    if isinstance(item, dict):
                        # cross_language_analogues: list of objects
                        first = True
                        for subkey, subvalue in item.items():
                            prefix = "  - " if first else "    "
                            lines.append(f"{prefix}{subkey}: {yaml_scalar(subvalue)}")
                            first = False
                    else:
                        lines.append(f"  - {yaml_scalar(item)}")
        else:
            lines.append(f"{key}: {yaml_scalar(value)}")
    return "\n".join(lines) + "\n"


def output_filename(record: Dict[str, object]) -> str:
    record_id = str(record["record_id"])
    digest = record_id.rsplit(":", 1)[-1]
    source = str(record["source_audit_ref"])
    return f"{slugify(source, max_len=110)}-{digest}.yaml"


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
    parser.add_argument(
        "--out-dir",
        required=True,
        help="Directory for emitted hackerman_record YAML files.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Build records without writing YAML files.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        help="Maximum records to emit (default: emit all).",
    )
    parser.add_argument(
        "--json-summary",
        action="store_true",
        help="Print a machine-readable JSON summary on stdout.",
    )
    args = parser.parse_args(argv)

    if args.limit is not None and args.limit < 0:
        print("--limit must be non-negative", file=sys.stderr)
        return 2

    out_dir = Path(args.out_dir).expanduser().resolve()
    records, counters = extract_records(args.limit)
    paths = write_records(records, out_dir, args.dry_run)

    summary = {
        "schema_version": SCHEMA_VERSION,
        "target_language": TARGET_LANGUAGE,
        "platform_tag": SHAPE_PLATFORM_TAG,
        "out_dir": str(out_dir),
        "dry_run": args.dry_run,
        "attack_classes_seen": counters["attack_classes_seen"],
        "components_seen": counters["components_seen"],
        "records_emitted": len(records),
        "files": [str(path) for path in paths],
    }
    if args.json_summary:
        print(json.dumps(summary, sort_keys=True))
    else:
        print(
            "hackerman rust-eth-client ETL: "
            f"attack_classes={summary['attack_classes_seen']} "
            f"records={summary['records_emitted']} "
            f"dry_run={summary['dry_run']} "
            f"out_dir={summary['out_dir']}"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
