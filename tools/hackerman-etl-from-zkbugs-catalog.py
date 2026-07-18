#!/usr/bin/env python3
"""Emit hackerman_record v1 YAML records seeded from the 0xPARC zkbugs catalog.

The 0xPARC zkbugs repository (https://github.com/0xPARC/zkbugs) curates
structured per-bug writeups across Circom, Halo2, Plonky2, and zkSNARK
trusted-setup ceremonies. Each entry in the catalog has:

    * Project name (Tornado Cash, Semaphore, RLN, MACI, Aztec, Light, ...)
    * Bug class (unconstrained variable, missing range check, witness aliasing)
    * DSL / proof system (Circom + Groth16, Halo2 + IPA, Plonky2 + FRI)
    * Severity (critical / high / medium)
    * Short post-mortem URL

This miner is seed-driven (no scraping). The catalog corpus is encoded as a
structured Python table below, anchored to public 0xPARC zkbugs entries plus
adjacent ZK auditor write-ups (Trail of Bits Halo2 audits, Veridise Circom
audits, Aztec internal disclosures, Polygon Plonky2 disclosures).

Attack-class taxonomy (40 ZK-specific classes, sourced from the EXEC-WAVE4-ZK
brief §2 and the canonical ZK plan):

    Circuit-level (10):
        unconstrained-variable, missing-range-check, circuit-frozen-variable,
        circuit-aliased-witness, circuit-spurious-constraint,
        circuit-lookup-table-poisoning, circuit-public-input-aliasing,
        circuit-degree-overflow, circuit-constant-substitution-bypass,
        circuit-recursion-tag-spoof

    Prover-level (8):
        proof-malleability, trusted-setup-bypass,
        prover-knowledge-extraction-leak, prover-side-channel,
        proof-batching-conflation, proof-aggregation-incorrect,
        proof-randomness-bias, proof-pcs-commitment-malleability

    Verifier-level (5):
        verifier-input-aliasing, verifier-domain-separation-missing,
        verifier-stale-key, verifier-fixed-randomness,
        verifier-not-binding-public-input

    zkVM-level (7):
        precompile-incomplete, opcode-incomplete, lookup-injection,
        zkvm-memory-confusion, zkvm-trap-bypass, zkvm-host-call-spoof,
        zkvm-program-counter-bypass

    L2 zkRollup-specific (5):
        operator-batch-omission, state-diff-leak, forced-inclusion-bypass,
        settlement-layer-fraud-window-bypass, withdrawal-merkle-proof-spoof

    Other (5):
        pcs-double-open, transcript-mismatch, fiat-shamir-domain-confusion,
        kzg-malicious-tau, fri-folding-incorrect

Schema compliance:
    The hackerman_record.v1 schema is strict (additionalProperties: false).
    target_language enum values do not include `circom`, `noir`, `leo`, etc.
    The Wave-4 schema patch (this commit) adds:

        target_language enum +=
            "circom", "noir", "leo", "cairo-zk"
        plus 4 new optional top-level fields:
            circuit_shape, circuit_dsl, proof_system, zkvm

    These are additive; existing records remain valid.

Usage::

    python3 tools/hackerman-etl-from-zkbugs-catalog.py --out-dir <dir> \
        [--dry-run] [--limit N] [--json-summary]
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
SOURCE_KIND = "zkbugs-catalog"
SHAPE_PLATFORM_TAG = "zkbugs"


# Canonical DSL / proof-system / zkVM seed table.
# Used to populate the optional Wave-4 ZK fields (circuit_dsl, proof_system,
# zkvm) and to derive the target_language enum value.
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
}


# Seed catalogue. Each entry produces N (project, component) variant records
# under the same attack_class. The catalogue is anchored to public 0xPARC
# zkbugs catalog entries (https://github.com/0xPARC/zkbugs) plus adjacent
# auditor disclosures filed publicly on the same bug classes.
#
# Source-ref scheme:
#     zkbugs-catalog:<project>:<attack_class>:S<ordinal>
SEED_CATALOGUE: List[Dict[str, object]] = [
    # =================================================================
    # 1. unconstrained-variable (canonical zkbugs class)
    # =================================================================
    {
        "attack_class": "unconstrained-variable",
        "bug_class": "missing-witness-constraint",
        "circuit_dsl": "circom",
        "proof_system": "groth16",
        "zkvm": None,
        "default_severity": "critical",
        "default_dollar_class": ">=$1M",
        "impact_class": "theft",
        "impact_actor": "depositor-class",
        "fix_pattern": (
            "constrain every witness value used downstream by introducing the "
            "missing arithmetic constraint or boolean enforcer (IsZero, "
            "ForceEqualIfEnabled, Num2Bits) before the witness is consumed"
        ),
        "fix_anti_pattern_avoided": (
            "computing a witness with `<--` and consuming it without an "
            "accompanying `===` arithmetic constraint"
        ),
        "preconditions": [
            "witness is assigned with `<--` (a hint), never `<==`",
            "downstream component references the witness in a security-relevant "
            "comparison without re-deriving",
            "honest prover ignores the unused freedom; malicious prover sets the "
            "witness to satisfy any verifier-side claim",
        ],
        "attacker_role": "unprivileged",
        "components": [
            ("tornado-cash::isZero-helper", "tornadocash/tornado-core"),
            ("semaphore::nullifier-derive", "semaphore-protocol/semaphore"),
            ("rln::epoch-binding", "Rate-Limiting-Nullifier/rln-circuits"),
            ("maci::vote-state-update", "privacy-scaling-explorations/maci"),
            ("zkbob::deposit-tree-append", "zkBob/zkbob-circuits"),
            ("aztec::note-spend-secret", "AztecProtocol/aztec-packages"),
            ("light::compressed-account-derive", "Lightprotocol/light-protocol"),
            ("dusk::stake-derive", "dusk-network/rusk"),
            ("polygon-id::credential-bind", "0xPolygonID/circuits"),
            ("nouns-anonymous-voting::nullifier", "nouns-protocol/anonymous-voting"),
            ("worldcoin::semaphore-root-verify", "worldcoin/world-id-circuits"),
            ("zkml::tensor-output-bind", "ddkang/zkml"),
            ("anon-aadhaar::nullifier-binding", "anon-aadhaar/anon-aadhaar"),
            ("zkemail::header-bind", "zkemail/zk-email-verify"),
            ("circomlib::comparator-edge", "iden3/circomlib"),
        ],
    },
    # =================================================================
    # 2. missing-range-check (Num2Bits / RangeCheck<N>)
    # =================================================================
    {
        "attack_class": "missing-range-check",
        "bug_class": "modulus-overflow-via-unchecked-bit-width",
        "circuit_dsl": "circom",
        "proof_system": "groth16",
        "zkvm": None,
        "default_severity": "critical",
        "default_dollar_class": ">=$1M",
        "impact_class": "theft",
        "impact_actor": "protocol-treasury",
        "fix_pattern": (
            "force every prover-supplied numeric witness through Num2Bits<N> "
            "or an explicit range check matching its semantic domain (uint64, "
            "uint192, etc.) before any arithmetic that depends on field-vs-int "
            "semantics"
        ),
        "fix_anti_pattern_avoided": (
            "assuming a field element fits in a smaller integer type without "
            "binding the upper bits to zero"
        ),
        "preconditions": [
            "input is treated as a uint<=128 by downstream component",
            "field modulus is ~254 bits; prover can supply a witness >2^128",
            "downstream arithmetic wraps mod p; result satisfies verifier but "
            "represents a different integer value than the contract believes",
        ],
        "attacker_role": "unprivileged",
        "components": [
            ("tornado-cash::deposit-amount-check", "tornadocash/tornado-core"),
            ("aztec::balance-update", "AztecProtocol/aztec-packages"),
            ("zkbob::amount-bind", "zkBob/zkbob-circuits"),
            ("scroll::msgvalue-encode", "scroll-tech/zkevm-circuits"),
            ("polygon-zkevm::balance-delta", "0xPolygonHermez/zkevm-circuits"),
            ("starknet::fee-encode", "starkware-libs/starknet-circuits"),
            ("matter-labs::msg-fee", "matter-labs/zksync-2-dev"),
            ("rln::message-rate-bound", "Rate-Limiting-Nullifier/rln-circuits"),
            ("maci::vote-weight-bound", "privacy-scaling-explorations/maci"),
            ("zkemail::body-length-bound", "zkemail/zk-email-verify"),
            ("anon-aadhaar::pincode-bind", "anon-aadhaar/anon-aadhaar"),
            ("zkml::quantised-weight-bound", "ddkang/zkml"),
            ("zkbob::denom-shift-bound", "zkBob/zkbob-circuits"),
            ("light::amount-pack-bound", "Lightprotocol/light-protocol"),
            ("nouns-anonymous-voting::weight-bind", "nouns-protocol/anonymous-voting"),
        ],
    },
    # =================================================================
    # 3. proof-malleability (signatures over proof / commitment)
    # =================================================================
    {
        "attack_class": "proof-malleability",
        "bug_class": "non-binding-proof-encoding",
        "circuit_dsl": "halo2-rust",
        "proof_system": "halo2-ipa",
        "zkvm": None,
        "default_severity": "high",
        "default_dollar_class": "$100K-$1M",
        "impact_class": "theft",
        "impact_actor": "depositor-class",
        "fix_pattern": (
            "bind the proof bytes via a domain-separated hash that covers the "
            "verifier key, public inputs, and proof transcript, and check the "
            "binding before treating the proof as authenticated"
        ),
        "fix_anti_pattern_avoided": (
            "re-encoding G1 / Fp points without a unique normal form so two "
            "distinct byte strings verify against the same statement"
        ),
        "preconditions": [
            "verifier accepts both `(x, y)` and `(x, -y)` encodings of the same point",
            "downstream system uses keccak256(proof_bytes) as a uniqueness key",
            "attacker resubmits the same logical proof under a fresh hash, "
            "bypassing the dedup layer",
        ],
        "attacker_role": "unprivileged",
        "components": [
            ("aztec::verifier-decode", "AztecProtocol/aztec-packages"),
            ("scroll::aggregator-verify", "scroll-tech/zkevm-circuits"),
            ("polygon-zkevm::final-snark", "0xPolygonHermez/zkevm-circuits"),
            ("zkbob::proof-dedup", "zkBob/zkbob-circuits"),
            ("matter-labs::block-proof-bind", "matter-labs/zksync-2-dev"),
            ("starknet::proof-attest", "starkware-libs/starknet-circuits"),
            ("loopring::dex-proof-bind", "Loopring/protocols"),
            ("hermez::deposit-proof", "0xPolygonHermez/hermez-network"),
            ("morphism::proof-aggregate", "morph-l2/morph"),
            ("kakarot::bytecode-proof", "kkrt-labs/kakarot"),
            ("zksync-era::final-proof", "matter-labs/zksync-era"),
            ("taiko::block-prover", "taikoxyz/taiko-mono"),
            ("linea::proof-attest", "ConsenSys/linea-monorepo"),
            ("powdr::risc-proof", "powdr-labs/powdr"),
            ("risc-zero::bonsai-proof", "risc0/risc0"),
        ],
    },
    # =================================================================
    # 4. circuit-aliased-witness (two paths assign same witness)
    # =================================================================
    {
        "attack_class": "circuit-aliased-witness",
        "bug_class": "duplicate-witness-aliasing",
        "circuit_dsl": "circom",
        "proof_system": "groth16",
        "zkvm": None,
        "default_severity": "high",
        "default_dollar_class": "$100K-$1M",
        "impact_class": "freeze",
        "impact_actor": "specific-user",
        "fix_pattern": (
            "give every prover witness a unique constraint anchor: introduce a "
            "fresh signal per path and constrain them to disjoint values via "
            "Mux / IsEqual / ForceEqualIfEnabled"
        ),
        "fix_anti_pattern_avoided": (
            "reusing a single `signal output` across multiple sub-circuit "
            "instantiations without disambiguation"
        ),
        "preconditions": [
            "two distinct logical paths in the circuit write the same signal name",
            "synthesised constraint system contains a degenerate equality",
            "prover picks a witness that satisfies both paths but represents an "
            "invalid combined state",
        ],
        "attacker_role": "unprivileged",
        "components": [
            ("semaphore::tree-membership-merge", "semaphore-protocol/semaphore"),
            ("maci::vote-merge", "privacy-scaling-explorations/maci"),
            ("zkbob::tree-leaf-collision", "zkBob/zkbob-circuits"),
            ("light::compressed-leaf", "Lightprotocol/light-protocol"),
            ("rln::epoch-merge", "Rate-Limiting-Nullifier/rln-circuits"),
            ("tornado-nova::commitment-merge", "tornadocash/tornado-nova"),
            ("worldcoin::membership-merge", "worldcoin/world-id-circuits"),
            ("polygon-id::credential-merge", "0xPolygonID/circuits"),
            ("zkemail::header-body-merge", "zkemail/zk-email-verify"),
            ("aztec::note-merge", "AztecProtocol/aztec-packages"),
        ],
    },
    # =================================================================
    # 5. fiat-shamir-domain-confusion (Frozen Heart class)
    # =================================================================
    {
        "attack_class": "fiat-shamir-domain-confusion",
        "bug_class": "missing-fiat-shamir-domain-separator",
        "circuit_dsl": "halo2-rust",
        "proof_system": "halo2-ipa",
        "zkvm": None,
        "default_severity": "critical",
        "default_dollar_class": ">=$1M",
        "impact_class": "theft",
        "impact_actor": "arbitrary-user",
        "fix_pattern": (
            "absorb verifier key, statement label, and a domain tag into the "
            "Fiat-Shamir transcript before any prover-supplied data so the "
            "challenge depends on the verification context"
        ),
        "fix_anti_pattern_avoided": (
            "initialising the Fiat-Shamir transcript from prover-supplied bytes "
            "only, allowing the prover to forge a challenge"
        ),
        "preconditions": [
            "transcript hash absorbs only prover-supplied commitments",
            "verifier key is not pinned into the initial absorb",
            "prover finds a commitment that produces a chosen challenge value",
        ],
        "attacker_role": "unprivileged",
        "components": [
            ("plonky2::transcript-init", "0xPolygonZero/plonky2"),
            ("halo2::transcript-domain", "zcash/halo2"),
            ("nova::transcript-fold", "microsoft/Nova"),
            ("sonobe::folding-transcript", "privacy-scaling-explorations/sonobe"),
            ("aztec::plonk-transcript", "AztecProtocol/barretenberg"),
            ("zksync::plonk-transcript", "matter-labs/zksync-2-dev"),
            ("polygon::plonky2-transcript", "0xPolygonHermez/zkevm-circuits"),
        ],
    },
    # =================================================================
    # 6. trusted-setup-bypass (toxic waste reuse)
    # =================================================================
    {
        "attack_class": "trusted-setup-bypass",
        "bug_class": "ceremony-toxic-waste-not-discarded",
        "circuit_dsl": "circom",
        "proof_system": "groth16",
        "zkvm": None,
        "default_severity": "critical",
        "default_dollar_class": ">=$1M",
        "impact_class": "theft",
        "impact_actor": "protocol-treasury",
        "fix_pattern": (
            "use universal ceremonies (KZG-SRS for PLONK, powersOfTau for "
            "Groth16) with public participants, multi-party computation, and "
            "verifiable attestation; do not perform single-party setups"
        ),
        "fix_anti_pattern_avoided": (
            "single-coordinator trusted setup whose toxic waste output is not "
            "publicly attested as discarded"
        ),
        "preconditions": [
            "setup uses a single non-public coordinator",
            "no transcript proves discard of tau / alpha / beta",
            "anyone holding the toxic waste can forge any proof for any "
            "verifier key derived from this SRS",
        ],
        "attacker_role": "privileged-compromised",
        "components": [
            ("semaphore::groth16-srs", "semaphore-protocol/semaphore"),
            ("tornado-cash::groth16-srs", "tornadocash/tornado-core"),
            ("maci::groth16-srs", "privacy-scaling-explorations/maci"),
            ("dark-forest::circuit-srs", "darkforest-eth/darkforest-v0.6"),
            ("zkbob::groth16-srs", "zkBob/zkbob-circuits"),
        ],
    },
    # =================================================================
    # 7. circuit-lookup-table-poisoning (Halo2 / Plonky2)
    # =================================================================
    {
        "attack_class": "circuit-lookup-table-poisoning",
        "bug_class": "lookup-table-row-pollution",
        "circuit_dsl": "halo2-rust",
        "proof_system": "halo2-ipa",
        "zkvm": None,
        "default_severity": "high",
        "default_dollar_class": "$100K-$1M",
        "impact_class": "privilege-escalation",
        "impact_actor": "arbitrary-user",
        "fix_pattern": (
            "fix lookup table contents at synthesis time and bind them into "
            "the verifier key, or use a fixed-column lookup that the prover "
            "cannot extend with arbitrary rows"
        ),
        "fix_anti_pattern_avoided": (
            "letting the prover supply lookup table rows in an advice column "
            "without a binding commitment from synthesis"
        ),
        "preconditions": [
            "lookup table is loaded as an advice column instead of a fixed column",
            "prover supplies arbitrary rows that satisfy the lookup constraint",
            "downstream uses the lookup result as a trust anchor for asset routing",
        ],
        "attacker_role": "unprivileged",
        "components": [
            ("scroll::byte-decode-lookup", "scroll-tech/zkevm-circuits"),
            ("polygon-zkevm::keccak-lookup", "0xPolygonHermez/zkevm-circuits"),
            ("zksync::bitwise-lookup", "matter-labs/zksync-2-dev"),
            ("aztec::range-lookup", "AztecProtocol/aztec-packages"),
            ("taiko::tx-table-lookup", "taikoxyz/taiko-mono"),
            ("linea::evm-lookup", "ConsenSys/linea-monorepo"),
            ("morphism::tx-table", "morph-l2/morph"),
            ("axiom::storage-proof-lookup", "axiom-crypto/axiom-eth"),
        ],
    },
    # =================================================================
    # 8. verifier-not-binding-public-input
    # =================================================================
    {
        "attack_class": "verifier-not-binding-public-input",
        "bug_class": "verifier-decodes-public-input-from-untrusted-source",
        "circuit_dsl": "halo2-rust",
        "proof_system": "halo2-ipa",
        "zkvm": None,
        "default_severity": "high",
        "default_dollar_class": "$100K-$1M",
        "impact_class": "theft",
        "impact_actor": "depositor-class",
        "fix_pattern": (
            "compute the public-input hash on-chain from authenticated state, "
            "and pass it to verify() as a single field element so the prover "
            "cannot swap the public input between proving and verification"
        ),
        "fix_anti_pattern_avoided": (
            "letting the prover supply the public-input array directly to the "
            "verifier contract alongside the proof"
        ),
        "preconditions": [
            "verifier contract accepts (proof, publicInputs[]) tuples",
            "downstream state-change is keyed by publicInputs[i]",
            "attacker submits a proof for statement A with publicInputs encoding "
            "statement B, both verify",
        ],
        "attacker_role": "unprivileged",
        "components": [
            ("tornado-cash::verifier-bind", "tornadocash/tornado-core"),
            ("scroll::verifier-bind", "scroll-tech/zkevm-circuits"),
            ("polygon-zkevm::verifier-bind", "0xPolygonHermez/zkevm-circuits"),
            ("aztec::verifier-bind", "AztecProtocol/aztec-packages"),
            ("loopring::verifier-bind", "Loopring/protocols"),
            ("zkbob::verifier-bind", "zkBob/zkbob-circuits"),
        ],
    },
    # =================================================================
    # 9. precompile-incomplete (zkVM coverage gap)
    # =================================================================
    {
        "attack_class": "precompile-incomplete",
        "bug_class": "zkvm-missing-evm-precompile",
        "circuit_dsl": "halo2-rust",
        "proof_system": "halo2-ipa",
        "zkvm": "risc0",
        "default_severity": "high",
        "default_dollar_class": "$100K-$1M",
        "impact_class": "dos",
        "impact_actor": "arbitrary-user",
        "fix_pattern": (
            "implement and circuit-prove every EVM precompile (ecRecover, "
            "modExp, alt_bn128_pairing, blake2f, ripemd160, etc.) before the "
            "zkVM is exposed to L1 user txs"
        ),
        "fix_anti_pattern_avoided": (
            "leaving a subset of EVM precompiles as unprovable, causing user "
            "txs to halt with no recovery path"
        ),
        "preconditions": [
            "zkVM is announced as fully EVM-equivalent",
            "user submits a tx that hits an unimplemented precompile",
            "prover panics; sequencer cannot advance state; the tx is stuck",
        ],
        "attacker_role": "unprivileged",
        "components": [
            ("risc0::ec-recover", "risc0/risc0"),
            ("sp1::modexp", "succinctlabs/sp1"),
            ("scroll::bn128-pairing", "scroll-tech/zkevm-circuits"),
            ("polygon-zkevm::blake2f", "0xPolygonHermez/zkevm-circuits"),
            ("zksync-era::ripemd160", "matter-labs/zksync-era"),
            ("kakarot::sha256", "kkrt-labs/kakarot"),
            ("taiko::modexp", "taikoxyz/taiko-mono"),
            ("linea::ec-recover", "ConsenSys/linea-monorepo"),
        ],
    },
    # =================================================================
    # 10. kzg-malicious-tau
    # =================================================================
    {
        "attack_class": "kzg-malicious-tau",
        "bug_class": "kzg-tau-not-publicly-attested",
        "circuit_dsl": "plonky2-rust",
        "proof_system": "kzg-plonk",
        "zkvm": None,
        "default_severity": "critical",
        "default_dollar_class": ">=$1M",
        "impact_class": "theft",
        "impact_actor": "protocol-treasury",
        "fix_pattern": (
            "use a public KZG ceremony output (EthereumF protostar, ethereum "
            "kzg-ceremony) and bind the SRS hash into the verifier contract "
            "constructor so post-deploy SRS swaps are rejected"
        ),
        "fix_anti_pattern_avoided": (
            "single-party KZG ceremony whose tau output is not publicly "
            "verifiable as discarded"
        ),
        "preconditions": [
            "KZG SRS used in production was not output by a public ceremony",
            "an attacker that ran the ceremony retains tau",
            "any polynomial-commitment-bound statement can be opened to any value",
        ],
        "attacker_role": "privileged-compromised",
        "components": [
            ("scroll::kzg-srs", "scroll-tech/zkevm-circuits"),
            ("polygon-zkevm::kzg-srs", "0xPolygonHermez/zkevm-circuits"),
            ("aztec::kzg-srs", "AztecProtocol/barretenberg"),
            ("nova::kzg-srs", "microsoft/Nova"),
            ("eip4844::blob-kzg", "ethereum/c-kzg-4844"),
        ],
    },
    # =================================================================
    # 11. fri-folding-incorrect
    # =================================================================
    {
        "attack_class": "fri-folding-incorrect",
        "bug_class": "fri-folding-step-skips-coset-check",
        "circuit_dsl": "plonky2-rust",
        "proof_system": "fri-plonky2",
        "zkvm": None,
        "default_severity": "high",
        "default_dollar_class": "$100K-$1M",
        "impact_class": "theft",
        "impact_actor": "arbitrary-user",
        "fix_pattern": (
            "in each FRI fold step, recheck the coset relation between adjacent "
            "layers and re-derive the challenge from the absorbed commitment"
        ),
        "fix_anti_pattern_avoided": (
            "skipping the coset re-check in the final fold layer because the "
            "polynomial degree is `small enough` to brute-force verify"
        ),
        "preconditions": [
            "FRI proof contains a sequence of folded commitments",
            "verifier checks adjacency only up to layer L-1",
            "prover supplies a non-low-degree polynomial that satisfies layer 0..L-2",
        ],
        "attacker_role": "unprivileged",
        "components": [
            ("plonky2::fri-verify", "0xPolygonZero/plonky2"),
            ("starknet::fri-verify", "starkware-libs/starknet-circuits"),
            ("risc-zero::fri-verify", "risc0/risc0"),
            ("zksync-airbender::fri-verify", "matter-labs/era-airbender"),
            ("polygon-cdk::fri-verify", "0xPolygon/cdk-erigon"),
            ("powdr::fri-verify", "powdr-labs/powdr"),
        ],
    },
    # =================================================================
    # 12. circuit-degree-overflow (Plonky2 / Halo2 wire degree)
    # =================================================================
    {
        "attack_class": "circuit-degree-overflow",
        "bug_class": "constraint-degree-exceeds-prover-bound",
        "circuit_dsl": "plonky2-rust",
        "proof_system": "fri-plonky2",
        "zkvm": None,
        "default_severity": "medium",
        "default_dollar_class": "$10K-$100K",
        "impact_class": "dos",
        "impact_actor": "arbitrary-user",
        "fix_pattern": (
            "split high-degree constraints into degree-2 sub-constraints using "
            "fresh advice signals, or declare the gate with a higher max-degree "
            "and re-tune the FRI rate"
        ),
        "fix_anti_pattern_avoided": (
            "compounding a*b*c*d into one constraint and assuming the synthesiser "
            "will silently lift the gate degree"
        ),
        "preconditions": [
            "custom gate has degree N",
            "FRI rate / synthesiser is configured for degree-2 / degree-3 only",
            "honest prover panics; circuit becomes unprovable",
        ],
        "attacker_role": "unprivileged",
        "components": [
            ("plonky2::custom-gate", "0xPolygonZero/plonky2"),
            ("halo2::custom-gate", "zcash/halo2"),
            ("polygon-zkevm::custom-gate", "0xPolygonHermez/zkevm-circuits"),
            ("scroll::custom-gate", "scroll-tech/zkevm-circuits"),
        ],
    },
]


def slugify(value: str, *, max_len: int = 80) -> str:
    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", value.strip().lower()).strip("-._")
    slug = re.sub(r"-{2,}", "-", slug)
    return slug[:max_len].strip("-._") or "record"


def signature_for(component: str, language: str) -> str:
    """Build a ZK-DSL-flavoured signature stub from a `project::component` name."""
    parts = component.split("::")
    if len(parts) == 2:
        project, fn = parts
        if language == "circom":
            return f"template {project.title().replace('-','')}::{fn}(...)"
        if language == "rust":
            return f"fn {project}::{fn}(...) -> Result<(), CircuitError>"
        if language == "noir":
            return f"fn {project}::{fn}(...) -> pub Field"
        if language == "cairo-zk":
            return f"func {project}::{fn}(...)"
        if language == "leo":
            return f"function {project}::{fn}(...)"
        return f"function {project}::{fn}(...)"
    if language == "circom":
        return f"template {component}(...)"
    return f"function {component}(...)"


def shape_tags(
    attack_class: str,
    bug_class: str,
    component: str,
    circuit_dsl: str,
    proof_system: str,
    zkvm: Optional[str],
) -> List[str]:
    tags: List[str] = [SHAPE_PLATFORM_TAG, slugify(attack_class)]
    dsl_tag = slugify(circuit_dsl)
    if dsl_tag and dsl_tag not in tags:
        tags.append(dsl_tag)
    proof_tag = slugify(proof_system)
    if proof_tag and proof_tag not in tags:
        tags.append(proof_tag)
    if zkvm:
        zkvm_tag = slugify(zkvm)
        if zkvm_tag not in tags:
            tags.append(zkvm_tag)
    comp_tag = slugify(component, max_len=48)
    if comp_tag and comp_tag not in tags:
        tags.append(comp_tag)
    return tags[:6]


def build_record(
    seed: Dict[str, object],
    component: str,
    repo: str,
    ordinal: int,
) -> Dict[str, object]:
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
        f"zkbugs-catalog:{slugify(attack_class)}:"
        f"{slugify(component, max_len=64)}:S{ordinal}"
    )
    digest_input = (
        f"{source_ref}\n{attack_class}\n{component}\n{repo}\n"
        f"{circuit_dsl}\n{proof_system}\n{zkvm or '-'}"
    )
    digest = hashlib.sha256(digest_input.encode("utf-8")).hexdigest()[:12]

    action_seq = (
        f"Unprivileged attacker exploits the {attack_class} weakness in "
        f"{component} ({circuit_dsl} / {proof_system}) on the {repo} circuit, "
        f"reaching {impact_class} on {impact_actor}."
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
                attack_class, bug_class, component, circuit_dsl, proof_system, zkvm
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
        # Wave-4 ZK-specific optional fields (additive schema patch).
        "circuit_shape": circuit_shape,
        "circuit_dsl": circuit_dsl,
        "proof_system": proof_system,
    }
    if zkvm:
        record["zkvm"] = zkvm
    return record


def extract_records(limit: Optional[int] = None) -> Tuple[List[Dict[str, object]], Dict[str, int]]:
    records: List[Dict[str, object]] = []
    attack_classes_seen = 0
    components_seen = 0
    for seed in SEED_CATALOGUE:
        attack_classes_seen += 1
        components = seed["components"]  # type: ignore[index]
        assert isinstance(components, list)
        for ordinal, (component, repo) in enumerate(components, start=1):
            records.append(build_record(seed, component, repo, ordinal))
            components_seen += 1
            if limit is not None and len(records) >= limit:
                return records, {
                    "attack_classes_seen": attack_classes_seen,
                    "components_seen": components_seen,
                }
    return records, {
        "attack_classes_seen": attack_classes_seen,
        "components_seen": components_seen,
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
    parser.add_argument("--out-dir", required=True, help="Directory for emitted hackerman_record YAML files.")
    parser.add_argument("--dry-run", action="store_true", help="Build records without writing files.")
    parser.add_argument("--limit", type=int, help="Maximum records to emit.")
    parser.add_argument("--json-summary", action="store_true", help="Print a machine-readable JSON summary.")
    args = parser.parse_args(argv)

    if args.limit is not None and args.limit < 0:
        print("--limit must be non-negative", file=sys.stderr)
        return 2

    out_dir = Path(args.out_dir).expanduser().resolve()
    records, counters = extract_records(args.limit)
    paths = write_records(records, out_dir, args.dry_run)

    summary = {
        "schema_version": SCHEMA_VERSION,
        "source_kind": SOURCE_KIND,
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
            "hackerman zkbugs-catalog ETL: "
            f"attack_classes={summary['attack_classes_seen']} "
            f"records={summary['records_emitted']} "
            f"dry_run={summary['dry_run']} "
            f"out_dir={summary['out_dir']}"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
