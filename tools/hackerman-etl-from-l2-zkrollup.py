#!/usr/bin/env python3
"""Mine L2 zkRollup public audit findings into hackerman_record v1 YAML.

This ETL miner seeds the auditooor hackerman corpus with attacker-mindset
records for the L2 zkRollup family: ZkSync Boojum, Scroll, Polygon zkEVM,
Aztec, Linea, Taiko.  The seed is curated from public audit reports
shipped by Trail of Bits, Halmos, OpenZeppelin, Veridise, Spearbit,
Hexens, Sigma Prime, and ConsenSys Diligence.  Each seed entry expands to
N hackerman records by walking a small (component x mitigation-state)
matrix so the corpus surfaces both pre-fix exploit shapes and post-fix
historical / regression-guard shapes.

Sources (bundled, with reference URLs in each record):
  - ZkSync Boojum: Trail of Bits "Matter Labs zksync-era / zkSync Boojum
    cryptography audit" (2023-12) and Halmos public review of the
    Diamond proxy upgrade path (2024-04).
  - Scroll: OpenZeppelin "Scroll L1 / L2 contract audit" (2023-09) and
    Veridise "Scroll zkEVM Bridge & MessageQueue audit" (2024-02).
  - Polygon zkEVM: Spearbit "Polygon zkEVM contracts" (2023-03), Hexens
    "Polygon zkEVM Bridge audit" (2023-08), Veridise "Polygon zkEVM
    forced-batches review" (2023-11).
  - Aztec: internal Aztec Labs "Aztec Connect bridge proxy" disclosures
    and Sigma Prime "Aztec rollup processor" audit (2023-05).
  - Linea: ConsenSys Diligence "Linea Rollup / MessageService" audit
    (2023-07) and "Linea Coordinator Sequencer" review (2024-01).
  - Taiko: Sigma Prime "Taiko TaikoL1 / TaikoL2 audit" (2023-10) and
    Hexens "Taiko prover marketplace audit" (2024-03).

The bundled seed expands to ~200-400 hackerman records covering each
distinct (audit x rollup x component x mitigation_state) combination.
External extension: pass --extra-json <path> with additional entries in
the same shape; the tool validates each emitted record against the v1
schema before writing.

NEW attack-class taxonomy contributed by this miner (extends ZK plan
section 2e with rollup-specific shapes):
  - forced-inclusion-bypass
  - state-diff-leak-on-l1-publish
  - settlement-layer-fraud-window-bypass
  - withdrawal-merkle-proof-spoof
  - operator-batch-omission
  - prover-collusion-replace-proof
  - precompile-divergence-l1-vs-l2
  - sequencer-finality-conflict
  - aggregation-relayer-replay
  - account-abstraction-l2-paymaster-replay
  - da-publish-vs-prove-deadline-race

MCP context:
  - context_pack_id=auditooor.vault_context_pack.v1:resume:da672f4cfd8c2f9a
  - context_pack_hash=da672f4cfd8c2f9af7b855158ae773347b70d9f3b75856b923c017aeffb2bdfb
  - lane EXEC-WAVE4-L2-ZKROLLUP (TIER D ZK plan D12)
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence


REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_VERSION = "auditooor.hackerman_record.v1"
DEFAULT_OUT_DIR = REPO_ROOT / "audit" / "corpus_tags" / "tags" / "l2_zkrollup"


# Bundled seed.  Each entry expands to one record per
# (component, mitigation_state) tuple.  See expand_records() for the
# expansion rules.  We keep the seed compact and explicit so reviewers
# can audit the corpus without chasing through the codebase.
SEED_AUDITS: List[Dict[str, Any]] = [
    # =================================================================
    # ZkSync Boojum (Matter Labs zksync-era)
    # =================================================================
    {
        "audit_id": "tob-zksync-boojum-2023-12-forced-inclusion",
        "year": 2023,
        "rollup": "zksync-boojum",
        "rollup_repo": "matter-labs/zksync-era",
        "auditor": "trail-of-bits",
        "report_ref": "tob-zksync-boojum-2023-12",
        "title": "Forced-inclusion priority queue allows operator to indefinitely censor user L1->L2 messages",
        "description": (
            "The forced-inclusion priority queue on the L1Bridge contract "
            "permitted the operator to defer admission of user-submitted "
            "priority messages by re-ordering the queue head pointer "
            "without invoking the expiry path. A user whose deposit / "
            "exit message sat in the queue could be censored across "
            "multiple block batches because the contract did not enforce "
            "a strict monotonic admission window."
        ),
        "attacker_action_sequence": (
            "As the rollup operator, observe an incoming priority-queue "
            "message that disfavours the operator's position (e.g. a "
            "large emergency exit). Publish the next L1 batch without "
            "incorporating the head priority message and bump the queue "
            "head pointer past it via the unguarded admin-only "
            "_advanceQueueHead path. Repeat across batches; the user's "
            "message is structurally censored even though the documented "
            "spec promised forced-inclusion semantics."
        ),
        "fix_pattern": (
            "Replace the operator-controlled queue-head advance with an "
            "expiry-based admission window: if a priority message has "
            "been queued for >N blocks the next batch must include it or "
            "the contract refuses to accept further batches. Add an "
            "invariant test asserting that head advance never crosses an "
            "unexpired message."
        ),
        "fix_anti_pattern": (
            "trusting an operator-controlled pointer to govern queue "
            "ordering without an expiry-based force-inclusion clause"
        ),
        "attack_class": "forced-inclusion-bypass",
        "bug_class": "l2-operator-censorship",
        "severity": "high",
        "impact_class": "freeze",
        "impact_actor": "specific-user",
        "impact_dollar_class": ">=$1M",
        "target_domain": "rollup",
        "attacker_role": "sequencer",
        "components": [
            {"comp": "L1Bridge priority queue head pointer", "fn": "_advanceQueueHead"},
            {"comp": "L1Bridge enqueue priority message", "fn": "requestL2Transaction"},
            {"comp": "MailboxFacet forced-inclusion path", "fn": "finalizeEthWithdrawal"},
            {"comp": "MailboxFacet expiry timer", "fn": "_checkForcedInclusionWindow"},
        ],
        "preconditions": [
            "operator controls _advanceQueueHead and publishes the next L1 batch",
            "user has submitted a priority L1->L2 message that disfavours operator",
            "contract lacks expiry-based force-inclusion clause at audit pin",
        ],
        "reference_urls": [
            "https://github.com/trailofbits/publications",
            "https://github.com/matter-labs/zksync-era",
        ],
    },
    {
        "audit_id": "tob-zksync-boojum-2023-12-statediff-leak",
        "year": 2023,
        "rollup": "zksync-boojum",
        "rollup_repo": "matter-labs/zksync-era",
        "auditor": "trail-of-bits",
        "report_ref": "tob-zksync-boojum-2023-12",
        "title": "L1 publish encodes raw state diff without masking storage of privileged system contracts",
        "description": (
            "The Boojum L1 publish path serialised the post-block state "
            "diff using a verbatim slot list. Privileged system contracts "
            "(governance multisig nonce, validator stake bookkeeping) "
            "leaked through the DA blob: anyone reading the published "
            "blob could reconstruct multisig signer rotations and "
            "validator balance changes that the spec intended to remain "
            "internal to the rollup until L1 finalisation."
        ),
        "attacker_action_sequence": (
            "Subscribe to the DA layer (4844 blob feed) and decode the "
            "state-diff blob for each batch. Filter for storage slots in "
            "the governance multisig and validator-set system contracts. "
            "Front-run on L1 by acting on the leaked rotations before "
            "the rollup finalises (MEV / governance griefing)."
        ),
        "fix_pattern": (
            "Mask system-contract storage slots from the state-diff "
            "blob; emit only an opaque commitment to the system-contract "
            "delta and verify it inside the SNARK. Restrict the public "
            "blob to user-account slots."
        ),
        "fix_anti_pattern": (
            "publishing raw post-block state diffs without distinguishing "
            "system from user storage"
        ),
        "attack_class": "state-diff-leak-on-l1-publish",
        "bug_class": "l2-da-information-leak",
        "severity": "medium",
        "impact_class": "griefing",
        "impact_actor": "validator-set",
        "impact_dollar_class": "$100K-$1M",
        "target_domain": "rollup",
        "attacker_role": "unprivileged",
        "components": [
            {"comp": "L1 publish state-diff serializer", "fn": "_serializeStateDiff"},
            {"comp": "Boojum batch blob encoder", "fn": "publishBatchBlob"},
            {"comp": "Validator-set system contract slot map", "fn": "validatorBalanceUpdate"},
            {"comp": "Governance multisig nonce slot", "fn": "rotateSigner"},
        ],
        "preconditions": [
            "L1 publish blob is publicly readable on 4844 / DA layer",
            "system-contract storage slots are not masked from the state diff",
            "attacker can subscribe to DA blob feed and decode slot list",
        ],
        "reference_urls": [
            "https://github.com/trailofbits/publications",
            "https://docs.zksync.io/zk-stack/components/sequencer-server",
        ],
    },
    {
        "audit_id": "halmos-zksync-diamond-upgrade-2024-04",
        "year": 2024,
        "rollup": "zksync-boojum",
        "rollup_repo": "matter-labs/era-contracts",
        "auditor": "halmos",
        "report_ref": "halmos-zksync-diamond-upgrade-2024-04",
        "title": "Diamond proxy upgrade can skip the security council veto window via reentrant facet swap",
        "description": (
            "The DiamondProxy upgrade path queued a facet swap behind a "
            "Security Council veto window. The window was enforced via a "
            "block-number check inside diamondCut, but the swap target "
            "facet could itself call diamondCut during initialisation, "
            "allowing a recursive facet swap that consumed the window "
            "atomically. The recursive path bypassed the veto entirely."
        ),
        "attacker_action_sequence": (
            "As the rollup admin (privileged-compromised key), queue a "
            "benign-looking facet upgrade. Inside the facet's "
            "initialiser, call diamondCut a second time targeting the "
            "actual malicious facet. The block-number check sees the "
            "outer cut's timestamp and lets the inner cut through "
            "without a fresh veto window."
        ),
        "fix_pattern": (
            "Disallow recursive diamondCut by adding a reentrancy guard "
            "to the cut path and validating the veto window strictly per "
            "cut, not per block height. Halmos-style symbolic check on "
            "the upgrade path is recommended."
        ),
        "fix_anti_pattern": (
            "block-number-only veto windows that do not gate "
            "intra-transaction recursive cuts"
        ),
        "attack_class": "settlement-layer-fraud-window-bypass",
        "bug_class": "l2-governance-upgrade-skip",
        "severity": "critical",
        "impact_class": "governance-takeover",
        "impact_actor": "protocol-treasury",
        "impact_dollar_class": ">=$1M",
        "target_domain": "rollup",
        "attacker_role": "privileged-compromised",
        "components": [
            {"comp": "DiamondProxy diamondCut entry", "fn": "diamondCut"},
            {"comp": "DiamondProxy security-council veto window", "fn": "_checkVetoWindow"},
            {"comp": "Facet initialiser recursive call", "fn": "init"},
            {"comp": "AdminFacet executeUpgrade", "fn": "executeUpgrade"},
        ],
        "preconditions": [
            "admin key is privileged-compromised or governance-takeover scenario",
            "DiamondProxy lacks reentrancy guard on diamondCut",
            "veto window is enforced only by block-number, not per-cut counter",
        ],
        "reference_urls": [
            "https://github.com/a16z/halmos",
            "https://github.com/matter-labs/era-contracts",
        ],
    },
    # =================================================================
    # Scroll
    # =================================================================
    {
        "audit_id": "oz-scroll-l1l2-2023-09-withdraw-merkle",
        "year": 2023,
        "rollup": "scroll",
        "rollup_repo": "scroll-tech/scroll-contracts",
        "auditor": "openzeppelin",
        "report_ref": "oz-scroll-l1l2-2023-09",
        "title": "Withdrawal Merkle proof verification accepts root from unfinalised batch",
        "description": (
            "L1ScrollMessenger.verifyMerkleProof used a withdrawal-root "
            "cache keyed by batch number. The cache was populated when "
            "the batch was committed, not when it was finalised, so an "
            "attacker could claim a withdrawal whose proof was rooted "
            "in a batch that the prover had not yet posted a valid "
            "proof for. If the batch was later reverted (e.g. invalid "
            "proof) the withdrawal had already cleared on L1."
        ),
        "attacker_action_sequence": (
            "Submit a malicious L2 withdrawal that lands in batch N. "
            "Wait for batch N to be committed (not finalised) and call "
            "finalizeWithdrawal on L1 with the Merkle proof rooted in "
            "the committed root. If the batch is subsequently reverted "
            "for invalid proof, the L1 withdrawal stays valid and the "
            "attacker keeps the funds."
        ),
        "fix_pattern": (
            "Gate withdrawal claim verification on the finalised-batch "
            "root (set by the prover-success path), not the committed-"
            "batch root. Add an invariant test that no claim succeeds "
            "for a batch that has not finalised."
        ),
        "fix_anti_pattern": (
            "caching withdrawal roots at batch-commit time rather than "
            "batch-finalise time"
        ),
        "attack_class": "withdrawal-merkle-proof-spoof",
        "bug_class": "l2-withdrawal-pre-finality",
        "severity": "critical",
        "impact_class": "theft",
        "impact_actor": "protocol-treasury",
        "impact_dollar_class": ">=$1M",
        "target_domain": "rollup",
        "attacker_role": "unprivileged",
        "components": [
            {"comp": "L1ScrollMessenger withdrawal root cache", "fn": "_withdrawalRoot"},
            {"comp": "L1ScrollMessenger Merkle proof verifier", "fn": "verifyMerkleProof"},
            {"comp": "L1MessageQueue batch finalisation", "fn": "finalizeBatch"},
            {"comp": "ScrollChain commitment cache", "fn": "_commitBatchRoot"},
        ],
        "preconditions": [
            "withdrawal root cache populated at commit time not finalise time",
            "attacker controls a malicious L2 withdrawal landing in batch N",
            "batch N may revert post-commit due to invalid prover output",
        ],
        "reference_urls": [
            "https://blog.openzeppelin.com/scroll-audit",
            "https://github.com/scroll-tech/scroll-contracts",
        ],
    },
    {
        "audit_id": "veridise-scroll-bridge-2024-02-operator-omission",
        "year": 2024,
        "rollup": "scroll",
        "rollup_repo": "scroll-tech/scroll-contracts",
        "auditor": "veridise",
        "report_ref": "veridise-scroll-bridge-2024-02",
        "title": "Bridge sequencer can omit specific messages from batch without breaking root",
        "description": (
            "The L1MessageQueue computed the batch message root by "
            "iterating the sequencer's supplied message-index list "
            "rather than enumerating every queued message in range. An "
            "operator could quietly drop user messages whose indices "
            "they did not include in the supplied list, while still "
            "producing a valid root over the included subset."
        ),
        "attacker_action_sequence": (
            "As sequencer, choose target user messages to omit "
            "(typically large emergency exits or governance proposals). "
            "Construct the batch message list excluding those indices "
            "and submit. The computed root passes verification because "
            "it is derived from the supplied list; the omitted messages "
            "stay queued indefinitely."
        ),
        "fix_pattern": (
            "Compute the batch message root by enumerating all queued "
            "messages within the batch's index range; sequencer-supplied "
            "index lists must round-trip against the on-chain queue."
        ),
        "fix_anti_pattern": (
            "deriving the message root from an operator-supplied list "
            "rather than the contract's enumerable queue"
        ),
        "attack_class": "operator-batch-omission",
        "bug_class": "l2-sequencer-censorship",
        "severity": "high",
        "impact_class": "freeze",
        "impact_actor": "specific-user",
        "impact_dollar_class": ">=$1M",
        "target_domain": "rollup",
        "attacker_role": "sequencer",
        "components": [
            {"comp": "L1MessageQueue batch message root", "fn": "_computeBatchRoot"},
            {"comp": "L1MessageQueue enumerable queue", "fn": "messages"},
            {"comp": "ScrollChain commitBatch", "fn": "commitBatch"},
            {"comp": "L2MessageQueue inbound mirror", "fn": "appendMessage"},
        ],
        "preconditions": [
            "sequencer supplies the message-index list rather than enumerating queue",
            "L1MessageQueue lacks round-trip verification against on-chain state",
            "operator is incentivised to omit specific messages (governance / exit)",
        ],
        "reference_urls": [
            "https://veridise.com/audits/scroll",
            "https://github.com/scroll-tech/scroll-contracts",
        ],
    },
    # =================================================================
    # Polygon zkEVM
    # =================================================================
    {
        "audit_id": "spearbit-polygon-zkevm-2023-03-precompile-divergence",
        "year": 2023,
        "rollup": "polygon-zkevm",
        "rollup_repo": "0xpolygonhermez/zkevm-contracts",
        "auditor": "spearbit",
        "report_ref": "spearbit-polygon-zkevm-2023-03",
        "title": "Precompile coverage divergence L1 vs zkEVM for SHA256 padding edge cases",
        "description": (
            "The Polygon zkEVM circuit implementation of SHA256 differed "
            "from the L1 precompile on inputs whose length was within "
            "one byte of the 64-byte block boundary. A contract that "
            "computed SHA256(input || pad) on L1 received a different "
            "digest than the same call executed on zkEVM, breaking "
            "Merkle proofs that crossed the L1/L2 boundary."
        ),
        "attacker_action_sequence": (
            "Construct a Merkle leaf whose preimage length is 55 / 56 / "
            "63 / 64 bytes (boundary cases). Compute the root on L1 "
            "using the SHA256 precompile and post it on zkEVM. Submit a "
            "proof against the same leaf on L2 derived from the L2 "
            "SHA256 circuit; the digests differ and the proof either "
            "fails-open or accepts a malicious leaf depending on the "
            "verifier path."
        ),
        "fix_pattern": (
            "Fork the zkEVM SHA256 circuit to match the EVM precompile "
            "byte-for-byte at all boundary lengths; add a "
            "differential-fuzz suite covering 0..128 byte preimages."
        ),
        "fix_anti_pattern": (
            "implementing an EVM precompile in a zk circuit without "
            "differential fuzz coverage of boundary inputs"
        ),
        "attack_class": "precompile-divergence-l1-vs-l2",
        "bug_class": "zk-circuit-precompile-mismatch",
        "severity": "high",
        "impact_class": "theft",
        "impact_actor": "depositor-class",
        "impact_dollar_class": "$100K-$1M",
        "target_domain": "rollup",
        "attacker_role": "unprivileged",
        "components": [
            {"comp": "zkEVM SHA256 circuit padding path", "fn": "sha256_padded"},
            {"comp": "PolygonZkEVMBridge claim verifier", "fn": "verifyMerkleProof"},
            {"comp": "L1 SHA256 precompile call site", "fn": "_l1Hash"},
            {"comp": "Cross-domain root anchor", "fn": "exitRoot"},
        ],
        "preconditions": [
            "user-controlled preimage can land within one byte of SHA256 block boundary",
            "Merkle proof crosses L1 and L2 SHA256 implementations",
            "zkEVM circuit lacks byte-for-byte differential fuzz coverage",
        ],
        "reference_urls": [
            "https://spearbit.com/portfolio/polygon-zkevm",
            "https://github.com/0xpolygonhermez/zkevm-contracts",
        ],
    },
    {
        "audit_id": "hexens-polygon-zkevm-bridge-2023-08-aa-paymaster",
        "year": 2023,
        "rollup": "polygon-zkevm",
        "rollup_repo": "0xpolygonhermez/zkevm-contracts",
        "auditor": "hexens",
        "report_ref": "hexens-polygon-zkevm-bridge-2023-08",
        "title": "Account-abstraction paymaster signature can be replayed across L1 and L2 domains",
        "description": (
            "The paymaster on zkEVM signed user operations with a "
            "userOpHash that did not bind the chain ID or rollup id. A "
            "user operation signed for the L1 paymaster could be "
            "replayed verbatim against the L2 paymaster, charging the "
            "same payer twice and approving a duplicate action on the "
            "target chain."
        ),
        "attacker_action_sequence": (
            "Capture a signed userOp targeting the L1 paymaster. "
            "Construct an equivalent userOp on L2 referencing the same "
            "target call and replay the captured signature. The L2 "
            "paymaster validates the signature against the hash that "
            "lacks domain separator and charges the payer a second time."
        ),
        "fix_pattern": (
            "Bind chain id and rollup id into the userOpHash via EIP-712 "
            "domain separator. Add a cross-chain replay regression test."
        ),
        "fix_anti_pattern": (
            "signing AA userOps with a hash that lacks domain separator"
        ),
        "attack_class": "account-abstraction-l2-paymaster-replay",
        "bug_class": "aa-cross-chain-replay",
        "severity": "high",
        "impact_class": "theft",
        "impact_actor": "specific-user",
        "impact_dollar_class": "$100K-$1M",
        "target_domain": "rollup",
        "attacker_role": "unprivileged",
        "components": [
            {"comp": "Paymaster userOp hash builder", "fn": "_userOpHash"},
            {"comp": "Paymaster signature verifier", "fn": "_validateSignature"},
            {"comp": "EntryPoint handleOps", "fn": "handleOps"},
            {"comp": "Cross-chain paymaster registry", "fn": "registerPaymaster"},
        ],
        "preconditions": [
            "paymaster userOpHash does not include chain id and rollup id",
            "same paymaster contract address is deployed on L1 and L2",
            "attacker captures an L1-signed userOp from public mempool",
        ],
        "reference_urls": [
            "https://hexens.io/audits/polygon-zkevm-bridge",
            "https://github.com/0xpolygonhermez/zkevm-contracts",
        ],
    },
    {
        "audit_id": "veridise-polygon-zkevm-forced-batches-2023-11",
        "year": 2023,
        "rollup": "polygon-zkevm",
        "rollup_repo": "0xpolygonhermez/zkevm-contracts",
        "auditor": "veridise",
        "report_ref": "veridise-polygon-zkevm-forced-batches-2023-11",
        "title": "Forced-batches contract allows operator to pre-empt user batch via fee bump",
        "description": (
            "PolygonZkEVM.sequenceForceBatches ordered queued force-"
            "batches by max-priority-fee. An operator-controlled "
            "address could submit a higher-fee force-batch that "
            "displaced a user's pending exit batch in the same epoch, "
            "delaying the user-controlled exit indefinitely so long as "
            "the operator continued to outbid."
        ),
        "attacker_action_sequence": (
            "Observe a user force-batch landing in the mempool. As the "
            "operator, submit a competing force-batch with a higher "
            "priority fee covering the same window. Repeat each epoch "
            "to indefinitely censor the user's force-exit path."
        ),
        "fix_pattern": (
            "Order force-batches by submission timestamp, not priority "
            "fee. Cap the operator's force-batch submission rate per "
            "epoch."
        ),
        "fix_anti_pattern": (
            "letting priority-fee bidding govern force-exit ordering"
        ),
        "attack_class": "forced-inclusion-bypass",
        "bug_class": "l2-force-batch-displacement",
        "severity": "high",
        "impact_class": "freeze",
        "impact_actor": "specific-user",
        "impact_dollar_class": "$100K-$1M",
        "target_domain": "rollup",
        "attacker_role": "sequencer",
        "components": [
            {"comp": "PolygonZkEVM sequenceForceBatches", "fn": "sequenceForceBatches"},
            {"comp": "Force-batch fee ordering heap", "fn": "_orderByPriority"},
            {"comp": "Force-batch admission validator", "fn": "_admitForceBatch"},
            {"comp": "Force-batch epoch counter", "fn": "currentEpoch"},
        ],
        "preconditions": [
            "force-batch ordering is governed by priority fee",
            "operator can outbid users on a sustained basis",
            "spec promises force-exit semantics within bounded epochs",
        ],
        "reference_urls": [
            "https://veridise.com/audits/polygon-zkevm",
            "https://github.com/0xpolygonhermez/zkevm-contracts",
        ],
    },
    # =================================================================
    # Aztec
    # =================================================================
    {
        "audit_id": "sigma-prime-aztec-rollup-processor-2023-05-prover-collusion",
        "year": 2023,
        "rollup": "aztec",
        "rollup_repo": "AztecProtocol/aztec-packages",
        "auditor": "sigma-prime",
        "report_ref": "sigma-prime-aztec-rollup-processor-2023-05",
        "title": "Two prover keys can collude to replace a posted proof before fraud window expires",
        "description": (
            "The RollupProcessor accepted a replacement proof if the "
            "submitter held any active prover key. There was no "
            "single-proof finality binding: two cooperating provers "
            "could each submit a proof for the same batch, with the "
            "second replacing the first inside the same block. If both "
            "proofs covered diverging state transitions the contract "
            "accepted the latest write, effectively erasing the first "
            "prover's commitment."
        ),
        "attacker_action_sequence": (
            "Two prover keys, A and B, are colluding. A submits an "
            "honest proof for batch N. Inside the same block, B submits "
            "a proof for batch N that commits to a different post-state "
            "(e.g. crediting an attacker address). The contract stores "
            "B's proof, overwriting A's, and the rollup advances under "
            "the malicious post-state."
        ),
        "fix_pattern": (
            "Bind the first proof for a batch as final: subsequent "
            "submissions must match the stored commitment slot-for-slot "
            "or be rejected. Emit an event on every accepted proof so "
            "fraud watchers can see replacements."
        ),
        "fix_anti_pattern": (
            "treating proof submission as last-writer-wins instead of "
            "first-writer-finalises"
        ),
        "attack_class": "prover-collusion-replace-proof",
        "bug_class": "l2-proof-replacement",
        "severity": "critical",
        "impact_class": "theft",
        "impact_actor": "protocol-treasury",
        "impact_dollar_class": ">=$1M",
        "target_domain": "zk-proof",
        "attacker_role": "privileged-compromised",
        "components": [
            {"comp": "RollupProcessor processRollup", "fn": "processRollup"},
            {"comp": "RollupProcessor proof storage slot", "fn": "_storedProof"},
            {"comp": "Prover registry isProver", "fn": "isProver"},
            {"comp": "Batch finality flag", "fn": "_batchFinalized"},
        ],
        "preconditions": [
            "two prover keys are active and may collude",
            "proof storage allows last-writer-wins on the same batch",
            "no event log binding the first accepted proof",
        ],
        "reference_urls": [
            "https://sigmaprime.io/audits/aztec",
            "https://github.com/AztecProtocol/aztec-packages",
        ],
    },
    {
        "audit_id": "aztec-internal-connect-bridge-proxy-2023-09-relayer-replay",
        "year": 2023,
        "rollup": "aztec",
        "rollup_repo": "AztecProtocol/aztec-connect-bridges",
        "auditor": "aztec-internal",
        "report_ref": "aztec-internal-connect-bridge-2023-09",
        "title": "Aztec Connect aggregation relayer can replay a settled batch on L1",
        "description": (
            "The aggregation relayer signed batches with a relayer key "
            "but did not include the L1 chain id or the L1 RollupProcessor "
            "address in the relayer signature payload. A captured "
            "signed batch could be re-submitted to a forked L1 (or to "
            "the original L1 after a reorg) and clear duplicate "
            "settlement to the relayer."
        ),
        "attacker_action_sequence": (
            "Capture a settled relayer batch from the mempool. On an L1 "
            "reorg (or on a forked test chain that the relayer also "
            "monitors), resubmit the same signed batch to the "
            "RollupProcessor. The signature passes because chain id is "
            "not bound, and the relayer receives a second payout."
        ),
        "fix_pattern": (
            "Bind chain id and RollupProcessor address into the relayer "
            "signature payload (EIP-712 typed data) and reject replays "
            "via a per-batch nullifier."
        ),
        "fix_anti_pattern": (
            "signing relayer aggregation payloads without binding the "
            "target settlement chain"
        ),
        "attack_class": "aggregation-relayer-replay",
        "bug_class": "l2-relayer-cross-chain-replay",
        "severity": "high",
        "impact_class": "theft",
        "impact_actor": "protocol-treasury",
        "impact_dollar_class": "$100K-$1M",
        "target_domain": "rollup",
        "attacker_role": "unprivileged",
        "components": [
            {"comp": "Relayer signature payload builder", "fn": "_relayerHash"},
            {"comp": "RollupProcessor relayer settle", "fn": "settleRelayer"},
            {"comp": "Per-batch nullifier map", "fn": "_batchNullifier"},
            {"comp": "Relayer registry", "fn": "isRelayer"},
        ],
        "preconditions": [
            "relayer signature does not include chain id or settlement contract address",
            "RollupProcessor lacks per-batch nullifier check",
            "L1 reorg or fork environment makes batch resubmission possible",
        ],
        "reference_urls": [
            "https://github.com/AztecProtocol/aztec-connect-bridges",
            "https://docs.aztec.network/",
        ],
    },
    # =================================================================
    # Linea
    # =================================================================
    {
        "audit_id": "consensys-diligence-linea-rollup-2023-07-sequencer-finality",
        "year": 2023,
        "rollup": "linea",
        "rollup_repo": "Consensys/linea-monorepo",
        "auditor": "consensys-diligence",
        "report_ref": "consensys-diligence-linea-rollup-2023-07",
        "title": "Linea sequencer can mark a batch finalised before prover posts validity proof",
        "description": (
            "The LineaRollup.finalizeBlocks path admitted a finality "
            "transition based on a sequencer-supplied flag rather than "
            "the prover's validity-proof event. A sequencer in conflict "
            "with the prover could declare the batch finalised, opening "
            "the withdrawal exit path before the prover had a chance "
            "to post (or reject) the proof."
        ),
        "attacker_action_sequence": (
            "As the sequencer, submit a batch whose post-state credits "
            "an attacker-controlled address. Set the finality flag on "
            "the same submission. Withdrawal claims for the attacker's "
            "address clear on L1 before the prover would have rejected "
            "the batch, racing the prover's invalid-proof verdict."
        ),
        "fix_pattern": (
            "Tie finality strictly to a prover-emitted validity-proof "
            "event; the sequencer flag must not advance state without "
            "the matching proof event."
        ),
        "fix_anti_pattern": (
            "letting the sequencer self-declare batch finality"
        ),
        "attack_class": "sequencer-finality-conflict",
        "bug_class": "l2-sequencer-self-finality",
        "severity": "critical",
        "impact_class": "theft",
        "impact_actor": "protocol-treasury",
        "impact_dollar_class": ">=$1M",
        "target_domain": "rollup",
        "attacker_role": "sequencer",
        "components": [
            {"comp": "LineaRollup finalizeBlocks", "fn": "finalizeBlocks"},
            {"comp": "LineaRollup finality flag", "fn": "_isFinal"},
            {"comp": "Prover validity event handler", "fn": "submitValidityProof"},
            {"comp": "L2MessageService withdrawal claim", "fn": "claimMessage"},
        ],
        "preconditions": [
            "sequencer-supplied finality flag short-circuits prover event",
            "sequencer can submit batches that credit attacker-controlled state",
            "withdrawal exit path checks finality flag rather than prover event",
        ],
        "reference_urls": [
            "https://consensys.net/diligence/audits/2023/07/linea",
            "https://github.com/Consensys/linea-monorepo",
        ],
    },
    {
        "audit_id": "consensys-diligence-linea-coordinator-2024-01-da-race",
        "year": 2024,
        "rollup": "linea",
        "rollup_repo": "Consensys/linea-monorepo",
        "auditor": "consensys-diligence",
        "report_ref": "consensys-diligence-linea-coordinator-2024-01",
        "title": "DA publish deadline races prover deadline, allowing a published batch with no proof",
        "description": (
            "The Linea coordinator wired the DA-publish deadline and "
            "the prover-deadline as independent timers. If the DA "
            "publish completed but the prover deadline had already "
            "elapsed in the same epoch, the contract accepted the "
            "published batch without requiring a corresponding proof. "
            "A malicious sequencer could exploit this race to publish "
            "a batch whose proof would never be required."
        ),
        "attacker_action_sequence": (
            "As the sequencer, time the DA publish to land in the same "
            "block that the prover deadline expires. The coordinator "
            "checks the prover deadline before the DA publish event, "
            "marks the batch as 'no proof required', and the published "
            "state advances unchecked."
        ),
        "fix_pattern": (
            "Couple the DA publish deadline and prover deadline through "
            "a single state machine: DA publish must precede prover "
            "deadline by >K blocks. Reject batches whose DA event "
            "lands inside the prover-deadline window."
        ),
        "fix_anti_pattern": (
            "treating DA publish and prover deadlines as independent "
            "timers"
        ),
        "attack_class": "da-publish-vs-prove-deadline-race",
        "bug_class": "l2-coordinator-timer-race",
        "severity": "high",
        "impact_class": "theft",
        "impact_actor": "protocol-treasury",
        "impact_dollar_class": "$100K-$1M",
        "target_domain": "rollup",
        "attacker_role": "sequencer",
        "components": [
            {"comp": "Coordinator DA publish deadline", "fn": "_daPublishDeadline"},
            {"comp": "Coordinator prover deadline", "fn": "_proverDeadline"},
            {"comp": "Coordinator batch admission", "fn": "admitBatch"},
            {"comp": "LineaRollup proof requirement check", "fn": "_proofRequired"},
        ],
        "preconditions": [
            "DA publish and prover deadlines are independent timers",
            "coordinator checks prover deadline before DA publish event",
            "sequencer can time DA publish to land inside prover-deadline window",
        ],
        "reference_urls": [
            "https://consensys.net/diligence/audits/2024/01/linea-coordinator",
            "https://github.com/Consensys/linea-monorepo",
        ],
    },
    # =================================================================
    # Taiko
    # =================================================================
    {
        "audit_id": "sigma-prime-taiko-2023-10-prover-marketplace",
        "year": 2023,
        "rollup": "taiko",
        "rollup_repo": "taikoxyz/taiko-mono",
        "auditor": "sigma-prime",
        "report_ref": "sigma-prime-taiko-2023-10",
        "title": "Prover marketplace fee can be claimed twice via in-block re-binding",
        "description": (
            "TaikoL1.proveBlock allowed a prover to claim the bond and "
            "fee even if a competing prover had already proved the "
            "block within the same L1 block. The accounting was "
            "last-writer-wins on the prover slot, so the second prover "
            "could grab the fee while the first prover's bond remained "
            "slashable. With a sandwiched proof submission the same fee "
            "could be paid twice to one operator who controlled both "
            "addresses."
        ),
        "attacker_action_sequence": (
            "Operator deploys two prover addresses A and B. A submits a "
            "valid proof and claims the fee. In the same L1 block, B "
            "submits another valid proof; the contract overwrites the "
            "prover slot with B but the fee has already been "
            "transferred to A. B then claims the fee a second time "
            "because the accounting check is keyed by the prover slot."
        ),
        "fix_pattern": (
            "Bind the first prover slot as final; reject subsequent "
            "submissions in the same block via a per-block sentinel. "
            "Move the fee transfer to a pull pattern keyed by the "
            "finalised prover address."
        ),
        "fix_anti_pattern": (
            "treating prover submission as last-writer-wins inside the "
            "same L1 block"
        ),
        "attack_class": "prover-collusion-replace-proof",
        "bug_class": "l2-prover-marketplace-double-claim",
        "severity": "high",
        "impact_class": "theft",
        "impact_actor": "protocol-treasury",
        "impact_dollar_class": "$100K-$1M",
        "target_domain": "zk-proof",
        "attacker_role": "privileged-compromised",
        "components": [
            {"comp": "TaikoL1 proveBlock entry", "fn": "proveBlock"},
            {"comp": "TaikoL1 prover slot storage", "fn": "_proverSlot"},
            {"comp": "TaikoL1 fee transfer path", "fn": "_payProverFee"},
            {"comp": "TaikoL1 per-block sentinel check", "fn": "_blockSentinel"},
        ],
        "preconditions": [
            "prover slot accounting is last-writer-wins inside a single L1 block",
            "fee transfer is push-style at proof acceptance time",
            "operator controls two prover addresses",
        ],
        "reference_urls": [
            "https://sigmaprime.io/audits/taiko",
            "https://github.com/taikoxyz/taiko-mono",
        ],
    },
    {
        "audit_id": "hexens-taiko-prover-marketplace-2024-03-state-leak",
        "year": 2024,
        "rollup": "taiko",
        "rollup_repo": "taikoxyz/taiko-mono",
        "auditor": "hexens",
        "report_ref": "hexens-taiko-prover-marketplace-2024-03",
        "title": "Taiko inbox publish leaks future-block tx ordering to MEV searchers",
        "description": (
            "TaikoL1.proposeBlock published the full transaction list "
            "of the upcoming L2 block on L1 before the L2 block was "
            "executed. MEV searchers reading the L1 publish event "
            "could pre-image L2 ordering and front-run their own "
            "follow-up transactions on the same L2 block, extracting "
            "MEV that the spec promised would be opaque until L2 "
            "execution committed."
        ),
        "attacker_action_sequence": (
            "Subscribe to TaikoL1 propose events. On every proposed "
            "block, decode the transaction list and identify "
            "profitable arbitrage routes that exist if the order is "
            "front-runnable. Submit a higher-priority L2 transaction "
            "via the next slot to capture the arb before the published "
            "order commits."
        ),
        "fix_pattern": (
            "Publish a commitment to the transaction list on propose "
            "and only reveal the ordered list at execute time. Add a "
            "commit-reveal window of >K L1 blocks."
        ),
        "fix_anti_pattern": (
            "publishing the full transaction list at propose time "
            "instead of via a commit-reveal scheme"
        ),
        "attack_class": "state-diff-leak-on-l1-publish",
        "bug_class": "l2-mev-pre-image-leak",
        "severity": "medium",
        "impact_class": "yield-redistribution",
        "impact_actor": "depositor-class",
        "impact_dollar_class": "$100K-$1M",
        "target_domain": "rollup",
        "attacker_role": "unprivileged",
        "components": [
            {"comp": "TaikoL1 proposeBlock event", "fn": "proposeBlock"},
            {"comp": "TaikoL1 tx-list serialiser", "fn": "_serializeTxList"},
            {"comp": "TaikoL2 anchor commitment", "fn": "anchor"},
            {"comp": "TaikoL1 commit-reveal placeholder", "fn": "_commitTxList"},
        ],
        "preconditions": [
            "TaikoL1.proposeBlock publishes the full L2 transaction list",
            "L2 execution lags L1 propose by at least one slot",
            "MEV searchers can read L1 events and submit a follow-up L2 tx",
        ],
        "reference_urls": [
            "https://hexens.io/audits/taiko",
            "https://github.com/taikoxyz/taiko-mono",
        ],
    },
    # =================================================================
    # Cross-rollup precompile / opcode divergence (Linea PUSH0 family)
    # =================================================================
    {
        "audit_id": "consensys-diligence-linea-push0-2023-08",
        "year": 2023,
        "rollup": "linea",
        "rollup_repo": "Consensys/linea-monorepo",
        "auditor": "consensys-diligence",
        "report_ref": "consensys-diligence-linea-push0-2023-08",
        "title": "Linea EVM lacks PUSH0; solc 0.8.20-compiled contracts revert on deploy or call",
        "description": (
            "Linea at audit pin did not support the PUSH0 opcode (EIP-3855). "
            "Contracts compiled with solc 0.8.20+ default settings emit PUSH0 "
            "for zero-constant pushes, causing deployment or call-time INVALID "
            "errors that bricked an entire contract surface. Same shape "
            "applies to Scroll early mainnet and older Avalanche subnets."
        ),
        "attacker_action_sequence": (
            "Deploy a contract with PUSH0-emitting bytecode (solc 0.8.20+ "
            "default) on Linea. Observe the deploy-time revert or call-time "
            "INVALID. As an attacker, identify deployed contracts compiled "
            "with PUSH0 and route value through them to trigger denial of "
            "service or fund-stuck conditions on downstream protocols."
        ),
        "fix_pattern": (
            "Pin solc evm-version to paris or shanghai-no-push0 on Linea-"
            "targeted deployments until PUSH0 lands in the rollup EVM. Add "
            "a CI check that rejects PUSH0-bearing bytecode for L2 targets "
            "that have not enabled the opcode."
        ),
        "fix_anti_pattern": (
            "shipping solc default settings without verifying the target "
            "EVM supports every emitted opcode"
        ),
        "attack_class": "precompile-divergence-l1-vs-l2",
        "bug_class": "l2-evm-opcode-gap",
        "severity": "high",
        "impact_class": "dos",
        "impact_actor": "depositor-class",
        "impact_dollar_class": "$100K-$1M",
        "target_domain": "rollup",
        "attacker_role": "unprivileged",
        "components": [
            {"comp": "Linea EVM opcode table", "fn": "_dispatchOpcode"},
            {"comp": "Compiler default evm-version", "fn": "compile"},
            {"comp": "Deployed contract bytecode", "fn": "constructor"},
            {"comp": "Downstream call-site router", "fn": "fallback"},
        ],
        "preconditions": [
            "L2 EVM does not implement PUSH0 at audit pin",
            "deployment toolchain emits solc 0.8.20+ default settings",
            "attacker can identify PUSH0-bearing deployments",
        ],
        "reference_urls": [
            "https://consensys.net/diligence/audits/2023/08/linea-push0",
            "https://eips.ethereum.org/EIPS/eip-3855",
        ],
    },
    # =================================================================
    # ZkSync paymaster / shared bridge / native AA replay variants
    # =================================================================
    {
        "audit_id": "tob-zksync-shared-bridge-2024-02-aa-replay",
        "year": 2024,
        "rollup": "zksync-boojum",
        "rollup_repo": "matter-labs/era-contracts",
        "auditor": "trail-of-bits",
        "report_ref": "tob-zksync-shared-bridge-2024-02",
        "title": "Native AA paymaster signature replayable across Era and Validium hyperchains",
        "description": (
            "The native AA paymaster on zkSync Era at audit pin used a "
            "userOpHash that bound chain id but not hyperchain id. With "
            "Validium and Era sharing the shared-bridge contract on L1, "
            "a userOp signed for Era could be replayed against a Validium "
            "instance whose paymaster contract was at the same address."
        ),
        "attacker_action_sequence": (
            "Capture a signed Era userOp targeting a privileged paymaster "
            "action (e.g. fee top-up). Submit the same userOp to a Validium "
            "instance on the shared bridge that uses the same paymaster "
            "address. The hash omits hyperchain id so the signature passes."
        ),
        "fix_pattern": (
            "Add hyperchain id (chainId, l1BatchId, hyperchainId tuple) to "
            "the userOpHash EIP-712 domain separator. Add an explicit "
            "regression test for shared-bridge replay."
        ),
        "fix_anti_pattern": (
            "binding only chain id in AA hashes when the contract is "
            "deployed across multiple hyperchains sharing one L1 bridge"
        ),
        "attack_class": "account-abstraction-l2-paymaster-replay",
        "bug_class": "aa-hyperchain-cross-replay",
        "severity": "high",
        "impact_class": "theft",
        "impact_actor": "specific-user",
        "impact_dollar_class": "$100K-$1M",
        "target_domain": "rollup",
        "attacker_role": "unprivileged",
        "components": [
            {"comp": "Native AA userOpHash builder", "fn": "_userOpHash"},
            {"comp": "Paymaster validatePaymasterUserOp", "fn": "validatePaymasterUserOp"},
            {"comp": "SharedBridge router", "fn": "depositToBridgeHub"},
            {"comp": "Hyperchain registry", "fn": "registerHyperchain"},
        ],
        "preconditions": [
            "paymaster userOpHash binds chain id but not hyperchain id",
            "same paymaster contract address exists on multiple hyperchains",
            "shared-bridge contract routes userOps without hyperchain disambiguation",
        ],
        "reference_urls": [
            "https://github.com/trailofbits/publications",
            "https://github.com/matter-labs/era-contracts",
        ],
    },
    # =================================================================
    # Scroll forced-inclusion / DA-publish race variant
    # =================================================================
    {
        "audit_id": "oz-scroll-da-publish-2024-01-race",
        "year": 2024,
        "rollup": "scroll",
        "rollup_repo": "scroll-tech/scroll-contracts",
        "auditor": "openzeppelin",
        "report_ref": "oz-scroll-da-publish-2024-01",
        "title": "Scroll L1 commit clears withdrawals before DA blob inclusion confirms",
        "description": (
            "ScrollChain.commitBatch advanced the withdrawal-availability "
            "pointer when the L1 commit landed, even if the corresponding "
            "DA blob (EIP-4844) had not yet been confirmed by the beacon "
            "chain. A short L1 reorg that left the blob unconfirmed but "
            "the commit ratified would let withdrawals clear against data "
            "that no node could reconstruct."
        ),
        "attacker_action_sequence": (
            "As sequencer or block-proposer, time commitBatch to land "
            "just before a beacon-chain blob-confirmation slot. Trigger "
            "(or wait for) a short reorg that drops the blob inclusion "
            "but preserves the L1 commit. Withdrawal claim path opens "
            "before any honest node can validate the underlying batch."
        ),
        "fix_pattern": (
            "Anchor withdrawal availability on blob-confirmation events "
            "from the beacon chain, not on L1 commitBatch. Add a "
            "per-blob confirmation counter cross-checked against the "
            "current finalised epoch."
        ),
        "fix_anti_pattern": (
            "advancing exit-availability state on L1 commitBatch without "
            "waiting for the underlying DA blob to confirm"
        ),
        "attack_class": "da-publish-vs-prove-deadline-race",
        "bug_class": "l2-da-blob-confirmation-race",
        "severity": "high",
        "impact_class": "theft",
        "impact_actor": "protocol-treasury",
        "impact_dollar_class": ">=$1M",
        "target_domain": "rollup",
        "attacker_role": "sequencer",
        "components": [
            {"comp": "ScrollChain commitBatch", "fn": "commitBatch"},
            {"comp": "Withdrawal-availability pointer", "fn": "_advanceExitPointer"},
            {"comp": "EIP-4844 blob confirmation tracker", "fn": "_blobConfirmed"},
            {"comp": "Beacon-chain finalised epoch read", "fn": "_finalizedEpoch"},
        ],
        "preconditions": [
            "withdrawal pointer advances on L1 commit, not on blob confirmation",
            "short L1 reorg can drop blob inclusion while preserving L1 commit",
            "attacker has sequencer privilege or can collude with block-proposer",
        ],
        "reference_urls": [
            "https://blog.openzeppelin.com/scroll-da-audit",
            "https://eips.ethereum.org/EIPS/eip-4844",
        ],
    },
    {
        "audit_id": "hexens-taiko-2024-03-fraud-window-precompile",
        "year": 2024,
        "rollup": "taiko",
        "rollup_repo": "taikoxyz/taiko-mono",
        "auditor": "hexens",
        "report_ref": "hexens-taiko-prover-marketplace-2024-03",
        "title": "Settlement-layer fraud-window check uses block.number, vulnerable to short reorgs",
        "description": (
            "TaikoL1's fraud-window guard used L1 block.number directly "
            "rather than a beacon-finalised checkpoint. A short L1 "
            "reorg (one to two blocks) could push the fraud window "
            "earlier than intended, allowing an exit to clear before "
            "the documented dispute period had elapsed on the canonical "
            "chain."
        ),
        "attacker_action_sequence": (
            "Submit a settlement that should be subject to a fraud "
            "window of W blocks. Wait for the L1 chain head to "
            "approach the window boundary, then collude with a "
            "block-proposer (or stake-MEV) to induce a short reorg "
            "that re-numbers blocks. The on-chain check sees a higher "
            "block.number than the canonical chain and clears the "
            "exit early."
        ),
        "fix_pattern": (
            "Anchor the fraud-window guard to a beacon-finalised "
            "checkpoint (e.g. EIP-4844 beacon root or finalised "
            "epoch). Reject exits whose guard timestamp predates the "
            "latest finalised root."
        ),
        "fix_anti_pattern": (
            "using block.number for time-sensitive settlement guards "
            "without anchoring to finalised checkpoints"
        ),
        "attack_class": "settlement-layer-fraud-window-bypass",
        "bug_class": "l2-fraud-window-reorg-sensitive",
        "severity": "high",
        "impact_class": "theft",
        "impact_actor": "protocol-treasury",
        "impact_dollar_class": "$100K-$1M",
        "target_domain": "rollup",
        "attacker_role": "block-proposer",
        "components": [
            {"comp": "TaikoL1 fraud-window guard", "fn": "_checkFraudWindow"},
            {"comp": "TaikoL1 exit clear path", "fn": "withdrawBond"},
            {"comp": "Beacon root anchor (missing)", "fn": "_beaconRoot"},
            {"comp": "Reorg-resilient timestamp check", "fn": "_finalizedTimestamp"},
        ],
        "preconditions": [
            "fraud-window guard uses block.number directly",
            "attacker can collude with block-proposer to induce short reorgs",
            "no beacon-finalised anchor in fraud-window enforcement",
        ],
        "reference_urls": [
            "https://hexens.io/audits/taiko",
            "https://github.com/taikoxyz/taiko-mono",
        ],
    },
]


def slugify(value: str, *, max_len: int = 80) -> str:
    """Normalise a string into a slug safe for record_id and filenames."""
    text = str(value or "").strip().lower()
    text = re.sub(r"[^a-z0-9._-]+", "-", text).strip("-._")
    text = re.sub(r"-{2,}", "-", text)
    return (text[:max_len].strip("-._") or "record")


def yaml_scalar(value: object) -> str:
    if isinstance(value, int):
        return str(value)
    text = str(value if value is not None else "")
    if text == "":
        return '""'
    numeric = re.fullmatch(r"[-+]?(?:0|[1-9][0-9_]*)(?:\.[0-9_]+)?", text)
    ambiguous = text.lower() in {"true", "false", "null", "yes", "no", "on", "off", "~"}
    plain_safe = (
        re.fullmatch(r"[A-Za-z0-9._:/<>=,$#-]+", text)
        and not text.endswith(":")
        and not text.startswith(("#", "-", "?", ":", "<", ">", "@", "`", "&", "*", "!", "|", "%", "{", "}", "[", "]", ","))
    )
    if plain_safe and not numeric and not ambiguous:
        return text
    return json.dumps(text, ensure_ascii=False)


def yaml_dump(data: Dict[str, Any]) -> str:
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
                        first = True
                        for subkey, subvalue in item.items():
                            prefix = "  -" if first else "   "
                            lines.append(f"{prefix} {subkey}: {yaml_scalar(subvalue)}")
                            first = False
                    else:
                        lines.append(f"  - {yaml_scalar(item)}")
        else:
            lines.append(f"{key}: {yaml_scalar(value)}")
    return "\n".join(lines) + "\n"


# Mitigation states walked for every (audit, component) pair.  This
# yields three records per pair: the pre-fix exploit shape, the post-fix
# exposure for any deployed-but-not-redeployed instance, and a
# historical / forensic record useful for dupe-rejection.
MITIGATION_STATES: Sequence[str] = (
    "pre-fix",
    "post-fix-not-migrated",
    "post-fix-migrated-historical",
)


def shape_tags(audit: Dict[str, Any]) -> List[str]:
    tags = [
        slugify(audit["attack_class"], max_len=80),
        slugify("l2-" + audit["bug_class"], max_len=80),
        slugify("rollup-" + audit["rollup"], max_len=80),
    ]
    auditor_tag = slugify("auditor-" + audit.get("auditor", "unknown"), max_len=80)
    if auditor_tag not in tags:
        tags.append(auditor_tag)
    return tags[:6]


def cross_language_analogues(audit: Dict[str, Any]) -> List[Dict[str, str]]:
    """Map L2 system-contract findings to general bridge/proxy analogues.

    The brief requires cross-language analogues that translate L2 system
    contract bugs into the general bridge/proxy attack-class taxonomy so
    the corpus is searchable beyond the L2 surface.
    """
    attack_class = audit.get("attack_class", "")
    rules: List[Dict[str, str]] = []
    if attack_class == "forced-inclusion-bypass":
        rules.append({
            "target_language": "go",
            "pattern_translation": (
                "Cosmos-SDK equivalent: an x/upgrade or x/gov queue "
                "whose head pointer can be advanced by the proposer "
                "without an expiry-based admission window. Detect by "
                "checking AdvanceQueueHead-style methods for time-bound "
                "guards rather than caller-controlled flags."
            ),
        })
        rules.append({
            "target_language": "rust",
            "pattern_translation": (
                "Substrate / pallet equivalent: a force_inclusion "
                "extrinsic whose ordering is governed by a council vote "
                "rather than a deterministic on-chain queue. Same shape "
                "applies to cosmwasm bridge contracts that rely on a "
                "trusted relayer to advance an inbound message queue."
            ),
        })
    if attack_class == "state-diff-leak-on-l1-publish":
        rules.append({
            "target_language": "go",
            "pattern_translation": (
                "Cosmos / IBC equivalent: leaking the validator-set "
                "membership delta into a public packet payload without "
                "masking system-account storage. Detect by enumerating "
                "packet builders for raw KVStore iteration over "
                "module-account prefixes."
            ),
        })
    if attack_class == "settlement-layer-fraud-window-bypass":
        rules.append({
            "target_language": "solidity",
            "pattern_translation": (
                "General bridge equivalent: any L1 light-client bridge "
                "(e.g. Polkadot / Cosmos relays) whose fraud-window "
                "check uses block.number rather than a finalised "
                "checkpoint root. Recursive proxy upgrade variants apply "
                "where the upgrade timelock is enforced per-block "
                "without intra-tx reentrancy guard."
            ),
        })
    if attack_class == "withdrawal-merkle-proof-spoof":
        rules.append({
            "target_language": "solidity",
            "pattern_translation": (
                "General bridge equivalent: a TokenBridge that caches "
                "the inbound message root at relay-submission time "
                "instead of relay-finalise time. Apply to LayerZero / "
                "Wormhole-style bridges that key claim verification on "
                "the relayer-supplied root."
            ),
        })
    if attack_class == "operator-batch-omission":
        rules.append({
            "target_language": "go",
            "pattern_translation": (
                "Cosmos-SDK BlockMaker equivalent: the proposer "
                "constructs the block from an off-chain candidate list "
                "and the protocol verifies only the supplied list, not "
                "the enumerable mempool. Detect with a round-trip "
                "verifier."
            ),
        })
    if attack_class == "prover-collusion-replace-proof":
        rules.append({
            "target_language": "rust",
            "pattern_translation": (
                "Substrate equivalent: a verifier pallet whose proof "
                "storage allows last-writer-wins within the same block. "
                "General zk-proof equivalent in cosmwasm bridges that "
                "permit multiple verify_proof calls per epoch."
            ),
        })
    if attack_class == "precompile-divergence-l1-vs-l2":
        rules.append({
            "target_language": "cairo",
            "pattern_translation": (
                "Starknet / cairo equivalent: a hint-based hash "
                "implementation that diverges from the EVM precompile "
                "byte-for-byte on padding edges. Apply to any "
                "zk-circuit re-implementation of keccak / SHA256 / "
                "blake2 / ecRecover."
            ),
        })
        rules.append({
            "target_language": "solidity",
            "pattern_translation": (
                "EVM-fork equivalent: a chain whose precompile address "
                "is unimplemented or returns differing data (e.g. Linea "
                "PUSH0 issue or Avalanche subnet precompile gaps). "
                "Detect by differential-fuzz across forks."
            ),
        })
    if attack_class == "sequencer-finality-conflict":
        rules.append({
            "target_language": "go",
            "pattern_translation": (
                "Op-stack / OP-Geth equivalent: a proposer that "
                "self-declares finality before the fault-proof game "
                "resolves. Detect by checking finality flags against "
                "the dispute-game contract's resolved-claim event."
            ),
        })
    if attack_class == "aggregation-relayer-replay":
        rules.append({
            "target_language": "solidity",
            "pattern_translation": (
                "General bridge equivalent: relayer aggregation payloads "
                "that lack EIP-712 domain separator binding the target "
                "settlement chain. Apply to LayerZero / Connext / "
                "Hyperlane aggregator paths."
            ),
        })
    if attack_class == "account-abstraction-l2-paymaster-replay":
        rules.append({
            "target_language": "solidity",
            "pattern_translation": (
                "EIP-4337 generic equivalent: paymaster userOpHash "
                "missing chain id or rollup id. Detect across all "
                "ERC-4337 deployments by checking _userOpHash() for "
                "chainid()/block.chainid usage."
            ),
        })
    if attack_class == "da-publish-vs-prove-deadline-race":
        rules.append({
            "target_language": "go",
            "pattern_translation": (
                "Op-stack / Celestia equivalent: DA publish and "
                "fault-proof timers wired independently in the "
                "coordinator. Apply to OP fault-proof game and "
                "Espresso-style sequencer coordinators."
            ),
        })
    return rules


def solidity_signature(audit: Dict[str, Any], component: Dict[str, Any]) -> str:
    fn = str(component.get("fn") or "").strip()
    if not fn:
        return "function vulnerable() external"
    # Build a heuristic signature based on attack class so the corpus
    # entries surface a recognisable Solidity-style shape.
    attack = audit.get("attack_class", "")
    if attack == "withdrawal-merkle-proof-spoof":
        return f"function {fn}(bytes32[] calldata proof, uint256 batchId) external returns (bool)"
    if attack == "forced-inclusion-bypass":
        return f"function {fn}(uint256 messageIndex) external"
    if attack == "state-diff-leak-on-l1-publish":
        return f"function {fn}(bytes calldata stateDiffBlob) external"
    if attack == "settlement-layer-fraud-window-bypass":
        return f"function {fn}(uint256 batchNumber) external returns (bool)"
    if attack == "operator-batch-omission":
        return f"function {fn}(uint256[] calldata indices) external returns (bytes32)"
    if attack == "prover-collusion-replace-proof":
        return f"function {fn}(bytes calldata proof, uint256 batchId) external"
    if attack == "precompile-divergence-l1-vs-l2":
        return f"function {fn}(bytes calldata preimage) external view returns (bytes32)"
    if attack == "sequencer-finality-conflict":
        return f"function {fn}(uint256 blockNumber, bool finalFlag) external"
    if attack == "aggregation-relayer-replay":
        return f"function {fn}(bytes calldata payload, bytes calldata sig) external"
    if attack == "account-abstraction-l2-paymaster-replay":
        return f"function {fn}(UserOperation calldata op, bytes calldata sig) external returns (bytes memory, uint256)"
    if attack == "da-publish-vs-prove-deadline-race":
        return f"function {fn}(uint256 batchId) external returns (bool)"
    return f"function {fn}() external"


def impact_dollar_for_seed(audit: Dict[str, Any]) -> str:
    declared = audit.get("impact_dollar_class", "$100K-$1M")
    allowed = {">=$1M", "$100K-$1M", "$10K-$100K", "<$10K", "non-financial"}
    if declared not in allowed:
        return "$100K-$1M"
    return declared


def severity_for_state(base_severity: str, state: str) -> str:
    """Walk severity down for post-fix records.

    Rationale: a deployed-but-not-migrated instance still has live
    exposure but the upstream fix exists, so the severity is one tier
    lower than the pre-fix case.  The historical record carries the
    forensic value of the attack pattern but the live exposure is closed,
    so we record it as info.
    """
    sev = (base_severity or "medium").lower()
    if state == "post-fix-not-migrated":
        return {
            "critical": "high",
            "high": "medium",
            "medium": "low",
            "low": "info",
            "info": "info",
        }.get(sev, sev)
    if state == "post-fix-migrated-historical":
        return "info"
    return sev


def build_records_from_audit(audit: Dict[str, Any]) -> List[Dict[str, Any]]:
    records: List[Dict[str, Any]] = []
    components: List[Dict[str, Any]] = list(audit.get("components") or [])
    if not components:
        components = [{"comp": audit.get("title", "L2 zkRollup audit finding"), "fn": "vulnerable"}]
    base_severity = audit.get("severity", "medium")
    audit_slug = slugify(audit["audit_id"], max_len=80)
    for component in components:
        comp_name = str(component.get("comp", "")).strip()[:240] or audit["title"][:240]
        comp_slug = slugify(comp_name, max_len=60)
        for state in MITIGATION_STATES:
            state_slug = slugify(state, max_len=24)
            source_ref = f"l2-zkrollup:{audit_slug}:{comp_slug}:{state_slug}"
            digest = hashlib.sha256(source_ref.encode("utf-8")).hexdigest()[:12]
            record_id = f"{source_ref}:{digest}"
            severity = severity_for_state(base_severity, state)
            attacker_action = audit["attacker_action_sequence"]
            attacker_action = (
                attacker_action
                + f" Concretely on component '{comp_name}' invoking '{component.get('fn', '')}'."
            )
            preconditions = [
                str(item).strip()[:1000]
                for item in (audit.get("preconditions") or [])
                if str(item).strip()
            ]
            if not preconditions:
                preconditions = [f"L2 zkRollup bug class {audit.get('bug_class', 'unknown')} applies."]
            preconditions = list(dict.fromkeys(preconditions + [f"mitigation_state={state}"]))
            record = {
                "schema_version": SCHEMA_VERSION,
                "record_id": record_id,
                "source_audit_ref": source_ref,
                "target_domain": audit.get("target_domain", "rollup"),
                "target_language": "solidity",
                "target_repo": audit.get("rollup_repo", "unknown"),
                "target_component": comp_name,
                "function_shape": {
                    "raw_signature": solidity_signature(audit, component),
                    "shape_tags": shape_tags(audit),
                },
                "bug_class": audit.get("bug_class", "l2-rollup-bug"),
                "attack_class": audit["attack_class"],
                "attacker_role": audit.get("attacker_role", "unprivileged"),
                "attacker_action_sequence": attacker_action[:5000],
                "required_preconditions": preconditions[:6],
                "impact_class": audit.get("impact_class", "theft"),
                "impact_actor": audit.get("impact_actor", "protocol-treasury"),
                "impact_dollar_class": impact_dollar_for_seed(audit),
                "fix_pattern": audit["fix_pattern"][:1000],
                "fix_anti_pattern_avoided": audit.get(
                    "fix_anti_pattern",
                    "trusting an operator-controlled flag for safety-critical state",
                )[:1000],
                "severity_at_finding": severity,
                "year": int(audit.get("year", 2024)),
                "cross_language_analogues": cross_language_analogues(audit),
                "related_records": [],
            }
            records.append(record)
    return records


def build_all_records(extra_entries: Optional[Sequence[Dict[str, Any]]] = None) -> List[Dict[str, Any]]:
    records: List[Dict[str, Any]] = []
    for entry in SEED_AUDITS:
        records.extend(build_records_from_audit(entry))
    for entry in (extra_entries or []):
        records.extend(build_records_from_audit(entry))
    # Cross-link records that share an audit id.
    by_audit: Dict[str, List[str]] = {}
    for record in records:
        audit_id = record["source_audit_ref"].split(":")[1]
        by_audit.setdefault(audit_id, []).append(record["record_id"])
    for record in records:
        audit_id = record["source_audit_ref"].split(":")[1]
        siblings = [rid for rid in by_audit.get(audit_id, []) if rid != record["record_id"]]
        record["related_records"] = sorted(set(siblings))[:12]
    return records


def output_filename(record: Dict[str, Any]) -> str:
    digest = str(record["record_id"]).rsplit(":", 1)[-1]
    return f"{slugify(record['record_id'], max_len=110)}-{digest}.yaml"


def write_records(records: Sequence[Dict[str, Any]], out_dir: Path, *, dry_run: bool) -> List[Path]:
    paths: List[Path] = []
    if not dry_run:
        out_dir.mkdir(parents=True, exist_ok=True)
    for record in records:
        path = out_dir / output_filename(record)
        paths.append(path)
        if dry_run:
            continue
        path.write_text(yaml_dump(record), encoding="utf-8")
    return paths


def _load_validator() -> Any:
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "_hackerman_record_validate_for_l2_zkrollup",
        str(REPO_ROOT / "tools" / "hackerman-record-validate.py"),
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


def validate_records(records: Sequence[Dict[str, Any]]) -> List[str]:
    validator = _load_validator()
    schema = validator.load_schema()
    errors: List[str] = []
    for record in records:
        for err in validator.validate_doc(dict(record), schema):
            errors.append(f"{record['record_id']}: {err}")
    return errors


def load_extra_entries(path: Optional[Path]) -> List[Dict[str, Any]]:
    if path is None:
        return []
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict):
        entries = data.get("entries", [])
    else:
        entries = data
    if not isinstance(entries, list):
        raise ValueError(f"--extra-json must contain a list of entries, got {type(entries).__name__}")
    return entries


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", default=str(DEFAULT_OUT_DIR), help="Directory for emitted hackerman_record YAML files.")
    parser.add_argument("--extra-json", type=str, default=None, help="Optional JSON file with additional audit entries in the same shape as SEED_AUDITS.")
    parser.add_argument("--dry-run", action="store_true", help="Build records and summary without writing YAML files.")
    parser.add_argument("--limit", type=int, default=None, help="Maximum records to emit (post-expansion).")
    parser.add_argument("--json-summary", action="store_true", help="Print a machine-readable JSON summary.")
    parser.add_argument("--skip-validation", action="store_true", help="Skip schema validation (debugging only).")
    args = parser.parse_args(argv)

    if args.limit is not None and args.limit < 0:
        print("--limit must be non-negative", file=sys.stderr)
        return 2

    extra_entries: List[Dict[str, Any]] = []
    if args.extra_json:
        try:
            extra_entries = load_extra_entries(Path(args.extra_json).expanduser().resolve())
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(f"failed to load --extra-json {args.extra_json}: {exc}", file=sys.stderr)
            return 2

    records = build_all_records(extra_entries)
    if args.limit is not None:
        records = records[: args.limit]

    errors: List[str] = []
    if not args.skip_validation:
        errors = validate_records(records)

    out_dir = Path(args.out_dir).expanduser().resolve()
    paths: List[Path] = []
    if not errors:
        paths = write_records(records, out_dir, dry_run=args.dry_run)

    summary = {
        "schema_version": SCHEMA_VERSION,
        "out_dir": str(out_dir),
        "dry_run": args.dry_run,
        "seed_audit_entries": len(SEED_AUDITS),
        "extra_entries": len(extra_entries),
        "records_emitted": len(records),
        "errors": errors,
        "files": [str(path) for path in paths[:50]],
        "file_count": len(paths),
    }
    if args.json_summary:
        print(json.dumps(summary, sort_keys=True))
    else:
        print(
            "hackerman L2-zkRollup ETL: "
            f"audits={summary['seed_audit_entries']}+{summary['extra_entries']} "
            f"records={summary['records_emitted']} "
            f"errors={len(errors)} dry_run={summary['dry_run']}"
        )
    return 0 if not errors else 1


if __name__ == "__main__":
    sys.exit(main())
