#!/usr/bin/env python3
"""Hackerman ETL: ZcashFoundation/zebra published GitHub Security Advisories.

Emits, per published zebra GHSA, a TRIPLE of corpus artifacts:

  (a) one ``auditooor.hackerman_record.v1``  - the attacker-mindset finding
      record (carries attack_class + impact_class + GHSA/CWE/CVSS provenance);
  (b) one ``auditooor.invariant.v1``          - the protocol/state invariant the
      bug VIOLATED (the rule that, if held, would have prevented the bug);
  (c) one ``auditooor.detector_seed.v1``       - the SHAPE to catch the bug class
      (regex + AST hint + fp-reduction strategy + positive fixture).

All three carry ``verification_tier=tier-1-officially-disclosed`` (Rule 37:
manually verified against the published GHSA at miner-authoring time and baked
into the hard-coded ``ZEBRA_ADVISORIES`` constant set below). This mirrors the
tier-1-officially-disclosed NVD/GHSA constant set added Wave-2-A ``ad3cc4bda7``
- the data is NOT a live API pull, it is the verbatim published-advisory data
transcribed at authoring time and committed.

M14-trap discipline (per ``~/.claude/CLAUDE.md``):
  * No memory-recalled or synthesized GHSA IDs. Every id/severity/CWE/CVSS in
    ``ZEBRA_ADVISORIES`` is the verbatim published-advisory value.
  * Advisories whose full published root-cause is NOT verbatim-available at
    authoring time are NOT emitted (no fabrication of the missing advisories).
    Add them to ``ZEBRA_ADVISORIES`` as the data is verified.
  * Dedupe vs the existing hackerman corpus by ``source_audit_ref`` (the GHSA
    html_url): an advisory already present in ``--corpus-dir`` is skipped.

RELATED TOOLS (tool-duplication preflight, per CLAUDE.md operational anchor):
  * ``tools/hackerman-etl-from-github-advisory.py`` - generic GHSA REST puller
    (live ``gh api`` fetch; emits hackerman_record only, NO paired INV-* /
    detector_seed). This tool differs: zebra-specific baked dataset (tier-1-
    officially-disclosed, network-independent) AND emits the invariant +
    detector-seed TRIPLE per advisory, which the generic puller does not.
  * ``tools/hackerman-etl-from-evm-client-advisories.py`` - EVM EL/CL client
    GHSA puller (live fetch, hackerman_record only). Shape anchor for the
    record mapping here. Differs: EVM clients vs Zcash node, record-only.
  * ``tools/hackerman-etl-from-move-cve-advisory.py`` - Move CVE/advisory ETL.
    Different ecosystem (Move), different source feed.
  * ``tools/hackerman-etl-from-privacy-mixer-advisories.py`` - privacy/mixer
    advisory ETL. Different target class; no zebra/Zcash-node coverage.
  * ``tools/hackerman-etl-from-substrate-fix-history.py`` and siblings emit the
    invariant + detector-seed triple from fix-history diffs, NOT from a
    published GHSA constant set; different provenance, different tier.

GAP FILLED: a network-independent, officially-disclosed (tier-1) ETL of the
ZcashFoundation/zebra published advisories that emits the full
record + invariant + detector-seed triple. No existing tool covers zebra, and
no existing GHSA puller emits the paired INV-* / detector_seed alongside the
record.

CLI:
    python3 tools/hackerman-etl-from-zebra-advisories.py \\
        --records-dir audit/corpus_tags/tags/zebra_advisories \\
        --invariants-out audit/corpus_tags/derived/invariants_zebra_advisories.jsonl \\
        --detector-seeds-out audit/corpus_tags/derived/detector_seeds_zebra_advisories.jsonl

    # dedupe against an existing corpus tree:
    python3 tools/hackerman-etl-from-zebra-advisories.py ... \\
        --corpus-dir audit/corpus_tags/tags

    # inspect without writing:
    python3 tools/hackerman-etl-from-zebra-advisories.py --dry-run --json-summary
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml


REPO_ROOT = Path(__file__).resolve().parent.parent
RECORD_SCHEMA_VERSION = "auditooor.hackerman_record.v1"
INVARIANT_SCHEMA_VERSION = "auditooor.invariant.v1"
DETECTOR_SEED_SCHEMA_VERSION = "auditooor.detector_seed.v1"
SUMMARY_SCHEMA = "auditooor.hackerman_etl.zebra_advisories.summary.v1"
# r36-rebuttal: lane zebra-promote registered in .auditooor/agent_pathspec.json; edit scoped to this ETL tool + its test only
VERIFICATION_TIER = "tier-1-officially-disclosed"
ZEBRA_REPO = "ZcashFoundation/zebra"

# Router-stage batch id. The promote tool (promote-mined-to-canonical.py) reads
# from per-router source dirs under audit/corpus_tags/derived/<router>/<batch>/;
# the flat ``invariants_zebra_advisories.jsonl`` / ``detector_seeds_*.jsonl``
# files the ETL emits are NOT on any router's glob path, so they cannot be
# promoted to the canonical jsonls on their own. ``--router-stage`` writes the
# router-consumable batch files so a subsequent promote run lands the zebra
# invariants in invariants_pilot_audited.jsonl and the detector seeds in
# detector_seed_library_promoted.jsonl with verification_tier preserved.
ROUTER_STAGE_BATCH_ID = "zebra-advisories-2026-05-29"
INV_ROUTER_DIRNAME = "invariant_library_extended"
DET_ROUTER_DIRNAME = "detector_synthesis_v2"


def _load_record_validator() -> Any:
    spec = importlib.util.spec_from_file_location(
        "_hackerman_record_validate_zebra",
        str(REPO_ROOT / "tools" / "hackerman-record-validate.py"),
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


_RECORD_VALIDATOR = _load_record_validator()


def _load_invariant_schema() -> Dict[str, Any]:
    path = (
        REPO_ROOT
        / "audit"
        / "corpus_tags"
        / "schemas"
        / "auditooor.invariant.v1.schema.json"
    )
    return json.loads(path.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# Baked dataset: ZcashFoundation/zebra published GHSAs.
# Each entry's id/severity/cve/cvss/cwe/crate-version/root-cause is the verbatim
# published-advisory value transcribed at miner-authoring time (Rule 37
# tier-1-officially-disclosed). Only advisories whose full published root cause
# is verbatim-available are included; the rest are added as verified, never
# fabricated.
# ---------------------------------------------------------------------------


ZEBRA_ADVISORIES: List[Dict[str, Any]] = [
    {
        "ghsa": "GHSA-hhm7-qrv5-h4r6",
        "severity": "medium",
        "cve": None,
        "cvss": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H",
        "cvss_score": 5.9,
        "cwe": "CWE-696",
        "crates": [
            ("zebra-state", "<=6.0.0", "7.0.0"),
            ("zebrad", "<=4.4.1", "4.5.0"),
        ],
        "component": "zebra-state::service::non_finalized_state::Chain::push (tx_loc_by_hash index update ordering)",
        "bug_class": "toctou-index-update-before-validation",
        "attack_class": "ordering-validation-toctou",
        "attacker_role": "unprivileged",
        "impact_class": "dos",
        "impact_actor": "validator-set",
        "year": 2025,
        "summary": (
            "Repeated non-finalized shielded transaction aborts Zebra before the "
            "duplicate-nullifier rejection. Chain::push updates the tx_loc_by_hash "
            "index BEFORE running the duplicate shielded-nullifier guard; an invalid "
            "child block that repeats a shielded transaction aborts the node. "
            "Ordering / TOCTOU bug: the index mutation commits ahead of the validity "
            "check that should have rejected the block."
        ),
        "invariant_text": (
            "A block's transaction index (tx_loc_by_hash) MUST NOT be mutated before "
            "the block has passed every contextual validity check, including the "
            "duplicate shielded-nullifier guard; index updates MUST run only after "
            "all rejection conditions have been evaluated."
        ),
        "violated_consequence": (
            "An invalid child block repeating a shielded transaction mutates the index "
            "before the duplicate-nullifier check, triggering an abort that takes the "
            "node down (network-reachable DoS)."
        ),
        "inv_category": "ordering",
        "commit_point": "duplicate-nullifier-guard before tx_loc_by_hash index write in Chain::push",
        "defense_layer": "validate-then-commit ordering / contextual-check-before-state-mutation",
        "detector_id": "index-update-before-validity-check",
        "regex_pattern": r"\bfn\s+push\b[^}]*?\b(?:tx_loc_by_hash|insert)\b[^}]*?\b(?:check_|validate_|reject|duplicate)",
        "ast_hint": (
            "Flag state-index inserts (map.insert / index update) that lexically "
            "precede a validity/rejection guard inside the same block-push function."
        ),
        "fp_reduction": (
            "Only flag when the inserted key is derived from untrusted block content "
            "AND a rejection guard for that same content exists later in the function."
        ),
        "positive_fixture": (
            "fn push(&mut self, block: PreparedBlock) -> Result<()> {\n"
            "    self.tx_loc_by_hash.insert(tx.hash(), loc); // index updated first\n"
            "    self.check_duplicate_nullifiers(&block)?;     // guard runs AFTER\n"
            "    Ok(())\n"
            "}"
        ),
    },
    {
        "ghsa": "GHSA-w834-cf6p-9m9w",
        "severity": "high",
        "cve": None,
        "cvss": None,
        "cvss_score": None,
        "cwe": "CWE-191",
        "crates": [
            ("zebra-state", "<=6.0.0", "7.0.0"),
            ("zebrad", "<=4.4.1", "4.5.0"),
        ],
        "component": "zebra-state finalized transparent address-balance writer (credit-before-debit ordering)",
        "bug_class": "credit-before-debit-intermediate-overflow",
        "attack_class": "ordering-arithmetic-overflow",
        "attacker_role": "unprivileged",
        "impact_class": "dos",
        "impact_actor": "validator-set",
        "year": 2025,
        "summary": (
            "Finalized address-balance credit-first overflow. The finalized transparent "
            "address-balance writer processes credits (newly-created outputs) before "
            "debits (spends) within a block; a consensus-valid block with a long chain "
            "of same-address self-spends makes the intermediate per-address balance "
            "exceed MAX_MONEY, overflowing. Ordering / arithmetic-overflow bug."
        ),
        "invariant_text": (
            "When writing per-address balance deltas for a finalized block, debits and "
            "credits MUST be netted (or processed in an order) such that the running "
            "intermediate per-address balance never exceeds MAX_MONEY even though the "
            "final balance is in range; balance arithmetic MUST NOT overflow on any "
            "intermediate consensus-valid sequence of same-address spends."
        ),
        "violated_consequence": (
            "A consensus-valid block of same-address self-spends drives the intermediate "
            "balance past MAX_MONEY, overflowing the address-balance writer and halting "
            "the node on an otherwise-valid block."
        ),
        "inv_category": "arithmetic-safety",
        "commit_point": "net debits+credits (or process debits first) before the MAX_MONEY-bounded balance write",
        "defense_layer": "netted-delta / debit-before-credit ordering / checked arithmetic",
        "detector_id": "credit-before-debit-intermediate-overflow",
        "regex_pattern": r"\bbalance\b[^;]*\+=[^;]*credit[^;]*;[\s\S]{0,200}?\bbalance\b[^;]*-=[^;]*debit",
        "ast_hint": (
            "Flag per-address balance accumulation that adds credits before "
            "subtracting debits within one block when the type is MAX_MONEY-bounded; "
            "intermediate value can transiently exceed the cap."
        ),
        "fp_reduction": (
            "Only flag when the accumulator is bounded (asserts/clamps to a max) and "
            "the same accumulator both adds and subtracts within one transaction-set "
            "loop; ignore when a netted delta is computed first."
        ),
        "positive_fixture": (
            "for output in block.outputs() { balance += output.value; } // credits first\n"
            "for spend in block.spends() { balance -= spend.value; }     // debits after\n"
            "// balance may transiently exceed MAX_MONEY -> overflow"
        ),
    },
    {
        "ghsa": "GHSA-gvjc-3w7c-92jx",
        "severity": "medium",
        "cve": None,
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
        "cvss_score": 5.3,
        "cwe": "CWE-345",
        "crates": [
            ("zebra-consensus", "<=6.0.0", "7.0.0"),
            ("zebrad", "<=4.4.1", "4.5.0"),
        ],
        "component": "zebra-consensus / zebra-network sync restart on AboveLookaheadHeightLimit from a single unauthenticated peer",
        "bug_class": "unauthenticated-peer-induced-global-sync-restart",
        "attack_class": "insufficient-data-authenticity-sync-poisoning",
        "attacker_role": "unprivileged",
        "impact_class": "dos",
        "impact_actor": "validator-set",
        "year": 2025,
        "summary": (
            "Sync restart poisoning. A single unauthenticated peer answers "
            "getblocks/FindBlocks with a 2-hash inventory then serves a syntactically "
            "valid block whose coinbase height is far above the local tip; the "
            "AboveLookaheadHeightLimit condition triggers a global sync restart. One "
            "untrusted peer can repeatedly stall the node's sync. CWE-345 insufficient "
            "verification of data authenticity."
        ),
        "invariant_text": (
            "A single unauthenticated peer's response MUST NOT be able to trigger a "
            "global sync restart; an out-of-range coinbase height from one peer MUST be "
            "handled by penalizing/disconnecting that peer, not by resetting the whole "
            "sync pipeline."
        ),
        "violated_consequence": (
            "Any one untrusted peer repeatedly serves an above-lookahead block and forces "
            "global sync restarts, denying the node forward progress."
        ),
        "inv_category": "authenticity",
        "commit_point": "per-peer penalty/disconnect on AboveLookaheadHeightLimit instead of global restart",
        "defense_layer": "per-peer misbehavior scoring / single-peer-cannot-reset-global-state",
        "detector_id": "single-peer-triggers-global-reset",
        "regex_pattern": r"AboveLookaheadHeightLimit[\s\S]{0,300}?\b(?:restart|reset|clear)\b",
        "ast_hint": (
            "Flag handlers that respond to a single-peer-derived error/limit by "
            "restarting or clearing a global/shared sync state rather than scoping the "
            "response to that peer."
        ),
        "fp_reduction": (
            "Only flag when the trigger value is derived from one peer's unauthenticated "
            "response AND the reaction touches global (not per-peer) state."
        ),
        "positive_fixture": (
            "match verify(block) {\n"
            "    Err(AboveLookaheadHeightLimit) => self.restart_sync(), // global reset on 1 peer\n"
            "    _ => {}\n"
            "}"
        ),
    },
    {
        "ghsa": "GHSA-4m69-67m6-prqp",
        "severity": "high",
        "cve": None,
        "cvss": None,
        "cvss_score": None,
        "cwe": "CWE-459",
        "crates": [
            ("zebra-state", "<=6.0.0", "7.0.0"),
            ("zebrad", "<=4.4.1", "4.5.0"),
        ],
        "component": "zebra-state incomplete cleanup of non-finalized / intermediate state",
        "bug_class": "incomplete-cleanup-of-intermediate-state",
        "attack_class": "incomplete-cleanup-state-residue",
        "attacker_role": "unprivileged",
        "impact_class": "dos",
        "impact_actor": "validator-set",
        "year": 2025,
        "summary": (
            "Incomplete cleanup (CWE-459) in zebra-state: intermediate / non-finalized "
            "state is not fully removed on the rejection/abort path, leaving residue "
            "that an attacker can leverage against the node's state machine. Reachable "
            "by an unauthenticated peer via crafted block content."
        ),
        "invariant_text": (
            "On any block-rejection or abort path, ALL intermediate non-finalized state "
            "written for that block MUST be fully rolled back; no partial index, balance, "
            "or nullifier residue from a rejected block may persist into subsequent "
            "validation."
        ),
        "violated_consequence": (
            "Residual state from a rejected/aborted block persists and corrupts or "
            "destabilizes subsequent block validation, reachable by an unauthenticated "
            "peer."
        ),
        "inv_category": "cleanup-completeness",
        "commit_point": "full rollback of every write made for a block on its rejection/abort path",
        "defense_layer": "transactional-rollback / all-or-nothing state mutation per block",
        "detector_id": "incomplete-rollback-on-reject-path",
        "regex_pattern": r"\b(?:insert|push|update)\b[\s\S]{0,400}?\breturn\s+Err\b(?![\s\S]{0,200}?\b(?:rollback|revert|remove|drop|clear)\b)",
        "ast_hint": (
            "Flag functions that mutate shared/non-finalized state and then take an "
            "early-error return without a matching rollback/cleanup of every prior "
            "mutation in that function."
        ),
        "fp_reduction": (
            "Only flag when the mutation targets persistent/shared state (not a local) "
            "AND the error path lacks a rollback/remove for the same key; ignore when a "
            "scope-guard / Drop impl performs the rollback."
        ),
        "positive_fixture": (
            "self.state.insert(key, value);     // intermediate write\n"
            "if !self.check(block) {\n"
            "    return Err(Invalid);           // no remove(key) -> residue\n"
            "}"
        ),
    },
    {
        # https://github.com/ZcashFoundation/zebra/security/advisories/GHSA-4fc2-h7jh-287c
        "ghsa": "GHSA-4fc2-h7jh-287c",
        "severity": "medium",
        "cve": None,
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
        "cvss_score": 5.3,
        "cwe": "CWE-770",
        "crates": [
            ("zebrad", "<=4.4.1", "4.5.0"),
        ],
        "component": "zebra mempool download/verification pipeline - shared 25 inbound concurrency slots with no per-peer cap (Gossip type carries no peer identity)",
        "bug_class": "shared-slot-pool-no-per-peer-cap",
        "attack_class": "resource-exhaustion-no-per-peer-throttle",
        "attacker_role": "unprivileged",
        "impact_class": "dos",
        "impact_actor": "validator-set",
        "year": 2025,
        "summary": (
            "Mempool transaction admission denial via single-peer inbound queue "
            "saturation. The mempool download/verification pipeline has three gaps: "
            "no per-peer accounting (the 25 slots are shared across all peers with "
            "no cap on how many a single peer can hold); no overload signaling (when "
            "FullQueue is returned the inbound service maps it to Response::Nil, "
            "hiding the overload from the peer connection layer); and no misbehavior "
            "attribution (peer identity is not carried through the Gossip type into "
            "the download pipeline, so verification failures cannot be attributed to "
            "the originating peer). An unauthenticated peer advertises fake "
            "transaction IDs, consuming all 25 inbound concurrency slots while "
            "remaining unpenalized, blocking legitimate mempool transactions. "
            "CWE-770 allocation of resources without limits or throttling."
        ),
        "invariant_text": (
            "A single unauthenticated peer MUST NOT be able to occupy the entire "
            "shared mempool inbound concurrency-slot pool: per-peer accounting MUST "
            "cap how many of the shared download/verification slots one peer may "
            "hold, overload (FullQueue) MUST be signalled to the peer connection "
            "layer rather than masked as a Nil response, and peer identity MUST be "
            "carried through the gossip/download pipeline so verification failures "
            "are attributable to the originating peer."
        ),
        "violated_consequence": (
            "One unauthenticated peer advertising fake transaction IDs monopolizes "
            "all 25 shared inbound slots without penalty, denying mempool admission "
            "to legitimate transactions."
        ),
        "inv_category": "resource-bounds",
        "commit_point": "per-peer slot accounting + FullQueue overload signaling + peer-id propagation through Gossip into the download pipeline",
        "defense_layer": "per-peer resource cap / overload-signal-to-connection-layer / peer-attributable misbehavior",
        "detector_id": "shared-concurrency-pool-no-per-peer-cap",
        "regex_pattern": r"\b(?:slots?|semaphore|concurrency|in[_-]?flight)\b[\s\S]{0,200}?\b(?:shared|global)\b(?![\s\S]{0,200}?\bper[_-]?peer\b)",
        "ast_hint": (
            "Flag a shared/global concurrency-slot pool (semaphore, fixed slot "
            "count, in-flight map) populated from untrusted-peer requests that has "
            "no per-peer accounting/cap limiting one peer's share."
        ),
        "fp_reduction": (
            "Only flag when the pool is fed by network-peer-derived items AND no "
            "per-peer counter/quota gates admission; ignore pools that already "
            "track and cap per-source occupancy."
        ),
        "positive_fixture": (
            "// 25 slots shared across ALL peers, no per-peer cap\n"
            "let slots = Semaphore::new(25);\n"
            "// gossip item carries no peer id -> failures unattributable\n"
            "fn enqueue(&self, tx: Gossip) { self.slots.acquire(); /* any peer */ }"
        ),
    },
    {
        # https://github.com/ZcashFoundation/zebra/security/advisories/GHSA-65jj-fmw8-468q
        "ghsa": "GHSA-65jj-fmw8-468q",
        "severity": "medium",
        "cve": None,
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
        "cvss_score": 5.3,
        "cwe": "CWE-401",
        "crates": [
            ("zebrad", "<=4.4.1", "4.5.0"),
        ],
        "component": "zebra mempool download pipeline cancel_handles map - timeout-path entries never cleaned up (timeout error carries no tx id)",
        "bug_class": "timeout-path-handle-retention-memory-leak",
        "attack_class": "unbounded-memory-leak-via-uncleaned-timeout-path",
        "attacker_role": "unprivileged",
        "impact_class": "dos",
        "impact_actor": "validator-set",
        "year": 2025,
        "summary": (
            "Unbounded memory leak in the mempool download pipeline via timeout-path "
            "cancel_handles retention. The mempool verification pipeline maintains a "
            "cancel_handles map that fails to clean up entries when transactions time "
            "out at the outer 73-second boundary. The timeout error type carries no "
            "transaction identifier, making recovery impossible. Entries accumulate "
            "without bounds or cleanup, causing monotonic memory growth: a single "
            "retained entry can consume up to ~2 MB, leaking at ~685 KB/second per "
            "connection in worst case, potentially exhausting node memory over "
            "several hours of sustained attacker traffic. CWE-401 missing release of "
            "memory after effective lifetime / CWE-772 missing release of resource "
            "after effective lifetime."
        ),
        "invariant_text": (
            "Every entry inserted into the mempool cancel_handles (in-flight "
            "download/verification) map MUST be removed on ALL exit paths including "
            "the outer timeout path; the timeout error MUST carry the transaction "
            "identifier needed to remove its own cancel_handles entry, so the map's "
            "size stays bounded by the live in-flight set rather than growing "
            "monotonically."
        ),
        "violated_consequence": (
            "Timed-out transactions leave their cancel_handles entries behind "
            "permanently; sustained attacker traffic grows the map without bound and "
            "exhausts node memory over hours."
        ),
        "inv_category": "resource-bounds",
        "commit_point": "cancel_handles removal on the timeout path (timeout error must carry the tx id)",
        "defense_layer": "all-exit-path resource cleanup / timeout error carries the key needed to release its handle",
        "detector_id": "in-flight-handle-map-not-cleaned-on-timeout",
        "regex_pattern": r"\bcancel_handles\b[\s\S]{0,400}?\b(?:timeout|elapsed|deadline)\b(?![\s\S]{0,200}?\b(?:remove|clear|drop)\b)",
        "ast_hint": (
            "Flag an in-flight handle/cancel map whose insert has a removal on the "
            "success/error paths but NOT on the timeout/elapsed path, especially "
            "when the timeout error type carries no key to identify which entry to "
            "remove."
        ),
        "fp_reduction": (
            "Only flag when the map holds per-request handles fed by untrusted "
            "traffic AND a timeout branch exists with no matching remove; ignore "
            "when a Drop guard or a sweep task reclaims timed-out entries."
        ),
        "positive_fixture": (
            "self.cancel_handles.insert(txid, handle);\n"
            "match tokio::time::timeout(d, fut).await {\n"
            "    Err(_elapsed) => return Err(Timeout), // no txid -> cannot remove() -> leak\n"
            "    Ok(r) => { self.cancel_handles.remove(&txid); r }\n"
            "}"
        ),
    },
    {
        # https://github.com/ZcashFoundation/zebra/security/advisories/GHSA-h72h-ppcx-998p
        "ghsa": "GHSA-h72h-ppcx-998p",
        "severity": "medium",
        "cve": None,
        "cvss": None,
        "cvss_score": None,
        # Advisory references CWE-770 as related context; no first-class CWE field is
        # published. Transcribed as the related-context value (verbatim per the page).
        "cwe": "CWE-770",
        "crates": [
            ("zebra-network", "<=6.0.0", "7.0.0"),
            ("zebrad", "<=4.4.1", "4.5.0"),
        ],
        "component": "zebra-network P2P Codec::decode - src.reserve(body_len + HEADER_LEN) using attacker-claimed body_len before handshake completes",
        "bug_class": "pre-handshake-buffer-reserve-on-attacker-claimed-length",
        "attack_class": "untrusted-length-driven-allocation-pre-auth",
        "attacker_role": "unprivileged",
        "impact_class": "dos",
        "impact_actor": "validator-set",
        "year": 2025,
        "summary": (
            "Pre-handshake buffer capacity reservation based on attacker-claimed body "
            "length. The P2P codec's Codec::decode() method calls "
            "src.reserve(body_len + HEADER_LEN) after parsing a 24-byte protocol "
            "header, using the attacker-claimed body_len field, before the handshake "
            "completes. While this reserves virtual address space rather than "
            "physical memory, it is a resource-allocation vulnerability; the patch "
            "defers large reservations until after handshake completion. CWE-770 "
            "allocation of resources without limits or throttling is referenced as "
            "related context."
        ),
        "invariant_text": (
            "A network codec MUST NOT reserve buffer capacity sized by an "
            "attacker-claimed length field from an unauthenticated/pre-handshake "
            "peer; large reservations driven by a peer-supplied body_len MUST be "
            "bounded and/or deferred until after the handshake completes."
        ),
        "violated_consequence": (
            "Codec::decode reserves body_len + HEADER_LEN from a pre-handshake "
            "attacker-claimed length, letting an unauthenticated peer drive "
            "address-space reservation before any trust is established."
        ),
        "inv_category": "resource-bounds",
        "commit_point": "defer/bound src.reserve(body_len) until after handshake completion",
        "defense_layer": "post-handshake-only large reservation / cap untrusted-length-driven allocation",
        "detector_id": "reserve-sized-by-untrusted-length-pre-handshake",
        "regex_pattern": r"\.reserve\(\s*\w*body_len\w*[\s\S]{0,40}?\)",
        "ast_hint": (
            "Flag Buf/Vec reserve/with_capacity calls whose size argument is a "
            "length field parsed directly from an untrusted network header before "
            "authentication/handshake completion."
        ),
        "fp_reduction": (
            "Only flag when the size expression derives from a peer-supplied header "
            "length AND the call site is reachable pre-handshake/pre-auth; ignore "
            "reservations bounded by a constant max or gated behind a completed "
            "handshake."
        ),
        "positive_fixture": (
            "let body_len = header.body_len(); // attacker-claimed\n"
            "src.reserve(body_len + HEADER_LEN); // reserved before handshake completes"
        ),
    },
    {
        # https://github.com/ZcashFoundation/zebra/security/advisories/GHSA-gf9r-m956-97qx
        "ghsa": "GHSA-gf9r-m956-97qx",
        "severity": "critical",
        "cve": None,
        "cvss": None,
        "cvss_score": None,
        "cwe": "CWE-684",
        "crates": [
            ("zebra-script", "<=6.0.1", "7.0.0"),
            ("zebrad", "<=4.4.1", "4.5.0"),
        ],
        "component": "zebra-script P2SH sigop counter - pure-Rust path terminates early on disabled opcodes (e.g. OP_CODESEPARATOR), undercounting sigops vs zcashd",
        "bug_class": "p2sh-sigop-undercount-on-disabled-opcode-early-terminate",
        "attack_class": "consensus-divergence-via-implementation-disagreement",
        "attacker_role": "unprivileged",
        # schema impact_class enum lacks a consensus-split value; mapped to dos
        # (chain split -> node unavailability). Precise class lives in attack_class.
        "impact_class": "dos",
        "impact_actor": "validator-set",
        "year": 2025,
        "summary": (
            "Consensus divergence via P2SH sigop undercount in the pure-Rust "
            "disabled-opcode parser. Zebra's P2SH signature-operation counter uses a "
            "pure-Rust code path that terminates prematurely when encountering "
            "disabled opcodes like OP_CODESEPARATOR, producing an incomplete sigop "
            "count, whereas the reference implementation (zcashd) correctly counts "
            "through disabled opcodes during static analysis. The discrepancy allows "
            "blocks exceeding the MAX_BLOCK_SIGOPS = 20,000 threshold on one "
            "implementation but not the other, enabling attackers to craft "
            "transactions that trigger network divergence without requiring mining "
            "capability. CWE-684 incorrect provision of specified functionality."
        ),
        "invariant_text": (
            "Zebra's P2SH signature-operation counter MUST count sigops identically "
            "to the reference implementation (zcashd), including counting THROUGH "
            "disabled opcodes (e.g. OP_CODESEPARATOR) during static analysis; the "
            "counter MUST NOT terminate early on a disabled opcode, so the "
            "MAX_BLOCK_SIGOPS = 20000 acceptance decision is identical across "
            "implementations and cannot diverge."
        ),
        "violated_consequence": (
            "Zebra undercounts P2SH sigops by stopping at disabled opcodes, so a "
            "crafted block can exceed MAX_BLOCK_SIGOPS on zcashd but pass on Zebra "
            "(or vice versa), splitting the network with no mining capability "
            "required."
        ),
        "inv_category": "consensus-parity",
        "commit_point": "count sigops through disabled opcodes to match zcashd's static-analysis count before the MAX_BLOCK_SIGOPS check",
        "defense_layer": "implementation-parity with reference client / count-through-disabled-opcodes",
        "detector_id": "sigop-counter-early-terminate-on-disabled-opcode",
        "regex_pattern": r"\b(?:sigop|sig_op|signature_op)\w*\b[\s\S]{0,300}?\b(?:OP_CODESEPARATOR|disabled|is_disabled|break|return)\b",
        "ast_hint": (
            "Flag a signature-operation counting loop that breaks/returns on a "
            "disabled-opcode branch instead of continuing to scan, where the "
            "reference protocol requires counting through disabled opcodes."
        ),
        "fp_reduction": (
            "Only flag when the loop is the consensus sigop counter (feeds a "
            "MAX_BLOCK_SIGOPS / sigop-limit check) AND the disabled-opcode branch "
            "short-circuits the count; ignore execution-time interpreters where "
            "early-exit on disabled opcodes is correct."
        ),
        "positive_fixture": (
            "for op in script.opcodes() {\n"
            "    if op.is_disabled() { break; } // STOPS counting -> undercount vs zcashd\n"
            "    if op.is_sigop() { count += 1; }\n"
            "}\n"
            "// count compared to MAX_BLOCK_SIGOPS = 20000"
        ),
    },
    {
        # https://github.com/ZcashFoundation/zebra/security/advisories/GHSA-2prc-cj5x-4443
        "ghsa": "GHSA-2prc-cj5x-4443",
        "severity": "critical",
        "cve": None,
        "cvss": None,
        "cvss_score": None,
        "cwe": None,
        "crates": [
            ("zebra-script", "7.0.0", "7.0.1"),
            ("zebrad", "4.5.0", "4.5.1"),
        ],
        "component": "zebra-script P2SH sigop counter after GHSA-gf9r fix - consensus path used legacy counting mode GetSigOpCount(false) instead of accurate P2SH counting mode GetSigOpCount(true)",
        "bug_class": "p2sh-sigop-overcount-legacy-mode-after-incomplete-fix",
        "attack_class": "consensus-divergence-via-p2sh-sigop-mode-mismatch",
        "attacker_role": "unprivileged",
        # schema impact_class enum lacks a consensus-split value; mapped to dos
        # (chain split -> Zebra validator unavailability). Precise class lives in attack_class.
        "impact_class": "dos",
        "impact_actor": "validator-set",
        "year": 2026,
        "summary": (
            "P2SH sigop undercount was not correctly fixed in Zebra 4.5.0. After "
            "GHSA-gf9r-m956-97qx, Zebra switched the P2SH redeem-script counter to "
            "a pure C++ entry point that counted with legacy mode "
            "GetSigOpCount(false), while zcashd's P2SH path uses accurate mode "
            "GetSigOpCount(true). The difference is load-bearing for "
            "CHECKMULTISIG: a redeem script such as OP_1 <pubkey> OP_1 "
            "OP_CHECKMULTISIG counts as 20 in legacy mode but 1 in accurate mode. "
            "A block with enough low-threshold multisig P2SH spends can therefore "
            "cross MAX_BLOCK_SIGOPS on Zebra while remaining valid on zcashd, "
            "causing Zebra validators to reject canonical blocks and split off the "
            "chain. The attacker needs no mining capability, only valid spending "
            "transactions that an honest miner may include."
        ),
        "invariant_text": (
            "Zebra's P2SH signature-operation counter MUST use the same accurate "
            "P2SH counting mode as zcashd for redeem scripts: CHECKMULTISIG and "
            "CHECKMULTISIGVERIFY preceded by OP_1 to OP_16 MUST count the actual "
            "threshold, not the legacy fixed count of 20. The P2SH sigop total that "
            "feeds MAX_BLOCK_SIGOPS MUST be identical across Zebra and zcashd."
        ),
        "violated_consequence": (
            "Zebra over-counts low-threshold multisig P2SH redeem scripts, so an "
            "otherwise valid block can exceed MAX_BLOCK_SIGOPS on Zebra while "
            "staying below the limit on zcashd. Zebra rejects the canonical block "
            "and stalls at that height while zcashd nodes advance."
        ),
        "inv_category": "consensus-parity",
        "commit_point": "count P2SH redeem-script sigops with accurate mode before adding them to the block MAX_BLOCK_SIGOPS total",
        "defense_layer": "zcashd-parity for P2SH accurate sigop mode / no legacy-mode counter in consensus P2SH path",
        "detector_id": "p2sh-sigop-legacy-mode-used-in-consensus-path",
        "regex_pattern": r"\b(?:p2sh_sigop|sigop)\w*\b[\s\S]{0,320}?\b(?:legacy_sigop_count_script|GetSigOpCount\s*\(\s*false\s*\)|fAccurate\s*:\s*false|accurate\s*=\s*false)\b",
        "ast_hint": (
            "Flag a consensus P2SH sigop counter that calls a legacy-mode "
            "script-sigop function (GetSigOpCount(false) or a wrapper such as "
            "legacy_sigop_count_script) when the result feeds MAX_BLOCK_SIGOPS."
        ),
        "fp_reduction": (
            "Only flag consensus/block-validation or block-template P2SH sigop "
            "paths feeding MAX_BLOCK_SIGOPS. Ignore legacy non-P2SH sigop counters "
            "and tests that intentionally document the mode distinction."
        ),
        "positive_fixture": (
            "let p2sh = interpreter.legacy_sigop_count_script(&script::Code(redeem)); // GetSigOpCount(false)\n"
            "sigops = sigops.saturating_add(p2sh);\n"
            "if sigops > MAX_BLOCK_SIGOPS { return Err(TooManySigops); }"
        ),
    },
    {
        # https://github.com/ZcashFoundation/zebra/security/advisories/GHSA-63wg-wjjj-7cp8
        "ghsa": "GHSA-63wg-wjjj-7cp8",
        "severity": "high",
        "cve": None,
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        "cvss_score": 7.5,
        # Advisory page shows "No CWEs"; do not fabricate a CWE.
        "cwe": None,
        "crates": [
            ("zebra-network", "<=6.0.0", "7.0.0"),
            ("zebrad", "<=4.4.1", "4.5.0"),
        ],
        "component": "zebra-network address-book - mempool misbehavior path preserves raw IPv4-mapped-IPv6 while handshake canonicalizes to IPv4, assertion mismatch aborts node",
        "bug_class": "address-normalization-inconsistency-assert-abort",
        "attack_class": "normalization-mismatch-induced-assertion-failure",
        "attacker_role": "unprivileged",
        "impact_class": "dos",
        "impact_actor": "validator-set",
        "year": 2025,
        "summary": (
            "IPv4-mapped mempool misbehavior update aborts Zebra address book. An "
            "address-normalization inconsistency: when IPv4 peers connect to a "
            "dual-stack IPv6 listener on Linux, the handshake path canonicalizes "
            "IPv4-mapped IPv6 addresses to plain IPv4 for address-book storage, but "
            "the mempool misbehavior path preserves the raw IPv4-mapped IPv6 format "
            "when reporting penalties. This mismatch causes an assertion failure: the "
            "address book looks up the canonical IPv4 entry but then asserts that the "
            "previous entry's address matches the change's address, aborting the "
            "node. The fix applies address canonicalization through a new constructor "
            "before submitting misbehavior updates."
        ),
        "invariant_text": (
            "Every code path that keys, looks up, or updates an address-book entry "
            "MUST apply the SAME address canonicalization (IPv4-mapped IPv6 -> plain "
            "IPv4); the mempool misbehavior-update path MUST canonicalize the peer "
            "address before submitting a change, so the address-book consistency "
            "assertion (previous-entry address == change address) can never be "
            "violated by a normalization mismatch."
        ),
        "violated_consequence": (
            "An IPv4 peer on a dual-stack listener triggers a misbehavior update "
            "keyed on the raw IPv4-mapped IPv6 address while the book stored the "
            "canonical IPv4, failing the consistency assertion and aborting the node."
        ),
        "inv_category": "normalization-consistency",
        "commit_point": "canonicalize the peer address (new constructor) before submitting any misbehavior/address-book update",
        "defense_layer": "single canonicalization boundary applied on all address-book mutation paths",
        "detector_id": "address-key-normalization-mismatch-across-paths",
        "regex_pattern": r"\b(?:to_ipv4|canonical|normaliz|map(?:ped)?_ipv4)\w*\b[\s\S]{0,300}?\b(?:assert|debug_assert)\b",
        "ast_hint": (
            "Flag address-book lookups/updates where one path canonicalizes the "
            "address (IPv4-mapped IPv6 -> IPv4) and a sibling mutation path does not, "
            "guarded by an equality assertion on the stored vs incoming address."
        ),
        "fp_reduction": (
            "Only flag when two paths write the same keyed store with different "
            "normalization AND an assertion compares stored vs incoming key; ignore "
            "when a single canonicalization helper is applied uniformly."
        ),
        "positive_fixture": (
            "// handshake path: canonical IPv4\n"
            "book.insert(addr.to_canonical(), entry);\n"
            "// misbehavior path: raw IPv4-mapped IPv6 (NOT canonicalized)\n"
            "book.update(raw_v6_mapped_addr, change); // assert(prev.addr == change.addr) fails -> abort"
        ),
    },
    {
        # https://github.com/ZcashFoundation/zebra/security/advisories/GHSA-2gf8-q9rr-jq3h
        "ghsa": "GHSA-2gf8-q9rr-jq3h",
        "severity": "medium",
        "cve": None,
        "cvss": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:L",
        "cvss_score": 6.5,
        "cwe": "CWE-459",
        "crates": [
            ("zebra-state", "<=6.0.0", "7.0.0"),
            ("zebrad", "<=4.4.1", "4.5.0"),
        ],
        "component": "zebra-state non-finalized state - pop_tip retains note-commitment subtree-root contributions (pop_root cleans them; asymmetric), persisted to RocksDB on fork finalize",
        "bug_class": "asymmetric-pop-cleanup-stale-subtree-root-persisted",
        "attack_class": "incomplete-cleanup-on-reorg-persisted-corruption",
        "attacker_role": "unprivileged",
        # schema impact_class enum lacks a state-corruption value; mapped to dos
        # (persisted subtree-root corruption -> node integrity/availability loss).
        "impact_class": "dos",
        "impact_actor": "validator-set",
        "year": 2025,
        "summary": (
            "Persistent on-disk corruption of Sapling/Orchard subtree roots after a "
            "chain fork via pop_tip. Asymmetric cleanup between two block-removal "
            "methods in the non-finalized state: pop_root properly removes "
            "note-commitment subtree contributions during finalization, but pop_tip "
            "removes the block while retaining the block's subtree-root contributions "
            "in the in-memory state. When chain forks occur and subsequently "
            "finalize, the stale subtree data from the reverted blocks is included in "
            "the RocksDB write batch and persisted to disk, causing permanent "
            "corruption of Sapling and Orchard subtree-root history. CWE-459 "
            "incomplete cleanup / CWE-672 operation on a resource after expiration or "
            "release."
        ),
        "invariant_text": (
            "Both non-finalized block-removal methods (pop_root AND pop_tip) MUST "
            "symmetrically remove ALL of a removed block's contributions, including "
            "note-commitment Sapling/Orchard subtree-root contributions; a block "
            "reverted by pop_tip MUST NOT leave stale subtree-root data in the "
            "in-memory state that can later be flushed into the RocksDB write batch "
            "on finalization."
        ),
        "violated_consequence": (
            "pop_tip leaves a reverted block's subtree-root contributions in memory; "
            "on subsequent fork finalization the stale data is written to RocksDB, "
            "permanently corrupting Sapling/Orchard subtree-root history on disk."
        ),
        "inv_category": "cleanup-completeness",
        "commit_point": "pop_tip must remove subtree-root contributions symmetrically with pop_root before any finalize/write-batch flush",
        "defense_layer": "symmetric removal across all block-pop paths / no stale state reaches the persistence write batch",
        "detector_id": "asymmetric-block-pop-cleanup-stale-state-persisted",
        "regex_pattern": r"\bfn\s+pop_tip\b[\s\S]{0,500}?\}",
        "ast_hint": (
            "Flag paired removal methods (pop_root vs pop_tip / remove_root vs "
            "remove_tip) where one cleans a derived contribution (subtree root, "
            "note-commitment) and the sibling does not, when the residue can reach a "
            "persistence write batch."
        ),
        "fp_reduction": (
            "Only flag when a sibling removal method DOES clean the contribution "
            "(proving it is required) AND the under-cleaning method's residue is "
            "reachable by the on-disk write batch; ignore when both paths clean "
            "symmetrically."
        ),
        "positive_fixture": (
            "fn pop_root(&mut self) { self.remove_block(); self.subtree_roots.pop(); } // cleans\n"
            "fn pop_tip(&mut self)  { self.remove_block(); /* subtree_roots retained */ } // stale -> RocksDB"
        ),
    },
    {
        # https://github.com/ZcashFoundation/zebra/security/advisories/GHSA-h9hm-m2xj-4rq9
        "ghsa": "GHSA-h9hm-m2xj-4rq9",
        "severity": "critical",
        "cve": "CVE-2026-44499",
        "cvss": None,
        "cvss_score": None,
        "cwe": None,
        "crates": [
            ("zebrad", "<4.4.0", "4.4.0"),
        ],
        "component": "zebra block-discovery - no per-connection inv rate limit + zero-penalty empty-inv/NotFound responses degrade the syncer (single TCP peer)",
        "bug_class": "gossip-queue-saturation-plus-syncer-poisoning",
        "attack_class": "single-peer-permanent-block-discovery-halt",
        "attacker_role": "unprivileged",
        "impact_class": "dos",
        "impact_actor": "validator-set",
        "year": 2026,
        "summary": (
            "Permanent block-discovery halt via gossip-queue saturation and syncer "
            "poisoning. Three weaknesses in block-discovery: (1) there was no "
            "per-connection rate limit on inv messages, allowing attackers to flood "
            "the gossip queue with fake block hashes; (2) the syncer could be "
            "degraded through valid protocol responses (empty inv to FindBlocks "
            "requests and NotFound to block downloads) that carried zero misbehavior "
            "penalty; (3) combined, these vectors let an attacker via a single TCP "
            "peer connection suppress both discovery paths simultaneously, causing "
            "permanent chain-synchronization failure without operator intervention. "
            "Tracked as CVE-2026-44499."
        ),
        "invariant_text": (
            "Block discovery MUST survive a single malicious TCP peer: inv messages "
            "MUST be per-connection rate-limited so one peer cannot saturate the "
            "gossip queue with fake hashes, and protocol responses that starve the "
            "syncer (empty inv to FindBlocks, NotFound to block downloads) MUST carry "
            "a misbehavior penalty so a single peer cannot poison both the gossip and "
            "syncer discovery paths into a permanent halt."
        ),
        "violated_consequence": (
            "A single TCP peer floods inv with fake hashes (no per-connection limit) "
            "and starves the syncer with zero-penalty empty-inv/NotFound responses, "
            "permanently halting block discovery with no operator-free recovery."
        ),
        "inv_category": "resource-bounds",
        "commit_point": "per-connection inv rate limit + misbehavior penalty on syncer-starving empty-inv/NotFound responses",
        "defense_layer": "per-connection gossip rate limit / penalize syncer-starvation responses / single-peer-cannot-halt-discovery",
        "detector_id": "no-per-connection-inv-rate-limit-or-zero-penalty-starvation",
        "regex_pattern": r"\binv\b[\s\S]{0,200}?\b(?:gossip|queue|FindBlocks|NotFound)\b(?![\s\S]{0,200}?\b(?:rate[_-]?limit|penal|misbehav)\b)",
        "ast_hint": (
            "Flag inv/gossip ingest handlers with no per-connection rate limit, and "
            "FindBlocks/block-download response handlers that treat empty-inv / "
            "NotFound as benign (no misbehavior penalty) when they can starve the "
            "syncer."
        ),
        "fp_reduction": (
            "Only flag when inv ingest is per-peer-unbounded OR a syncer-starving "
            "response path applies zero penalty; ignore handlers that rate-limit per "
            "connection and score starvation responses."
        ),
        "positive_fixture": (
            "fn on_inv(&mut self, hashes: Vec<Hash>) { self.gossip_queue.extend(hashes); } // no per-conn rate limit\n"
            "fn on_find_blocks_empty(&mut self) { /* zero misbehavior penalty */ } // starves syncer"
        ),
    },
    {
        # https://github.com/ZcashFoundation/zebra/security/advisories/GHSA-c8w6-x74f-vmg3
        "ghsa": "GHSA-c8w6-x74f-vmg3",
        "severity": "medium",
        "cve": None,
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
        "cvss_score": 6.5,
        "cwe": "CWE-617",
        "crates": [
            ("zebra-rpc", "<=7.0.0", "8.0.0"),
            ("zebrad", "<=4.4.1", "4.5.0"),
        ],
        "component": "zebra-rpc z_listunifiedreceivers - .expect() on fallible Sapling-receiver subgroup validation; panic=abort terminates the node",
        "bug_class": "rpc-expect-panic-on-invalid-sapling-receiver",
        "attack_class": "authenticated-rpc-panic-abort-dos",
        "attacker_role": "privileged-trusted",  # authenticated RPC client; schema enum has no authenticated-user
        "impact_class": "dos",
        "impact_actor": "validator-set",
        "year": 2025,
        "summary": (
            "Full node denial of service via crafted Sapling receiver in "
            "z_listunifiedreceivers. The z_listunifiedreceivers RPC handler fails to "
            "validate Sapling receiver cryptographic data: a structurally valid "
            "Unified Address containing a 43-byte Sapling receiver that fails "
            "subgroup validation makes the handler call .expect() on a fallible "
            "operation. Because the release profile sets panic=abort, this terminates "
            "the entire node process. An authenticated attacker crashes zebrad "
            "indefinitely with a single malformed RPC request. CWE-20 / CWE-248 / "
            "CWE-617 / CWE-754."
        ),
        "invariant_text": (
            "RPC handlers MUST NOT call .expect()/.unwrap() on fallible validation of "
            "attacker-supplied cryptographic data; a Sapling receiver that fails "
            "subgroup validation MUST be handled as a returned RPC error, never a "
            "panic, especially under panic=abort where a panic kills the whole node."
        ),
        "violated_consequence": (
            "A malformed Sapling receiver triggers .expect() panic under panic=abort, "
            "aborting the node on a single authenticated RPC call."
        ),
        "inv_category": "input-validation",
        "commit_point": "return an RPC error (not .expect()) on Sapling-receiver subgroup-validation failure",
        "defense_layer": "no-panic-on-untrusted-input / fallible-result-propagation in RPC handlers",
        "detector_id": "rpc-expect-unwrap-on-untrusted-crypto-input",
        "regex_pattern": r"\b(?:receiver|sapling|unified)\w*\b[\s\S]{0,200}?\.(?:expect|unwrap)\(",
        "ast_hint": (
            "Flag .expect()/.unwrap() on a fallible parse/validate of attacker-"
            "supplied RPC input in an RPC handler when the build uses panic=abort."
        ),
        "fp_reduction": (
            "Only flag when the receiver/operand is attacker-controlled RPC input "
            "AND the call site is reachable from an RPC entrypoint; ignore unwrap on "
            "compile-time constants or already-validated values."
        ),
        "positive_fixture": (
            "let recv = ua.sapling_receiver().expect(\"valid\"); // panic=abort -> node dies\n"
            "// 43-byte receiver failing subgroup check reaches here"
        ),
    },
    {
        # https://github.com/ZcashFoundation/zebra/security/advisories/GHSA-pvmv-cwg8-v6c8
        "ghsa": "GHSA-pvmv-cwg8-v6c8",
        "severity": "critical",
        "cve": None,
        "cvss": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:H/SC:N/SI:H/SA:H",
        "cvss_score": 9.3,
        "cwe": None,
        "crates": [
            ("zebra-script", "<6.0.1", "6.0.1"),
            ("zebrad", "<4.4.1", "4.4.1"),
        ],
        "component": "zebra-script V5 transparent sighash - SIGHASH_SINGLE with no corresponding output digests over an empty output set instead of rejecting (ZIP-244)",
        "bug_class": "sighash-single-missing-output-not-rejected",
        "attack_class": "consensus-divergence-via-sighash-rule-omission",
        "attacker_role": "unprivileged",
        "impact_class": "dos",
        "impact_actor": "validator-set",
        "year": 2025,
        "summary": (
            "Zebra v4.4.0 still accepts V5 SIGHASH_SINGLE without a corresponding "
            "output. V5 transparent transaction validation failed to enforce a "
            "ZIP-244 consensus rule: when an input was signed with SIGHASH_SINGLE and "
            "no corresponding output existed at that input's index, validation should "
            "reject it, but Zebra's sighash callback forwarded to an underlying "
            "library that computed a digest over an empty output set. Crafted V5 "
            "transactions with more inputs than outputs are accepted by Zebra while "
            "rejected by zcashd, causing consensus divergence and potential "
            "double-spend. CVSS:4.0 base 9.3."
        ),
        "invariant_text": (
            "V5 transparent sighash validation MUST reject a SIGHASH_SINGLE input "
            "that has no corresponding output at its index (per ZIP-244), exactly as "
            "zcashd does; the sighash callback MUST NOT compute a digest over an "
            "empty output set for a missing corresponding output."
        ),
        "violated_consequence": (
            "Zebra accepts V5 transactions with more inputs than outputs under "
            "SIGHASH_SINGLE that zcashd rejects, splitting consensus and enabling "
            "double-spend vectors."
        ),
        "inv_category": "consensus-parity",
        "commit_point": "reject SIGHASH_SINGLE input with no corresponding output before computing the sighash digest",
        "defense_layer": "ZIP-244 corresponding-output enforcement / implementation-parity with zcashd",
        "detector_id": "sighash-single-no-output-not-rejected",
        "regex_pattern": r"SIGHASH_SINGLE[\s\S]{0,300}?\b(?:output|index|corresponding)\b",
        "ast_hint": (
            "Flag SIGHASH_SINGLE handling that computes a digest without first "
            "checking a corresponding output exists at the input index."
        ),
        "fp_reduction": (
            "Only flag in the consensus sighash path for V5+ transparent inputs; "
            "ignore wallet-side signing helpers."
        ),
        "positive_fixture": (
            "if hash_type == SIGHASH_SINGLE {\n"
            "    // missing: if outputs.get(input_index).is_none() { return Err(...) }\n"
            "    digest_over_empty_outputs(); // accepted, zcashd rejects\n"
            "}"
        ),
    },
    {
        # https://github.com/ZcashFoundation/zebra/security/advisories/GHSA-qv2r-v3mx-f4pf
        "ghsa": "GHSA-qv2r-v3mx-f4pf",
        "severity": "medium",
        "cve": None,
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
        "cvss_score": 6.5,
        "cwe": None,
        "crates": [
            ("zebra-rpc", "<=7.0.0", "8.0.0"),
            ("zebrad", "<=4.4.1", "4.5.0"),
        ],
        "component": "zebra-rpc getblocktemplate - byte-offset slicing of user LongPollId panics on multi-byte UTF-8 (str indexing); panic=abort kills node",
        "bug_class": "byte-offset-str-slice-panic-on-non-ascii",
        "attack_class": "authenticated-rpc-utf8-slice-panic-dos",
        "attacker_role": "privileged-trusted",  # authenticated RPC client; schema enum has no authenticated-user
        "impact_class": "dos",
        "impact_actor": "validator-set",
        "year": 2025,
        "summary": (
            "Full node denial of service via non-ASCII LongPollId in "
            "getblocktemplate. The getblocktemplate RPC handler slices the "
            "user-supplied LongPollId at fixed byte offsets to extract the encoded "
            "tip hash and tip height. When LongPollId contains multi-byte UTF-8 "
            "characters, the byte-indexed slice can land mid-character, causing "
            "Rust's str indexing to panic; under panic=abort this terminates the "
            "entire zebrad process."
        ),
        "invariant_text": (
            "RPC string parsing MUST NOT slice attacker-supplied strings at fixed "
            "byte offsets without validating char boundaries; the getblocktemplate "
            "LongPollId parser MUST handle non-ASCII input as a returned error "
            "rather than panicking on a mid-character str index under panic=abort."
        ),
        "violated_consequence": (
            "A non-ASCII LongPollId byte-slice lands mid-character, panicking str "
            "indexing and aborting the node on a single authenticated RPC call."
        ),
        "inv_category": "input-validation",
        "commit_point": "validate char boundaries / use checked parsing before slicing LongPollId",
        "defense_layer": "char-boundary-safe parsing / no-panic-on-untrusted-input",
        "detector_id": "fixed-byte-offset-slice-of-untrusted-string",
        "regex_pattern": r"\b(?:LongPollId|long_poll_id)\b[\s\S]{0,200}?\[\s*\d+\s*\.\.",
        "ast_hint": (
            "Flag fixed-numeric-offset slicing (s[0..N], s[N..]) of an attacker-"
            "supplied String without an is_char_boundary check."
        ),
        "fp_reduction": (
            "Only flag when the sliced string is attacker-controlled RPC input; "
            "ignore slices of byte arrays (&[u8]) or validated-ASCII strings."
        ),
        "positive_fixture": (
            "let tip = &long_poll_id[0..64]; // panics if a multi-byte char straddles byte 64"
        ),
    },
    {
        # https://github.com/ZcashFoundation/zebra/security/advisories/GHSA-gq4h-3grw-2rhv
        "ghsa": "GHSA-gq4h-3grw-2rhv",
        "severity": "critical",
        "cve": "CVE-2026-44497",
        "cvss": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:H/SC:N/SI:H/SA:H",
        "cvss_score": 9.3,
        "cwe": None,
        "crates": [
            ("zebra-script", "<6.0.0", "6.0.0"),
            ("zebrad", "<4.4.0", "4.4.0"),
        ],
        "component": "zebra-script transparent sighash FFI - Rust callback returns None on invalid hash-type; C++ bridge only updates sighash buffer on Some, leaving a stale digest",
        "bug_class": "stale-sighash-buffer-on-none-callback",
        "attack_class": "consensus-divergence-via-stale-ffi-buffer",
        "attacker_role": "unprivileged",
        "impact_class": "dos",
        "impact_actor": "validator-set",
        "year": 2026,
        "summary": (
            "Consensus divergence in transparent sighash hash-type handling due to a "
            "stale buffer. A fix for a previous vulnerability created a new consensus "
            "failure: when processing transparent transaction signatures the Rust "
            "callback validates hash-types but returns None for invalid ones, and the "
            "C++ FFI bridge only updates the sighash buffer on a Some return. When the "
            "callback fails the input sighash buffer is left untouched, so a valid "
            "digest from a prior operation remains in the buffer, causing signature "
            "verification to succeed incorrectly and creating network divergence "
            "between Zebra and zcashd. CVE-2026-44497, CVSS:4.0 base 9.3."
        ),
        "invariant_text": (
            "An FFI sighash bridge MUST NOT leave a stale digest in the output buffer "
            "when the Rust callback returns None (invalid hash-type); a failed "
            "callback MUST cause verification to fail, never reuse a prior "
            "operation's digest left in the untouched buffer."
        ),
        "violated_consequence": (
            "On an invalid hash-type the sighash buffer keeps a prior valid digest, "
            "making an invalid signature verify and diverging Zebra from zcashd."
        ),
        "inv_category": "consensus-parity",
        "commit_point": "clear/fail the sighash buffer when the callback returns None before any verification uses it",
        "defense_layer": "fail-closed FFI buffer handling / no-stale-digest-reuse",
        "detector_id": "ffi-output-buffer-not-cleared-on-callback-none",
        "regex_pattern": r"\b(?:Some|None)\b[\s\S]{0,200}?\b(?:sighash|buffer|digest)\b[\s\S]{0,120}?\b(?:update|copy|write)\b",
        "ast_hint": (
            "Flag an FFI bridge that writes an output buffer only on the Some/Ok "
            "branch of a callback and leaves it untouched on None/Err, where a "
            "consumer later reads the buffer regardless of the branch."
        ),
        "fp_reduction": (
            "Only flag when the untouched buffer is read by a security-critical "
            "consumer (signature/sighash verification) on the None/Err path; ignore "
            "buffers re-initialized before every use."
        ),
        "positive_fixture": (
            "match rust_callback(hash_type) {\n"
            "    Some(d) => buffer.copy_from(d), // only updated on Some\n"
            "    None => {} // buffer keeps prior digest -> stale -> verify passes\n"
            "}"
        ),
    },
    {
        # https://github.com/ZcashFoundation/zebra/security/advisories/GHSA-438q-jx8f-cccv
        "ghsa": "GHSA-438q-jx8f-cccv",
        "severity": "medium",
        "cve": "CVE-2026-44500",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
        "cvss_score": 5.3,
        "cwe": "CWE-770",
        "crates": [
            ("zebra-chain", "<6.0.3", "7.0.0"),
            ("zebra-network", "<5.0.2", "6.0.0"),
            ("zebrad", "<4.4.0", "4.4.0"),
        ],
        "component": "zebra inbound network deserializers - buffers allocated from generic transport/block-size ceilings instead of stricter protocol/consensus limits (4 amplification cases)",
        "bug_class": "deser-preallocation-from-transport-ceiling-not-protocol-limit",
        "attack_class": "allocation-amplification-on-inbound-deserialize",
        "attacker_role": "unprivileged",
        "impact_class": "dos",
        "impact_actor": "validator-set",
        "year": 2026,
        "summary": (
            "Allocation amplification in inbound network deserializers. "
            "Deserialization routines allocated buffers using generic transport or "
            "block-size ceilings rather than stricter protocol/consensus limits, "
            "producing four distinct allocation-amplification cases: headers-message "
            "ceilings (~8.8x gap), equihash solution lengths, Sapling spend vectors "
            "in coinbase transactions, and coinbase script bytes. An unauthenticated "
            "attacker sends malformed inbound messages to force excessive "
            "preallocation and parsing overhead, a DoS across concurrent peer "
            "connections. CVE-2026-44500, CWE-770."
        ),
        "invariant_text": (
            "Inbound network deserializers MUST size preallocations by the strictest "
            "applicable protocol/consensus limit (e.g. real headers count, equihash "
            "length, Sapling-spend cap, coinbase script cap), never by the generic "
            "transport/block-size ceiling; preallocation MUST NOT exceed what a "
            "valid message can contain."
        ),
        "violated_consequence": (
            "Deserializers preallocate from the 2 MiB transport ceiling instead of "
            "the real protocol limit, letting an attacker amplify allocation/parsing "
            "(up to ~8.8x) across peers into a DoS."
        ),
        "inv_category": "resource-bounds",
        "commit_point": "preallocate by the protocol/consensus limit, not the transport/block-size ceiling",
        "defense_layer": "strictest-limit-driven preallocation / bounded deserialize",
        "detector_id": "deser-prealloc-from-transport-ceiling",
        "regex_pattern": r"\b(?:with_capacity|reserve|Vec::with_capacity)\b[\s\S]{0,120}?\b(?:MAX_PROTOCOL_MESSAGE|MAX_BLOCK|2\s*\*\s*1024|message_size|body_len)\b",
        "ast_hint": (
            "Flag deserializer preallocations whose capacity is derived from a "
            "transport/block-size ceiling rather than the message-type's own "
            "protocol/consensus element-count limit."
        ),
        "fp_reduction": (
            "Only flag inbound (untrusted) deserialize paths where the cap used is "
            "looser than the documented protocol element limit; ignore paths already "
            "bounded by the per-type limit."
        ),
        "positive_fixture": (
            "let n = reader.read_compactsize()?; // bounded only by 2 MiB transport ceiling\n"
            "let mut v = Vec::with_capacity(n as usize); // ~233k addrs vs 1000 real limit"
        ),
    },
    {
        # https://github.com/ZcashFoundation/zebra/security/advisories/GHSA-cwfq-rfcr-8hmp
        "ghsa": "GHSA-cwfq-rfcr-8hmp",
        "severity": "critical",
        "cve": None,
        "cvss": None,
        "cvss_score": None,
        "cwe": None,
        "crates": [
            ("zebrad", "<4.4.0", "4.4.0"),
        ],
        "component": "zebra transparent V5+ verification - SIGHASH_SINGLE with no corresponding output computes a digest instead of failing, diverging from zcashd",
        "bug_class": "sighash-single-missing-output-digest-vs-reject",
        "attack_class": "consensus-divergence-block-validity-split",
        "attacker_role": "unprivileged",
        "impact_class": "dos",
        "impact_actor": "validator-set",
        "year": 2025,
        "summary": (
            "Zebra transparent SIGHASH_SINGLE corresponding-output handling diverges "
            "from zcashd. For V5+ transparent transactions, when processing "
            "SIGHASH_SINGLE signatures lacking a corresponding output, zcashd "
            "correctly rejects per ZIP-244, but Zebra's transparent verification path "
            "computes a digest for the missing-output scenario instead of failing. "
            "Crafted V5 transactions with fewer outputs than inputs pass Zebra's "
            "mempool and block-template selection while zcashd rejects them, a direct "
            "block-validity split where Zebra mines blocks zcashd rejects."
        ),
        "invariant_text": (
            "Zebra's transparent V5+ verification MUST reject a SIGHASH_SINGLE input "
            "with no corresponding output (ZIP-244), identically to zcashd, rather "
            "than computing a digest for the missing-output case; mempool and "
            "block-template selection MUST NOT admit such transactions."
        ),
        "violated_consequence": (
            "Zebra accepts/mines V5 transactions with fewer outputs than inputs under "
            "SIGHASH_SINGLE that zcashd rejects, a direct block-validity split."
        ),
        "inv_category": "consensus-parity",
        "commit_point": "reject SIGHASH_SINGLE with no corresponding output in the transparent verification path",
        "defense_layer": "ZIP-244 enforcement across mempool + block-template + verification / zcashd parity",
        "detector_id": "sighash-single-missing-output-not-rejected-verifypath",
        "regex_pattern": r"SIGHASH_SINGLE[\s\S]{0,300}?\b(?:digest|sighash|compute)\b",
        "ast_hint": (
            "Flag transparent verification SIGHASH_SINGLE handling that computes a "
            "digest without rejecting a missing corresponding output."
        ),
        "fp_reduction": (
            "Only flag the consensus verification path; ignore wallet signing. "
            "Distinct from GHSA-pvmv (same bug class, earlier crate range)."
        ),
        "positive_fixture": (
            "// SIGHASH_SINGLE, input_index >= outputs.len()\n"
            "let d = compute_sighash(...); // computed instead of Err -> diverges from zcashd"
        ),
    },
    {
        # https://github.com/ZcashFoundation/zebra/security/advisories/GHSA-jv4h-j224-23cc
        "ghsa": "GHSA-jv4h-j224-23cc",
        "severity": "critical",
        "cve": "CVE-2026-44498",
        "cvss": None,
        "cvss_score": None,
        "cwe": None,
        "crates": [
            ("zebrad", "<4.4.0", "4.4.0"),
        ],
        "component": "zebra block validator Sigops impl - skips coinbase input entirely + never accumulates per-block P2SH sigops during block validation (only mempool path)",
        "bug_class": "coinbase-and-p2sh-sigop-undercount-block-validation",
        "attack_class": "consensus-divergence-via-sigop-undercount",
        "attacker_role": "unprivileged",
        "impact_class": "dos",
        "impact_actor": "validator-set",
        "year": 2026,
        "summary": (
            "Block validator undercounts coinbase and P2SH sigops. Two sigop-counting "
            "flaws let Zebra accept blocks zcashd rejects: (1) coinbase legacy sigops "
            "undercount - Zebra's Sigops impl skipped the coinbase input entirely, "
            "hiding up to ~98 sigops in the coinbase scriptSig despite the 100-byte "
            "script-length cap; (2) aggregate P2SH sigops undercount - Zebra computed "
            "P2SH sigops only on the mempool-acceptance path and never accumulated "
            "them during block validation, while zcashd aggregates per block. Blocks "
            "exceeding the 20,000-sigop limit are accepted by Zebra but rejected by "
            "zcashd, risking network divergence. CVE-2026-44498."
        ),
        "invariant_text": (
            "Block-validation sigop counting MUST include the coinbase input's sigops "
            "and MUST accumulate per-block P2SH sigops during block validation (not "
            "only on the mempool path), so the MAX_BLOCK_SIGOPS=20000 decision is "
            "identical to zcashd and cannot be undercounted."
        ),
        "violated_consequence": (
            "Zebra omits coinbase sigops and never aggregates P2SH sigops at block "
            "validation, accepting over-limit blocks that zcashd rejects."
        ),
        "inv_category": "consensus-parity",
        "commit_point": "count coinbase sigops + accumulate per-block P2SH sigops in the block-validation path before the MAX_BLOCK_SIGOPS check",
        "defense_layer": "complete sigop accounting at block validation / zcashd parity",
        "detector_id": "block-validation-sigop-undercount-coinbase-p2sh",
        "regex_pattern": r"\b(?:Sigops|sigop)\w*\b[\s\S]{0,300}?\b(?:coinbase|p2sh|P2SH|skip|continue)\b",
        "ast_hint": (
            "Flag a block-validation sigop counter that skips the coinbase input or "
            "that computes P2SH sigops only on the mempool path with no per-block "
            "accumulation."
        ),
        "fp_reduction": (
            "Only flag the block-validation sigop path feeding MAX_BLOCK_SIGOPS; "
            "ignore mempool-only counters that are correctly separate."
        ),
        "positive_fixture": (
            "for input in tx.inputs() { if input.is_coinbase() { continue; } count += sigops(input); } // coinbase skipped\n"
            "// P2SH sigops never accumulated during block validation"
        ),
    },
    {
        # https://github.com/ZcashFoundation/zebra/security/advisories/GHSA-29x4-r6jv-ff4w
        "ghsa": "GHSA-29x4-r6jv-ff4w",
        "severity": "medium",
        "cve": None,
        "cvss": "CVSS:4.0/AV:N/AC:L/AT:P/PR:H/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:H",
        "cvss_score": 6.9,
        "cwe": "CWE-617",
        "crates": [
            ("zebra-rpc", ">=1.0.0-beta.45,<6.0.2", "6.0.2"),
            ("zebrad", ">=2.2.0,<4.3.1", "4.3.1"),
        ],
        "component": "zebra-rpc JSON-RPC HTTP middleware - treats failure to read request body as unrecoverable, aborts process instead of returning an error response",
        "bug_class": "rpc-body-read-failure-treated-as-fatal-abort",
        "attack_class": "authenticated-rpc-disconnect-abort-dos",
        "attacker_role": "privileged-trusted",  # authenticated RPC client; schema enum has no authenticated-user
        "impact_class": "dos",
        "impact_actor": "validator-set",
        "year": 2025,
        "summary": (
            "Denial of service via interrupted JSON-RPC requests from authenticated "
            "clients. Zebra's JSON-RPC HTTP middleware treated failures reading "
            "incoming request bodies as fatal rather than recoverable: when an "
            "authenticated client disconnected mid-transmission, the node treats the "
            "failure to read the HTTP request body as an unrecoverable error and "
            "aborts the process instead of returning an error response. CWE-248 "
            "uncaught exception / CWE-617 reachable assertion. CVSS:4.0 base 6.9."
        ),
        "invariant_text": (
            "The JSON-RPC HTTP middleware MUST treat a failure to read an incoming "
            "request body (e.g. a mid-transmission client disconnect) as a "
            "recoverable per-request error returning a standard error response, "
            "never as an unrecoverable condition that aborts the node process."
        ),
        "violated_consequence": (
            "An authenticated client disconnecting mid-request makes the body read "
            "fail and the node abort, rather than returning an RPC error."
        ),
        "inv_category": "error-handling",
        "commit_point": "map request-body read errors to an RPC error response, not a process abort",
        "defense_layer": "recoverable per-request error handling / no-abort-on-IO-error",
        "detector_id": "rpc-body-read-error-aborts-process",
        "regex_pattern": r"\b(?:read|body|request)\b[\s\S]{0,160}?\.(?:expect|unwrap)\(|\bpanic!\([\s\S]{0,80}?body",
        "ast_hint": (
            "Flag RPC/HTTP middleware that .expect()/.unwrap()/panics on a "
            "request-body read error instead of returning an error response."
        ),
        "fp_reduction": (
            "Only flag the inbound RPC request-read path; ignore outbound client "
            "code or test harnesses."
        ),
        "positive_fixture": (
            "let body = read_body(&mut req).expect(\"body\"); // client disconnect -> abort"
        ),
    },
    {
        # https://github.com/ZcashFoundation/zebra/security/advisories/GHSA-452v-w3gx-72wg
        "ghsa": "GHSA-452v-w3gx-72wg",
        "severity": "critical",
        "cve": "CVE-2026-41584",
        "cvss": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:H",
        "cvss_score": 9.2,
        "cwe": None,
        "crates": [
            ("zebra-chain", "<6.0.2", "6.0.2"),
            ("zebrad", "<4.3.1", "4.3.1"),
        ],
        "component": "zebra-chain Orchard rk verification - gets coordinates of rk and unwrap()s, panicking if rk is the identity point (spec permits identity)",
        "bug_class": "orchard-rk-identity-point-unwrap-panic",
        "attack_class": "crafted-tx-identity-point-panic-dos",
        "attacker_role": "unprivileged",
        "impact_class": "dos",
        "impact_actor": "validator-set",
        "year": 2026,
        "summary": (
            "rk identity point panic in transaction verification. Orchard "
            "transactions contain an rk field (randomized validating key, an EC "
            "point). While the Zcash spec permits identity values, the orchard "
            "crate's verification logic gets the coordinates of rk and calls unwrap() "
            "on the results, panicking if rk is the identity. An attacker crafts a "
            "transaction with an identity rk and submits it to crash vulnerable Zebra "
            "nodes. The fix rejects identity rk values during transaction parsing "
            "rather than modifying the orchard crate. CVE-2026-41584, CVSS:4.0 base "
            "9.2."
        ),
        "invariant_text": (
            "Transaction parsing MUST reject an Orchard rk that is the identity point "
            "before any verification step that takes its affine coordinates and "
            "unwrap()s; identity-point inputs that the spec permits structurally MUST "
            "NOT reach an unwrap()-on-coordinates that panics the node."
        ),
        "violated_consequence": (
            "An identity-point rk reaches coordinate extraction + unwrap(), panicking "
            "and crashing the node on a crafted transaction."
        ),
        "inv_category": "input-validation",
        "commit_point": "reject identity rk at parse time before coordinate extraction",
        "defense_layer": "reject-identity-point-at-parse / no-unwrap-on-untrusted-point-coords",
        "detector_id": "ec-point-coordinate-unwrap-on-untrusted-identity",
        "regex_pattern": r"\brk\b[\s\S]{0,160}?\.(?:coordinates|to_affine|x|y)\(\)[\s\S]{0,60}?\.unwrap\(",
        "ast_hint": (
            "Flag .unwrap()/.expect() on coordinate extraction of an attacker-"
            "supplied EC point (rk/validating key) that can be the identity."
        ),
        "fp_reduction": (
            "Only flag points parsed from untrusted transaction data where identity "
            "is structurally representable; ignore points known non-identity."
        ),
        "positive_fixture": (
            "let (x, y) = rk.to_affine().coordinates().unwrap(); // identity rk -> panic"
        ),
    },
    {
        # https://github.com/ZcashFoundation/zebra/security/advisories/GHSA-8m29-fpq5-89jj
        "ghsa": "GHSA-8m29-fpq5-89jj",
        "severity": "critical",
        "cve": "CVE-2026-41583",
        "cvss": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:H/SC:N/SI:H/SA:H",
        "cvss_score": 9.3,
        "cwe": None,
        "crates": [
            ("zebra-script", "<5.0.2", "5.0.2"),
            ("zebrad", "<4.3.1", "4.3.1"),
        ],
        "component": "zebra-script transparent sighash - C++->Rust refactor omitted the V5 hash-type-restriction consensus rule; V4 used canonical instead of raw hash-type values",
        "bug_class": "sighash-hashtype-restriction-omitted-on-refactor",
        "attack_class": "consensus-divergence-via-sighash-rule-omission",
        "attacker_role": "unprivileged",
        "impact_class": "dos",
        "impact_actor": "validator-set",
        "year": 2026,
        "summary": (
            "Consensus divergence in transparent sighash hash-type handling. After a "
            "refactor that moved verification logic from C++ to Rust, a consensus "
            "rule validation was omitted: the code failed to validate the rule "
            "restricting the possible sighash hash-type values for V5 transactions, "
            "and for V4 transactions it incorrectly used canonical hash-type values "
            "instead of raw values during sighash computation. This let Zebra accept "
            "transactions rejected by zcashd, enabling network partitioning, service "
            "disruption, and potential double-spend. CVE-2026-41583, CVSS:4.0 base "
            "9.3."
        ),
        "invariant_text": (
            "Transparent sighash validation MUST enforce the V5 hash-type-value "
            "restriction and MUST use raw (not canonical) hash-type values for V4 "
            "sighash computation, identically to zcashd; a C++->Rust refactor MUST "
            "preserve every consensus rule it moves."
        ),
        "violated_consequence": (
            "Omitting the V5 hash-type restriction and using canonical V4 values "
            "makes Zebra accept transactions zcashd rejects, partitioning the "
            "network."
        ),
        "inv_category": "consensus-parity",
        "commit_point": "restore the V5 hash-type-restriction check + use raw V4 hash-type values in sighash",
        "defense_layer": "consensus-rule-preservation-across-refactor / zcashd parity",
        "detector_id": "sighash-hashtype-restriction-missing-or-canonical-v4",
        "regex_pattern": r"\bhash_type\b[\s\S]{0,200}?\b(?:canonical|V5|V4|restrict|valid)\b",
        "ast_hint": (
            "Flag sighash code that does not restrict V5 hash-type values, or that "
            "canonicalizes the V4 hash-type before digesting."
        ),
        "fp_reduction": (
            "Only flag the consensus sighash path; distinct from GHSA-gq4h "
            "(stale-buffer) and GHSA-pvmv (SIGHASH_SINGLE)."
        ),
        "positive_fixture": (
            "// V5: missing restriction on allowed hash_type values\n"
            "let ht = canonical_hash_type(raw); // V4 should use raw, not canonical"
        ),
    },
    {
        # https://github.com/ZcashFoundation/zebra/security/advisories/GHSA-xr93-pcq3-pxf8
        "ghsa": "GHSA-xr93-pcq3-pxf8",
        "severity": "medium",
        "cve": "CVE-2026-40881",
        "cvss": "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:L",
        "cvss_score": 6.3,
        "cwe": "CWE-770",
        "crates": [
            ("zebra-network", "<5.0.1", "5.0.1"),
            ("zebrad", "<4.3.1", "4.3.1"),
        ],
        "component": "zebra-network addr/addrv2 deserialize - fully deserializes up to >233000 addresses (derived from 2 MiB msg cap) before the 1000-address limit check",
        "bug_class": "addr-deser-fully-before-1000-cap-check",
        "attack_class": "allocation-amplification-deserialize-before-cap",
        "attacker_role": "unprivileged",
        "impact_class": "dos",
        "impact_actor": "validator-set",
        "year": 2026,
        "summary": (
            "addr/addrv2 deserialization resource exhaustion. When deserializing addr "
            "or addrv2 messages (vectors of addresses), Zebra fully deserialized them "
            "up to a maximum length over 233,000 derived from the 2 MiB message-size "
            "limit, whereas the specification mandates a maximum of 1,000 addresses. "
            "The limit check occurred AFTER deserialization completed, so an attacker "
            "could trigger excessive memory allocation and DoS crashes by sending "
            "crafted messages across connections. CVE-2026-40881, CWE-770, CVSS:4.0 "
            "base 6.3."
        ),
        "invariant_text": (
            "addr/addrv2 deserialization MUST enforce the 1000-address protocol limit "
            "DURING (or before) deserialization, never allocate/deserialize up to the "
            "~233000-entry transport ceiling and check the limit only afterward."
        ),
        "violated_consequence": (
            "Zebra deserializes up to ~233000 addresses before applying the 1000-cap, "
            "letting an attacker amplify allocation into a DoS."
        ),
        "inv_category": "resource-bounds",
        "commit_point": "enforce the 1000-address cap during deserialization, before full allocation",
        "defense_layer": "limit-before-allocate / bounded vector deserialize",
        "detector_id": "vector-deser-cap-checked-after-allocation",
        "regex_pattern": r"\b(?:addr|addrv2)\b[\s\S]{0,200}?\b(?:deserialize|read)\b[\s\S]{0,200}?\b(?:1000|MAX_ADDR|len\s*>)\b",
        "ast_hint": (
            "Flag vector deserialize that reads up to a transport-derived ceiling "
            "and applies the protocol element-count cap only after the loop."
        ),
        "fp_reduction": (
            "Only flag inbound addr/addrv2 (and similar capped-vector) deserialize "
            "where the cap check is post-loop; ignore pre-bounded reads."
        ),
        "positive_fixture": (
            "let addrs: Vec<_> = read_vec(reader)?; // up to ~233k\n"
            "if addrs.len() > 1000 { return Err(...); } // checked AFTER full deser"
        ),
    },
    {
        # https://github.com/ZcashFoundation/zebra/security/advisories/GHSA-xvj8-ph7x-65gf
        "ghsa": "GHSA-xvj8-ph7x-65gf",
        "severity": "high",
        "cve": "CVE-2026-40880",
        "cvss": "CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:N/VC:N/VI:H/VA:H/SC:N/SI:H/SA:H",
        "cvss_score": 7.2,
        "cwe": None,
        "crates": [
            ("zebra-consensus", "<5.0.2", "5.0.2"),
            ("zebrad", "<4.3.1", "4.3.1"),
        ],
        "component": "zebra-consensus tx verification cache - caches valid txs without height-dependent validity (expiry/locktime/upgrade), reused for ahead-of-tip blocks",
        "bug_class": "tx-cache-ignores-height-dependent-validity",
        "attack_class": "consensus-divergence-via-height-blind-cache",
        "attacker_role": "privileged-trusted",  # authenticated RPC client; schema enum has no authenticated-user
        "impact_class": "dos",
        "impact_actor": "validator-set",
        "year": 2026,
        "summary": (
            "Cached mempool verification bypasses consensus rules for ahead-of-tip "
            "blocks. A flawed performance optimization cached valid transactions "
            "without accounting for height-dependent validity constraints (expiry "
            "heights, lock times, network upgrades). An attacker submits a "
            "transaction valid at height H+1 but invalid at H+2, mines it in a block "
            "at H+2 submitted before H+1, and makes vulnerable nodes accept the "
            "invalid block while others reject it, a network partition. "
            "CVE-2026-40880, CVSS:4.0 base 7.2."
        ),
        "invariant_text": (
            "The transaction verification cache MUST key/scope cached validity by the "
            "height-dependent constraints (expiry height, lock time, active network "
            "upgrade) so a cache hit at a different height cannot bypass a "
            "height-dependent consensus rule; a tx valid at H+1 MUST NOT be treated "
            "as valid at H+2 from cache."
        ),
        "violated_consequence": (
            "A height-blind cache hit lets a transaction valid at one height be "
            "accepted at another, so an ahead-of-tip block bypasses height-dependent "
            "rules and splits the network."
        ),
        "inv_category": "consensus-parity",
        "commit_point": "include height-dependent context in the verification-cache key / re-check height-dependent rules on hit",
        "defense_layer": "height-scoped verification cache / no-height-blind-reuse",
        "detector_id": "verification-cache-key-omits-height-context",
        "regex_pattern": r"\b(?:cache|verified)\b[\s\S]{0,200}?\b(?:txid|hash)\b(?![\s\S]{0,160}?\b(?:height|expiry|lock_time|upgrade)\b)",
        "ast_hint": (
            "Flag a verification cache keyed only by txid/hash with no height/"
            "expiry/locktime/upgrade component when cached validity is height-"
            "dependent."
        ),
        "fp_reduction": (
            "Only flag caches whose hit short-circuits height-dependent consensus "
            "checks; ignore caches that re-validate height rules on hit."
        ),
        "positive_fixture": (
            "if let Some(ok) = cache.get(&txid) { return ok; } // ignores height -> H+1 reused at H+2"
        ),
    },
    {
        # https://github.com/ZcashFoundation/zebra/security/advisories/GHSA-3vmh-33xr-9cqh
        "ghsa": "GHSA-3vmh-33xr-9cqh",
        "severity": "high",
        "cve": "CVE-2026-34377",
        "cvss": "CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:N/VI:H/VA:H/SC:N/SI:H/SA:H",
        "cvss_score": 8.4,
        "cwe": "CWE-347",
        "crates": [
            ("zebra-consensus", "<5.0.1", "5.0.1"),
            ("zebrad", "<4.3.0", "4.3.0"),
        ],
        "component": "zebra-consensus find_verified_unmined_tx - uses ZIP-244 txid (excludes V5 auth data) as sole cache key, skipping check_v5_auth() on a same-txid modified tx",
        "bug_class": "v5-auth-skipped-via-txid-only-cache-key",
        "attack_class": "consensus-divergence-via-auth-data-excluded-key",
        "attacker_role": "privileged-trusted",  # authenticated RPC client; schema enum has no authenticated-user
        "impact_class": "dos",
        "impact_actor": "validator-set",
        "year": 2026,
        "summary": (
            "Consensus failure via crafted V5 authorization data. A logic flaw in the "
            "verification cache's find_verified_unmined_tx used the ZIP-244 txid as "
            "the sole lookup key, but for V5 transactions that identifier excludes "
            "authorization data. An attacker broadcasts a valid transaction, then "
            "includes a modified version with identical txid but invalid signatures "
            "in a block, making vulnerable nodes skip the critical check_v5_auth() "
            "call and accept invalid data, a consensus split. CVE-2026-34377, "
            "CWE-347 improper verification of cryptographic signature, CVSS:4.0 base "
            "8.4."
        ),
        "invariant_text": (
            "The verification cache lookup for V5 transactions MUST key on an "
            "identifier that includes authorization data (or MUST re-run "
            "check_v5_auth() on every cache hit); the ZIP-244 txid, which excludes "
            "auth data, MUST NOT be the sole key, so a same-txid tx with different "
            "(invalid) signatures cannot reuse a prior valid verification."
        ),
        "violated_consequence": (
            "A modified V5 tx with the same txid but invalid signatures hits the "
            "cache, skips check_v5_auth(), and is accepted, splitting consensus."
        ),
        "inv_category": "consensus-parity",
        "commit_point": "key the V5 verification cache on auth-inclusive id (e.g. wtxid/authdigest) or re-run check_v5_auth() on hit",
        "defense_layer": "auth-inclusive cache key / re-verify-signature-on-hit",
        "detector_id": "v5-verification-cache-keyed-on-authless-txid",
        "regex_pattern": r"\bfind_verified_unmined_tx\b|\bcache\b[\s\S]{0,160}?\btxid\b[\s\S]{0,160}?\bv5|auth",
        "ast_hint": (
            "Flag a V5 verification-cache lookup keyed solely on a ZIP-244 txid "
            "(auth-data-excluding) whose hit skips signature/auth re-verification."
        ),
        "fp_reduction": (
            "Only flag V5+ paths where the cache hit bypasses check_v5_auth(); "
            "ignore caches keyed on wtxid/authdigest or that re-verify on hit."
        ),
        "positive_fixture": (
            "if let Some(tx) = cache.find_verified_unmined_tx(&txid) { /* skips check_v5_auth() */ }"
        ),
    },
    {
        # https://github.com/ZcashFoundation/zebra/security/advisories/GHSA-qp6f-w4r3-h8wg
        "ghsa": "GHSA-qp6f-w4r3-h8wg",
        "severity": "critical",
        "cve": "CVE-2026-34202",
        "cvss": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:H",
        "cvss_score": 9.2,
        "cwe": "CWE-248",
        "crates": [
            ("zebra-chain", "<6.0.1", "6.0.1"),
            ("zebrad", "<4.3.0", "4.3.0"),
        ],
        "component": "zebra-chain V5 tx parsing - network codec deserializes malformed V5 tx successfully but TxID calculation panics (lazy validation vs librustzcash eager)",
        "bug_class": "lazy-v5-field-validation-txid-calc-panic",
        "attack_class": "unauthenticated-crafted-tx-panic-dos",
        "attacker_role": "unprivileged",
        "impact_class": "dos",
        "impact_actor": "validator-set",
        "year": 2026,
        "summary": (
            "Remote denial of service via crafted V5 transactions. The vulnerability "
            "arises from lazy validation of transaction fields that are eagerly "
            "validated in the librustzcash parsing logic. When Zebra processes V5 "
            "transactions, the network codec successfully deserializes malformed "
            "transactions, but the subsequent TxID calculation triggers a panic. An "
            "attacker exploits this by transmitting a crafted transaction message to "
            "the P2P port (default 8233) or via the sendrawtransaction RPC, causing "
            "immediate node failure without authentication. CVE-2026-34202, CWE-248, "
            "CVSS:4.0 base 9.2."
        ),
        "invariant_text": (
            "V5 transaction field validation MUST be eager (matching librustzcash) so "
            "the network codec rejects a malformed V5 transaction at deserialization; "
            "a malformed transaction MUST NOT deserialize successfully only to panic "
            "later during TxID calculation."
        ),
        "violated_consequence": (
            "A malformed V5 tx deserializes, then panics in TxID calculation, "
            "crashing the node from the P2P port or sendrawtransaction without auth."
        ),
        "inv_category": "input-validation",
        "commit_point": "validate V5 fields eagerly at deserialize (parity with librustzcash) before TxID calculation",
        "defense_layer": "eager-validate-at-deserialize / no-panic-in-txid-calc",
        "detector_id": "lazy-v5-validation-panic-in-txid",
        "regex_pattern": r"\b(?:txid|tx_id|TxId)\b[\s\S]{0,200}?\.(?:expect|unwrap)\(|\bpanic!\([\s\S]{0,80}?txid",
        "ast_hint": (
            "Flag TxID/hash calculation that .expect()/.unwrap()/panics on fields a "
            "valid V5 transaction must have, where deserialization did not validate "
            "them up front."
        ),
        "fp_reduction": (
            "Only flag where the network codec admits the tx before the panicking "
            "TxID calc; ignore paths that eagerly validate at parse."
        ),
        "positive_fixture": (
            "let tx = codec.decode_v5(bytes)?; // malformed admitted (lazy)\n"
            "let id = tx.txid(); // panics here"
        ),
    },
]


# ---------------------------------------------------------------------------
# helpers (byte-stable yaml, mirrored from sibling miners)
# ---------------------------------------------------------------------------


def slugify(value: object, *, max_len: int = 80) -> str:
    text = str(value or "").strip().lower()
    text = re.sub(r"[^a-z0-9._:/-]+", "-", text).strip("-._")
    text = re.sub(r"-{2,}", "-", text)
    return text[:max_len].strip("-._") or "record"


def one_line(text: object, fallback: str, *, max_len: int = 1000) -> str:
    cleaned = re.sub(r"\s+", " ", str(text or "")).strip()
    return cleaned[:max_len].strip() if cleaned else fallback


def yaml_scalar(value: object) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    text = str(value if value is not None else "")
    if text == "":
        return '""'
    numeric = re.fullmatch(r"[-+]?(?:0|[1-9][0-9_]*)(?:\.[0-9_]+)?", text)
    ambiguous = text.lower() in {"true", "false", "null", "yes", "no", "on", "off", "~"}
    plain_safe = (
        re.fullmatch(r"[A-Za-z0-9._:/<>=,$#-]+", text)
        and not text.endswith(":")
        and not text.startswith(
            ("#", "-", "?", ":", "<", ">", "@", "`", "&", "*", "!", "|", "%", "{", "}", "[", "]", ",")
        )
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
                    lines.append(f"  - {yaml_scalar(item)}")
        else:
            lines.append(f"{key}: {yaml_scalar(value)}")
    return "\n".join(lines) + "\n"


def _dollar_class(severity: str) -> str:
    return {
        "critical": ">=$1M",
        "high": "$100K-$1M",
        "medium": "$10K-$100K",
        "low": "<$10K",
    }.get(severity.lower(), "non-financial")


def _ghsa_url(ghsa: str) -> str:
    return f"https://github.com/{ZEBRA_REPO}/security/advisories/{ghsa}"


# ---------------------------------------------------------------------------
# builders
# ---------------------------------------------------------------------------


def build_record(adv: Dict[str, Any]) -> Dict[str, Any]:
    ghsa = adv["ghsa"]
    severity = adv["severity"]
    url = _ghsa_url(ghsa)
    crate_tags = [slugify(f"crate-{c[0]}", max_len=64) for c in adv["crates"]]
    shape_tags = [
        slugify(ghsa, max_len=64),
        slugify(f"bug-{adv['bug_class']}", max_len=64),
        slugify(f"attack-{adv['attack_class']}", max_len=64),
        "zcash-node",
        "zebra",
        "verification_tier=" + VERIFICATION_TIER,
    ]
    if adv.get("cwe"):
        shape_tags.append(slugify(adv["cwe"], max_len=64))
    shape_tags.extend(crate_tags)
    seen: set = set()
    uniq_tags: List[str] = []
    for t in shape_tags:
        if t and t not in seen:
            seen.add(t)
            uniq_tags.append(t)

    pre = [f"Reference advisory at {url}"]
    if adv.get("cwe"):
        pre.append(f"Weakness {adv['cwe']}")
    if adv.get("cvss"):
        pre.append(f"CVSS:3.1 vector {adv['cvss']}")
    if adv.get("cvss_score") is not None:
        pre.append(f"CVSS base score {adv['cvss_score']}")
    for crate, vuln, patched in adv["crates"]:
        pre.append(f"Affected crate {crate} {vuln} -> patched {patched}")
    pre.append(f"verification_tier={VERIFICATION_TIER}")

    record = {
        "schema_version": RECORD_SCHEMA_VERSION,
        "record_id": _record_id(ghsa),
        "source_audit_ref": one_line(url, f"ghsa:{ghsa}", max_len=240),
        "target_domain": "l1-client",
        "target_language": "rust",
        "target_repo": ZEBRA_REPO,
        "target_component": one_line(adv["component"], f"{ZEBRA_REPO}:{ghsa}", max_len=240),
        "function_shape": {
            "raw_signature": one_line(adv["component"], adv["bug_class"], max_len=500),
            "shape_tags": uniq_tags,
        },
        "bug_class": one_line(adv["bug_class"], "zebra-public-advisory", max_len=160),
        "attack_class": one_line(adv["attack_class"], "zebra-public-advisory", max_len=160),
        "attacker_role": adv["attacker_role"],
        "attacker_action_sequence": one_line(
            adv["summary"]
            + f" [source=github-security-advisory; ghsa={ghsa}; "
            + f"verification_tier={VERIFICATION_TIER}]",
            "Zebra GHSA-tracked attacker action sequence",
            max_len=4900,
        ),
        "required_preconditions": [one_line(p, "precondition", max_len=900) for p in pre],
        "impact_class": adv["impact_class"],
        "impact_actor": adv["impact_actor"],
        "impact_dollar_class": _dollar_class(severity),
        "fix_pattern": one_line(
            "Upgrade to the patched crate versions: "
            + "; ".join(f"{c[0]} {c[2]}" for c in adv["crates"])
            + ". Root-cause fix: "
            + adv["defense_layer"]
            + ".",
            "Apply the upstream patched-version range.",
            max_len=900,
        ),
        "fix_anti_pattern_avoided": one_line(
            f"Running an unpatched {severity}-severity zebra node ({adv['bug_class']}); "
            + "ignoring the published GHSA before applying the patched-versions tag.",
            "Running an unpatched advisory-tagged zebra node.",
            max_len=900,
        ),
        "severity_at_finding": severity,
        "year": int(adv["year"]),
        "record_tier": VERIFICATION_TIER,
        "record_quality_score": 4.5,
        "source_extraction_method": "human-curated",
        "source_extraction_confidence": 0.95,
        "cross_language_analogues": [],
        "related_records": [],
    }
    return record


def build_invariant(adv: Dict[str, Any]) -> Dict[str, Any]:
    ghsa = adv["ghsa"]
    inv_id = _invariant_id(adv)
    record = {
        "schema_version": INVARIANT_SCHEMA_VERSION,
        "record_id": _invariant_record_id(ghsa),
        "source": {
            "task_id": f"zebra-advisories-etl:{ghsa}",
            "task_type": "ghsa-advisory-etl",
            "source_audit_ref": _ghsa_url(ghsa),
        },
        "verification_tier": VERIFICATION_TIER,
        "generated_by": {
            "provider": "human-curated",
            "model_id": "hackerman-etl-from-zebra-advisories",
            "verified_by_second_pass": False,
        },
        "content": {
            "invariant_id": inv_id,
            "invariant_text": one_line(adv["invariant_text"], adv["bug_class"], max_len=4000),
            "violation_consequence": one_line(
                adv["violated_consequence"], "node-level impact", max_len=1000
            ),
            "bug_class": one_line(adv["bug_class"], "zebra", max_len=100),
            "attack_class": one_line(adv["attack_class"], "zebra", max_len=100),
            "target_language": "rust",
            "preconditions": [
                one_line(f"Commit point: {adv['commit_point']}", "commit-point", max_len=500),
                one_line(f"Defense layer: {adv['defense_layer']}", "defense-layer", max_len=500),
            ],
            "source_findings": [one_line(_ghsa_url(ghsa), ghsa, max_len=240)],
        },
        "generated_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    return record


def build_detector_seed(adv: Dict[str, Any]) -> Dict[str, Any]:
    ghsa = adv["ghsa"]
    statement = json.dumps(
        {
            "detector_id": adv["detector_id"],
            "language": "rust",
            "regex_pattern": adv["regex_pattern"],
            "ast_query_hint": adv["ast_hint"],
            "fp_reduction_strategy": adv["fp_reduction"],
            "positive_fixture_snippet": adv["positive_fixture"],
        },
        sort_keys=True,
    )
    record = {
        "schema_version": DETECTOR_SEED_SCHEMA_VERSION,
        "record_id": _detector_seed_id(ghsa),
        "kind": "detector_seed",
        "router": "zebra_advisories_etl",
        "category": adv["inv_category"],
        "statement": statement,
        "target_lang": "rust",
        "raw_keys": [
            "ast_query_hint",
            "detector_id",
            "fp_reduction_strategy",
            "language",
            "positive_fixture_snippet",
            "regex_pattern",
        ],
        "verification_tier": VERIFICATION_TIER,
        "source_task_id": f"zebra-advisories-etl:{ghsa}",
        "source_audit_ref": _ghsa_url(ghsa),
        "attack_class": one_line(adv["attack_class"], "zebra", max_len=160),
        "audit_status": "tier-1-officially-disclosed:zebra-advisories-etl",
        "ts_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    return record


def _record_id(ghsa: str) -> str:
    digest = hashlib.sha256(f"zebra|{ghsa}".encode("utf-8")).hexdigest()[:12]
    return f"zebra:{slugify(ghsa, max_len=64)}:{digest}"[:160]


def _invariant_id(adv: Dict[str, Any]) -> str:
    short = slugify(adv["ghsa"].replace("GHSA-", ""), max_len=40).replace("/", "-")
    short = re.sub(r"[^A-Za-z0-9_.-]", "-", short)
    return f"INV-ZEBRA-{short}"[:84]


def _invariant_record_id(ghsa: str) -> str:
    digest = hashlib.sha256(f"zebra-inv|{ghsa}".encode("utf-8")).hexdigest()[:12]
    return f"zebra-inv:{slugify(ghsa, max_len=60)}:{digest}"[:200]


def _detector_seed_id(ghsa: str) -> str:
    digest = hashlib.sha256(f"zebra-det|{ghsa}".encode("utf-8")).hexdigest()[:12]
    return f"zebra-det:{slugify(ghsa, max_len=60)}:{digest}"[:200]


# ---------------------------------------------------------------------------
# dedupe
# ---------------------------------------------------------------------------


def load_existing_refs(corpus_dir: Optional[Path]) -> set:
    refs: set = set()
    if not corpus_dir or not corpus_dir.exists():
        return refs
    for rec in corpus_dir.rglob("record.json"):
        try:
            doc = json.loads(rec.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        ref = doc.get("source_audit_ref")
        if isinstance(ref, str):
            refs.add(ref)
    return refs


# r36-rebuttal: lane zebra-promote registered in .auditooor/agent_pathspec.json; edit scoped to this ETL tool only
# ---------------------------------------------------------------------------
# router-stage: write promote-tool-consumable batch files
# ---------------------------------------------------------------------------


def _invariant_router_yaml(invariant: Dict[str, Any]) -> Dict[str, Any]:
    """Map a built ``auditooor.invariant.v1`` record to the flat-YAML shape that
    ``promote-mined-to-canonical.py``'s ``invariant_library_extended`` router
    consumes (``_extract_invariant_library_extended``). That extractor reads
    ``content.invariant_id`` + ``content.statement`` (falling back to
    ``content.invariant_text``) and preserves ``verification_tier``."""
    content = invariant.get("content", {})
    src = invariant.get("source", {})
    return {
        "schema_version": "auditooor.invariant_pilot.v1",
        "invariant_id": content.get("invariant_id"),
        "statement": content.get("invariant_text", ""),
        "category": content.get("attack_class") or content.get("bug_class") or "zebra",
        "attack_class": content.get("attack_class"),
        "bug_class": content.get("bug_class"),
        "target_lang": content.get("target_language", "rust"),
        "source_incident_ids": content.get("source_findings", []),
        "verification_tier": invariant.get("verification_tier", VERIFICATION_TIER),
        "batch_id": ROUTER_STAGE_BATCH_ID,
        "source_audit_ref": src.get("source_audit_ref"),
        "violation_consequence": content.get("violation_consequence"),
        "preconditions": content.get("preconditions", []),
    }


def _detector_router_json(detector: Dict[str, Any]) -> Dict[str, Any]:
    """Map a built ``auditooor.detector_seed.v1`` record to the dispatch-ledger
    shape that ``promote-mined-to-canonical.py``'s ``detector_synthesis_v2``
    router consumes (``_extract_dispatch_ledger_generic`` with ``kind=
    detector_seed``). That extractor parses ``rec["result"]`` (string-encoded
    JSON) and preserves ``verification_tier`` from the top-level record."""
    # The built detector's ``statement`` is already string-encoded JSON of the
    # detector body; enrich it with the routing fields the dispatch-ledger
    # extractor pulls (attack_class/category/target_lang/detector_id) so the
    # promoted record carries them.
    body = json.loads(detector["statement"])
    body.update(
        {
            "detector_id": detector["record_id"],
            "attack_class": detector.get("attack_class"),
            "category": detector.get("category"),
            "target_lang": detector.get("target_lang", "rust"),
            "target_language": detector.get("target_lang", "rust"),
            "known_corpus_anchor": detector.get("source_audit_ref"),
        }
    )
    return {
        "schema_version": "auditooor.detector_seed.v1",
        "record_id": detector["record_id"],
        "task_id": detector["record_id"],
        "task_type": "zebra_detector_seed",
        "status": "ok",
        "verification_tier": detector.get("verification_tier", VERIFICATION_TIER),
        "result": json.dumps(body, sort_keys=True),
        "source": {
            "batch_id": ROUTER_STAGE_BATCH_ID,
            "source_audit_ref": detector.get("source_audit_ref"),
            "task_id": detector.get("source_task_id"),
        },
        "generated_by": {
            "tool": "hackerman-etl-from-zebra-advisories",
            "tool_version": "1.0.0",
        },
        "ingested_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


def write_router_stage(
    derived_root: Path,
    invariants: List[Dict[str, Any]],
    detectors: List[Dict[str, Any]],
    *,
    dry_run: bool,
) -> List[str]:
    """Stage the built zebra invariants + detector seeds into the promote tool's
    router source dirs so a subsequent ``promote-mined-to-canonical.py`` run
    lands them in the canonical jsonls. Idempotent: each artifact is keyed by
    invariant_id / detector record_id, so re-staging overwrites the same file."""
    written: List[str] = []
    inv_dir = derived_root / INV_ROUTER_DIRNAME / ROUTER_STAGE_BATCH_ID
    det_dir = derived_root / DET_ROUTER_DIRNAME / ROUTER_STAGE_BATCH_ID
    if not dry_run:
        inv_dir.mkdir(parents=True, exist_ok=True)
        det_dir.mkdir(parents=True, exist_ok=True)
    for inv in invariants:
        staged = _invariant_router_yaml(inv)
        inv_id = staged["invariant_id"]
        path = inv_dir / f"{inv_id}.yaml"
        if not dry_run:
            path.write_text(yaml.safe_dump(staged, sort_keys=True), encoding="utf-8")
        written.append(str(path))
    for det in detectors:
        # r36-rebuttal: zebra-promote lane registered; scoped edit
        staged = _detector_router_json(det)
        # Sanitize the record_id for a portable filename (record_ids carry ':').
        fname = re.sub(r"[^A-Za-z0-9._-]", "_", str(staged["record_id"]))
        path = det_dir / f"{fname}.json"
        if not dry_run:
            path.write_text(
                json.dumps(staged, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
        written.append(str(path))
    return written


# ---------------------------------------------------------------------------
# pipeline
# ---------------------------------------------------------------------------


# r36-rebuttal: lane zebra-promote registered in .auditooor/agent_pathspec.json; scoped edit
def convert(
    *,
    records_dir: Path,
    invariants_out: Optional[Path],
    detector_seeds_out: Optional[Path],
    corpus_dir: Optional[Path],
    dry_run: bool,
    router_stage: bool = False,
    derived_root: Optional[Path] = None,
) -> Dict[str, Any]:
    record_schema = _RECORD_VALIDATOR.load_schema()
    inv_schema = _load_invariant_schema()
    try:
        import jsonschema  # type: ignore

        inv_validator = jsonschema.Draft202012Validator(inv_schema)
    except Exception:  # pragma: no cover - jsonschema absent
        inv_validator = None

    existing_refs = load_existing_refs(corpus_dir)

    errors: List[str] = []
    files: List[str] = []
    records_emitted = 0
    invariants_emitted = 0
    detector_seeds_emitted = 0
    deduped = 0
    by_severity: Dict[str, int] = {}
    by_attack_class: Dict[str, int] = {}
    invariant_lines: List[str] = []
    detector_lines: List[str] = []
    # r36-rebuttal: zebra-promote lane scoped edit. Accumulate the built dicts
    # for router-stage emission (promote-tool consumable batch files).
    staged_invariants: List[Dict[str, Any]] = []
    staged_detectors: List[Dict[str, Any]] = []
    router_stage_files: List[str] = []

    if not dry_run:
        records_dir.mkdir(parents=True, exist_ok=True)

    for adv in ZEBRA_ADVISORIES:
        ghsa = adv["ghsa"]
        url = _ghsa_url(ghsa)
        if url in existing_refs:
            deduped += 1
            continue

        record = build_record(adv)
        invariant = build_invariant(adv)
        detector = build_detector_seed(adv)

        rendered_yaml = yaml_dump(record)
        try:
            doc = yaml.safe_load(rendered_yaml)
        except yaml.YAMLError as exc:
            errors.append(f"{ghsa}: record yaml-parse-error: {exc}")
            continue
        rec_errs = _RECORD_VALIDATOR.validate_doc(doc, record_schema)
        if rec_errs:
            errors.extend(f"{ghsa}: record: {e}" for e in rec_errs)
            continue

        if inv_validator is not None:
            inv_errs = sorted(inv_validator.iter_errors(invariant), key=lambda e: list(e.path))
            if inv_errs:
                errors.extend(f"{ghsa}: invariant: {e.message}" for e in inv_errs)
                continue

        by_severity[record["severity_at_finding"]] = (
            by_severity.get(record["severity_at_finding"], 0) + 1
        )
        by_attack_class[record["attack_class"]] = (
            by_attack_class.get(record["attack_class"], 0) + 1
        )

        slug = slugify(f"{ZEBRA_REPO.replace('/', '__')}__{ghsa}", max_len=140)
        rec_subdir = records_dir / slug
        json_path = rec_subdir / "record.json"
        yaml_path = rec_subdir / "record.yaml"
        files.append(str(json_path))

        if not dry_run:
            rec_subdir.mkdir(parents=True, exist_ok=True)
            json_path.write_text(
                json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
            yaml_path.write_text(rendered_yaml, encoding="utf-8")

        records_emitted += 1
        invariant_lines.append(json.dumps(invariant, sort_keys=True))
        invariants_emitted += 1
        detector_lines.append(json.dumps(detector, sort_keys=True))
        detector_seeds_emitted += 1
        # r36-rebuttal: zebra-promote lane registered; scoped edit
        staged_invariants.append(invariant)
        staged_detectors.append(detector)

    if not dry_run:
        if invariants_out and invariant_lines:
            invariants_out.parent.mkdir(parents=True, exist_ok=True)
            with invariants_out.open("a", encoding="utf-8") as fh:
                for line in invariant_lines:
                    fh.write(line + "\n")
            files.append(str(invariants_out))
        if detector_seeds_out and detector_lines:
            detector_seeds_out.parent.mkdir(parents=True, exist_ok=True)
            with detector_seeds_out.open("a", encoding="utf-8") as fh:
                for line in detector_lines:
                    fh.write(line + "\n")
            files.append(str(detector_seeds_out))

    # r36-rebuttal: zebra-promote lane registered; scoped edit.
    # Router-stage builds from the full dataset (NOT the dedupe-gated
    # accumulators), so the canonical promotion path is populated even when the
    # per-advisory records were already present in --corpus-dir. The promote
    # tool itself is idempotent (keys by invariant_id / detector record_id).
    if router_stage:
        root = derived_root or (REPO_ROOT / "audit" / "corpus_tags" / "derived")
        all_invariants = [build_invariant(adv) for adv in ZEBRA_ADVISORIES]
        all_detectors = [build_detector_seed(adv) for adv in ZEBRA_ADVISORIES]
        router_stage_files = write_router_stage(
            root, all_invariants, all_detectors, dry_run=dry_run
        )
        files.extend(router_stage_files)

    return {
        "schema_version": SUMMARY_SCHEMA,
        "dry_run": dry_run,
        "verification_tier": VERIFICATION_TIER,
        "advisories_in_dataset": len(ZEBRA_ADVISORIES),
        "records_emitted": records_emitted,
        "invariants_emitted": invariants_emitted,
        "detector_seeds_emitted": detector_seeds_emitted,
        # r36-rebuttal: zebra-promote lane registered; scoped edit
        "router_staged_files": len(router_stage_files),
        "deduped": deduped,
        "errors": errors,
        "by_severity": by_severity,
        "by_attack_class": by_attack_class,
        "file_count": len(files),
        "files": files[:50],
    }


# ---------------------------------------------------------------------------
# generic-engine delegation
#
# r36-rebuttal: lane advisory-generic-miner registered; scoped edit.
# The repo-agnostic engine lives in tools/hackerman-etl-from-advisories.py. This
# zebra entrypoint keeps its baked, network-independent ZEBRA_ADVISORIES dataset
# (offline/CI determinism, tier-1-officially-disclosed) AND can delegate to the
# generic engine over zebra's LIVE published advisories with
# ``--delegate-generic`` (equivalent to running the generic tool with
# ``--repo ZcashFoundation/zebra``). Delegation does not touch the baked path or
# any existing function; it imports the generic module and calls its convert().
# ---------------------------------------------------------------------------


def _load_generic_engine() -> Any:
    spec = importlib.util.spec_from_file_location(
        "_hackerman_etl_from_advisories_generic",
        str(REPO_ROOT / "tools" / "hackerman-etl-from-advisories.py"),
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


def delegate_to_generic(
    *,
    records_dir: Path,
    invariants_out: Optional[Path],
    detector_seeds_out: Optional[Path],
    corpus_dir: Optional[Path],
    dry_run: bool,
    cache_file: Optional[Path] = None,
    write_cache_file: Optional[Path] = None,
) -> Dict[str, Any]:
    """Run the repo-agnostic engine with ``--repo ZcashFoundation/zebra`` so the
    zebra entrypoint shares the generic fetch/generalize/emit logic. Returns the
    generic engine's summary dict."""
    engine = _load_generic_engine()
    return engine.convert(
        repo=ZEBRA_REPO,
        records_dir=records_dir,
        invariants_out=invariants_out,
        detector_seeds_out=detector_seeds_out,
        corpus_dir=corpus_dir,
        dry_run=dry_run,
        ecosystem="crates.io",
        target_domain="l1-client",
        target_language="rust",
        extra_cves=[],
        cache_file=cache_file,
        write_cache_file=write_cache_file,
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--records-dir",
        default="audit/corpus_tags/tags/zebra_advisories",
        help="Output dir for per-advisory record.{json,yaml}.",
    )
    parser.add_argument(
        "--invariants-out",
        default="audit/corpus_tags/derived/invariants_zebra_advisories.jsonl",
        help="Append the INV-* invariant records here (JSONL).",
    )
    parser.add_argument(
        "--detector-seeds-out",
        default="audit/corpus_tags/derived/detector_seeds_zebra_advisories.jsonl",
        help="Append the detector-seed records here (JSONL).",
    )
    parser.add_argument(
        "--corpus-dir",
        default=None,
        help="Existing corpus tree to dedupe against (by source_audit_ref).",
    )
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--json-summary", action="store_true")
    # r36-rebuttal: zebra-promote lane registered; scoped edit
    parser.add_argument(
        "--router-stage",
        action="store_true",
        help=(
            "Also write the promote-tool-consumable batch files under "
            "derived/invariant_library_extended/<batch>/ and "
            "derived/detector_synthesis_v2/<batch>/ so a subsequent "
            "promote-mined-to-canonical.py run lands the zebra invariants + "
            "detector seeds in the canonical jsonls."
        ),
    )
    parser.add_argument(
        "--derived-root",
        default="audit/corpus_tags/derived",
        help="Derived corpus root that holds the promote-tool router source dirs.",
    )
    # r36-rebuttal: lane advisory-generic-miner registered; scoped edit
    parser.add_argument(
        "--delegate-generic",
        action="store_true",
        help=(
            "Mine zebra's LIVE published advisories via the repo-agnostic engine "
            "tools/hackerman-etl-from-advisories.py (equivalent to that tool's "
            "--repo ZcashFoundation/zebra). Bypasses the baked ZEBRA_ADVISORIES "
            "constant set; use --cache-file for an offline/deterministic run."
        ),
    )
    parser.add_argument(
        "--cache-file",
        default=None,
        help="With --delegate-generic: read advisories from a saved JSON payload "
        "instead of calling gh api (offline / deterministic).",
    )
    return parser


def _resolve(p: Optional[str]) -> Optional[Path]:
    if p is None:
        return None
    pp = Path(p).expanduser()
    return pp if pp.is_absolute() else (REPO_ROOT / pp)


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    # r36-rebuttal: lane advisory-generic-miner registered; scoped edit.
    # --delegate-generic routes the zebra entrypoint through the repo-agnostic
    # engine (live fetch over ZcashFoundation/zebra); default path keeps the
    # baked ZEBRA_ADVISORIES constant set.
    if getattr(args, "delegate_generic", False):
        summary = delegate_to_generic(
            records_dir=_resolve(args.records_dir),  # type: ignore[arg-type]
            invariants_out=_resolve(args.invariants_out),
            detector_seeds_out=_resolve(args.detector_seeds_out),
            corpus_dir=_resolve(args.corpus_dir),
            dry_run=args.dry_run,
            cache_file=_resolve(getattr(args, "cache_file", None)),
        )
        if args.json_summary:
            print(json.dumps(summary, sort_keys=True))
        else:
            print(
                "hackerman zebra-advisories ETL [delegate-generic]: "
                f"repo={summary['repo']} fetched={summary['advisories_fetched']} "
                f"records={summary['records_emitted']} "
                f"invariants={summary['invariants_emitted']} "
                f"detector_seeds={summary['detector_seeds_emitted']} "
                f"errors={len(summary['errors'])}"
            )
        return 0 if not summary["errors"] else 1
    # r36-rebuttal: zebra-promote lane registered; scoped edit
    summary = convert(
        records_dir=_resolve(args.records_dir),  # type: ignore[arg-type]
        invariants_out=_resolve(args.invariants_out),
        detector_seeds_out=_resolve(args.detector_seeds_out),
        corpus_dir=_resolve(args.corpus_dir),
        dry_run=args.dry_run,
        router_stage=args.router_stage,
        derived_root=_resolve(args.derived_root),
    )
    if args.json_summary:
        print(json.dumps(summary, sort_keys=True))
    else:
        print(
            "hackerman zebra-advisories ETL: "
            f"records={summary['records_emitted']} "
            f"invariants={summary['invariants_emitted']} "
            f"detector_seeds={summary['detector_seeds_emitted']} "
            f"deduped={summary['deduped']} "
            f"verification_tier={summary['verification_tier']} "
            f"by_severity={summary['by_severity']} "
            f"errors={len(summary['errors'])}"
        )
    return 0 if not summary["errors"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
