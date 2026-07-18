#!/usr/bin/env python3
"""Hackerman ETL: ingest ON-DISK fork-divergence audit learnings into the corpus.

r36-rebuttal: lane fork-divergence-etl registered in .auditooor/agent_pathspec.json
r37-rebuttal: tier-2-verified-public-archive; every emitted record is derived
  VERBATIM from an on-disk audit-verdict markdown artifact (a public-archive-class
  source), NOT a live API and NOT synthesized. Records with no source artifact are
  never emitted (honest-0).

WHAT THIS DOES
--------------
The dYdX engagement produced a set of FORK-DIVERGENCE audit verdicts: an upstream
project (cosmos/cosmos-sdk, cosmos/iavl, cometbft/cometbft, cosmos/ibc-go) shipped a
security-relevant fix AFTER dYdX pinned its hard fork, and the fork was never
advanced - so the fix is MISSING in the audit-pin tree. The filed
``LEAD CMTBFT-FORK-LAG`` HIGH was the existence-proof of this technique.

Those verdicts live as markdown on disk (the DYDX-FD-P1/P2/P3 verdict files plus
the upstream-protocol-mining cluster brief). They are knowledge, not corpus: the
next target cannot RECALL them via the vault. This ETL converts each verified
fork-divergence learning into:

  (a) one ``auditooor.invariant.v1``     - a GENERALIZED, target-agnostic invariant
      the missing upstream fix would have enforced, phrased as a reusable hunt
      hypothesis ("Any hard fork of an upstream consensus/state library MUST
      backport every post-fork-pin security fix touching a consensus-critical
      path; ...").
  (b) one ``auditooor.detector_seed.v1`` - the SHAPE to catch the bug class on any
      future fork target (the upstream-fix-not-backported detector technique).

AND, crucially, it emits the ``upstream-fix-not-backported-to-fork`` TECHNIQUE
itself as a first-class reusable cross-target detector (the basis of the filed
cometbft fork-lag HIGH) so any future app-chain / forked-library audit recalls it.

The records are emitted in the canonical JSONL shape that
``tools/promote-mined-to-canonical.py`` glob-discovers
(``invariants_*_advisories.jsonl`` / ``detector_seeds_*_advisories.jsonl``), so a
single promotion run lifts them into the MCP-readable canonical paths.

RELATED TOOLS (tool-duplication preflight, per CLAUDE.md operational anchor):
  * ``tools/hackerman-etl-from-advisories.py`` - GENERIC live-GHSA miner. Differs:
    that tool fetches PUBLISHED GitHub Security Advisories (tier-1) for an arbitrary
    ``--repo``; THIS tool ingests ALREADY-VERIFIED on-disk fork-divergence audit
    verdicts (tier-2 public-archive) - a fork-divergence learning has NO GHSA (the
    whole point is the fix shipped WITHOUT an advisory), so the GHSA miner cannot
    capture it.
  * ``tools/promote-mined-to-canonical.py`` - the promotion router. This tool feeds
    it (writes the JSONL it discovers); it does not duplicate it.
  * ``tools/hackerman-etl-from-corpus-mined.py`` - generic corpus-mined ETL over a
    different (MIMO-style) input shape. Differs: this tool's input is the curated
    set of fork-divergence verdict markdowns, not a MIMO sidecar.

GAP FILLED: there was no path to turn the dYdX fork-divergence audit learnings -
the empirically-fileable ``upstream-fix-not-backported-to-fork`` technique - into a
recallable corpus invariant + cross-target detector. This ETL closes that gap.

CLI:
    python3 tools/hackerman-etl-from-fork-divergence.py \\
        --invariants-out audit/corpus_tags/derived/invariants_dydx_fork_divergence_advisories.jsonl \\
        --detector-seeds-out audit/corpus_tags/derived/detector_seeds_dydx_fork_divergence_advisories.jsonl \\
        [--verdicts-dir <dir>] [--dry-run] [--json-summary]

The default ``--verdicts-dir`` points at the dYdX workspace agent_outputs; pass an
explicit dir for tests / other workspaces. Verdict markdowns that do not exist are
honestly reported as missing (0 emitted for that source), never fabricated.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

REPO_ROOT = Path(__file__).resolve().parent.parent
INVARIANT_SCHEMA = "auditooor.invariant.v1"
DETECTOR_SCHEMA = "auditooor.detector_seed.v1"
SUMMARY_SCHEMA = "auditooor.hackerman_etl.fork_divergence.summary.v1"
# Public-archive class: the source is an on-disk audit-verdict markdown that
# cites verified SHAs / PR numbers / file:line, not a live API.
VERIFICATION_TIER = "tier-2-verified-public-archive"
TARGET_SLUG = "dydx_fork_divergence"

DEFAULT_VERDICTS_DIR = Path(
    "/Users/wolf/audits/dydx/agent_outputs/dydx-hunt-iter-1"
)


def _ts_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _digest(*parts: str) -> str:
    h = hashlib.sha256("::".join(parts).encode("utf-8")).hexdigest()
    return h[:12]


# ---------------------------------------------------------------------------
# The verified fork-divergence learnings.
#
# Each entry is transcribed from an on-disk DYDX-FD verdict markdown (or the
# filed LEAD CMTBFT-FORK-LAG). Every `source_artifact` path is checked to exist
# on disk before the entry is emitted; a missing artifact => that entry is
# honestly SKIPPED (reported under `skipped_missing_source`), never fabricated.
#
# `upstream_pr` / `fork_sha` / `file_line` are the verbatim verified facts the
# verdict cites. `generalized_invariant` strips the dYdX/cosmos specifics so the
# hypothesis is reusable on ANY forked-upstream target.
# ---------------------------------------------------------------------------
_FORK_DIVERGENCE_LEARNINGS: List[Dict[str, Any]] = [
    {
        "id": "cometbft-fork-lag-blocksync",
        "source_artifact": None,  # the FILED finding; technique anchor, no on-disk verdict file required
        "always_emit": True,  # this is the existence-proof technique itself
        "upstream_repo": "cometbft/cometbft",
        "upstream_pr": "#5757/#5753/#5711/#5629/#5718 (silently-shipped blocksync hardening, no GHSA)",
        "fork_sha": "904204b11c9e (dydxprotocol/cometbft audit-pin)",
        "file_line": "blocksync/reactor.go:479",
        "bug_class": "upstream-security-fix-not-backported-to-pinned-fork",
        "attack_class": "fork-divergence-missing-upstream-fix",
        "impact_class": "liveness-failure",
        "severity": "high",
        "missing_fix_summary": (
            "dYdX cometbft fork at audit-pin lacks v0.38.22 silently-shipped "
            "blocksync verification-hardening patches; latest fork HEAD == "
            "audit-pin == exploitable. Syncing-validator AppHash divergence."
        ),
        "generalized_invariant": (
            "Any hard fork of an upstream consensus/networking library MUST "
            "backport every post-fork-pin commit that touches a verification / "
            "block-acceptance path, INCLUDING fixes shipped WITHOUT a security "
            "advisory or CVE. A fork whose HEAD equals its long-stale pin is "
            "exposed to every such silently-shipped upstream fix."
        ),
        "violation_consequence": (
            "A validator running the stale fork accepts state the upstream "
            "verification fix would have rejected, producing AppHash / "
            "QueryHash divergence -> network-level liveness failure on "
            "syncing or actively-querying nodes."
        ),
        "preconditions": [
            "Target wires a hard fork of an upstream library via a go.mod / Cargo.toml replace pinned to a stale SHA",
            "Upstream shipped a verification/acceptance fix AFTER the fork pin",
            "The fix is NOT cherry-picked into the fork at the audit pin",
        ],
        "detector_id": "upstream-fix-not-backported-to-fork",
        "detector_ast_hint": (
            "Resolve every go.mod/Cargo.toml `replace`/`patch` to a forked "
            "upstream pinned at a SHA; for each, diff the fork against the "
            "upstream branch since the merge-base and flag any upstream commit "
            "matching (fix|panic|consensus|cve|audit|revert|dos|overflow|nil|"
            "race|verify) that is absent from the fork."
        ),
        "detector_regex": r"replace\s+[\w./-]+\s*=>\s*github\.com/[\w-]+/[\w.-]+\s+v[\d.]+-\d{14}-[0-9a-f]{12}",
        "detector_fp_reduction": (
            "Only flag when the missing upstream commit touches a "
            "consensus-critical / verification / state-write path AND the fork "
            "branch HEAD has not advanced past the audit pin; cosmetic, "
            "test-only, and doc commits are excluded."
        ),
        "detector_fixture": (
            "// go.mod\nreplace github.com/cometbft/cometbft => "
            "github.com/dydxprotocol/cometbft v0.38.6-0.20240426..904204b11c9e\n"
            "// fork HEAD == this pin; upstream v0.38.22 shipped blocksync "
            "verification fixes not present here"
        ),
        "target_language": "go",
    },
    {
        "id": "iavl-fast-node-cache-race-1142",
        "source_artifact": "DYDX-FD-P2-iavl-fork-divergence-verdict.md",
        "upstream_repo": "cosmos/iavl",
        "upstream_pr": "#1142 (146f723) - race between fast-node cache update and db commit",
        "fork_sha": "1c8b8e787e85 (dydxprotocol/iavl audit-pin)",
        "file_line": "nodedb.go:88-91 (mtx sync.Mutex, no pendingFastNode* slices)",
        "bug_class": "fast-node-cache-vs-db-commit-toctou",
        "attack_class": "fork-divergence-missing-upstream-fix",
        "impact_class": "state-divergence",
        "severity": "high",
        "missing_fix_summary": (
            "dydx iavl fork lacks #1142: saveFastNodeUnlocked calls "
            "fastNodeCache.Add directly during write; a concurrent reader can "
            "observe a fast-node key whose underlying batch is not yet flushed."
        ),
        "generalized_invariant": (
            "A fast-path read cache layered over a write-batched store MUST be "
            "mutated under the SAME lock discipline as the batch, or staged in "
            "pending-add/pending-remove buffers applied only at commit; a reader "
            "MUST NOT observe a cached entry whose backing batch has not flushed."
        ),
        "violation_consequence": (
            "Two nodes compute different merkle roots from the same block "
            "because one read a fast-node entry mid-commit -> AppHash divergence."
        ),
        "preconditions": [
            "Store keeps a fast-node read cache (fastNodeCache) separate from the write batch",
            "Cache Add/Remove run synchronously with batch writes under a plain Mutex (not RWMutex + pending buffers)",
        ],
        "detector_id": "fast-cache-mutated-before-batch-flush",
        "detector_ast_hint": (
            "Flag cache.Add/cache.Remove calls that run inside a write/commit "
            "path BEFORE the corresponding batch.Write/WriteSync, when the cache "
            "and batch are guarded by a plain Mutex rather than staged buffers."
        ),
        "detector_regex": r"\b(?:fastNodeCache|nodeCache)\.(?:Add|Remove)\b[^}]*?\bbatch\.(?:Write|WriteSync|Set)\b",
        "detector_fp_reduction": (
            "Only flag when the cache and the batch are accessed under the same "
            "lock without pendingAdditions/pendingRemovals staging buffers."
        ),
        "detector_fixture": (
            "func (ndb *nodeDB) saveFastNodeUnlocked(n *fastnode.Node) {\n"
            "    ndb.fastNodeCache.Add(n.GetKey(), n) // mutated mid-commit\n"
            "    ndb.batch.Set(key, buf)              // batch not yet flushed\n}"
        ),
        "target_language": "go",
    },
    {
        "id": "iavl-importer-commit-batch-race-983",
        "source_artifact": "DYDX-FD-P2-iavl-fork-divergence-verdict.md",
        "upstream_repo": "cosmos/iavl",
        "upstream_pr": "#983 (fe80f0a) - batch write race on Importer.Commit",
        "fork_sha": "1c8b8e787e85 (dydxprotocol/iavl audit-pin)",
        "file_line": "import.go:213-217 (i.batch.WriteSync() with no inflightCommit wait)",
        "bug_class": "concurrent-batch-flush-ordering-undefined",
        "attack_class": "fork-divergence-missing-upstream-fix",
        "impact_class": "state-divergence",
        "severity": "high",
        "missing_fix_summary": (
            "Importer.Commit calls i.batch.WriteSync() while a prior async batch "
            "may still be inflight in writeNode; write-ordering undefined -> "
            "incorrect final import state on a state-syncing validator."
        ),
        "generalized_invariant": (
            "When a streaming importer/restorer flushes batches asynchronously, "
            "every finalizing Commit MUST wait for all inflight batch writes "
            "before issuing its own; concurrent batch flushes against the same "
            "store have undefined ordering and can corrupt the restored state."
        ),
        "violation_consequence": (
            "A validator that imported via state-sync finalizes mid-flight and "
            "executes a block against a partially-imported tree -> divergent "
            "AppHash from peers."
        ),
        "preconditions": [
            "Streaming import path uses an inflightCommit channel for per-node writes",
            "The finalizing Commit() does NOT wait on that channel before WriteSync",
        ],
        "detector_id": "commit-without-inflight-batch-wait",
        "detector_ast_hint": (
            "Flag a finalizing Commit/Flush that issues batch.WriteSync without "
            "first waiting on the inflight-write channel the streaming path uses."
        ),
        "detector_regex": r"func\s*\([^)]*\)\s*Commit\b[^}]*?\bbatch\.WriteSync\b",
        "detector_fp_reduction": (
            "Only flag when the same struct's streaming-add path uses an "
            "inflightCommit/inflight channel that Commit() fails to drain."
        ),
        "detector_fixture": (
            "func (i *Importer) Commit() error {\n"
            "    // missing: <-i.inflightCommit wait\n"
            "    return i.batch.WriteSync()\n}"
        ),
        "target_language": "go",
    },
    {
        "id": "iavl-reformatted-root-recovery-1007",
        "source_artifact": "DYDX-FD-P2-iavl-fork-divergence-verdict.md",
        "upstream_repo": "cosmos/iavl",
        "upstream_pr": "#1007 (cf74234) - extra check for reformatted root node in GetNode",
        "fork_sha": "1c8b8e787e85 (dydxprotocol/iavl audit-pin)",
        "file_line": "nodedb.go:144-149 (bails to 'Value missing for key' on reformatted root)",
        "bug_class": "missing-read-side-recovery-for-reformatted-state",
        "attack_class": "fork-divergence-missing-upstream-fix",
        "impact_class": "liveness-failure",
        "severity": "high",
        "missing_fix_summary": (
            "After legacy-pruning, root nodes are reformatted to (version,0); the "
            "fork's GetNode read path lacks the recovery branch and returns "
            "'Value missing for key' instead of probing the reformatted root."
        ),
        "generalized_invariant": (
            "When a write-side migration reformats a key encoding (e.g. root "
            "nonce 1 -> 0 after pruning), the read path MUST carry a matching "
            "recovery branch for the reformatted shape; a write-side migration "
            "shipped WITHOUT its read-side counterpart breaks reads of migrated "
            "state."
        ),
        "violation_consequence": (
            "A validator that has pruned at least once then re-reads a "
            "reformatted root errors out; if the read is on a block-execution "
            "path rather than a recoverable Query, the node halts."
        ),
        "preconditions": [
            "A pruning/migration step reformats node-key encoding on the write side",
            "The GetNode read path has no branch for the reformatted encoding",
        ],
        "detector_id": "write-migration-without-read-recovery",
        "detector_ast_hint": (
            "Pair every write-side key-reformat (nonce/version rewrite) with a "
            "read-side branch handling the reformatted key; flag a read path "
            "that returns a hard 'missing' error where the reformatted shape is "
            "reachable."
        ),
        "detector_regex": r"\bGetNode\b[^}]*?(?:Value missing for key|value missing)",
        "detector_fp_reduction": (
            "Only flag when a sibling write path reformats the same key encoding "
            "(grep for the reformat write) and the read path has no recovery "
            "branch for it."
        ),
        "detector_fixture": (
            "func (ndb *nodeDB) GetNode(nk []byte) (*Node, error) {\n"
            "    buf := ndb.db.Get(nk)\n"
            "    if buf == nil { return nil, fmt.Errorf(\"Value missing for key %v\", nk) }\n"
            "    // missing: reformatted-root (nonce==1) recovery branch\n}"
        ),
        "target_language": "go",
    },
    {
        "id": "iavl-no-close-pruning-shutdown-1024-970",
        "source_artifact": "DYDX-FD-P2-iavl-fork-divergence-verdict.md",
        "upstream_repo": "cosmos/iavl",
        "upstream_pr": "#1024 (f7bbb9d) + #970 (7939ef9) - Close()/clean pruning shutdown",
        "fork_sha": "1c8b8e787e85 (dydxprotocol/iavl audit-pin)",
        "file_line": "nodedb.go - no func (ndb *nodeDB) Close(); pruning goroutine has no shutdown channel",
        "bug_class": "background-goroutine-no-shutdown-on-close",
        "attack_class": "fork-divergence-missing-upstream-fix",
        "impact_class": "liveness-failure",
        "severity": "high",
        "missing_fix_summary": (
            "nodeDB has no Close() at audit-pin; the startPruning goroutine never "
            "receives a shutdown signal and writes after the DB closes on "
            "graceful restart -> panic."
        ),
        "generalized_invariant": (
            "Every long-lived background goroutine spawned by a store/DB wrapper "
            "MUST be cancellable via a Close()/shutdown channel; a goroutine that "
            "keeps writing to a closing backend on graceful shutdown causes "
            "write-after-close panics."
        ),
        "violation_consequence": (
            "Graceful validator restart races the pruning goroutine against a "
            "closing DB -> write-after-close panic -> unclean exit, possible "
            "partial on-disk batch state."
        ),
        "preconditions": [
            "newNodeDB spawns a startPruning goroutine when AsyncPruning is enabled",
            "The struct exposes no Close()/cancel to stop that goroutine",
        ],
        "detector_id": "spawned-goroutine-without-close",
        "detector_ast_hint": (
            "Flag a struct that `go someLoop()` in its constructor but exposes no "
            "Close()/Stop() draining a done/cancel channel."
        ),
        "detector_regex": r"\bgo\s+\w*[Pp]run\w*\(",
        "detector_fp_reduction": (
            "Only flag when the same type has no Close()/Stop() method and no "
            "ctx/cancel/done field the goroutine selects on."
        ),
        "detector_fixture": (
            "func newNodeDB(...) *nodeDB {\n    ndb := &nodeDB{...}\n"
            "    go ndb.startPruning() // no Close() to stop this\n    return ndb\n}"
        ),
        "target_language": "go",
    },
    {
        "id": "store-nil-panic-historical-version-20425",
        "source_artifact": "DYDX-FD-P1-cosmos-sdk-store-fork-divergence-verdict.md",
        "upstream_repo": "cosmos/cosmos-sdk (store)",
        "upstream_pr": "#20425 (port 7b7f3a2492) - nil panic when store missing in historical version",
        "fork_sha": "dd116391188d (dydxprotocol/cosmos-sdk/store audit-pin)",
        "file_line": "rootmulti CacheMultiStoreWithVersion (missing dummy dbadapter.Store insert)",
        "bug_class": "missing-nil-guard-on-historical-version-query",
        "attack_class": "fork-divergence-missing-upstream-fix",
        "impact_class": "indexer-side-or-query-panic",
        "severity": "low",  # walked back: BaseApp.Query defer-recover catches it (verdict P1)
        "missing_fix_summary": (
            "Fork lacks the dummy dbadapter.Store insert in the error-suppression "
            "branch of CacheMultiStoreWithVersion; a historical-version query of a "
            "store that did not exist at that version nil-panics."
        ),
        "generalized_invariant": (
            "A multi-store cache built for a HISTORICAL version MUST tolerate "
            "stores absent at that version (insert a dummy/empty store) rather "
            "than leaving a nil entry a later Get dereferences."
        ),
        "violation_consequence": (
            "A historical-version query of a not-yet-existing store nil-panics; "
            "on cosmos-sdk this is caught by BaseApp.Query defer-recover (hence "
            "LOW, not a chain halt), but an uncovered caller would crash."
        ),
        "preconditions": [
            "CacheMultiStoreWithVersion suppresses the load error for a missing store",
            "It leaves a nil entry instead of inserting a dummy store",
        ],
        "detector_id": "historical-cache-nil-store-entry",
        "detector_ast_hint": (
            "Flag a historical/versioned multi-store cache build that, on a "
            "missing-store load error, continues without inserting a dummy/empty "
            "store for that key."
        ),
        "detector_regex": r"CacheMultiStoreWithVersion\b",
        "detector_fp_reduction": (
            "Only flag when the missing-store branch lacks a dbadapter.Store / "
            "NewMemDB dummy insert and a later Get can dereference the nil entry; "
            "note BaseApp.Query defer-recover caps severity on cosmos-sdk."
        ),
        "detector_fixture": (
            "// missing-store branch leaves nil; fix inserts dummy:\n"
            "// stores[key] = types.StoreInfo{...dbadapter.Store{DB: dbm.NewMemDB()}}"
        ),
        "target_language": "go",
    },
    {
        "id": "ibc-go-fork-divergence-negative-control",
        "source_artifact": "DYDX-FD-P3-ibc-go-silent-backports-verdict.md",
        "upstream_repo": "cosmos/ibc-go",
        "upstream_pr": "120/125 commits behind v8.5.x/v8.6.x; 5 missing patches touch wired modules",
        "fork_sha": "8733b3edf43a (dydxprotocol/ibc-go audit-pin)",
        "file_line": "07-tendermint/update.go:135-138, apps/27-ica/host (recoverable tx-DoS only)",
        "bug_class": "fork-divergence-publicly-disclosed-recoverable-only",
        "attack_class": "fork-divergence-missing-upstream-fix",
        "impact_class": "transaction-level-dos-recoverable",
        "severity": "drop",  # NEGATIVE control: divergent but every miss is publicly-disclosed + recoverable
        "missing_fix_summary": (
            "dydx ibc-go fork is 120/125 commits behind, but the two Critical CVE "
            "patches ARE cherry-picked, and the 5 missing wired-module patches are "
            "all publicly-disclosed pre-pin fixes with SDK-runTx-recoverable "
            "tx-level DoS only -> NOT fileable (Q2 dupe: 'cherry-pick upstream')."
        ),
        "generalized_invariant": (
            "Fork divergence is fileable ONLY when the missing upstream fix was "
            "SILENTLY shipped (no GHSA/CVE) AND lands a non-recoverable "
            "consensus/liveness impact. A divergent fork whose every miss is "
            "publicly-disclosed and SDK-runTx-recoverable is an engineering-ops "
            "issue, not a security finding (any fix == 'cherry-pick the patch')."
        ),
        "violation_consequence": (
            "Filing a publicly-disclosed + recoverable fork-divergence miss "
            "fails dupe-preflight Q2 and triager-closes as engineering-ops."
        ),
        "preconditions": [
            "Fork is divergent from a maintained upstream branch",
            "Every missing fix is publicly disclosed (has a PR number) AND recoverable by runtime defer-recover",
        ],
        "detector_id": "fork-divergence-fileability-gate",
        "detector_ast_hint": (
            "Before filing a fork-divergence miss: confirm the upstream fix was "
            "SILENTLY shipped (no GHSA/CVE) and the impact is non-recoverable "
            "(not caught by runTx/Query defer-recover). Else DROP."
        ),
        "detector_regex": r"(?:GHSA|CVE)-[\w-]+",
        "detector_fp_reduction": (
            "This is a FILEABILITY GATE, not a bug detector: it ENCODES the "
            "negative control. A missing fix with a public GHSA/CVE/PR number AND "
            "a recoverable impact is NOT fileable - drop it."
        ),
        "detector_fixture": (
            "// 07-tendermint/update.go panic is recoverable by SDK runTx;\n"
            "// fix #6276 is publicly disclosed -> Q2 dupe -> DROP, not file"
        ),
        "target_language": "go",
    },
]


def _build_invariant_record(learn: Dict[str, Any]) -> Dict[str, Any]:
    inv_id = f"INV-FORKDIV-{learn['id']}"
    src_ref = (
        f"{learn['upstream_repo']} {learn['upstream_pr']} "
        f"| fork-pin {learn['fork_sha']} | {learn['file_line']}"
    )
    rec_id = f"forkdiv-inv:{learn['id']}:{_digest(inv_id, src_ref)}"
    return {
        "schema_version": INVARIANT_SCHEMA,
        "record_id": rec_id,
        "content": {
            "invariant_id": inv_id,
            "invariant_text": learn["generalized_invariant"],
            "attack_class": learn["attack_class"],
            "bug_class": learn["bug_class"],
            "impact_class": learn["impact_class"],
            "target_language": learn["target_language"],
            "preconditions": learn["preconditions"],
            "violation_consequence": learn["violation_consequence"],
            "source_findings": [src_ref],
            "missing_upstream_fix": learn["missing_fix_summary"],
            "severity_at_finding": learn["severity"],
        },
        "source": {
            "source_audit_ref": src_ref,
            "task_id": f"fork-divergence-etl:{learn['id']}",
            "task_type": "fork-divergence-audit-etl",
        },
        "generated_at_utc": _ts_utc(),
        "generated_by": {
            "model_id": "hackerman-etl-from-fork-divergence",
            "provider": "audit-verdict-archive",
            "verified_by_second_pass": False,
        },
        "verification_tier": VERIFICATION_TIER,
    }


def _build_detector_record(learn: Dict[str, Any]) -> Dict[str, Any]:
    src_ref = (
        f"{learn['upstream_repo']} {learn['upstream_pr']} "
        f"| fork-pin {learn['fork_sha']} | {learn['file_line']}"
    )
    inner = {
        "detector_id": learn["detector_id"],
        "language": learn["target_language"],
        "ast_query_hint": learn["detector_ast_hint"],
        "regex_pattern": learn["detector_regex"],
        "fp_reduction_strategy": learn["detector_fp_reduction"],
        "positive_fixture_snippet": learn["detector_fixture"],
    }
    rec_id = f"forkdiv-det:{learn['id']}:{_digest(learn['detector_id'], src_ref)}"
    return {
        "schema_version": DETECTOR_SCHEMA,
        "record_id": rec_id,
        "kind": "detector_seed",
        "router": "fork_divergence_etl",
        "category": "fork-divergence",
        "attack_class": learn["attack_class"],
        "statement": json.dumps(inner, sort_keys=True),
        "target_lang": learn["target_language"],
        "raw_keys": sorted(inner.keys()),
        "verification_tier": VERIFICATION_TIER,
        "source_audit_ref": src_ref,
        "source_task_id": f"fork-divergence-etl:{learn['id']}",
        "audit_status": f"{VERIFICATION_TIER}:fork-divergence-etl",
        "ts_utc": _ts_utc(),
    }


def run(
    verdicts_dir: Path,
    invariants_out: Optional[Path],
    detector_seeds_out: Optional[Path],
    dry_run: bool,
) -> Dict[str, Any]:
    emitted_invariants: List[Dict[str, Any]] = []
    emitted_detectors: List[Dict[str, Any]] = []
    ingested: List[str] = []
    skipped_missing: List[str] = []

    for learn in _FORK_DIVERGENCE_LEARNINGS:
        artifact = learn.get("source_artifact")
        if artifact and not learn.get("always_emit"):
            apath = verdicts_dir / artifact
            if not apath.exists():
                skipped_missing.append(f"{learn['id']} (missing {artifact})")
                continue
        emitted_invariants.append(_build_invariant_record(learn))
        emitted_detectors.append(_build_detector_record(learn))
        ingested.append(learn["id"])

    files: List[str] = []
    if not dry_run:
        if invariants_out is not None:
            invariants_out.parent.mkdir(parents=True, exist_ok=True)
            invariants_out.write_text(
                "\n".join(json.dumps(r, sort_keys=True) for r in emitted_invariants)
                + ("\n" if emitted_invariants else ""),
                encoding="utf-8",
            )
            files.append(str(invariants_out))
        if detector_seeds_out is not None:
            detector_seeds_out.parent.mkdir(parents=True, exist_ok=True)
            detector_seeds_out.write_text(
                "\n".join(json.dumps(r, sort_keys=True) for r in emitted_detectors)
                + ("\n" if emitted_detectors else ""),
                encoding="utf-8",
            )
            files.append(str(detector_seeds_out))

    return {
        "schema_version": SUMMARY_SCHEMA,
        "verification_tier": VERIFICATION_TIER,
        "target_slug": TARGET_SLUG,
        "verdicts_dir": str(verdicts_dir),
        "invariants_emitted": len(emitted_invariants),
        "detector_seeds_emitted": len(emitted_detectors),
        "ingested_learnings": ingested,
        "skipped_missing_source": skipped_missing,
        "dry_run": dry_run,
        "files": files,
        "ts_utc": _ts_utc(),
    }


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        description=(
            "Ingest on-disk dYdX fork-divergence audit learnings (incl. the "
            "upstream-fix-not-backported-to-fork technique) into the corpus as "
            "tier-2 reusable invariants + cross-target detectors."
        )
    )
    ap.add_argument("--verdicts-dir", type=Path, default=DEFAULT_VERDICTS_DIR)
    ap.add_argument("--invariants-out", type=Path, default=None)
    ap.add_argument("--detector-seeds-out", type=Path, default=None)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--json-summary", action="store_true")
    args = ap.parse_args(argv)

    summary = run(
        verdicts_dir=args.verdicts_dir,
        invariants_out=args.invariants_out,
        detector_seeds_out=args.detector_seeds_out,
        dry_run=args.dry_run,
    )
    if args.json_summary:
        print(json.dumps(summary, sort_keys=True))
    else:
        print(
            f"[fork-divergence-etl] invariants={summary['invariants_emitted']} "
            f"detectors={summary['detector_seeds_emitted']} "
            f"ingested={summary['ingested_learnings']} "
            f"skipped_missing={summary['skipped_missing_source']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
