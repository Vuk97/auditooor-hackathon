#!/usr/bin/env python3
"""go-detector-runner.py — SPARK-GAP-001 seed.

Runs lightweight Go-source pattern detectors over a workspace and emits
findings to ``<workspace>/.auditooor/go_findings.json``. Mirrors the shape
of the Rust scan summary so downstream gap-analyzer / triage tooling can
consume it the same way.

Phase B pattern classes (9 of 10 from the SPARK handoff plan):

1. ``go.bitcoin.txid_equality_without_utxo_spend_check`` — a function
   accepts a ``txid`` / ``Hash`` (or similarly-named) parameter, performs
   an equality check against a persisted ID, but never calls a
   spend/UTXO/validate verifier in the same body.
2. ``go.statemachine.guard_only_on_one_path`` — a guard function name
   (config-driven, defaulting to a small set of common names) is called by
   only ONE caller in the same package while sibling callers in the same
   package mutate ``transfer.Status`` / ``node.Status`` / similar without
   invoking the guard.
3. ``go.statemachine.self_heal_on_unexpected_status`` — an ``if`` whose
   condition compares a ``.Status`` field with ``!=``, whose body logs a
   warning (``Warnf``/``Warnln``/``Warning``/``Errorf``) but DOES NOT
   ``return`` / ``panic`` / ``continue`` / ``break``. The author has
   structurally chosen to swallow the unexpected status.
4. ``go.protohash.kind_identifier_collision`` — a body that calls
   ``protohash.Hash(...)`` AND uses two or more of the kind-identifier
   helpers (``intIdentifier`` / ``uintIdentifier`` / ``enumIdentifier``)
   over the SAME argument expression. A field-kind change under the same
   field number then produces an identical ``protohash.Hash`` for two
   semantically distinct messages. (SPARK-K verdict.)
5. ``go.consensus.gossip_perimeter_trust`` — a file registers a gRPC
   service AND configures ``tls.NoClientCert`` (perimeter trust) AND
   exposes ``Gossip``/``Broadcast`` handlers whose bodies do not invoke any
   ``VerifyECDSASignature`` / ``VerifySignature`` / ``VerifySig`` call.
   (SPARK-L verdict.)
6. ``go.bitcoin.byte_reversed_lookup_set`` — a function body computes
   ``slices.Reverse(...)`` (or a manual reverse) over a hash value and
   inserts BOTH the original value and the reversed value into the same
   ``map[...]`` / set. (``watch_chain.go:894-925`` shape.)
7. ``go.cosmos.message_ordering_replay`` — a Cosmos-SDK / IBC message
   handler (``Handle``/``Process``/``Execute``/``MsgServer.*``) that calls
   ``proto.Unmarshal`` on a ``Msg``-shaped payload but does NOT reference
   any of ``Sequence``/``nonce``/``Header().Height``/``BlockHash`` in the
   same function body. Stage-1: high precision via narrow name predicate;
   gopls/cross-file flow is stage-2.
8. ``go.lightning.htlc_settlement_state_drift`` — a function body that
   references BOTH an HTLC success-path token (``HtlcSuccessTx`` /
   ``htlc_success_tx`` / ``SuccessScript``) AND a timeout-path token
   (``HtlcTimeoutTx`` / ``htlc_timeout_tx`` / ``TimeoutScript``) without
   any cross-check (``require.Equal``/``assert.Equal``/``bytes.Equal``/
   ``reflect.DeepEqual``/``CrossCheck``). Conservative stage-1 form.
9. ``go.frost.aggregate_pubkey_invariant_violation`` — a function whose
   name signals a participant share rotation (``TweakKeyShare`` /
   ``RotateShare`` / ``UpdateKeyShare`` / ``TweakLeafKeyUpdate``) and
   whose body assigns to a ``verifying_pubkey`` / ``VerifyingPubkey`` /
   ``AggregatePubkey`` field WITHOUT recomputing it via group-op
   (``.Add(`` / ``.Sub(`` / ``Aggregate(`` / ``Recompute``). Inverse of
   ``go.bitcoin.statechain.refund_tx_remains_valid_post_tweak``.
10. ``go.cosmos.gas_price_zero_unchecked`` — a function body divides or
    mods by a ``gasPrice``-shaped identifier (``gasPrice`` / ``GasPrice``
    / ``gas_price`` / ``gasFee``) WITHOUT a guard ruling out the zero
    value first (``== 0`` / ``<= 0`` / ``.IsZero()`` / ``> 0`` /
    ``!= 0``). Mirrors solodit-55256 (SEDA Sherlock 2024-12 M-10): a
    permissionless data-request with ``gasPrice=0`` divides-by-zero in
    the tally path and panics every validator, halting the chain. Stage-1
    predicate is intentionally narrow: divisor name has to look gas-price-
    shaped, and the body must contain a literal ``/`` or ``%`` operator
    against it. Cross-file flow (validation in a sibling helper) is
    deferred to stage-2.
11. ``go.cosmos.vote_extension_unverified`` — a function whose body
    iterates over vote extensions / commit-vote entries AND accumulates
    voting-power totals (``totalVP`` / ``totalVotingPower`` /
    ``sumPower`` / ``totalPower``) WITHOUT a ``ValidateVoteExtensions``
    call or any per-extension signature verification
    (``Verify``/``bls.Verify``/``ed25519.Verify``/``VerifySignature``).
    Mirrors solodit-47220 (OtterSec Ethos Cosmos): a malicious proposer
    can inject vote-extension data and skew consensus weights when the
    accumulator trusts proposer-supplied VE metadata. Stage-1 narrow
    name predicate; cross-file callee tracing deferred.
12. ``go.spark.tree_node.terminal_state_revival`` — a function body
    that advances a tree-node row to ``TreeNodeStatusAvailable``
    (field-assign ``.Status = TreeNodeStatusAvailable`` OR ent-builder
    ``.SetStatus(TreeNodeStatusAvailable)``) WITHOUT first calling the
    canonical guard ``CanBecomeAvailable()`` /
    ``TreeNodeCanBecomeAvailable(...)`` and WITHOUT an explicit compare
    against any of the five terminal status constants (``Splitted`` /
    ``OnChain`` / ``Exited`` / ``ParentExited`` / ``Reimbursed``). Write-
    side mirror of LEAD H-D's read-side ``guard_only_on_one_path``:
    SP-3049 ("block reviving terminal-state tree nodes") landed 13h
    after audit-pin and is the upstream-equivalent gate for this class.
    Test files (``*_test.go``) are skipped because terminal statuses are
    forced in setup helpers.
13. ``go.spark.coop_exit.coordinator_confirmation_guard_asymmetry`` —
    sharpened cross-function (per-package) detector. Fires on a function
    that:
      * lives in a Go package which ALSO defines or calls a coop-exit
        confirmation guard helper (``checkCoopExitTxBroadcasted`` /
        ``CheckCoopExitTxBroadcasted``) — i.e. the package is
        coop-exit-aware;
      * its body queries / loads / mutates a transfer in a pre-finalize
        coop-exit-eligible state. Trigger tokens (any of):
        ``TransferStatusReceiverRefundSigned`` /
        ``TransferStatusSenderInitiated`` /
        ``TransferStatusReceiverKeyTweaked`` /
        ``TransferStatusSenderKeyTweaked`` /
        ``TransferTypeCooperativeExit`` / ``CooperativeExit`` /
        a downstream-terminal status update via ``Update().SetStatus(``
        against any ``TransferStatus*`` token;
      * its body does NOT call the coop-exit confirmation guard;
      * the function name is NOT itself the guard helper, AND the body
        does NOT delegate via ``verifyAndUpdateTransfer(`` (the
        post-fix tree carries the guard internally on that callee).
    Mirrors SP-2961 (``buildonspark/spark`` commit ``fbd0598``): the
    coordinator's ``verifyAndUpdateTransfer`` finalize path was missing
    the guard while ``InternalTransferHandler.FinalizeTransfer`` and
    ``TransferHandler.FinalizeTransferWithTransferPackage`` both call
    it, producing permanent state divergence on coop-exit transfers
    that complete before the on-chain coop-exit tx reaches the required
    confirmations. **High value: this is the LEAD 1 family** — any
    pattern fire on Spark code paths NOT covered by LEAD 1's PoC scope
    is a candidate new finding.
14. ``go.spark.coop_exit.key_tweak_resumability`` — a function body
    that iterates over per-leaf cooperative-exit rows
    (``transferLeaves`` / ``coopExits`` / ``pendingCoopExits``) AND
    mutates per-iteration row state via an ent-style write call
    (``.Update().Save`` / ``ClearKeyTweak`` / ``SetStatus`` /
    ``.Exec(ctx)``) on a coop-exit / key-tweak-shaped entity, but
    DOES NOT carry an in-loop idempotency guard — no ``if leaf.KeyTweak
    == nil { continue }`` / ``if <row>.Status == <terminal> { continue
    }`` / ``if len(<field>) == 0 { continue }`` skip, and no
    ``RegisterResumeHandler`` / ``OnStartup`` registration anywhere in
    the same file. Mirrors SP-2988 (commits ``c36d0a4`` + ``9e06adf``
    on ``buildonspark/spark``): coordinator restart partway through
    ``tweakKeysForCoopExit`` re-runs already-cleared leaves and may
    diverge ephemeral / main commit state. Stage-1 predicate is
    intentionally narrow: in-loop ``continue``-skip on a sentinel
    field is the canonical resumability shape; cross-file resume-
    handler tracing is deferred to stage-2. Test files
    (``*_test.go``) are skipped — terminal/transient statuses are
    forced in setup helpers and flagging them is noise.
15. ``go.spark.signed_payload.req_identity_validator`` — a function
    body passes a request-supplied identity (``req.<*>IdentityPublicKey``
    / ``keys.ParsePublicKey(req.<*>IdentityPublicKey)``) to a
    ``Validate*Package`` (or other ``Validate*`` /
    ``Verify*Signature``) call without first reading a DB-sourced
    sender / owner identity for the same record (``mimo.GetSingleTransferSender``
    / ``transfer.QuerySender*`` / similar). Mirrors SP-5998
    (``6daafae89b`` on ``buildonspark/spark``): pre-fix
    ``FinalizeTransferWithTransferPackage`` passed
    ``req.OwnerIdentityPublicKey`` straight to ``ValidateTransferPackage``
    where signature verification then trusted the caller's claimed
    identity rather than the DB-stored sender identity. Stage-1
    predicate is intentionally narrow: req-identity must reach a
    Validate-shaped call AND the body must lack a DB-sourced
    identity read or an equality compare between request identity
    and DB-stored identity. Test files (``*_test.go``) are skipped.
16. ``go.spark.retry.prior_phase_commit_check`` — a function body that
    extracts and decrypts a coordinator-portion of a claim / settle
    payload (``KeyTweakPackage[h.config.Identifier]`` /
    ``EncryptedKeyTweakPackage[h.config.Identifier]`` /
    ``encryptedKeyTweakPackage[h.config.Identifier]``) and proceeds
    to decrypt it (``eciesgo.Decrypt`` / ``ecies.Decrypt`` /
    ``proto.Unmarshal`` over the decrypted bytes) WITHOUT a prior-phase
    commit gate — none of ``useStoredKeyTweaks`` / ``alreadyLocked`` /
    ``skipPackageDecryption`` / ``isPhase1Committed`` set as a guard
    AND no compare of ``transfer.Status`` / ``receiver.Status``
    against any ``ReceiverKeyTweak`` / ``ReceiverRefundSigned`` /
    ``KeyTweakLocked`` token (the canonical "prior phase already
    committed" sentinels). Mirrors SP-5498 (``f26284dd5f`` on
    ``buildonspark/spark``): pre-fix ``claim_transfer`` decrypted the
    fresh caller package even on retry, diverging coordinator extracts
    from SO stored material. Test files are skipped.
17. ``go.spark.cross_so.tweak_guard_pre_post_persist`` — a handler /
    base-handler function that performs an ent-mutation on a
    transfer-leaf record (``.SetKeyTweak(`` /
    ``.SetStatus(...KeyTweak*)`` / ``ClearKeyTweak(`` / ``Save(ctx)``
    on a leaf-builder / ``Update().Save(ctx)`` over a
    ``transferLeaf``) AND uses a sender-key-tweak-proof input
    (``senderKeyTweakProofs`` / ``KeyTweakProofs`` /
    ``SenderKeyTweakProofs``) but only invokes ONE of the two
    canonical guard helpers — either the pre-persist in-memory
    matcher (``verifySenderKeyTweakProofsMatch`` /
    ``VerifySenderKeyTweakProofsMatch``) OR the post-persist DB-
    backed validator (``validateKeyTweakProofs`` /
    ``ValidateKeyTweakProofs``) — not both. Mirrors SP-5589
    (``dae7686f2c`` on ``buildonspark/spark``): a coordinator that
    forwards plaintext proofs to a receiving SO must be checked
    in-memory against independently-decrypted package proofs BEFORE
    persistence (``verifySenderKeyTweakProofsMatch``) AND
    re-validated against the persisted leaves AFTER persistence
    (``validateKeyTweakProofs``). Functions named like the guard
    helpers themselves are skipped, as are ``*_test.go`` files.
18. ``go.cosmos.attacker_divisor_zero_unchecked`` (G2, ADVISORY, env-gated)
    generalizes Pattern 11 (gas-price subset) to ANY divisor whose name
    is external-taint-shaped (``msg`` / ``req`` / ``vote`` / ``order`` /
    ``param`` / ``amount`` receiver chain). Fires on a ``/`` or ``%`` OR a
    cosmos ``.Quo*(`` division whose divisor is a taint-shaped FIELD with
    NO zero-guard / positivity check (``.IsPositive()`` / ``.IsZero()`` /
    ``== 0`` / ``> 0`` on the divisor) AND no top-level ``defer``+``recover``
    in the function body. Because div-by-non-const is ubiquitous the
    predicate additionally REQUIRES a cosmos handler / abci / keeper
    context (``/x/<module>/`` path OR handler-shaped name OR ``sdk.Context``
    param). Advisory-first: emits ONLY when ``AUDITOOR_G2_ATTACKER_DIVISOR_
    ZERO`` is set, to ``<ws>/.auditooor/attacker_divisor_zero_hypotheses
    .jsonl`` with ``verdict="needs-fuzz"`` (NO auto-credit). Distinct from
    Pattern 11: gas-price-shaped divisors are delegated to
    ``gas_price_zero_unchecked`` and de-duplicated out of this lane by both
    a name exclusion AND a ``(file,line)`` diff against Pattern 11's hits.
19. ``go.consensus.nondeterministic_time_float_rand`` (G4, ADVISORY, env-gated)
    fires when a keeper/abci/module fn body reads a NONDETERMINISTIC source
    (``time.Now()`` / unseeded ``math/rand`` / ``float32|64`` arith) AND writes
    consensus state (``store.Set`` / ``KVStore().Set`` / ``k.Set*`` /
    ``SetParams``) in the SAME body - two honest validators then diverge ->
    AppHash mismatch -> chain halt.  CONTEXT-gated (``sdk.Context`` param OR
    handler-shaped name OR keeper/abci/module path).  FP-guard: telemetry /
    metric / log lines (``telemetry.``/``SetGauge``/``MeasureSince``/``log.``)
    are excluded as sources (latency gauges, not consensus), and a store-write
    in the SAME body is REQUIRED.  ``float32|64`` is IEEE754-deterministic so
    that arm is low-signal (tagged ``advisory_float``); the time/rand arms are
    prioritized.  Advisory-first: emits ONLY when
    ``AUDITOOR_G4_NONDET_TIME_FLOAT_RAND`` is set, to
    ``<ws>/.auditooor/nondeterministic_time_float_rand_hypotheses.jsonl`` with
    ``verdict="needs-fuzz"`` (NO auto-credit), gating exploit-class
    ``apphash-divergence``.  Distinct from the map-iteration determinism
    detector (that flags range-over-map ordering); de-duped by ``(file,line)``
    against its hits (A1 dedup boundary).

Detection is regex + bracketed-body slicing rather than a full Go AST. We
deliberately avoid shelling out to ``go/parser`` so the runner works in
sandboxes without a Go toolchain. False-positive shape is documented in
``docs/next-loop/spark_gap_001_go_detector_seed_2026-05-06.md``.

Outputs (idempotent rewrite):

    <workspace>/.auditooor/go_findings.json
    <workspace>/.auditooor/SCAN_GO_SUMMARY.json   (compat alias)

JSON shape::

    {
      "schema_version": 1,
      "workspace": "<abs path>",
      "scanner": "go-detector-runner.py",
      "scanner_version": "0.1.0",
      "go_files_scanned": <int>,
      "patterns": {
          "<pattern_id>": {
              "id": "<pattern_id>",
              "hits": [
                  {"file": "<rel path>", "line": <int>, "snippet": "..."}
              ],
              "hit_count": <int>
          },
          ...
      },
      "totals": {"hits": <int>, "files": <int>}
    }

When no Go files are present the runner exits 0 with ``go_files_scanned=0``
and an empty ``patterns`` map — i.e. it is a no-op for non-Go workspaces,
which is what ``tools/engage.py`` relies on.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

SCANNER_VERSION = "0.1.0"
STRICT_SCHEMA = "auditooor.go_detector_runner.strict.v1"
STRICT_DISPOSITION_SCHEMA = "auditooor.detector_disposition.v1"
STRICT_DISPOSITION_FILENAME = "go_detector_dispositions.jsonl"
_STRICT_DISPOSITION_TYPES = frozenset({
    "accepted", "covered", "duplicate", "filed", "false-positive",
    "known-issue", "not-applicable", "refuted", "resolved",
})

# ---------------------------------------------------------------------------
# Fire* provenance filter
# ---------------------------------------------------------------------------
# The go_wave1/*fire*.py corpus defines the CONFIRMED-BUG / low-FP quality
# bar (admin bypass, bridge domain binding, oracle staleness, signature
# replay, rounding, IBC rate limit, integer overflow, fee redirect).  The
# patterns below are the runner's own internally-coded equivalents that cover
# the same bug-class families.
#
# Excluded from the fire* set (advisory / needs-fuzz / broad):
#   go.go.panic.dereference_before_nil_check  — 1418 hits on injective alone;
#       fires on almost every nil-checked access pattern in Go; too broad to be
#       actionable without triage.
#   go.crypto.race.unsynchronized_concurrent_access — 91 hits; data-race
#       heuristic over file-level shared-map writes; high FP without goroutine
#       proof; advisory.
#   go.crypto.parse.negative_or_zero_int_unchecked — 43 hits; broad integer
#       sign check missing; plausible but requires function-level invariant
#       verification before promotion; advisory.
#
# All remaining runner patterns are fire* quality: domain-specific predicates
# derived from real CVEs / commit-backed bug instances with 0-6 hits per
# workspace (injective baseline).
_FIRE_EXCLUDED_PATTERN_IDS: frozenset[str] = frozenset({
    "go.go.panic.dereference_before_nil_check",
    "go.crypto.race.unsynchronized_concurrent_access",
    "go.crypto.parse.negative_or_zero_int_unchecked",
})


def _build_fire_pattern_ids(all_pattern_ids: frozenset[str]) -> frozenset[str]:
    """Return the fire* subset: all patterns except the broad/advisory ones."""
    return all_pattern_ids - _FIRE_EXCLUDED_PATTERN_IDS


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

# Skip these directories when walking — vendored / generated / test-output
# trees that bloat scan time without yielding actionable findings.
_SKIP_DIRS = {
    ".git", ".idea", ".vscode", "node_modules", "vendor", "third_party",
    "_archive", "_archived", ".auditooor", "dist", "build", "out",
}

# Default guard-function names worth checking for "guard_only_on_one_path".
# Operators can extend via --guard-name (repeatable). Keep this list short
# so the false-positive surface stays small.
_DEFAULT_GUARDS = (
    "validateTransition", "ValidateTransition",
    "checkTransition",   "CheckTransition",
    "assertGuard",       "AssertGuard",
    "guardStatus",       "GuardStatus",
)

# Project-specific guard naming convention. Recognises any function whose
# name begins with validate/enforce/check/assert followed by a Camel
# segment, e.g. ``validateTransferLeavesNotExitedToL1``,
# ``checkBlockHeight``, ``assertSenderKey``. This lets the package-aware
# detector arm catch project-specific guards without requiring an
# operator-supplied --guard-name.
_PROJECT_GUARD_NAME = re.compile(r"^(?:validate|enforce|check|assert)[A-Z]\w+$")

# gRPC-handler param shape: a parameter typed as a pointer to a request
# message (``*pb.ClaimTransferRequest``, ``*pbinternal.SettleReq``). We
# match on the trailing ``Request`` token so we don't trip on generic
# ``*pb.Foo`` parameters.
_GRPC_REQUEST_PARAM = re.compile(r"\*\s*\w+(?:\.\w+)*Request\b")

# Status-mutation marker substrings: a caller is treated as "status-mutating"
# if its body contains any of these substrings.
_STATUS_MUTATION_MARKERS = (
    "transfer.Status =", "node.Status =", ".Status =",
    "transfer.SetStatus(", "node.SetStatus(", ".SetStatus(",
)

# Logger patterns we treat as a "warning, no return" smell.
_WARN_LOGGER = re.compile(r"\b(?:Warnf|Warnln|Warning|Errorf|Errorln)\s*\(")

# Function header regex (very permissive — full Go grammar would need a real
# parser; this catches the common shapes including methods).
_FUNC_HEADER = re.compile(
    r"^func\s+(?:\((?P<recv>[^)]+)\)\s*)?(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\("
    r"(?P<params>[^)]*)\)",
    re.MULTILINE,
)

# Equality-against-persisted-ID heuristic — left or right side mentions
# txid/hash and the comparison is against an attribute lookup.
_TXID_EQ = re.compile(
    r"(?P<lhs>\b\w*(?:txid|TxID|TxId|Txid|hash|Hash)\w*)\s*==\s*"
    r"(?P<rhs>\w+(?:\.\w+){1,4})"
)
_TXID_EQ_REV = re.compile(
    r"(?P<lhs>\w+(?:\.\w+){1,4})\s*==\s*"
    r"(?P<rhs>\w*(?:txid|TxID|TxId|Txid|hash|Hash)\w*)\b"
)

# Names we accept as "the body validates the spend / utxo / signature".
_SPEND_VERIFIER = re.compile(
    r"\b(?:Validate(?:Spend|UTXO|Outpoint|Tx)?|Verify(?:Spend|UTXO|Sig|"
    r"Signature)?|SpendsOutpoint|SpendsUTXO|UTXO[A-Za-z]*Check|"
    r"CheckSpend|AssertSpend)\s*\("
)

# Proto-enum dispatch suppression. A comparison against a token shaped like
# ``<package>.<TypeName>_<VARIANT_NAME>`` (or just ``<TypeName>_<VARIANT>``)
# where the segment after the FIRST underscore is ALL-CAPS (digits / extra
# underscores allowed) is a generated proto enum constant — protoc emits
# ``<package>.<EnumType>_<VARIANT>`` for every enum value. These compares
# are dispatch sites (e.g. ``hashVariant == pb.HashVariant_HASH_VARIANT_V2``),
# NOT txid-equality bugs. We require at least one all-caps post-underscore
# segment (length>=2) to avoid matching CamelCase identifiers.
_PROTO_ENUM_CONSTANT = re.compile(
    r"\b[A-Za-z_]\w*\.[A-Za-z_]\w*_[A-Z][A-Z0-9]+(?:_[A-Z0-9]+)*\b"
    r"|\b[A-Z][A-Za-z0-9]*_[A-Z][A-Z0-9]+(?:_[A-Z0-9]+)*\b"
)

# ent-query / set-membership style txid lookup.  Matches calls like
# ``cooperativeexit.ExitTxidIn(...)``, ``treenode.RawTxidIn(...)``,
# ``foo.BarHashEq(...)`` — any call ending in
# ``<Txid|Hash>(In|Eq|EQ|Equal|Equals)(`` against an entgo-style schema
# helper. Captures the LEAD 1 shape at watch_chain.go:843 where the
# equality check is structured as a SQL ``IN`` query rather than ``==``.
_TXID_QUERY_CALL = re.compile(
    r"\b\w+\.\w*(?:Txid|TxID|TxId|Txid|Hash)(?:In|Eq|EQ|Equal|Equals)\s*\("
)

# ---------------------------------------------------------------------------
# Pattern for go.bitcoin.txid_without_vout_outpoint_binding (Spark LEAD 1
# txid-vs-UTXO class).
#
# A body compares / looks up a txid/Hash field but does NOT also constrain
# the output-index (vout / Vout / OutputIndex / output_index / TxIndex /
# outpointIndex). Without the vout constraint, an attacker can satisfy the
# check with any unrelated transaction that shares only the txid field while
# targeting a different output.
#
# Positive predicate (fires when ALL are true):
#   1. Function param mentions a txid/hash-shaped name (PARAM_TXID_RE).
#   2. Body contains a txid equality/query match (_TXID_EQ, _TXID_EQ_REV, or
#      _TXID_QUERY_CALL).
#   3. Body does NOT contain a vout / output-index binding (_VOUT_BINDING).
#   4. Proto-enum dispatch suppression still applies.
#
# Negative control (fires when EITHER):
#   - Body contains both a txid match AND a vout/output-index binding.
#   - Body contains a recognised full-outpoint verifier call.
# ---------------------------------------------------------------------------

# Vout / output-index binding: presence of any of these means the code
# correctly binds to the full outpoint (txid + vout), not just txid alone.
# We match field accesses, variable names, struct literals, and equality
# comparisons against vout / output-index-shaped tokens.
_VOUT_BINDING = re.compile(
    r"\b(?:vout|Vout|VOut|outputIndex|OutputIndex|output_index"
    r"|txIndex|TxIndex|tx_index|outpointIndex|OutpointIndex"
    r"|outpoint_index|outputIdx|OutputIdx|txVout|TxVout"
    r"|\.Vout\b|\.OutputIndex\b|\.TxIndex\b|\.Outpoint\b"
    r"|Outpoint(?:Index|Idx)?|UTXO(?:Index|Idx|Key)?)\b"
)

# Full-outpoint verifier: any call that validates the complete outpoint
# (txid + vout) by name is an explicit safe signal.
_OUTPOINT_VERIFIER = re.compile(
    r"\b(?:ValidateOutpoint|VerifyOutpoint|CheckOutpoint|SpendsOutpoint"
    r"|MatchesOutpoint|OutpointEquals|outpointMatch|OutpointMatch"
    r"|checkUTXO|CheckUTXO|verifyUTXO|VerifyUTXO)\s*\("
)

# Status-comparison condition for self-heal pattern. RHS is intentionally
# permissive: identifier, dotted attr, string literal, or rune.
_STATUS_NEQ = re.compile(
    r"\b\w+(?:\.\w+)*\.Status\b\s*!=\s*"
    r"(?:\"[^\"]*\"|`[^`]*`|'[^']*'|\w+(?:\.\w+)*)"
)

# Pattern 5 — protohash kind-identifier collision.
# We look for a body that calls protohash.Hash(...) AND uses two or more
# kind-identifier helpers (int/uint/enumIdentifier) over what looks like the
# same argument. The "same argument" check is approximate: we compare the
# raw argument substring up to the first `,` or `)` after each identifier
# call, then ask if the same argument shows up under two different kinds.
_PROTOHASH_CALL = re.compile(r"\bprotohash\.Hash\s*\(")
_KIND_IDENT_CALL = re.compile(
    r"\b(?P<kind>intIdentifier|uintIdentifier|enumIdentifier)\s*\(\s*"
    r"(?P<arg>[A-Za-z_][\w\.\[\]]*)\s*[,\)]"
)

# Pattern 6 — gossip perimeter trust.
# These markers must all appear in a single file:
#   * tls.NoClientCert (perimeter trust posture)
#   * a gRPC server registration (RegisterXxxServer or grpc.NewServer)
#   * at least one handler named Gossip/Broadcast/HandleGossip/...
# AND no VerifyECDSASignature/VerifySignature/VerifySig call appears in any
# of those handler bodies.
_TLS_NO_CLIENT_CERT = re.compile(r"\btls\.NoClientCert\b")
_GRPC_REGISTER = re.compile(
    r"\b(?:Register[A-Za-z_]*Server\s*\(|grpc\.NewServer\s*\()"
)
_GOSSIP_HANDLER_NAME = re.compile(
    r"^(?:Gossip|Broadcast|HandleGossip|OnGossip|GossipMessage|"
    r"BroadcastMessage|HandleBroadcast)$"
)
_VERIFY_SIG_CALL = re.compile(
    r"\bVerify(?:ECDSASignature|Signature|Sig)\s*\("
)

# Pattern 7 — byte-reversed lookup set.
# The function body must:
#   * compute a reversed hash via `slices.Reverse(<x>)` OR a manual byte
#     swap loop (`for i := 0; i < ...; i++ { x[i], x[len-1-i] = ... }`).
#   * insert BOTH the original and reversed value into the same map[]/set.
# We approximate "same map" by looking for two assignments of the form
# `<map>[<expr>] = <val>` (or `<map>[<expr>] = struct{}{}` set-style)
# where the same map name is used twice and at least one of the keys
# references the reversed variable / call.
_SLICES_REVERSE_CALL = re.compile(
    r"\bslices\.Reverse\s*\(\s*(?P<arg>[A-Za-z_][\w]*)\s*\)"
)
_MANUAL_REVERSE_LOOP = re.compile(
    r"for\s+\w+\s*,\s*\w+\s*:=\s*0\s*,\s*len\(\s*(?P<arg>[A-Za-z_][\w]*)"
    r"\s*\)\s*-\s*1\s*;[^{]*?\{\s*"
    r"(?P=arg)\s*\[\s*\w+\s*\]\s*,\s*(?P=arg)\s*\[\s*\w+\s*\]\s*=\s*"
    r"(?P=arg)\s*\[\s*\w+\s*\]\s*,\s*(?P=arg)\s*\[\s*\w+\s*\]"
)
_MAP_ASSIGN = re.compile(
    r"\b(?P<name>[A-Za-z_]\w*)\s*\[\s*(?P<key>[^\]]+?)\s*\]\s*="
)

# Pattern 8 — cosmos message_ordering_replay.
# Narrow function-name predicate: the handler shape we care about is
# something like Handle*/Process*/Execute* or a method on MsgServer. We
# require BOTH a proto.Unmarshal call AND a reference to a Msg* type, AND
# absence of any sequence / nonce / height / block-hash mention in the body.
_COSMOS_HANDLER_NAME = re.compile(
    r"^(?:Handle|Process|Execute|Deliver|Apply|Dispatch)[A-Z][A-Za-z0-9_]*$"
)
_PROTO_UNMARSHAL = re.compile(r"\bproto\.Unmarshal\s*\(")
_MSG_TYPE_USE = re.compile(r"\bMsg[A-Z][A-Za-z0-9_]*\b")
_COSMOS_SEQ_GUARD = re.compile(
    r"\b(?:[Ss]equence|[Nn]once|"
    r"Header\s*\(\s*\)\s*\.\s*Height|"
    r"BlockHash|HeaderHash|TxIndex|"
    r"BlockHeight|GetSequence|"
    r"sequence_number|packet_sequence)\b"
)

# Pattern 9 — lightning htlc_settlement_state_drift.
# A function body references both a "success" path token AND a "timeout" path
# token (HTLC-specific), and has NO cross-check helper indicating the two
# scripts/witnesses agree.
_HTLC_SUCCESS_TOKEN = re.compile(
    r"\b(?:HtlcSuccessTx|htlc_success_tx|HTLCSuccessTx|"
    r"SuccessScript|successScript|success_script|SuccessWitness)\b"
)
_HTLC_TIMEOUT_TOKEN = re.compile(
    r"\b(?:HtlcTimeoutTx|htlc_timeout_tx|HTLCTimeoutTx|"
    r"TimeoutScript|timeoutScript|timeout_script|TimeoutWitness)\b"
)
_HTLC_CROSSCHECK = re.compile(
    r"\b(?:require\.Equal|assert\.Equal|bytes\.Equal|reflect\.DeepEqual|"
    r"CrossCheck|crossCheck|VerifyEquivalent|MustEqual)\s*\("
)

# Pattern 10 — frost aggregate_pubkey_invariant_violation.
# Function name signals a participant share rotation, body assigns to an
# aggregate-pubkey field, and the function does NOT recompute via a group
# operation (.Add(/.Sub(/Aggregate(/Recompute).
_FROST_ROTATE_NAME = re.compile(
    r"^(?:Tweak[A-Za-z0-9_]*Share|RotateShare|RotateKeyShare|"
    r"UpdateKeyShare|TweakLeafKeyUpdate|TweakLeafKey|"
    r"TweakKeyShare|RefreshShare)$"
)
_FROST_AGG_PUBKEY_ASSIGN = re.compile(
    r"\b(?:verifying_pubkey|VerifyingPubkey|VerifyingKey|"
    r"AggregatePubkey|aggregate_pubkey|GroupPubkey|GroupPublicKey)\b"
    r"\s*[:=]\s*"
)
_FROST_RECOMPUTE_OP = re.compile(
    r"\.(?:Add|Sub|Combine|Aggregate)\s*\(|"
    r"\b(?:Aggregate|Recompute|RecomputeVerifyingKey|"
    r"DeriveVerifyingKey|ComputeAggregate)\s*\("
)

# Pattern 11 — cosmos gas_price_zero_unchecked.
# An identifier whose name is gas-price-shaped (``gasPrice`` / ``GasPrice`` /
# ``gas_price`` / ``gasFee`` / ``GasFee`` / ``gas_fee``). We require a
# division or modulo operator with the gas-price-shaped identifier as the
# RIGHT-hand operand (the divisor). Selectors like ``req.GasPrice`` are also
# accepted — the trailing identifier is what counts.
_GAS_PRICE_NAME = (
    r"(?:gas_?[Pp]rice|GasPrice|gas_?[Ff]ee|GasFee)"
)
_GAS_PRICE_DIVISION = re.compile(
    # numerator (allow chained selectors / array index / parens)
    r"(?P<num>[A-Za-z_][\w\.\[\]]*|\([^)]+\))"
    r"\s*(?P<op>/|%)\s*"
    # divisor: optional receiver chain followed by the gas-price token
    r"(?P<div>(?:[A-Za-z_][\w]*\.)*" + _GAS_PRICE_NAME + r")\b"
)
_GAS_PRICE_ZERO_GUARD = re.compile(
    # Any zero-guard mention of a gas-price-shaped identifier:
    #   if gasPrice == 0
    #   if gasPrice <= 0
    #   if gasPrice > 0
    #   if gasPrice != 0
    #   if gasPrice.IsZero()
    #   gasPrice.IsZero(
    #   IsZero(gasPrice)
    r"(?:[A-Za-z_][\w]*\.)*" + _GAS_PRICE_NAME +
    r"\s*(?:==|!=|<=|>=|<|>)\s*(?:0|big\.NewInt\s*\(\s*0\s*\)|sdk\.ZeroInt\s*\(\s*\))"
    r"|(?:[A-Za-z_][\w]*\.)*" + _GAS_PRICE_NAME + r"\.IsZero\s*\("
    r"|\bIsZero\s*\(\s*(?:[A-Za-z_][\w]*\.)*" + _GAS_PRICE_NAME + r"\s*\)"
    r"|(?:[A-Za-z_][\w]*\.)*" + _GAS_PRICE_NAME + r"\.Sign\s*\(\s*\)\s*(?:==|!=|<=|>=|<|>)"
)

# ---------------------------------------------------------------------------
# G2 - go.cosmos.attacker_divisor_zero_unchecked (advisory, env-gated).
# ---------------------------------------------------------------------------
# Generalizes Pattern 11 to ANY divisor whose receiver-chain name is
# external-taint-shaped.  See module docstring entry 18 for the full spec.
G2_ATTACKER_DIVISOR_ENV = "AUDITOOR_G2_ATTACKER_DIVISOR_ZERO"
G2_ATTACKER_DIVISOR_PID = "go.cosmos.attacker_divisor_zero_unchecked"
G2_ATTACKER_DIVISOR_OUT = "attacker_divisor_zero_hypotheses.jsonl"

# A divisor segment counts as external-taint-shaped iff (lower-cased) it is
# one of these msg/req/vote/order/param/amount receiver-chain tokens.  Kept
# small so the FP surface stays tight (div-by-non-const is ubiquitous).
_ADV_TAINT_SEGMENTS = frozenset({
    "msg", "req", "request", "vote", "votes", "order", "orders",
    "param", "params", "amount", "amt", "amounts",
})

# Gas-price-shaped names are Pattern 11's turf; exclude by name so the two
# detectors never overlap by construction (dedup boundary, A1 lesson).
_ADV_GASPRICE_SEG = re.compile(r"gas_?(?:price|fee)$", re.IGNORECASE)

# operator division/modulo whose divisor is a dotted selector (a FIELD).
_ADV_DIV_OP = re.compile(
    r"(?P<op>/|%)\s*(?P<div>(?:[A-Za-z_]\w*\.)+[A-Za-z_]\w*)"
)
# cosmos sdk.Dec / sdk.Int division method whose FIRST arg is a FIELD.
_ADV_DIV_METHOD = re.compile(
    r"\.(?P<op>Quo(?:Int64|Int|Raw|Truncate|RoundUp|Mut)?)\s*\(\s*"
    r"(?P<div>(?:[A-Za-z_]\w*\.)+[A-Za-z_]\w*)"
)
# cosmos handler / abci / keeper CONTEXT (one of these must hold).
_ADV_MODULE_PATH = re.compile(r"(?:^|/)x/[^/]+/")
_ADV_HANDLER_NAME = re.compile(
    r"^(?:Handle|Msg|EndBlock|BeginBlock|Tally|Process|Execute|Deliver|"
    r"CheckTx|Ante)\w*$|(?:MsgServer|Handler)$"
)
_ADV_CTX_PARAM = re.compile(r"\bsdk\.Context\b|\bcontext\.Context\b")
_ADV_TEST_FILE = re.compile(r"_test\.go$")
# Generated protobuf / gRPC-gateway / mock code: the ``msg / index`` shapes
# emitted by protoc are not hand-written division sites (FP flood otherwise).
_ADV_GENERATED_FILE = re.compile(
    r"\.pb(?:\.gw|\.validate)?\.go$|(?:^|/)mock_[^/]*\.go$|_generated\.go$"
)


def _adv_divisor_guarded(body_nc: str, div: str) -> bool:
    """True iff a zero-guard / positivity check on ``div`` exists in the
    (comment-stripped) function body: ``div.IsPositive()`` /
    ``div.IsZero()`` / ``div.Sign()`` / ``div.GT(``/``.GTE(``/``.LT(``/
    ``.LTE(`` OR a compare of ``div`` against zero.  A bare assignment
    (single ``=``) is NOT a guard.
    """
    esc = re.escape(div)
    guard = re.compile(
        esc + r"\s*(?:"
        r"\.IsPositive\s*\(|\.IsNegative\s*\(|\.IsZero\s*\(|"
        r"\.GT\s*\(|\.GTE\s*\(|\.LT\s*\(|\.LTE\s*\(|\.Sign\s*\(\s*\)|"
        r"(?:==|!=|>|>=|<|<=)\s*(?:0\b|sdk\.Zero(?:Dec|Int)\s*\(\s*\)|"
        r"big\.NewInt\s*\(\s*0\s*\)))"
    )
    if guard.search(body_nc):
        return True
    # bare IsZero(div) / IsPositive(div) helper form.
    if re.search(r"\bIs(?:Zero|Positive|Negative)\s*\(\s*" + esc + r"\s*\)",
                 body_nc):
        return True
    return False


def _adv_has_top_level_defer(body_nc: str) -> bool:
    """True iff the function body contains a ``recover(`` AND a ``defer`` at
    function-body top level (brace-depth 0).  A top-level defer/recover is
    the canonical cosmos chain-halt guard: it protects the whole function.
    A defer nested inside an inner closure (ballot.go ``ToCrossRate``) is
    NOT top-level, so it does NOT suppress.
    """
    if "recover(" not in body_nc.replace(" ", ""):
        return False
    depth = 0
    for m in re.finditer(r"[{}]|\bdefer\b", body_nc):
        tok = m.group(0)
        if tok == "{":
            depth += 1
        elif tok == "}":
            depth -= 1
        elif depth == 0:  # a `defer` keyword at function-body top level
            return True
    return False


# ---------------------------------------------------------------------------
# G4 - go.consensus.nondeterministic_time_float_rand (advisory, env-gated).
# ---------------------------------------------------------------------------
# A keeper/abci/module fn that reads a NONDETERMINISTIC source (time.Now /
# unseeded math/rand / float32|64 arith) AND writes consensus state in the
# SAME body can make two honest validators compute different state ->
# AppHash mismatch -> chain halt.  See module docstring entry 19.  Advisory:
# emitted ONLY behind AUDITOOR_G4_NONDET_TIME_FLOAT_RAND, verdict=needs-fuzz,
# NO auto-credit.  Distinct from the map-iteration determinism detector
# (go.consensus.map_iteration_nondeterministic_state_write): that flags
# range-over-map ordering; this flags wall-clock / RNG / float sources.
G4_NONDET_ENV = "AUDITOOR_G4_NONDET_TIME_FLOAT_RAND"
G4_NONDET_PID = "go.consensus.nondeterministic_time_float_rand"
G4_NONDET_OUT = "nondeterministic_time_float_rand_hypotheses.jsonl"
G4_NONDET_EXPLOIT_CLASS = "apphash-divergence"

# ---------------------------------------------------------------------------
# G6 - go.concurrency.goroutine_fanout_unsync_shared (advisory, env-gated).
# ---------------------------------------------------------------------------
# A ``go func(...){...}()`` fan-out whose closure body WRITES a captured,
# non-receiver shared cell (map/slice index, pointer deref, or an
# sdk.Context mutating method) with NO mutual-exclusion guard (mutex
# Lock/Unlock CALL, channel op, or atomic helper) anywhere in the
# closure + enclosing lexical scope is a data-race candidate: two spawned
# goroutines write the same cell concurrently -> torn/lost state.
#
# FP-guard: mature Go fan-outs are mostly -race-clean, so the guard-search
# spans the closure body AND the whole enclosing function body, and ANY
# mutex/channel/atomic call there suppresses the hit. A bare
# ``sync.WaitGroup`` (wg.Add/Done/Wait) is a COMPLETION barrier, not a
# write-serializer, so it is NOT counted as a guard. Static-only is
# insufficient; needs-fuzz / ``go test -race`` confirm.
#
# Distinct from Pattern 39 (go.crypto.race.unsynchronized_concurrent_access):
# that flags an exported method writing its OWN receiver field with no
# goroutine required; this REQUIRES a goroutine closure and a CAPTURED
# non-receiver write. De-duped by ``(file,line)`` diff against Pattern 39
# (A1 dedup boundary: we do NOT re-derive a ``covered_by`` signal).
G6_FANOUT_ENV = "AUDITOOR_G6_GOROUTINE_FANOUT_UNSYNC"
G6_FANOUT_PID = "go.concurrency.goroutine_fanout_unsync_shared"
G6_FANOUT_OUT = "goroutine_fanout_unsync_shared_hypotheses.jsonl"
G6_FANOUT_EXPLOIT_CLASS = "data-race-state-corruption"

# ``go func(<params>) {`` closure-spawn.
_G6_GO_CLOSURE = re.compile(r"\bgo\s+func\s*\((?P<cparams>[^)]*)\)")
# Receiver ident of an enclosing method header (None for free functions).
_G6_RECV = re.compile(r"^func\s*\(\s*(?P<recv>[A-Za-z_]\w*)\s+\*?\s*[A-Za-z_]")
# Mutual-exclusion / channel / atomic guard CALL. NOT a bare mutex TYPE decl
# (a declared-but-unlocked mutex protects nothing) and NOT a WaitGroup.
_G6_GUARD = re.compile(
    r"\.\s*R?Lock\s*\(|\.\s*R?Unlock\s*\(|"
    r"\batomic\s*\.\s*(?:Store|Load|Add|Swap|CompareAndSwap)\w*\s*\(|"
    r"<-\s*[A-Za-z_]\w*|[A-Za-z_]\w*\s*<-"
)
# Shared-write shapes anchored on a captured base ident.
#   (a) index write:  base[...] = / base.field[...] =
_G6_INDEX_WRITE = re.compile(
    r"(?P<base>[A-Za-z_]\w*)(?:\.\w+)*\s*\[[^\]]+\]\s*=(?!=)"
)
#   (b) pointer deref write:  *base =
_G6_PTR_WRITE = re.compile(r"\*\s*(?P<base>[A-Za-z_]\w*)\s*=(?!=)")
#   (c) sdk.Context mutating method:  base.KVStore(..).Set / base.Set*/Store*
_G6_CTX_WRITE = re.compile(
    r"(?P<base>[A-Za-z_]\w*)\.(?:KVStore|Set[A-Z]\w*|Store|WithValue|"
    r"EventManager)\s*\("
)
# Local (in-closure) declaration => not a captured shared var.
_G6_LOCAL_DECL_TPL = r"\b{name}\b\s*(?::=|,)|\bvar\s+{name}\b"


def _g6_shared_write(cbody: str, recv: str | None, local: set):
    """First captured, non-receiver shared write in a goroutine closure body.

    Returns ``(kind, base, match)`` or ``None``. A write is skipped when the
    base ident is the enclosing receiver, a closure parameter, or is locally
    declared inside the closure BEFORE the write (all non-shared).
    """
    for rx, kind in (
        (_G6_INDEX_WRITE, "index"),
        (_G6_PTR_WRITE, "ptr_deref"),
        (_G6_CTX_WRITE, "ctx_method"),
    ):
        for m in rx.finditer(cbody):
            base = m.group("base")
            if recv is not None and base == recv:
                continue  # receiver write -> Pattern 39 territory
            if base in local:
                continue  # closure parameter -> not captured
            decl = re.search(
                _G6_LOCAL_DECL_TPL.format(name=re.escape(base)), cbody
            )
            if decl is not None and decl.start() < m.start():
                continue  # declared locally before write -> not shared
            return kind, base, m
    return None


# ---------------------------------------------------------------------------
# G7 - go.crypto.counter.onesided_acceptance (advisory, env-gated).
# ---------------------------------------------------------------------------
# An accept/reject branch keyed on a NONCE / SEQ / SEQUENCE-named identifier
# whose comparison ADMITS the boundary-equal value (the stored counter
# value) into the accept region, WITHOUT a paired strict-successor
# (``== stored + 1``) validation. The boundary-equal value being accepted is
# the classic nonce/sequence REUSE (replay) shape: the guard accepts a value
# equal to the stored counter instead of demanding the exact successor.
#
# Polarity-correct (the boundary-equal admission test):
#   * REJECT branch (guarded block bails: return/continue/break/goto/panic):
#       accept region = condition FALSE. Equal is admitted iff the condition
#       is FALSE at ``L == R`` -> op ``>`` admits (FIRE), op ``>=`` rejects
#       (CLEAN), op ``==`` rejects (CLEAN).
#   * ACCEPT branch (guarded block does work): accept region = condition
#       TRUE. Equal is admitted iff the condition is TRUE at ``L == R`` ->
#       op ``>=`` admits (FIRE), op ``==`` admits (FIRE), op ``>`` rejects
#       (CLEAN).
# Truth-at-equal depends ONLY on the operator (equality is symmetric), so
# operand ORIENTATION does not matter: ``>=`` true, ``==`` true, ``>`` false.
#
# FP-guard (one-sided comparisons are ubiquitous in Go -> high FP):
#   * scope STRICTLY to comparisons where >=1 side is a nonce/seq/sequence-
#     named ident AND the other side is also an ident/field (literal
#     comparisons like ``seq == 0`` are excluded by the ident-only operand
#     regex - init/empty checks are not replay guards);
#   * operator set restricted to ``{>=, >, ==}`` (keeps OFF Pattern 40's
#     strict-``<`` skip-forward turf -> distinct);
#   * SUPPRESS when the enclosing function body contains a strict-successor
#     form ``== <x> + 1`` / ``<x> + 1 ==`` (the exact-successor validation
#     that a correct monotone nonce/seq guard uses).
# Polarity-sensitive -> mutation-verify mandatory. Static-only; needs-fuzz /
# a runtime replay PoC confirm.
#
# Distinct from Pattern 37 (go.crypto.counter.wrap_unchecked): that flags an
# unchecked counter INCREMENT (overflow/wrap); this flags a one-sided
# ACCEPTANCE comparison (reuse of the stored value). Distinct from Pattern 8
# (cosmos message_ordering_replay ABSENCE of a sequence guard): that flags a
# MISSING guard; this flags a PRESENT-but-one-sided guard. Distinct from
# Pattern 40 (strict_lt_only): that flags strict ``<`` skip-forward; this
# flags ``>=``/``>``/``==`` boundary-equal reuse. De-duped by ``(file,line)``
# diff against Pattern 40 (A1 dedup boundary: we do NOT re-derive a
# ``covered_by`` signal, we diff emitted hits vs Pattern 40's hits).
G7_ONESIDED_ENV = "AUDITOOR_G7_ONESIDED_ACCEPTANCE"
G7_ONESIDED_PID = "go.crypto.counter.onesided_acceptance"
G7_ONESIDED_OUT = "onesided_acceptance_hypotheses.jsonl"
G7_ONESIDED_EXPLOIT_CLASS = "nonce-seq-reuse-replay"

# ``if <cond> {`` header (cond captured up to the block brace).
_G7_IF = re.compile(r"\bif\b(?P<cond>[^{;]*)\{")
# Comparison with BOTH operands ident/field chains (no numeric literals) and
# the operator in the reuse-relevant set. Orientation-agnostic.
_G7_CMP = re.compile(
    r"(?P<lhs>(?:[A-Za-z_]\w*\s*\.\s*)*[A-Za-z_]\w*)\s*"
    r"(?P<op>>=|==|>)\s*"
    r"(?P<rhs>(?:[A-Za-z_]\w*\s*\.\s*)*[A-Za-z_]\w*)"
)
# Nonce / seq / sequence token inside an identifier (case-insensitive).
_G7_NONCE_TOKEN = re.compile(r"(?i)(?:nonce|sequence|\bseq\w*|\w*seq)")
# Strict-successor validation (``== x + 1`` / ``x + 1 ==``) -> correct guard.
_G7_SUCCESSOR = re.compile(
    r"==\s*(?:[A-Za-z_]\w*\s*\.\s*)*[A-Za-z_]\w*\s*\+\s*1\b|"
    r"(?:[A-Za-z_]\w*\s*\.\s*)*[A-Za-z_]\w*\s*\+\s*1\s*=="
)
# Bail-statement leading token of a REJECT branch.
_G7_BAIL = frozenset({"return", "continue", "break", "goto", "panic"})
# Non-counter operands (nil/bool checks are not reuse guards).
_G7_LITERAL_OPERAND = frozenset({"nil", "true", "false"})


def _g7_mask_comments(body: str) -> str:
    """Length-preserving comment/string mask: replaces ``//``, ``/*...*/``
    and string / rune / backtick literal INTERIORS with spaces while keeping
    every newline, so regex offsets still map 1:1 onto ``body``. Prevents
    the ``if`` / comparison regexes from matching inside a comment (which
    otherwise produced cross-comment ``cond`` spans and misplaced lines)."""
    out = list(body)
    i, n = 0, len(body)
    in_str = None  # '"' | '`' | "'"
    while i < n:
        c = body[i]
        if in_str is not None:
            if c == "\\" and in_str != "`" and i + 1 < n:
                if body[i + 1] != "\n":
                    out[i + 1] = " "
                out[i] = " "
                i += 2
                continue
            if c == in_str:
                # Symmetric mask: blank the CLOSING quote too. The opening quote is
                # blanked below; leaving the close-quote here left exactly one stray
                # quote per literal, so an ODD count between a brace pair flips a
                # downstream _balance_braces (which re-parses quotes on the already-
                # masked body) into string-mode and it swallows the matching brace ->
                # None -> a silent false-negative (e.g. the G-CENSUS map-range arm
                # missing a genuine store.Set inside a loop whose body has an odd
                # number of string/rune literals via fmt.Errorf / string keys).
                out[i] = " "
                in_str = None
            elif c != "\n":
                out[i] = " "
            i += 1
            continue
        if c == "/" and i + 1 < n and body[i + 1] == "/":
            while i < n and body[i] != "\n":
                out[i] = " "
                i += 1
            continue
        if c == "/" and i + 1 < n and body[i + 1] == "*":
            while i < n and not (body[i] == "*" and i + 1 < n
                                 and body[i + 1] == "/"):
                if body[i] != "\n":
                    out[i] = " "
                i += 1
            if i < n:
                out[i] = " "
                if i + 1 < n:
                    out[i + 1] = " "
                i += 2
            continue
        if c in ('"', "`", "'"):
            in_str = c
            out[i] = " "
        i += 1
    return "".join(out)


def _g7_is_nonce_ident(tok: str) -> bool:
    """True when ``tok`` (an operand ident/field chain) names a nonce/seq/
    sequence value. Restricts firing to the replay-relevant surface."""
    return bool(_G7_NONCE_TOKEN.search(tok))


def _g7_branch_kind(block_body: str) -> str:
    """``reject`` when the guarded block leads with a bail statement,
    else ``accept``."""
    stripped = _strip_comments(block_body).strip()
    m = re.match(r"[A-Za-z_]\w*", stripped)
    first = m.group(0) if m else ""
    return "reject" if first in _G7_BAIL else "accept"


def _g7_equal_admitted(op: str, kind: str) -> bool:
    """True when the boundary-equal value (L == R) lands in the ACCEPT
    region for this operator + branch polarity -> reuse candidate."""
    true_at_equal = op in {">=", "=="}  # ``>`` is false at equal
    if kind == "reject":
        return not true_at_equal  # accepted = condition FALSE at equal
    return true_at_equal           # accept branch: accepted = condition TRUE

# Nondeterministic sources.  time.Now + unseeded math/rand are HIGH signal;
# float32|64 arith is LOW signal (IEEE754 is deterministic across Go archs)
# so it is tagged advisory-float and de-prioritized (float arm reported but
# never promoted above the time/rand arms).
_G4_TIME_NOW = re.compile(r"\btime\.Now\s*\(")
# math/rand global / unseeded funcs.  crypto/rand exposes only Read / Int /
# Prime, so we name the math-rand-ONLY methods to avoid flagging crypto/rand.
_G4_MATH_RAND = re.compile(
    r"\brand\.(?:Intn|Int31n?|Int63n?|Uint32|Uint64|Float32|Float64|"
    r"NormFloat64|ExpFloat64|Perm|Shuffle)\s*\("
)
# float cast / arith (advisory arm).
_G4_FLOAT = re.compile(r"\bfloat(?:32|64)\s*\(")

# Consensus store / state write sink in the SAME body (narrow, named).
_G4_STORE_WRITE = re.compile(
    r"\b\w*[Ss]tore\.Set\("
    r"|\bKVStore\([^)]*\)\.Set\("
    r"|\.Set\(\s*ctx\b"
    r"|\b(?:k|keeper|Keeper)\.Set[A-Z]\w*\("
    r"|\.SetParams\("
)

# keeper / abci / module CONTEXT path (ibc-go-style trees have no /x/).
_G4_CTX_PATH = re.compile(r"(?:^|/)(?:x|modules?|keeper|abci|app)/", re.IGNORECASE)

# Telemetry / metric / log sinks (FP-guard): a nondeterministic read that
# feeds one of these is a latency / gauge measurement, NOT consensus state.
# Broadened to the real sei shapes: ``telemetry.SetGaugeWithLabels`` (float
# arg), ``telemetry.ModuleMeasureSince`` (latency), ``evpool.Metrics.Foo.Set(
# float64(..))`` (gauge), ``.Record(``/``.Observe(`` (otel histograms).
_G4_TELEMETRY = re.compile(
    r"\btelemetry\.|\bSetGauge\w*|\bMeasureSince\w*|\bIncrCounter\w*"
    r"|\b[Mm]etrics\.|\bprometheus\.|\.Logger\s*\(|\blog\.|"
    r"\.(?:Record|Observe)\s*\(|\.Set\(\s*float"
    r"|\.(?:Info|Debug|Warn|Warnf|Error|Errorf)\s*\("
)
# Latency idiom: ``<var> := time.Now()`` whose var only feeds a MeasureSince /
# time.Since duration measurement.  If a body measures elapsed time, a
# top-of-handler time.Now capture is a duration probe, not consensus input.
_G4_LATENCY_IDIOM = re.compile(r"MeasureSince\w*\s*\(|\btime\.Since\s*\(")
# Test / mock / fixture helpers that legitimately read wall-clock (skip).
_G4_TEST_NAME = re.compile(r"(?:Test|Mock|Fixture|Fake|Stub|Bench)", re.IGNORECASE)
_G4_TESTUTIL_PATH = re.compile(r"(?:^|/)(?:testutil|testutils|mock|mocks)s?/",
                               re.IGNORECASE)


def _g4_source_arm(
    body_nc: str,
    *,
    has_latency: bool = False,
) -> tuple[str | None, str | None]:
    """Return ``(arm, frag)`` for the first NON-telemetry nondeterministic
    source in ``body_nc`` (comment-stripped), preferring the high-signal arms
    (time.Now, then math/rand) over the low-signal float arm.  A source is
    skipped (FP-guard) when a small WINDOW around it (3 lines back, 4 forward -
    enough to reach a multi-line ``SetGaugeWithLabels(`` arg or a deferred
    ``MeasureSince``) matches a telemetry / log sink, OR - for the time.Now
    arm - when the body measures elapsed time (``has_latency``) and the match
    is a ``:= time.Now()`` capture.  Returns ``(None, None)`` when none survive.
    """
    lines = body_nc.split("\n")
    # precompute per-char line index for O(1) window lookup.
    def _window(start: int) -> str:
        ln = body_nc.count("\n", 0, start)
        lo = max(0, ln - 3)
        hi = min(len(lines), ln + 5)
        return "\n".join(lines[lo:hi])

    def _first_non_telemetry(rx: re.Pattern, arm: str) -> str | None:
        for m in rx.finditer(body_nc):
            if _G4_TELEMETRY.search(_window(m.start())):
                continue
            if arm == "time_now" and has_latency:
                ls = body_nc.rfind("\n", 0, m.start()) + 1
                le = body_nc.find("\n", m.end())
                line = body_nc[ls:(le if le >= 0 else len(body_nc))]
                if re.search(r":=\s*time\.Now\s*\(", line):
                    continue  # latency capture, not consensus input
            return m.group(0)
        return None

    for arm, rx in (("time_now", _G4_TIME_NOW), ("math_rand", _G4_MATH_RAND),
                    ("float", _G4_FLOAT)):
        frag = _first_non_telemetry(rx, arm)
        if frag is not None:
            return arm, frag
    return None, None


def _detect_nondeterministic_time_float_rand(
    funcs: Iterable[GoFunction],
) -> list[Hit]:
    """G4 - keeper/abci/module fn that reads a nondeterministic source AND
    writes consensus state in the SAME body (AppHash divergence candidate).

    Predicate (stage-1, narrow):
      (a) CONTEXT: sdk.Context / context.Context param OR a handler-shaped
          name OR a keeper/abci/module path (FP-guard - not any Go fn);
      (b) a NON-telemetry nondeterministic source (time.Now / unseeded
          math/rand / float cast) in the body - telemetry/log lines excluded;
      (c) a consensus store-write sink in the SAME body.

    ADVISORY: emitted only behind AUDITOOR_G4_NONDET_TIME_FLOAT_RAND with
    verdict=needs-fuzz.  ``*_test.go`` and generated files are skipped.
    """
    hits: list[Hit] = []
    seen: set[tuple[str, int]] = set()
    for fn in funcs:
        fpath = str(fn.file).replace("\\", "/")
        if _ADV_TEST_FILE.search(fpath) or _ADV_GENERATED_FILE.search(fpath):
            continue
        # FP-guard: test / mock / fixture helpers legitimately read wall-clock.
        if _G4_TESTUTIL_PATH.search(fpath) or _G4_TEST_NAME.search(fn.name):
            continue
        # (a) CONTEXT gate.
        in_ctx = (
            bool(_ADV_CTX_PARAM.search(fn.params))
            or bool(_ADV_HANDLER_NAME.match(fn.name))
            or bool(_G4_CTX_PATH.search(fpath))
        )
        if not in_ctx:
            continue
        body_nc = _strip_comments(fn.body)
        # (b) non-telemetry nondeterministic source (window + latency guard).
        has_latency = bool(_G4_LATENCY_IDIOM.search(body_nc))
        arm, frag = _g4_source_arm(body_nc, has_latency=has_latency)
        if arm is None or frag is None:
            continue
        # (c) consensus store-write in the same body.
        if not _G4_STORE_WRITE.search(body_nc):
            continue
        # Anchor the hit at the source fragment in the ORIGINAL body.
        idx = fn.body.find(frag)
        if idx < 0:
            idx = 0
        line_off = fn.body[:idx].count("\n")
        line = fn.body_start_line + line_off
        key = (str(fn.file), line)
        if key in seen:
            continue
        seen.add(key)
        lines = fn.body.splitlines()
        snippet = lines[line_off].strip() if line_off < len(lines) else fn.header
        hits.append(
            Hit(
                file=str(fn.file),
                line=line,
                snippet=snippet[:200],
                extra={
                    "function": fn.name,
                    "arm": arm,
                    "advisory_float": arm == "float",
                    "source": frag.strip(),
                },
            )
        )
    return hits


def _emit_nondeterministic_time_float_rand_hypotheses(
    workspace: Path,
    funcs: Iterable[GoFunction],
    map_iter_hits: Iterable[Hit],
    *,
    out_path: Path | None = None,
) -> tuple[list[dict], Path]:
    """Advisory G4 lane emitter.  Returns ``(records, out_path)`` and writes a
    ``needs-fuzz`` hypotheses jsonl.  De-dups emitted hits against the named
    existing detector ``go.consensus.map_iteration_nondeterministic_state_write``
    by ``(file,line)`` (A1 dedup boundary: we do NOT re-derive a ``covered_by``
    signal, we diff the emitted hits against the named detector's hits).  NO
    auto-credit: every record carries ``verdict="needs-fuzz"``.
    """
    hits = _detect_nondeterministic_time_float_rand(funcs)
    map_keys = {(h.file, h.line) for h in map_iter_hits}
    records: list[dict] = []
    for h in hits:
        if (h.file, h.line) in map_keys:
            continue  # already covered by the map-iteration determinism lane
        records.append({
            "workspace": str(workspace),
            "file": h.file,
            "line": h.line,
            "function": h.extra.get("function"),
            "arm": h.extra.get("arm"),
            "advisory_float": h.extra.get("advisory_float"),
            "source": h.extra.get("source"),
            "snippet": h.snippet,
            "pattern_id": G4_NONDET_PID,
            "attack_class": "consensus-nondeterminism-chain-halt",
            "exploit_class": G4_NONDET_EXPLOIT_CLASS,
            "lane": "G4",
            "verdict": "needs-fuzz",
        })
    out = (
        Path(out_path) if out_path
        else workspace / ".auditooor" / G4_NONDET_OUT
    )
    out.parent.mkdir(parents=True, exist_ok=True)
    text = "".join(json.dumps(r, sort_keys=True) + "\n" for r in records)
    out.write_text(text, encoding="utf-8")
    return records, out


# Pattern 12 — cosmos vote_extension_unverified.
# Body iterates over a vote-extension collection AND sums voting-power into
# a total accumulator WITHOUT a ValidateVoteExtensions call or any per-VE
# signature verification helper.
_VE_ITER = re.compile(
    r"\bfor\s+[^{]*?\b(?:VoteExtensions?|ExtendedCommitInfo|ExtendedVoteInfo|"
    r"vote_extensions?|extended_commit_info|extendedCommitInfo|"
    r"extendedVoteInfo|votes|Votes|commitInfo|CommitInfo)\b[^{]*?\{"
)
_VE_TOTAL_ACC = re.compile(
    r"\b(?P<acc>totalVP|totalVotingPower|total_voting_power|sumPower|"
    r"totalPower|total_power|sumVotingPower|aggregatedPower|"
    r"votingPowerSum|totalStake|sum_stake)\b\s*(?:\+=|=\s*\w+\s*\+|=)"
)
_VE_VALIDATE_CALL = re.compile(
    r"\bValidateVoteExtensions?\s*\("
)
_VE_VERIFY_SIG = re.compile(
    r"\b(?:bls\.Verify|ed25519\.Verify|VerifySignature|VerifyECDSA|"
    r"VerifyVoteExtension|VerifyVE|cmtcrypto\.Verify|VerifyBLS)\s*\("
    r"|\bsignature\.Verify\s*\("
    r"|\bpubKey\.VerifySignature\s*\("
    r"|\bpubkey\.VerifySignature\s*\("
    r"|\.VerifySignature\s*\("
)

# Pattern 13 — tree-node terminal-state revival (SP-3049 / LEAD H-D write-side
# mirror). A function body advances a TreeNode row to AVAILABLE (either by
# direct field assignment ``treeNode.Status = st.TreeNodeStatusAvailable`` or
# via the ent-builder shape ``...SetStatus(st.TreeNodeStatusAvailable)``)
# WITHOUT first checking that the source row is non-terminal. The fix
# introduced ``CanBecomeAvailable()`` (method on the status enum) and the
# pre-existing ``TreeNodeCanBecomeAvailable(node)`` helper as the canonical
# guards. Stage-1 predicate is intentionally narrow: we only fire when we see
# a TreeNodeStatusAvailable target (skipping unrelated ``.Status = "Available"``
# strings in other domains). Cross-file flow (guard performed by a private
# helper) is deferred to stage-2.
_TREENODE_AVAILABLE_ASSIGN = re.compile(
    # Field-assign form: <expr>.Status = <pkg>.TreeNodeStatusAvailable
    r"\b\w+(?:\.\w+)*\.Status\s*=\s*(?:[A-Za-z_]\w*\.)?TreeNodeStatusAvailable\b"
)
_TREENODE_AVAILABLE_SETSTATUS = re.compile(
    # ent-builder form: .SetStatus(<pkg>.TreeNodeStatusAvailable)
    r"\.SetStatus\s*\(\s*(?:[A-Za-z_]\w*\.)?TreeNodeStatusAvailable\s*[,)]"
)
_TREENODE_TERMINAL_GUARD_CALL = re.compile(
    # Either form of the SP-3049 guard:
    #   <expr>.Status.CanBecomeAvailable()
    #   <expr>.CanBecomeAvailable()
    #   TreeNodeCanBecomeAvailable(<expr>)
    #   tree.TreeNodeCanBecomeAvailable(<expr>)
    r"\b(?:[A-Za-z_]\w*\.)?TreeNodeCanBecomeAvailable\s*\("
    r"|\.CanBecomeAvailable\s*\("
)
# Explicit terminal-state compare: ``if <expr>.Status == <pkg>.TreeNodeStatusSplitted``
# (or any of the 5 terminal status constants). If the function body contains
# such a compare AGAINST any of the canonical terminal-status constants we
# accept it as a hand-rolled guard. Matching against a single terminal status
# is sufficient — the SP-3049 fix's CanBecomeAvailable() returns false for
# any of the five and authors who hand-roll the guard typically do so for
# the status they actually expect.
_TREENODE_TERMINAL_CONST_NAME = (
    r"TreeNodeStatus(?:Splitted|OnChain|Exited|ParentExited|Reimbursed)"
)
_TREENODE_TERMINAL_COMPARE = re.compile(
    r"\b\w+(?:\.\w+)*\.Status\s*(?:==|!=)\s*(?:[A-Za-z_]\w*\.)?" +
    _TREENODE_TERMINAL_CONST_NAME + r"\b"
    r"|\b(?:[A-Za-z_]\w*\.)?" + _TREENODE_TERMINAL_CONST_NAME +
    r"\s*(?:==|!=)\s*\w+(?:\.\w+)*\.Status\b"
)

# Pattern 13 — coop-exit coordinator confirmation-guard asymmetry (SP-2961
# / LEAD 1 family). A function in a coop-exit-aware Go package that
# loads / asserts / mutates a transfer in a pre-finalize coop-exit-eligible
# state but does NOT call the package-local coop-exit confirmation guard
# helper.
#
# Cross-function (per-package) detector: similar in shape to pattern 2's
# sharpened arm (`go.statemachine.guard_only_on_one_path`), but specialised
# to coop-exit. The asymmetry sentinel is the existence of
# ``checkCoopExitTxBroadcasted`` (or ``CheckCoopExitTxBroadcasted``) as a
# def or call site in the same package.

# Guard-call regex — case-insensitive on the leading ``c`` so we accept
# both the unexported helper and any future public alias.
_COOP_EXIT_GUARD_CALL = re.compile(
    r"\b[Cc]heck[A-Z][A-Za-z0-9_]*CoopExit[A-Za-z0-9_]*Broadcast(?:ed)?\s*\("
    r"|\b[Cc]heckCoopExit(?:Tx)?Broadcast(?:ed)?\s*\("
)
# Guard def regex — match a top-level ``func checkCoopExitTxBroadcasted``
# (or any case variant). Used to detect the package contains the guard
# helper.
_COOP_EXIT_GUARD_DEF = re.compile(
    r"^func\s+(?:\([^)]+\)\s*)?[Cc]heck[A-Za-z0-9_]*CoopExit[A-Za-z0-9_]*Broadcast(?:ed)?\s*\(",
    re.MULTILINE,
)
# Pre-finalize sentinel tokens that indicate the body works on a
# coop-exit-eligible transfer that has NOT yet seen the on-chain
# confirmation broadcast.
_COOP_EXIT_PREFINALIZE_TOKEN = re.compile(
    r"\b(?:TransferStatusReceiverRefundSigned"
    r"|TransferStatusSenderInitiated[A-Za-z0-9_]*"
    r"|TransferStatusReceiverKeyTweak[A-Za-z0-9_]*"
    r"|TransferStatusSenderKeyTweak[A-Za-z0-9_]*"
    r"|TransferTypeCooperativeExit"
    r"|CooperativeExit\b"
    r"|CoopExit[A-Za-z0-9_]*Tx"
    r")\b"
)
# Downstream-terminal status update via ent builder, e.g.
# ``transfer.Update().SetStatus(st.TransferStatusCompleted).Save(ctx)``.
# Accepts any ``TransferStatus*`` token as the argument since downstream
# terminal naming varies (Completed / Returned / Expired / etc.).
_COOP_EXIT_TERMINAL_UPDATE = re.compile(
    r"\.SetStatus\s*\(\s*(?:[A-Za-z_]\w*\.)?TransferStatus[A-Z][A-Za-z0-9_]*\s*[,)]"
)
# Delegating-callee suppression: if the body delegates via
# ``verifyAndUpdateTransfer(`` (or any case variant), the post-fix tree
# carries the guard internally on that callee — accept as a defended
# delegation.
_COOP_EXIT_DELEGATE = re.compile(
    r"\b[vV]erifyAndUpdateTransfer\s*\("
)

# Pattern 14 — coop-exit key-tweak resumability (SP-2988 — commits c36d0a4 +
# 9e06adf on buildonspark/spark). A function body iterates over per-leaf
# cooperative-exit rows (transferLeaves / coopExits / pendingCoopExits) AND
# mutates per-iteration row state via an ent-style write call (.Update().Save
# / ClearKeyTweak / SetStatus / .Exec(ctx)) on a coop-exit / key-tweak-shaped
# entity, but does NOT carry an in-loop idempotency guard — no
# ``if leaf.KeyTweak == nil { continue }`` / ``if <row>.Status == <terminal>
# { continue }`` / ``if len(<field>) == 0 { continue }`` skip and no
# ``RegisterResumeHandler`` / ``OnStartup`` registration anywhere in the
# same file.

# Loop header that iterates over a collection. The collection name is later
# matched against `_COOP_EXIT_LEAF_COLL_NAME` to keep the predicate selective.
_COOP_EXIT_LEAF_LOOP = re.compile(
    r"\bfor\s+[^{]*?\brange\s+(?P<coll>[A-Za-z_]\w*)\b"
)
# Recognised collection names. We deliberately keep this list short to avoid
# false positives on unrelated leaf-list iteration. Operators can extend by
# editing this list when new naming conventions appear.
_COOP_EXIT_LEAF_COLL_NAME = re.compile(
    r"^(?:transferLeaves|TransferLeaves|coopExits|CoopExits|"
    r"pendingCoopExits|PendingCoopExits|coopExitsToTweak|"
    r"unconfirmedCoopExits|cooperativeExits|CooperativeExits|"
    r"coopExitLeaves|CoopExitLeaves)$"
)

# Body must mutate the per-iteration row. We require at least one ent-style
# write call on a coop-exit / key-tweak surface. Match flavours:
#   * ``ClearKeyTweak(`` / ``.ClearKeyTweak(`` (the SP-2988 sentinel write)
#   * ``leaf.Update()...Save(ctx)`` / ``coopExit.Update()...Save(ctx)``
#   * ``...SetStatus(<TransferStatus*KeyTweak*|*CoopExit*>)``
#   * ``...Exec(ctx)`` chained off an ent .Update() builder
_COOP_EXIT_KEY_TWEAK_MUTATION = re.compile(
    r"\bClearKeyTweak\s*\("
    r"|\.Update\s*\(\s*\)[^\n;]*?\.Save\s*\(\s*ctx\b"
    r"|\.SetStatus\s*\(\s*(?:[A-Za-z_]\w*\.)?TransferStatus(?:Sender|Receiver)?KeyTweak[A-Za-z0-9_]*\s*[,)]"
    r"|\.SetStatus\s*\(\s*(?:[A-Za-z_]\w*\.)?(?:CoopExit|CooperativeExit)[A-Za-z0-9_]*\s*[,)]"
    r"|\.Update\s*\(\s*\)[^\n;]*?\.Exec\s*\(\s*ctx\b"
)

# Resumability guard inside the loop body: an early ``continue`` whose
# control predicate keys off a sentinel field that gets cleared by the
# mutation. Accepted shapes (any of which clears the body):
#   * ``if <expr>.KeyTweak == nil { continue }`` (post-fix c36d0a4 shape)
#   * ``if len(<expr>.KeyTweak) == 0 { continue }`` (v1 9e06adf shape)
#   * ``if <expr>.Status == <terminal> { continue }`` (general resumability)
#   * ``if <expr>.<Field> == nil { continue }`` (sentinel-field nil check)
#   * ``if <expr>.<Field>IsNil() { continue }`` (ent-builder-style nil check)
#   * ``if len(<expr>) == 0 { continue }`` (empty-collection sentinel)
_COOP_EXIT_RESUME_GUARD_CONTINUE = re.compile(
    r"\bif\b[^{]*?(?:"
    r"\.KeyTweak\s*(?:==|!=)\s*nil"
    r"|\blen\s*\(\s*[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*\.KeyTweak\s*\)\s*(?:==|!=)\s*0"
    r"|\.Status\s*(?:==|!=)\s*(?:[A-Za-z_]\w*\.)?TransferStatus[A-Z][A-Za-z0-9_]*"
    r"|\.[A-Za-z_]\w*\s*(?:==|!=)\s*nil"
    r"|\.[A-Za-z_]\w*IsNil\s*\(\s*\)"
    r"|\blen\s*\([^)]+\)\s*(?:==|!=)\s*0"
    r")[^{]*\{[^{}]*?\bcontinue\b",
    re.DOTALL,
)

# File-level resume-handler registration: when present anywhere in the file,
# we accept it as a defended posture (the ent-hook / coordinator-startup
# layer handles resumability externally).
_COOP_EXIT_RESUME_FILE_REGISTRATION = re.compile(
    r"\b(?:RegisterResumeHandler|OnStartup|RegisterStartupHook|"
    r"ResumePendingCoopExits|RecoverPendingCoopExits|"
    r"WithResumeHandler|RegisterRecoveryHandler|"
    r"reopenInProgressCoopExits|reopenPendingCoopExits)\s*\("
)

# Coop-exit / key-tweak domain filter: at least one of these tokens must
# appear in the function body. Without this filter, any unrelated leaf-
# iteration loop in the project would trip the detector.
_COOP_EXIT_DOMAIN_TOKEN = re.compile(
    r"\b(?:[Cc]oopExit"
    r"|[Cc]ooperativeExit"
    r"|KeyTweak"
    r"|TransferLeaf"
    r"|TweakLeafKey"
    r"|tweakKeysForCoopExit"
    r"|TransferStatusSenderKeyTweak[A-Za-z0-9_]*"
    r"|TransferStatusReceiverKeyTweak[A-Za-z0-9_]*"
    r"|TransferTypeCooperativeExit)\b"
)


# ---------------------------------------------------------------------------
# Pattern 15 — go.spark.signed_payload.req_identity_validator (L14-BACK-1).
# A handler-body that passes a request-supplied identity public key to a
# Validate*Package call (or any Validate* / Verify*Signature shape) WITHOUT
# first reading a DB-sourced sender / owner identity to compare against the
# request value. Modeled on SP-5998 (``6daafae89b``):
# FinalizeTransferWithTransferPackage pre-fix passed
# ``reqOwnerIdentityPubKey`` straight to ValidateTransferPackage.
# ---------------------------------------------------------------------------

# Request-supplied identity reaches a Validate-shaped call. The idiomatic
# Spark form is ``h.ValidateTransferPackage(ctx, ..., reqOwnerPubKey, ...)``
# where ``reqOwnerPubKey`` traces back to ``req.OwnerIdentityPublicKey`` /
# ``req.GetOwnerIdentityPublicKey()`` parsed via ``keys.ParsePublicKey``.
# We approximate the data-flow with a textual proximity match: the body
# must contain BOTH (a) a ``req.<X>IdentityPublicKey`` / ``GetXIdentityPublicKey()``
# extraction OR a ``keys.ParsePublicKey(req...)`` parse, AND (b) a
# ``Validate*Package(`` / ``Verify*Signature(`` / similar verifier call
# whose arguments include either the parsed identity variable or the
# raw req field.
_REQ_IDENTITY_EXTRACT = re.compile(
    r"\breq(?:\.[A-Za-z_]\w*)?\s*\.\s*"
    r"(?:Get)?[A-Za-z_]*IdentityPublicKey\b"
    r"|\bkeys\.ParsePublicKey\s*\(\s*req(?:\.[A-Za-z_]\w*)?\s*\."
)
# Validator call that consumes an identity-shaped argument. We accept any
# call whose name matches ``Validate*Package`` / ``Validate*Identity*`` /
# ``Verify*Signature`` / ``Verify*Package`` / ``Verify*Identity*``.
_VALIDATE_PACKAGE_CALL = re.compile(
    r"\b(?:[Vv]alidate[A-Za-z_]*Package"
    r"|[Vv]alidate[A-Za-z_]*Identity[A-Za-z_]*"
    r"|[Vv]erify[A-Za-z_]*Signature"
    r"|[Vv]erify[A-Za-z_]*Package"
    r"|[Vv]erify[A-Za-z_]*Identity[A-Za-z_]*"
    r")\s*\("
)
# DB-sourced identity reads. The post-fix shape reads the DB-stored sender
# identity (e.g. ``mimo.GetSingleTransferSender(ctx, transfer)``) before
# comparing against the request value. We accept any of:
#   * ``mimo.GetSingleTransferSender(``
#   * ``transfer.QuerySender(`` / ``QuerySenderIdentity(`` / similar
#   * ``transfer.SenderIdentityPublicKey`` field reads
#   * ``loadTransferForUpdate(`` followed by a sender / owner identity
#     attribute access
_DB_IDENTITY_READ = re.compile(
    r"\b(?:mimo\.GetSingleTransferSender|"
    r"GetSingleTransferSender|"
    r"GetTransferSenderIdentity|"
    r"loadSenderIdentity|"
    r"LoadSenderIdentity|"
    r"loadTransferOwner|"
    r"LoadTransferOwner)\s*\("
    r"|(?<!req\.)(?<!\.)\b(?!req\b)\w+\.QuerySender(?:Identity)?[A-Za-z_]*\s*\("
    r"|(?<!req\.)(?<!\.)\b(?!req\b)\w+\.QueryOwner(?:Identity)?[A-Za-z_]*\s*\("
    r"|(?<!req\.)(?<!\.)\b(?!req\b)\w+\.SenderIdentityPublicKey\b"
)
# Equality compare between req-supplied identity and a DB-sourced /
# parsed-DB identity. ``reqOwnerPubKey.Equals(senderPubkey)`` is the
# canonical post-fix gate.
_REQ_DB_IDENTITY_COMPARE = re.compile(
    r"\b\w+\.Equals\s*\(\s*\w+\s*\)"
    r"|\bbytes\.Equal\s*\(\s*[^,]+(?:Identity|Sender|Owner)[^,]*,\s*[^)]+(?:Identity|Sender|Owner)[^)]*\)"
)
# Function body must show a "this is a signed-payload finalize" intent —
# at least one of these tokens must appear so we don't fire on unrelated
# handlers that happen to mention req.<*>IdentityPublicKey.
_SIGNED_PAYLOAD_TOKEN = re.compile(
    r"\b(?:TransferPackage"
    r"|ClaimPackage"
    r"|SettlePackage"
    r"|SignedPayload"
    r"|SignedPackage"
    r"|UserSignature"
    r"|claimSignature)\b"
)


# ---------------------------------------------------------------------------
# Pattern 16 — go.spark.retry.prior_phase_commit_check (L14-BACK-2).
# A handler/body that decrypts the coordinator-portion of a claim / settle
# package without checking whether a prior phase already committed (and
# thus stored material should be preferred over fresh caller payload).
# Modeled on SP-5498 (``f26284dd5f``).
# ---------------------------------------------------------------------------

# Coordinator-portion extraction off the claim/settle/key-tweak package.
# Canonical: ``claimPackage.KeyTweakPackage[h.config.Identifier]`` or
# ``encryptedKeyTweakPackage[h.config.Identifier]``.
_COORD_PORTION_EXTRACT = re.compile(
    r"\b(?:[A-Za-z_]\w*\.)?(?:[Ee]ncrypted)?KeyTweakPackage\s*\[\s*"
    r"(?:[A-Za-z_]\w*\.)*(?:[Ii]dentifier|[Oo]perator[Ii]d|[Cc]onfig\s*\.\s*Identifier)\s*\]"
)
# Decrypt step over the extracted coordinator portion. The post-fix tree
# only enters this branch when ``useStoredKeyTweaks == false`` and the
# package length is non-zero.
_COORD_DECRYPT_CALL = re.compile(
    r"\beciesgo\.Decrypt\s*\("
    r"|\becies\.Decrypt\s*\("
    r"|\bDecrypt\s*\(\s*\w*[Pp]rivate[Kk]ey\b"
    r"|\bproto\.Unmarshal\s*\(\s*decrypted\b"
)
# Prior-phase-commit guard: any of the canonical sentinel variable names
# being assigned/checked, OR a status compare against a ReceiverKeyTweak /
# KeyTweakLocked / ReceiverRefundSigned token. Either form is enough to
# clear the body.
_PRIOR_PHASE_GUARD = re.compile(
    r"\b(?:useStoredKeyTweaks"
    r"|alreadyLocked"
    r"|skipPackageDecryption"
    r"|isPhase1Committed"
    r"|phase1Committed"
    r"|phaseOneCommitted)\b"
    r"|\b\w+\.Status\s*(?:==|!=)\s*(?:[A-Za-z_]\w*\.)?"
    r"(?:Transfer(?:Receiver)?Status(?:KeyTweakLocked|KeyTweakApplied|"
    r"ReceiverKeyTweakLocked|ReceiverKeyTweakApplied|ReceiverRefundSigned|"
    r"ReceiverKeyTweaked|SenderKeyTweaked))\b"
    r"|\b(?:[A-Za-z_]\w*\.)?Transfer(?:Receiver)?Status(?:KeyTweakLocked|"
    r"KeyTweakApplied|ReceiverKeyTweakLocked|ReceiverKeyTweakApplied|"
    r"ReceiverRefundSigned|ReceiverKeyTweaked|SenderKeyTweaked)\b"
)


# ---------------------------------------------------------------------------
# Pattern 17 — go.spark.cross_so.tweak_guard_pre_post_persist (L14-BACK-5).
# A handler/base-handler function that exercises sender-key-tweak proofs
# alongside a leaf mutation, but only invokes ONE of the two guard halves —
# the pre-persist in-memory matcher OR the post-persist DB-backed validator.
# Modeled on SP-5589 (``dae7686f2c``).
# ---------------------------------------------------------------------------

# Pre-persist in-memory matcher (verifies coordinator plaintext proofs vs
# independently-decrypted package proofs BEFORE persistence).
_PRE_PERSIST_TWEAK_MATCH = re.compile(
    r"\b[Vv]erifySenderKeyTweakProofsMatch\s*\("
    r"|\b[Vv]erifyKeyTweakProofsMatch\s*\("
    r"|\b[Vv]erifyKeyTweakPackageProofsMatch\s*\("
)
# Post-persist DB-backed validator (checks proofs against leaves stored in
# DB AFTER persistence).
_POST_PERSIST_TWEAK_VALIDATE = re.compile(
    r"\b[Vv]alidateKeyTweakProofs\s*\("
    r"|\b[Vv]alidateSenderKeyTweakProofs\s*\("
    r"|\b[Vv]alidatePersistedKeyTweakProofs\s*\("
)
# Sender-key-tweak proof input — the function works with these proofs.
_SENDER_KEY_TWEAK_PROOF_USE = re.compile(
    r"\b(?:senderKeyTweakProofs"
    r"|SenderKeyTweakProofs"
    r"|sender_key_tweak_proofs"
    r"|keyTweakProofs"
    r"|KeyTweakProofs)\b"
)
# Mutation of a transfer-leaf row (the persistence step). Either an ent-
# style leaf builder save, a ``ClearKeyTweak`` clear, or a ``SetKeyTweak``
# / ``SetStatus(...KeyTweak*)`` write.
_TRANSFER_LEAF_MUTATION = re.compile(
    r"\bClearKeyTweak\s*\("
    r"|\.SetKeyTweak\s*\("
    r"|\.SetStatus\s*\(\s*(?:[A-Za-z_]\w*\.)?(?:Transfer(?:Receiver)?Status[A-Za-z_]*KeyTweak[A-Za-z_]*"
    r"|TransferStatusSenderKeyTweak[A-Za-z_]*|TransferStatusReceiverKeyTweak[A-Za-z_]*)\s*[,)]"
    r"|\btransferLeaf\.Update\s*\(\s*\)"
    r"|\btransferLeaves\b[^\n]{0,80}?\.(?:Update|Save|Exec)\s*\("
    r"|\bcommitSenderKeyTweaks\s*\("
    r"|\bsettleSenderKeyTweaks\s*\("
)
# Function-name suppression: do NOT flag the guard helpers themselves.
_TWEAK_GUARD_HELPER_NAME = re.compile(
    r"^(?:[Vv]erifySenderKeyTweakProofsMatch"
    r"|[Vv]erifyKeyTweakProofsMatch"
    r"|[Vv]alidateKeyTweakProofs"
    r"|[Vv]alidateSenderKeyTweakProofs)$"
)


# ---------------------------------------------------------------------------
# Pattern 18 — go.spark.leaf_marshal.knob_gated_residual_disclosure
# (L14-BACK-3; SP-5846 ``25c37ff813``).
# A receiver-facing endpoint marshals a transfer / leaf via
# ``MarshalProto(ctx)`` (the unfiltered serializer) under a knob-gated
# else-branch. When the knob flips OFF post-creation, the receiver gets the
# unfiltered MarshalProto rather than the per-receiver MarshalProtoForReceiver,
# leaking sibling receivers' leaf material. We flag the residual class:
# bodies whose intent is "claim/query/pending transfer" AND that retain a
# knob-gated unfiltered marshal call without a static guarantee (such as a
# fixed-true literal) that the knob is unconditionally honored.
# ---------------------------------------------------------------------------

# Receiver-facing endpoint name predicate. We require the function name to
# start with one of these tokens so we don't fire on internal admin / cron
# helpers that legitimately need the unfiltered marshal.
_KNOB_RECEIVER_ENDPOINT_NAME = re.compile(
    r"^(?:[Cc]laim"
    r"|[Qq]uery"
    r"|[Gg]et[A-Z]\w*Transfer\w*"
    r"|[Pp]endingTransfers"
    r"|[Qq]ueryPendingTransfers"
    r"|[Qq]ueryTransfer\w*"
    r"|[Gg]etTransfer\w*"
    r"|[Mm]arshal[A-Z]\w*"
    r"|[Bb]uild[A-Z]\w*Response"
    r"|getTransferLeavesForReceiverQuery"
    r")"
)
# Unfiltered marshal call. ``transfer.MarshalProto(ctx)`` /
# ``t.MarshalProto(ctx)`` / ``freshTransfer.MarshalProto(ctx)`` — anything
# that calls ``.MarshalProto(`` with a single ctx argument and is NOT the
# per-receiver variant.
_UNFILTERED_MARSHAL_CALL = re.compile(
    r"\b\w+\.MarshalProto\s*\(\s*ctx\s*\)"
)
# Per-receiver filtered marshal call. The post-fix shape MUST also contain
# this AND the unfiltered call has to be in an else-branch — so detection
# WITHOUT this token is still a residual hit (knob never set).
_PER_RECEIVER_MARSHAL_CALL = re.compile(
    r"\b\w+\.MarshalProtoForReceiver\s*\("
)
# Knob-gated branch token. We treat any of these as the "knob conditional"
# under which the unfiltered marshal sits. Mirrors the canonical Spark
# names; cross-codebase coverage extends to any IsXxxEnabled / xxxEnabled
# style boolean predicate.
_KNOB_GATED_TOKEN = re.compile(
    r"\b(?:isMimoReceiveEnabled"
    r"|IsMimoReceiveEnabled"
    r"|isMimoTransferEnabled"
    r"|isMimoEnabled"
    r"|useMIMO"
    r"|useMimo"
    r"|MimoReceiveEnabled"
    r"|knobs\.GetKnobsService\s*\(\s*ctx\s*\)"
    r"|knobs\.Get\w*Knob\w*"
    r"|knobs\.\w*Enabled\b"
    r"|knobsService\.\w*Enabled\b"
    r")"
)
# Static-disable suppression: if the body contains a literal ``return false``
# from a helper-style early-exit (kill switch off forever), or a runtime
# unconditionally-true gate (``_, _ = ctx, _``) we bail. We use a permissive
# token-set to recognise the post-fix form: an explicit
# ``MarshalProtoForReceiver`` PLUS a default branch that calls
# ``MarshalProto(ctx)`` is the SAFE post-fix shape — only flag when the
# function name is a receiver-facing endpoint AND the knob token IS in the
# body AND there is NO MarshalProtoForReceiver companion.
_KNOB_DEFAULT_RECEIVER_FALLBACK = re.compile(
    r"\bif\s+!?\s*\w*[Mm]imo\w*\s*\("
    r"|\bif\s+!?\s*\w*[Mm]imo\w*\s*\b"
)


# ---------------------------------------------------------------------------
# Pattern 19 — go.spark.background_session.parent_tx_reopen_hook_missing
# (L14-BACK-4; SP-6329 ``dfb6b50ec9``).
# A function obtains an ent.Tx from a parent context (``entephemeral.GetTx
# FromContext(ctx)``, ``ent.GetTxFromContext(ctx)``, ``getTxFromContext``,
# etc.) and registers a deferred cleanup function (``defer func() { ... }``)
# that uses that Tx — but the function body never registers an OnCommit or
# OnRollback hook to reopen a fresh ephemeral tx after the parent finalizes,
# nor binds the cleanup to a session that hooks reopen. Result: rollback
# hooks fire on an already-finalized parent tx and no-op silently.
# ---------------------------------------------------------------------------

# Parent-context tx acquisition tokens. We accept either the spark-specific
# entephemeral helper or the generic ent.Tx helpers.
_PARENT_CTX_TX_GET = re.compile(
    r"\bentephemeral\.GetTxFromContext\s*\(\s*ctx\s*\)"
    r"|\bent\.GetTxFromContext\s*\(\s*ctx\s*\)"
    r"|\bGetTxFromContext\s*\(\s*ctx\s*\)"
    r"|\bGetEphemeralTxFromContext\s*\(\s*ctx\s*\)"
)
# Deferred-cleanup pattern: a ``defer func() { ... }()`` whose body
# references a session/tx/cleanup helper that mutates ephemeral state.
_DEFERRED_CLEANUP_FN = re.compile(
    r"\bdefer\s+func\s*\(\s*\)\s*\{[^}]*?"
    r"(?:[Cc]leanup|[Rr]ollback|[Dd]elete|[Rr]elease|[Cc]lose)\b"
    r"[^}]*?\}\s*\(\s*\)",
    re.DOTALL,
)
# OnCommit / OnRollback reopen-ephemeral hook registration. The post-fix
# shape MUST register at least one of these so the cleanup re-binds a fresh
# tx after the parent commits.
_REOPEN_EPHEMERAL_HOOK = re.compile(
    r"\bOnCommit\s*\("
    r"|\bOnRollback\s*\("
    r"|\bbindTx\s*\("
    r"|\bnewTxBackedEphemeralSession\s*\("
    r"|\breopenEphemeralTx\s*\("
    r"|\bRebindEphemeralTx\s*\("
    r"|\bResetEphemeralTx\s*\("
)
# Background-session domain token: at least one chainwatcher / cleanup
# domain token must appear so we don't fire on every helper that obtains a
# ctx-bound tx + has a defer cleanup. We use the leading word-boundary
# anchor only so the trailing CamelCase suffix (``chainwatcherCleanupHook``,
# ``orphanedSigningKeyshareSecretCleanup``, etc.) still matches.
_BG_SESSION_DOMAIN_TOKEN = re.compile(
    r"\b(?:[Cc]hainwatcher"
    r"|[Cc]hainWatcher"
    r"|[Cc]hain_watcher"
    r"|[Ee]phemeral[Ss]ession"
    r"|[Ss]igningKeyshareSecret"
    r"|[Oo]rphaned[A-Za-z_]*"
    r"|[Bb]ackground[Ss]ession"
    r"|[Cc]leanupHook"
    r"|[Cc]leanupSigning)"
)


# ---------------------------------------------------------------------------
# Pattern 20 — go.spark.post_commit_rollback_unprotected
# (SPARK-PT-L15-001; SP-6390 ``a5550e78e5632a8675bfefdad74a6e6054d89d2f``).
# A function registers a deferred ``Rollback()`` then calls ``Commit()`` on
# the same tx without a ``committed``/``rolledBack`` boolean guard. After
# commit succeeds, the deferred Rollback still fires, triggering OnRollback
# hooks that mutate state which Commit already cleared.
# ---------------------------------------------------------------------------

# defer Rollback() shapes:
#   * `defer func() { _ = tx.Rollback() }()`
#   * `defer func() { tx.Rollback() }()`
#   * `defer tx.Rollback()`  -- direct defer
# We capture the receiver name so we can later look for a matching
# ``<receiver>.Commit()`` in the same body. The first capture group is the
# receiver-style identifier (e.g. ``ephemeralTx`` / ``tx`` / ``mainTx``).
_DEFER_ROLLBACK_FUNC = re.compile(
    r"\bdefer\s+func\s*\(\s*\)\s*\{\s*"
    r"(?:_\s*=\s*)?(?P<rcvr>[A-Za-z_]\w*)\.Rollback\s*\(\s*\)\s*"
    r"\}\s*\(\s*\)"
)
_DEFER_ROLLBACK_DIRECT = re.compile(
    r"\bdefer\s+(?P<rcvr>[A-Za-z_]\w*)\.Rollback\s*\(\s*\)"
)
# Boolean guard suppression. If the body has a sentinel boolean (``committed``
# / ``didCommit`` / ``rolledBack`` / ``commitDone``) AND the deferred body
# checks the sentinel before calling Rollback, suppress.
_COMMITTED_GUARD_VAR = re.compile(
    r"\b(?:committed"
    r"|didCommit"
    r"|rolledBack"
    r"|commitDone"
    r"|isCommitted"
    r"|hasCommitted"
    r"|wasCommitted)\b"
)
# Guarded defer body: ``defer func() { if !committed { _ = tx.Rollback() } }()``.
# The presence of ``if`` inside the deferred-body Rollback indicates a guard.
_GUARDED_DEFER_ROLLBACK = re.compile(
    r"\bdefer\s+func\s*\(\s*\)\s*\{[^}]*?\bif\s+[!]?\s*\w*[Cc]ommitted[^}]*?"
    r"Rollback\s*\(",
    re.DOTALL,
)


# ---------------------------------------------------------------------------
# Pattern 21 — go.spark.cron_forupdate.adjacent_read_lock_missing
# (L14-BACK-6; SP-5433 ``594a8dbab7``).
# A function reads a transfer / leaf row via an ent-style query and then
# performs (or queues for) a structural decision (creation / cancel / status
# write) about that row, but the read does NOT include ``ForUpdate(...)``.
# The same package, however, contains a cron-task / scheduled-job code path
# that DOES use ``ForUpdate`` over the same entity family. Without a matching
# row-lock on the read side, the read sees a snapshot the cron task is about
# to mutate (TOCTOU), and the structural decision diverges.
# ---------------------------------------------------------------------------

# Generic ent-query without ForUpdate. We require the body to call one of the
# canonical ent query helpers AND not call ForUpdate anywhere in the same
# function body.
_ENT_QUERY_CALL = re.compile(
    r"\b(?:[A-Za-z_]\w*)\.Query\w*\s*\(\s*\)"
    r"|\b(?:[A-Za-z_]\w*)\.Get\s*\(\s*ctx\b"
    r"|\b(?:[A-Za-z_]\w*)\.Only\s*\(\s*ctx\b"
    r"|\b(?:[A-Za-z_]\w*)\.First\s*\(\s*ctx\b"
)
# ForUpdate row-lock token. Either ``ForUpdate(`` (no args) or
# ``ForUpdate(sql.LockForUpdate)`` / similar.
_FOR_UPDATE_TOKEN = re.compile(r"\bForUpdate\s*\(")
# Cron-task / scheduled-job marker. We treat any of these tokens as
# "this package has a cron lane". The combination of a non-cron read +
# a cron sibling that uses ForUpdate is the symptom.
_CRON_TASK_TOKEN = re.compile(
    r"\b(?:CronTask"
    r"|cronTask"
    r"|cron_task"
    r"|registerCron"
    r"|RegisterCron"
    r"|scheduledTask"
    r"|ScheduledTask"
    r"|scheduledJob"
    r"|ScheduledJob"
    r"|cancelStuckTransfer"
    r"|CancelStuckTransfer"
    r"|cancelStuckCounterSwap"
    r"|CancelStuckCounterSwap"
    r"|cancelExpiredCounterSwap"
    r"|CancelExpiredCounterSwap"
    r"|cancelExpiredTransfer"
    r"|CancelExpiredTransfer"
    r"|reapStuckRows)\b"
)
# Counter-swap / transfer-lifecycle entity tokens. The read must touch the
# same entity family that the cron lane mutates.
_COUNTER_SWAP_ENTITY_TOKEN = re.compile(
    r"\b(?:CounterSwap"
    r"|counterSwap"
    r"|counter_swap"
    r"|TransferLeaf"
    r"|transferLeaf"
    r"|transfer_leaf"
    r"|primaryTransfer"
    r"|PrimaryTransfer"
    r"|TransferReceiver"
    r"|transferReceiver"
    r"|pendingCounterSwap"
    r"|PendingCounterSwap)\b"
)
# Read-side function name predicate — only flag bodies whose name suggests a
# creation / lookup that should be lockstep with the cron mutation. We avoid
# flagging the cron-task itself (which legitimately uses ForUpdate), and the
# many helpers that just GET a row for a read-only display.
_CRON_ADJACENT_READ_NAME = re.compile(
    r"^(?:create"
    r"|Create"
    r"|initiate"
    r"|Initiate"
    r"|register"
    r"|Register"
    r"|primaryRead"
    r"|PrimaryRead"
    r"|loadFor[A-Z]"
    r"|LoadFor[A-Z]"
    r"|reserve"
    r"|Reserve"
    r"|acquire"
    r"|Acquire"
    r"|claim"
    r"|Claim"
    r"|finalize"
    r"|Finalize)\w*"
)
# Function-name suppression — the cron task itself uses ForUpdate; never
# flag the cron task.
_CRON_TASK_FUNC_NAME = re.compile(
    r"^(?:cancel(?:Stuck|Expired)\w*"
    r"|Cancel(?:Stuck|Expired)\w*"
    r"|reapStuckRows"
    r"|ReapStuckRows"
    r"|runCron\w*"
    r"|RunCron\w*"
    r"|.*CronTask"
    r"|.*cronTask)$"
)


# ---------------------------------------------------------------------------
# Pattern 22 — go.spark.coordinator_fanout.tx_commit_before_remote_call
# (L14-BACK-7; SP-5783 ``b154174cee``).
# A coordinator-side function performs a tx-bound write (ent ``Update().Save``
# / ``Create().Save`` / ``Exec(ctx)``) and then calls a remote-SO fanout
# helper (``ExecuteTaskWithAllOperators`` / ``Broadcast*ToOperators`` / equivalent
# gossip helper) WITHOUT an explicit commit between the write and the
# fanout. If the fanout fails partway through, the coordinator's tx may
# rollback while remote SOs have committed — divergent state.
# ---------------------------------------------------------------------------

# Coordinator-side ent write. Match the canonical write call shapes.
_ENT_TX_WRITE_CALL = re.compile(
    r"\b\w+\.Update\s*\(\s*\)\s*\.[^\n]{0,200}?\.Save\s*\(\s*ctx\b"
    r"|\b\w+\.Create\s*\(\s*\)\s*\.[^\n]{0,400}?\.Save\s*\(\s*ctx\b"
    r"|\b\w+\.UpdateOne\w*\s*\(\s*[A-Za-z_][\w.]*\s*\)\s*\.[^\n]{0,400}?\.Save\s*\(\s*ctx\b"
    r"|\bUpdate\s*\(\s*\)\s*\.[^\n]{0,200}?\.Exec\s*\(\s*ctx\b"
    r"|\.SetStatus\s*\([^)]+\)\s*\.Save\s*\(\s*ctx\b",
    re.DOTALL,
)
# Remote-SO fanout helper invocation.
_REMOTE_FANOUT_CALL = re.compile(
    r"\b(?:helper\.)?ExecuteTaskWithAllOperators\s*\("
    r"|\b(?:helper\.)?ExecuteTaskWithOperators\s*\("
    r"|\bBroadcast(?:Settle|Claim|Refund|Tweak|KeyShare|Finalize|Transfer)\w*ToOperators\s*\("
    r"|\bSendToAllOperators\s*\("
    r"|\bGossipToOperators\s*\("
    r"|\bFanoutTo(?:All)?Operators\s*\("
    r"|\bcallAllOperators\s*\("
    r"|\bsendSettleToOperators\s*\("
    r"|\bsendClaimToOperators\s*\("
    r"|\bsendRefundToOperators\s*\("
    r"|\bnotifyAllOperators\s*\("
    r"|\bsendToAllSOs\s*\("
)
# Explicit commit between write and fanout — if present in the body BEFORE
# the fanout, the bug shape doesn't apply.
_TX_COMMIT_CALL = re.compile(
    r"\b\w+\.Commit\s*\(\s*\)"
    r"|\bent\.DbCommit\s*\("
    r"|\bDbCommit\s*\("
    r"|\bCommitTx\s*\("
    r"|\bcommitCoordinatorTx\s*\("
    r"|\bcommitCoordinator\s*\("
    r"|\bCommitCoordinatorTx\s*\("
)
# Cron-context suppression: the cron-task DatabaseMiddleware commits when
# the task returns. If the function body reads as a cron-task callee
# (signalled by canonical cron tokens), don't flag — different lifecycle.
_FANOUT_CRON_CONTEXT_TOKEN = re.compile(
    r"\b(?:CronTask"
    r"|cronTask"
    r"|registerCron"
    r"|RegisterCron"
    r"|cronContextOnly"
    r"|cron-bound"
    r"|cron_bound"
    r"|CronOnlyHandler)\b"
)
# Coordinator-intent token — the function must reference a coordinator /
# coop-exit / preimage / settle / claim / transfer-finalize concept.
_COORDINATOR_INTENT_TOKEN = re.compile(
    r"\b(?:[Cc]oordinator"
    r"|[Pp]reimage[Ss]wap"
    r"|[Cc]oopExit"
    r"|[Cc]ooperativeExit"
    r"|[Ff]inalizeTransfer"
    r"|[Ss]ettleSenderKeyTweaks"
    r"|[Cc]laimTransfer"
    r"|[Ss]ettleTransfer"
    r"|[Ff]inalizeWithTransferPackage)\b"
)


# ---------------------------------------------------------------------------
# Pattern 23 — go.spark.grpc.default_service_config_last_write_wins
# (SPARK-PT-L15-009; SP-6314 ``51dc21a3ce``).
# grpc-go's ``WithDefaultServiceConfig`` is a single-pointer setter on the
# DialOption chain. If a builder/path appends ``WithDefaultServiceConfig``
# more than once on the same chain (whether literally adjacent in a slice
# or via successive ``append``s on the same options slice), only the last
# wins — silently dropping earlier service-config values such as retry
# policies / load-balancing config / health-check policy.
# ---------------------------------------------------------------------------

# Match any ``grpc.WithDefaultServiceConfig(...)`` call (or unqualified
# ``WithDefaultServiceConfig`` which is grpc-go aliased).
_DEFAULT_SVC_CONFIG_CALL = re.compile(
    r"\b(?:grpc\.)?WithDefaultServiceConfig\s*\("
)


# ---------------------------------------------------------------------------
# Pattern 24 — go.spark.multi_receiver.rollup_first_only
# (L14-BACK-8; SP-5842 ``c78104eab8``).
# Multi-receiver rollups (CancelStuckTransfer / RefundExpiredTransfer / etc.)
# must enumerate ALL receivers; the original bug touched only ``receivers[0]``
# leaving the remaining receivers in a divergent state.
# ---------------------------------------------------------------------------

# MIMO-aware file/function tokens: only flag inside files / functions whose
# scope intersects the multi-receiver transfer surface.
_MIMO_MULTI_RECEIVER_TOKEN = re.compile(
    r"\b(?:transferReceivers"
    r"|TransferReceivers"
    r"|QueryReceivers"
    r"|queryReceivers"
    r"|primaryTransfer"
    r"|PrimaryTransfer"
    r"|MimoReceive"
    r"|mimoReceive"
    r"|MIMOReceive"
    r"|mimo_receive"
    r"|isMimoReceiveEnabled"
    r"|allReceivers"
    r"|AllReceivers"
    r"|receivers\b)"
)
# First-only collapse: ``QueryReceivers().Only()`` / ``QueryReceivers().First()``
# or ``receivers[0]`` indexing followed by Update/Save/SetStatus.
_FIRST_RECEIVER_QUERY_CALL = re.compile(
    r"\b\w+\.QueryReceivers\s*\(\s*\)\s*\.[^;\n]{0,200}?\.(?:First|Only)\s*\(\s*ctx\b"
    r"|\b\w+\.QueryReceivers\s*\(\s*\)\s*\.(?:First|Only)\s*\(\s*ctx\b"
    r"|\breceivers\s*\[\s*0\s*\]\s*\.(?:Update|SetStatus|Save|Mutate)\s*\("
    r"|\bAllReceivers\s*\[\s*0\s*\]\s*\.(?:Update|SetStatus|Save|Mutate)\s*\("
    r"|\btransferReceivers\s*\[\s*0\s*\]\s*\.(?:Update|SetStatus|Save|Mutate)\s*\("
)
# Receiver-mutation token in the body — we want to flag only when the
# function intends to mutate receiver-side state, not when it merely reads.
_RECEIVER_MUTATE_TOKEN = re.compile(
    r"\b(?:SetStatus\s*\("
    r"|\.Update\s*\(\s*\)\s*\.(?:Set\w+\s*\([^)]*\)\s*\.)+Save\s*\(\s*ctx"
    r"|UpdateOne(?:ID)?\s*\("
    r"|\.Save\s*\(\s*ctx)"
)
# Enumeration-suppression: presence of a for-range loop over the receivers
# slice means the function did NOT collapse to first-only.
_RECEIVER_RANGE_LOOP = re.compile(
    r"\bfor\b\s*[\w_,\s]*\brange\b\s*"
    r"(?:[\w_]*\.?(?:[Tt]ransferReceivers|[Aa]llReceivers|receivers))\b"
    r"|\bfor\b\s*[\w_,\s]*\brange\b\s*"
    r"(?:[\w_]*\.?QueryReceivers\s*\(\s*\)\.AllX?\s*\(\s*ctx\s*\))"
)
# Cancel/Refund/Expired-style multi-receiver entry points. We require that
# the function name suggest a rollup operation (where enumeration is the
# correct shape). This avoids flagging legitimate single-receiver helpers.
_MULTI_RECEIVER_ROLLUP_FUNC_NAME = re.compile(
    r"^(?:[cC]ancel\w*Transfer\w*"
    r"|[rR]efund\w*Transfer\w*"
    r"|[eE]xpire\w*Transfer\w*"
    r"|[fF]inalize\w*Transfer\w*"
    r"|[sS]ettle\w*Transfer\w*"
    r"|[cC]laim\w*Transfer\w*"
    r"|[rR]oll\s*back\w*Transfer\w*"
    r"|[rR]ollback\w*Transfer\w*"
    r"|[rR]eapStuck\w*Transfer\w*"
    r"|[uU]pdateAllReceivers\w*"
    r"|[mM]ark(?:All)?Receivers\w*"
    r"|[sS]etReceiversStatus\w*)\w*"
)


# ---------------------------------------------------------------------------
# Pattern 25 — go.spark.so_pubkey.req_payload_not_session
# (lane spec maps to backward-mining seed: SO-pubkey resolution lifted from
# the request payload instead of the session-bound identity).
# A handler resolves a downstream SO pubkey from a request field
# (``req.OperatorPublicKey``, ``req.SOIdentityPublicKey``, etc.) and feeds it
# into a downstream lookup/resolver, with no session-bound identity check
# (``h.config.Identifier`` / ``auth.IdentityPublicKey(ctx)`` /
# ``session.Identity*``).
# ---------------------------------------------------------------------------

# Field-extraction shape: ``req.<*>(SO|Operator)<*>(Public|Identity)Key``.
_REQ_PAYLOAD_SO_PUBKEY_FIELD = re.compile(
    r"\breq(?:uest)?\.(?:[A-Z]\w*)*"
    r"(?:Operator|SO|SigningOperator|To|Target|Destination)"
    r"(?:[A-Z]\w*)*"
    r"(?:Public|Identity)Key\b"
    r"|\bin\.(?:[A-Z]\w*)*"
    r"(?:Operator|SO|SigningOperator|To|Target|Destination)"
    r"(?:[A-Z]\w*)*"
    r"(?:Public|Identity)Key\b"
)
# Downstream resolver/lookup that consumes the pubkey to dispatch a
# subsequent action (gossip / RPC / DB lookup). Presence of this AFTER
# the field-extraction is part of the bug shape.
_SO_PUBKEY_DOWNSTREAM_USE = re.compile(
    r"\b(?:[Rr]esolveOperator\s*\("
    r"|[Ll]ookupOperator\s*\("
    r"|[Gg]etOperator(?:By(?:Pubkey|Key|Identity))?\s*\("
    r"|[Dd]ialOperator\s*\("
    r"|[Ss]endTo(?:Operator|SO)\s*\("
    r"|[Gg]ossipTo(?:Operator|SO)\s*\("
    r"|[Vv]erifySignatureFrom(?:Operator|SO)\s*\("
    r"|[Vv]erifyOperatorSignature\s*\("
    r"|[Vv]erifySOSignature\s*\("
    r"|[Vv]alidateOperatorIdentity\s*\("
    r"|[Vv]alidateSOIdentity\s*\("
    r"|[Vv]erifyKeyTweakProof\s*\()"
)
# Suppression token: the body reads the session-bound identity.
_SESSION_IDENTITY_LOOKUP = re.compile(
    r"\bh\.config\.Identifier\b"
    r"|\bauth\.IdentityPublicKey\s*\(\s*ctx\b"
    r"|\bauthn\.IdentityPublicKey\s*\(\s*ctx\b"
    r"|\bsession\.Identity\w*\b"
    r"|\bsession\.OperatorPublicKey\b"
    r"|\bsession\.SOIdentityPublicKey\b"
    r"|\bIdentityFromContext\s*\(\s*ctx\b"
    r"|\bauthn\.IdentityFromContext\s*\(\s*ctx\b"
    r"|\bGetIdentityFromContext\s*\(\s*ctx\b"
    r"|\bcurrentSO(?:Identity|Pubkey)\s*\(\s*ctx\b"
)
# Function-scope predicate: only fire on handler-style functions
# (validators / dispatchers / signers).
_SO_HANDLER_FUNC_NAME = re.compile(
    r"^(?:[Vv]alidate"
    r"|[Vv]erify"
    r"|[Hh]andle"
    r"|[Dd]ispatch"
    r"|[Rr]oute"
    r"|[Ss]ign"
    r"|[Pp]rocess"
    r"|[Ff]orward"
    r"|[Ss]end"
    r"|[Rr]elay"
    r"|[Rr]esolve"
    r"|[Pp]repare)\w*"
)


# ---------------------------------------------------------------------------
# Pattern 26 — go.spark.guard_set.shrinkage_status_still_set
# (SPARK-PT-L17-003; SP-6286 ``1da2e92e93``).
# A package-level guard slice (``var <name> = []st.<EnumType>{...}``)
# referenced by ``StatusIn(<varName>...)`` / ``StatusNotIn(<varName>...)``
# omits one or more enum values that are STILL SET in production code via
# ``SetStatus(st.<EnumType><EnumValue>)`` (or equivalent) outside of test
# files — guard regression that lets formerly-protected statuses be
# overwritten.
# ---------------------------------------------------------------------------

# Match a package-level slice declaration of an enum-typed guard set:
#   var statusesNotAllowedFor = []st.SomeEnum{
#       st.SomeEnumA,
#       st.SomeEnumB,
#   }
# Captures: 1=var name, 2=enum type, 3=enum-value body (multi-line OK).
_GUARD_SET_VAR_DECL = re.compile(
    r"^var\s+(\w+)\s*=\s*\[\]\s*st\.(\w+)\s*\{([^}]*)\}",
    re.MULTILINE | re.DOTALL,
)
# Match an enum-value entry inside the guard slice body:
#   st.SomeEnumA,
#   st.SomeEnumB
_GUARD_SET_ENUM_ENTRY = re.compile(
    r"\bst\.(\w+)\b"
)
# Match a SetStatus call referencing an st.<EnumType><EnumValue> sym:
#   .SetStatus(st.SomeEnumValue)
#   SetStatus(ctx, st.SomeEnumValue)
_SET_STATUS_ENUM_CALL = re.compile(
    r"\bSetStatus\s*\(\s*(?:ctx\s*,\s*)?st\.(\w+)\s*[,)]"
)
# Match a StatusIn / StatusNotIn predicate consumer of a guard slice:
#   predicate.StatusIn(varName...)
#   *.StatusNotIn(varName...)
_GUARD_SET_CONSUMER = re.compile(
    r"\b(?:Status(?:In|NotIn))\s*\(\s*(\w+)\s*\.\.\.\s*\)"
)


# ---------------------------------------------------------------------------
# Pattern 27 — go.crypto.alias.constructor_stores_caller_slice_without_copy
# Pattern 28 — go.crypto.unmarshal.trailing_bytes_accepted
# Pattern 29 — go.spark.rpc_boundary.bare_fmterrorf_user_input_parse_failure
# Pattern 30 — go.crypto.alias.exported_getter_returns_internal_slice_without_copy
# Pattern 31 — go.spark.ent.edge_join_with_eq_when_denormalized_column_exists
# Pattern 32 — go.crypto.panic.zero_or_negative_length_reaches_make_slice
# Pattern 33 — go.crypto.parse.negative_or_zero_int_unchecked
# Pattern 34 — go.crypto.scalar_mult.identity_point_unchecked
# Pattern 35 — go.go.panic.dereference_before_nil_check
# Pattern 36 — go.crypto.loop.untrusted_length_unbounded
# Pattern 37 — go.crypto.counter.wrap_unchecked
# Pattern 38 — go.crypto.fips.approval_on_uninit
# Pattern 39 — go.crypto.race.unsynchronized_concurrent_access
# Pattern 40 — go.crypto.skip_allowed.strict_lt_only
# Pattern 41 — go.crypto.x509.suffix_match_no_dot_anchor
# ---------------------------------------------------------------------------

# Pattern 27: identify a func whose name is exported-constructor-shaped
# (``^New[A-Z]\w*``) and whose params include at least one ``[]byte``
# argument. We capture the param NAME so the body-search can look for a
# struct-literal field-write of that exact identifier.
_NEW_CONSTRUCTOR_NAME = re.compile(r"^New[A-Z]\w*$")
_BYTES_PARAM = re.compile(
    r"\b([A-Za-z_]\w*)\s+\[\]byte\b"
)
# Helpers that prove a defensive copy was made BEFORE the field-write.
_COPY_HELPERS = re.compile(
    r"\b(?:copy\s*\(|append\s*\(\s*\[\]byte\b|bytes\.Clone\s*\(|"
    r"slices\.Clone\s*\()"
)

# Pattern 28: detect Unmarshal-family calls without a trailing-byte guard
# in the same function body.
#
# L21 ABA refinement (post-AAU L20 empirical falsification at 14/14
# Spark handler-class hits):
#   1. encoder asymmetry — DROP json.Unmarshal entirely; stdlib rejects
#      trailing non-whitespace bytes (verified L20 runtime). Only fire on
#      proto / asn1 / cbor / ReadASN1 (permissive parsers).
#   2. byte_source annotation — classify the source of the bytes arg as
#      db_load / decrypted_plaintext / network_received / unknown. DB-load
#      of locally-marshaled bytes is canonical-only round-trip
#      (defensive design); we suppress it.
#   3. signature_boundary tag — fire only when the unmarshaled value
#      (or fields derived from it) feeds a signature-verify or
#      hash-equality check; otherwise distinct re-encodings have no
#      impact channel.
_UNMARSHAL_CALL = re.compile(
    r"\b(?:proto|asn1|cbor|json)\.Unmarshal\s*\(|"
    r"\.ReadASN1[A-Za-z0-9_]*\s*\("
)
# Refinement 2: permissive parsers that DO accept extension/unknown
# fields as trailing-byte equivalents. JSON is excluded — stdlib already
# rejects trailing non-whitespace.
_PERMISSIVE_UNMARSHAL_CALL = re.compile(
    r"\b(?:proto|asn1|cbor)\.Unmarshal\s*\(|"
    r"\.ReadASN1[A-Za-z0-9_]*\s*\("
)
_JSON_UNMARSHAL_CALL = re.compile(r"\bjson\.Unmarshal\s*\(")
_TRAILING_BYTE_GUARD = re.compile(
    r"\blen\s*\(\s*\w+\s*\)\s*(?:==|!=|>)\s*0\b|"
    r"\b\w+\.Empty\s*\(\s*\)|"
    r"\bbytes\.Equal\s*\(\s*\w+\s*,\s*nil\s*\)"
)

# Refinement 1 helpers: classify byte_source by looking at the FIRST
# arg of the Unmarshal call + the surrounding function context.
#
# Captures the bytes-arg expression. Tolerates ``Unmarshal(buf, ...)``,
# ``Unmarshal(leaf.KeyTweak, ...)``, ``Unmarshal(plaintext, ...)`` etc.
_UNMARSHAL_BYTES_ARG = re.compile(
    r"(?:proto|asn1|cbor)\.Unmarshal\s*\(\s*([A-Za-z_][\w.\[\]]*)\s*,"
)
# Markers indicating the bytes were locally produced (canonical-only
# round-trip path) — defensive design.
_LOCAL_MARSHAL_PRODUCER = re.compile(
    r"\b(?:proto|json|asn1|cbor)\.Marshal\s*\(|"
    r"\b\w+\.MarshalBinary\s*\(|\bmarshalAny\s*\("
)
# DB-load markers in the function body: ent ``assignValues``, ``Scan(``,
# ent ``Query*(ctx`` query loops, sql Rows.
_DB_LOAD_MARKERS = re.compile(
    r"\bassignValues\s*\(|"
    r"\bfunc\s*\(\s*\w+\s+\*?\w+\s*\)\s+UnmarshalJSON\s*\(|"
    r"\bsql\.Rows\b|\.Scan\s*\(|"
    r"\bQuery\w*\s*\(\s*ctx\b"
)
# Plaintext-from-decrypt markers (attacker-controlled plaintext).
_DECRYPT_MARKERS = re.compile(
    r"\beciesgo\.Decrypt\s*\(|\becies\.Decrypt\s*\(|"
    r"\bgcm\.Open\s*\(|\bcipher\.AEAD\b|"
    r"\bDecrypt\w*\s*\("
)
# Network-received markers: gRPC request struct, HTTP body, ws frame.
_NETWORK_MARKERS = re.compile(
    r"\bpb\w*Request\b|"
    r"\.Body\b|\bhttp\.Request\b|"
    r"\bgrpc\.\w+Stream\b|\bws\.\w+\("
)

# Refinement 3: hit-tag for whether the parsed value flows into a
# signature / hash-equality boundary. Cheap proxy: same-body presence
# of common signature-verify or hash-construction calls.
_SIGNATURE_BOUNDARY = re.compile(
    r"\bsignature\.Verify\b|"
    r"\becdsa\.Verify\w*\s*\(|"
    r"\bed25519\.Verify\s*\(|"
    r"\bschnorr\.Verify\w*\s*\(|"
    r"\bbls\.Verify\w*\s*\(|"
    r"\bVerifySignature\w*\s*\(|"
    r"\bVerifyHash\w*\s*\(|"
    r"\bsha256\.Sum256\s*\(|"
    r"\bsha512\.Sum\w*\s*\(|"
    r"\bbytes\.Equal\s*\(\s*\w*(?:[Hh]ash|[Ss]ig|[Dd]igest|[Ss]um)\w*\b"
)

# Pattern 29: spot a bare ``fmt.Errorf`` returned from an RPC handler when
# the wrapped error came from a USER-INPUT PARSER (proto.Unmarshal,
# uuid.Parse, hex.DecodeString, keys.Parse*, strconv.Parse*, base64.*Decode).
# Spark wraps these with ``errors.InvalidArgument*``-style helpers — bare
# ``fmt.Errorf`` returns lose the gRPC status-code mapping.
_PARSE_FAILURE_CALL = re.compile(
    r"\b(?:uuid\.Parse|hex\.DecodeString|base64\.[A-Za-z]*Decode|"
    r"strconv\.Parse\w+|keys\.Parse\w+|proto\.Unmarshal|"
    r"asn1\.Unmarshal|json\.Unmarshal|cbor\.Unmarshal|"
    r"net\.ParseIP|url\.Parse|time\.Parse[A-Za-z]*|"
    r"crypto\.ParseECDSA|x509\.Parse[A-Za-z]+)\s*\("
)
_RPC_STATUS_WRAPPER = re.compile(
    r"\berrors\.(?:InvalidArgument|Internal|NotFound|Unauthenticated|"
    r"PermissionDenied|FailedPrecondition|OutOfRange|Unimplemented|"
    r"Unavailable|DataLoss|Aborted|Canceled|AlreadyExists|"
    r"DeadlineExceeded|ResourceExhausted)[A-Za-z]*\s*\(|"
    r"\bstatus\.Errorf?\s*\(|\bgrpc\.Status\s*\(|"
    r"\btwirp\.[A-Za-z]+Error\s*\("
)
_BARE_FMT_ERRORF_RETURN = re.compile(
    r"return\s+(?:[^\n,]*,\s*)?fmt\.Errorf\s*\("
)

# ---------------------------------------------------------------------------
# Pattern 44 — go.cosmos.subaccount_filter_mismatch
# (Lane 11 NBQ-010; dYdX/Cosmos subaccount isolation; W68 family).
#
# A Cosmos-SDK keeper / gRPC handler function body contains BOTH:
#   (a) a subaccount-shaped selector or filter key — any of
#       ``SubaccountId``, ``Subaccount``, ``GetSubaccount*``, ``SubaccountKey``
#       used as a query/filter argument (ent-style or direct keeper call), AND
#   (b) an account-level query / balance read that does NOT thread the
#       subaccount ID through as the owner key —
#       ``GetBalance(``/ ``QueryBalance(`` / ``BankKeeper.GetBalance(``
#       / ``QueryBalances(`` called with a DIFFERENT address-shaped argument
#       (i.e. address does NOT carry the subaccount suffix).
#
# This pattern fires when subaccount isolation breaks because the subaccount
# filter and the account-level ledger read use different owner keys. Canonical
# form from dYdX: a ``GetSubaccountId()`` call followed by a
# ``bankKeeper.GetBalance(ctx, moduleAddr, ...)`` over the MODULE address
# rather than the per-subaccount address, causing the balance check to cover
# the whole module rather than the isolated subaccount.
#
# Negative control (SILENT): body reads balance using the subaccount-derived
# address (``types.SubaccountIdToAddress`` / ``SubaccountToAddress`` / any
# explicit ``ToAddress`` call on the subaccount ID) — guard confirmed.
# ---------------------------------------------------------------------------

_SUBACCOUNT_FILTER_USE = re.compile(
    r"\b(?:SubaccountId|GetSubaccountId|SubaccountKey"
    r"|GetSubaccount\b"
    r"|subaccountId|subaccount_id)\b"
)
_ACCOUNT_BALANCE_READ = re.compile(
    r"\b(?:bankKeeper|BankKeeper|bank_keeper)\.GetBalance\s*\("
    r"|\bGetBalance\s*\(\s*ctx\b"
    r"|\bQueryBalance(?:s)?\s*\(\s*ctx\b"
    r"|\bBankKeeper\.GetBalance\s*\("
    r"|\bGetAllBalances\s*\(\s*ctx\b"
    r"|\bGetCoins\s*\(\s*ctx\b"
)
_SUBACCOUNT_ADDRESS_DERIVATION = re.compile(
    r"\b(?:SubaccountIdToAddress|SubaccountToAddress|ToAddress|toAddress"
    r"|GetSubaccountAddress|subaccountAddress|SubaccountAddr)\s*\("
)


# ---------------------------------------------------------------------------
# Pattern 45 — go.cosmos.stale_tail_health_check
# (Lane 11 NBQ-010; stale tail-only health checks in Cosmos consensus paths).
#
# A function body:
#   (a) reads only the LAST/TAIL item from a collection — via
#       ``Last(ctx)`` / ``Tail(ctx)`` / ``[len(...)-1]`` indexing /
#       ``GetLast*`` / ``MustGetLast*`` / ``LatestHeight`` /
#       ``GetLatest*`` — AND
#   (b) makes a health / validity assertion on that tail item —
#       ``require.*``  / ``assert.*`` / ``if err != nil { panic`` /
#       explicit ``panic(`` / ``Require`` / ``Assert`` shape, AND
#   (c) does NOT range-iterate over the collection to check every element —
#       no ``for ... range`` loop consuming the same collection.
#
# Bug class: a health check that only validates the tail of a sequence
# silently skips gaps / corruption at earlier positions. In Cosmos SDK,
# this appears when the commit-height validator reads only the latest
# committed height but not intermediate entries — a truncation attack or
# corruption at any non-tail position goes undetected.
#
# Negative control (SILENT): body contains a ``for ... range`` loop over
# the same collection OR uses ``All(ctx)`` / ``GetAll*`` / ``ForEach*``
# to iterate the full set.
# ---------------------------------------------------------------------------

_TAIL_READ = re.compile(
    r"\b(?:GetLast|MustGetLast|Last|Tail|GetLatest|MustGetLatest|LatestHeight"
    r"|GetLatestHeight|lastCommittedHeight|lastCommitInfo)\s*\("
    r"|\bgetLast[A-Z]\w*\s*\("
    r"|\[len\s*\([^)]+\)\s*-\s*1\]"
)
_HEALTH_ASSERT = re.compile(
    r"\b(?:require\.|assert\.|Require\.|Assert\.)\w+\s*\("
    r"|\bpanic\s*\("
    r"|\bif\s+err\s*!=\s*nil\s*\{[^}]*panic\b"
    r"|\bMust\w+\s*\("
)
_FULL_ITERATION = re.compile(
    r"\bfor\b[^{]*\brange\b"
    r"|\bAll\s*\(\s*ctx"
    r"|\bGetAll\w*\s*\(\s*ctx"
    r"|\bForEach\w*\s*\("
    r"|\bIterateAll\w*\s*\("
    r"|\bWalkAll\w*\s*\("
)


# Pattern 30: getter-shaped exported method returning a ``[]byte`` field
# directly. We look at the function HEADER LINE in the file source to
# identify (a) the receiver name, (b) zero formal parameters, (c) a
# ``[]byte`` return type. The body must then be a single ``return
# <recv>.<field>`` statement (whitespace + comments tolerated). Inverse
# companion to pattern 27 — Swival #023/#024/#025/#045/#046 cluster.
# **Spark structural prediction (AAK L18):** ``common/bitmap.go:33``
# ``func (b *BitMap) Bytes() []byte { return b.value }``.
_GETTER_HEADER = re.compile(
    r"^func\s*\(\s*(?P<recv>[A-Za-z_]\w*)\s+\*?\s*[A-Za-z_]\w*\s*\)\s+"
    r"(?P<name>[A-Z]\w*)\s*\(\s*\)\s+\[\]byte\s*\{",
    re.MULTILINE,
)
# Body shape: a single return statement `return <id>.<field>`. The body
# may also contain leading whitespace/blank lines and a trailing newline,
# but no other executable statements.
_BODY_RETURN_FIELD = re.compile(
    r"^\s*return\s+(?P<recv>[A-Za-z_]\w*)\.(?P<field>[A-Za-z_]\w*)\s*$",
    re.MULTILINE,
)

# Pattern 31: structural ``Has<Edge>With(<Pkg>.<Col>EQ(...))`` ent edge-join
# call shape. Per L17 PT-L17-002, when the inner column has a denormalized
# mirror on the outer entity, the edge-join is a query-plan tax. The
# narrow predicate fires on any ``<pkg>.Has<X>With(<pkg2>.<Y>EQ(`` token
# regardless of whether the denormalized column actually exists — triage
# step 2 (manual or follow-up loop) confirms denormalization. The original
# upstream fix landed in commit ``e330cd3458`` for one site
# (``internal_prepare_token_handler.go``); adjacent unfixed sites are at
# ``internal_sign_token_handler.go:428`` and ``so/tokens/validation.go:136``.
#
# Single-line predicate: matches the ``Has<X>With(<pkg>.<Y>EQ(`` token
# pair on a single physical line OR across two adjacent lines. We
# conservatively start with the line-scoped form to avoid noise.
_ENT_EDGE_JOIN_EQ = re.compile(
    r"\bHas[A-Z]\w*With\s*\(\s*\w+(?:\.\w+)*\.\w+EQ\s*\("
)
# Multi-line variant — the most common Spark spelling splits across two
# lines: ``Has<X>With(\n\t\t<pkg>.<Y>EQ(``.
_ENT_EDGE_JOIN_EQ_MULTILINE = re.compile(
    r"\bHas[A-Z]\w*With\s*\(\s*\n\s*\w+(?:\.\w+)*\.\w+EQ\s*\(",
    re.MULTILINE,
)
# Suppress test-only sites — we already file-skip ``_test.go`` but the
# ``testing/wallet/`` corpus lives under non-_test.go names. To preserve
# the L17 KF001 triage scope (production-handler-only), we accept the
# trade-off of including ``testing/wallet/`` hits in the hit-list and
# tagging them via ``extra.path_class`` for downstream filtering.

# Pattern 32: ``make([]byte, n)`` / ``make([]byte, 0, n)`` where ``n`` is
# the name of an integer parameter AND the function body has no preceding
# ``if n <= 0`` / ``if n < 0`` / ``if n < <const>`` guard.
# Mirrors Swival #047/#048/#049/#052/#053 — caller-controlled length
# reaches ``make`` and a zero/negative value either panics (negative) or
# silently allocates an empty slice (zero) leading to logic-error.
_MAKE_BYTE_SLICE = re.compile(
    r"\bmake\s*\(\s*\[\]byte\s*,\s*(?:0\s*,\s*)?(?P<lenexpr>\w+)\s*\)"
)
# Allowed integer parameter type names — we treat any signed/unsigned int
# kind as a candidate. ``uintptr`` excluded; ``byte`` excluded.
_INT_PARAM = re.compile(
    r"\b([A-Za-z_]\w*)\s+(?:int|int8|int16|int32|int64)\b"
)
# A defensive guard ANYWHERE in the body before the make-call. Spelled
# either as `n <= 0`, `n < 0`, `n == 0`, or via a `n > 0` precondition
# branch that returns/aborts on the negative path. We accept any of those
# as evidence of intent — strict over-approximation matches the M14-trap
# discipline (false-negative on overly-broad guard ≪ false-positive).
_LEN_GUARD = re.compile(
    r"\b(?P<name>\w+)\s*(?:<=|<|==|!=|>=|>)\s*0\b"
)

# Pattern 33 — go.crypto.parse.negative_or_zero_int_unchecked
# Body parses an integer field via a parser call (cryptobyte ASN1 int
# readers, strconv.Atoi/ParseInt, asn1.Unmarshal-derived integer fields)
# and uses the integer value WITHOUT enforcing both `value > 0` AND a
# documented upper bound. Mirrors Swival #060/#061/#062/#063 — RFC5280
# x509 policy fields ``requireExplicitPolicy`` / ``inhibitPolicyMapping``
# / ``requireExplicitPolicyZero`` accepted negative or zero values that
# x509 RFC documents as "MUST be a non-negative integer", flowing into
# certificate-path validation as a panic / off-by-one surface.
#
# Predicate (body-local, single-function):
#   * fn body contains a call site of `<x>.ReadASN1Int*` (cryptobyte) /
#     `strconv.ParseInt|Atoi` / `binary.BigEndian.Uint*` writing into a
#     destination identifier `<dst>`;
#   * the same body uses `<dst>` as a counter / iter / policy bound
#     downstream (any subsequent reference suffices — over-approx);
#   * the same body does NOT contain a guard checking `<dst>` against a
#     positive lower bound (`<dst> <= 0`, `<dst> < 0`, `<dst> > 0`,
#     `<dst> > <max>`, `<dst> >= <max>`, etc.) for that exact identifier.
#
# This is intentionally narrower than #32 (which only fires on `make`
# call sites with an integer parameter): #33 fires on PARSED integer
# fields irrespective of their downstream use, capturing the broader
# policy-int-validation class the Swival x509 cluster surfaced.
_PARSE_INT_CALL = re.compile(
    # Capture the LEAD identifier on a `<dst>[, <other>...] := <call>`
    # OR `<dst>[, <other>...] = <call>` line. The remaining LHS slots
    # (typically `_` or `err`) are tolerated; only the FIRST LHS slot
    # is captured as the integer destination.
    r"\b(?P<dst>[A-Za-z_]\w*)\s*(?:,\s*[A-Za-z_]\w*\s*)*"
    r"(?::=|=)\s*"
    r"(?:[A-Za-z_]\w*\s*\.\s*)?"
    r"(?:ReadASN1Int(?:64)?|ReadASN1Integer|ReadInt(?:8|16|32|64)?|"
    r"strconv\s*\.\s*(?:Atoi|ParseInt|ParseUint)|"
    r"asn1\s*\.\s*Unmarshal|"
    r"binary\s*\.\s*(?:BigEndian|LittleEndian)\s*\.\s*Uint(?:8|16|32|64)?)\s*\("
)
# Lower-bound guard on `<dst>` somewhere in the body (any of the six
# zero-comparisons; we accept all forms because authors spell the
# precondition multiple ways).
_INT_LB_GUARD = re.compile(
    r"\b(?P<name>\w+)\s*(?:<=|<|==|!=|>=|>)\s*0\b"
)

# Pattern 34 — go.crypto.scalar_mult.identity_point_unchecked
# Body invokes `<curve>.ScalarMult(<x>, <y>, ...)` /
# `<curve>.ScalarBaseMult(...)` / `<curve>.Add(...)` against caller-
# supplied or unverified affine coordinates without first checking
# that the input point is on the curve and not the point-at-infinity.
# Mirrors Swival #028/#029/#034/#035/#066/#067/#073 cluster — secp /
# NIST curves over malformed (x=0, y=0) or sub-group order points
# silently leak structural invariants (key recovery on twist curves,
# small-subgroup attacks on insecure pairings).
#
# Predicate (body-local, single-function):
#   * fn body contains a `<x>.ScalarMult` / `<x>.ScalarBaseMult` /
#     `<x>.Add` / `<x>.Double` call;
#   * the same body does NOT contain `<x>.IsOnCurve(`,
#     `IsOnCurve(...)`, `IsInfinity(...)`, `IsIdentity(...)`,
#     `(<n> == 0 && <m> == 0)`-style identity check, or
#     `curve.Params().N`-bound check on the scalar.
#
# Strict over-approximation — false-positives on internal callers
# that have already validated the point upstream; M14-trap requires
# documented runtime PoC before any escalation.
_SCALAR_MULT_CALL = re.compile(
    # Only the strongly-curve-specific call shapes — `Add` and
    # `Double` are too common (math/big, time, atomic, prometheus
    # counters) and cause heavy noise; we restrict to ScalarMult-
    # family method names that are curve-only by convention. We
    # accept both the package-level invocation
    # (``btcec.ScalarMultNonConst``, used heavily in Spark) and the
    # method-style invocation (``curve.ScalarMult``).
    r"\b[A-Za-z_]\w*\s*\.\s*"
    r"(?:ScalarMult|ScalarBaseMult|ScalarMultBase|"
    r"ScalarMultNonConst|ScalarBaseMultNonConst)\s*\("
)
_CURVE_VALIDATION_GUARD = re.compile(
    r"\b(?:IsOnCurve|IsIdentity|IsInfinity|IsAtInfinity)\s*\(|"
    r"\b[A-Za-z_]\w*\s*\.\s*(?:IsOnCurve|IsIdentity|IsInfinity|IsAtInfinity)\s*\(|"
    r"\bcurve\s*\.\s*Params\s*\(\s*\)\s*\.\s*N\b"
)

# Pattern 35 — go.go.panic.dereference_before_nil_check
# Body reads a field on a pointer-typed parameter (`<param>.<Field>`)
# BEFORE any nil-check on `<param>` (`<param> == nil`,
# `<param> != nil`). Mirrors Swival #028/#029/#042/#074 — function
# accepts a `*Options` / `*Config` / `*Request` whose fields are
# read unconditionally; a nil caller (legitimate per Go's "zero
# value is valid" idiom for some types) panics.
#
# Predicate (body-local, single-function):
#   * fn params declare at least one pointer parameter `<param> *T`
#     (`*T` excluding `*<receiver>` self-types — pointer-receiver
#     methods deref `<recv>.<Field>` legitimately because the
#     receiver is non-nil for all reachable call sites within the
#     same package; we conservatively skip receiver-name dereferences);
#   * fn body contains `<param>.<Field>` somewhere;
#   * fn body does NOT contain `<param> == nil` or `<param> != nil`
#     BEFORE the dereference position.
_PTR_PARAM = re.compile(
    r"\b([A-Za-z_]\w*)\s+\*[A-Za-z_]\w[A-Za-z_0-9.]*\b"
)

# Pattern 36 — go.crypto.loop.untrusted_length_unbounded
# Body parses an untrusted length-prefix field (cryptobyte
# ``ReadASN1*`` integer / length readers, ``binary.BigEndian.Uint*``,
# ``strconv.ParseUint``, ``asn1.Unmarshal`` over an integer field) and
# subsequently uses the parsed value as the bound of an iteration
# (``for i := <init>; i < <length>; i++`` /
# ``for <length> > 0 { <length> -= n }`` /
# ``for j := 0; j < int(<length>); j++``) WITHOUT enforcing a static
# upper-bound cap (``<length> > <maxLen>`` / ``<length> >= <maxLen>``).
# Mirrors Swival #010 / #067 — RFC5280 explicit-length parser flaws +
# CVE-2025-22871-shape (length-prefixed protocol parser allocates a
# buffer sized by attacker-controlled length and pegs the goroutine).
#
# Predicate (body-local, single-function):
#   * fn body contains a parse-int-style assignment whose destination
#     name is ``<dst>`` (matches ``_PARSE_INT_CALL`` from #33), AND
#   * fn body contains a loop-bound use of ``<dst>`` (regex
#     ``_LOOP_BOUND_USE``: ``for ...; ... <dst>...`` /
#     ``for <dst> > 0`` / ``for j := 0; j < int(<dst>); ...``), AND
#   * fn body does NOT contain an upper-bound cap on ``<dst>`` —
#     specifically a ``<dst> > <ident-or-literal>`` / ``<dst> >= ...``
#     comparison (we exclude ``<dst> > 0`` / ``<dst> >= 0`` since those
#     are lower-bound guards, not upper-bound caps).
#
# Strict over-approx — we do not attempt to disambiguate the source of
# bytes (network vs DB vs config). Detector telemetry classification
# is the L20 framing default; CONFIRMED-CANDIDATE only with a runtime
# PoC of attacker-controlled length flowing into an unbounded loop.
_LOOP_BOUND_USE = re.compile(
    # Capture either:
    #   (a) `for ... ; <ident> <op> <length> ; <ident>++` — classic
    #       three-part for with `<length>` on the rhs of the
    #       comparison, OR
    #   (b) `for <length> > 0` — countdown loop, OR
    #   (c) `for <length> < <bound>` — just the rare init-counter
    #       loop where `<length>` itself is the iter var.
    # We accept any optional `int(...)` cast and tolerate
    # leading/trailing whitespace / parens.
    r"\bfor\b[^\n{]*?\b(?:[A-Za-z_]\w*\s*<\s*(?:int\s*\(\s*)?(?P<bound>[A-Za-z_]\w*)"
    r"|(?P<countdown>[A-Za-z_]\w*)\s*>\s*0\b)"
)
_INT_UB_CAP = re.compile(
    # Upper-bound cap on `<dst>`: `<dst> > <something-non-zero>` or
    # `<dst> >= <something>`. We explicitly EXCLUDE the lower-bound
    # comparisons (`<dst> > 0` / `<dst> >= 0`) because those are
    # rejection-of-zero guards — not upper-bound caps. The detector's
    # "missing cap" predicate must not be defused by a `>0` lower-bound
    # check.
    r"\b(?P<name>[A-Za-z_]\w*)\s*(?:>=?\s*(?!0\b))(?P<rhs>[A-Za-z_0-9.]+)"
)

# Pattern 37 — go.crypto.counter.wrap_unchecked
# Body increments a counter-shaped identifier (``seqNum`` / ``next`` /
# ``counter`` / ``nonce`` / ``index``) via ``++`` or ``+= 1`` inside a
# loop or hot-path, WITHOUT an overflow guard against
# ``math.MaxUint64`` / ``^uint64(0)`` / a documented modulus reset.
# Mirrors Swival #009 / #044 — counter wrap collides under heavy load
# (e.g. AES-GCM nonce reuse on per-message counters; gossip sequence
# replay on uint64 wrap).
#
# Predicate (body-local, single-function):
#   * fn body contains an increment statement on a counter-named
#     identifier matching ``_COUNTER_INC`` (``seqNum++`` /
#     ``s.counter += 1`` / ``atomic.AddUint64(&n.next, 1)``);
#   * fn body does NOT contain an overflow guard matching
#     ``_COUNTER_WRAP_GUARD`` (``math.MaxUint64`` / ``^uint64(0)`` /
#     ``^uint32(0)`` / a numeric ``2**63``-shaped literal that maps to
#     a documented wrap sentinel).
#
# Strict over-approx — many production counters are formally
# unbounded (Go's int64 wrap-around is a documented part of the type's
# semantics) and the predicate WILL fire on some legitimate counters.
# Detector telemetry classification per L20 framing.
_COUNTER_NAME = (
    r"(?:seqNum|seq_num|SeqNum|next|Next|counter|Counter|nonce|Nonce|"
    r"index|Index|seq|Seq)"
)
_COUNTER_INC = re.compile(
    # Matches:
    #   `seqNum++` / `s.SeqNum++` / `n.next += 1`
    #   `atomic.AddUint64(&<...>.<counter>, 1)`
    r"(?:"
    r"\b(?:[A-Za-z_]\w*\s*\.\s*)*" + _COUNTER_NAME + r"\s*(?:\+\+|\+=\s*1\b)"
    r"|"
    r"\batomic\s*\.\s*Add(?:Uint|Int)(?:32|64)\s*\(\s*&[^,]*\b"
    + _COUNTER_NAME + r"\b\s*,\s*1\s*\)"
    r")"
)
_COUNTER_WRAP_GUARD = re.compile(
    # Authors guard counter wrap by either:
    #   (a) explicit comparison against `math.MaxUint*` / `^uint*(0)`;
    #   (b) modulus reset using a constant (`% N`), implying the
    #       counter is intentionally bounded;
    #   (c) calling a `Reset` / `Rotate` method on the counter holder,
    #       implying renewal happens before wrap.
    r"\bmath\.MaxUint(?:8|16|32|64)\b|"
    r"\^uint(?:8|16|32|64)\s*\(\s*0\s*\)|"
    r"\bmath\.MaxInt(?:8|16|32|64)\b|"
    r"\b" + _COUNTER_NAME + r"\s*%\s*[A-Za-z_0-9]+|"
    r"\b(?:Reset|Rotate|Rewind|Rekey)\s*\("
)

# Pattern 38 — go.crypto.fips.approval_on_uninit
# Body calls a FIPS approval / validation helper
# (``<algo>.Approved(<hash>)`` / ``<algo>.Validate(<hash>)`` /
# ``fips.Approved(<x>)``) BEFORE checking that the hash / algorithm
# argument is initialised. The canonical sentinel for an uninitialised
# ``crypto.Hash`` value is ``crypto.Hash(0)`` (the zero value). When
# the approval check evaluates an uninitialised hash, the function
# returns "approved" for a path that has not actually been configured
# — a documented FIPS conformance hole.
# Mirrors Swival #075 — the Go stdlib FIPS approval gate accepted an
# uninitialised hash and reported it approved, letting non-FIPS code
# paths assert FIPS conformance.
#
# Predicate (body-local, single-function):
#   * fn body contains an approval call matching ``_FIPS_APPROVAL_CALL``
#     (``<x>.Approved(<arg>)`` / ``fips.Approved(<arg>)`` /
#     ``<x>.IsApproved(<arg>)`` / ``<x>.Validate(<arg>)`` where the
#     receiver / package name contains a fips/approve/algo token);
#   * fn body does NOT contain an uninit-sentinel guard
#     (``<arg> == crypto.Hash(0)`` /
#     ``<arg> == 0`` /
#     ``<arg> == nil`` /
#     ``IsZero(<arg>)``) BEFORE the approval call.
#
# Strict over-approx — the predicate fires on any approval call whose
# argument has not been zero-checked earlier in the body. Detector
# telemetry per L20 framing; CONFIRMED-CANDIDATE only when the
# argument is reachable from an attacker-controlled or
# default-initialised path.
_FIPS_APPROVAL_CALL = re.compile(
    # Match the call site shape `<recv>.<Approved|Validate|...>(<arg>)`
    # where `<recv>` contains a fips/approve/algo/hashes name token
    # (case-insensitive). We capture the argument identifier so the
    # uninit-sentinel guard search can target it.
    r"\b(?P<recv>[A-Za-z_]\w*(?:\s*\.\s*[A-Za-z_]\w*)*)\s*\.\s*"
    r"(?P<call>Approved|IsApproved|Validate|Allowed|IsAllowed)\s*\(\s*"
    r"(?P<arg>[A-Za-z_]\w*)\s*[,)]"
)
_FIPS_RECV_TOKEN = re.compile(
    r"(?i)\b(?:fips|approve|approval|algo|algorithm|hash|policy)"
)
_FIPS_UNINIT_GUARD_TPL = (
    # Composed at runtime per <arg>:
    #   `<arg> == crypto.Hash(0)` / `<arg> == 0` / `<arg> == nil` /
    #   `IsZero(<arg>)` / `<arg>.IsZero(`.
    r"\b{arg}\s*==\s*(?:crypto\.Hash\s*\(\s*0\s*\)|0\b|nil\b)|"
    r"\bIsZero\s*\(\s*{arg}\s*\)|"
    r"\b{arg}\s*\.\s*IsZero\s*\("
)

# Pattern 39 — go.crypto.race.unsynchronized_concurrent_access
# Body of an exported method on a pointer receiver assigns to a
# self-field (``r.X = ...`` / ``r.field += ...``) WITHOUT taking a
# lock or routing through ``atomic.*`` helpers. The assignment plus
# the missing synchronisation primitive together are the classic
# data-race shape — concurrent callers of the exported method
# observe torn writes / lost updates on the receiver.
# Mirrors Swival #008 / #022 / #027 — TLS / x509 wrappers mutating
# shared state inside an exported method without internal locking,
# leaving callers responsible for synchronisation that they don't
# always provide.
#
# Predicate (header-scoped, body-confirmed):
#   * method header matches ``func (<recv> *<Type>) <Name>(...)``
#     where ``<Name>`` is exported (PascalCase first char) and the
#     receiver is a pointer (``*<Type>``);
#   * body assigns to ``<recv>.<field>`` (``=``, ``+=``, ``-=``,
#     ``++``, ``--``) for at least one identifier;
#   * body does NOT contain ANY synchronisation primitive matching
#     ``_RACE_SYNC_PRIMITIVE`` (``<recv>.<lockfield>.Lock``,
#     ``<recv>.<lockfield>.RLock``, ``sync.Mutex`` declaration,
#     ``sync.RWMutex`` declaration, ``atomic.Store*`` /
#     ``atomic.Load*`` / ``atomic.Add*`` / ``atomic.Swap*`` /
#     ``atomic.CompareAndSwap*`` calls, channel send/recv).
#
# Strict over-approx — many exported methods on receivers that are
# documented as caller-synchronised will fire (e.g. ``(*Buffer).Write``
# ABI). Detector telemetry per L20 framing; CONFIRMED-CANDIDATE only
# with a runtime PoC of a concurrent reachable caller.
_METHOD_HEADER = re.compile(
    # ``func (<recv> *<Type>) <Name>(<params>) <ret> {``
    # Captures: recv (single ident), Type (no leading ``*``),
    # name (the method name, must start uppercase to count as
    # exported).
    r"^func\s*\(\s*(?P<recv>[A-Za-z_]\w*)\s+\*\s*(?P<type>[A-Za-z_]\w*)\s*\)"
    r"\s+(?P<name>[A-Z]\w*)\s*\(",
    re.MULTILINE,
)
# Composed at runtime per recv:
#   matches `<recv>.<field> = ...` / `<recv>.<field> += ...` /
#   `<recv>.<field>++` / `<recv>.<field>--`. We deliberately exclude
#   `<recv>.<x>.<y> = ...` since deeply-nested writes are usually
#   the responsibility of the inner type's exported API.
_RACE_SELF_WRITE_TPL = (
    r"\b{recv}\s*\.\s*(?P<field>[A-Za-z_]\w*)"
    r"\s*(?:=(?!=)|\+=|-=|\*=|/=|\^=|\|=|&=|<<=|>>=|\+\+|--)"
)
_RACE_SYNC_PRIMITIVE = re.compile(
    # Any sync primitive in the body (for the same receiver or
    # otherwise): a lock helper call, an atomic helper call, or a
    # channel op. We're permissive on which lock — the predicate
    # asks "is there ANY synchronisation in the body?" — accepting
    # documented hand-rolled patterns counts as defended.
    r"\.\s*R?Lock\s*\(|"
    r"\.\s*R?Unlock\s*\(|"
    r"\bsync\s*\.\s*(?:Mutex|RWMutex|Once|WaitGroup|Map)\b|"
    r"\batomic\s*\.\s*(?:Store|Load|Add|Swap|CompareAndSwap)\w*\b|"
    r"<-\s*[A-Za-z_]\w*|"
    r"[A-Za-z_]\w*\s*<-"
)

# Pattern 40 — go.crypto.skip_allowed.strict_lt_only
# Body validates a counter / nonce / sequence number with a STRICT
# less-than check (``<counter> < g.next``, ``seq < expected``)
# that allows monotonic skips: an attacker / faulty peer can jump
# the counter forward (``g.next = received_seq + 1``) and skip the
# guard for any future, never-seen value. The defended shape
# requires a paired equality check (``<counter> == g.next``) or a
# delta-bound check (``<counter> - g.next == 1``). Mirrors Swival
# #032 / #033 — TLS / DTLS sequence-number guards rejecting only
# replays (``<``) without rejecting jumps (``==``-pair / delta).
#
# Predicate (body-local, single-function):
#   * fn body contains a comparison ``<lhs> < <rhs>`` where AT
#     LEAST ONE side matches ``_COUNTER_NAME`` (``seq`` / ``next``
#     / ``counter`` / ``nonce`` / ``index`` / ``seqNum``);
#   * fn body does NOT contain a paired ``<lhs> == <rhs>`` /
#     ``<rhs> == <lhs>`` equality check between the same operands,
#     nor a delta-bound check (``<lhs> - <rhs>`` / ``<rhs> - <lhs>``
#     bounded against a small constant).
#
# Strict over-approx — many comparison sites are intentionally
# strict (e.g. log-level filters). Detector telemetry per L20
# framing; CONFIRMED-CANDIDATE only when the counter is the
# anti-replay invariant for a security boundary.
_SKIP_LT_CHECK = re.compile(
    # `<lhs> < <rhs>`. Captures both sides. We tolerate optional
    # leading receiver-dot chains (`s.next`, `g.next`).
    r"\b(?P<lhs>(?:[A-Za-z_]\w*\s*\.\s*)*[A-Za-z_]\w*)\s*<\s*"
    r"(?P<rhs>(?:[A-Za-z_]\w*\s*\.\s*)*[A-Za-z_]\w*)\b"
)
_SKIP_COUNTER_NAME = re.compile(
    # Counter-shaped name token (case-sensitive, with PascalCase).
    r"\b(?:seqNum|seq_num|SeqNum|next|Next|counter|Counter|"
    r"nonce|Nonce|index|Index|seq|Seq)\b"
)
# Composed at runtime per (lhs, rhs):
#   matches `<lhs> == <rhs>` / `<rhs> == <lhs>` / a delta check
#   `<lhs> - <rhs>` / `<rhs> - <lhs>`.
_SKIP_EQ_OR_DELTA_TPL = (
    r"\b{lhs}\s*==\s*{rhs}\b|"
    r"\b{rhs}\s*==\s*{lhs}\b|"
    r"\b{lhs}\s*-\s*{rhs}\b|"
    r"\b{rhs}\s*-\s*{lhs}\b"
)

# Pattern 41 — go.crypto.x509.suffix_match_no_dot_anchor
# Body uses ``strings.HasSuffix(addr, constraint)`` /
# ``strings.Contains(host, constraint)`` / a manual
# ``addr[len(addr)-len(c):] == c`` slice compare for a name-
# constraint check WITHOUT first anchoring the constraint with a
# leading ``.`` separator (``"." + constraint``) or bytewise
# checking ``addr[len(addr)-len(c)-1] == '.'`` to ensure the match
# is on a domain-label boundary. Without the dot anchor,
# ``HasSuffix("evilexample.com", "example.com")`` matches and an
# attacker registers ``evilexample.com`` to bypass a name
# constraint scoped to ``example.com``. Mirrors Swival #038 — Go
# crypto/x509 name-constraint match accepting label-prefix
# violations.
#
# Predicate (body-local, single-function):
#   * fn body contains a name-suffix check shape matching
#     ``_X509_SUFFIX_CALL`` (``strings.HasSuffix`` /
#     ``strings.HasPrefix``-on-reversed / a bytewise
#     ``addr[len(addr)-len(c):]`` slice compare);
#   * fn body does NOT contain a dot-anchor preparation matching
#     ``_X509_DOT_ANCHOR`` (``"." + constraint`` / a bytewise
#     ``addr[len(addr)-len(c)-1] == '.'`` / ``IDNA``-style helper).
#
# Strict over-approx — the predicate fires on any
# ``strings.HasSuffix`` invocation in a body that does not also
# contain the dot anchor token. Detector telemetry per L20
# framing; CONFIRMED-CANDIDATE only when the suffix check is the
# trust gate for a name-constraint enforcement layer.
_X509_SUFFIX_CALL = re.compile(
    # `strings.HasSuffix(<haystack>, <needle>)` /
    # `strings.HasPrefix(<haystack>, <needle>)` /
    # `bytes.HasSuffix(...)` / `bytes.HasPrefix(...)`. We capture
    # the needle so the dot-anchor search can target it.
    r"\b(?:strings|bytes)\s*\.\s*Has(?:Suffix|Prefix)\s*\(\s*"
    r"(?P<haystack>[A-Za-z_]\w*)\s*,\s*"
    r"(?P<needle>[A-Za-z_]\w*)\s*\)"
)
_X509_DOT_ANCHOR = re.compile(
    # Defensive shapes:
    #   `"." + needle` / `needle + "."`
    #   `'.', '.'` byte literal compare
    #   IDNA / publicsuffix / matchHostname style helpers
    #   Manual `addr[len(addr)-len(c)-1] == '.'` check.
    r'"\."\s*\+|\+\s*"\."|'
    r"'\.'|"
    r"\b(?:idna|publicsuffix|matchHostnames|matchExactly)\b|"
    r"\[\s*len\s*\([^)]*\)\s*-\s*len\s*\([^)]*\)\s*-\s*1\s*\]"
)


# ---------------------------------------------------------------------------
# Loop 24 ABM additions
#
# Pattern 42 — go.crypto.context_cancel.afterfunc_on_success
# Pattern 43 — go.crypto.kem.imported_key_skips_pairwise_consistency_test
# Pattern 39 stage-2 narrowing — extra.suspect_class classifier
# ---------------------------------------------------------------------------

# Pattern 42 — body installs ``stop := context.AfterFunc(ctx, func(){...})``
# whose closure releases a resource (Close / Cancel / Unregister) and then
# returns success WITHOUT cancelling the AfterFunc on the success path.
# Mirrors Swival #005.
#
# Capture forms:
#   1. ``stop := context.AfterFunc(ctx, ...)`` — explicit handle.
#   2. ``_ = context.AfterFunc(ctx, ...)`` — discarded handle (always
#      a leak / double-close hazard, fires unconditionally).
#   3. ``context.AfterFunc(ctx, ...)`` — bare expression-statement
#      (also fires; no handle to call).
_AFTERFUNC_CALL_NAMED = re.compile(
    # ``<name> := context.AfterFunc(`` — captures the binding name.
    r"\b(?P<name>[A-Za-z_]\w*)\s*:?=\s*context\s*\.\s*AfterFunc\s*\("
)
_AFTERFUNC_CALL_BARE = re.compile(
    # Catches the call regardless of binding form.
    r"\bcontext\s*\.\s*AfterFunc\s*\("
)
# Composed at runtime per binding name:
#   matches ``<name>()`` / ``defer <name>()`` / ``go <name>()``.
_AFTERFUNC_STOP_CALL_TPL = (
    r"\b{name}\s*\(\s*\)"
)

# Pattern 43 — body matches a KEM key-import / key-load / key-parse
# function and returns the parsed key WITHOUT performing a downstream
# pairwise consistency test (encap-then-decap or explicit pairwise
# helper). Mirrors Swival #026.
_KEM_IMPORT_FUNC_NAME = re.compile(
    # Function name shape: covers KEM-import / parse / load idioms.
    # We deliberately allow ``Unmarshal`` only when the name also
    # contains the ``KEM``/``Kyber``/``ML_KEM``/``ML-KEM`` token so
    # generic protobuf unmarshalers don't fire pattern 43.
    r"^(?:"
    r"Import(?:Private|PQ|KEM)\w*Key\w*|"
    r"Parse(?:KEM|MLKEM|ML_KEM|Kyber|HPKE|HKDF)\w*(?:Key|PrivateKey)?|"
    r"Load(?:KEM|MLKEM|ML_KEM|Kyber|HPKE)\w*(?:Key|PrivateKey)?|"
    r"NewKEM\w*FromBytes|"
    r"(?:KEM|MLKEM|ML_KEM|Kyber|HPKE)\w*Unmarshal\w*"
    r")$"
)
_KEM_PAIRWISE_CHECK = re.compile(
    # Cheap proxy for an in-body pairwise consistency test:
    # encap-then-decap (or named pairwise helper) by any of the common
    # names.
    r"\b(?:Encapsulate|Decapsulate|Encap|Decap|"
    r"PairwiseConsistency|PairwiseCheck|PairwiseSelfTest|"
    r"selfTest|pairwiseSelfTest|kemPairwise)\s*\("
)

# Pattern 39 stage-2 narrowing — classifier helpers for the
# ``extra.suspect_class`` annotation. The classifier looks at the
# method header + receiver type + file path to bucket each pattern-39
# hit. Default-suppressed buckets: ``unmarshaler`` (caller-synchronised
# by Go encoding/json contract pre-publish), ``ent_generated``
# (auto-generated single-flow caller code), ``setter`` (configuration
# / builder setters caller-synchronised by Go convention).
# Preserved bucket: ``genuine_concurrent`` — methods that aren't any
# of the above and DO write self-state without sync — these are the
# real signal class.
_RACE_CLS_UNMARSHALER_TYPE = re.compile(
    # Receiver-type or method-name signal that this is an
    # encoding/json (or other) Unmarshaler implementation.
    r"(?:JSON|Decoder|Unmarshaler|Codec|Encoder)$"
)
_RACE_CLS_UNMARSHALER_METHOD = re.compile(
    # Method name signals: ``UnmarshalX``, ``DecodeX``, ``UnmarshalJSON``,
    # ``ReadX``, ``Scan`` (sql.Scanner). These run pre-publish on
    # caller-controlled state and are caller-synchronised by Go
    # convention.
    r"^(?:Unmarshal|Decode|UnmarshalJSON|UnmarshalBinary|"
    r"UnmarshalText|UnmarshalYAML|UnmarshalProto|Scan)\w*$"
)
_RACE_CLS_ENT_PATH = re.compile(
    # File path signals an ent-generated package: any segment that is
    # ``ent`` (canonical), or any file matching the generated name
    # pattern (``*_generated.go`` / ``*_create.go`` / ``*_update.go``
    # / ``*_query.go`` / ``*_delete.go`` / ``*_mutation.go``).
    r"(?:^|/)ent/|"
    r"_generated\.go$|"
    r"(?:_create|_update|_query|_delete|_mutation|_client)\.go$"
)
_RACE_CLS_SETTER_METHOD = re.compile(
    # Method name signal: ``Set<X>`` / ``With<X>`` / single-arg
    # builder pattern. ent generated code uses Set heavily;
    # configuration objects also use Set.
    r"^(?:Set|With)[A-Z]\w*$"
)


# ---------------------------------------------------------------------------
# data classes
# ---------------------------------------------------------------------------

@dataclass
class Hit:
    file: str
    line: int
    snippet: str
    extra: dict = field(default_factory=dict)

    def to_json(self) -> dict:
        d = {"file": self.file, "line": self.line, "snippet": self.snippet}
        if self.extra:
            d["extra"] = self.extra
        return d


@dataclass
class GoFunction:
    name: str
    params: str
    start_line: int           # 1-indexed line of the `func` keyword
    body_start_line: int      # 1-indexed line of opening `{`
    body: str                 # raw text between the matching braces (exclusive)
    file: Path                # absolute path
    receiver: str = ""        # raw receiver clause, e.g. "msg *MsgClaimSpecific"

    @property
    def header(self) -> str:
        return f"func {self.name}({self.params})"


# ---------------------------------------------------------------------------
# Go function extraction (brace-balanced; no full AST)
# ---------------------------------------------------------------------------

def _balance_braces(src: str, start_idx: int) -> int | None:
    """Given index of an opening ``{``, return index just past matching ``}``.

    Skips string / rune / line-comment / block-comment contents. Returns
    ``None`` if no balancing brace is found (truncated source).
    """
    depth = 0
    i = start_idx
    n = len(src)
    in_str: str | None = None  # one of '"', '`', "'"
    in_line_comment = False
    in_block_comment = False
    while i < n:
        ch = src[i]
        nxt = src[i + 1] if i + 1 < n else ""
        if in_line_comment:
            if ch == "\n":
                in_line_comment = False
        elif in_block_comment:
            if ch == "*" and nxt == "/":
                in_block_comment = False
                i += 1
        elif in_str is not None:
            if ch == "\\" and in_str != "`":
                i += 1  # skip escaped char
            elif ch == in_str:
                in_str = None
        else:
            if ch == "/" and nxt == "/":
                in_line_comment = True
                i += 1
            elif ch == "/" and nxt == "*":
                in_block_comment = True
                i += 1
            elif ch in ("\"", "`", "'"):
                in_str = ch
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return i + 1
        i += 1
    return None


def _extract_functions(src: str, file: Path) -> list[GoFunction]:
    funcs: list[GoFunction] = []
    for m in _FUNC_HEADER.finditer(src):
        # find opening brace after the params, skipping return-type/whitespace
        brace_idx = src.find("{", m.end())
        if brace_idx < 0:
            continue
        end_idx = _balance_braces(src, brace_idx)
        if end_idx is None:
            continue
        body = src[brace_idx + 1:end_idx - 1]
        # 1-indexed line numbers
        start_line = src.count("\n", 0, m.start()) + 1
        body_start_line = src.count("\n", 0, brace_idx) + 1
        funcs.append(
            GoFunction(
                name=m.group("name"),
                params=m.group("params"),
                start_line=start_line,
                body_start_line=body_start_line,
                body=body,
                file=file,
                receiver=(m.group("recv") or "").strip(),
            )
        )
    return funcs


# ---------------------------------------------------------------------------
# detector predicates
# ---------------------------------------------------------------------------

PARAM_TXID_RE = re.compile(
    r"\b(?:txid|TxID|TxId|Txid|hash|Hash)[A-Za-z0-9_]*\b"
)


def _detect_txid_eq_no_spend(funcs: Iterable[GoFunction]) -> list[Hit]:
    hits: list[Hit] = []
    for fn in funcs:
        # Predicate: param list mentions a txid/hash-shaped name.
        if not PARAM_TXID_RE.search(fn.params):
            continue
        # Body must contain an equality compare against an attribute lookup
        # OR an ent-query field-membership/equality lookup over a Txid/Hash
        # field (``cooperativeexit.ExitTxidIn(...)``,
        # ``treenode.RawTxidEq(...)``, etc.).
        eq_match = (
            _TXID_EQ.search(fn.body)
            or _TXID_EQ_REV.search(fn.body)
            or _TXID_QUERY_CALL.search(fn.body)
        )
        if not eq_match:
            continue
        # Body must NOT contain a recognised spend/utxo verifier call.
        if _SPEND_VERIFIER.search(fn.body):
            continue
        # Compute line of the equality match for the snippet.
        body_off = eq_match.start()
        line_off = fn.body[:body_off].count("\n")
        snippet_line = fn.body_start_line + line_off
        snippet = fn.body.splitlines()[line_off].strip() if line_off < len(
            fn.body.splitlines()) else fn.header
        # Proto-enum dispatch suppression. If either side of the equality is
        # a generated proto enum constant (``pb.HashVariant_HASH_VARIANT_V2``
        # shape — package.Type_VARIANT with an ALL-CAPS variant tail), this
        # is enum-dispatch, not a missing-spend bug. See FP triage in
        # docs/next-loop/scan_go_proto_enum_fp_kill_2026-05-06.md.
        if _PROTO_ENUM_CONSTANT.search(snippet):
            continue
        hits.append(
            Hit(
                file=str(fn.file),
                line=snippet_line,
                snippet=snippet[:200],
                extra={"function": fn.name},
            )
        )
    return hits


def _detect_txid_without_vout_binding(funcs: Iterable[GoFunction]) -> list[Hit]:
    """Pattern go.bitcoin.txid_without_vout_outpoint_binding (Spark LEAD 1 family).

    Fires on a function that:
      1. Accepts a txid/hash-shaped parameter.
      2. Performs a txid equality/query match in the body.
      3. Does NOT also reference a vout/output-index token (the outpoint index).
      4. Does NOT call a recognised full-outpoint verifier.

    Negative control: a body that matches txid AND constrains vout/output-index
    (or calls a full-outpoint verifier) is NOT flagged - it correctly binds to
    the specific UTXO rather than just the parent transaction.

    This is the txid-vs-UTXO bug class: attacker satisfies a txid-only check
    with an unrelated transaction sharing only the txid while targeting a
    different output index (different UTXO).
    """
    hits: list[Hit] = []
    for fn in funcs:
        # Predicate 1: param list mentions a txid/hash-shaped name.
        if not PARAM_TXID_RE.search(fn.params):
            continue
        # Predicate 2: body contains a txid equality/query match.
        eq_match = (
            _TXID_EQ.search(fn.body)
            or _TXID_EQ_REV.search(fn.body)
            or _TXID_QUERY_CALL.search(fn.body)
        )
        if not eq_match:
            continue
        # Predicate 3 (negative): body also constrains vout / output-index.
        # If it does, this is a correct full-outpoint binding - do NOT flag.
        if _VOUT_BINDING.search(fn.body):
            continue
        # Predicate 4 (negative): body calls a recognised full-outpoint verifier.
        if _OUTPOINT_VERIFIER.search(fn.body):
            continue
        # Proto-enum dispatch suppression (same as pattern 1).
        body_off = eq_match.start()
        line_off = fn.body[:body_off].count("\n")
        snippet_line = fn.body_start_line + line_off
        snippet_lines = fn.body.splitlines()
        snippet = (
            snippet_lines[line_off].strip()
            if line_off < len(snippet_lines)
            else fn.header
        )
        if _PROTO_ENUM_CONSTANT.search(snippet):
            continue
        hits.append(
            Hit(
                file=str(fn.file),
                line=snippet_line,
                snippet=snippet[:200],
                extra={"function": fn.name},
            )
        )
    return hits


_LINE_COMMENT_RE = re.compile(r"//[^\n]*")
_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)


def _strip_comments(s: str) -> str:
    """Best-effort comment stripper for an if-block body. We don't try to
    handle string literals containing `//` perfectly — the regex would
    over-match if we did, but in practice this is enough to suppress the
    common ``// no return`` false-negative.
    """
    s = _BLOCK_COMMENT_RE.sub("", s)
    s = _LINE_COMMENT_RE.sub("", s)
    return s


def _detect_self_heal_unexpected_status(funcs: Iterable[GoFunction]) -> list[Hit]:
    hits: list[Hit] = []
    exit_re = re.compile(r"\b(?:return\b|panic\s*\(|continue\b|break\b)")
    for fn in funcs:
        # Find every `if <expr>.Status != <expr> {` block in the body.
        for m in _STATUS_NEQ.finditer(fn.body):
            # Walk back from match start to confirm an `if ` on this line.
            line_start = fn.body.rfind("\n", 0, m.start()) + 1
            line_text = fn.body[line_start:fn.body.find("\n", m.end())
                                if fn.body.find("\n", m.end()) >= 0
                                else len(fn.body)]
            if "if" not in line_text:
                continue
            brace_idx = fn.body.find("{", m.end())
            if brace_idx < 0:
                continue
            end_idx = _balance_braces(fn.body, brace_idx)
            if end_idx is None:
                continue
            block_raw = fn.body[brace_idx + 1:end_idx - 1]
            block = _strip_comments(block_raw)
            if not _WARN_LOGGER.search(block):
                continue
            if exit_re.search(block):
                continue
            line_off = fn.body[:m.start()].count("\n")
            hits.append(
                Hit(
                    file=str(fn.file),
                    line=fn.body_start_line + line_off,
                    snippet=line_text.strip()[:200],
                    extra={"function": fn.name},
                )
            )
    return hits


def _detect_protohash_kind_collision(funcs: Iterable[GoFunction]) -> list[Hit]:
    """Pattern 5 — protohash.Hash + multiple kind identifiers over the same arg.

    A body that mixes ``intIdentifier`` / ``uintIdentifier`` / ``enumIdentifier``
    over the *same* argument expression and then routes the result through
    ``protohash.Hash(...)`` will produce identical hashes when the descriptor
    field-kind silently changes between releases.
    """
    hits: list[Hit] = []
    for fn in funcs:
        if not _PROTOHASH_CALL.search(fn.body):
            continue
        # Collect (kind, arg) pairs.
        by_arg: dict[str, set[str]] = {}
        first_idx_for_arg: dict[str, int] = {}
        for m in _KIND_IDENT_CALL.finditer(fn.body):
            arg = m.group("arg").strip()
            kind = m.group("kind")
            by_arg.setdefault(arg, set()).add(kind)
            first_idx_for_arg.setdefault(arg, m.start())
        colliding = [a for a, ks in by_arg.items() if len(ks) >= 2]
        if not colliding:
            continue
        for arg in colliding:
            idx = first_idx_for_arg[arg]
            line_off = fn.body[:idx].count("\n")
            lines = fn.body.splitlines()
            snippet = lines[line_off].strip() if line_off < len(lines) else fn.header
            hits.append(
                Hit(
                    file=str(fn.file),
                    line=fn.body_start_line + line_off,
                    snippet=snippet[:200],
                    extra={
                        "function": fn.name,
                        "argument": arg,
                        "kinds": sorted(by_arg[arg]),
                    },
                )
            )
    return hits


# Set of names we treat as "gossip handler" in pattern 6.
_GOSSIP_HANDLER_PREFIXES = (
    "Gossip", "Broadcast", "HandleGossip", "OnGossip",
    "GossipMessage", "BroadcastMessage", "HandleBroadcast",
)


def _is_gossip_handler(fn: GoFunction) -> bool:
    if _GOSSIP_HANDLER_NAME.match(fn.name):
        return True
    # Also treat methods whose name starts with a gossip prefix as handlers.
    for pref in _GOSSIP_HANDLER_PREFIXES:
        if fn.name.startswith(pref):
            return True
    return False


def _detect_gossip_perimeter_trust(
    file_sources: dict[Path, str],
    funcs_by_file: dict[Path, list[GoFunction]],
) -> list[Hit]:
    """Pattern 6 — gRPC service + tls.NoClientCert + unsigned gossip handlers.

    A file-level predicate: the file must register a gRPC service AND opt
    into ``tls.NoClientCert``. Then we find any function whose name looks
    like a gossip / broadcast handler and check that body for a
    ``VerifySignature`` / ``VerifyECDSASignature`` / ``VerifySig`` call.
    Bodies missing such a call get flagged.
    """
    hits: list[Hit] = []
    for file_path, src in file_sources.items():
        if not _TLS_NO_CLIENT_CERT.search(src):
            continue
        if not _GRPC_REGISTER.search(src):
            continue
        for fn in funcs_by_file.get(file_path, []):
            if not _is_gossip_handler(fn):
                continue
            if _VERIFY_SIG_CALL.search(fn.body):
                continue
            hits.append(
                Hit(
                    file=str(fn.file),
                    line=fn.start_line,
                    snippet=fn.header[:200],
                    extra={
                        "function": fn.name,
                        "perimeter_marker": "tls.NoClientCert",
                    },
                )
            )
    return hits


def _detect_byte_reversed_lookup_set(funcs: Iterable[GoFunction]) -> list[Hit]:
    """Pattern 7 — same hash + reversed hash inserted into the same set/map.

    We require a ``slices.Reverse(x)`` call (or a manual byte-swap loop on
    ``x``) AND at least two assignments to the same map name where the
    keys differ and at least one references either the reversed value or
    the original ``x``.
    """
    hits: list[Hit] = []
    for fn in funcs:
        rev_match = _SLICES_REVERSE_CALL.search(fn.body) \
            or _MANUAL_REVERSE_LOOP.search(fn.body)
        if not rev_match:
            continue
        rev_arg = rev_match.group("arg")
        # Collect map[key] = ... assignments.
        map_assigns: dict[str, list[tuple[str, int]]] = {}
        for m in _MAP_ASSIGN.finditer(fn.body):
            map_name = m.group("name")
            key_expr = m.group("key").strip()
            map_assigns.setdefault(map_name, []).append((key_expr, m.start()))
        for map_name, entries in map_assigns.items():
            if len(entries) < 2:
                continue
            keys = {k for k, _ in entries}
            if len(keys) < 2:
                continue
            # At least one key must reference the reversed-base argument.
            if not any(rev_arg in k for k in keys):
                continue
            # And at least one OTHER key must reference something different
            # (typically a reversed alias / call result).
            idx = entries[0][1]
            line_off = fn.body[:idx].count("\n")
            lines = fn.body.splitlines()
            snippet = lines[line_off].strip() if line_off < len(lines) else fn.header
            hits.append(
                Hit(
                    file=str(fn.file),
                    line=fn.body_start_line + line_off,
                    snippet=snippet[:200],
                    extra={
                        "function": fn.name,
                        "map": map_name,
                        "reversed_arg": rev_arg,
                        "keys": sorted(keys),
                    },
                )
            )
    return hits


def _detect_cosmos_message_ordering_replay(funcs: Iterable[GoFunction]) -> list[Hit]:
    """Pattern 8 — Cosmos handler that unmarshals a Msg without sequence guard.

    Stage-1 predicate (high precision, low recall — we expect to miss many
    real bugs but produce few false positives):

      * function name matches Handle/Process/Execute/Deliver/Apply/Dispatch
        followed by a CamelCase suffix, OR appears on a MsgServer-like
        receiver (we approximate via param/header containing ``Msg``);
      * body calls ``proto.Unmarshal`` AND references a ``Msg`` type;
      * body does NOT mention any of: Sequence, nonce, Height, BlockHash,
        HeaderHash, TxIndex, BlockHeight, GetSequence, packet_sequence.
    """
    hits: list[Hit] = []
    for fn in funcs:
        name_ok = bool(_COSMOS_HANDLER_NAME.match(fn.name))
        if not name_ok:
            continue
        # Strip comments so commentary mentioning "sequence/nonce/etc." in
        # the body doesn't suppress the detection.
        body_no_comments = _strip_comments(fn.body)
        if not _PROTO_UNMARSHAL.search(body_no_comments):
            continue
        if not _MSG_TYPE_USE.search(body_no_comments):
            continue
        if _COSMOS_SEQ_GUARD.search(body_no_comments):
            continue
        # Heuristic: body must do something nontrivial (>5 lines) so we don't
        # flag tiny stub handlers in test fixtures.
        if fn.body.count("\n") < 3:
            continue
        # Use the unmarshal call as the snippet anchor.
        m = _PROTO_UNMARSHAL.search(fn.body)
        idx = m.start() if m else 0
        line_off = fn.body[:idx].count("\n")
        lines = fn.body.splitlines()
        snippet = lines[line_off].strip() if line_off < len(lines) else fn.header
        hits.append(
            Hit(
                file=str(fn.file),
                line=fn.body_start_line + line_off,
                snippet=snippet[:200],
                extra={"function": fn.name},
            )
        )
    return hits


def _detect_lightning_htlc_state_drift(funcs: Iterable[GoFunction]) -> list[Hit]:
    """Pattern 9 — HTLC success+timeout tokens in same body without cross-check.

    Stage-1 predicate:
      * function body references at least one HTLC success-path token AND
        at least one HTLC timeout-path token;
      * body does NOT contain any cross-check helper (require.Equal /
        assert.Equal / bytes.Equal / reflect.DeepEqual / CrossCheck /
        VerifyEquivalent / MustEqual).
    """
    hits: list[Hit] = []
    for fn in funcs:
        body_no_comments = _strip_comments(fn.body)
        succ = _HTLC_SUCCESS_TOKEN.search(body_no_comments)
        if not succ:
            continue
        tmo = _HTLC_TIMEOUT_TOKEN.search(body_no_comments)
        if not tmo:
            continue
        if _HTLC_CROSSCHECK.search(body_no_comments):
            continue
        # Anchor on whichever token comes first in the original body.
        succ_orig = _HTLC_SUCCESS_TOKEN.search(fn.body) or succ
        tmo_orig = _HTLC_TIMEOUT_TOKEN.search(fn.body) or tmo
        idx = min(succ_orig.start(), tmo_orig.start())
        succ, tmo = succ_orig, tmo_orig
        line_off = fn.body[:idx].count("\n")
        lines = fn.body.splitlines()
        snippet = lines[line_off].strip() if line_off < len(lines) else fn.header
        hits.append(
            Hit(
                file=str(fn.file),
                line=fn.body_start_line + line_off,
                snippet=snippet[:200],
                extra={
                    "function": fn.name,
                    "success_token": succ.group(0),
                    "timeout_token": tmo.group(0),
                },
            )
        )
    return hits


def _detect_frost_aggregate_pubkey_invariant(
    funcs: Iterable[GoFunction],
) -> list[Hit]:
    """Pattern 10 — share-rotation function mutates aggregate pubkey w/o recompute.

    Stage-1 predicate:
      * function name matches a participant-share rotation shape (Tweak /
        Rotate / Update / Refresh);
      * body assigns to a verifying_pubkey / VerifyingPubkey / VerifyingKey
        / AggregatePubkey / GroupPubkey field;
      * body does NOT call a group recompute op (.Add( / .Sub( / .Combine(
        / Aggregate( / Recompute / DeriveVerifyingKey / ComputeAggregate).
    """
    hits: list[Hit] = []
    for fn in funcs:
        if not _FROST_ROTATE_NAME.match(fn.name):
            continue
        body_no_comments = _strip_comments(fn.body)
        m_assign = _FROST_AGG_PUBKEY_ASSIGN.search(body_no_comments)
        if not m_assign:
            continue
        if _FROST_RECOMPUTE_OP.search(body_no_comments):
            continue
        # Anchor the snippet using the original body (with comments) for
        # readable line/text in the report.
        m_assign = _FROST_AGG_PUBKEY_ASSIGN.search(fn.body) or m_assign
        idx = m_assign.start()
        line_off = fn.body[:idx].count("\n")
        lines = fn.body.splitlines()
        snippet = lines[line_off].strip() if line_off < len(lines) else fn.header
        hits.append(
            Hit(
                file=str(fn.file),
                line=fn.body_start_line + line_off,
                snippet=snippet[:200],
                extra={"function": fn.name},
            )
        )
    return hits


def _detect_gas_price_zero_unchecked(funcs: Iterable[GoFunction]) -> list[Hit]:
    """Pattern 11 — division/modulo by gas-price-shaped identifier without zero guard.

    Stage-1 predicate (high precision):
      * function body contains a ``/`` or ``%`` whose RIGHT-hand operand
        is a gas-price-shaped identifier (``gasPrice`` / ``GasPrice`` /
        ``gas_price`` / ``gasFee`` / ``GasFee`` / ``gas_fee``);
      * function body does NOT contain a zero-guard against any
        gas-price-shaped identifier (``== 0``, ``<= 0``, ``> 0``,
        ``!= 0``, ``.IsZero()``, ``.Sign() == 0``).

    Mirrors solodit-55256 SEDA M-10: tally path divides by ``gasPrice``
    user can post as 0, panic halts validators.
    """
    hits: list[Hit] = []
    for fn in funcs:
        body_no_comments = _strip_comments(fn.body)
        m = _GAS_PRICE_DIVISION.search(body_no_comments)
        if not m:
            continue
        # Suppress: if the SAME body has a zero-guard for any gas-price token,
        # treat as defended. This is conservative — operators may have multiple
        # gas-price-shaped names, but a single guard is enough to clear the body.
        if _GAS_PRICE_ZERO_GUARD.search(body_no_comments):
            continue
        # Anchor on the original body for correct line number.
        m_orig = _GAS_PRICE_DIVISION.search(fn.body) or m
        idx = m_orig.start()
        line_off = fn.body[:idx].count("\n")
        lines = fn.body.splitlines()
        snippet = lines[line_off].strip() if line_off < len(lines) else fn.header
        hits.append(
            Hit(
                file=str(fn.file),
                line=fn.body_start_line + line_off,
                snippet=snippet[:200],
                extra={
                    "function": fn.name,
                    "divisor": m_orig.group("div"),
                    "operator": m_orig.group("op"),
                },
            )
        )
    return hits


def _detect_attacker_divisor_zero_unchecked(
    funcs: Iterable[GoFunction],
) -> list[Hit]:
    """G2 - division/modulo by an external-taint-shaped divisor FIELD with no
    zero-guard, positivity check, or top-level defer/recover, in a cosmos
    handler / abci / keeper context.  See module docstring entry 18.

    ADVISORY: this predicate is deliberately broader than Pattern 11 so it is
    only emitted behind ``AUDITOOR_G2_ATTACKER_DIVISOR_ZERO`` (see
    ``_emit_attacker_divisor_hypotheses``) with ``verdict="needs-fuzz"``.
    """
    hits: list[Hit] = []
    for fn in funcs:
        fpath = str(fn.file).replace("\\", "/")
        if _ADV_TEST_FILE.search(fpath) or _ADV_GENERATED_FILE.search(fpath):
            continue
        # CONTEXT gate (FP-guard): a cosmos handler / abci / keeper surface.
        in_ctx = (
            bool(_ADV_MODULE_PATH.search(fpath))
            or bool(_ADV_HANDLER_NAME.match(fn.name))
            or bool(_ADV_CTX_PARAM.search(fn.params))
        )
        if not in_ctx:
            continue
        body_nc = _strip_comments(fn.body)
        # A top-level defer/recover protects the whole function body.
        if _adv_has_top_level_defer(body_nc):
            continue
        seen_lines: set[int] = set()
        for rx in (_ADV_DIV_METHOD, _ADV_DIV_OP):
            for m in rx.finditer(body_nc):
                div = m.group("div")
                segs = [s.lower() for s in div.split(".")]
                # taint gate: at least one segment is taint-shaped.
                if not any(s in _ADV_TAINT_SEGMENTS for s in segs):
                    continue
                # dedup boundary: gas-price divisors are Pattern 11's.
                if _ADV_GASPRICE_SEG.search(div):
                    continue
                if _adv_divisor_guarded(body_nc, div):
                    continue
                # anchor the line via the original (un-stripped) body.
                frag = m.group(0)
                idx = fn.body.find(frag)
                if idx < 0:
                    idx = 0
                line_off = fn.body[:idx].count("\n")
                line = fn.body_start_line + line_off
                if line in seen_lines:
                    continue
                seen_lines.add(line)
                lines = fn.body.splitlines()
                snippet = (
                    lines[line_off].strip()
                    if line_off < len(lines) else fn.header
                )
                hits.append(
                    Hit(
                        file=str(fn.file),
                        line=line,
                        snippet=snippet[:200],
                        extra={
                            "function": fn.name,
                            "divisor": div,
                            "operator": m.group("op"),
                        },
                    )
                )
    return hits


def _emit_attacker_divisor_hypotheses(
    workspace: Path,
    funcs: Iterable[GoFunction],
    gas_price_hits: Iterable[Hit],
    *,
    out_path: Path | None = None,
) -> tuple[list[dict], Path]:
    """Advisory G2 lane emitter.  Returns ``(records, out_path)`` and writes a
    ``needs-fuzz`` hypotheses jsonl.  De-dups emitted hits against Pattern 11
    (``gas_price_zero_unchecked``) by ``(file,line)`` (A1 dedup boundary: we
    do NOT re-derive a ``covered_by`` signal, we diff emitted hits against the
    named existing detector's hits).  NO auto-credit: every record carries
    ``verdict="needs-fuzz"``.
    """
    hits = _detect_attacker_divisor_zero_unchecked(funcs)
    gp_keys = {(h.file, h.line) for h in gas_price_hits}
    records: list[dict] = []
    for h in hits:
        if (h.file, h.line) in gp_keys:
            continue  # already covered by Pattern 11
        records.append({
            "workspace": str(workspace),
            "file": h.file,
            "line": h.line,
            "function": h.extra.get("function"),
            "divisor": h.extra.get("divisor"),
            "operator": h.extra.get("operator"),
            "snippet": h.snippet,
            "pattern_id": G2_ATTACKER_DIVISOR_PID,
            "attack_class": "divide-by-zero-chain-halt",
            "source": "G2",
            "verdict": "needs-fuzz",
        })
    out = (
        Path(out_path) if out_path
        else workspace / ".auditooor" / G2_ATTACKER_DIVISOR_OUT
    )
    out.parent.mkdir(parents=True, exist_ok=True)
    text = "".join(json.dumps(r, sort_keys=True) + "\n" for r in records)
    out.write_text(text, encoding="utf-8")
    return records, out


def _detect_vote_extension_unverified(funcs: Iterable[GoFunction]) -> list[Hit]:
    """Pattern 12 — vote-extension iteration + power totaling w/o verification.

    Stage-1 predicate (high precision, low recall):
      * body has a ``for`` loop over a vote-extension / extended-commit-info
        collection;
      * body accumulates voting power into a total-shaped variable
        (``totalVP`` / ``totalVotingPower`` / ``sumPower`` / ``totalPower``);
      * body does NOT call ``ValidateVoteExtensions`` AND does NOT call any
        per-VE signature verifier (``bls.Verify`` / ``ed25519.Verify`` /
        ``VerifySignature`` / ``VerifyVoteExtension`` / etc.).

    Mirrors solodit-47220 OtterSec Ethos: trusting proposer-supplied VE
    metadata when computing totalVP skews consensus weights.
    """
    hits: list[Hit] = []
    for fn in funcs:
        body_no_comments = _strip_comments(fn.body)
        ve_iter = _VE_ITER.search(body_no_comments)
        if not ve_iter:
            continue
        acc_match = _VE_TOTAL_ACC.search(body_no_comments)
        if not acc_match:
            continue
        if _VE_VALIDATE_CALL.search(body_no_comments):
            continue
        if _VE_VERIFY_SIG.search(body_no_comments):
            continue
        # Anchor on the iteration line in the original body.
        m_iter_orig = _VE_ITER.search(fn.body) or ve_iter
        idx = m_iter_orig.start()
        line_off = fn.body[:idx].count("\n")
        lines = fn.body.splitlines()
        snippet = lines[line_off].strip() if line_off < len(lines) else fn.header
        hits.append(
            Hit(
                file=str(fn.file),
                line=fn.body_start_line + line_off,
                snippet=snippet[:200],
                extra={
                    "function": fn.name,
                    "accumulator": acc_match.group("acc"),
                },
            )
        )
    return hits


def _detect_tree_node_terminal_state_revival(
    funcs: Iterable[GoFunction],
) -> list[Hit]:
    """Pattern 13 — tree-node terminal-state revival (SP-3049 / LEAD H-D
    write-side mirror).

    Fires on any function whose body advances a tree-node row to
    ``TreeNodeStatusAvailable`` (either by direct field-assign or via the
    ent-builder ``.SetStatus(...)`` shape) WITHOUT first calling the
    canonical guard ``CanBecomeAvailable()`` /
    ``TreeNodeCanBecomeAvailable(...)`` AND without an explicit hand-rolled
    compare against any of the five terminal status constants
    (``TreeNodeStatusSplitted`` / ``TreeNodeStatusOnChain`` /
    ``TreeNodeStatusExited`` / ``TreeNodeStatusParentExited`` /
    ``TreeNodeStatusReimbursed``).

    Test files (``*_test.go``) are skipped — the SP-3049 commit explicitly
    sets terminal statuses in setup helpers (e.g. forcing a leaf to
    ``EXITED`` to reproduce the bug); flagging them is noise.

    Stage-1 form mirrors the structure of pattern 3
    (``go.statemachine.guard_only_on_one_path``) but on the WRITE side: the
    earlier detector flags missing read-side leaf-status guards in the
    claim path; this one flags missing write-side terminal guards in tree
    mutation paths. A pattern fire on a Spark file BEYOND the SP-3049 diff
    scope (i.e. a tree-node mutation in a file/function that the SP-3049
    fix did NOT touch) is a candidate write-side regression: the ent-hook
    layer added by SP-3049 catches all such mutations at the storage
    boundary, but a hand-rolled compatible guard at the call-site is the
    SP-3049 author's pattern, and a hit here means the call-site is
    relying entirely on the ent-hook (no defense-in-depth).
    """
    hits: list[Hit] = []
    for fn in funcs:
        # Skip Go test files outright — terminal statuses are forced in
        # setup helpers as part of regression test scaffolding.
        if str(fn.file).endswith("_test.go"):
            continue
        assign = _TREENODE_AVAILABLE_ASSIGN.search(fn.body)
        setstatus = _TREENODE_AVAILABLE_SETSTATUS.search(fn.body)
        if not assign and not setstatus:
            continue
        # Either guard form acceptable: CanBecomeAvailable() call OR an
        # explicit compare against any of the five terminal status
        # constants. Either appearing anywhere in the body is enough; we
        # don't insist on a specific control-flow ordering at stage-1.
        if _TREENODE_TERMINAL_GUARD_CALL.search(fn.body):
            continue
        if _TREENODE_TERMINAL_COMPARE.search(fn.body):
            continue
        # Compute snippet line at the FIRST mutation site (earliest of the
        # two candidate matches).
        candidates = [m for m in (assign, setstatus) if m is not None]
        first = min(candidates, key=lambda m: m.start())
        line_off = fn.body[:first.start()].count("\n")
        lines = fn.body.splitlines()
        snippet = lines[line_off].strip() if line_off < len(lines) else fn.header
        hits.append(
            Hit(
                file=str(fn.file),
                line=fn.body_start_line + line_off,
                snippet=snippet[:200],
                extra={
                    "function": fn.name,
                    "mutation_form": (
                        "set_status_builder" if setstatus and (not assign or setstatus.start() <= assign.start())
                        else "field_assign"
                    ),
                },
            )
        )
    return hits


def _detect_coop_exit_coordinator_guard_asymmetry(
    file_sources: dict[Path, str],
    funcs_by_file: dict[Path, list[GoFunction]],
) -> list[Hit]:
    """Pattern 13 — coop-exit coordinator confirmation-guard asymmetry.

    Cross-function (per-package) detector. Models the SP-2961 (LEAD 1)
    structural shape:

      * The coop-exit confirmation guard helper
        ``checkCoopExitTxBroadcasted`` exists in the package — either as
        a top-level def (``func checkCoopExitTxBroadcasted(...)``) or as
        a call site in any sibling file. Either is enough to mark the
        package as coop-exit-aware.
      * The function under inspection has a body that touches a
        coop-exit-eligible transfer in a pre-finalize state (any of the
        ``TransferStatusReceiverRefundSigned`` / ``Sender(Receiver)
        KeyTweak*`` / ``CooperativeExit`` / ``CoopExit*Tx`` tokens) OR
        performs a downstream-terminal status update via the ent builder
        (``.SetStatus(... TransferStatus*)``).
      * The function body does NOT call the guard helper.
      * The function name is NOT itself the guard (we don't flag the
        guard def).
      * The function does NOT delegate via ``verifyAndUpdateTransfer(``
        (post-fix tree carries the guard internally on that callee).
      * Test files (``*_test.go``) are skipped — regression scaffolding
        often forces ReceiverRefundSigned to assert the guard fails.

    Hits are recorded against the unguarded function. Each hit's
    ``extra.predicate_arm`` is ``"package_coop_exit_guard"``.
    """
    hits: list[Hit] = []
    # Bucket per package directory.
    by_pkg: dict[Path, list[tuple[Path, str, list[GoFunction]]]] = {}
    for file_path, src in file_sources.items():
        pkg_dir = file_path.parent
        funcs_here = funcs_by_file.get(file_path, [])
        by_pkg.setdefault(pkg_dir, []).append((file_path, src, funcs_here))

    for pkg_dir, entries in by_pkg.items():
        # Determine if this package is coop-exit-aware: either a guard def
        # or a guard call exists in ANY file in the package.
        guard_present = False
        for _, src, _ in entries:
            if _COOP_EXIT_GUARD_DEF.search(src) or _COOP_EXIT_GUARD_CALL.search(src):
                guard_present = True
                break
        if not guard_present:
            continue
        # Walk all functions in this package.
        for file_path, _src, funcs_here in entries:
            if str(file_path).endswith("_test.go"):
                continue
            for fn in funcs_here:
                # Skip the guard-helper definition itself.
                fn_name_lower = fn.name.lower()
                if (
                    "coopexit" in fn_name_lower
                    and "broadcast" in fn_name_lower
                    and fn_name_lower.startswith("check")
                ):
                    continue
                # Strip comments before predicate evaluation so a comment
                # like ``// Missing: checkCoopExitTxBroadcasted(...)`` is
                # NOT treated as the actual guard call.
                body_no_comments = _strip_comments(fn.body)
                # Trigger: pre-finalize sentinel OR downstream-terminal
                # status update via ent builder. Either qualifies the
                # function as a coop-exit-eligible mutation site.
                pref_match = _COOP_EXIT_PREFINALIZE_TOKEN.search(body_no_comments)
                term_match = _COOP_EXIT_TERMINAL_UPDATE.search(body_no_comments)
                if not (pref_match or term_match):
                    continue
                # Selectivity: skip trivial loader/factory helpers whose
                # body merely struct-initializes a Transfer with the
                # sentinel token. Require the body to either (a) compare
                # or assert ``.Status`` directly OR (b) call ``.SetStatus(``
                # OR (c) reference ``checkCoopExitTxBroadcasted`` as a
                # commented-out missing-call (which would be filtered
                # below anyway). This collapses the FP rate on tiny
                # struct-literal helpers (e.g. test fixtures' factories).
                has_status_use = (
                    re.search(r"\.Status\s*(?:==|!=|=|<|>)", body_no_comments) is not None
                    or ".SetStatus(" in body_no_comments
                    or ".Update(" in body_no_comments
                )
                if not has_status_use:
                    continue
                # Suppression: body calls the guard helper directly
                # (post-strip so comments don't trigger false suppression).
                if _COOP_EXIT_GUARD_CALL.search(body_no_comments):
                    continue
                # Suppression: body delegates via verifyAndUpdateTransfer
                # (which on the post-fix tree carries the guard).
                if _COOP_EXIT_DELEGATE.search(body_no_comments):
                    continue
                # Anchor matches in the ORIGINAL body for snippet/line.
                # Re-run the search; if the original-body match is
                # missing (would only happen if the trigger is solely
                # in a comment, which we'd want to ignore), fall back to
                # body_no_comments offset.
                pref_match = _COOP_EXIT_PREFINALIZE_TOKEN.search(fn.body) or pref_match
                term_match = _COOP_EXIT_TERMINAL_UPDATE.search(fn.body) or term_match
                # Compute snippet anchor at the earliest trigger.
                candidates = [m for m in (pref_match, term_match) if m is not None]
                first = min(candidates, key=lambda m: m.start())
                line_off = fn.body[:first.start()].count("\n")
                lines = fn.body.splitlines()
                snippet = (
                    lines[line_off].strip()
                    if line_off < len(lines)
                    else fn.header
                )
                hits.append(
                    Hit(
                        file=str(fn.file),
                        line=fn.body_start_line + line_off,
                        snippet=snippet[:200],
                        extra={
                            "function": fn.name,
                            "trigger_token": first.group(0)[:80],
                            "package_dir": str(pkg_dir),
                            "predicate_arm": "package_coop_exit_guard",
                        },
                    )
                )
    return hits


def _detect_coop_exit_key_tweak_resumability(
    funcs: Iterable[GoFunction],
    file_sources: dict[Path, str],
) -> list[Hit]:
    """Pattern 14 — coop-exit key-tweak resumability (SP-2988).

    Stage-1 predicate (high precision, low recall):
      * skip Go test files (``*_test.go``);
      * function body iterates over a per-leaf coop-exit collection
        (``transferLeaves`` / ``coopExits`` / ``pendingCoopExits`` / etc.);
      * function body contains at least one coop-exit / key-tweak DOMAIN
        token (``CoopExit`` / ``KeyTweak`` / ``TransferLeaf`` / etc.) — this
        keeps the predicate from firing on unrelated leaf-iteration loops;
      * function body mutates per-iteration row state via an ent-style
        write call (``ClearKeyTweak`` / ``.Update().Save(ctx)`` /
        ``SetStatus(<KeyTweak|CoopExit>...)`` / ``.Update().Exec(ctx)``);
      * function body does NOT contain an in-loop ``continue`` keyed off a
        sentinel field (``KeyTweak == nil`` / ``len(KeyTweak) == 0`` /
        ``Status == <terminal>`` / etc.);
      * the host file does NOT register a startup-resume handler
        (``RegisterResumeHandler`` / ``OnStartup`` / etc.).
    """
    hits: list[Hit] = []
    # Pre-compute file-level resume-handler registration markers.
    file_has_resume_handler: dict[Path, bool] = {
        p: bool(_COOP_EXIT_RESUME_FILE_REGISTRATION.search(src))
        for p, src in file_sources.items()
    }
    for fn in funcs:
        # Skip Go test files outright.
        if str(fn.file).endswith("_test.go"):
            continue
        body_no_comments = _strip_comments(fn.body)
        # Loop header over a recognised coop-exit collection.
        loop_match = None
        for m in _COOP_EXIT_LEAF_LOOP.finditer(body_no_comments):
            if _COOP_EXIT_LEAF_COLL_NAME.match(m.group("coll")):
                loop_match = m
                break
        if not loop_match:
            continue
        # Domain filter: must mention a coop-exit / key-tweak token.
        if not _COOP_EXIT_DOMAIN_TOKEN.search(body_no_comments):
            continue
        # Per-iteration row mutation.
        if not _COOP_EXIT_KEY_TWEAK_MUTATION.search(body_no_comments):
            continue
        # In-loop resumability guard suppresses the hit.
        if _COOP_EXIT_RESUME_GUARD_CONTINUE.search(body_no_comments):
            continue
        # File-level resume-handler registration suppresses the hit.
        if file_has_resume_handler.get(fn.file, False):
            continue
        # Anchor on the loop header in the original (with-comments) body so
        # the line number matches the source.
        loop_orig = _COOP_EXIT_LEAF_LOOP.search(fn.body) or loop_match
        idx = loop_orig.start()
        line_off = fn.body[:idx].count("\n")
        lines = fn.body.splitlines()
        snippet = lines[line_off].strip() if line_off < len(lines) else fn.header
        coll_name = loop_match.group("coll")
        hits.append(
            Hit(
                file=str(fn.file),
                line=fn.body_start_line + line_off,
                snippet=snippet[:200],
                extra={
                    "function": fn.name,
                    "collection": coll_name,
                },
            )
        )
    return hits


def _detect_guard_only_on_one_path(
    funcs: list[GoFunction],
    guard_names: tuple[str, ...],
) -> list[Hit]:
    """Group functions by file (default arm) AND by package directory
    (sharpened arm); flag where:

    Default arm — file-local default-guard-name list:
      * at least one function in the file calls a known guard (default list
        + operator additions via --guard-name), AND
      * at least one OTHER function in the same file mutates ``.Status``
        but does NOT call any guard.

    Sharpened arm — package-wide project-specific-guard discovery:
      * a function whose name matches ``^(validate|enforce|check|assert)[A-Z]``
        exists in the package (the package = the parent directory of the
        source file), AND
      * that guard is called from at least 1 sibling in the same package,
        AND
      * at least 2 OTHER public-method status-mutating siblings in the
        package take a ``*...Request``-shaped parameter (gRPC handler
        shape) and do NOT call the guard.

    The sharpened arm catches the LEAD H-D mechanism in
    ``so/handler/transfer_handler.go`` where ``validateTransferLeavesNotExitedToL1``
    lives in ``base_transfer_handler.go`` (same package, different file)
    and is missing from 4 receiver-claim handlers.

    Hits are recorded against each status-mutating function "missing" the
    guard. Each hit's ``extra.predicate_arm`` field is ``"file_default"``
    or ``"package_project_guard"`` so triage can split arms.
    """
    hits: list[Hit] = []

    # ------------------------- Default arm (per-file) ------------------------
    by_file: dict[Path, list[GoFunction]] = {}
    for fn in funcs:
        by_file.setdefault(fn.file, []).append(fn)

    guard_call_re = re.compile(
        r"\b(?:" + "|".join(re.escape(g) for g in guard_names) + r")\s*\("
    )

    seen_keys: set[tuple[str, str]] = set()

    for file_path, file_funcs in by_file.items():
        guarded: list[GoFunction] = []
        unguarded_mutators: list[GoFunction] = []
        for fn in file_funcs:
            calls_guard = bool(guard_call_re.search(fn.body))
            mutates = any(m in fn.body for m in _STATUS_MUTATION_MARKERS)
            if calls_guard:
                guarded.append(fn)
            elif mutates:
                unguarded_mutators.append(fn)
        if guarded and unguarded_mutators:
            for fn in unguarded_mutators:
                key = (str(fn.file), fn.name)
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                hits.append(
                    Hit(
                        file=str(fn.file),
                        line=fn.start_line,
                        snippet=fn.header[:200],
                        extra={
                            "function": fn.name,
                            "guarded_siblings": [g.name for g in guarded],
                            "predicate_arm": "file_default",
                        },
                    )
                )

    # ----------------- Sharpened arm (per-package, project guards) ------------
    # Group by package directory (the parent of the source file). When the
    # runner is invoked with relative paths, parent="" => single-bucket;
    # this matches the existing per-package convention used by Go.
    by_pkg: dict[Path, list[GoFunction]] = {}
    for fn in funcs:
        pkg_dir = fn.file.parent
        by_pkg.setdefault(pkg_dir, []).append(fn)

    for pkg_dir, pkg_funcs in by_pkg.items():
        # 1. Discover project-specific guards present in this package.
        project_guards: list[GoFunction] = [
            fn for fn in pkg_funcs if _PROJECT_GUARD_NAME.match(fn.name)
        ]
        if not project_guards:
            continue
        # 2. Identify gRPC-handler-shaped, status-mutating, public-method
        #    siblings up front. The per-guard arm only fires when MULTIPLE
        #    such siblings exist (otherwise selectivity collapses).
        grpc_handlers: list[GoFunction] = [
            fn for fn in pkg_funcs
            if fn.name and fn.name[0].isupper()
            and _GRPC_REQUEST_PARAM.search(fn.params)
            and any(m in fn.body for m in _STATUS_MUTATION_MARKERS)
        ]
        if len(grpc_handlers) < 2:
            continue
        # 3. Per-guard: flag handlers that don't call THIS guard, provided
        #    at least one in-package sibling DOES call it. Per-guard
        #    iteration (rather than "calls ANY guard") is what catches the
        #    LEAD H-D shape: ClaimTransfer calls checkTransferAccess* but
        #    is still missing validateTransferLeavesNotExitedToL1.
        for guard in project_guards:
            call_re = re.compile(rf"\b{re.escape(guard.name)}\s*\(")
            # at least one sibling calls the guard
            callers = [
                fn for fn in pkg_funcs
                if fn is not guard and call_re.search(fn.body)
            ]
            if not callers:
                continue
            unguarded = [fn for fn in grpc_handlers if not call_re.search(fn.body)]
            # Require at least 2 unguarded siblings AND at least one
            # CALLER that is itself a public, *Request-shaped, status-
            # mutating sibling — i.e. the guard is part of the handler
            # contract, not just a private helper. This kills the
            # "guard called only from a single private helper" FP.
            handler_callers = [
                fn for fn in callers
                if fn.name and fn.name[0].isupper()
                and _GRPC_REQUEST_PARAM.search(fn.params)
                and any(m in fn.body for m in _STATUS_MUTATION_MARKERS)
            ]
            if not handler_callers or len(unguarded) < 2:
                continue
            for fn in unguarded:
                key = (str(fn.file), fn.name)
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                hits.append(
                    Hit(
                        file=str(fn.file),
                        line=fn.start_line,
                        snippet=fn.header[:200],
                        extra={
                            "function": fn.name,
                            "missing_guard": guard.name,
                            "guarded_siblings": sorted({c.name for c in handler_callers})[:5],
                            "predicate_arm": "package_project_guard",
                            "package_dir": str(pkg_dir),
                        },
                    )
                )
    return hits


# ---------------------------------------------------------------------------
# Pattern 15 detector — req-identity passed to validator without DB-sourced
# identity reconciliation.
# ---------------------------------------------------------------------------


def _detect_signed_payload_req_identity_validator(
    funcs: Iterable[GoFunction],
) -> list[Hit]:
    """Pattern 15 — request-supplied identity reaches Validate*Package
    without prior DB-sourced identity comparison.

    Stage-1 predicate (high precision, low recall):
      * skip ``*_test.go`` files;
      * function body extracts a request-supplied identity public key
        (``req.<*>IdentityPublicKey`` or ``keys.ParsePublicKey(req...)``);
      * function body calls a Validate*Package / Verify*Signature /
        Validate*Identity-shaped helper;
      * function body mentions a signed-payload domain token
        (TransferPackage / ClaimPackage / SettlePackage / SignedPayload /
        UserSignature / claimSignature) — keeps the predicate from
        firing on unrelated identity-passthrough utilities;
      * function body does NOT contain a DB-sourced identity read
        (mimo.GetSingleTransferSender / QuerySender* / QueryOwner* /
        SenderIdentityPublicKey / etc.) AND does NOT contain a
        request-vs-DB equality compare (``Equals(`` between two
        identity-shaped variables, or ``bytes.Equal`` over identity
        fields).

    Mirrors SP-5998 (``6daafae89b`` on ``buildonspark/spark``) — pre-fix
    ``FinalizeTransferWithTransferPackage`` passed
    ``req.OwnerIdentityPublicKey`` straight to ``ValidateTransferPackage``
    where the signature verification then trusted the caller's claimed
    identity rather than the DB-stored sender identity. Although three
    layers of defense gated exploitation, the pattern is structurally a
    defense-in-depth gap and is derivable as a hygiene scan.
    """
    hits: list[Hit] = []
    for fn in funcs:
        if str(fn.file).endswith("_test.go"):
            continue
        body_no_comments = _strip_comments(fn.body)
        # (a) request-supplied identity must be extracted in the body.
        req_match = _REQ_IDENTITY_EXTRACT.search(body_no_comments)
        if not req_match:
            continue
        # (b) a Validate-shaped call must appear in the body.
        validate_match = _VALIDATE_PACKAGE_CALL.search(body_no_comments)
        if not validate_match:
            continue
        # (c) signed-payload domain token must appear (selectivity).
        if not _SIGNED_PAYLOAD_TOKEN.search(body_no_comments):
            continue
        # (d) suppress if a DB-sourced identity read exists OR a
        # request-vs-DB equality compare is present.
        if _DB_IDENTITY_READ.search(body_no_comments):
            continue
        if _REQ_DB_IDENTITY_COMPARE.search(body_no_comments):
            continue
        # Anchor on the validator call line in the original body so the
        # snippet shows the suspect call site, not the req-extract.
        validate_orig = _VALIDATE_PACKAGE_CALL.search(fn.body) or validate_match
        idx = validate_orig.start()
        line_off = fn.body[:idx].count("\n")
        lines = fn.body.splitlines()
        snippet = lines[line_off].strip() if line_off < len(lines) else fn.header
        hits.append(
            Hit(
                file=str(fn.file),
                line=fn.body_start_line + line_off,
                snippet=snippet[:200],
                extra={
                    "function": fn.name,
                    "validator_call": validate_orig.group(0)[:80],
                },
            )
        )
    return hits


# ---------------------------------------------------------------------------
# Pattern 16 detector — coordinator-package decrypt without prior-phase
# commit gate.
# ---------------------------------------------------------------------------


def _detect_retry_prior_phase_commit_check(
    funcs: Iterable[GoFunction],
) -> list[Hit]:
    """Pattern 16 — coordinator-portion key-tweak package decrypt without
    a prior-phase commit gate.

    Stage-1 predicate:
      * skip ``*_test.go`` files;
      * function body extracts the coordinator-portion of the key-tweak
        package (``KeyTweakPackage[h.config.Identifier]`` /
        ``EncryptedKeyTweakPackage[...config.Identifier]`` /
        ``encryptedKeyTweakPackage[Identifier]``);
      * function body decrypts the extracted coordinator portion
        (``eciesgo.Decrypt`` / ``ecies.Decrypt`` / ``proto.Unmarshal`` over
        the decrypted bytes);
      * function body does NOT contain a prior-phase-commit guard:
        no sentinel variable (``useStoredKeyTweaks`` / ``alreadyLocked`` /
        ``skipPackageDecryption`` / ``isPhase1Committed``) AND no compare
        of ``transfer.Status`` / ``receiver.Status`` against any of the
        ``ReceiverKeyTweak*`` / ``KeyTweakLocked`` / ``ReceiverRefundSigned``
        canonical "prior phase already committed" sentinel constants.

    Mirrors SP-5498 (``f26284dd5f`` on ``buildonspark/spark``) — pre-fix
    ``claim_transfer`` decrypted the fresh caller package even on retry,
    diverging coordinator extracts from SO-stored material when an SO
    had already locked Phase 1.
    """
    hits: list[Hit] = []
    for fn in funcs:
        if str(fn.file).endswith("_test.go"):
            continue
        body_no_comments = _strip_comments(fn.body)
        coord_match = _COORD_PORTION_EXTRACT.search(body_no_comments)
        if not coord_match:
            continue
        if not _COORD_DECRYPT_CALL.search(body_no_comments):
            continue
        # Suppress when a prior-phase-commit guard exists in the same body.
        if _PRIOR_PHASE_GUARD.search(body_no_comments):
            continue
        # Anchor on the coordinator-extract line in the original body.
        coord_orig = _COORD_PORTION_EXTRACT.search(fn.body) or coord_match
        idx = coord_orig.start()
        line_off = fn.body[:idx].count("\n")
        lines = fn.body.splitlines()
        snippet = lines[line_off].strip() if line_off < len(lines) else fn.header
        hits.append(
            Hit(
                file=str(fn.file),
                line=fn.body_start_line + line_off,
                snippet=snippet[:200],
                extra={
                    "function": fn.name,
                    "extract_token": coord_orig.group(0)[:80],
                },
            )
        )
    return hits


# ---------------------------------------------------------------------------
# Pattern 17 detector — cross-SO key-tweak proof guards must run pre AND
# post-persist (asymmetric guard usage = hit).
# ---------------------------------------------------------------------------


def _detect_cross_so_tweak_guard_pre_post_persist(
    funcs: Iterable[GoFunction],
) -> list[Hit]:
    """Pattern 17 — sender-key-tweak proofs persisted with only one of
    the two canonical guard halves.

    Stage-1 predicate:
      * skip ``*_test.go`` files AND the guard helper definitions
        themselves (``verifySenderKeyTweakProofsMatch`` /
        ``validateKeyTweakProofs``);
      * function body uses a sender-key-tweak-proof input
        (``senderKeyTweakProofs`` / ``KeyTweakProofs`` / ...);
      * function body mutates a transfer-leaf row (``ClearKeyTweak`` /
        ``.SetKeyTweak(`` / ``.SetStatus(...KeyTweak*)`` /
        ``transferLeaf.Update().Save(ctx)`` / ``commitSenderKeyTweaks(`` /
        ``settleSenderKeyTweaks(``);
      * function body invokes EXACTLY ONE of the two canonical guards —
        the pre-persist in-memory matcher (``verifySenderKeyTweakProofsMatch``)
        XOR the post-persist DB-backed validator
        (``validateKeyTweakProofs``).

    Mirrors SP-5589 (``dae7686f2c`` on ``buildonspark/spark``): a
    coordinator that forwards plaintext proofs to a receiving SO must run
    the in-memory match BEFORE persistence AND the DB-backed validate
    AFTER persistence; either guard alone is insufficient.
    """
    hits: list[Hit] = []
    for fn in funcs:
        if str(fn.file).endswith("_test.go"):
            continue
        if _TWEAK_GUARD_HELPER_NAME.match(fn.name):
            continue
        body_no_comments = _strip_comments(fn.body)
        # Function must work with sender-key-tweak proofs.
        if not _SENDER_KEY_TWEAK_PROOF_USE.search(body_no_comments):
            continue
        # Function must perform a transfer-leaf mutation.
        if not _TRANSFER_LEAF_MUTATION.search(body_no_comments):
            continue
        pre = bool(_PRE_PERSIST_TWEAK_MATCH.search(body_no_comments))
        post = bool(_POST_PERSIST_TWEAK_VALIDATE.search(body_no_comments))
        # Both guards present -> defended; neither -> belongs to other
        # patterns (no pre/post asymmetry to flag); exactly one -> hit.
        if pre == post:
            continue
        # Anchor on the lone guard call site in the original body.
        if pre:
            anchor = _PRE_PERSIST_TWEAK_MATCH.search(fn.body) or _PRE_PERSIST_TWEAK_MATCH.search(body_no_comments)
            half = "pre_persist_only"
        else:
            anchor = _POST_PERSIST_TWEAK_VALIDATE.search(fn.body) or _POST_PERSIST_TWEAK_VALIDATE.search(body_no_comments)
            half = "post_persist_only"
        idx = anchor.start() if anchor else 0
        line_off = fn.body[:idx].count("\n")
        lines = fn.body.splitlines()
        snippet = lines[line_off].strip() if line_off < len(lines) else fn.header
        hits.append(
            Hit(
                file=str(fn.file),
                line=fn.body_start_line + line_off,
                snippet=snippet[:200],
                extra={
                    "function": fn.name,
                    "guard_half": half,
                },
            )
        )
    return hits


# ---------------------------------------------------------------------------
# Pattern 18 detector — knob-gated MarshalProto residual disclosure.
# ---------------------------------------------------------------------------


def _detect_knob_gated_leaf_marshal_residual(
    funcs: Iterable[GoFunction],
) -> list[Hit]:
    """Pattern 18 — receiver-facing endpoint marshals a transfer/leaf via
    the unfiltered ``MarshalProto(ctx)`` under a knob-gated branch without
    a per-receiver companion call.

    Stage-1 predicate (high precision, low recall):
      * skip ``*_test.go`` files;
      * function name matches the receiver-facing endpoint family
        (Claim* / Query* / GetTransfer* / getTransferLeavesForReceiver* /
        Pending* / Marshal* / Build*Response);
      * function body contains the unfiltered ``MarshalProto(ctx)`` call;
      * function body references a knob-gated token
        (``isMimoReceiveEnabled`` / ``useMIMO`` / ``knobs.GetKnobsService``
        / ``knobs.\\w+Enabled``);
      * function body does NOT also contain a ``MarshalProtoForReceiver``
        companion call. The post-fix shape branches on the knob and uses
        MarshalProtoForReceiver on the per-receiver path; absence of that
        companion = residual disclosure on knob-flip-OFF.

    Mirrors SP-5846 (``25c37ff813`` on ``buildonspark/spark``) — the
    ClaimTransfer per-receiver filter relies on a knob; an unfiltered
    MarshalProto in a sibling endpoint without a per-receiver companion is
    the residual class.
    """
    hits: list[Hit] = []
    for fn in funcs:
        if str(fn.file).endswith("_test.go"):
            continue
        if not _KNOB_RECEIVER_ENDPOINT_NAME.match(fn.name):
            continue
        body_no_comments = _strip_comments(fn.body)
        unfilt_match = _UNFILTERED_MARSHAL_CALL.search(body_no_comments)
        if not unfilt_match:
            continue
        if not _KNOB_GATED_TOKEN.search(body_no_comments):
            continue
        # Suppress: post-fix branches BOTH paths via MarshalProtoForReceiver
        # AND MarshalProto. If MarshalProtoForReceiver is present in the
        # same body, the unfiltered call is the safe sender / non-MIMO
        # branch — don't flag.
        if _PER_RECEIVER_MARSHAL_CALL.search(body_no_comments):
            continue
        unfilt_orig = _UNFILTERED_MARSHAL_CALL.search(fn.body) or unfilt_match
        idx = unfilt_orig.start()
        line_off = fn.body[:idx].count("\n")
        lines = fn.body.splitlines()
        snippet = lines[line_off].strip() if line_off < len(lines) else fn.header
        hits.append(
            Hit(
                file=str(fn.file),
                line=fn.body_start_line + line_off,
                snippet=snippet[:200],
                extra={
                    "function": fn.name,
                    "marshal_call": unfilt_orig.group(0)[:80],
                },
            )
        )
    return hits


# ---------------------------------------------------------------------------
# Pattern 19 detector — chainwatcher-style background sessions sharing a
# parent tx with deferred cleanup but no reopen-ephemeral hook registration.
# ---------------------------------------------------------------------------


def _detect_background_session_parent_tx_reopen_hook(
    funcs: Iterable[GoFunction],
) -> list[Hit]:
    """Pattern 19 — background-session functions that bind a deferred
    cleanup against a parent-context-derived ent.Tx without registering
    OnCommit / OnRollback reopen-ephemeral hooks.

    Stage-1 predicate:
      * skip ``*_test.go`` files;
      * body acquires a tx from the parent context
        (``entephemeral.GetTxFromContext(ctx)`` / ``ent.GetTxFromContext`` /
        equivalent helper);
      * body registers a ``defer func() { ... cleanup-style ... }()``;
      * body references a chainwatcher / ephemeral-session / cleanup
        domain token;
      * body does NOT register an OnCommit / OnRollback reopen hook
        (``OnCommit(`` / ``OnRollback(`` / ``bindTx(`` /
        ``newTxBackedEphemeralSession(``).

    Mirrors SP-6329 (``dfb6b50ec9`` on ``buildonspark/spark``) — chain-
    watcher orphaned signing-keyshare-secret cleanup paths share a parent
    tx and deferred rollback hooks no-op when the parent commits.
    """
    hits: list[Hit] = []
    for fn in funcs:
        if str(fn.file).endswith("_test.go"):
            continue
        body_no_comments = _strip_comments(fn.body)
        if not _PARENT_CTX_TX_GET.search(body_no_comments):
            continue
        if not _DEFERRED_CLEANUP_FN.search(body_no_comments):
            continue
        if not _BG_SESSION_DOMAIN_TOKEN.search(body_no_comments):
            continue
        # Suppress when reopen-ephemeral hooks are registered.
        if _REOPEN_EPHEMERAL_HOOK.search(body_no_comments):
            continue
        defer_orig = _DEFERRED_CLEANUP_FN.search(fn.body) or _DEFERRED_CLEANUP_FN.search(body_no_comments)
        idx = defer_orig.start() if defer_orig else 0
        line_off = fn.body[:idx].count("\n")
        lines = fn.body.splitlines()
        snippet = lines[line_off].strip() if line_off < len(lines) else fn.header
        hits.append(
            Hit(
                file=str(fn.file),
                line=fn.body_start_line + line_off,
                snippet=snippet[:200],
                extra={
                    "function": fn.name,
                    "session_lane": "background_session_no_reopen_hook",
                },
            )
        )
    return hits


# ---------------------------------------------------------------------------
# Pattern 20 detector — post-commit deferred Rollback without a guard.
# ---------------------------------------------------------------------------


def _detect_post_commit_rollback_unprotected(
    funcs: Iterable[GoFunction],
) -> list[Hit]:
    """Pattern 20 — ``defer func() { _ = X.Rollback() }()`` followed by
    ``X.Commit()`` in the same function body, without a ``committed``-
    style boolean guard.

    Stage-1 predicate:
      * skip ``*_test.go`` files;
      * body registers a deferred Rollback on receiver ``X`` (anonymous-
        function form OR direct defer);
      * body calls ``X.Commit()`` (same receiver) somewhere AFTER the
        deferred rollback registration;
      * body does NOT contain a sentinel-guarded defer
        (``if !committed { Rollback() }`` shape) AND does NOT contain a
        ``committed`` / ``rolledBack`` boolean assignment that would gate
        post-rollback hooks.

    Mirrors SP-6390 (``a5550e78e5632a...`` on ``buildonspark/spark``):
    ``cleanupSigningKeyshareSecret`` and ``prepareSigningKeyshareSecret
    Rotation`` registered ``defer func() { _ = ephemeralTx.Rollback() }()``
    and committed the tx; the deferred Rollback fires after Commit and
    triggers OnRollback hooks that mutate state Commit cleared.
    """
    hits: list[Hit] = []
    for fn in funcs:
        if str(fn.file).endswith("_test.go"):
            continue
        body_no_comments = _strip_comments(fn.body)
        # Sentinel-guarded defer body suppresses everything else.
        if _GUARDED_DEFER_ROLLBACK.search(body_no_comments):
            continue
        receivers: list[tuple[str, int]] = []
        for m in _DEFER_ROLLBACK_FUNC.finditer(body_no_comments):
            receivers.append((m.group("rcvr"), m.start()))
        for m in _DEFER_ROLLBACK_DIRECT.finditer(body_no_comments):
            receivers.append((m.group("rcvr"), m.start()))
        if not receivers:
            continue
        # Body-level committed-guard suppression: any ``committed`` /
        # ``rolledBack`` style sentinel anywhere in the function body
        # implies the operator is intentionally gating rollback.
        if _COMMITTED_GUARD_VAR.search(body_no_comments):
            continue
        flagged_receivers: set[str] = set()
        for rcvr, defer_pos in receivers:
            commit_re = re.compile(
                r"\b" + re.escape(rcvr) + r"\.Commit\s*\("
            )
            commit_match = commit_re.search(body_no_comments, pos=defer_pos)
            if not commit_match:
                continue
            flagged_receivers.add(rcvr)
        if not flagged_receivers:
            continue
        # Anchor on the first defer-Rollback in the original body that
        # references one of the flagged receivers.
        anchor_pos: int | None = None
        for rcvr in flagged_receivers:
            anchor_re = re.compile(
                r"\bdefer\s+(?:func\s*\(\s*\)\s*\{\s*(?:_\s*=\s*)?)?"
                + re.escape(rcvr) + r"\.Rollback\s*\("
            )
            m = anchor_re.search(fn.body)
            if m:
                anchor_pos = m.start()
                break
        line_off = fn.body[:anchor_pos].count("\n") if anchor_pos is not None else 0
        lines = fn.body.splitlines()
        snippet = lines[line_off].strip() if line_off < len(lines) else fn.header
        hits.append(
            Hit(
                file=str(fn.file),
                line=fn.body_start_line + line_off,
                snippet=snippet[:200],
                extra={
                    "function": fn.name,
                    "tx_receivers": sorted(flagged_receivers),
                },
            )
        )
    return hits


# ---------------------------------------------------------------------------
# Pattern 21 detector — read-side queries adjacent to cron ForUpdate paths.
# ---------------------------------------------------------------------------


def _detect_cron_forupdate_adjacent_read_lock_missing(
    funcs_by_file: dict,
    file_sources: dict,
) -> list[Hit]:
    """Pattern 21 — flag a read-side function in a package whose cron lane
    uses ``ForUpdate`` over the same entity family, where the read does NOT
    use ``ForUpdate``.

    Stage-1 predicate (per-package, two-pass):
      * skip ``*_test.go`` files;
      * compute the per-package set of files that contain at least one
        ``ForUpdate(`` call AND a cron-task token (cron-aware package);
      * for every other function in such a package whose name matches the
        read-side predicate (Create* / Initiate* / Register* / Reserve* /
        Acquire* / LoadFor* / Claim* / Finalize*), AND whose body
        references a counter-swap / transfer-leaf entity token,
        AND whose body contains an ent-query call but NOT a ``ForUpdate``
        token: flag.

    Mirrors SP-5433 (``594a8dbab7`` on ``buildonspark/spark``) — counter-
    swap creation read symmetrized with the cancel cron's ForUpdate lock.
    """
    # Group functions by package (= directory of the file).
    pkg_funcs: dict = {}
    for f, fs in funcs_by_file.items():
        pkg = str(Path(f).parent)
        pkg_funcs.setdefault(pkg, []).extend(fs)

    pkg_is_cron_aware: dict = {}
    for pkg, fns in pkg_funcs.items():
        cron_aware = False
        for fn in fns:
            if str(fn.file).endswith("_test.go"):
                continue
            body = _strip_comments(fn.body)
            if _FOR_UPDATE_TOKEN.search(body) and _CRON_TASK_TOKEN.search(body):
                cron_aware = True
                break
        pkg_is_cron_aware[pkg] = cron_aware

    hits: list[Hit] = []
    for pkg, fns in pkg_funcs.items():
        if not pkg_is_cron_aware.get(pkg):
            continue
        for fn in fns:
            if str(fn.file).endswith("_test.go"):
                continue
            if _CRON_TASK_FUNC_NAME.match(fn.name):
                continue
            if not _CRON_ADJACENT_READ_NAME.match(fn.name):
                continue
            body = _strip_comments(fn.body)
            if not _COUNTER_SWAP_ENTITY_TOKEN.search(body):
                continue
            if not _ENT_QUERY_CALL.search(body):
                continue
            # Suppress: read body itself uses ForUpdate.
            if _FOR_UPDATE_TOKEN.search(body):
                continue
            qmatch = _ENT_QUERY_CALL.search(fn.body) or _ENT_QUERY_CALL.search(body)
            idx = qmatch.start() if qmatch else 0
            line_off = fn.body[:idx].count("\n")
            lines = fn.body.splitlines()
            snippet = lines[line_off].strip() if line_off < len(lines) else fn.header
            hits.append(
                Hit(
                    file=str(fn.file),
                    line=fn.body_start_line + line_off,
                    snippet=snippet[:200],
                    extra={
                        "function": fn.name,
                        "package_dir": pkg,
                        "cron_lane": "package_has_forupdate_cron_sibling",
                    },
                )
            )
    return hits


# ---------------------------------------------------------------------------
# Pattern 22 detector — coordinator fanout without commit before remote call.
# ---------------------------------------------------------------------------


def _detect_coordinator_fanout_tx_commit_before_remote_call(
    funcs: Iterable[GoFunction],
) -> list[Hit]:
    """Pattern 22 — coordinator-side function performs a tx-bound write
    then calls a remote-SO fanout helper without an explicit commit
    between the two.

    Stage-1 predicate:
      * skip ``*_test.go`` files;
      * skip cron-task functions (DatabaseMiddleware commits on return);
      * body must reference a coordinator-intent token
        (Coordinator / PreimageSwap / CoopExit / FinalizeTransfer /
        SettleSenderKeyTweaks / etc.);
      * body must contain at least one ent-tx write call;
      * body must contain at least one remote-SO fanout helper call AFTER
        the write;
      * body must NOT contain a tx commit call BEFORE the fanout.

    Mirrors SP-5783 (``b154174cee`` on ``buildonspark/spark``) — coop_exit
    preimage-swap settle wrote a tx-bound update before fanning out to
    remote SOs, allowing coordinator/remote state divergence on partial
    fanout failure.
    """
    hits: list[Hit] = []
    for fn in funcs:
        if str(fn.file).endswith("_test.go"):
            continue
        if _CRON_TASK_FUNC_NAME.match(fn.name):
            continue
        body_no_comments = _strip_comments(fn.body)
        # Cron-context body suppression — cron-bound functions have a
        # different commit lifecycle.
        if _FANOUT_CRON_CONTEXT_TOKEN.search(body_no_comments):
            continue
        if not _COORDINATOR_INTENT_TOKEN.search(body_no_comments):
            continue
        write_match = _ENT_TX_WRITE_CALL.search(body_no_comments)
        if not write_match:
            continue
        fanout_match = _REMOTE_FANOUT_CALL.search(body_no_comments, pos=write_match.end())
        if not fanout_match:
            continue
        # Look for a commit BETWEEN the write and the fanout.
        between = body_no_comments[write_match.end(): fanout_match.start()]
        if _TX_COMMIT_CALL.search(between):
            continue
        # Anchor on the fanout call in the original body.
        anchor_match = _REMOTE_FANOUT_CALL.search(fn.body) or fanout_match
        idx = anchor_match.start()
        line_off = fn.body[:idx].count("\n")
        lines = fn.body.splitlines()
        snippet = lines[line_off].strip() if line_off < len(lines) else fn.header
        hits.append(
            Hit(
                file=str(fn.file),
                line=fn.body_start_line + line_off,
                snippet=snippet[:200],
                extra={
                    "function": fn.name,
                    "fanout_call": anchor_match.group(0)[:80],
                },
            )
        )
    return hits


# ---------------------------------------------------------------------------
# Pattern 23 detector — grpc.WithDefaultServiceConfig last-write-wins.
# ---------------------------------------------------------------------------


def _detect_grpc_default_service_config_last_write_wins(
    funcs: Iterable[GoFunction],
) -> list[Hit]:
    """Pattern 23 — a single function body contains TWO OR MORE
    ``WithDefaultServiceConfig(...)`` calls. grpc-go's setter is a
    single-pointer overwrite, so only the last call wins; the earlier
    service-config payload (retry policy / load-balancing / health-check)
    is silently dropped.

    Stage-1 predicate:
      * skip ``*_test.go`` files;
      * count occurrences of ``(grpc\\.)?WithDefaultServiceConfig\\(`` in the
        function body;
      * fire when the count is >= 2.

    Mirrors SP-6314 (``51dc21a3ce`` on ``buildonspark/spark``) — gRPC
    DialOption chain accidentally appended ``WithDefaultServiceConfig``
    twice and the earlier retry policy was dropped.
    """
    hits: list[Hit] = []
    for fn in funcs:
        if str(fn.file).endswith("_test.go"):
            continue
        body_no_comments = _strip_comments(fn.body)
        matches = list(_DEFAULT_SVC_CONFIG_CALL.finditer(body_no_comments))
        if len(matches) < 2:
            continue
        # Anchor on the SECOND occurrence (the one that overwrites).
        original_matches = list(_DEFAULT_SVC_CONFIG_CALL.finditer(fn.body))
        if len(original_matches) >= 2:
            anchor_idx = original_matches[1].start()
        else:
            anchor_idx = matches[1].start()
        line_off = fn.body[:anchor_idx].count("\n")
        lines = fn.body.splitlines()
        snippet = lines[line_off].strip() if line_off < len(lines) else fn.header
        hits.append(
            Hit(
                file=str(fn.file),
                line=fn.body_start_line + line_off,
                snippet=snippet[:200],
                extra={
                    "function": fn.name,
                    "occurrence_count": len(matches),
                },
            )
        )
    return hits


# ---------------------------------------------------------------------------
# Pattern 24 detector — multi-receiver rollup collapses to receivers[0].
# ---------------------------------------------------------------------------


def _detect_multi_receiver_rollup_first_only(
    funcs: Iterable[GoFunction],
) -> list[Hit]:
    """Pattern 24 — flag a function whose name suggests a multi-receiver
    rollup (CancelStuckTransfer / RefundExpiredTransfer / etc.) that
    collapses receivers to the first/only entry instead of enumerating
    every receiver.

    Stage-1 predicate:
      * skip ``*_test.go`` files;
      * function name matches the rollup-entry-point predicate;
      * body references a MIMO / multi-receiver-aware token;
      * body contains at least one first-only receiver query
        (``QueryReceivers().First(ctx)`` / ``receivers[0].Update(...)``);
      * body contains a receiver-side mutation token
        (``SetStatus(...)`` / ``Update(...).Save(ctx)`` / ``UpdateOne...``);
      * body does NOT contain a ``for ... := range receivers`` /
        ``range AllReceivers`` loop (enumeration suppression).

    Mirrors SP-5842 (``c78104eab8`` on ``buildonspark/spark``) —
    CancelStuckTransfer originally only updated ``receivers[0]``, leaving
    the remaining receivers in a divergent state.
    """
    hits: list[Hit] = []
    for fn in funcs:
        if str(fn.file).endswith("_test.go"):
            continue
        if not _MULTI_RECEIVER_ROLLUP_FUNC_NAME.match(fn.name):
            continue
        body_no_comments = _strip_comments(fn.body)
        if not _MIMO_MULTI_RECEIVER_TOKEN.search(body_no_comments):
            continue
        first_match = _FIRST_RECEIVER_QUERY_CALL.search(body_no_comments)
        if not first_match:
            continue
        if not _RECEIVER_MUTATE_TOKEN.search(body_no_comments):
            continue
        # Suppress: an explicit range-loop over receivers means the function
        # is enumerating, not collapsing.
        if _RECEIVER_RANGE_LOOP.search(body_no_comments):
            continue
        # Anchor on the first-only call in the original body.
        anchor_match = _FIRST_RECEIVER_QUERY_CALL.search(fn.body) or first_match
        idx = anchor_match.start()
        line_off = fn.body[:idx].count("\n")
        lines = fn.body.splitlines()
        snippet = lines[line_off].strip() if line_off < len(lines) else fn.header
        hits.append(
            Hit(
                file=str(fn.file),
                line=fn.body_start_line + line_off,
                snippet=snippet[:200],
                extra={
                    "function": fn.name,
                    "first_only_call": anchor_match.group(0)[:100],
                },
            )
        )
    return hits


# ---------------------------------------------------------------------------
# Pattern 25 detector — SO pubkey resolved from req payload not session.
# ---------------------------------------------------------------------------


def _detect_so_pubkey_req_payload_not_session(
    funcs: Iterable[GoFunction],
) -> list[Hit]:
    """Pattern 25 — flag a handler that resolves a downstream SO public
    key from the request payload (``req.<*>(SO|Operator)<*>(Public|Identity)Key``)
    and feeds it into a downstream resolver / RPC dispatcher / signature
    verifier WITHOUT first reading the session-bound identity.

    Stage-1 predicate:
      * skip ``*_test.go`` files;
      * function name matches the handler-style predicate
        (Validate / Verify / Handle / Dispatch / Sign / Process / etc.);
      * body extracts an SO/operator pubkey field from ``req.*`` / ``in.*``;
      * body uses that pubkey downstream (resolve / lookup / dial / send /
        gossip / verify-signature);
      * body does NOT contain a session-bound identity lookup
        (``h.config.Identifier`` / ``auth.IdentityPublicKey(ctx)`` /
        ``session.Identity*`` / ``IdentityFromContext(ctx)``).

    Reference: backward-mining seed (lane spec) — SO-pubkey resolution
    via request payload not session identity. Detector is defensive: it
    flags the bug shape so a future contributor adding a handler that
    trusts ``req.OperatorPublicKey`` without a session check is caught.
    """
    hits: list[Hit] = []
    for fn in funcs:
        if str(fn.file).endswith("_test.go"):
            continue
        if not _SO_HANDLER_FUNC_NAME.match(fn.name):
            continue
        body_no_comments = _strip_comments(fn.body)
        field_match = _REQ_PAYLOAD_SO_PUBKEY_FIELD.search(body_no_comments)
        if not field_match:
            continue
        downstream_match = _SO_PUBKEY_DOWNSTREAM_USE.search(
            body_no_comments, pos=field_match.end()
        )
        if not downstream_match:
            continue
        # Suppression: any session-bound identity lookup anywhere in the body.
        if _SESSION_IDENTITY_LOOKUP.search(body_no_comments):
            continue
        # Anchor on the field extraction in the original body.
        anchor_match = _REQ_PAYLOAD_SO_PUBKEY_FIELD.search(fn.body) or field_match
        idx = anchor_match.start()
        line_off = fn.body[:idx].count("\n")
        lines = fn.body.splitlines()
        snippet = lines[line_off].strip() if line_off < len(lines) else fn.header
        hits.append(
            Hit(
                file=str(fn.file),
                line=fn.body_start_line + line_off,
                snippet=snippet[:200],
                extra={
                    "function": fn.name,
                    "pubkey_field": anchor_match.group(0)[:100],
                    "downstream_call": downstream_match.group(0)[:80],
                },
            )
        )
    return hits


# ---------------------------------------------------------------------------
# Pattern 26 detector — guard-set shrinkage with SetStatus sites still live.
# ---------------------------------------------------------------------------


def _detect_guard_set_shrinkage_status_still_set(
    file_sources: dict,
    funcs_by_file: dict,
) -> list[Hit]:
    """Pattern 26 — flag a guard-set slice
    (``var <name> = []st.<EnumType>{...}``) that is consumed by a
    ``StatusIn(<varName>...)`` / ``StatusNotIn(<varName>...)`` predicate
    AND that omits at least one enum value still SET in production code
    via ``SetStatus(st.<EnumType><EnumValue>)`` outside of test files.

    Stage-1 predicate (cross-file):
      * collect every guard-set declaration across all non-test ``.go``
        files in scope, with its enum type, member set, and the
        consumer call sites;
      * collect every ``SetStatus(st.<EnumType><EnumValue>)`` site across
        all non-test ``.go`` files;
      * for each guard slice that has at least one ``StatusIn`` /
        ``StatusNotIn`` consumer, check whether any production
        ``SetStatus`` site for the same enum type uses an enum value
        NOT present in the guard slice;
      * fire ONE hit per (guard-slice declaration, missing enum value)
        pair, anchored on the guard-slice line.

    Mirrors SP-6286 (``1da2e92e93`` on ``buildonspark/spark``) —
    pruning a status from the lock-status guard slice without
    auditing every SetStatus consumer leaves a guard regression
    that allows formerly-protected statuses to be force-overwritten.
    """
    # Pass 1: collect SetStatus(st.X) usage per enum-type root, by walking
    # every non-test source. We approximate the enum-type by the prefix
    # before the value tail; since Go enum constants are typically named
    # like ``st.TreeNodeStatusFrozen`` (type=TreeNodeStatus, value=Frozen),
    # we conservatively collect the FULL identifier and let the pair-up
    # step match by suffix.
    set_status_idents: dict = {}  # enum_ident -> [(file, line)]
    for f, src in file_sources.items():
        if str(f).endswith("_test.go"):
            continue
        for m in _SET_STATUS_ENUM_CALL.finditer(src):
            ident = m.group(1)
            line = src[: m.start()].count("\n") + 1
            set_status_idents.setdefault(ident, []).append((str(f), line))

    # Pass 2: collect StatusIn/StatusNotIn consumer call sites by guard-var
    # name across the whole scope (any file). A guard slice with NO
    # consumer is uninteresting for this detector.
    consumers_by_var: dict = {}  # var_name -> [(file, line)]
    for f, src in file_sources.items():
        for m in _GUARD_SET_CONSUMER.finditer(src):
            varname = m.group(1)
            line = src[: m.start()].count("\n") + 1
            consumers_by_var.setdefault(varname, []).append((str(f), line))

    hits: list[Hit] = []
    # Pass 3: walk each guard-slice declaration and decide whether a
    # SetStatus site exists for an enum value the guard slice OMITS.
    for f, src in file_sources.items():
        if str(f).endswith("_test.go"):
            continue
        for m in _GUARD_SET_VAR_DECL.finditer(src):
            varname = m.group(1)
            enum_type = m.group(2)
            members_blob = m.group(3)
            if varname not in consumers_by_var:
                continue
            members = set(_GUARD_SET_ENUM_ENTRY.findall(members_blob))
            if not members:
                continue
            # The guard's enum-type is `enum_type`. Production SetStatus
            # idents that begin with `enum_type` (case-sensitive prefix)
            # AND that aren't in the guard's member set are the leak.
            missing_idents: list[str] = []
            for ident, sites in set_status_idents.items():
                if not ident.startswith(enum_type):
                    continue
                if ident in members:
                    continue
                missing_idents.append(ident)
            if not missing_idents:
                continue
            decl_line = src[: m.start()].count("\n") + 1
            snippet_line = src.splitlines()[decl_line - 1].strip() if decl_line - 1 < len(src.splitlines()) else f"var {varname}"
            for missing in sorted(missing_idents):
                set_sites = set_status_idents.get(missing, [])
                hits.append(
                    Hit(
                        file=str(f),
                        line=decl_line,
                        snippet=snippet_line[:200],
                        extra={
                            "guard_var": varname,
                            "enum_type": enum_type,
                            "missing_enum_value": missing,
                            "set_sites": [
                                {"file": s[0], "line": s[1]} for s in set_sites[:5]
                            ],
                            "consumer_sites": [
                                {"file": c[0], "line": c[1]}
                                for c in consumers_by_var.get(varname, [])[:5]
                            ],
                        },
                    )
                )
    return hits


def _detect_constructor_stores_caller_slice_without_copy(
    funcs: Iterable[GoFunction],
) -> list[Hit]:
    """Pattern 27 — exported ``New*`` constructor stores a caller-supplied
    ``[]byte`` slice in a returned struct field WITHOUT a defensive copy.

    Predicate (single-function, body-local):
      * fn name matches ``^New[A-Z]\\w*``;
      * params declare at least one ``<name> []byte`` parameter;
      * fn body contains a struct-literal field-write of the form
        ``<field>: <name>`` (the struct stores the param verbatim);
      * fn body does NOT contain ``copy(``, ``append([]byte{...``,
        ``bytes.Clone(`` or ``slices.Clone(`` BEFORE that field-write
        (i.e. no defensive copy was performed).

    Mirrors Swival #023/#024/#025/#045/#046 cluster — the caller can
    later mutate their own slice and corrupt internal state of the
    returned object. **Spark structural hit:** ``spark/common/bitmap.go:12``
    ``NewBitMapFromBytes(bytes []byte, ...) { return &BitMap{value: bytes, ...}}``
    (per AAK L18 ``swival_go_crypto_mine_l18_2026-05-07``).

    M14-trap: structural-only. Promoting any hit beyond Informational
    requires a runtime PoC of an untrusted concurrent mutator AND a
    demonstrated downstream impact (PoI-aligned).
    """
    hits: list[Hit] = []
    for fn in funcs:
        if not _NEW_CONSTRUCTOR_NAME.match(fn.name):
            continue
        # Suppress *_test.go files — fixture-skipping is handled at
        # extract time via the path, but we belt-and-suspender here.
        if str(fn.file).endswith("_test.go"):
            continue
        # Scrape every []byte param NAME.
        byte_params = _BYTES_PARAM.findall(fn.params)
        if not byte_params:
            continue
        body = fn.body
        # For each byte param, look for ``<field>: <param>``-style
        # struct-literal field-writes inside the body.
        for pname in byte_params:
            field_write_re = re.compile(
                r"\b([A-Za-z_]\w*)\s*:\s*" + re.escape(pname) + r"\s*[,\}\)]"
            )
            for m in field_write_re.finditer(body):
                # Ensure the assignment occurs inside an actual struct
                # literal (preceded somewhere on the same line by ``{``
                # OR by a ``T{`` on a prior line — we approximate with a
                # simple ``{`` lookback in the slice up to the match).
                pre = body[: m.start()]
                # Check that NO defensive copy preceded the field write.
                # We test the entire prefix; if the only copy is in a
                # post-construction tail, the constructor is still
                # vulnerable so this is a strict-superset detection.
                if _COPY_HELPERS.search(pre):
                    continue
                # Confirm the field-write is inside a struct literal —
                # heuristic: the preceding text contains an open brace
                # not yet matched within the function body slice.
                opens = pre.count("{")
                closes = pre.count("}")
                if opens <= closes:
                    continue
                line_off = pre.count("\n")
                snippet_line = fn.body_start_line + line_off
                snippet = (
                    body.splitlines()[line_off].strip()
                    if line_off < len(body.splitlines())
                    else fn.header
                )
                field_name = m.group(1)
                hits.append(
                    Hit(
                        file=str(fn.file),
                        line=snippet_line,
                        snippet=snippet[:200],
                        extra={
                            "function": fn.name,
                            "param": pname,
                            "field": field_name,
                        },
                    )
                )
                # Only report ONE hit per (fn, param) pair so a struct
                # initialised with multiple field-writes doesn't fan out.
                break
    return hits


def _classify_byte_source(bytes_arg: str, body: str, fn: GoFunction) -> str:
    """Refinement 1 (L21 ABA) — best-effort classifier for the byte_source
    field of a pattern-#28 hit. Returns one of:

      * ``"db_load"`` — bytes were loaded from a DB column or via an
        ent ``assignValues`` / ``UnmarshalJSON`` receiver. Pairs with a
        local ``proto.Marshal``/``json.Marshal`` producer = canonical
        round-trip = defensive design.
      * ``"decrypted_plaintext"`` — bytes are the plaintext output of an
        attacker-supplied ECIES / AES-GCM decrypt call. The attacker
        chose the plaintext entirely; trailing-bytes attack reduces to
        "send a different valid encoding," which is no attack.
      * ``"network_received"`` — bytes came directly off the wire (gRPC
        request struct, HTTP body, peer-SO RPC response).
      * ``"unknown"`` — none of the above markers detected in the
        function body.

    Heuristic only — caller should treat ``unknown`` as conservative
    "fire" when paired with ``signature_boundary``.
    """
    # Decrypt has the strongest semantic — check first.
    if _DECRYPT_MARKERS.search(body):
        return "decrypted_plaintext"
    # DB load: handler body has assignValues / Scan / UnmarshalJSON
    # receiver / ent QueryX(ctx loop AND a same-package marshal producer
    # signature OR the bytes-arg looks like an ent column accessor.
    if _DB_LOAD_MARKERS.search(body) or _DB_LOAD_MARKERS.search(fn.header):
        return "db_load"
    # Bytes arg shape ``leaf.X`` / ``row.X`` / ``cursor.X`` is a strong
    # ent-column-accessor signature even without an in-body marker.
    if re.match(r"^(?:leaf|row|cursor|entity)\.[A-Z]\w*$", bytes_arg):
        return "db_load"
    # Network markers in fn params or body (gRPC request, HTTP body).
    if _NETWORK_MARKERS.search(fn.params) or _NETWORK_MARKERS.search(body):
        return "network_received"
    return "unknown"


def _detect_unmarshal_trailing_bytes_accepted(
    funcs: Iterable[GoFunction],
) -> list[Hit]:
    """Pattern 28 — body calls a PERMISSIVE Unmarshal-family call
    (``proto.Unmarshal`` / ``asn1.Unmarshal`` / ``cbor.Unmarshal`` /
    ``ReadASN1*``) and does NOT subsequently check that no trailing
    bytes remain (``len(rest) == 0``, ``s.Empty()``, etc).

    L21 ABA refinement (post-AAU L20 empirical falsification at 14/14
    Spark hits — all DB-load, JSON-FP, or no-signature-boundary cases):

      * Refinement 1 — emit ``byte_source`` extra field to distinguish
        ``db_load`` / ``decrypted_plaintext`` / ``network_received`` /
        ``unknown`` source-of-bytes. We SUPPRESS ``db_load`` because
        ent column round-trips are canonical-only by design.
      * Refinement 2 — DROP ``json.Unmarshal``. Stdlib JSON rejects
        trailing non-whitespace bytes (verified L20 runtime). Pattern
        only fires on permissive parsers (proto / asn1 / cbor).
      * Refinement 3 — emit ``signature_boundary`` extra field. We
        SUPPRESS hits with ``byte_source=unknown`` AND
        ``signature_boundary=false``: distinct re-encodings have no
        security impact without a downstream signature/hash check.

    Predicate (single-function, body-local):
      * fn body contains a permissive Unmarshal call;
      * AFTER the Unmarshal call, no len/Empty/bytes.Equal guard;
      * byte_source != ``db_load``;
      * NOT (byte_source == ``unknown`` AND signature_boundary == False).

    Mirrors Swival #011/#039/#056. M14-trap: structural-only.
    Promoting beyond Informational still requires runtime evidence
    that the parsed bytes are attacker-controlled AND that a distinct
    re-encoding has security impact.
    """
    hits: list[Hit] = []
    for fn in funcs:
        if str(fn.file).endswith("_test.go"):
            continue
        body = fn.body
        # Refinement 2: only fire on permissive parsers. Skip JSON.
        m = _PERMISSIVE_UNMARSHAL_CALL.search(body)
        if not m:
            continue
        # Look for any trailing-byte guard ANYWHERE in the body. Strict
        # over-approximation: function-wide len(...)==0 elsewhere counts.
        if _TRAILING_BYTE_GUARD.search(body):
            continue

        # Refinement 1: classify source-of-bytes.
        bytes_arg_match = _UNMARSHAL_BYTES_ARG.search(body)
        bytes_arg = bytes_arg_match.group(1) if bytes_arg_match else ""
        byte_source = _classify_byte_source(bytes_arg, body, fn)

        # SUPPRESS db_load — defensive-design canonical round-trip.
        if byte_source == "db_load":
            continue

        # Refinement 3: tag signature_boundary.
        signature_boundary = bool(_SIGNATURE_BOUNDARY.search(body))

        # SUPPRESS unknown-source AND no signature boundary — distinct
        # re-encodings have no impact without a downstream check. This
        # is the M14-trap discipline: don't fan-out without a real
        # impact channel.
        if byte_source == "unknown" and not signature_boundary:
            continue

        line_off = body[: m.start()].count("\n")
        snippet_line = fn.body_start_line + line_off
        snippet = (
            body.splitlines()[line_off].strip()
            if line_off < len(body.splitlines())
            else fn.header
        )
        hits.append(
            Hit(
                file=str(fn.file),
                line=snippet_line,
                snippet=snippet[:200],
                extra={
                    "function": fn.name,
                    "unmarshal_kind": m.group(0),
                    "byte_source": byte_source,
                    "bytes_arg": bytes_arg,
                    "signature_boundary": signature_boundary,
                },
            )
        )
    return hits


def _detect_rpc_bare_fmterrorf_user_input_parse_failure(
    funcs: Iterable[GoFunction],
) -> list[Hit]:
    """Pattern 29 — RPC handler returns a BARE ``fmt.Errorf(...)`` wrapping
    a user-input parse failure (``uuid.Parse``, ``hex.DecodeString``,
    ``keys.ParsePublicKey``, ``proto.Unmarshal``, etc) WITHOUT routing the
    error through an ``errors.InvalidArgument*`` (or ``status.Errorf``)
    helper that maps to the correct gRPC status code.

    Predicate (single-function, body-local):
      * params include a ``*<XxxRequest>``-shaped argument (see
        ``_GRPC_REQUEST_PARAM``) — indicates this is an RPC handler;
      * fn body contains at least one user-input parse call (see
        ``_PARSE_FAILURE_CALL``);
      * fn body contains at least one ``return ..., fmt.Errorf(...)``
        line that is NOT preceded on the same line by an
        ``errors.<RpcCode>*(`` / ``status.Errorf(`` wrapper.

    Mirrors Spark commit ``86ee75a99f`` (PR #6420 — "Fix error
    classifications at RPC boundary"). At audit-pin many adjacent RPC
    handlers still leak bare ``fmt.Errorf`` returns from parse failures,
    which the gRPC layer maps to ``Unknown`` (2) — degrading the gRPC
    status-code contract for client error handling and observability.

    M14-trap: severity Informational/Operational. Funds-handling impact
    is NOT established absent a downstream consumer that branches on
    the gRPC status code in a security-sensitive way.
    """
    hits: list[Hit] = []
    for fn in funcs:
        if str(fn.file).endswith("_test.go"):
            continue
        if not _GRPC_REQUEST_PARAM.search(fn.params):
            continue
        body = fn.body
        if not _PARSE_FAILURE_CALL.search(body):
            continue
        # Walk every bare ``return ..., fmt.Errorf(...)`` line; if it is
        # NOT wrapped by an RPC status helper on the same line, fire.
        lines = body.splitlines()
        for idx, line_text in enumerate(lines):
            if not _BARE_FMT_ERRORF_RETURN.search(line_text):
                continue
            if _RPC_STATUS_WRAPPER.search(line_text):
                continue
            snippet_line = fn.body_start_line + idx
            hits.append(
                Hit(
                    file=str(fn.file),
                    line=snippet_line,
                    snippet=line_text.strip()[:200],
                    extra={"function": fn.name},
                )
            )
            # Only fire ONCE per function — multiple bare returns in a
            # single handler are the SAME bug shape; we report on first.
            break
    return hits


def _detect_exported_getter_returns_internal_slice_without_copy(
    file_sources: dict,
) -> list[Hit]:
    """Pattern 30 — exported method returning a ``[]byte`` struct field
    directly without a defensive copy.

    Predicate (header-scoped, body-confirmed):
      * function header matches ``func (<recv> *?<Type>) <Name>() []byte {``
        (zero formal parameters, ``[]byte`` return type, exported method);
      * body is a single ``return <recv>.<field>`` statement (whitespace
        and comments are tolerated, but no other executable lines);
      * body does not contain a defensive copy helper (``copy(``,
        ``bytes.Clone(``, ``slices.Clone(``, ``append([]byte{...``).

    Mirrors Swival #023/#024/#025/#045/#046 cluster (inverse of pattern
    27 — caller-side aliasing through an exported getter rather than a
    constructor). **Spark structural prediction (AAK L18):**
    ``common/bitmap.go:33`` ``func (b *BitMap) Bytes() []byte { return b.value }``.

    M14-trap: structural-only. Any escalation requires a runtime PoC of
    an untrusted concurrent mutator AND demonstrated downstream impact
    (PoI-aligned). Pairs with pattern 27 for full bitmap.go aliasing
    coverage.
    """
    hits: list[Hit] = []
    for rel_path, src in file_sources.items():
        if str(rel_path).endswith("_test.go"):
            continue
        for hdr in _GETTER_HEADER.finditer(src):
            recv_name = hdr.group("recv")
            method_name = hdr.group("name")
            # Find the body for this match.
            brace_idx = src.find("{", hdr.end() - 1)
            if brace_idx < 0:
                continue
            end_idx = _balance_braces(src, brace_idx)
            if end_idx is None:
                continue
            body = src[brace_idx + 1:end_idx - 1]
            # Reject if a defensive copy is present anywhere in the body.
            if _COPY_HELPERS.search(body):
                continue
            # Body must consist of a single return-of-field statement.
            stripped = body.strip()
            if not stripped:
                continue
            ret_match = _BODY_RETURN_FIELD.match(stripped)
            if not ret_match:
                continue
            # Confirm the returned identifier matches the receiver name.
            if ret_match.group("recv") != recv_name:
                continue
            field_name = ret_match.group("field")
            line_no = src.count("\n", 0, hdr.start()) + 1
            snippet = src[hdr.start():hdr.end()].strip()
            hits.append(
                Hit(
                    file=str(rel_path),
                    line=line_no,
                    snippet=snippet[:200],
                    extra={
                        "method": method_name,
                        "receiver": recv_name,
                        "field": field_name,
                    },
                )
            )
    return hits


def _detect_ent_edge_join_when_denormalized_column_exists(
    funcs: Iterable[GoFunction],
) -> list[Hit]:
    """Pattern 31 — ``Has<Edge>With(<pkg>.<Col>EQ(...))`` ent edge-join
    where the inner column likely has a denormalized mirror on the outer
    entity.

    Predicate (body-local, single-function):
      * body matches ``Has<X>With(<pkg>.<Y>EQ(`` either inline or
        across two adjacent lines (the most common Spark spelling
        splits the args).

    Mirrors L17 PT-L17-002: commit ``e330cd3458`` (PR #6416) replaced
    one such edge-join with a denormalized predicate
    (``CreatedTransactionFinalizedHashEQ``) inside
    ``validateOutputsMatchSenderAndNetwork``. Adjacent unfixed sites
    remain at ``internal_sign_token_handler.go:428`` and
    ``so/tokens/validation.go:136`` per L17 AAE's audit.

    M14-trap: severity Performance / Code-quality. The query plan
    differs (extra join → table scan vs index lookup) but no funds-
    handling boundary is engaged. Promotion requires a runtime PoC of
    DoS via query-plan exploit OR a correctness divergence under a
    specific transaction isolation level.
    """
    hits: list[Hit] = []
    for fn in funcs:
        if str(fn.file).endswith("_test.go"):
            continue
        body = fn.body
        # Try the line-scoped form first, then multi-line.
        m = _ENT_EDGE_JOIN_EQ.search(body)
        if not m:
            m = _ENT_EDGE_JOIN_EQ_MULTILINE.search(body)
        if not m:
            continue
        line_off = body[: m.start()].count("\n")
        snippet_line = fn.body_start_line + line_off
        snippet_lines = body.splitlines()
        snippet = (
            snippet_lines[line_off].strip()
            if line_off < len(snippet_lines) else fn.header
        )
        # Tag the path-class for triage (production handlers vs
        # testing/wallet helpers vs ent schema).
        path_str = str(fn.file)
        if "testing/" in path_str or path_str.startswith("testing"):
            path_class = "testing"
        elif "/ent/" in path_str or path_str.startswith("so/ent"):
            path_class = "ent_schema"
        else:
            path_class = "production"
        hits.append(
            Hit(
                file=str(fn.file),
                line=snippet_line,
                snippet=snippet[:200],
                extra={
                    "function": fn.name,
                    "match_token": m.group(0).strip(),
                    "path_class": path_class,
                },
            )
        )
    return hits


def _detect_zero_or_negative_length_reaches_make_slice(
    funcs: Iterable[GoFunction],
) -> list[Hit]:
    """Pattern 32 — body contains ``make([]byte, n)`` (or
    ``make([]byte, 0, n)``) where ``n`` is the name of an integer-
    typed parameter AND the body has no preceding zero/negative-length
    guard.

    Predicate (body-local, single-function):
      * fn params declare at least one integer-typed parameter
        (``int``/``int8``/``int16``/``int32``/``int64``);
      * fn body contains ``make([]byte, n)`` or ``make([]byte, 0, n)``
        where ``n`` is one of those parameter names;
      * fn body does NOT contain ``n <= 0`` / ``n < 0`` / ``n == 0`` /
        ``n != 0`` / ``n > 0`` / ``n >= 0`` etc. on the SAME parameter
        before the ``make`` call.

    Mirrors Swival #047/#048/#049/#052/#053 — caller-controlled length
    reaches ``make`` and a zero or negative value panics (negative) or
    silently allocates an empty slice (zero), leading to logic errors
    and potential DoS surfaces.

    M14-trap: panic-class shapes are OOS for Spark's bounty rubric
    UNLESS DoS-related and matching the HIGH-1 row precisely. AAK L18
    pre-implementation grep found 0 unsafe Spark hits; if Spark scan
    yields any, default to Informational and require a runtime PoC of
    consumer-reachable DoS for any escalation.
    """
    hits: list[Hit] = []
    for fn in funcs:
        if str(fn.file).endswith("_test.go"):
            continue
        # Collect integer-typed param names.
        int_param_names = set(_INT_PARAM.findall(fn.params))
        if not int_param_names:
            continue
        body = fn.body
        for m in _MAKE_BYTE_SLICE.finditer(body):
            len_expr = m.group("lenexpr")
            if len_expr not in int_param_names:
                continue
            # Look for a preceding guard on this exact param name BEFORE
            # the ``make`` call. We slice the body up to ``m.start()``
            # and search for any comparison ``len_expr <op> 0``.
            prefix = body[: m.start()]
            guarded = False
            for g in _LEN_GUARD.finditer(prefix):
                if g.group("name") == len_expr:
                    guarded = True
                    break
            if guarded:
                continue
            line_off = prefix.count("\n")
            snippet_line = fn.body_start_line + line_off
            snippet_lines = body.splitlines()
            snippet = (
                snippet_lines[line_off].strip()
                if line_off < len(snippet_lines) else fn.header
            )
            hits.append(
                Hit(
                    file=str(fn.file),
                    line=snippet_line,
                    snippet=snippet[:200],
                    extra={
                        "function": fn.name,
                        "param": len_expr,
                    },
                )
            )
            # One report per (fn, param) pair; we break after the first
            # unguarded make-call for this param.
            break
    return hits


def _detect_parse_negative_or_zero_int_unchecked(
    funcs: Iterable[GoFunction],
) -> list[Hit]:
    """Pattern 33 — parsed integer (cryptobyte/asn1/strconv/binary)
    flows into the body without a lower-bound guard.

    Predicate (body-local, single-function):
      * fn body contains a parse-int-style assignment
        ``<dst> := <pkg>.<ParserCall>(...)`` or
        ``<dst>, _ := strconv.ParseInt(...)``;
      * fn body does NOT contain a guard ``<dst> <op> 0`` for the
        same destination identifier (``<=``, ``<``, ``==``, ``!=``,
        ``>``, ``>=``).

    Mirrors Swival #060/#061/#062/#063 — RFC5280 x509 policy fields
    accept negative or zero values where the spec mandates "MUST be
    a non-negative integer", flowing into certificate-path validation
    as a panic / off-by-one surface.

    M14-trap: structural-only. Promoting beyond Informational requires
    a runtime PoC of attacker-supplied bytes producing a downstream
    out-of-bounds / panic / policy-bypass.
    """
    hits: list[Hit] = []
    seen_dsts: set[tuple[str, str]] = set()
    for fn in funcs:
        if str(fn.file).endswith("_test.go"):
            continue
        body = fn.body
        for m in _PARSE_INT_CALL.finditer(body):
            dst = m.group("dst")
            if dst in {"_", "err"}:
                continue
            # De-dupe per (fn, dst).
            key = (str(fn.file) + ":" + fn.name, dst)
            if key in seen_dsts:
                continue
            # Look for a lower-bound guard on `<dst>` ANYWHERE in the
            # body (strict over-approx — if the author guards the value
            # later down the line, we accept the function as defended).
            guarded = False
            for g in _INT_LB_GUARD.finditer(body):
                if g.group("name") == dst:
                    guarded = True
                    break
            if guarded:
                continue
            seen_dsts.add(key)
            line_off = body[: m.start()].count("\n")
            snippet_line = fn.body_start_line + line_off
            body_lines = body.splitlines()
            snippet = (
                body_lines[line_off].strip()
                if line_off < len(body_lines) else fn.header
            )
            hits.append(
                Hit(
                    file=str(fn.file),
                    line=snippet_line,
                    snippet=snippet[:200],
                    extra={
                        "function": fn.name,
                        "dst": dst,
                    },
                )
            )
    return hits


def _detect_scalar_mult_identity_unchecked(
    funcs: Iterable[GoFunction],
) -> list[Hit]:
    """Pattern 34 — body invokes a curve scalar/point op without a
    documented identity-or-on-curve guard.

    Predicate (body-local, single-function):
      * fn body contains a call site of
        ``<x>.ScalarMult`` / ``<x>.ScalarBaseMult`` /
        ``<x>.ScalarMultBase`` / ``<x>.Add`` / ``<x>.Double``;
      * fn body does NOT contain an ``IsOnCurve``/``IsIdentity``/
        ``IsInfinity``/``IsAtInfinity`` call OR a
        ``curve.Params().N``-bound reference anywhere in the body.

    Mirrors Swival #028/#029/#034/#035/#066/#067/#073 — secp / NIST
    curves over malformed (x=0, y=0) or sub-group order points
    silently leak structural invariants.

    M14-trap: structural-only. Suppresses false-positives via the
    helper-function name prefix (``unsafe`` / ``trusted`` / ``verified``
    / ``checked`` are ignored — any Go function whose own NAME contains
    a trust qualifier is treated as a safe internal entry point).
    """
    hits: list[Hit] = []
    safe_name_marker = re.compile(
        r"(?i)\b(?:unsafe|trusted|verified|checked)_?[A-Za-z]"
    )
    for fn in funcs:
        if str(fn.file).endswith("_test.go"):
            continue
        # Allow developer-tagged "trusted" helpers to opt out.
        if safe_name_marker.search(fn.name):
            continue
        body = fn.body
        m = _SCALAR_MULT_CALL.search(body)
        if not m:
            continue
        if _CURVE_VALIDATION_GUARD.search(body):
            continue
        line_off = body[: m.start()].count("\n")
        snippet_line = fn.body_start_line + line_off
        body_lines = body.splitlines()
        snippet = (
            body_lines[line_off].strip()
            if line_off < len(body_lines) else fn.header
        )
        hits.append(
            Hit(
                file=str(fn.file),
                line=snippet_line,
                snippet=snippet[:200],
                extra={
                    "function": fn.name,
                    "call": m.group(0).strip(),
                },
            )
        )
    return hits


def _detect_panic_dereference_before_nil_check(
    funcs: Iterable[GoFunction],
) -> list[Hit]:
    """Pattern 35 — body reads a field on a pointer-typed parameter
    BEFORE any nil-check on the same parameter.

    Predicate (body-local, single-function):
      * fn params declare at least one pointer parameter ``<param> *T``;
      * fn body references ``<param>.<Field>`` somewhere;
      * fn body does NOT contain ``<param> == nil`` or
        ``<param> != nil`` BEFORE the dereference position.

    Mirrors Swival #028/#029/#042/#074 — function accepts a
    ``*Options`` / ``*Config`` / ``*Request`` whose fields are
    read unconditionally; a nil caller (legitimate per Go's
    "zero value is valid" idiom) panics.

    M14-trap: structural-only. Skips test files; reports one hit per
    (fn, param) pair (the first unguarded dereference).
    """
    hits: list[Hit] = []
    for fn in funcs:
        if str(fn.file).endswith("_test.go"):
            continue
        body = fn.body
        # Collect every pointer parameter NAME from the signature.
        ptr_params: list[str] = []
        for m in _PTR_PARAM.finditer(fn.params):
            name = m.group(1)
            if name.startswith("_"):
                continue
            ptr_params.append(name)
        if not ptr_params:
            continue
        for pname in ptr_params:
            deref_re = re.compile(
                r"\b" + re.escape(pname) + r"\.([A-Z][A-Za-z_0-9]*)\b"
            )
            nil_check_re = re.compile(
                r"\b" + re.escape(pname) + r"\s*(?:==|!=)\s*nil\b"
            )
            deref_m = deref_re.search(body)
            if not deref_m:
                continue
            prefix = body[: deref_m.start()]
            if nil_check_re.search(prefix):
                continue
            line_off = body[: deref_m.start()].count("\n")
            snippet_line = fn.body_start_line + line_off
            body_lines = body.splitlines()
            snippet = (
                body_lines[line_off].strip()
                if line_off < len(body_lines) else fn.header
            )
            hits.append(
                Hit(
                    file=str(fn.file),
                    line=snippet_line,
                    snippet=snippet[:200],
                    extra={
                        "function": fn.name,
                        "param": pname,
                        "field": deref_m.group(1),
                    },
                )
            )
            # Only ONE hit per (fn, param) — the first unguarded deref.
            break
    return hits


def _detect_loop_untrusted_length_unbounded(
    funcs: Iterable[GoFunction],
) -> list[Hit]:
    """Pattern 36 — body parses an integer length-prefix and uses it
    as the bound of a loop without enforcing an upper-bound cap.

    Predicate (body-local, single-function):
      * fn body contains a parse-int-style assignment whose
        destination identifier is ``<dst>`` (matches
        ``_PARSE_INT_CALL`` from #33);
      * fn body contains a ``for`` loop where the bound is ``<dst>``
        (matches ``_LOOP_BOUND_USE``);
      * fn body does NOT contain an upper-bound cap on ``<dst>`` —
        i.e. no ``<dst> > <non-zero>`` / ``<dst> >= <something>``
        comparison (lower-bound ``<dst> > 0`` / ``<dst> >= 0`` is
        explicitly NOT counted as a cap).

    Mirrors Swival #010 / #067 — RFC5280-shape parsers reading a
    length-prefix and walking a buffer that long without sanity-
    checking the length against the remaining input. CVE-2025-22871
    shape: TLS-handshake-style length-prefixed protocol parser
    allocates and then iterates over an attacker-controlled length.

    M14-trap: structural-only. CONFIRMED-CANDIDATE only with a runtime
    PoC of attacker-controlled length flowing into the unbounded loop.
    Skips ``*_test.go`` files.
    """
    hits: list[Hit] = []
    seen: set[tuple[str, str]] = set()
    for fn in funcs:
        if str(fn.file).endswith("_test.go"):
            continue
        body = fn.body
        # Step 1: every parsed integer destination
        parsed_dsts: list[tuple[int, str]] = []
        for m in _PARSE_INT_CALL.finditer(body):
            dst = m.group("dst")
            if dst in {"_", "err"}:
                continue
            parsed_dsts.append((m.start(), dst))
        if not parsed_dsts:
            continue
        # Step 2: loop bounds
        loop_bounds: list[tuple[int, str]] = []
        for m in _LOOP_BOUND_USE.finditer(body):
            ident = m.group("bound") or m.group("countdown")
            if ident:
                loop_bounds.append((m.start(), ident))
        if not loop_bounds:
            continue
        # Step 3: upper-bound caps already in body (cap any matched dst)
        capped: set[str] = set()
        for m in _INT_UB_CAP.finditer(body):
            capped.add(m.group("name"))
        # Pair: every (parsed_dst, loop_bound_using_same_name) where
        # the loop start follows the parse start, and the dst is NOT
        # capped anywhere in the body.
        for pstart, pdst in parsed_dsts:
            if pdst in capped:
                continue
            for lstart, lname in loop_bounds:
                if lname != pdst:
                    continue
                if lstart < pstart:
                    # loop precedes parse — not the unbounded shape
                    continue
                key = (str(fn.file) + ":" + fn.name, pdst)
                if key in seen:
                    break
                seen.add(key)
                line_off = body[: lstart].count("\n")
                snippet_line = fn.body_start_line + line_off
                body_lines = body.splitlines()
                snippet = (
                    body_lines[line_off].strip()
                    if line_off < len(body_lines) else fn.header
                )
                hits.append(
                    Hit(
                        file=str(fn.file),
                        line=snippet_line,
                        snippet=snippet[:200],
                        extra={
                            "function": fn.name,
                            "dst": pdst,
                        },
                    )
                )
                break
    return hits


def _detect_counter_wrap_unchecked(
    funcs: Iterable[GoFunction],
) -> list[Hit]:
    """Pattern 37 — body increments a counter-named identifier without
    an overflow / wrap guard.

    Predicate (body-local, single-function):
      * fn body contains an increment of a counter-named identifier
        (``seqNum`` / ``next`` / ``counter`` / ``nonce`` / ``index``)
        via ``++`` / ``+= 1`` / ``atomic.AddUint64(&...n, 1)``;
      * fn body does NOT contain an overflow guard (``math.MaxUint*``,
        ``^uint*(0)``, modulus-reset on the counter, or a ``Reset``/
        ``Rotate``/``Rewind``/``Rekey`` call).

    Mirrors Swival #009 / #044 — counter wrap collisions on per-message
    sequence numbers (gossip replay) or per-block AES-GCM nonces.

    M14-trap: structural-only. Detector telemetry per L20 framing;
    CONFIRMED-CANDIDATE requires a runtime PoC showing a wrap is
    reachable in production. Skips ``*_test.go`` files.
    """
    hits: list[Hit] = []
    seen: set[str] = set()
    for fn in funcs:
        if str(fn.file).endswith("_test.go"):
            continue
        body = fn.body
        m = _COUNTER_INC.search(body)
        if not m:
            continue
        if _COUNTER_WRAP_GUARD.search(body):
            continue
        key = str(fn.file) + ":" + fn.name
        if key in seen:
            continue
        seen.add(key)
        line_off = body[: m.start()].count("\n")
        snippet_line = fn.body_start_line + line_off
        body_lines = body.splitlines()
        snippet = (
            body_lines[line_off].strip()
            if line_off < len(body_lines) else fn.header
        )
        hits.append(
            Hit(
                file=str(fn.file),
                line=snippet_line,
                snippet=snippet[:200],
                extra={
                    "function": fn.name,
                    "stmt": m.group(0).strip()[:80],
                },
            )
        )
    return hits


def _detect_fips_approval_on_uninit(
    funcs: Iterable[GoFunction],
) -> list[Hit]:
    """Pattern 38 — body calls a FIPS approval helper before checking
    that the input is initialised.

    Predicate (body-local, single-function):
      * fn body contains a FIPS-approval-shaped call site
        ``<recv>.<Approved|IsApproved|Validate|Allowed|IsAllowed>(<arg>)``
        where ``<recv>`` references a fips/approve/algo/hash/policy
        token (case-insensitive);
      * fn body does NOT contain an uninit-sentinel guard on
        ``<arg>`` (``<arg> == crypto.Hash(0)`` / ``<arg> == 0`` /
        ``<arg> == nil`` / ``IsZero(<arg>)`` / ``<arg>.IsZero(``)
        BEFORE the approval call.

    Mirrors Swival #075 — Go stdlib FIPS approval gate accepted an
    uninitialised hash and reported it approved, letting non-FIPS
    code paths assert FIPS conformance.

    M14-trap: structural-only. Detector telemetry per L20 framing.
    Skips ``*_test.go`` files.
    """
    hits: list[Hit] = []
    seen: set[tuple[str, str]] = set()
    for fn in funcs:
        if str(fn.file).endswith("_test.go"):
            continue
        body = fn.body
        for m in _FIPS_APPROVAL_CALL.finditer(body):
            recv = m.group("recv")
            arg = m.group("arg")
            if arg in {"_", "err", "nil"}:
                continue
            # The receiver must contain a FIPS / approve / algo /
            # hash / policy token (else this is a generic
            # `.Validate(x)` call — too noisy without the domain
            # qualifier).
            if not _FIPS_RECV_TOKEN.search(recv):
                continue
            # Look for an uninit-sentinel guard on `<arg>` BEFORE the
            # approval call.
            prefix = body[: m.start()]
            uninit_guard = re.compile(
                _FIPS_UNINIT_GUARD_TPL.format(arg=re.escape(arg))
            )
            if uninit_guard.search(prefix):
                continue
            key = (str(fn.file) + ":" + fn.name, arg)
            if key in seen:
                continue
            seen.add(key)
            line_off = body[: m.start()].count("\n")
            snippet_line = fn.body_start_line + line_off
            body_lines = body.splitlines()
            snippet = (
                body_lines[line_off].strip()
                if line_off < len(body_lines) else fn.header
            )
            hits.append(
                Hit(
                    file=str(fn.file),
                    line=snippet_line,
                    snippet=snippet[:200],
                    extra={
                        "function": fn.name,
                        "recv": recv,
                        "call": m.group("call"),
                        "arg": arg,
                    },
                )
            )
    return hits


def _classify_race_suspect(
    rel_path: str, type_name: str, method_name: str,
) -> str:
    """Pattern 39 stage-2 narrowing (L24 ABM) — bucket a candidate
    pattern-39 hit into one of:

      * ``"unmarshaler"`` — encoding/json (or similar) Unmarshaler
        impl. Caller-synchronised by Go convention pre-publish.
      * ``"ent_generated"`` — file lives in an ent-generated package.
        Single-flow caller code; concurrent mutation is a higher-level
        invariant of the caller's transaction layer.
      * ``"setter"`` — ``SetX``/``WithX`` builder/configuration setter.
        Caller-synchronised by Go convention.
      * ``"genuine_concurrent"`` — none of the above. The preserved
        signal class.

    Mirrors L21 ABA pattern #28 refinement shape — additive predicates
    annotate the hit; default-suppress the noise classes; preserve a
    small high-signal class for L25+ deeper investigation.
    """
    # ent-generated — strongest path-based signal. Check first so
    # ent-generated SetX setters bucket as ent_generated rather than
    # setter (more accurate noise origin).
    if _RACE_CLS_ENT_PATH.search(rel_path):
        return "ent_generated"
    # unmarshaler — receiver type-name suffix OR method-name shape.
    if _RACE_CLS_UNMARSHALER_TYPE.search(type_name):
        return "unmarshaler"
    if _RACE_CLS_UNMARSHALER_METHOD.match(method_name):
        return "unmarshaler"
    # setter — Set<X> / With<X> builder pattern.
    if _RACE_CLS_SETTER_METHOD.match(method_name):
        return "setter"
    return "genuine_concurrent"


def _detect_race_unsynchronized_concurrent_access(
    file_sources: dict,
) -> list[Hit]:
    """Pattern 39 — exported method on a pointer receiver mutates a
    self-field WITHOUT any synchronisation primitive in the body.

    Predicate (header-scoped, body-confirmed):
      * method header matches ``func (<recv> *<Type>) <Name>(...)``
        with ``<Name>`` exported (PascalCase first char) and the
        receiver pointer-typed;
      * body assigns to ``<recv>.<field>`` (``=``, ``+=``, ``-=``,
        ``*=``, ``/=``, bitwise-assign, ``++``, ``--``);
      * body does NOT contain ANY synchronisation primitive matching
        ``_RACE_SYNC_PRIMITIVE`` (``Lock``/``Unlock`` calls,
        ``sync.Mutex``/``sync.RWMutex`` declarations, ``atomic.*``
        helpers, channel send/recv).

    L24 ABM stage-2 narrowing (post-L23 ABI 2326-hit Spark fan-out):
      * each surviving candidate is classified into ``suspect_class``
        ∈ {``unmarshaler``, ``ent_generated``, ``setter``,
        ``genuine_concurrent``};
      * ``unmarshaler`` / ``ent_generated`` / ``setter`` are
        DEFAULT-SUPPRESSED — these classes are caller-synchronised by
        Go convention (encoding/json contract pre-publish, ent
        builder transaction layer, single-flow configuration
        builders);
      * ``genuine_concurrent`` is preserved — the residual high-signal
        class for L25+ deeper investigation. Mirrors L21 ABA pattern
        #28 refinement (cut 36→2 while preserving signal class).

    Mirrors Swival #008 / #022 / #027 — TLS / x509 wrappers mutating
    shared state inside an exported method without internal locking.

    M14-trap: structural-only. Detector telemetry per L20 framing;
    CONFIRMED-CANDIDATE only with a runtime PoC of a concurrent
    reachable caller. Skips ``*_test.go`` files; emits one hit per
    ``(<file>, <Type>, <Name>)`` triple.
    """
    hits: list[Hit] = []
    seen: set[tuple[str, str, str]] = set()
    for rel_path, src in file_sources.items():
        if str(rel_path).endswith("_test.go"):
            continue
        for hdr in _METHOD_HEADER.finditer(src):
            recv_name = hdr.group("recv")
            type_name = hdr.group("type")
            method_name = hdr.group("name")
            brace_idx = src.find("{", hdr.end() - 1)
            if brace_idx < 0:
                continue
            end_idx = _balance_braces(src, brace_idx)
            if end_idx is None:
                continue
            body = src[brace_idx + 1:end_idx - 1]
            # Step 1: any self-field assignment via the receiver?
            self_write_re = re.compile(
                _RACE_SELF_WRITE_TPL.format(recv=re.escape(recv_name))
            )
            m_write = self_write_re.search(body)
            if not m_write:
                continue
            # Step 2: is there ANY sync primitive in the body? If yes,
            # we treat the method as defended.
            if _RACE_SYNC_PRIMITIVE.search(body):
                continue
            # Step 3 (L24 ABM stage-2 narrowing): classify and
            # default-suppress noise classes.
            suspect_class = _classify_race_suspect(
                str(rel_path), type_name, method_name
            )
            if suspect_class in ("unmarshaler", "ent_generated", "setter"):
                continue
            key = (str(rel_path), type_name, method_name)
            if key in seen:
                continue
            seen.add(key)
            body_start_line = src.count("\n", 0, brace_idx) + 1
            line_off = body[: m_write.start()].count("\n")
            snippet_line = body_start_line + line_off
            body_lines = body.splitlines()
            snippet = (
                body_lines[line_off].strip()
                if line_off < len(body_lines)
                else f"func ({recv_name} *{type_name}) {method_name}"
            )
            hits.append(
                Hit(
                    file=str(rel_path),
                    line=snippet_line,
                    snippet=snippet[:200],
                    extra={
                        "type": type_name,
                        "method": method_name,
                        "field": m_write.group("field"),
                        "suspect_class": suspect_class,
                    },
                )
            )
    return hits


def _detect_goroutine_fanout_unsync_shared(file_sources: dict) -> list[Hit]:
    """G6 (ADVISORY) - a ``go func(...){...}()`` fan-out whose closure body
    writes a captured non-receiver shared cell (map/slice index, pointer
    deref, or sdk.Context mutating method) with NO mutex/channel/atomic
    guard in the closure body OR the enclosing function scope.

    A ``sync.WaitGroup`` alone does NOT count as a guard (it orders
    completion, not concurrent writes). ``*_test.go`` and generated files
    are skipped. Emits one hit per ``(file,line)`` of the shared write.
    Advisory-first: surfaced only behind ``AUDITOOR_G6_GOROUTINE_FANOUT_
    UNSYNC`` with ``verdict="needs-fuzz"`` (NO auto-credit).
    """
    hits: list[Hit] = []
    seen: set[tuple[str, int]] = set()
    for rel_path, src in file_sources.items():
        p = str(rel_path).replace("\\", "/")
        if p.endswith("_test.go") or _ADV_GENERATED_FILE.search(p):
            continue
        for hdr in _FUNC_HEADER.finditer(src):
            hbrace = src.find("{", hdr.end())
            if hbrace < 0:
                continue
            hend = _balance_braces(src, hbrace)
            if hend is None:
                continue
            enclosing = src[hbrace + 1:hend - 1]
            if "go func" not in enclosing:
                continue
            header_text = src[hdr.start():hbrace]
            rm = _G6_RECV.match(header_text)
            recv = rm.group("recv") if rm else None
            enclosing_guard = bool(_G6_GUARD.search(_strip_comments(enclosing)))
            for gm in _G6_GO_CLOSURE.finditer(enclosing):
                cbrace = enclosing.find("{", gm.end())
                if cbrace < 0:
                    continue
                cend = _balance_braces(enclosing, cbrace)
                if cend is None:
                    continue
                cbody = enclosing[cbrace + 1:cend - 1]
                cparams = gm.group("cparams")
                local = set(re.findall(r"[A-Za-z_]\w*", cparams))
                found = _g6_shared_write(cbody, recv, local)
                if found is None:
                    continue
                wkind, wbase, wmatch = found
                # Guard search: closure body OR enclosing scope. Any
                # mutex/channel/atomic CALL suppresses (FP-guard).
                if enclosing_guard or _G6_GUARD.search(_strip_comments(cbody)):
                    continue
                abs_off = hbrace + 1 + cbrace + 1 + wmatch.start()
                line = src.count("\n", 0, abs_off) + 1
                key = (p, line)
                if key in seen:
                    continue
                seen.add(key)
                ls = src.rfind("\n", 0, abs_off) + 1
                le = src.find("\n", abs_off)
                snippet = src[ls:(le if le >= 0 else len(src))].strip()
                hits.append(
                    Hit(
                        file=str(rel_path),
                        line=line,
                        snippet=snippet[:200],
                        extra={
                            "function": hdr.group("name"),
                            "write_kind": wkind,
                            "shared_base": wbase,
                        },
                    )
                )
    return hits


def _emit_goroutine_fanout_unsync_shared_hypotheses(
    workspace: Path,
    file_sources: dict,
    race_hits: Iterable[Hit],
    *,
    out_path: Path | None = None,
) -> tuple[list[dict], Path]:
    """Advisory G6 emitter. Returns ``(records, out_path)`` and writes a
    ``needs-fuzz`` hypotheses jsonl. De-dups emitted hits against the named
    existing detector ``_detect_race_unsynchronized_concurrent_access``
    (Pattern 39) by ``(file,line)`` (A1 dedup boundary: we do NOT re-derive
    a ``covered_by`` signal, we diff emitted hits vs Pattern 39's hits). NO
    auto-credit: every record carries ``verdict="needs-fuzz"``.
    """
    hits = _detect_goroutine_fanout_unsync_shared(file_sources)
    race_keys = {(h.file, h.line) for h in race_hits}
    records: list[dict] = []
    for h in hits:
        if (h.file, h.line) in race_keys:
            continue  # already surfaced by Pattern 39's receiver-write lane
        records.append({
            "workspace": str(workspace),
            "file": h.file,
            "line": h.line,
            "function": h.extra.get("function"),
            "write_kind": h.extra.get("write_kind"),
            "shared_base": h.extra.get("shared_base"),
            "snippet": h.snippet,
            "pattern_id": G6_FANOUT_PID,
            "attack_class": "concurrency-data-race",
            "exploit_class": G6_FANOUT_EXPLOIT_CLASS,
            "lane": "G6",
            "verdict": "needs-fuzz",
        })
    out = (
        Path(out_path) if out_path
        else workspace / ".auditooor" / G6_FANOUT_OUT
    )
    out.parent.mkdir(parents=True, exist_ok=True)
    text = "".join(json.dumps(r, sort_keys=True) + "\n" for r in records)
    out.write_text(text, encoding="utf-8")
    return records, out


def _detect_onesided_acceptance(
    funcs: Iterable[GoFunction],
) -> list[Hit]:
    """G7 (ADVISORY) - an ``if`` guard keyed on a nonce/seq/sequence-named
    ident whose ``>=`` / ``>`` / ``==`` comparison ADMITS the boundary-equal
    value (the stored counter) into the accept region, with NO strict-
    successor (``== stored + 1``) validation in the enclosing function.

    Polarity-correct: for a REJECT branch (leading bail) ``>`` admits equal
    (FIRE) while ``>=`` rejects it (CLEAN); for an ACCEPT branch ``>=`` /
    ``==`` admit equal (FIRE) while ``>`` does not. See ``_g7_equal_admitted``.

    FP-guard: >=1 operand must be a nonce/seq-named ident, both operands are
    ident/field chains (literal init-checks excluded by the regex), and a
    strict-successor form anywhere in the body suppresses the hit.
    ``*_test.go`` and generated files are skipped. Advisory-first: surfaced
    only behind ``AUDITOOR_G7_ONESIDED_ACCEPTANCE`` with
    ``verdict="needs-fuzz"`` (NO auto-credit).
    """
    hits: list[Hit] = []
    seen: set[tuple[str, int]] = set()
    for fn in funcs:
        fpath = str(fn.file)
        if fpath.endswith("_test.go") or _ADV_GENERATED_FILE.search(
            fpath.replace("\\", "/")
        ):
            continue
        body = fn.body
        # Length-preserving comment/string mask: offsets map 1:1 onto `body`,
        # so `if`/comparison regexes never match inside a comment or literal.
        masked = _g7_mask_comments(body)
        # A correct exact-successor guard elsewhere in the function means the
        # acceptance is not one-sided -> suppress the whole function.
        if _G7_SUCCESSOR.search(masked):
            continue
        for ifm in _G7_IF.finditer(masked):
            cond = masked[ifm.start("cond"):ifm.end("cond")]
            brace_idx = masked.find("{", ifm.end() - 1)
            if brace_idx < 0:
                continue
            end_idx = _balance_braces(masked, brace_idx)
            if end_idx is None:
                continue
            block_body = masked[brace_idx + 1:end_idx - 1]
            kind = _g7_branch_kind(block_body)
            for cm in _G7_CMP.finditer(cond):
                lhs, op, rhs = cm.group("lhs"), cm.group("op"), cm.group("rhs")
                if lhs in _G7_LITERAL_OPERAND or rhs in _G7_LITERAL_OPERAND:
                    continue  # nil/bool checks are not reuse guards
                if not (_g7_is_nonce_ident(lhs) or _g7_is_nonce_ident(rhs)):
                    continue
                if not _g7_equal_admitted(op, kind):
                    continue
                # Offset of the if-header inside the body -> absolute line.
                line_off = body[: ifm.start()].count("\n")
                line = fn.body_start_line + line_off
                key = (fpath, line)
                if key in seen:
                    continue
                seen.add(key)
                body_lines = body.splitlines()
                snippet = (
                    body_lines[line_off].strip()
                    if line_off < len(body_lines) else fn.header
                )
                hits.append(
                    Hit(
                        file=fpath,
                        line=line,
                        snippet=snippet[:200],
                        extra={
                            "function": fn.name,
                            "op": op,
                            "branch_kind": kind,
                            "cmp": (lhs + op + rhs)[:80],
                        },
                    )
                )
                break  # one hit per if-guard
    return hits


def _emit_onesided_acceptance_hypotheses(
    workspace: Path,
    funcs: Iterable[GoFunction],
    skip_lt_hits: Iterable[Hit],
    *,
    out_path: Path | None = None,
) -> tuple[list[dict], Path]:
    """Advisory G7 emitter. Returns ``(records, out_path)`` and writes a
    ``needs-fuzz`` hypotheses jsonl. De-dups emitted hits against the named
    existing detector ``_detect_skip_allowed_strict_lt_only`` (Pattern 40)
    by ``(file,line)`` (A1 dedup boundary: we do NOT re-derive a
    ``covered_by`` signal, we diff emitted hits vs Pattern 40's hits). NO
    auto-credit: every record carries ``verdict="needs-fuzz"``.
    """
    hits = _detect_onesided_acceptance(funcs)
    lt_keys = {(h.file, h.line) for h in skip_lt_hits}
    records: list[dict] = []
    for h in hits:
        if (h.file, h.line) in lt_keys:
            continue  # already surfaced by Pattern 40's strict-``<`` lane
        records.append({
            "workspace": str(workspace),
            "file": h.file,
            "line": h.line,
            "function": h.extra.get("function"),
            "op": h.extra.get("op"),
            "branch_kind": h.extra.get("branch_kind"),
            "cmp": h.extra.get("cmp"),
            "snippet": h.snippet,
            "pattern_id": G7_ONESIDED_PID,
            "attack_class": "nonce-seq-reuse",
            "exploit_class": G7_ONESIDED_EXPLOIT_CLASS,
            "lane": "G7",
            "verdict": "needs-fuzz",
        })
    out = (
        Path(out_path) if out_path
        else workspace / ".auditooor" / G7_ONESIDED_OUT
    )
    out.parent.mkdir(parents=True, exist_ok=True)
    text = "".join(json.dumps(r, sort_keys=True) + "\n" for r in records)
    out.write_text(text, encoding="utf-8")
    return records, out


# ---------------------------------------------------------------------------
# G8 (ADVISORY) - go.crypto.decode_accepts_malformed_then_trusted
# ---------------------------------------------------------------------------
# Fires when a body decodes attacker-controlled bytes (SigToPub / Ecrecover /
# asn1.Unmarshal / ParseCertificate / SetBytes) and the decoded value flows
# (decoder appears BEFORE the sink) into a TRUST sink (Check / Verify /
# PubkeyToAddress+allowlist) with NO canonical well-formedness guard
# (ValidateSignatureValues / low-S / half-order compare / len== / IsZero) in
# the SAME body. Advisory exploit-class axis: signature-malleability /
# malformed-decode-then-trust.
#
# High-FP surface: recover-then-check is idiomatic and malleability is often
# address-irrelevant. FP-guard REQUIRES the impact_contract (decoder value
# reaching a trust sink) AND records a `malleability_matters` heuristic; the
# canonical-guard absence + trust-sink presence + decoder-before-sink flow
# proxy keep the emit tight. Advisory-first (env-gated, OFF by default),
# verdict="needs-fuzz", NO auto-credit.
#
# DEDUP vs Pattern 5/6 (go.consensus.gossip_perimeter_trust): that detector
# = decode-with-NO-verify (a gossip handler missing any VerifySignature);
# G8 = verify-PRESENT-but-decode-lax (a canonical-guard omission on a body
# that DOES reach a trust/verify sink). De-duped by ``(file,line)`` diff vs
# the gossip detector's hits (A1 dedup boundary: we do NOT re-derive a
# ``covered_by`` signal).
G8_DECODE_ENV = "AUDITOOR_G8_DECODE_MALFORMED_TRUSTED"
G8_DECODE_PID = "go.crypto.decode_accepts_malformed_then_trusted"
G8_DECODE_OUT = "decode_malformed_then_trusted_hypotheses.jsonl"
G8_DECODE_EXPLOIT_CLASS = "signature-malleability-decode-trust"

# Decoder call that produces a value from attacker-controlled bytes.
_G8_DECODER = re.compile(
    r"\bcrypto\.SigToPub\s*\(|"
    r"\b(?:crypto\.)?Ecrecover\s*\(|"
    r"\basn1\.Unmarshal\s*\(|"
    r"\b(?:x509\.)?ParseCertificate\s*\(|"
    r"\.SetBytes\s*\("
)
# Family label for the record (first matching arm).
_G8_DECODER_ARMS = (
    ("sig_to_pub", re.compile(r"\bcrypto\.SigToPub\s*\(")),
    ("ecrecover", re.compile(r"\b(?:crypto\.)?Ecrecover\s*\(")),
    ("asn1_unmarshal", re.compile(r"\basn1\.Unmarshal\s*\(")),
    ("parse_certificate", re.compile(r"\b(?:x509\.)?ParseCertificate\s*\(")),
    ("set_bytes", re.compile(r"\.SetBytes\s*\(")),
)
# Trust sink: the AUTHORIZATION decision itself - an allowlist ``Check`` or a
# signature ``Verify``. The impact_contract - the decoded value must reach one
# of these. ``PubkeyToAddress`` is a decode-adjacent TRANSFORM, not itself a
# trust decision (a bare recover-then-display is benign), so it is NOT a sink;
# it only marks the address-allowlist malleability heuristic below.
_G8_TRUST_SINK = re.compile(
    r"\.Check\s*\(|"
    r"\bCheck\s*\(|"
    r"\.Verify\w*\s*\(|"
    r"\bVerify\w+\s*\("
)
# Address-allowlist shape -> malleability is address-based (maybe benign but
# still replay/equivocation-relevant); recorded as the malleability_matters
# heuristic on the record.
_G8_ADDR_ALLOWLIST = re.compile(r"\bPubkeyToAddress\s*\(|\.Check\s*\(")
# Canonical well-formedness / low-S / malleability guard. Presence anywhere
# in the body => the code enforces canonicity => suppress the hit.
_G8_CANONICAL_GUARD = re.compile(
    r"\bValidateSignatureValues\s*\(|"
    r"half[_-]?(?:n|order)\b|secp256k1half|secp256k1n\b|"
    r"\blow[_-]?s\b|"
    r"\.Cmp\s*\([^)]*(?:half|secp256k1)|"
    r"\blen\s*\(\s*[A-Za-z_][\w.\[\]]*\s*\)\s*(?:==|!=)|"
    r"\bIsZero\s*\(",
    re.IGNORECASE,
)


def _g8_decoder_arm(frag: str) -> str:
    """Return the decoder-family label for a matched decoder fragment."""
    for name, rx in _G8_DECODER_ARMS:
        if rx.search(frag):
            return name
    return "decoder"


def _detect_decode_accepts_malformed_then_trusted(
    funcs: Iterable[GoFunction],
) -> list[Hit]:
    """G8 (ADVISORY) - body decodes attacker bytes then trusts the result
    with no canonical guard. See the module-level G8 block for the full
    predicate + dedup rationale.

    Predicate (body-local, single-function):
      * a decoder call (``_G8_DECODER``) is present;
      * a trust sink (``_G8_TRUST_SINK``) appears AFTER the decoder
        (a flow proxy - decoder value reaches the sink) => impact_contract;
      * NO canonical guard (``_G8_CANONICAL_GUARD``) anywhere in the body.

    FP-guard: impact_contract required (no bare decode-then-log); test /
    generated files skipped; ``malleability_matters`` recorded per hit.
    Comment/string interiors are masked length-preserving so offsets map
    1:1 onto ``fn.body``.
    """
    hits: list[Hit] = []
    seen: set[tuple[str, int]] = set()
    for fn in funcs:
        fpath = str(fn.file)
        if _ADV_TEST_FILE.search(fpath) or _ADV_GENERATED_FILE.search(
            fpath.replace("\\", "/")
        ):
            continue
        masked = _g7_mask_comments(fn.body)
        dm = _G8_DECODER.search(masked)
        if dm is None:
            continue
        # Trust sink must appear AFTER the decoder (flow proxy). A sink at or
        # before the decoder is a different value -> not this contract.
        sink_m = None
        for cand in _G8_TRUST_SINK.finditer(masked):
            if cand.start() > dm.end():
                sink_m = cand
                break
        if sink_m is None:
            continue  # impact_contract absent -> decode-then-(log/return)
        # Canonical guard anywhere in body => canonicity enforced => clean.
        if _G8_CANONICAL_GUARD.search(masked):
            continue
        line_off = fn.body[: dm.start()].count("\n")
        line = fn.body_start_line + line_off
        key = (fpath, line)
        if key in seen:
            continue
        seen.add(key)
        body_lines = fn.body.splitlines()
        snippet = (
            body_lines[line_off].strip()
            if line_off < len(body_lines) else fn.header
        )
        decoder = _g8_decoder_arm(dm.group(0))
        sink = sink_m.group(0).strip().rstrip("(").strip().lstrip(".")
        mall_matters = bool(_G8_ADDR_ALLOWLIST.search(masked)) or (
            "Verify" in sink_m.group(0)
        )
        hits.append(
            Hit(
                file=fpath,
                line=line,
                snippet=snippet[:200],
                extra={
                    "function": fn.name,
                    "decoder": decoder,
                    "sink": sink[:40],
                    "impact_contract": f"{decoder}->{sink[:24]}",
                    "malleability_matters": mall_matters,
                },
            )
        )
    return hits


def _emit_decode_malformed_then_trusted_hypotheses(
    workspace: Path,
    funcs: Iterable[GoFunction],
    gossip_hits: Iterable[Hit],
    *,
    out_path: Path | None = None,
) -> tuple[list[dict], Path]:
    """Advisory G8 emitter. Returns ``(records, out_path)`` and writes a
    ``needs-fuzz`` hypotheses jsonl. De-dups emitted hits against the named
    existing detector ``_detect_gossip_perimeter_trust`` (Pattern 5/6) by
    ``(file,line)`` (A1 dedup boundary: we do NOT re-derive a ``covered_by``
    signal, we diff emitted hits vs the gossip detector's hits). NO
    auto-credit: every record carries ``verdict="needs-fuzz"``.
    """
    hits = _detect_decode_accepts_malformed_then_trusted(funcs)
    gossip_keys = {(h.file, h.line) for h in gossip_hits}
    records: list[dict] = []
    for h in hits:
        if (h.file, h.line) in gossip_keys:
            continue  # already surfaced by the gossip-perimeter detector
        records.append({
            "workspace": str(workspace),
            "file": h.file,
            "line": h.line,
            "function": h.extra.get("function"),
            "decoder": h.extra.get("decoder"),
            "sink": h.extra.get("sink"),
            "impact_contract": h.extra.get("impact_contract"),
            "malleability_matters": h.extra.get("malleability_matters"),
            "snippet": h.snippet,
            "pattern_id": G8_DECODE_PID,
            "attack_class": "decode-malformed-then-trust",
            "exploit_class": G8_DECODE_EXPLOIT_CLASS,
            "lane": "G8",
            "verdict": "needs-fuzz",
        })
    out = (
        Path(out_path) if out_path
        else workspace / ".auditooor" / G8_DECODE_OUT
    )
    out.parent.mkdir(parents=True, exist_ok=True)
    text = "".join(json.dumps(r, sort_keys=True) + "\n" for r in records)
    out.write_text(text, encoding="utf-8")
    return records, out


# ---------------------------------------------------------------------------
# G9 (ADVISORY) - go.consensus.decoded_value_consumed_unchecked_type_nil
# ---------------------------------------------------------------------------
# Fires when a body DESERIALIZES attacker-controlled bytes (proto/json/codec/
# asn1/gob Unmarshal, (codectypes.)UnpackAny, Any.GetCachedValue,
# ParseCertificate) and then CONSUMES the decoded value at a type/nil-unsound
# enforcement point - a single-return type assertion that panics on the wrong
# dynamic type, an Any unpacked without the comma-ok/err-checked variant, or a
# decoded-pointer field-deref before any nil-check. Attacker controls the wire
# bytes => controls the decoded value's concrete type / nil-ness => a validator
# panic / type-confusion (consensus-availability / DoS axis).
#
# This is a GENERAL enforcement-point census, NOT a single shape silo: we
# enumerate every consumption point of a deserialized value (Arm A type-assert,
# Arm B Any-unpack, Arm C pointer-deref) and drive the per-point type/nil
# soundness check on each. The load-bearing precision gate is the DECODE-TAINT
# GATE: the body MUST contain a deserialize source AND the consumed expression
# MUST be the decode target (the ``&target`` of Unmarshal/UnpackAny, or a
# ``GetCachedValue()``-shaped receiver) - never an arbitrary interface/pointer.
# That gate is exactly what keeps R9 out of Pattern-35's over-broad
# pointer-param nil-deref set (1418 hits/injective): decode calls are far rarer
# than generic derefs, and we only fire on the deserialize target.
#
# Advisory-first (env-gated, OFF by default), verdict="needs-fuzz", NO
# auto-credit; kept OUT of the ``patterns`` dict so it never feeds go_findings /
# the ``--fire-only`` subset / any L37 gate. A static hit alone is needs-fuzz: a
# CONFIRMED needs a runtime path delivering the malformed/type-mismatched bytes
# to the consumption point.
#
# DEDUP (A1 boundary - diff emitted ``(file,line)``, do NOT re-derive a
# covered_by):
#   * Pattern 35 ``go.go.panic.dereference_before_nil_check`` = generic
#     pointer-PARAM nil-deref with NO decode gate (FIRE-EXCLUDED for breadth).
#     R9 Arm C is a strict decode-taint-gated SUBSET (only the deserialize
#     target). We pass Pattern 35's hits as the emitter dedup prior and diff by
#     ``(file,line)`` - this is also the precision boundary keeping R9 out of
#     the Pattern-35 noise trap.
#   * G8 ``decode_accepts_malformed_then_trusted`` = decode -> crypto
#     trust-sink (signature malleability); R9 = decode -> type-assert / nil-deref
#     (Go type-system / nil trust) - a DIFFERENT enforcement axis. Same decode
#     source, different sink; diff by ``(file,line)`` vs G8 to avoid restating a
#     line.
#   * G5 ``unmarshal_type_ambiguity_first_match`` needs >=2 rival decodes of ONE
#     buffer (decode-CHOICE determinism); R9 fires on the assert/deref of a
#     SINGLE decoded value - orthogonal shape, noted not diffed.
G9_DECODE_CONSUME_ENV = "AUDITOOR_G9_DECODE_CONSUMPTION_TYPE_NIL"
G9_DECODE_CONSUME_PID = "go.consensus.decoded_value_consumed_unchecked_type_nil"
G9_DECODE_CONSUME_OUT = "decode_consumption_type_nil_hypotheses.jsonl"
G9_DECODE_CONSUME_EXPLOIT_CLASS = "decode-consumption-type-confusion-nil-panic"

# DECODE-TAINT GATE: a deserialize source. Body must contain >=1 of these or the
# whole function is skipped (this is what separates R9 from the generic
# pointer-deref / bare-assert space).
_G9_DECODE = re.compile(
    r"\bproto\.Unmarshal\s*\(|"
    r"\bjson\.Unmarshal\s*\(|"
    r"\bcodec\.Unmarshal\s*\(|"
    r"\basn1\.Unmarshal\s*\(|"
    r"\bgob\.\w*Decode\w*\s*\(|"
    r"\b(?:x509\.)?ParseCertificate\s*\(|"
    r"\.Unmarshal\s*\(|"
    r"\b(?:codectypes\.)?UnpackAny\s*\(|"
    r"\.GetCachedValue\s*\("
)
# The ``&target`` argument of an Unmarshal / UnpackAny call -> ``target`` is the
# decode target (tainted). Captures the pointed-at ident.
_G9_UNMARSHAL_TARGET = re.compile(
    r"(?:Unmarshal|UnpackAny)\s*\([^)]*?&\s*([A-Za-z_]\w*)"
)
# A type assertion ``<expr>.(<Type>)``. ``<expr>`` is an ident / dotted chain
# optionally ending in an empty ``()`` call (so ``any.GetCachedValue()`` is
# captured whole). The ``.(type)`` type-switch head is excluded downstream
# (typ == "type").
_G9_ASSERT = re.compile(
    r"(?P<expr>[A-Za-z_][\w.]*(?:\(\s*\))?)\s*\.\(\s*(?P<typ>[\w.\*\[\]]+)\s*\)"
)
# comma-ok binding directly preceding the asserted expr: ``, ok := <expr>.(T)``
# / ``, ok = <expr>.(T)``. Applied to the body slice ENDING at the expr start.
_G9_COMMAOK_PREFIX = re.compile(r",\s*[A-Za-z_]\w*\s*(?::=|=)\s*$")
# An Any ``GetCachedValue()`` result field-dereferenced directly (``.Field``,
# uppercase) with no comma-ok / nil guard - the non-assert Any consumption.
_G9_CACHED_FIELD_DEREF = re.compile(
    r"\.GetCachedValue\s*\(\s*\)\s*\.\s*[A-Z]\w*"
)
# An err-checked inline UnpackAny: ``if err := ...UnpackAny(...&x...); err != nil``
# The target ``x`` is then validated -> suppressed. Captures the target ident.
_G9_UNPACK_ERRCHECKED = re.compile(
    r"if\s+\w+\s*:?=\s*[^;{}\n]*UnpackAny\s*\([^;{}\n]*&\s*([A-Za-z_]\w*)"
    r"[^;{}\n]*;\s*\w+\s*!=\s*nil"
)


def _g9_base_ident(expr: str) -> str:
    """Leading ident of an assert expr (``any.GetCachedValue()`` -> ``any``)."""
    m = re.match(r"[A-Za-z_]\w*", expr)
    return m.group(0) if m else ""


def _g9_target_is_pointer(
    masked_body: str, params: str, receiver: str, pname: str
) -> bool:
    """ARM-C PRECISION GATE. True only when the decode target ``pname`` is a
    POINTER (nil-able), False for a VALUE struct captured by ``&valueVar``.

    Arm C flags a decode-target field-deref before a nil-check - but a nil-deref
    only *exists* for a pointer target. The value-decode idiom
    ``var dec T; json.Unmarshal(data, &dec); use dec.Field`` captures ``dec`` via
    ``&dec`` YET ``dec`` is a value struct that can NEVER be nil, so the
    field-deref is sound and must stay SILENT (the optimism 29/36, polygon 96/123
    arm-C value-target FP class). Only the genuine pointer forms fire:
      * ``var pname *T``           - a pointer variable declaration;
      * ``pname := new(T)``        - ``new`` returns ``*T``;
      * ``pname := &...``          - address-of (incl. ``&T{}``) yields a pointer;
      * ``pname *T`` in the params / receiver - a pointer parameter.
    Contrast the value forms (``var pname T`` / ``pname := T{}`` /
    ``pname := f()``), which return False -> arm C is suppressed.
    """
    esc = re.escape(pname)
    # (1) ``var pname *T`` - a pointer variable declaration.
    if re.search(r"\bvar\s+" + esc + r"\s+\*", masked_body):
        return True
    # (2) ``pname := new(T)`` / ``pname = new(T)`` - ``new`` returns ``*T``.
    if re.search(r"\b" + esc + r"\s*(?::=|=)\s*new\s*\(", masked_body):
        return True
    # (3) ``pname := &...`` / ``pname = &...`` (incl. ``&T{}``) - a pointer.
    if re.search(r"\b" + esc + r"\s*(?::=|=)\s*&", masked_body):
        return True
    # (4) a pointer parameter / receiver ``pname *T``.
    if re.search(r"\b" + esc + r"\s+\*", params + " " + receiver):
        return True
    return False


def _detect_decoded_value_consumed_unchecked_type_nil(
    funcs: Iterable[GoFunction],
) -> list[Hit]:
    """G9 (ADVISORY) - a body deserializes attacker bytes then consumes the
    decoded value at a type/nil-unsound enforcement point. See the module-level
    G9 block for the full predicate + FP-guard + dedup rationale.

    GENERAL enforcement-point logic (body-local, single-function): gate on a
    decode source, capture the decode-target ident(s), then drive three
    consumption-point soundness checks over the tainted value -

      * Arm A - a single-return type assertion ``<expr>.(T)`` where ``<expr>``
        is decode-tainted (a decode-target ident), that is NOT comma-ok and NOT
        a ``switch <x>.(type)`` head -> panics on wrong dynamic type.
      * Arm B - an ``Any`` consumed via ``GetCachedValue()`` and immediately
        single-return ``.(T)``-asserted or ``.Field``-dereferenced (the checked
        comma-ok / err-checked variant absent).
      * Arm C - a decode-target POINTER field-deref ``<target>.<Field>`` before
        any nil-check on ``<target>`` (scoped to the decode target only - never
        an arbitrary pointer param, which is Pattern 35's over-broad set).

    FP-guards (suppress): comma-ok on the same asserted expr; ``switch
    <x>.(type)`` on the same base ident; a ``<target> == nil`` / ``!= nil`` /
    ``errors.Is`` guard before the deref; an err-checked ``UnpackAny``. One Hit
    per ``(fn, file, line)``. ``*_test.go`` / generated files skipped;
    comment/string interiors masked length-preserving so offsets map 1:1 onto
    ``fn.body``.
    """
    hits: list[Hit] = []
    for fn in funcs:
        fpath = str(fn.file)
        if _ADV_TEST_FILE.search(fpath) or _ADV_GENERATED_FILE.search(
            fpath.replace("\\", "/")
        ):
            continue
        masked = _g7_mask_comments(fn.body)
        dm = _G9_DECODE.search(masked)
        if dm is None:
            continue  # DECODE-TAINT GATE: no deserialize source -> skip fn.
        decode_source = dm.group(0).strip().rstrip("(").strip().lstrip(".")
        # Decode-target idents: the ``&target`` of every Unmarshal/UnpackAny.
        targets = {
            m.group(1) for m in _G9_UNMARSHAL_TARGET.finditer(masked)
        }
        # err-checked UnpackAny targets are validated -> drop from the set.
        errchecked = {
            m.group(1) for m in _G9_UNPACK_ERRCHECKED.finditer(masked)
        }
        targets -= errchecked
        body_lines = fn.body.splitlines()
        seen_lines: set[int] = set()

        def _emit(pos: int, arm: str, consumed: str, typ: str) -> None:
            line_off = fn.body[:pos].count("\n")
            line = fn.body_start_line + line_off
            if line in seen_lines:
                return  # one Hit per (fn,file,line)
            seen_lines.add(line)
            snippet = (
                body_lines[line_off].strip()
                if line_off < len(body_lines) else fn.header
            )
            hits.append(
                Hit(
                    file=fpath,
                    line=line,
                    snippet=snippet[:200],
                    extra={
                        "function": fn.name,
                        "arm": arm,
                        "decode_source": decode_source[:40],
                        "consumed_expr": consumed[:60],
                        "asserted_type": typ[:40],
                    },
                )
            )

        # ---- ARM A / ARM B: type assertions on a decode-tainted value -------
        for am in _G9_ASSERT.finditer(masked):
            typ = am.group("typ")
            if typ == "type":
                continue  # ``switch x.(type)`` head, not a panicking assert.
            expr = am.group("expr")
            base = _g9_base_ident(expr)
            is_cached = "GetCachedValue" in expr
            if not (is_cached or base in targets):
                continue  # not decode-tainted -> Pattern-35 space, excluded.
            # comma-ok binding this assert (``v, ok := expr.(T)`` / ``= expr.(T)``).
            # Go's comma-ok assertion ALWAYS binds the two-value result on the
            # immediate LHS of the SAME statement, so the direct-prefix check is
            # complete for the real comma-ok form on this expr.
            if _G9_COMMAOK_PREFIX.search(masked[: am.start("expr")]):
                continue
            # ``switch <base>.(type)`` consumes the value type-safely -> suppress.
            typeswitch = re.compile(
                re.escape(base) + r"[\w.]*\s*\.\(\s*type\s*\)"
            )
            if typeswitch.search(masked):
                continue
            _emit(
                am.start(),
                "B" if is_cached else "A",
                expr,
                typ,
            )

        # ---- ARM B (field-deref): Any.GetCachedValue().Field, no err-check ---
        # Only when no UnpackAny was err-checked in the body (the checked
        # variant would validate the cached value).
        if not errchecked:
            for cm in _G9_CACHED_FIELD_DEREF.finditer(masked):
                _emit(cm.start(), "B", cm.group(0).strip(), "")

        # ---- ARM C: decode-target POINTER field-deref before any nil-check ---
        # PRECISION GATE (value-target FP kill): arm C's nil-deref only exists
        # when the decode target is a POINTER. The value-decode idiom
        # ``var dec T; json.Unmarshal(data, &dec); use dec.Field`` captures
        # ``dec`` via ``&dec`` YET ``dec`` is a value struct that can NEVER be
        # nil, so the field-deref is sound - it must stay SILENT (the optimism
        # 29/36, polygon 96/123 arm-C value-target FP rows). Fire only when
        # ``pname`` is declared / parametrised as a pointer.
        for pname in targets:
            if not _g9_target_is_pointer(
                masked, fn.params, fn.receiver, pname
            ):
                continue  # value struct captured by &var -> never nil -> clean.
            deref_re = re.compile(
                r"\b" + re.escape(pname) + r"\.([A-Z][A-Za-z_0-9]*)\b"
            )
            nil_re = re.compile(
                r"\b" + re.escape(pname) + r"\s*(?:==|!=)\s*nil\b"
                r"|errors\.Is\s*\([^)]*\b" + re.escape(pname) + r"\b"
            )
            deref_m = deref_re.search(masked)
            if deref_m is None:
                continue
            if nil_re.search(masked[: deref_m.start()]):
                continue  # nil-guarded before the deref -> clean.
            _emit(
                deref_m.start(),
                "C",
                pname + "." + deref_m.group(1),
                "",
            )
    return hits


def _emit_decode_consumption_type_nil_hypotheses(
    workspace: Path,
    funcs: Iterable[GoFunction],
    dereference_before_nil_hits: Iterable[Hit],
    *,
    out_path: Path | None = None,
) -> tuple[list[dict], Path]:
    """Advisory G9 emitter. Returns ``(records, out_path)`` and writes a
    ``needs-fuzz`` hypotheses jsonl. De-dups emitted hits against Pattern 35
    ``_detect_panic_dereference_before_nil_check`` (the generic pointer-deref
    detector R9 Arm C is a strict decode-taint-gated subset of) by
    ``(file,line)`` (A1 dedup boundary: we do NOT re-derive a ``covered_by``
    signal). NO auto-credit: every record carries ``verdict="needs-fuzz"``.
    """
    hits = _detect_decoded_value_consumed_unchecked_type_nil(funcs)
    prior_keys = {(h.file, h.line) for h in dereference_before_nil_hits}
    records: list[dict] = []
    for h in hits:
        if (h.file, h.line) in prior_keys:
            continue  # already surfaced by Pattern 35's generic deref detector
        records.append({
            "workspace": str(workspace),
            "file": h.file,
            "line": h.line,
            "function": h.extra.get("function"),
            "arm": h.extra.get("arm"),
            "decode_source": h.extra.get("decode_source"),
            "consumed_expr": h.extra.get("consumed_expr"),
            "asserted_type": h.extra.get("asserted_type"),
            "snippet": h.snippet,
            "pattern_id": G9_DECODE_CONSUME_PID,
            "attack_class": "decode-consumption-unchecked-type-nil",
            "exploit_class": G9_DECODE_CONSUME_EXPLOIT_CLASS,
            "lane": "G9",
            "verdict": "needs-fuzz",
        })
    out = (
        Path(out_path) if out_path
        else workspace / ".auditooor" / G9_DECODE_CONSUME_OUT
    )
    out.parent.mkdir(parents=True, exist_ok=True)
    text = "".join(json.dumps(r, sort_keys=True) + "\n" for r in records)
    out.write_text(text, encoding="utf-8")
    return records, out


# ---------------------------------------------------------------------------
# G11 - go.panic.untrusted_ingress_unbounded_loop_or_panic (advisory, gated).
# ---------------------------------------------------------------------------
# A value that enters through an EXTERNAL ingress (a Cosmos-SDK ``sdk.Msg``
# method - ValidateBasic / a Msg receiver - or a gRPC handler taking a
# ``*...Request``) reaches an UNBOUNDED sink (``for range``, ``make([]T,n)``,
# an index ``x[taint]``, or a ``/`` / ``%`` divisor) with NO dominating
# ``len(...)`` / zero guard on that taint root BEFORE the sink. Attacker
# controls the slice length / index / divisor -> DoS (unbounded work / OOM)
# or a panic. Advisory-first (env-gated, OFF by default), verdict=needs-fuzz,
# NO auto-credit.
#
# TAINT-GATE (real external entry point): we only taint a var that is either
# the receiver of a ``Msg*`` type OR a ``*...Request`` param - not any local.
# This is what stops it re-deriving the two overlapping signals below.
#
# DEDUP (A1 boundary - diff emitted hits, do NOT re-derive a covered_by):
#   * fire7 ``go_ast_dos_cap_unbounded_input_growth_fire7`` cap-growth AND its
#     in-file analog Pattern 36 ``go.crypto.loop.untrusted_length_unbounded``
#     (parse-int length-prefix -> loop): drop a (file,line) already surfaced
#     there so the range/make arm never restates the growth signal;
#   * ``gas_price_zero`` (Pattern 11 div-by-zero panic): drop a (file,line)
#     already surfaced there so the div arm never restates the panic signal.
#   * Rust RU1 overlap is cross-language; the taint-gate keeps this Go-only.
G11_INGRESS_ENV = "AUDITOOR_G11_INGRESS_UNBOUNDED_PANIC"
G11_INGRESS_PID = "go.panic.untrusted_ingress_unbounded_loop_or_panic"
G11_INGRESS_OUT = "ingress_unbounded_loop_or_panic_hypotheses.jsonl"
G11_INGRESS_EXPLOIT_CLASS = "untrusted-ingress-unbounded-dos-or-panic"

# Receiver whose TYPE is Msg-shaped (``*MsgClaimSpecific`` / ``Msg...``): the
# canonical Cosmos external ingress (sdk.Msg interface methods, msg handlers).
_G11_MSG_RECV = re.compile(r"^\s*(?P<var>\w+)\s+\*?\s*\w*Msg\w*")
# gRPC handler param: ``name *pkg.FooRequest`` (external ingress).
_G11_REQ_PARAM = re.compile(r"(?P<var>\w+)\s+\*?\s*[\w.]*Request\b")
# Handler-shaped fn names that ARE external entry points even w/o the above.
_G11_ENTRY_NAME = re.compile(r"^ValidateBasic$")
# Accessor / serializer methods are NOT ingress handlers - they run on
# already-decoded state (getters, proto (un)marshal, String). A missing
# len-cap there is not the ingress-DoS contract, so they are excluded to
# keep the FP surface tight (getter-shape FP flood otherwise).
_G11_ACCESSOR_NAME = re.compile(
    r"^(?:Get|Set|Unpack|Pack|Marshal|Unmarshal|String|Reset|Size|"
    r"Descriptor|ProtoMessage|Equal|Clone|Copy|Hash|Bytes|Format)\w*$"
    r"|^XXX_"
)


def _g11_taint_roots(fn: "GoFunction") -> tuple[set[str], str]:
    """Return ``(roots, entry_kind)`` - the set of externally-tainted var
    names for ``fn`` and the ingress kind label. Empty roots => not an
    external entry point => the taint-gate excludes it."""
    roots: set[str] = set()
    kind = ""
    if _G11_ACCESSOR_NAME.match(fn.name):
        return roots, kind  # accessor/serializer, not an ingress handler
    rm = _G11_MSG_RECV.match(fn.receiver)
    if rm:
        roots.add(rm.group("var"))
        kind = "msg"
    for pm in _G11_REQ_PARAM.finditer(fn.params):
        roots.add(pm.group("var"))
        kind = kind or "rpc"
    # A Msg receiver whose var we already have but the fn is ValidateBasic:
    # kind stays "msg". If no receiver/param matched but the name is a known
    # ingress method, we still need a taint root - fall back to the receiver
    # var (first token) so ValidateBasic on a non-"Msg" receiver is covered.
    if not roots and _G11_ENTRY_NAME.match(fn.name) and fn.receiver:
        first = fn.receiver.split()[0]
        if first and first != "_":
            roots.add(first)
            kind = "msg"
    return roots, kind


def _g11_sink(masked: str, root: str) -> tuple[int, str] | None:
    """First unbounded sink over ``root`` in ``masked`` body. Returns
    ``(offset, kind)`` for the earliest of: ``range`` / ``make`` / index /
    div-mod, or ``None``. ``kind`` in {range, make_slice, index, divmod}."""
    r = re.escape(root)
    cands: list[tuple[int, str]] = []
    m = re.search(r"\brange\s+" + r + r"\b", masked)
    if m:
        cands.append((m.start(), "range"))
    m = re.search(
        r"\bmake\s*\(\s*\[\][\w.\*\[\]]*\s*,\s*[^,)]*\b" + r + r"\b", masked
    )
    if m:
        cands.append((m.start(), "make_slice"))
    m = re.search(r"\w+\s*\[\s*" + r + r"\b", masked)
    if m:
        cands.append((m.start(), "index"))
    m = re.search(r"[/%]\s*" + r + r"\b", masked)
    if m:
        cands.append((m.start(), "divmod"))
    if not cands:
        return None
    cands.sort(key=lambda t: t[0])
    return cands[0]


def _g11_guard_before(masked: str, root: str, sink_off: int) -> bool:
    """True iff a dominating ``len(root)`` / ``root ==/!= 0|nil`` / IsZero
    guard on ``root`` appears BEFORE ``sink_off`` (dominates the sink)."""
    r = re.escape(root)
    guard = re.compile(
        r"\blen\s*\(\s*" + r + r"\b"
        r"|\b" + r + r"[\w.]*\s*(?:==|!=|<=|>=|<|>)\s*(?:0|nil)\b"
        r"|\b" + r + r"[\w.]*\.IsZero\s*\("
    )
    for gm in guard.finditer(masked):
        if gm.start() < sink_off:
            return True
    return False


def _detect_ingress_unbounded_loop_or_panic(
    funcs: Iterable[GoFunction],
) -> list[Hit]:
    """G11 (ADVISORY) - external-ingress value reaches an unbounded
    range/make/index/div sink with no dominating len/zero guard. See the
    module-level G11 block for the full predicate + dedup rationale.

    FP-guard: taint root MUST be a Msg receiver or ``*...Request`` param
    (real external entry point, not any local); guard must be ABSENT before
    the sink; ``*_test.go`` / generated files skipped; comment / string
    interiors masked length-preserving so offsets map 1:1 onto ``fn.body``.
    The benign sibling (a ValidateBasic that caps ``len`` before the range)
    is suppressed by ``_g11_guard_before``.
    """
    hits: list[Hit] = []
    seen: set[tuple[str, int, str]] = set()
    for fn in funcs:
        fpath = str(fn.file)
        if _ADV_TEST_FILE.search(fpath) or _ADV_GENERATED_FILE.search(
            fpath.replace("\\", "/")
        ):
            continue
        roots, kind = _g11_taint_roots(fn)
        if not roots:
            continue  # taint-gate: not an external entry point
        masked = _g7_mask_comments(fn.body)
        for root in sorted(roots):
            sk = _g11_sink(masked, root)
            if sk is None:
                continue
            sink_off, sink_kind = sk
            if _g11_guard_before(masked, root, sink_off):
                continue  # dominating len/zero guard -> benign
            line_off = fn.body[:sink_off].count("\n")
            line = fn.body_start_line + line_off
            key = (fpath, line, sink_kind)
            if key in seen:
                continue
            seen.add(key)
            body_lines = fn.body.splitlines()
            snippet = (
                body_lines[line_off].strip()
                if line_off < len(body_lines) else fn.header
            )
            hits.append(
                Hit(
                    file=fpath,
                    line=line,
                    snippet=snippet[:200],
                    extra={
                        "function": fn.name,
                        "receiver": fn.receiver[:60],
                        "taint_root": root,
                        "entry_kind": kind,
                        "sink": sink_kind,
                        "impact_contract": f"{kind}:{root}->{sink_kind}",
                    },
                )
            )
    return hits


def _emit_ingress_unbounded_loop_or_panic_hypotheses(
    workspace: Path,
    funcs: Iterable[GoFunction],
    growth_hits: Iterable[Hit],
    gas_price_hits: Iterable[Hit],
    *,
    out_path: Path | None = None,
) -> tuple[list[dict], Path]:
    """Advisory G11 emitter. Returns ``(records, out_path)`` and writes a
    ``needs-fuzz`` hypotheses jsonl. De-dups emitted hits against the named
    existing detectors - Pattern 36 ``loop.untrusted_length_unbounded`` (the
    in-file analog of fire7 cap-growth) and Pattern 11 ``gas_price_zero`` -
    by ``(file,line)`` (A1 dedup boundary: we do NOT re-derive a
    ``covered_by`` signal, we diff emitted hits vs those detectors' hits). NO
    auto-credit: every record carries ``verdict="needs-fuzz"``.
    """
    hits = _detect_ingress_unbounded_loop_or_panic(funcs)
    covered = {(h.file, h.line) for h in growth_hits}
    covered |= {(h.file, h.line) for h in gas_price_hits}
    records: list[dict] = []
    for h in hits:
        if (h.file, h.line) in covered:
            continue  # already surfaced by growth / gas-price detector
        records.append({
            "workspace": str(workspace),
            "file": h.file,
            "line": h.line,
            "function": h.extra.get("function"),
            "receiver": h.extra.get("receiver"),
            "taint_root": h.extra.get("taint_root"),
            "entry_kind": h.extra.get("entry_kind"),
            "sink": h.extra.get("sink"),
            "impact_contract": h.extra.get("impact_contract"),
            "snippet": h.snippet,
            "pattern_id": G11_INGRESS_PID,
            "attack_class": "untrusted-ingress-unbounded",
            "exploit_class": G11_INGRESS_EXPLOIT_CLASS,
            "lane": "G11",
            "verdict": "needs-fuzz",
        })
    out = (
        Path(out_path) if out_path
        else workspace / ".auditooor" / G11_INGRESS_OUT
    )
    out.parent.mkdir(parents=True, exist_ok=True)
    text = "".join(json.dumps(r, sort_keys=True) + "\n" for r in records)
    out.write_text(text, encoding="utf-8")
    return records, out


# ---------------------------------------------------------------------------
# G12 - go.go.panic.goroutine_no_toplevel_recover (advisory, env-gated).
# ---------------------------------------------------------------------------
# A ``go func(...){...}()`` spawn whose brace-balanced closure body has ZERO
# ``recover(`` call. A panic inside a bare goroutine is NOT recoverable by the
# caller (recover only works IN the panicking goroutine's own stack), so a
# panicking callee reachable from the closure crashes the WHOLE process. This
# is the structural reachable-panic axis (M14-trap): a CONFIRMED needs a
# runtime panicking-callee path, hence verdict=needs-fuzz, NO auto-credit.
#
# FP-guard (high FP surface): many goroutines are supervised / short-lived or
# their callee cannot panic -> the CLEAN sibling is a ``go func`` WHOSE body
# DOES contain ``recover(`` (searched IN the closure body only - a caller-scope
# recover is useless and does NOT suppress). ``*_test.go`` / testdata /
# generated files are skipped. Comment/string interiors are stripped so a
# ``// recover()`` comment never counts as a guard.
#
# DEDUP (A1 boundary - diff emitted hits, do NOT re-derive a covered_by):
#   * G6 ``goroutine_fanout_unsync_shared`` is the sibling goroutine-closure
#     detector; we drop a (file,line) it already surfaced so the panic arm
#     never restates a goroutine G6 already flagged.
G12_NORECOVER_ENV = "AUDITOOR_G12_GOROUTINE_NO_RECOVER"
G12_NORECOVER_PID = "go.go.panic.goroutine_no_toplevel_recover"
G12_NORECOVER_OUT = "goroutine_no_toplevel_recover_hypotheses.jsonl"
G12_NORECOVER_EXPLOIT_CLASS = "goroutine-panic-process-crash"


def _detect_goroutine_no_toplevel_recover(file_sources: dict) -> list[Hit]:
    """G12 (ADVISORY) - a ``go func(...){...}()`` spawn whose brace-balanced
    closure body contains ZERO ``recover(`` call. See the module-level G12
    block for the full predicate + FP-guard + dedup rationale.

    Emits one hit per ``(file,line)`` of the ``go func`` spawn. ``*_test.go``,
    ``/testdata/`` and generated files are skipped. Advisory-first: surfaced
    only behind ``AUDITOOR_G12_GOROUTINE_NO_RECOVER`` with
    ``verdict="needs-fuzz"`` (NO auto-credit).
    """
    hits: list[Hit] = []
    seen: set[tuple[str, int]] = set()
    for rel_path, src in file_sources.items():
        p = str(rel_path).replace("\\", "/")
        if (_ADV_TEST_FILE.search(p) or "/testdata/" in p
                or _ADV_GENERATED_FILE.search(p)):
            continue
        for gm in _G6_GO_CLOSURE.finditer(src):
            cbrace = src.find("{", gm.end())
            if cbrace < 0:
                continue
            cend = _balance_braces(src, cbrace)
            if cend is None:
                continue
            cbody = src[cbrace + 1:cend - 1]
            # recover MUST be IN the goroutine body (caller-scope is useless).
            if "recover(" in _strip_comments(cbody).replace(" ", ""):
                continue  # benign sibling: goroutine WITH recover()
            line = src.count("\n", 0, gm.start()) + 1
            key = (p, line)
            if key in seen:
                continue
            seen.add(key)
            ls = src.rfind("\n", 0, gm.start()) + 1
            le = src.find("\n", gm.start())
            snippet = src[ls:(le if le >= 0 else len(src))].strip()
            hits.append(
                Hit(
                    file=str(rel_path),
                    line=line,
                    snippet=snippet[:200],
                    extra={"closure_params": gm.group("cparams").strip()},
                )
            )
    return hits


def _emit_goroutine_no_toplevel_recover_hypotheses(
    workspace: Path,
    file_sources: dict,
    fanout_hits: Iterable[Hit],
    *,
    out_path: Path | None = None,
) -> tuple[list[dict], Path]:
    """Advisory G12 emitter. Returns ``(records, out_path)`` and writes a
    ``needs-fuzz`` hypotheses jsonl. De-dups emitted hits against the named
    existing detector ``_detect_goroutine_fanout_unsync_shared`` (G6) by
    ``(file,line)`` (A1 dedup boundary: we do NOT re-derive a ``covered_by``
    signal, we diff emitted hits vs G6's hits). NO auto-credit: every record
    carries ``verdict="needs-fuzz"``.
    """
    hits = _detect_goroutine_no_toplevel_recover(file_sources)
    covered = {(h.file, h.line) for h in fanout_hits}
    records: list[dict] = []
    for h in hits:
        if (h.file, h.line) in covered:
            continue  # already surfaced by G6's goroutine-fanout lane
        records.append({
            "workspace": str(workspace),
            "file": h.file,
            "line": h.line,
            "closure_params": h.extra.get("closure_params"),
            "snippet": h.snippet,
            "pattern_id": G12_NORECOVER_PID,
            "attack_class": "reachable-panic-goroutine",
            "exploit_class": G12_NORECOVER_EXPLOIT_CLASS,
            "lane": "G12",
            "verdict": "needs-fuzz",
        })
    out = (
        Path(out_path) if out_path
        else workspace / ".auditooor" / G12_NORECOVER_OUT
    )
    out.parent.mkdir(parents=True, exist_ok=True)
    text = "".join(json.dumps(r, sort_keys=True) + "\n" for r in records)
    out.write_text(text, encoding="utf-8")
    return records, out


# ---------------------------------------------------------------------------
# G5 (ADVISORY) - go.consensus.unmarshal_type_ambiguity_first_match
# ---------------------------------------------------------------------------
# Fires when a single body attempts >=2 ``proto.Unmarshal`` decodes of the SAME
# bytes argument into DISTINCT target types under a first-``== nil``-wins accept
# ladder, with NO TypeUrl / version discriminator dispatching the choice. protobuf
# wire encoding is not self-describing, so a payload that decodes cleanly into
# more than one message type is a differential-decode ambiguity: two honest nodes
# (or a node vs. a hashing/indexing peer) can pick DIFFERENT concrete types for
# the same bytes and diverge -> a consensus-determinism axis defect (E1 Go-
# instantiation family). Static hit alone = needs-fuzz; genuine divergence is
# confirmed by the E1 differential-fuzz (feed one payload, assert both decode
# lanes agree on the chosen type).
#
# Predicate (body-local, single-function):
#   * >=2 ``proto.Unmarshal(arg, &target)`` calls share the SAME first (bytes)
#     arg, into >=2 DISTINCT target idents;
#   * the accept is first-``== nil``-wins (>=2 of those calls sit in a
#     ``proto.Unmarshal(arg, ...) == nil`` accept form);
#   * NO TypeUrl / version discriminator (``TypeUrl`` / ``GetTypeUrl`` / a
#     ``switch`` on a Type/Version/Kind/Variant field) anywhere in the body;
#   * file path names a codec / consensus surface, non-test.
#
# FP-guard: the discriminator regex suppresses the benign variant that switches
# on ``any.TypeUrl`` (or a version field) BEFORE decoding - that code is NOT
# ambiguous (the type is chosen deterministically), so it must stay silent; the
# codec/consensus path gate + >=2-distinct-target + first-nil-accept contract
# keep the emit tight. Advisory-first (env-gated OFF by default),
# verdict="needs-fuzz", NO auto-credit.
#
# DEDUP (A1 boundary - diff emitted hits, do NOT re-derive a covered_by):
#   * vs Pattern 28 (go.crypto.unmarshal.trailing_bytes_accepted): that detector
#     = a SINGLE Unmarshal accepting trailing bytes past the message (a
#     signature/length-boundary defect); G5 = MULTIPLE Unmarshals of one buffer
#     into rival types (a type-choice ambiguity). De-duped by ``(file,line)``
#     diff vs Pattern 28's hits.
#   * vs G1 (go.consensus.map_iteration_nondeterministic_state_write, map-
#     iteration nondeterminism): orthogonal shape (range-over-map, no Unmarshal)
#     -> disjoint by construction; noted, not diffed.
G5_UNMARSHAL_AMBIG_ENV = "AUDITOOR_G5_UNMARSHAL_TYPE_AMBIGUITY"
G5_UNMARSHAL_AMBIG_PID = "go.consensus.unmarshal_type_ambiguity_first_match"
G5_UNMARSHAL_AMBIG_OUT = "unmarshal_type_ambiguity_first_match_hypotheses.jsonl"
G5_UNMARSHAL_AMBIG_EXPLOIT_CLASS = "consensus-determinism-decode-ambiguity"

# A ``proto.Unmarshal(<bytesArg>, &<target>)`` call; capture bytes arg + target.
_G5_UNMARSHAL = re.compile(
    r"\bproto\.Unmarshal\s*\(\s*(?P<arg>[A-Za-z_][\w.]*)\s*,\s*"
    r"&?\s*(?P<target>[A-Za-z_][\w.]*)"
)
# A first-``== nil``-wins accept form on a proto.Unmarshal of the same buffer.
_G5_NIL_ACCEPT = re.compile(
    r"\bproto\.Unmarshal\s*\([^)]*\)\s*==\s*nil"
)
# TypeUrl / version discriminator - presence => the concrete type is chosen
# deterministically before/around decode => NOT ambiguous => suppress.
_G5_DISCRIMINATOR = re.compile(
    r"\bTypeUrl\b|\bGetTypeUrl\b|"
    r"\bswitch\b[^{\n]*\b(?:Type|Version|Kind|Variant)\b"
)
# Codec / consensus surface gate (non-test enforced separately).
_G5_CODEC_PATH = re.compile(r"codec|consensus", re.IGNORECASE)


def _detect_unmarshal_type_ambiguity_first_match(
    funcs: Iterable[GoFunction],
) -> list[Hit]:
    """G5 (ADVISORY) - a body trial-decodes one buffer into >=2 rival types
    under a first-``== nil``-wins ladder with no TypeUrl/version discriminator.
    See the module-level G5 block for the full predicate + dedup rationale.

    Comment/string interiors are masked length-preserving so offsets map 1:1
    onto ``fn.body``. ``*_test.go`` / generated files and non-codec/consensus
    paths are skipped.
    """
    hits: list[Hit] = []
    seen: set[tuple[str, int]] = set()
    for fn in funcs:
        fpath = str(fn.file)
        norm = fpath.replace("\\", "/")
        if _ADV_TEST_FILE.search(fpath) or _ADV_GENERATED_FILE.search(norm):
            continue
        if not _G5_CODEC_PATH.search(norm):
            continue
        masked = _g7_mask_comments(fn.body)
        # A deterministic type discriminator anywhere => not ambiguous => clean.
        if _G5_DISCRIMINATOR.search(masked):
            continue
        # Group Unmarshal calls by their (bytes) first arg.
        by_arg: dict[str, list] = {}
        for m in _G5_UNMARSHAL.finditer(masked):
            by_arg.setdefault(m.group("arg"), []).append(m)
        # First-nil-wins accept forms must back the ladder (>=2).
        if len(_G5_NIL_ACCEPT.findall(masked)) < 2:
            continue
        for arg, matches in by_arg.items():
            targets = {m.group("target") for m in matches}
            if len(matches) < 2 or len(targets) < 2:
                continue  # need >=2 decodes into >=2 distinct rival types
            first = min(matches, key=lambda mm: mm.start())
            line_off = fn.body[: first.start()].count("\n")
            line = fn.body_start_line + line_off
            key = (fpath, line)
            if key in seen:
                continue
            seen.add(key)
            body_lines = fn.body.splitlines()
            snippet = (
                body_lines[line_off].strip()
                if line_off < len(body_lines) else fn.header
            )
            hits.append(
                Hit(
                    file=fpath,
                    line=line,
                    snippet=snippet[:200],
                    extra={
                        "function": fn.name,
                        "bytes_arg": arg[:60],
                        "decode_attempts": len(matches),
                        "distinct_types": len(targets),
                        "candidate_types": sorted(targets)[:8],
                    },
                )
            )
    return hits


def _emit_unmarshal_type_ambiguity_hypotheses(
    workspace: Path,
    funcs: Iterable[GoFunction],
    trailing_bytes_hits: Iterable[Hit],
    *,
    out_path: Path | None = None,
) -> tuple[list[dict], Path]:
    """Advisory G5 emitter. Returns ``(records, out_path)`` and writes a
    ``needs-fuzz`` hypotheses jsonl. De-dups emitted hits against the named
    existing detector ``_detect_unmarshal_trailing_bytes_accepted`` (Pattern 28)
    by ``(file,line)`` (A1 dedup boundary: we do NOT re-derive a ``covered_by``
    signal, we diff emitted hits vs Pattern 28's hits). Distinct from G1 (map-
    iteration) by construction. NO auto-credit: every record carries
    ``verdict="needs-fuzz"``.
    """
    hits = _detect_unmarshal_type_ambiguity_first_match(funcs)
    covered = {(h.file, h.line) for h in trailing_bytes_hits}
    records: list[dict] = []
    for h in hits:
        if (h.file, h.line) in covered:
            continue  # already surfaced by Pattern 28's trailing-byte lane
        records.append({
            "workspace": str(workspace),
            "file": h.file,
            "line": h.line,
            "function": h.extra.get("function"),
            "bytes_arg": h.extra.get("bytes_arg"),
            "decode_attempts": h.extra.get("decode_attempts"),
            "distinct_types": h.extra.get("distinct_types"),
            "candidate_types": h.extra.get("candidate_types"),
            "snippet": h.snippet,
            "pattern_id": G5_UNMARSHAL_AMBIG_PID,
            "attack_class": "decode-type-ambiguity",
            "exploit_class": G5_UNMARSHAL_AMBIG_EXPLOIT_CLASS,
            "lane": "G5",
            "verdict": "needs-fuzz",
        })
    out = (
        Path(out_path) if out_path
        else workspace / ".auditooor" / G5_UNMARSHAL_AMBIG_OUT
    )
    out.parent.mkdir(parents=True, exist_ok=True)
    text = "".join(json.dumps(r, sort_keys=True) + "\n" for r in records)
    out.write_text(text, encoding="utf-8")
    return records, out


def _detect_skip_allowed_strict_lt_only(
    funcs: Iterable[GoFunction],
) -> list[Hit]:
    """Pattern 40 — body contains a strict ``<counter> < <max>`` check
    that allows monotonic skips by accepting any future, never-seen
    value.

    Predicate (body-local, single-function):
      * fn body contains a ``<lhs> < <rhs>`` comparison where AT
        LEAST ONE side matches ``_SKIP_COUNTER_NAME`` (``seq`` /
        ``next`` / ``counter`` / ``nonce`` / ``index`` / ``seqNum``);
      * fn body does NOT contain a paired equality
        (``<lhs> == <rhs>`` / ``<rhs> == <lhs>``) or delta-bound
        check (``<lhs> - <rhs>`` / ``<rhs> - <lhs>``) on the same
        operands.

    Mirrors Swival #032 / #033 — TLS / DTLS sequence-number guards
    rejecting only replays (``<``) without rejecting jumps
    (``==``-pair / delta).

    M14-trap: structural-only. Detector telemetry per L20 framing.
    Skips ``*_test.go`` files; de-dupes per ``(fn, lhs, rhs)``.
    """
    hits: list[Hit] = []
    seen: set[tuple[str, str, str]] = set()
    for fn in funcs:
        if str(fn.file).endswith("_test.go"):
            continue
        body = fn.body
        for m in _SKIP_LT_CHECK.finditer(body):
            lhs = m.group("lhs")
            rhs = m.group("rhs")
            # At least one side must reference a counter-shaped name
            # token; otherwise this is a generic numeric compare.
            if not (
                _SKIP_COUNTER_NAME.search(lhs)
                or _SKIP_COUNTER_NAME.search(rhs)
            ):
                continue
            # Skip trivial bound-against-literal forms (``i < 10``)
            # — we want operand-vs-operand comparisons.
            if rhs.isdigit() or lhs.isdigit():
                continue
            # Look for an equality / delta-bound paired check on the
            # same operands anywhere in the body.
            paired = re.compile(
                _SKIP_EQ_OR_DELTA_TPL.format(
                    lhs=re.escape(lhs), rhs=re.escape(rhs),
                )
            )
            if paired.search(body):
                continue
            key = (str(fn.file) + ":" + fn.name, lhs, rhs)
            if key in seen:
                continue
            seen.add(key)
            line_off = body[: m.start()].count("\n")
            snippet_line = fn.body_start_line + line_off
            body_lines = body.splitlines()
            snippet = (
                body_lines[line_off].strip()
                if line_off < len(body_lines)
                else fn.header
            )
            hits.append(
                Hit(
                    file=str(fn.file),
                    line=snippet_line,
                    snippet=snippet[:200],
                    extra={
                        "function": fn.name,
                        "lhs": lhs,
                        "rhs": rhs,
                    },
                )
            )
    return hits


def _detect_x509_suffix_match_no_dot_anchor(
    funcs: Iterable[GoFunction],
) -> list[Hit]:
    """Pattern 41 — body uses ``strings.HasSuffix`` /
    ``strings.HasPrefix`` (or the ``bytes`` equivalents) for what
    looks like a name-constraint check WITHOUT a dot-anchor on the
    needle.

    Predicate (body-local, single-function):
      * fn body contains a ``strings.HasSuffix(<haystack>, <needle>)``
        / ``strings.HasPrefix`` / ``bytes.HasSuffix`` / ``bytes.HasPrefix``
        invocation;
      * fn body does NOT contain a dot-anchor preparation matching
        ``_X509_DOT_ANCHOR`` (``"." + needle`` / ``needle + "."`` /
        ``'.'`` byte-literal compare / ``idna``/``publicsuffix``/
        ``matchHostnames`` helpers / a ``[len(addr)-len(c)-1]``
        bytewise check).

    Mirrors Swival #038 — Go crypto/x509 name-constraint match
    accepting label-prefix violations
    (``HasSuffix("evilexample.com", "example.com")``).

    M14-trap: structural-only. Detector telemetry per L20 framing;
    CONFIRMED-CANDIDATE only when the suffix check is the trust gate
    for a name-constraint enforcement layer. Skips ``*_test.go``
    files; de-dupes per ``(fn, needle)``.
    """
    hits: list[Hit] = []
    seen: set[tuple[str, str]] = set()
    for fn in funcs:
        if str(fn.file).endswith("_test.go"):
            continue
        body = fn.body
        # Body-wide dot anchor / IDNA helper presence?
        anchored = bool(_X509_DOT_ANCHOR.search(body))
        if anchored:
            continue
        for m in _X509_SUFFIX_CALL.finditer(body):
            needle = m.group("needle")
            haystack = m.group("haystack")
            key = (str(fn.file) + ":" + fn.name, needle)
            if key in seen:
                continue
            seen.add(key)
            line_off = body[: m.start()].count("\n")
            snippet_line = fn.body_start_line + line_off
            body_lines = body.splitlines()
            snippet = (
                body_lines[line_off].strip()
                if line_off < len(body_lines)
                else fn.header
            )
            hits.append(
                Hit(
                    file=str(fn.file),
                    line=snippet_line,
                    snippet=snippet[:200],
                    extra={
                        "function": fn.name,
                        "haystack": haystack,
                        "needle": needle,
                    },
                )
            )
    return hits


# ---------------------------------------------------------------------------
# G13 - go.consensus.ctx_cancellation_ignored_verdict (advisory, env-gated).
# ---------------------------------------------------------------------------
# A consensus/validation/state-commitment function TRUSTS ctx cancellation to
# abort a security-relevant action, but a finalizing ``select`` performs a
# blocking channel SEND (or commits a verdict/write) WITHOUT a
# ``case <-ctx.Done()`` (or any cancellation-receive) escape arm. When the
# caller has already cancelled the ctx, the send-select still finalizes on
# STALE/aborted state -> a trusted-but-invalid verdict is committed. This is
# the FRESHNESS invariant: the enforcer must re-check ctx.Done() at the commit
# point, not assume the caller's cancellation short-circuited it.
#
# The natural instance is SEI memiavl snapshot writer: writeLeaf/writeBranch
# gate their channel sends with ``case <-w.ctx.Done(): return w.ctx.Err()``.
# Drop that arm and the send blocks/commits an aborted snapshot leaf -> the
# state-commitment (apphash) input is written for a cancelled context.
#
# Static hit alone = needs-fuzz (NO auto-credit): a CONFIRMED needs a runtime
# path where the caller cancels between arm-drop and consumer-drain, so the
# commit lands on state the consensus round has already abandoned.
#
# FP-guard (scoped tight to avoid generic worker channels):
#   * fn (or its file path) must be on a consensus/validation/state-commit
#     path (``_G13_CONSENSUS_ANCHOR``);
#   * the FILE must already USE a cancellation contract elsewhere
#     (``context.Context`` import OR a ``.Done()`` receive somewhere in the
#     file) - so we only fire where the component KNOWS about cancellation but
#     THIS select ignores it;
#   * a select is DEFENDED (skipped) if any of its case arms is a
#     cancellation-receive (``case <-...Done()`` / ``<-...ctx`` / a
#     quit/stop/cancel/abort channel) - the CLEAN sibling shape;
#   * a select with a ``default:`` arm is DEFENDED: it is NON-BLOCKING
#     best-effort (cannot hang on a cancelled ctx), so it is not a
#     blocking-verdict-commit that trusts cancellation;
#   * only selects that contain a channel SEND case fire (a pure
#     recv-multiplex is not a finalizing verdict);
#   * ``*_test.go`` / ``/testdata/`` / generated files are skipped; comment and
#     string interiors are stripped so a ``// <-ctx.Done()`` never defends.
#
# DEDUP (A1 boundary - diff emitted hits, do NOT re-derive a covered_by):
#   * G3 hook-panic and G12 goroutine_no_toplevel_recover both attack a PANIC
#     (process crash); G13 attacks the FRESHNESS invariant (a verdict/write
#     finalized AFTER the caller already cancelled) - a DISTINCT exploit_class.
#     We still diff emitted ``(file,line)`` against G12's goroutine-spawn hits
#     so a select that G12 already surfaced on the SAME line is not restated.
G13_CTXVERDICT_ENV = "AUDITOOR_G13_CTX_CANCELLATION_IGNORED_VERDICT"
G13_CTXVERDICT_PID = "go.consensus.ctx_cancellation_ignored_verdict"
G13_CTXVERDICT_OUT = "ctx_cancellation_ignored_verdict_hypotheses.jsonl"
G13_CTXVERDICT_EXPLOIT_CLASS = "consensus-stale-ctx-ignored-verdict"

# consensus / validation / state-commitment path OR fn/receiver idiom.
_G13_CONSENSUS_ANCHOR = re.compile(
    r"(?:consensus|abci|validat|verif|snapshot|memiavl|commit|apphash"
    r"|state.?db|state.?commit|quorum|vote|finaliz|checkpoint|keeper)",
    re.IGNORECASE,
)
# file-level cancellation contract: context import OR a Done() receive.
_G13_FILE_CTX = re.compile(r"context\.Context\b|<-[^\n]{0,40}\.Done\s*\(")
# a select statement head.
_G13_SELECT = re.compile(r"\bselect\s*\{")
# a case arm performing a channel SEND: `case <ident-chain> <- ...:`.
_G13_SEND_CASE = re.compile(
    r"\bcase\s+[A-Za-z_][\w.]*(?:\[[^\]]*\])?\s*<-",
)
# a case arm that is a cancellation-receive (DEFENDED sibling shape):
#   case <-ctx.Done():  /  case <-w.ctx.Done():  /  case <-quit:  ...
_G13_CANCEL_RECV_CASE = re.compile(
    r"\bcase\s*<-\s*[\w.]*"
    r"(?:\.Done\s*\(|ctx\b|quit\b|stop\b|cancel|abort|shutdown|done\b)",
    re.IGNORECASE,
)
# a ``default:`` arm makes the select NON-BLOCKING (best-effort) -> defended.
_G13_DEFAULT_CASE = re.compile(r"\bdefault\s*:")


def _detect_ctx_cancellation_ignored_verdict(
    funcs: Iterable[GoFunction],
    file_sources: dict,
) -> list[Hit]:
    """G13 (ADVISORY) - a consensus/validation fn whose finalizing ``select``
    performs a channel SEND with NO cancellation-receive arm, while the file
    otherwise honours a ctx-cancellation contract. See the module-level G13
    block for the full predicate + FP-guard + dedup rationale.

    Emits one hit per ``(file, select-line)``. Advisory-first: surfaced only
    behind ``AUDITOOR_G13_CTX_CANCELLATION_IGNORED_VERDICT`` with
    ``verdict="needs-fuzz"`` (NO auto-credit). ``*_test.go`` / ``/testdata/`` /
    generated files skipped.
    """
    # file-level cancellation-contract presence, keyed by normalized path.
    file_has_ctx: dict[str, bool] = {}
    for rel_path, src in file_sources.items():
        p = str(rel_path).replace("\\", "/")
        file_has_ctx[p] = bool(_G13_FILE_CTX.search(src))

    hits: list[Hit] = []
    seen: set[tuple[str, int]] = set()
    for fn in funcs:
        p = str(fn.file).replace("\\", "/")
        if (_ADV_TEST_FILE.search(p) or "/testdata/" in p
                or _ADV_GENERATED_FILE.search(p)):
            continue
        # consensus/validation/state-commit anchor: path OR fn/receiver idiom.
        if not (_G13_CONSENSUS_ANCHOR.search(p)
                or _G13_CONSENSUS_ANCHOR.search(fn.name)
                or _G13_CONSENSUS_ANCHOR.search(fn.receiver)):
            continue
        # file must already know about cancellation (else no contract to break).
        if not file_has_ctx.get(p, False):
            continue
        body_nc = _strip_comments(fn.body)
        # walk each select block; fire on a send-select with no cancel-recv arm.
        for sm in _G13_SELECT.finditer(body_nc):
            brace = body_nc.find("{", sm.start())
            if brace < 0:
                continue
            end = _balance_braces(body_nc, brace)
            if end is None:
                continue
            block = body_nc[brace + 1:end - 1]
            if not _G13_SEND_CASE.search(block):
                continue  # no finalizing send -> not a verdict-commit select
            if _G13_CANCEL_RECV_CASE.search(block):
                continue  # DEFENDED: has a cancellation-receive arm (clean)
            if _G13_DEFAULT_CASE.search(block):
                continue  # DEFENDED: non-blocking best-effort send (default:)
            line = fn.body_start_line + body_nc.count("\n", 0, sm.start())
            key = (str(fn.file), line)
            if key in seen:
                continue
            seen.add(key)
            body_lines = fn.body.splitlines()
            off = body_nc.count("\n", 0, sm.start())
            snippet = (
                body_lines[off].strip() if off < len(body_lines) else fn.header
            )
            hits.append(
                Hit(
                    file=str(fn.file),
                    line=line,
                    snippet=snippet[:200],
                    extra={"function": fn.name, "receiver": fn.receiver},
                )
            )
    return hits


def _emit_ctx_cancellation_ignored_verdict_hypotheses(
    workspace: Path,
    funcs: Iterable[GoFunction],
    file_sources: dict,
    norecover_hits: Iterable[Hit],
    *,
    out_path: Path | None = None,
) -> tuple[list[dict], Path]:
    """Advisory G13 emitter. Returns ``(records, out_path)`` and writes a
    ``needs-fuzz`` hypotheses jsonl. De-dups emitted hits against G12
    (``_detect_goroutine_no_toplevel_recover``) by ``(file,line)`` (A1 dedup
    boundary: we do NOT re-derive a ``covered_by`` signal, we diff emitted hits
    vs G12's hits so a line G12 already surfaced is not restated). NO
    auto-credit: every record carries ``verdict="needs-fuzz"``.
    """
    hits = _detect_ctx_cancellation_ignored_verdict(funcs, file_sources)
    covered = {(h.file, h.line) for h in norecover_hits}
    records: list[dict] = []
    for h in hits:
        if (h.file, h.line) in covered:
            continue  # already surfaced by G12's goroutine-panic lane
        records.append({
            "workspace": str(workspace),
            "file": h.file,
            "line": h.line,
            "function": h.extra.get("function"),
            "receiver": h.extra.get("receiver"),
            "snippet": h.snippet,
            "pattern_id": G13_CTXVERDICT_PID,
            "attack_class": "ctx-cancellation-ignored-stale-verdict",
            "exploit_class": G13_CTXVERDICT_EXPLOIT_CLASS,
            "lane": "G13",
            "verdict": "needs-fuzz",
        })
    out = (
        Path(out_path) if out_path
        else workspace / ".auditooor" / G13_CTXVERDICT_OUT
    )
    out.parent.mkdir(parents=True, exist_ok=True)
    text = "".join(json.dumps(r, sort_keys=True) + "\n" for r in records)
    out.write_text(text, encoding="utf-8")
    return records, out


# ---------------------------------------------------------------------------
# G15 - go.iteration.bound_bypass_sibling_exit (advisory, env-gated).
# ---------------------------------------------------------------------------
# A per-iteration bound (a trusted enforcement point) that a SIBLING early-exit
# branch bypasses. Concretely: a bounded iteration - a cosmos collection
# ``.Walk(`` / ``.WalkDue(`` / ``.WalkKeys(`` / ``.Iterate(`` callback, or a
# ``for ... range`` loop - whose body BOTH (a) enforces a per-item cap via
# ``if <counter> == <bound>`` / ``>= <bound>`` that STOPS the walk
# (``return true`` in a stop-bool callback, or ``break`` in a for-range), AND
# (b) increments ``<counter>++`` guarding that cap, but ALSO (c) has a SIBLING
# guard-clause exit that CONTINUES to the next item (``return false`` /
# ``return nil`` in a callback, ``continue`` in a for-range) positioned BEFORE
# the ``<counter>++`` - so items taking the sibling branch are walked WITHOUT
# ever being counted and the cap is BYPASSED -> an unbounded walk over that
# item class. NORTH STAR: a trusted per-iteration bound is bypassable by a
# sibling early-exit path.
#
# Mined from a PoC-confirmed nuva Medium (src/vault/keeper/payout.go:26-37,
# EndBlocker processPendingSwapOuts): the ``WalkDue`` cap
# ``if processed == batchSize { return true, nil }`` (payout.go:31) is bypassed
# by the sibling ``if ok && vault.Paused { return false, nil }`` (payout.go:29)
# which returns BEFORE ``processed++`` (payout.go:34), so paused entries are
# walked uncounted -> the per-block cap does not bound the walk.
#
# DEDUP (disjoint predicate - NOT a runtime diff): G15 REQUIRES a per-iteration
# bound to be PRESENT (the ``if c ==/>= bound`` stop clause). G11
# (``ingress_unbounded_loop_or_panic``) and Pattern 36
# (``loop.untrusted_length_unbounded``) fire on the OPPOSITE shape - a loop with
# NO cap at all. A genuinely-uncapped loop therefore never reaches a G15 hit
# (no bound-check-with-stop => nothing to bypass), so the two lanes are
# structurally non-overlapping and G15 does not restate an unbounded-loop hit.
#
# FP-guard: the sibling exit must be (1) a CONTINUE exit (never the ``return
# true`` / ``break`` that stops), (2) at brace-depth > 0 (a guard clause, not
# the unconditional tail return), and (3) textually BEFORE the first
# ``counter++``. If ``counter++`` precedes every continue-exit (the benign
# shape) the detector is SILENT. ``*_test.go`` / ``/testdata/`` / generated
# files are skipped; comment + string interiors are masked (length-preserving)
# so a ``// return false`` comment never counts.
_G15_ITER_BOUND_BYPASS_ENV = "AUDITOOR_G15_ITER_BOUND_BYPASS"
_G15_PID = "go.iteration.bound_bypass_sibling_exit"
_G15_OUT = "iter_bound_bypass_hypotheses.jsonl"
_G15_EXPLOIT_CLASS = "iteration-bound-bypass-unbounded"

# Walk/iterate call sites that take a per-item callback (longest method names
# first so the alternation binds e.g. ``WalkDue`` before ``Walk``).
_G15_WALK_CALL = re.compile(
    r"\.(?P<method>WalkDue|WalkKeys|WalkPrefix|Walk|IterateKeys|IterateAll|"
    r"IterateRaw|Iterate)\s*\("
)
_G15_FUNC_LIT = re.compile(r"\bfunc\s*\(")
_G15_FOR_RANGE = re.compile(r"\bfor\b[^\n{;]*\brange\b[^\n{]*\{")
_G15_IF = re.compile(r"\bif\b")
# ``<ident>++`` counter increment (not a field-selector tail like ``x.y++``).
_G15_INCR = re.compile(r"(?<![\w.])(?P<c>[A-Za-z_]\w*)\s*\+\+")
# CONTINUE (keep-walking) exits per shape.
_G15_CB_CONTINUE = re.compile(r"\breturn\s+false\b|\breturn\s+nil\b")
_G15_CB_STOP = re.compile(r"\breturn\s+true\b")
_G15_FR_CONTINUE = re.compile(r"\bcontinue\b")
# A for-range per-iteration CAP that STOPS the walk is expressed with ``break``.
# ``return`` is deliberately EXCLUDED: a bare/`return err` inside a threshold
# block is almost always a flush-batch or error path (``if n >= flushN {
# flush(); return err }``), NOT a hard cap - counting it produced a confirmed FP
# on sei sei-db/.../evm/store.go:317 (a flush-on-threshold import loop). break
# only keeps the lane on genuine stop-caps.
_G15_FR_STOP = re.compile(r"\bbreak\b")


def _g15_mask(s: str) -> str:
    """Length- and newline-preserving mask of Go string/rune/comment interiors
    (replaced with spaces) so downstream regex offsets map 1:1 back to ``s`` for
    accurate line computation, while a token inside a comment or string literal
    can never match a predicate."""
    out = list(s)
    i, n = 0, len(s)
    in_str: str | None = None
    in_line = in_block = False
    while i < n:
        ch = s[i]
        nxt = s[i + 1] if i + 1 < n else ""
        if in_line:
            if ch == "\n":
                in_line = False
            else:
                out[i] = " "
        elif in_block:
            if ch == "*" and nxt == "/":
                out[i] = out[i + 1] = " "
                i += 2
                in_block = False
                continue
            if ch != "\n":
                out[i] = " "
        elif in_str is not None:
            if ch == "\\" and in_str != "`":
                out[i] = " "
                if i + 1 < n and s[i + 1] != "\n":
                    out[i + 1] = " "
                i += 2
                continue
            if ch == in_str:
                in_str = None
            if ch != "\n":
                out[i] = " "
        else:
            if ch == "/" and nxt == "/":
                in_line = True
                out[i] = " "
            elif ch == "/" and nxt == "*":
                in_block = True
                out[i] = " "
            elif ch in ("\"", "`", "'"):
                in_str = ch
                out[i] = " "
        i += 1
    return "".join(out)


def _g15_depth(body: str, off: int) -> int:
    """Brace depth at ``off`` within a masked ``body`` (a guard clause is > 0)."""
    seg = body[:off]
    return seg.count("{") - seg.count("}")


def _g15_find_bound_check(
    body: str, counter: str, stop_re: "re.Pattern[str]",
) -> tuple[int, tuple[int, int]] | None:
    """Return ``(if_offset, (block_open, block_end))`` for the FIRST
    ``if <cond involving counter via == / >= / >> { ...stop... }`` block, or
    ``None``. The block MUST contain a STOP token (``stop_re``) - that is what
    makes it a genuine per-iteration cap rather than an ordinary compare."""
    cre = re.escape(counter)
    fwd = re.compile(r"(?<![\w.])" + cre + r"\s*(?:==|>=|>)\s*[\w.]")
    rev = re.compile(r"[\w.]\s*(?:==|>=|>)\s*" + cre + r"(?![\w.])")
    for m in _G15_IF.finditer(body):
        brace = body.find("{", m.end())
        if brace < 0:
            continue
        cond = body[m.end():brace]
        if not (fwd.search(cond) or rev.search(cond)):
            continue
        end = _balance_braces(body, brace)
        if end is None:
            continue
        block = body[brace + 1:end - 1]
        if stop_re.search(block):
            return m.start(), (brace, end)
    return None


def _g15_analyze_body(body: str, *, is_callback: bool) -> dict | None:
    """Return the bypass descriptor ``{counter, bound_check_off, incr_off,
    bypass_off}`` for a callback / for-range body, or ``None`` when no
    cap-present-but-bypassed shape exists. ``body`` MUST be pre-masked."""
    incrs = list(_G15_INCR.finditer(body))
    if not incrs:
        return None
    cont_re = _G15_CB_CONTINUE if is_callback else _G15_FR_CONTINUE
    stop_re = _G15_CB_STOP if is_callback else _G15_FR_STOP
    incr_by_c: dict[str, list[int]] = {}
    for im in incrs:
        incr_by_c.setdefault(im.group("c"), []).append(im.start())
    best: dict | None = None
    for counter, offs in incr_by_c.items():
        first_incr = min(offs)
        bc = _g15_find_bound_check(body, counter, stop_re)
        if bc is None:
            continue  # no per-iteration cap on this counter -> not our lane
        _bc_off, (bc_open, bc_end) = bc
        for cm in cont_re.finditer(body):
            coff = cm.start()
            if coff >= first_incr:
                continue  # counter++ already passed -> not a bypass
            if bc_open <= coff < bc_end:
                continue  # inside the bound-check block (a stop, not a skip)
            if _g15_depth(body, coff) <= 0:
                continue  # unconditional tail return, not a guard-clause sibling
            if best is None or coff < best["bypass_off"]:
                best = {
                    "counter": counter,
                    "bound_check_off": _bc_off,
                    "incr_off": first_incr,
                    "bypass_off": coff,
                }
    return best


def _g15_enclosing_fn(
    funcs: Iterable[GoFunction], line: int,
) -> "GoFunction | None":
    """Nearest enclosing named function for an absolute ``line`` (for the
    advisory ``function`` field). Anonymous callbacks are not named funcs, so
    this returns the outer named function that hosts the walk/loop."""
    best: "GoFunction | None" = None
    for fn in funcs:
        end = fn.body_start_line + fn.body.count("\n")
        if fn.start_line <= line <= end:
            if best is None or fn.start_line > best.start_line:
                best = fn
    return best


def _detect_iteration_bound_bypass(
    file_sources: dict, funcs_by_file: dict,
) -> list[Hit]:
    """G15 (ADVISORY) - a bounded iteration whose per-item cap is bypassable by
    a sibling continue-exit that skips the counter increment. See the
    module-level G15 block for the full predicate + FP-guard + dedup rationale.

    Emits one hit per ``(file, walk/loop line, counter)``. ``*_test.go``,
    ``/testdata/`` and generated files are skipped. Advisory-first: surfaced
    only behind ``AUDITOOR_G15_ITER_BOUND_BYPASS`` with ``verdict="needs-fuzz"``
    (NO auto-credit)."""
    hits: list[Hit] = []
    seen: set[tuple[str, int, str]] = set()
    for rel_path, src in file_sources.items():
        p = str(rel_path).replace("\\", "/")
        if (_ADV_TEST_FILE.search(p) or "/testdata/" in p
                or _ADV_GENERATED_FILE.search(p)):
            continue
        funcs = funcs_by_file.get(rel_path, [])
        masked = _g15_mask(src)

        def _emit(anchor_off: int, body: str, body_off: int,
                  res: dict, shape: str) -> None:
            line = masked.count("\n", 0, anchor_off) + 1
            key = (str(rel_path), line, res["counter"])
            if key in seen:
                return
            seen.add(key)
            bc_line = masked.count("\n", 0, body_off + res["bound_check_off"]) + 1
            by_line = masked.count("\n", 0, body_off + res["bypass_off"]) + 1
            fn = _g15_enclosing_fn(funcs, line)
            ls = src.rfind("\n", 0, anchor_off) + 1
            le = src.find("\n", anchor_off)
            snippet = src[ls:(le if le >= 0 else len(src))].strip()
            hits.append(Hit(
                file=str(rel_path),
                line=line,
                snippet=snippet[:200],
                extra={
                    "function": fn.name if fn else "",
                    "receiver": fn.receiver if fn else "",
                    "counter": res["counter"],
                    "bound_check_line": bc_line,
                    "bypass_branch_line": by_line,
                    "shape": shape,
                },
            ))

        # (A) Walk / Iterate callback shape.
        for wm in _G15_WALK_CALL.finditer(masked):
            fm = _G15_FUNC_LIT.search(masked, wm.end())
            if fm is None or fm.start() - wm.end() > 400:
                continue
            brace = masked.find("{", fm.end())
            if brace < 0:
                continue
            end = _balance_braces(masked, brace)
            if end is None:
                continue
            body = masked[brace + 1:end - 1]
            res = _g15_analyze_body(body, is_callback=True)
            if res is not None:
                _emit(wm.start(), body, brace + 1, res, "walk-callback")

        # (B) for-range loop shape (counter + break/return cap + continue-bypass).
        for fr in _G15_FOR_RANGE.finditer(masked):
            brace = masked.find("{", fr.start())
            if brace < 0:
                continue
            end = _balance_braces(masked, brace)
            if end is None:
                continue
            body = masked[brace + 1:end - 1]
            res = _g15_analyze_body(body, is_callback=False)
            if res is not None:
                _emit(fr.start(), body, brace + 1, res, "for-range")
    return hits


def _emit_iteration_bound_bypass_hypotheses(
    workspace: Path,
    file_sources: dict,
    funcs_by_file: dict,
    *,
    out_path: Path | None = None,
) -> tuple[list[dict], Path]:
    """Advisory G15 emitter. Returns ``(records, out_path)`` and writes a
    ``needs-fuzz`` hypotheses jsonl. DEDUP is by DISJOINT PREDICATE (documented
    in the module-level G15 block): G15 requires a per-iteration bound to be
    PRESENT, whereas G11 / Pattern 36 fire on an uncapped loop - the shapes do
    not overlap, so no runtime (file,line) diff is needed. NO auto-credit:
    every record carries ``verdict="needs-fuzz"``."""
    hits = _detect_iteration_bound_bypass(file_sources, funcs_by_file)
    records: list[dict] = []
    for h in hits:
        records.append({
            "workspace": str(workspace),
            "file": h.file,
            "line": h.line,
            "function": h.extra.get("function"),
            "receiver": h.extra.get("receiver"),
            "counter": h.extra.get("counter"),
            "bound_check_line": h.extra.get("bound_check_line"),
            "bypass_branch_line": h.extra.get("bypass_branch_line"),
            "shape": h.extra.get("shape"),
            "snippet": h.snippet,
            "pattern_id": _G15_PID,
            "attack_class": "iteration-bound-bypass-unbounded",
            "exploit_class": _G15_EXPLOIT_CLASS,
            "source": "G15",
            "lane": "G15",
            "verdict": "needs-fuzz",
        })
    out = (
        Path(out_path) if out_path
        else workspace / ".auditooor" / _G15_OUT
    )
    out.parent.mkdir(parents=True, exist_ok=True)
    text = "".join(json.dumps(r, sort_keys=True) + "\n" for r in records)
    out.write_text(text, encoding="utf-8")
    return records, out


# ---------------------------------------------------------------------------
# G14 - go.errors.wrap_loses_sentinel (advisory, env-gated).
# ---------------------------------------------------------------------------
# A guard that keys off a SENTINEL error identity - ``errors.Is(err,
# ErrSentinel)`` or a direct ``err ==/!= ErrSentinel`` - whose sentinel is ALSO
# wrapped LOSSILY somewhere in the SAME file by a ``fmt.Errorf(...)`` that drops
# the sentinel: a non-``%w`` format (``%v`` / ``%s`` / ``%q`` / ``%d`` / ``%+v``,
# i.e. the format string carries NO ``%w`` verb) is used on that sentinel arg,
# so the produced error no longer Unwraps to the sentinel. Downstream,
# ``errors.Is`` / ``==`` against that sentinel can NEVER match the wrapped error,
# and the guard's protected safety branch (retry / refund / pause / reject)
# silently never fires. NORTH STAR: the guard's private invariant - that the
# error still CARRIES the sentinel - is UNSOUND because a lossy wrap severed the
# sentinel chain.
#
# Anchor idiom (nuva src/vault/keeper/payout.go:224): ``getRefundReason`` keys
# the refund category off ``errors.Is(err, sdkerrors.ErrInsufficientFunds)``; if
# any producer on that path wraps the sentinel with ``%v`` instead of ``%w`` the
# guard is dead and every insufficient-funds refund is mis-categorised. (nuva
# itself uses ``%w`` on that path -> the detector is correctly SILENT there, a
# true-negative.)
#
# DEDUP (disjoint predicate): Pattern 29
# (``rpc_boundary.bare_fmterrorf_user_input_parse_failure``) fires on a gRPC
# handler (a ``*XxxRequest`` param) that returns a BARE ``fmt.Errorf`` from a
# PARSE failure, regardless of any sentinel - it NEVER requires a sentinel var
# nor an ``errors.Is`` / ``==`` guard. G14 REQUIRES BOTH a sentinel-identity
# guard AND a lossy wrap OF THAT SAME sentinel; a bare parse-error wrap with no
# co-located sentinel guard never reaches a G14 hit, so the two lanes are
# structurally non-overlapping. G15 / G11 / Pattern-36 are iteration/loop lanes
# (orthogonal shape). So G14 restates none of them.
#
# FP-guard / disclosed precision boundary (advisory-first, must-not-spray): the
# wrapped argument MUST be the sentinel var LITERALLY (a possibly-qualified
# Err-named identifier appearing as a top-level ``fmt.Errorf`` argument) AND a
# guard on that EXACT sentinel must co-exist in the same file. The caller/callee
# split (wrapping a plain ``err`` that only CARRIES the sentinel at runtime), the
# local reassign-then-guard shape, and the custom-error-type-lacking-Unwrap()/
# Is() mechanism are DELIBERATELY out of scope for this first landing - they need
# dataflow / type resolution and would spray. That is the honest precision
# boundary: G14 under-reports those (stays SILENT) rather than false-firing.
# ``*_test.go`` / ``/testdata/`` / generated (``.pb.go`` / ``mock_*.go``) files
# are skipped; comment + string interiors are masked (length-preserving) so a
# ``// errors.Is(...)`` comment never counts - but the format-string literal is
# read back from the UNMASKED source at the matched offset to test for ``%w``.
_G14_SENTINEL_LOSS_ENV = "AUDITOOR_G14_SENTINEL_LOSS"
_G14_PID = "go.errors.wrap_loses_sentinel"
_G14_OUT = "sentinel_loss_hypotheses.jsonl"
_G14_EXPLOIT_CLASS = "error-wrap-loses-sentinel-guard-dead"

# A (possibly package-qualified) sentinel error identifier by Go convention: an
# exported ``Err<Word>`` or ``<Word>Error`` name, optionally ``pkg.``-qualified.
# The Err/Error name is REQUIRED to be exported (upper-initial on the final
# segment) so lowercase locals like ``expectedError`` never register as
# sentinels.
_G14_SENT = r"(?:[A-Za-z_]\w*\.)?(?:Err[A-Z]\w*|[A-Z][A-Za-z0-9]*Error)"
# ``errors.Is(<x>, <SENT>)`` - the sentinel is the SECOND (target) argument. The
# first arg is kept simple (no nested comma) to stay precise; a call-valued
# first arg is an accepted under-report.
_G14_ERRORS_IS = re.compile(
    r"\berrors\.Is\(\s*[^,()]+?\s*,\s*(?P<sent>" + _G14_SENT + r")\s*\)"
)
# direct identity compare ``x == ErrSentinel`` / ``ErrSentinel != x``.
_G14_CMP = re.compile(
    r"(?:(?:==|!=)\s*(?P<s1>" + _G14_SENT + r")(?![\w.]))"
    r"|(?:(?<![\w.])(?P<s2>" + _G14_SENT + r")\s*(?:==|!=))"
)
# ``fmt.Errorf(`` call site.
_G14_ERRORF = re.compile(r"\bfmt\.Errorf\s*\(")
# a top-level ``fmt.Errorf`` arg that IS exactly a sentinel identifier.
_G14_SENT_ARG = re.compile(r"^\s*(?P<sent>" + _G14_SENT + r")\s*$")


def _g14_balance_parens(masked: str, open_idx: int) -> int | None:
    """Given the index of an opening ``(`` in the MASKED source (string / comment
    interiors already blanked, so parens inside literals cannot mis-balance),
    return the index just past the matching ``)``, or ``None`` if unbalanced."""
    depth = 0
    for i in range(open_idx, len(masked)):
        ch = masked[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return i + 1
    return None


def _g14_split_top_args(arglist: str) -> list[str]:
    """Split a MASKED ``fmt.Errorf`` argument list on TOP-LEVEL commas only
    (ignoring commas nested in parens / brackets / braces)."""
    args: list[str] = []
    depth = 0
    start = 0
    for i, ch in enumerate(arglist):
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == "," and depth == 0:
            args.append(arglist[start:i])
            start = i + 1
    args.append(arglist[start:])
    return args


def _g14_first_string_literal(src: str, start: int, end: int) -> str | None:
    """Return the FIRST Go string literal (double-quoted or raw-backtick) found
    in ``src[start:end]`` - the ``fmt.Errorf`` format argument - or ``None``."""
    i = start
    while i < end:
        ch = src[i]
        if ch == '"':
            j = i + 1
            buf = []
            while j < end:
                c = src[j]
                if c == "\\":
                    buf.append(src[j:j + 2])
                    j += 2
                    continue
                if c == '"':
                    return "".join(buf)
                buf.append(c)
                j += 1
            return "".join(buf)
        if ch == "`":
            j = src.find("`", i + 1)
            if j < 0 or j >= end:
                return None
            return src[i + 1:j]
        i += 1
    return None


def _g14_guarded_sentinels(masked: str) -> set[str]:
    """Collect every sentinel identity that is GUARDED in ``masked`` via
    ``errors.Is(_, SENT)`` or a direct ``== / != SENT`` compare. Returns the set
    of matched sentinel tokens (qualifier preserved)."""
    out: set[str] = set()
    for m in _G14_ERRORS_IS.finditer(masked):
        out.add(m.group("sent"))
    for m in _G14_CMP.finditer(masked):
        out.add(m.group("s1") or m.group("s2"))
    return out


def _g14_sentinel_matches(arg_sent: str, guarded: set[str]) -> bool:
    """A wrapped sentinel arg matches the guarded set when the token is present
    verbatim OR its unqualified tail equals a guarded token's tail (so a
    ``pkg.ErrX`` wrap matches a ``pkg.ErrX`` / ``ErrX`` guard and vice versa)."""
    if arg_sent in guarded:
        return True
    tail = arg_sent.rsplit(".", 1)[-1]
    for g in guarded:
        if g == arg_sent or g.rsplit(".", 1)[-1] == tail:
            return True
    return False


def _detect_error_wrap_loses_sentinel(
    file_sources: dict, funcs_by_file: dict,
) -> list[Hit]:
    """G14 (ADVISORY) - a sentinel-identity guard rendered dead by a lossy
    ``fmt.Errorf`` (non-``%w``) wrap of that SAME sentinel in the same file. See
    the module-level G14 block for the full predicate + FP-guard + dedup
    rationale.

    Emits one hit per ``(file, wrap line, sentinel)``. ``*_test.go``,
    ``/testdata/`` and generated files are skipped. Advisory-first: surfaced only
    behind ``AUDITOOR_G14_SENTINEL_LOSS`` with ``verdict="needs-fuzz"`` (NO
    auto-credit)."""
    hits: list[Hit] = []
    seen: set[tuple[str, int, str]] = set()
    for rel_path, src in file_sources.items():
        p = str(rel_path).replace("\\", "/")
        if (_ADV_TEST_FILE.search(p) or "/testdata/" in p
                or _ADV_GENERATED_FILE.search(p)):
            continue
        masked = _g15_mask(src)          # generic masker (reused from G15)
        guarded = _g14_guarded_sentinels(masked)
        if not guarded:
            continue                     # no sentinel guard -> nothing to kill
        funcs = funcs_by_file.get(rel_path, [])
        for em in _G14_ERRORF.finditer(masked):
            open_idx = masked.find("(", em.start())
            if open_idx < 0:
                continue
            close = _g14_balance_parens(masked, open_idx)
            if close is None:
                continue
            # Format literal (read from UNMASKED src): a ``%w`` verb preserves
            # the sentinel chain -> NOT lossy. Absent ``%w`` -> lossy.
            fmt_lit = _g14_first_string_literal(src, open_idx + 1, close - 1)
            if fmt_lit is None or "%w" in fmt_lit:
                continue
            arglist = masked[open_idx + 1:close - 1]
            for arg in _g14_split_top_args(arglist):
                am = _G14_SENT_ARG.match(arg)
                if am is None:
                    continue
                sent = am.group("sent")
                if not _g14_sentinel_matches(sent, guarded):
                    continue
                line = masked.count("\n", 0, em.start()) + 1
                key = (str(rel_path), line, sent)
                if key in seen:
                    continue
                seen.add(key)
                fn = _g15_enclosing_fn(funcs, line)
                ls = src.rfind("\n", 0, em.start()) + 1
                le = src.find("\n", em.start())
                snippet = src[ls:(le if le >= 0 else len(src))].strip()
                hits.append(Hit(
                    file=str(rel_path),
                    line=line,
                    snippet=snippet[:200],
                    extra={
                        "function": fn.name if fn else "",
                        "receiver": fn.receiver if fn else "",
                        "sentinel": sent,
                        "verb": "non-%w",
                        "format": fmt_lit[:120],
                    },
                ))
    return hits


def _emit_sentinel_loss_hypotheses(
    workspace: Path,
    file_sources: dict,
    funcs_by_file: dict,
    *,
    out_path: Path | None = None,
) -> tuple[list[dict], Path]:
    """Advisory G14 emitter. Returns ``(records, out_path)`` and writes a
    ``needs-fuzz`` hypotheses jsonl. DEDUP is by DISJOINT PREDICATE (documented
    in the module-level G14 block): G14 requires a sentinel-identity guard PLUS a
    lossy wrap of that SAME sentinel, whereas Pattern 29 fires on a bare RPC
    parse-error wrap with no sentinel guard - the shapes do not overlap, so no
    runtime (file,line) diff is needed. NO auto-credit: every record carries
    ``verdict="needs-fuzz"``."""
    hits = _detect_error_wrap_loses_sentinel(file_sources, funcs_by_file)
    records: list[dict] = []
    for h in hits:
        records.append({
            "workspace": str(workspace),
            "file": h.file,
            "line": h.line,
            "function": h.extra.get("function"),
            "receiver": h.extra.get("receiver"),
            "sentinel": h.extra.get("sentinel"),
            "verb": h.extra.get("verb"),
            "format": h.extra.get("format"),
            "snippet": h.snippet,
            "pattern_id": _G14_PID,
            "attack_class": "error-wrap-loses-sentinel",
            "exploit_class": _G14_EXPLOIT_CLASS,
            "source": "G14",
            "lane": "G14",
            "verdict": "needs-fuzz",
        })
    out = (
        Path(out_path) if out_path
        else workspace / ".auditooor" / _G14_OUT
    )
    out.parent.mkdir(parents=True, exist_ok=True)
    text = "".join(json.dumps(r, sort_keys=True) + "\n" for r in records)
    out.write_text(text, encoding="utf-8")
    return records, out


def _detect_context_afterfunc_on_success(
    funcs: Iterable[GoFunction],
) -> list[Hit]:
    """Pattern 42 (L24 ABM, AAK seed #13, Swival #005) —
    ``go.crypto.context_cancel.afterfunc_on_success``.

    Predicate (single-function, body-local):
      * fn body contains a ``context.AfterFunc(...)`` call;
      * the binding name ``stop`` (``stop := context.AfterFunc(...)``)
        is captured if present; if the call is bare or
        underscore-discarded, we fire unconditionally;
      * fn body does NOT contain any call site that invokes the
        captured stop name (``stop()``, ``defer stop()``,
        ``go stop()``); a ``defer stop()`` anywhere in the body
        counts as defended.

    Mirrors Swival #005 — Go ``context.AfterFunc`` registers a
    cancellation callback that runs when the context is cancelled.
    If the surrounding fn returns success without calling the
    returned stop function, the callback stays armed, leaking the
    goroutine and (critically) closing/cancelling a resource the
    success path is still using.

    M14-trap: structural-only. Detector telemetry per L20 framing;
    CONFIRMED-CANDIDATE only with a runtime PoC that the leaked
    cancel-callback fires on a still-live success-path resource.
    Skips ``*_test.go`` files; de-dupes per ``(file, fn, call_idx)``.
    """
    hits: list[Hit] = []
    seen: set[tuple[str, str, int]] = set()
    for fn in funcs:
        if str(fn.file).endswith("_test.go"):
            continue
        body = fn.body
        # Comment-stripped variant is used ONLY for the defended-shape
        # lookup (so a ``// stop()`` doc-comment does not falsely
        # convince us the handle is invoked). Offsets / snippets stay
        # tied to the original body for source-faithful reporting.
        body_no_comments = _strip_comments(body)
        # Walk every AfterFunc call site in the body. If a binding
        # name is captured and that name is invoked anywhere in the
        # body, the call is defended; otherwise fire.
        for m in _AFTERFUNC_CALL_BARE.finditer(body):
            # Look for the surrounding line to detect a binding form.
            # We re-search _AFTERFUNC_CALL_NAMED at the same span;
            # if it matches, the call has a stop handle name.
            line_start = body.rfind("\n", 0, m.start()) + 1
            line_end = body.find("\n", m.end())
            if line_end < 0:
                line_end = len(body)
            line_text = body[line_start:line_end]
            named = _AFTERFUNC_CALL_NAMED.search(line_text)
            if named:
                stop_name = named.group("name")
                if stop_name in {"_", "ctx", "context"}:
                    # Discarded handle — fires unconditionally.
                    is_defended = False
                else:
                    stop_call_re = re.compile(
                        _AFTERFUNC_STOP_CALL_TPL.format(
                            name=re.escape(stop_name),
                        )
                    )
                    # Defended if ANY invocation of stop_name exists
                    # in the comment-stripped body (defer / direct
                    # call / go stop()). We scan the FULL body —
                    # defer can appear above the AfterFunc call site.
                    # ``_AFTERFUNC_STOP_CALL_TPL`` matches a paren-
                    # call only, so the named binding line itself
                    # (``stop := context.AfterFunc(...)``) cannot
                    # spuriously match.
                    is_defended = bool(
                        stop_call_re.search(body_no_comments)
                    )
            else:
                # Bare expression-statement / no handle bound at all.
                stop_name = ""
                is_defended = False
            if is_defended:
                continue
            key = (str(fn.file), fn.name, m.start())
            if key in seen:
                continue
            seen.add(key)
            line_off = body[: m.start()].count("\n")
            snippet_line = fn.body_start_line + line_off
            body_lines = body.splitlines()
            snippet = (
                body_lines[line_off].strip()
                if line_off < len(body_lines)
                else fn.header
            )
            hits.append(
                Hit(
                    file=str(fn.file),
                    line=snippet_line,
                    snippet=snippet[:200],
                    extra={
                        "function": fn.name,
                        "stop_name": stop_name,
                        "binding_form": "named" if named else "bare",
                    },
                )
            )
    return hits


def _detect_kem_imported_key_skips_pairwise(
    funcs: Iterable[GoFunction],
) -> list[Hit]:
    """Pattern 43 (L24 ABM, AAK seed #15, Swival #026) —
    ``go.crypto.kem.imported_key_skips_pairwise_consistency_test``.

    Predicate (single-function, body-local):
      * fn name matches ``_KEM_IMPORT_FUNC_NAME`` (covers
        ``ImportPrivateKey`` / ``ParseKEM*Key`` / ``LoadKEM*Key`` /
        ``NewKEM*FromBytes`` / KEM-prefixed unmarshal idioms);
      * fn body returns the parsed key WITHOUT calling
        ``Encapsulate``/``Decapsulate``/``Encap``/``Decap``/
        ``PairwiseConsistency``/``PairwiseCheck``/``selfTest`` —
        i.e. no in-body pairwise consistency self-test before the
        success return.

    Mirrors Swival #026 — KEM (Key Encapsulation Mechanism) imports
    that fail-safe the pairwise consistency test. NIST SP 800-56C
    REQUIRES that imported KEM keys are subjected to an
    encap-then-decap pairwise consistency test before use; without
    it, a malformed/corrupted import can be accepted as a healthy
    keypair, breaking the FIPS 203 contract.

    M14-trap: structural-only. Detector telemetry per L20 framing;
    CONFIRMED-CANDIDATE only when the absence of the pairwise
    self-test admits a documented attack model (e.g. backdoor,
    fault-induction, cross-key confusion). Skips ``*_test.go`` files.
    """
    hits: list[Hit] = []
    seen: set[tuple[str, str]] = set()
    for fn in funcs:
        if str(fn.file).endswith("_test.go"):
            continue
        if not _KEM_IMPORT_FUNC_NAME.match(fn.name):
            continue
        body = fn.body
        # Pairwise consistency check anywhere in the body counts as
        # defended.
        if _KEM_PAIRWISE_CHECK.search(body):
            continue
        key = (str(fn.file), fn.name)
        if key in seen:
            continue
        seen.add(key)
        snippet = body.splitlines()[0].strip() if body.splitlines() else fn.header
        hits.append(
            Hit(
                file=str(fn.file),
                line=fn.body_start_line,
                snippet=snippet[:200],
                extra={
                    "function": fn.name,
                },
            )
        )
    return hits


# ---------------------------------------------------------------------------
# Pattern 44 detector — go.cosmos.subaccount_filter_mismatch
# ---------------------------------------------------------------------------

def _detect_subaccount_filter_mismatch(
    funcs: Iterable[GoFunction],
) -> list[Hit]:
    """Pattern 44 (Lane 11 NBQ-010) —
    ``go.cosmos.subaccount_filter_mismatch``.

    Fires when a function both:
      * uses a subaccount-shaped filter/selector key, AND
      * reads a balance at the account/module level WITHOUT deriving the
        address from the subaccount ID first.

    Negative control: body contains ``SubaccountIdToAddress`` /
    ``SubaccountToAddress`` / ``ToAddress`` applied to the subaccount, OR
    it never reads an account-level balance.

    Skips ``*_test.go`` files.
    """
    hits: list[Hit] = []
    seen: set[tuple[str, str]] = set()
    for fn in funcs:
        if str(fn.file).endswith("_test.go"):
            continue
        body = fn.body
        # Must use a subaccount selector
        if not _SUBACCOUNT_FILTER_USE.search(body):
            continue
        # Must read a balance
        if not _ACCOUNT_BALANCE_READ.search(body):
            continue
        # Safe if the body derives an address from the subaccount first
        if _SUBACCOUNT_ADDRESS_DERIVATION.search(body):
            continue
        key = (str(fn.file), fn.name)
        if key in seen:
            continue
        seen.add(key)
        snippet = body.splitlines()[0].strip() if body.splitlines() else fn.header
        hits.append(
            Hit(
                file=str(fn.file),
                line=fn.body_start_line,
                snippet=snippet[:200],
                extra={
                    "function": fn.name,
                    "predicate_arm": "subaccount_filter_account_balance_mismatch",
                },
            )
        )
    return hits


# ---------------------------------------------------------------------------
# Pattern 45 detector — go.cosmos.stale_tail_health_check
# ---------------------------------------------------------------------------

def _detect_stale_tail_health_check(
    funcs: Iterable[GoFunction],
) -> list[Hit]:
    """Pattern 45 (Lane 11 NBQ-010) —
    ``go.cosmos.stale_tail_health_check``.

    Fires when a function:
      * reads only the tail / latest element from a sequence, AND
      * applies a health assertion on it, AND
      * does NOT iterate the full collection.

    Negative control: any ``for ... range`` / ``All(ctx)`` / ``GetAll*`` /
    ``ForEach*`` / ``IterateAll*`` in the same body means the check is
    not tail-only.

    Skips ``*_test.go`` files.
    """
    hits: list[Hit] = []
    seen: set[tuple[str, str]] = set()
    for fn in funcs:
        if str(fn.file).endswith("_test.go"):
            continue
        body = fn.body
        # Must read from tail
        if not _TAIL_READ.search(body):
            continue
        # Must apply a health assertion
        if not _HEALTH_ASSERT.search(body):
            continue
        # Safe if the body also iterates the full collection
        if _FULL_ITERATION.search(body):
            continue
        key = (str(fn.file), fn.name)
        if key in seen:
            continue
        seen.add(key)
        snippet = body.splitlines()[0].strip() if body.splitlines() else fn.header
        hits.append(
            Hit(
                file=str(fn.file),
                line=fn.body_start_line,
                snippet=snippet[:200],
                extra={
                    "function": fn.name,
                    "predicate_arm": "tail_only_health_no_full_iteration",
                },
            )
        )
    return hits


# range-over-map loop header: ``for k, v := range m`` (value optional).
_MAP_RANGE = re.compile(
    r"\bfor\s+(?P<k>\w+)\s*(?:,\s*(?P<v>\w+)\s*)?(?::=|=)\s*range\s+(?P<ident>\w+)"
)

# Consensus-bound write sink INSIDE the loop body. Named sinks only
# (stage-1 narrow): KVStore Set / ctx-Set / byte-accumulator later hashed /
# event emit / app-hash. Cross-fn provenance is deferred.
_MAP_CONSENSUS_SINK = re.compile(
    r"\b\w*[Ss]tore\.Set\("
    r"|\bKVStore\([^)]*\)\.Set\("
    r"|\.Set\(\s*ctx\b"
    r"|\b(?:bz|buf|out|acc)\s*(?::=|=)\s*append\("
    r"|\bbuf\.Write"
    r"|\.EmitEvent\("
    r"|\bAppHash\b"
)

# Key-ordering suppressor: a sort / ordered-keys call means the iteration is
# deterministic, so no divergence.
_MAP_KEY_ORDER = re.compile(r"\bsort\.|\bslices\.Sort|OrderedKeys|\.Sort\(")


def _ident_is_map(body: str, ident: str) -> bool:
    """True if ``ident`` is declared map-shaped in ``body``.

    Matches ``m := map[``, ``m := make(map[``, ``m map[`` (param /
    ``var`` decl), ``m = make(map[``.
    """
    pat = re.compile(
        r"\b" + re.escape(ident) + r"\b\s*(?::=|=)?\s*(?:make\()?\s*map\["
    )
    return bool(pat.search(body))


def _detect_range_over_map_nondeterministic_consensus_write(
    funcs: Iterable[GoFunction],
) -> list[Hit]:
    """``go.consensus.map_iteration_nondeterministic_state_write``.

    Go map iteration order is randomized. A ``for k, v := range m`` loop whose
    body writes CONSENSUS-BOUND state (KVStore Set / byte-accumulator later
    hashed) with NO key ordering makes two honest validators diverge -> chain
    halt (HIGH).

    Stage-1 predicate (narrow, name the sink):
      (a) ``<ident>`` is map-shaped in the func (a ``map[`` / ``make(map[``
          decl for that var),
      (b) the loop body has a consensus-bound write sink,
      (c) NO key ordering between decl and loop (no ``sort.`` / ``slices.Sort``
          / ``OrderedKeys`` / ranging a pre-sorted keys slice).
    """
    hits: list[Hit] = []
    seen: set[tuple[str, int]] = set()
    for fn in funcs:
        if str(fn.file).endswith("_test.go"):
            continue
        body_nc = _strip_comments(fn.body)
        # (c) key ordering anywhere in the func -> deterministic, skip.
        if _MAP_KEY_ORDER.search(body_nc):
            continue
        for m in _MAP_RANGE.finditer(fn.body):
            ident = m.group("ident")
            # (a) ranged var must be map-shaped (body decl OR param type).
            if not (_ident_is_map(body_nc, ident) or _ident_is_map(fn.params, ident)):
                continue
            # slice loop body via matching braces.
            brace_idx = fn.body.find("{", m.end())
            if brace_idx < 0:
                continue
            end_idx = _balance_braces(fn.body, brace_idx)
            if end_idx is None:
                continue
            loop_body = _strip_comments(fn.body[brace_idx + 1:end_idx - 1])
            # (b) consensus-bound write sink in loop body.
            sink = _MAP_CONSENSUS_SINK.search(loop_body)
            if not sink:
                continue
            line_off = fn.body[:m.start()].count("\n")
            line = fn.body_start_line + line_off
            key = (str(fn.file), line)
            if key in seen:
                continue
            seen.add(key)
            lines = fn.body.splitlines()
            snippet = lines[line_off].strip() if line_off < len(lines) else fn.header
            hits.append(
                Hit(
                    file=str(fn.file),
                    line=line,
                    snippet=snippet[:200],
                    extra={
                        "function": fn.name,
                        "map_var": ident,
                        "sink": sink.group(0).strip(),
                    },
                )
            )
    return hits


# ---------------------------------------------------------------------------
# G-CENSUS - go.consensus.state_write_nondeterministic_provenance
#            (advisory, env-gated).  FUSION arm - NOT a 4th detector.
# ---------------------------------------------------------------------------
# The three DONE determinism arms each pair THEIR OWN narrow source with THEIR
# OWN narrow sink inside one function shape:
#   * G1 (map_iteration_nondeterministic_state_write) - range-over-map ORDER;
#   * G4 (nondeterministic_time_float_rand)           - wall-clock / RNG / float;
#   * G5 (unmarshal_type_ambiguity_first_match)       - non-canonical decode.
# This census INVERTS control: it enumerates the consensus-state-WRITE universe
# ONCE (the UNION of every arm's sink regex PLUS the previously-uncovered cosmos
# ``collections`` Map/KeySet/Item/Sequence handles - grep-confirmed 0 coverage
# of ``collections.(Map|KeySet|Item|Sequence)`` / ``.Push(`` in this runner),
# then fans the SAME source predicates (reused VERBATIM, zero re-derivation)
# over each write's value-provenance window and asks ONE question: "is this
# write's value provenance nondeterministic?"  A write reached by ANY of the
# four sources (map-range order / wall-clock+rand+float / non-canonical decode /
# goroutine-shared) is caught even when it lives in a function shape none of the
# standalone arms would have entered.  AppHash-divergence -> chain-halt class.
#
# Advisory-first: emitted ONLY behind AUDITOOOR_G_CONSENSUS_WRITE_DETERMINISM,
# verdict=needs-fuzz, NO auto-credit, kept OUT of pattern_results (never feeds
# go_findings / the fire subset).  De-duped by (file,line) against the already-
# emitted G1 + G4/G5/G6 hits (A1 dedup boundary, mirroring G4@1098 / G5@6957)
# so every consensus write is asked the determinism question exactly once.
#
# PRECISION (a deterministic write stays GREEN even under a nondet-shaped body):
#   * sorted keys        -> _MAP_KEY_ORDER neutralizes the map-range source;
#   * block-time         -> _G4_TIME_NOW matches ONLY ``time.Now(`` (not
#                           ctx.BlockTime), so header-time writes never fire;
#   * telemetry gauge    -> _G4_TELEMETRY / _G4_LATENCY_IDIOM suppress (via
#                           _g4_source_arm);
#   * decode discriminator -> _G5_DISCRIMINATOR present => canonical => suppress;
#   * IEEE754 float      -> de-prioritized (advisory_float=True; cross-arch
#                           deterministic);
#   * serialized goroutine -> _G6_GUARD in closure/enclosing scope => suppress.
GCENSUS_WRITE_DET_ENV = "AUDITOOOR_G_CONSENSUS_WRITE_DETERMINISM"
GCENSUS_WRITE_DET_PID = "go.consensus.state_write_nondeterministic_provenance"
GCENSUS_WRITE_DET_OUT = "consensus_write_determinism_census_hypotheses.jsonl"
GCENSUS_WRITE_DET_EXPLOIT_CLASS = "apphash-divergence"

# Cosmos ``collections`` handle declarations (Map/KeySet/IndexedMap/Item/
# Sequence) - both the struct-field/param form ``Balances collections.Map[...]``
# and the constructor form ``bals := collections.NewMap(...)``.  Analogous to
# _ident_is_map (map handles) but for collections handles: used to gate the
# collections write sink so only genuine collections writes are enumerated.
_GCENSUS_COLLECTIONS_DECL = re.compile(
    r"\b(?P<name>[A-Za-z_]\w*)\s*"
    r"(?::=\s*collections\.New(?:Map|KeySet|IndexedMap|Item|Sequence)\b"
    r"|\s+collections\.(?:Map|KeySet|IndexedMap|Item|Sequence)\b)"
)
# A consensus-state write onto a collections handle: ``<chain>.<handle>.Set(`` /
# ``.Remove(`` / ``.Push(`` - only credited when <handle> resolves to a
# collections decl (keeps precision: not every ``.Set(`` is a collections write).
# This closes the enumeration gap the arms' KVStore/keeper sink regexes miss.
_GCENSUS_COLLECTIONS_WRITE = re.compile(
    r"(?:[A-Za-z_]\w*\s*\.\s*)*(?P<handle>[A-Za-z_]\w*)\s*\.\s*"
    r"(?P<meth>Set|Remove|Push)\s*\("
)

# A GENUINE AppHash WRITE-LHS (precision fix): ``<x>.AppHash = <rhs>`` /
# ``AppHash = <rhs>`` - the AppHash identifier on the LEFT of a single ``=``
# assignment (``(?<!:)`` excludes the ``:=`` fresh-local decl; ``(?!=)`` excludes
# the ``==`` comparator).  The census enumerates AppHash writes ONLY through this
# regex, NEVER the bare ``\bAppHash\b`` token that lives in _MAP_CONSENSUS_SINK:
# a bare token also matches a RETURN (``return h.AppHash, nil``) or an RHS READ,
# which are NOT writes and manufactured net-new FPs the standalone arms never
# produced.  (A ``.SetAppHash(``/``k.SetAppHash(`` setter is already covered by
# the _G4_STORE_WRITE keeper-setter sink, so it need not be restated here.)
_GCENSUS_APPHASH_WRITE = re.compile(
    r"(?:[A-Za-z_]\w*\s*\.\s*)*\bAppHash\b\s*(?<!:)=(?!=)"
)

# OFF-CONSENSUS node subsystems (statesync / light-client / block-sync / mempool
# / p2p / privval): these run OUTSIDE the deterministic app state machine, so a
# nondeterministic value there never enters the app-hash the census reasons
# about.  cometbft's ``statesync``/``light`` trees pass ``time.Now()`` into
# light-block VERIFICATION (expiry/trust window), which taints no committed
# value - excluding them keeps the consensus-reachable gate honest.
_GCENSUS_OFFCONSENSUS_PATH = re.compile(
    r"(?:^|/)(?:statesync|state_sync|light|lite|blocksync|blockchain|"
    r"mempool|p2p|privval)/",
    re.IGNORECASE,
)

# Raw G4 arm -> its source regex, so the census can run the dataflow-link gate
# for the SAME source _g4_source_arm reported (it returns the arm, not the rx).
_G4_SOURCE_RX = {
    "time_now": _G4_TIME_NOW,
    "math_rand": _G4_MATH_RAND,
    "float": _G4_FLOAT,
}


def _gcensus_collection_handles(*sources: str) -> set:
    """Names bound to a cosmos ``collections`` handle across the given source
    blobs (function body/params + whole-file text for the cross-file keeper-
    field shape). Gates _GCENSUS_COLLECTIONS_WRITE so only real collections
    .Set/.Remove/.Push writes are enumerated (precision)."""
    handles: set = set()
    for src in sources:
        if not src or "collections." not in src:
            continue
        for m in _GCENSUS_COLLECTIONS_DECL.finditer(src):
            handles.add(m.group("name"))
    return handles


def _gcensus_enumerate_writes(masked_body: str, handles: set):
    """Yield ``(pos, sink_text, sink_kind)`` for every consensus-state write in
    the comment/string-masked body: the UNION of the existing arm sinks
    (reused _MAP_CONSENSUS_SINK + _G4_STORE_WRITE = KVStore/ctx-store/keeper-
    setter/byte-accumulator/event) PLUS the collections Map/KeySet/Item/Sequence
    .Set/.Remove/.Push writes (the census gap-closure) PLUS a GENUINE AppHash
    write-LHS.  This is the sink UNIVERSE the source oracles are fanned over.

    PRECISION: the bare ``\\bAppHash\\b`` token from _MAP_CONSENSUS_SINK is
    DROPPED here (it also matches a ``return h.AppHash``/RHS read, not a write);
    genuine AppHash writes are enumerated ONLY via _GCENSUS_APPHASH_WRITE (an
    assignment LHS).  This is a census-local tightening; the standalone G1 arm
    keeps _MAP_CONSENSUS_SINK verbatim (it searches only inside a map loop body,
    where the token is already constrained)."""
    seen_pos: set = set()
    for rx, kind in ((_MAP_CONSENSUS_SINK, "kv_store"),
                     (_G4_STORE_WRITE, "keeper_setter")):
        for m in rx.finditer(masked_body):
            # (a) drop the bare AppHash token: it is enumerated below ONLY when
            # it is a real write-LHS, never as a return/RHS occurrence.
            if m.group(0).strip() == "AppHash":
                continue
            if m.start() in seen_pos:
                continue
            seen_pos.add(m.start())
            yield m.start(), m.group(0).strip(), kind
    for m in _GCENSUS_APPHASH_WRITE.finditer(masked_body):
        if m.start() in seen_pos:
            continue
        seen_pos.add(m.start())
        yield m.start(), m.group(0).strip(), "apphash"
    if handles:
        for m in _GCENSUS_COLLECTIONS_WRITE.finditer(masked_body):
            if m.group("handle") not in handles:
                continue
            if m.start() in seen_pos:
                continue
            seen_pos.add(m.start())
            yield m.start(), m.group(0).strip(), "collections"


def _gcensus_enclosing_window(masked_body: str, pos: int) -> str:
    """Innermost brace-balanced block containing ``pos`` (masked body so braces
    inside string/comment literals do not mislead; offsets map 1:1 onto the raw
    body), falling back to the WHOLE body when ``pos`` sits at function-body top
    level.  This is the value-provenance window the G4/G5/G6 oracles fan over."""
    stack: list = []
    best = None
    for idx, ch in enumerate(masked_body):
        if ch == "{":
            stack.append(idx)
        elif ch == "}":
            if not stack:
                continue
            o = stack.pop()
            if o < pos < idx:
                if best is None or (idx - o) < (best[1] - best[0]):
                    best = (o, idx)
    if best is None:
        return masked_body
    return masked_body[best[0] + 1: best[1]]


def _gcensus_maprange_windows(masked_body: str, params: str):
    """(start,end,keyvar) char-spans of every UNORDERED range-over-map loop body
    - reuses G1's OWN predicate verbatim (_MAP_RANGE + _ident_is_map minus
    _MAP_KEY_ORDER, exactly as _detect_range_over_map_...@8256-8271).  A write
    whose pos falls in one of these spans has map-iteration-ORDER value
    provenance.  ``keyvar`` is the loop's KEY identifier (``for <keyvar>, v :=
    range m``), carried so the census can suppress an order-INVARIANT
    distinct-key write (each iteration writes ``store.Set(<keyvar>, ...)`` at a
    distinct key -> final state is order-independent).  Empty when any key
    ordering is present (G1 suppressor)."""
    if _MAP_KEY_ORDER.search(masked_body):
        return []
    spans = []
    for m in _MAP_RANGE.finditer(masked_body):
        ident = m.group("ident")
        if not (_ident_is_map(masked_body, ident) or _ident_is_map(params, ident)):
            continue
        brace_idx = masked_body.find("{", m.end())
        if brace_idx < 0:
            continue
        end_idx = _balance_braces(masked_body, brace_idx)
        if end_idx is None:
            continue
        spans.append((brace_idx, end_idx, m.group("k")))
    return spans


def _gcensus_write_is_distinct_key(write_line: str, keyvar: str | None) -> bool:
    """True when ``write_line`` is a keyed ``.Set/.Remove/.Insert(<key>, ...)``
    whose KEY argument (the first arg) references the map loop's ``keyvar`` - so
    each iteration writes a DISTINCT key and the committed state is INDEPENDENT
    of iteration order (an order-invariant write, NOT a map-order divergence).
    Accumulator writes (``.Push``/``append``/a fixed-key ``.Set``) return False
    because their result DOES depend on iteration order."""
    if not keyvar:
        return False
    m = re.search(r"\.(?:Set|Remove|Insert)\s*\(", write_line)
    if not m:
        return False
    # first argument (the key), sliced up to the top-level comma / close paren.
    depth = 0
    first_arg: list = []
    for ch in write_line[m.end():]:
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth == 0:
                break
            depth -= 1
        elif ch == "," and depth == 0:
            break
        first_arg.append(ch)
    return bool(re.search(r"\b" + re.escape(keyvar) + r"\b", "".join(first_arg)))


def _gcensus_bracket_depth(text: str, pos: int) -> int:
    """Net ``()[]{}`` nesting depth of ``text[:pos]`` - used to tell a source at
    a VALUE position (depth 0, e.g. ``x := time.Now().Unix()``) apart from a
    source buried as a nested call ARGUMENT (depth >0, e.g.
    ``h, _ := verify(ctx, time.Now())`` where the RESULT, not the wall-clock, is
    what gets assigned)."""
    return (
        text.count("(", 0, pos) - text.count(")", 0, pos)
        + text.count("[", 0, pos) - text.count("]", 0, pos)
        + text.count("{", 0, pos) - text.count("}", 0, pos)
    )


def _gcensus_split_assignment(line: str):
    """``(lhs, rhs)`` split of a Go assignment line at its top-level ``:=`` or a
    lone ``=`` (excluding ``==``/``!=``/``<=``/``>=``); ``(None, line)`` when the
    line is not an assignment (a bare call write)."""
    m = re.search(r":=|(?<![=!<>:])=(?!=)", line)
    if not m:
        return None, line
    return line[:m.start()], line[m.end():]


def _gcensus_g4_source_links_write(window: str, source_rx, write_value_expr: str) -> bool:
    """DATAFLOW-LINK gate (precision fix (b)): True iff the nondeterministic G4
    source actually FLOWS INTO ``write_value_expr`` - not merely co-occurs
    somewhere in ``window``.  A write is linked when either:
      * the source token appears directly in the write's value expression, OR
      * a variable TAINTED by the source (seeded at a VALUE position - the source
        at bracket-depth 0 of an assignment RHS, then propagated transitively)
        appears in the write's value expression.
    A source that only reaches a nested call ARGUMENT (depth >0, e.g. passed to a
    verification/expiry helper) taints nothing, so a write publishing that call's
    RESULT stays SILENT."""
    if source_rx.search(write_value_expr):
        return True
    tainted: set = set()
    for _ in range(6):  # bounded fixpoint over the window's assignments
        grew = False
        for line in window.split("\n"):
            lhs, rhs = _gcensus_split_assignment(line)
            if lhs is None:
                continue
            seed = any(
                _gcensus_bracket_depth(rhs, sm.start()) == 0
                for sm in source_rx.finditer(rhs)
            )
            if not seed:
                seed = any(
                    re.search(r"\b" + re.escape(t) + r"\b", rhs) for t in tainted
                )
            if not seed:
                continue
            for ident in re.findall(r"[A-Za-z_]\w*", lhs):
                if ident not in tainted:
                    tainted.add(ident)
                    grew = True
        if not grew:
            break
    return any(
        re.search(r"\b" + re.escape(t) + r"\b", write_value_expr) for t in tainted
    )


def _gcensus_decode_ambiguity_targets(window: str) -> set:
    """Distinct rival unmarshal targets in ``window`` when it carries the G5
    first-nil-wins ambiguity ladder (>=2 nil-accepts, >=2 rival targets on one
    buffer) with NO TypeUrl/version discriminator - reuses G5's OWN predicates
    (_G5_DISCRIMINATOR / _G5_NIL_ACCEPT / _G5_UNMARSHAL) as the source oracle.
    Empty set when the shape is absent or canonically discriminated (GREEN)."""
    if _G5_DISCRIMINATOR.search(window):
        return set()
    if len(_G5_NIL_ACCEPT.findall(window)) < 2:
        return set()
    by_arg: dict = {}
    for m in _G5_UNMARSHAL.finditer(window):
        by_arg.setdefault(m.group("arg"), set()).add(m.group("target"))
    rival: set = set()
    for _arg, targets in by_arg.items():
        if len(targets) >= 2:
            rival |= targets
    return rival


def _gcensus_goroutine_source(masked_body: str, pos: int, receiver: str):
    """Optional G6 oracle: ``go func(){...}`` (_G6_GO_CLOSURE) enclosing ``pos``
    whose write is a captured non-receiver shared cell (_g6_shared_write) with
    NO _G6_GUARD in the closure OR enclosing function scope.  Returns a source
    tag or None.  A serialized (mutex/channel/atomic) goroutine write is GREEN."""
    recv = None
    if receiver:
        rm = re.match(r"\s*(?P<recv>[A-Za-z_]\w*)\b", receiver)
        recv = rm.group("recv") if rm else None
    fn_guarded = bool(_G6_GUARD.search(masked_body))
    for gm in _G6_GO_CLOSURE.finditer(masked_body):
        cbrace = masked_body.find("{", gm.end())
        if cbrace < 0:
            continue
        cend = _balance_braces(masked_body, cbrace)
        if cend is None:
            continue
        if not (cbrace < pos < cend):
            continue
        cbody = masked_body[cbrace + 1:cend - 1]
        if fn_guarded or _G6_GUARD.search(cbody):
            return None
        local = set(re.findall(r"[A-Za-z_]\w*", gm.group("cparams")))
        found = _g6_shared_write(cbody, recv, local)
        if found is not None:
            return "go func:" + found[0]
    return None


def _detect_consensus_write_determinism_census(
    funcs: Iterable[GoFunction],
    file_sources: dict | None = None,
) -> list[Hit]:
    """G-CENSUS (ADVISORY) - the consensus-write determinism CENSUS.

    Enumerate every consensus-state write reachable from a consensus surface
    (reuse G4's CONTEXT gate: sdk.Context/context.Context param OR handler-shaped
    name OR keeper/abci/module path -> Msg-server/BeginBlocker/EndBlocker/ABCI),
    then fan the reused G1/G4/G5/G6 source predicates over each write's value-
    provenance window.  Emit a violator per (write, nondeterministic-source).

    Sources (each answering one provenance sub-question, reused verbatim):
      * map_range_order       (G1)  - write inside an unordered range-over-map;
      * wall_clock/unseeded_rand/float_arith (G4) - _g4_source_arm over window;
      * noncanonical_decode   (G5)  - value traces to a first-nil-wins ambiguous
                                      decode ladder with no discriminator;
      * goroutine_shared      (G6)  - captured non-receiver write in an unguarded
                                      goroutine closure.
    A write whose provenance includes NO nondeterministic source stays CLEAN.
    """
    handles_ws = (
        _gcensus_collection_handles(*list(file_sources.values()))
        if file_sources else set()
    )
    decode_arm_map = {
        "time_now": "wall_clock",
        "math_rand": "unseeded_rand",
        "float": "float_arith",
    }
    hits: list[Hit] = []
    seen: set = set()
    for fn in funcs:
        fpath = str(fn.file)
        norm = fpath.replace("\\", "/")
        if _ADV_TEST_FILE.search(fpath) or _ADV_GENERATED_FILE.search(norm):
            continue
        if _G4_TESTUTIL_PATH.search(norm) or _G4_TEST_NAME.search(fn.name):
            continue
        # (c) OFF-CONSENSUS node subsystems (statesync / light-client / block-
        # sync / mempool / p2p / privval) are NOT the deterministic app state
        # machine, so exclude them from the consensus-reachable gate even when a
        # context.Context param would otherwise pass it.
        if _GCENSUS_OFFCONSENSUS_PATH.search(norm):
            continue
        # CONSENSUS-REACHABLE CONTEXT gate (reuse G4@1039-1043 + module path).
        in_ctx = (
            bool(_ADV_CTX_PARAM.search(fn.params))
            or bool(_ADV_HANDLER_NAME.match(fn.name))
            or bool(_ADV_MODULE_PATH.search(norm))
            or bool(_G4_CTX_PATH.search(norm))
        )
        if not in_ctx:
            continue
        masked = _g7_mask_comments(fn.body)
        handles = handles_ws | _gcensus_collection_handles(fn.body, fn.params)
        maprange_spans = _gcensus_maprange_windows(masked, fn.params)
        # G5 ambiguity ladder is a function-scope shape (spans >=2 if-blocks), so
        # compute rival decode targets once over the whole body and link a write
        # to a target by the value it publishes.
        rival_targets = _gcensus_decode_ambiguity_targets(masked)
        for pos, sink_text, sink_kind in _gcensus_enumerate_writes(masked, handles):
            window = _gcensus_enclosing_window(masked, pos)
            ls = masked.rfind("\n", 0, pos) + 1
            le = masked.find("\n", pos)
            line_text = masked[ls:(le if le >= 0 else len(masked))]
            source_arm = None
            advisory_float = False
            frag = None
            # (1) MAP-RANGE-ORDER (G1 predicate reused as oracle).  (d) suppress
            # an order-INVARIANT distinct-key write (``store.Set(<keyvar>, ...)``
            # each iteration writes a distinct key -> order-independent state).
            span = next(
                ((o, c, kv) for (o, c, kv) in maprange_spans if o < pos < c),
                None,
            )
            if span is not None and not _gcensus_write_is_distinct_key(
                line_text, span[2]
            ):
                source_arm, frag = "map_range_order", "range-over-map"
            # (2) WALL-CLOCK / UNSEEDED-RAND / FLOAT (G4 predicate reused).  (b)
            # require the source to DATAFLOW into the written value, not merely
            # co-occur in the window (a source reaching only a verification arg
            # taints nothing).
            if source_arm is None:
                arm, g4frag = _g4_source_arm(
                    window, has_latency=bool(_G4_LATENCY_IDIOM.search(window))
                )
                if arm is not None:
                    _lhs, _wexpr = _gcensus_split_assignment(line_text)
                    if _gcensus_g4_source_links_write(
                        window, _G4_SOURCE_RX.get(arm, _G4_TIME_NOW), _wexpr
                    ):
                        source_arm = decode_arm_map.get(arm, arm)
                        advisory_float = arm == "float"
                        frag = g4frag
            # (3) NON-CANONICAL DECODE (G5 predicate reused): the write publishes
            # a value that traces back to a rival decode target.
            if source_arm is None and rival_targets:
                if any(
                    re.search(r"\b" + re.escape(t) + r"\b", line_text)
                    for t in rival_targets
                ):
                    source_arm, frag = "noncanonical_decode", "proto.Unmarshal"
            # (4) GOROUTINE-SHARED (G6 predicate reused, optional).
            if source_arm is None:
                gv = _gcensus_goroutine_source(masked, pos, fn.receiver)
                if gv is not None:
                    source_arm, frag = "goroutine_shared", gv
            if source_arm is None:
                continue  # deterministic value provenance -> stays GREEN
            line_off = fn.body[:pos].count("\n")
            line = fn.body_start_line + line_off
            key = (fpath, line)
            if key in seen:
                continue
            seen.add(key)
            body_lines = fn.body.splitlines()
            snippet = (
                body_lines[line_off].strip()
                if line_off < len(body_lines) else fn.header
            )
            hits.append(
                Hit(
                    file=fpath,
                    line=line,
                    snippet=snippet[:200],
                    extra={
                        "function": fn.name,
                        "source_arm": source_arm,
                        "sink_text": sink_text[:80],
                        "sink_kind": sink_kind,
                        "advisory_float": advisory_float,
                        "provenance_frag": (frag or "").strip()[:80],
                    },
                )
            )
    return hits


def _emit_consensus_write_determinism_census_hypotheses(
    workspace: Path,
    funcs: Iterable[GoFunction],
    file_sources: dict,
    map_iter_hits: Iterable[Hit],
    *,
    out_path: Path | None = None,
) -> tuple[list[dict], Path]:
    """Advisory G-CENSUS emitter. Returns ``(records, out_path)`` and writes a
    ``needs-fuzz`` hypotheses jsonl.  De-dups emitted (file,line) against the
    arms the census FUSES - G1 (map-iteration, passed in from pattern_results)
    plus the G4/G5/G6 advisory hits - so a write those arms already surfaced is
    NOT restated (A1 dedup boundary; NO ``covered_by`` re-derivation).  NO auto-
    credit: every record carries ``verdict="needs-fuzz"``.
    """
    hits = _detect_consensus_write_determinism_census(funcs, file_sources)
    covered = {(h.file, h.line) for h in map_iter_hits}
    covered |= {
        (h.file, h.line)
        for h in _detect_nondeterministic_time_float_rand(funcs)
    }
    covered |= {
        (h.file, h.line)
        for h in _detect_unmarshal_type_ambiguity_first_match(funcs)
    }
    try:
        covered |= {
            (h.file, h.line)
            for h in _detect_goroutine_fanout_unsync_shared(file_sources or {})
        }
    except Exception:
        pass  # G6 dedup is best-effort; never break the census on it
    records: list[dict] = []
    for h in hits:
        if (h.file, h.line) in covered:
            continue
        records.append({
            "workspace": str(workspace),
            "file": h.file,
            "line": h.line,
            "function": h.extra.get("function"),
            "source_arm": h.extra.get("source_arm"),
            "sink_text": h.extra.get("sink_text"),
            "sink_kind": h.extra.get("sink_kind"),
            "advisory_float": h.extra.get("advisory_float"),
            "provenance_frag": h.extra.get("provenance_frag"),
            "snippet": h.snippet,
            "pattern_id": GCENSUS_WRITE_DET_PID,
            "attack_class": "consensus-nondeterminism-chain-halt",
            "exploit_class": GCENSUS_WRITE_DET_EXPLOIT_CLASS,
            "lane": "G-CENSUS",
            "verdict": "needs-fuzz",
        })
    out = (
        Path(out_path) if out_path
        else workspace / ".auditooor" / GCENSUS_WRITE_DET_OUT
    )
    out.parent.mkdir(parents=True, exist_ok=True)
    text = "".join(json.dumps(r, sort_keys=True) + "\n" for r in records)
    out.write_text(text, encoding="utf-8")
    return records, out


# ---------------------------------------------------------------------------
# orchestration
# ---------------------------------------------------------------------------

class _StrictVerificationError(ValueError):
    """An invalid canonical inventory or strict evidence input."""


def _strict_unit_id(row: dict, rel: str) -> str:
    """Return the inventory's exact ID, or a deterministic file/function ID."""
    for key in ("unit_id", "inventory_unit_id", "id"):
        value = row.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    identity = {
        "file": rel,
        "function": str(row.get("function") or row.get("fn") or "").strip(),
    }
    digest = hashlib.sha256(
        json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()[:24]
    return f"go-unit-{digest}"


def _strict_hit_id(pattern_id: str, hit: Hit) -> str:
    body = {
        "language": "go",
        "pattern_id": pattern_id,
        "file": hit.file,
        "line": hit.line,
        "snippet": hit.snippet,
        "function": hit.extra.get("function", ""),
    }
    digest = hashlib.sha256(
        json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()[:24]
    return f"go-hit-{digest}"


def _strict_row_is_excluded(row: dict) -> bool:
    return row.get("applicable") is False or row.get("in_scope") is False


def _strict_status_errors(row: dict, label: str) -> list[str]:
    errors: list[str] = []
    if row.get("degraded") is True:
        errors.append(f"{label}:degraded")
    for key in ("parser_error", "parse_error", "parser_errors", "parse_errors"):
        value = row.get(key)
        if value not in (None, False, [], ""):
            errors.append(f"{label}:{key}")
    status = str(row.get("parser_status") or row.get("scan_status") or row.get("status") or "").strip().lower()
    if status in {"missing", "degraded", "error", "failed", "parser-error", "parser_error"}:
        errors.append(f"{label}:{status}")
    return errors


def _load_strict_inventory(workspace: Path) -> tuple[list[dict], dict[str, dict], list[Path], list[str], str]:
    path = workspace / ".auditooor" / "inscope_units.jsonl"
    if not path.is_file() or path.is_symlink():
        raise _StrictVerificationError("missing canonical in-scope inventory")
    rows: list[dict] = []
    errors: list[str] = []
    try:
        raw_lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise _StrictVerificationError(f"cannot read canonical inventory: {exc}") from exc
    if not raw_lines:
        raise _StrictVerificationError("empty canonical in-scope inventory")
    for line_no, raw in enumerate(raw_lines, 1):
        if not raw.strip():
            errors.append(f"inventory:{line_no}:blank row")
            continue
        try:
            row = json.loads(raw)
        except json.JSONDecodeError as exc:
            errors.append(f"inventory:{line_no}:malformed JSON")
            continue
        if not isinstance(row, dict):
            errors.append(f"inventory:{line_no}:object required")
            continue
        rows.append(row)
    if errors:
        raise _StrictVerificationError("; ".join(errors))

    units: dict[str, dict] = {}
    files: dict[str, Path] = {}
    for index, row in enumerate(rows, 1):
        if _strict_row_is_excluded(row):
            continue
        raw_file = row.get("file") or row.get("path")
        if not isinstance(raw_file, str) or not raw_file.strip():
            errors.append(f"inventory:{index}:missing file")
            continue
        rel = raw_file.replace("\\", "/").strip().lstrip("./")
        candidate = Path(rel)
        if candidate.is_absolute() or ".." in candidate.parts:
            errors.append(f"inventory:{index}:path escapes workspace")
            continue
        if candidate.suffix.lower() != ".go":
            declared = str(row.get("lang") or row.get("language") or "").strip().lower()
            if declared in {"go", ".go"}:
                errors.append(f"inventory:{index}:Go row is not a .go source")
            continue
        declared = str(row.get("lang") or row.get("language") or "").strip().lower()
        if declared and declared not in {"go", ".go"}:
            errors.append(f"inventory:{index}:language mismatch")
            continue
        source = workspace / candidate
        if source.is_symlink() or not source.is_file():
            errors.append(f"inventory:{index}:missing source {rel}")
            continue
        unit_id = _strict_unit_id(row, rel)
        if unit_id in units:
            errors.append(f"inventory:{index}:duplicate unit id {unit_id}")
            continue
        normalized = dict(row)
        normalized["file"] = rel
        normalized["unit_id"] = unit_id
        normalized["_line"] = index
        units[unit_id] = normalized
        files[rel] = source
        errors.extend(_strict_status_errors(row, f"inventory:{index}"))
    if errors:
        raise _StrictVerificationError("; ".join(errors))
    return rows, units, [files[key] for key in sorted(files)], [], hashlib.sha256(path.read_bytes()).hexdigest()


def _strict_parse_errors(src: str) -> list[str]:
    """Catch the truncated function bodies the legacy regex parser skips."""
    errors: list[str] = []
    for match in _FUNC_HEADER.finditer(src):
        brace = src.find("{", match.end())
        if brace >= 0 and _balance_braces(src, brace) is None:
            line = src.count("\n", 0, match.start()) + 1
            errors.append(f"parser error at line {line}: unbalanced function body")
    return errors


def _strict_disposition_paths(workspace: Path) -> list[Path]:
    names = (STRICT_DISPOSITION_FILENAME, "detector_dispositions.jsonl")
    return [workspace / ".auditooor" / name for name in names
            if (workspace / ".auditooor" / name).is_file()]


def _strict_source_evidence(workspace: Path, value, inventory_files: set[str]) -> bool:
    entries = [value] if isinstance(value, dict) else value
    if not isinstance(entries, list) or not entries:
        return False
    for entry in entries:
        if isinstance(entry, str):
            match = re.match(r"^(.+):(\d+)$", entry.strip())
            if not match:
                return False
            rel, line = match.group(1), int(match.group(2))
        elif isinstance(entry, dict):
            rel = entry.get("file") or entry.get("path") or entry.get("source_ref")
            line = entry.get("line")
            if not isinstance(rel, str) or not rel.strip() or isinstance(line, bool):
                return False
            try:
                line = int(line)
            except (TypeError, ValueError):
                return False
        else:
            return False
        rel = str(rel).replace("\\", "/").strip().lstrip("./")
        candidate = Path(rel)
        if candidate.is_absolute() or ".." in candidate.parts or line <= 0:
            return False
        if rel not in inventory_files:
            return False
        source = workspace / candidate
        if source.is_symlink() or not source.is_file():
            return False
        if line > len(source.read_text(encoding="utf-8", errors="replace").splitlines()):
            return False
    return True


def _strict_verify_hits(
    workspace: Path,
    pattern_results: dict[str, list[Hit]],
    units: dict[str, dict],
    scanned_units: set[str],
    inventory_sha256: str,
    parser_errors: list[str],
) -> dict:
    by_file: dict[str, list[dict]] = {}
    for unit in units.values():
        by_file.setdefault(unit["file"], []).append(unit)
    dispositions: dict[str, dict] = {}
    errors = list(parser_errors)
    for path in _strict_disposition_paths(workspace):
        for line_no, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if not raw.strip():
                errors.append(f"disposition:{path.name}:{line_no}:blank row")
                continue
            try:
                record = json.loads(raw)
            except json.JSONDecodeError:
                errors.append(f"disposition:{path.name}:{line_no}:malformed JSON")
                continue
            if not isinstance(record, dict):
                errors.append(f"disposition:{path.name}:{line_no}:object required")
                continue
            hit_id = record.get("hit_id") or record.get("stable_id") or record.get("finding_id")
            disposition_type = record.get("disposition_type")
            if not isinstance(hit_id, str) or not hit_id.strip():
                errors.append(f"disposition:{path.name}:{line_no}:missing stable hit id")
                continue
            if disposition_type not in _STRICT_DISPOSITION_TYPES:
                errors.append(f"disposition:{path.name}:{line_no}:invalid disposition type")
                continue
            if record.get("schema") not in (None, STRICT_DISPOSITION_SCHEMA):
                errors.append(f"disposition:{path.name}:{line_no}:schema mismatch")
                continue
            if hit_id in dispositions:
                errors.append(f"disposition:{path.name}:{line_no}:duplicate stable hit id")
                continue
            dispositions[hit_id] = record

    unresolved: list[dict] = []
    emitted = 0
    for pattern_id, hits in pattern_results.items():
        for hit in hits:
            emitted += 1
            hit_id = _strict_hit_id(pattern_id, hit)
            candidates = by_file.get(hit.file, [])
            function = str(hit.extra.get("function") or "").strip()
            if function:
                matching = [u for u in candidates if str(u.get("function") or u.get("fn") or "").strip() == function]
                if matching:
                    candidates = matching
            if len(candidates) != 1:
                unresolved.append({"hit_id": hit_id, "pattern_id": pattern_id, "file": hit.file, "line": hit.line, "reason": "hit not mapped to one inventory unit"})
                continue
            record = dispositions.get(hit_id)
            if record is None:
                unresolved.append({"hit_id": hit_id, "pattern_id": pattern_id, "unit_id": candidates[0]["unit_id"], "file": hit.file, "line": hit.line, "reason": "no exact typed disposition"})
                continue
            if record.get("unit_id") != candidates[0]["unit_id"]:
                unresolved.append({"hit_id": hit_id, "pattern_id": pattern_id, "file": hit.file, "line": hit.line, "reason": "disposition unit id mismatch"})
                continue
            if record.get("pattern_id") not in (None, pattern_id):
                unresolved.append({"hit_id": hit_id, "pattern_id": pattern_id, "file": hit.file, "line": hit.line, "reason": "disposition pattern id mismatch"})
                continue
            evidence = record.get("source_evidence") or record.get("source_refs")
            if not _strict_source_evidence(workspace, evidence, set(by_file)):
                unresolved.append({"hit_id": hit_id, "pattern_id": pattern_id, "unit_id": candidates[0]["unit_id"], "file": hit.file, "line": hit.line, "reason": "missing local source evidence"})

    missing_units = sorted(set(units) - scanned_units)
    return {
        "schema": STRICT_SCHEMA,
        "mode": "strict",
        "language": "go",
        "verdict": "pass" if not errors and not unresolved and not missing_units else "fail",
        "inventory": {"path": ".auditooor/inscope_units.jsonl", "sha256": inventory_sha256, "unit_count": len(units), "source_file_count": len(by_file)},
        "scanned_units": sorted(scanned_units),
        "scanned_unit_count": len(scanned_units),
        "missing_units": missing_units,
        "emitted_hit_count": emitted,
        "unresolved_hits": unresolved,
        "disposition_paths": [str(p.relative_to(workspace)) for p in _strict_disposition_paths(workspace)],
        "errors": errors,
    }

def _load_is_in_scope():
    """Lazy-load scope_exclusion.is_in_scope (manifest-authoritative). Returns None
    if unavailable so the walk degrades to its prior (unfiltered) behavior."""
    try:
        import sys as _sys
        _lib = str(Path(__file__).resolve().parent / "lib")
        if _lib not in _sys.path:
            _sys.path.insert(0, _lib)
        from scope_exclusion import is_in_scope  # type: ignore
        return is_in_scope
    except Exception:
        return None


def _walk_go_files(root: Path) -> Iterable[Path]:
    is_in_scope = _load_is_in_scope()
    for path in root.rglob("*.go"):
        if any(part in _SKIP_DIRS for part in path.parts):
            continue
        # SCOPE: when a <ws>/.auditooor/inscope_units.jsonl manifest exists,
        # is_in_scope trusts it verbatim so OOS sibling trees (e.g. cannon /
        # op-program / op-batcher on the OP Stack) are NOT scanned; without a
        # manifest is_in_scope is permissive, preserving prior behavior.
        if is_in_scope is not None:
            try:
                rel = str(path.relative_to(root))
            except ValueError:
                rel = str(path)
            if not is_in_scope(rel, workspace=root):
                continue
        # skip generated test fixtures from OTHER detectors so we don't
        # cross-pollinate counts
        yield path


def scan_workspace(
    workspace: Path,
    guard_names: tuple[str, ...],
    *,
    fire_only: bool = False,
    strict: bool = False,
) -> dict:
    workspace = workspace.resolve()
    strict_units: dict[str, dict] = {}
    strict_inventory_sha256 = ""
    strict_errors: list[str] = []
    if strict:
        try:
            _, strict_units, strict_paths, _, strict_inventory_sha256 = _load_strict_inventory(workspace)
            files = strict_paths
        except _StrictVerificationError as exc:
            strict_errors.append(str(exc))
            files = []
    else:
        files = list(_walk_go_files(workspace))

    funcs: list[GoFunction] = []
    file_sources: dict[Path, str] = {}
    funcs_by_file: dict[Path, list[GoFunction]] = {}
    strict_scanned_units: set[str] = set()
    for f in files:
        try:
            src = f.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            if strict:
                strict_errors.append(f"source read error {f}: {exc}")
            continue
        rel = f.relative_to(workspace)
        file_sources[rel] = src
        new_funcs = _extract_functions(src, rel)
        funcs.extend(new_funcs)
        funcs_by_file[rel] = new_funcs
        if strict:
            rel_text = rel.as_posix()
            file_units = [u for u in strict_units.values() if u["file"] == rel_text]
            strict_errors.extend(_strict_parse_errors(src))
            for unit in file_units:
                declared_fn = str(unit.get("function") or unit.get("fn") or "").strip()
                if declared_fn and not any(fn.name == declared_fn for fn in new_funcs):
                    strict_errors.append(
                        f"parser did not enumerate inventory function {rel_text}::{declared_fn}"
                    )
                else:
                    strict_scanned_units.add(unit["unit_id"])

    pattern_results = {
        "go.bitcoin.txid_equality_without_utxo_spend_check":
            _detect_txid_eq_no_spend(funcs),
        "go.bitcoin.txid_without_vout_outpoint_binding":
            _detect_txid_without_vout_binding(funcs),
        "go.statemachine.guard_only_on_one_path":
            _detect_guard_only_on_one_path(funcs, guard_names),
        "go.statemachine.self_heal_on_unexpected_status":
            _detect_self_heal_unexpected_status(funcs),
        "go.protohash.kind_identifier_collision":
            _detect_protohash_kind_collision(funcs),
        "go.consensus.gossip_perimeter_trust":
            _detect_gossip_perimeter_trust(file_sources, funcs_by_file),
        "go.bitcoin.byte_reversed_lookup_set":
            _detect_byte_reversed_lookup_set(funcs),
        "go.cosmos.message_ordering_replay":
            _detect_cosmos_message_ordering_replay(funcs),
        "go.lightning.htlc_settlement_state_drift":
            _detect_lightning_htlc_state_drift(funcs),
        "go.frost.aggregate_pubkey_invariant_violation":
            _detect_frost_aggregate_pubkey_invariant(funcs),
        "go.cosmos.gas_price_zero_unchecked":
            _detect_gas_price_zero_unchecked(funcs),
        "go.cosmos.vote_extension_unverified":
            _detect_vote_extension_unverified(funcs),
        "go.spark.tree_node.terminal_state_revival":
            _detect_tree_node_terminal_state_revival(funcs),
        "go.spark.coop_exit.coordinator_confirmation_guard_asymmetry":
            _detect_coop_exit_coordinator_guard_asymmetry(file_sources, funcs_by_file),
        "go.spark.coop_exit.key_tweak_resumability":
            _detect_coop_exit_key_tweak_resumability(funcs, file_sources),
        "go.spark.signed_payload.req_identity_validator":
            _detect_signed_payload_req_identity_validator(funcs),
        "go.spark.retry.prior_phase_commit_check":
            _detect_retry_prior_phase_commit_check(funcs),
        "go.spark.cross_so.tweak_guard_pre_post_persist":
            _detect_cross_so_tweak_guard_pre_post_persist(funcs),
        "go.spark.leaf_marshal.knob_gated_residual_disclosure":
            _detect_knob_gated_leaf_marshal_residual(funcs),
        "go.spark.background_session.parent_tx_reopen_hook_missing":
            _detect_background_session_parent_tx_reopen_hook(funcs),
        "go.spark.post_commit_rollback_unprotected":
            _detect_post_commit_rollback_unprotected(funcs),
        "go.spark.cron_forupdate.adjacent_read_lock_missing":
            _detect_cron_forupdate_adjacent_read_lock_missing(
                funcs_by_file, file_sources
            ),
        "go.spark.coordinator_fanout.tx_commit_before_remote_call":
            _detect_coordinator_fanout_tx_commit_before_remote_call(funcs),
        "go.spark.grpc.default_service_config_last_write_wins":
            _detect_grpc_default_service_config_last_write_wins(funcs),
        "go.spark.multi_receiver.rollup_first_only":
            _detect_multi_receiver_rollup_first_only(funcs),
        "go.spark.so_pubkey.req_payload_not_session":
            _detect_so_pubkey_req_payload_not_session(funcs),
        "go.spark.guard_set.shrinkage_status_still_set":
            _detect_guard_set_shrinkage_status_still_set(
                file_sources, funcs_by_file
            ),
        "go.crypto.alias.constructor_stores_caller_slice_without_copy":
            _detect_constructor_stores_caller_slice_without_copy(funcs),
        "go.crypto.unmarshal.trailing_bytes_accepted":
            _detect_unmarshal_trailing_bytes_accepted(funcs),
        "go.spark.rpc_boundary.bare_fmterrorf_user_input_parse_failure":
            _detect_rpc_bare_fmterrorf_user_input_parse_failure(funcs),
        "go.crypto.alias.exported_getter_returns_internal_slice_without_copy":
            _detect_exported_getter_returns_internal_slice_without_copy(
                file_sources
            ),
        "go.spark.ent.edge_join_with_eq_when_denormalized_column_exists":
            _detect_ent_edge_join_when_denormalized_column_exists(funcs),
        "go.crypto.panic.zero_or_negative_length_reaches_make_slice":
            _detect_zero_or_negative_length_reaches_make_slice(funcs),
        "go.crypto.parse.negative_or_zero_int_unchecked":
            _detect_parse_negative_or_zero_int_unchecked(funcs),
        "go.crypto.scalar_mult.identity_point_unchecked":
            _detect_scalar_mult_identity_unchecked(funcs),
        "go.go.panic.dereference_before_nil_check":
            _detect_panic_dereference_before_nil_check(funcs),
        "go.crypto.loop.untrusted_length_unbounded":
            _detect_loop_untrusted_length_unbounded(funcs),
        "go.crypto.counter.wrap_unchecked":
            _detect_counter_wrap_unchecked(funcs),
        "go.crypto.fips.approval_on_uninit":
            _detect_fips_approval_on_uninit(funcs),
        "go.crypto.race.unsynchronized_concurrent_access":
            _detect_race_unsynchronized_concurrent_access(file_sources),
        "go.crypto.skip_allowed.strict_lt_only":
            _detect_skip_allowed_strict_lt_only(funcs),
        "go.crypto.x509.suffix_match_no_dot_anchor":
            _detect_x509_suffix_match_no_dot_anchor(funcs),
        "go.crypto.context_cancel.afterfunc_on_success":
            _detect_context_afterfunc_on_success(funcs),
        "go.crypto.kem.imported_key_skips_pairwise_consistency_test":
            _detect_kem_imported_key_skips_pairwise(funcs),
        "go.cosmos.subaccount_filter_mismatch":
            _detect_subaccount_filter_mismatch(funcs),
        "go.cosmos.stale_tail_health_check":
            _detect_stale_tail_health_check(funcs),
        "go.consensus.map_iteration_nondeterministic_state_write":
            _detect_range_over_map_nondeterministic_consensus_write(funcs),
    }

    # G2 advisory (env-gated, OFF by default): emit attacker-divisor-zero
    # hypotheses (verdict=needs-fuzz, NO auto-credit) to a dedicated jsonl,
    # de-duplicated against Pattern 11.  Kept OUT of `patterns` so it never
    # feeds go_findings / the fire subset.
    if os.environ.get(G2_ATTACKER_DIVISOR_ENV):
        try:
            _emit_attacker_divisor_hypotheses(
                workspace,
                funcs,
                pattern_results["go.cosmos.gas_price_zero_unchecked"],
            )
        except Exception as exc:  # never break the scan on advisory failure
            print(
                f"[go-detector-runner] WARN G2 advisory emit failed: {exc}",
                file=sys.stderr,
            )

    # G4 advisory (env-gated, OFF by default): emit nondeterministic
    # time.Now/rand/float consensus-write hypotheses (verdict=needs-fuzz, NO
    # auto-credit) to a dedicated jsonl, de-duplicated against the
    # map-iteration determinism detector.  Kept OUT of `patterns`.
    if os.environ.get(G4_NONDET_ENV):
        try:
            _emit_nondeterministic_time_float_rand_hypotheses(
                workspace,
                funcs,
                pattern_results[
                    "go.consensus.map_iteration_nondeterministic_state_write"
                ],
            )
        except Exception as exc:  # never break the scan on advisory failure
            print(
                f"[go-detector-runner] WARN G4 advisory emit failed: {exc}",
                file=sys.stderr,
            )

    # G6 advisory (env-gated, OFF by default): emit goroutine-fan-out
    # unsynchronized-shared-write hypotheses (verdict=needs-fuzz, NO auto-
    # credit) to a dedicated jsonl, de-duplicated against Pattern 39. Kept
    # OUT of `patterns` so it never feeds go_findings / the fire subset.
    if os.environ.get(G6_FANOUT_ENV):
        try:
            _emit_goroutine_fanout_unsync_shared_hypotheses(
                workspace,
                file_sources,
                pattern_results[
                    "go.crypto.race.unsynchronized_concurrent_access"
                ],
            )
        except Exception as exc:  # never break the scan on advisory failure
            print(
                f"[go-detector-runner] WARN G6 advisory emit failed: {exc}",
                file=sys.stderr,
            )

    # G7 advisory (env-gated, OFF by default): emit one-sided nonce/seq
    # acceptance hypotheses (verdict=needs-fuzz, NO auto-credit) to a
    # dedicated jsonl, de-duplicated against Pattern 40's strict-``<`` hits.
    # Kept OUT of `patterns` so it never feeds go_findings / the fire subset.
    if os.environ.get(G7_ONESIDED_ENV):
        try:
            _emit_onesided_acceptance_hypotheses(
                workspace,
                funcs,
                pattern_results["go.crypto.skip_allowed.strict_lt_only"],
            )
        except Exception as exc:  # never break the scan on advisory failure
            print(
                f"[go-detector-runner] WARN G7 advisory emit failed: {exc}",
                file=sys.stderr,
            )

    # G8 advisory (env-gated, OFF by default): emit decode-accepts-malformed-
    # then-trusted hypotheses (verdict=needs-fuzz, NO auto-credit) to a
    # dedicated jsonl, de-duplicated against Pattern 5/6's gossip-perimeter
    # hits. Kept OUT of `patterns` so it never feeds go_findings / the fire
    # subset.
    if os.environ.get(G8_DECODE_ENV):
        try:
            _emit_decode_malformed_then_trusted_hypotheses(
                workspace,
                funcs,
                pattern_results["go.consensus.gossip_perimeter_trust"],
            )
        except Exception as exc:  # never break the scan on advisory failure
            print(
                f"[go-detector-runner] WARN G8 advisory emit failed: {exc}",
                file=sys.stderr,
            )

    # G9 advisory (env-gated, OFF by default): emit decoded-value-consumed-
    # unchecked (type-assert-panic / Any-unpack / decoded-pointer-nil-deref)
    # hypotheses (verdict=needs-fuzz, NO auto-credit) to a dedicated jsonl,
    # de-duplicated against Pattern 35 (go.go.panic.dereference_before_nil_check,
    # the generic pointer-deref detector Arm C is a strict decode-taint-gated
    # subset of). Kept OUT of `patterns` so it never feeds go_findings / the fire
    # subset.
    if os.environ.get(G9_DECODE_CONSUME_ENV):
        try:
            _emit_decode_consumption_type_nil_hypotheses(
                workspace,
                funcs,
                pattern_results["go.go.panic.dereference_before_nil_check"],
            )
        except Exception as exc:  # never break the scan on advisory failure
            print(
                f"[go-detector-runner] WARN G9 advisory emit failed: {exc}",
                file=sys.stderr,
            )

    # G11 advisory (env-gated, OFF by default): emit untrusted-ingress
    # unbounded-loop-or-panic hypotheses (verdict=needs-fuzz, NO auto-credit)
    # to a dedicated jsonl, de-duplicated against Pattern 36 (loop.untrusted_
    # length_unbounded, the in-file analog of fire7 cap-growth) AND Pattern 11
    # (gas_price_zero div-panic). Kept OUT of `patterns` so it never feeds
    # go_findings / the fire subset.
    if os.environ.get(G11_INGRESS_ENV):
        try:
            _emit_ingress_unbounded_loop_or_panic_hypotheses(
                workspace,
                funcs,
                pattern_results["go.crypto.loop.untrusted_length_unbounded"],
                pattern_results["go.cosmos.gas_price_zero_unchecked"],
            )
        except Exception as exc:  # never break the scan on advisory failure
            print(
                f"[go-detector-runner] WARN G11 advisory emit failed: {exc}",
                file=sys.stderr,
            )

    # G12 advisory (env-gated, OFF by default): emit goroutine-with-no-recover
    # reachable-panic hypotheses (verdict=needs-fuzz, NO auto-credit) to a
    # dedicated jsonl, de-duplicated against G6 (goroutine_fanout_unsync_shared,
    # the sibling goroutine-closure detector). Kept OUT of `patterns` so it
    # never feeds go_findings / the fire subset.
    if os.environ.get(G12_NORECOVER_ENV):
        try:
            _emit_goroutine_no_toplevel_recover_hypotheses(
                workspace,
                file_sources,
                _detect_goroutine_fanout_unsync_shared(file_sources),
            )
        except Exception as exc:  # never break the scan on advisory failure
            print(
                f"[go-detector-runner] WARN G12 advisory emit failed: {exc}",
                file=sys.stderr,
            )

    # G13 advisory (env-gated, OFF by default): emit consensus/validation
    # finalizing-select-ignores-ctx-cancellation hypotheses (verdict=needs-fuzz,
    # NO auto-credit) to a dedicated jsonl, de-duplicated against G12
    # (goroutine_no_toplevel_recover) by (file,line). Distinct exploit_class
    # from G3/G12 (PANIC) by construction: G13 attacks the freshness invariant
    # (a verdict finalized after the caller already cancelled). Kept OUT of
    # `patterns` so it never feeds go_findings / the fire subset.
    if os.environ.get(G13_CTXVERDICT_ENV):
        try:
            _emit_ctx_cancellation_ignored_verdict_hypotheses(
                workspace,
                funcs,
                file_sources,
                _detect_goroutine_no_toplevel_recover(file_sources),
            )
        except Exception as exc:  # never break the scan on advisory failure
            print(
                f"[go-detector-runner] WARN G13 advisory emit failed: {exc}",
                file=sys.stderr,
            )

    # G15 advisory (env-gated, OFF by default): emit iteration-bound-bypass
    # hypotheses (verdict=needs-fuzz, NO auto-credit) to a dedicated jsonl. G15
    # fires on a bounded iteration whose per-item cap is bypassed by a sibling
    # continue-exit that skips the counter increment. DEDUP is by disjoint
    # predicate (cap PRESENT-but-BYPASSED) vs G11 / Pattern 36 (cap ABSENT), so
    # no runtime diff is needed. Kept OUT of `patterns` so it never feeds
    # go_findings / the fire subset.
    if os.environ.get(_G15_ITER_BOUND_BYPASS_ENV):
        try:
            _emit_iteration_bound_bypass_hypotheses(
                workspace,
                file_sources,
                funcs_by_file,
            )
        except Exception as exc:  # never break the scan on advisory failure
            print(
                f"[go-detector-runner] WARN G15 advisory emit failed: {exc}",
                file=sys.stderr,
            )

    # G14 advisory (env-gated, OFF by default): emit error-wrap-loses-sentinel
    # hypotheses (verdict=needs-fuzz, NO auto-credit) to a dedicated jsonl. G14
    # fires when a sentinel-identity guard (errors.Is / == ErrSentinel) is
    # rendered dead by a lossy fmt.Errorf (non-%w) wrap of that SAME sentinel in
    # the same file. DEDUP is by disjoint predicate (guard + lossy-wrap of the
    # sentinel) vs Pattern 29 (bare RPC parse-error wrap, no sentinel guard), so
    # no runtime diff is needed. Kept OUT of `patterns` so it never feeds
    # go_findings / the fire subset.
    if os.environ.get(_G14_SENTINEL_LOSS_ENV):
        try:
            _emit_sentinel_loss_hypotheses(
                workspace,
                file_sources,
                funcs_by_file,
            )
        except Exception as exc:  # never break the scan on advisory failure
            print(
                f"[go-detector-runner] WARN G14 advisory emit failed: {exc}",
                file=sys.stderr,
            )

    # G5 advisory (env-gated, OFF by default): emit unmarshal-type-ambiguity
    # first-match hypotheses (verdict=needs-fuzz, NO auto-credit) to a dedicated
    # jsonl, de-duplicated against Pattern 28 (unmarshal.trailing_bytes_accepted).
    # Distinct from G1 (map-iteration) by construction. Kept OUT of `patterns`
    # so it never feeds go_findings / the fire subset.
    if os.environ.get(G5_UNMARSHAL_AMBIG_ENV):
        try:
            _emit_unmarshal_type_ambiguity_hypotheses(
                workspace,
                funcs,
                pattern_results["go.crypto.unmarshal.trailing_bytes_accepted"],
            )
        except Exception as exc:  # never break the scan on advisory failure
            print(
                f"[go-detector-runner] WARN G5 advisory emit failed: {exc}",
                file=sys.stderr,
            )

    # G-CENSUS advisory (env-gated, OFF by default): the consensus-write
    # determinism CENSUS - enumerate every consensus-state write (KVStore/keeper
    # sinks UNIONed with the previously-uncovered cosmos collections handles) and
    # fan the reused G1/G4/G5/G6 source predicates over each write's value
    # provenance; emit a violator per (write, nondeterministic-source) with
    # verdict=needs-fuzz (NO auto-credit), de-duped by (file,line) vs the arms it
    # fuses. Kept OUT of `patterns` so it never feeds go_findings / the fire subset.
    if os.environ.get(GCENSUS_WRITE_DET_ENV):
        try:
            _emit_consensus_write_determinism_census_hypotheses(
                workspace,
                funcs,
                file_sources,
                pattern_results[
                    "go.consensus.map_iteration_nondeterministic_state_write"
                ],
            )
        except Exception as exc:  # never break the scan on advisory failure
            print(
                f"[go-detector-runner] WARN G-CENSUS advisory emit failed: {exc}",
                file=sys.stderr,
            )

    # --fire-only: restrict to the confirmed-bug / low-FP pattern subset.
    # Build the allowed-set lazily so the scan still runs all detectors
    # (cheap) and we only gate the output shape here.
    if fire_only:
        all_ids: frozenset[str] = frozenset(pattern_results.keys())
        _allowed: frozenset[str] = _build_fire_pattern_ids(all_ids)
    else:
        _allowed = frozenset(pattern_results.keys())

    patterns_out: dict = {}
    total_hits = 0
    hit_files: set[str] = set()
    for pid, hits in pattern_results.items():
        if pid not in _allowed:
            continue
        hit_rows = []
        for hit in hits:
            row = hit.to_json()
            if strict:
                row["stable_id"] = _strict_hit_id(pid, hit)
                row["pattern_id"] = pid
                candidates = [
                    unit for unit in strict_units.values()
                    if unit["file"] == hit.file
                ]
                function = str(hit.extra.get("function") or "").strip()
                matching = [
                    unit for unit in candidates
                    if str(unit.get("function") or unit.get("fn") or "").strip() == function
                ] if function else candidates
                if len(matching) == 1:
                    row["unit_id"] = matching[0]["unit_id"]
            hit_rows.append(row)
        patterns_out[pid] = {
            "id": pid,
            "hit_count": len(hits),
            "hits": hit_rows,
        }
        total_hits += len(hits)
        hit_files.update(h.file for h in hits)

    summary = {
        "schema_version": 1,
        "workspace": str(workspace),
        "scanner": "go-detector-runner.py",
        "scanner_version": SCANNER_VERSION,
        "go_files_scanned": len(files),
        "patterns": patterns_out,
        "totals": {"hits": total_hits, "files": len(hit_files)},
        "fire_only": fire_only,
    }
    if strict:
        summary["strict_verification"] = _strict_verify_hits(
            workspace,
            pattern_results if not fire_only else {
                pid: hits for pid, hits in pattern_results.items() if pid in _allowed
            },
            strict_units,
            strict_scanned_units,
            strict_inventory_sha256,
            strict_errors,
        )
    return summary


def _write_outputs(workspace: Path, summary: dict) -> Path:
    out_dir = workspace / ".auditooor"
    out_dir.mkdir(parents=True, exist_ok=True)
    main_out = out_dir / "go_findings.json"
    alias_out = out_dir / "SCAN_GO_SUMMARY.json"
    text = json.dumps(summary, indent=2, sort_keys=True) + "\n"
    main_out.write_text(text, encoding="utf-8")
    alias_out.write_text(text, encoding="utf-8")
    return main_out


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else "")
    p.add_argument("--workspace", required=True, type=Path,
                   help="Workspace root to scan for *.go files.")
    p.add_argument("--guard-name", action="append", default=[],
                   help="Additional guard function name (repeatable).")
    p.add_argument("--print", action="store_true",
                   help="Print summary JSON to stdout.")
    p.add_argument(
        "--fire-only",
        action="store_true",
        default=False,
        help=(
            "Restrict emitted hits to the fire* confirmed-bug / low-FP pattern "
            "subset.  Excludes broad advisory patterns "
            f"({', '.join(sorted(_FIRE_EXCLUDED_PATTERN_IDS))}).  "
            "Default OFF (full scan behaviour preserved)."
        ),
    )
    p.add_argument(
        "--strict",
        action="store_true",
        help=(
            "Use the canonical in-scope inventory and fail closed on missing "
            "coverage, parser/read errors, or unresolved emitted hits."
        ),
    )
    args = p.parse_args(argv)

    ws = args.workspace
    if not ws.exists() or not ws.is_dir():
        print(f"[go-detector-runner] ERR workspace not found: {ws}",
              file=sys.stderr)
        return 2

    guard_names = tuple(_DEFAULT_GUARDS) + tuple(args.guard_name)
    summary = scan_workspace(ws, guard_names, fire_only=args.fire_only, strict=args.strict)
    out_path = _write_outputs(ws, summary)
    fire_tag = " [fire-only]" if args.fire_only else ""
    print(
        f"[go-detector-runner]{fire_tag} scanned {summary['go_files_scanned']} go files; "
        f"{summary['totals']['hits']} hits across "
        f"{len(summary['patterns'])} patterns -> {out_path}"
    )
    if args.print:
        print(json.dumps(summary, indent=2, sort_keys=True))
    if args.strict and summary["strict_verification"]["verdict"] != "pass":
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
