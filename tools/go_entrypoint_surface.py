#!/usr/bin/env python3
"""go_entrypoint_surface.py - the TRUE external attack surface of a Cosmos / Go-L1.

Why this exists (the root bug it fixes)
---------------------------------------
The per-function coverage gate (``function-coverage-completeness.py``) measures
BREADTH: was every externally-reachable ("entry") function actually attacked. For
Solidity it counts ``external``/``public`` only - an ``internal``/``private`` helper
is NOT in the denominator, because it is reached only THROUGH an external caller and
analysing that caller covers it.

For Go the gate used ``name[0].isupper()`` (every EXPORTED identifier) as the entry
surface. That is the WRONG analog: Go's ``export`` is a *linkage* property, not an
*external-attacker-reachability* property. A Cosmos L1 exports thousands of intra-
codebase helpers (``keeper.GetGasPool``, ``cachekv.Store.Set``, ``PrepareCtxForEVMTx``)
that no external actor can invoke directly - they are the Go analog of Solidity
``internal``. Counting them inflated e.g. SEI's denominator to ~11.7k fns and made the
gate demand a per-function verdict on every internal helper - over-scoping no real
audit does.

What the TRUE external surface of a Cosmos / Go-L1 IS
----------------------------------------------------
A finite, well-known set of framework interfaces / conventions - the only ways an
external actor (tx sender, EVM caller, RPC client, IBC counterparty, p2p peer,
consensus) can trigger code:

  1.  Tx message handlers      - methods on a ``msgServer`` (``Msg*`` in, ``*Response`` out)
  2.  ABCI / consensus app     - InitChain/PrepareProposal/ProcessProposal/ExtendVote/
                                 VerifyVoteExtension/FinalizeBlock/BeginBlock/EndBlock/
                                 CheckTx/DeliverTx/Commit/Query + snapshot chunk methods
  3.  Ante decorators          - ``AnteHandle``
  4.  IBC module callbacks     - ``OnRecvPacket``/``OnAcknowledgementPacket``/... (attacker
                                 = IBC counterparty)
  5.  Genesis                  - InitGenesis / ExportGenesis / ValidateGenesis
  6.  Module lifecycle hooks   - BeginBlocker / EndBlocker / Midblock / EndBlock
  7.  EVM precompile dispatch  - Run / Execute / RequiredGas (attacker = EVM caller)
  8.  EVM JSON-RPC API         - registered ``*API`` service methods in ``evmrpc/``
  9.  Mempool / p2p reactors   - Receive / ReceiveEnvelope / AddPeer / CheckTx / ...
 10.  CosmWasm dispatch        - Instantiate / Execute / Query / Sudo / Reply / Migrate
 11.  Stateless msg validation - ``ValidateBasic`` (attacker-controlled bytes)
 12.  Staking / slashing hooks - AfterValidatorCreated / BeforeDelegationCreated / ...
 13.  Boundary-file/package    - ANY exported method in a known entry-boundary FILE
                                 (``msg_server*.go``, ``abci*.go``, ``ante*.go``,
                                 ``handler*.go``, ``*genesis*.go``, ``*ibc_module*.go``,
                                 ``proposal*.go``) or PACKAGE (``precompiles/``) - a
                                 conservative-inclusive net so an unconventionally-NAMED
                                 handler that lives in a boundary location is still caught.

An exported helper that is NOT in any of these families (and not in a boundary
file/package) is an internal helper: it is reached only through an entry point, and is
covered transitively - exactly as a Solidity ``internal`` fn is.

Never-false-pass discipline (this is a completeness gate; under-scoping = false-green)
-------------------------------------------------------------------------------------
Narrowing a completeness denominator is dangerous: dropping a real entry point means the
gate no longer requires it to be covered, which can PASS an incompletely-audited
workspace. Three layers keep this safe:

  A. WORKSPACE fail-open: ``is_cosmos_go_workspace`` narrows ONLY when the workspace is
     CONFIDENTLY a Cosmos/Go-L1 (go.mod imports cosmos-sdk/cometbft/tendermint OR the
     canonical ``x/`` + (``app/`` | msg_server) layout). Anything else keeps the
     every-exported denominator. Falling back is always to the LARGER/stricter surface -
     never-false-pass by construction.

  B. FAMILY completeness + boundary-inclusive net: the 13 families above cover the whole
     Cosmos external boundary; family 13 adds an over-inclusive boundary-file/package
     net so a mis-NAMED entry point in a boundary location is still counted. When the
     classifier is unsure, it INCLUDES (keeps the fn as surface) - the drop only fires
     for a fn that is affirmatively an internal helper.

  C. Env kill-switch: ``AUDITOOOR_FCC_GO_ENTRYPOINT_SCOPE=0`` disables narrowing entirely
     (restores every-exported), so the change can never silently pass a workspace an
     operator wants scored the old way.

This module is PURE (stdlib + re), import-only, and has zero target hardcoding.
"""
from __future__ import annotations

import collections
import json
import os
import re
from pathlib import Path
from typing import Any, Callable, Optional


# --------------------------------------------------------------------------
# Workspace-level detector: is this a Cosmos / Go-L1 workspace?
# --------------------------------------------------------------------------
# go.mod dependency markers that unambiguously denote a Cosmos-SDK / CometBFT
# (Tendermint) chain. A Go workspace WITHOUT any of these (e.g. a plain Go
# service, a go-ethereum-only repo) is NOT narrowed - it keeps every-exported.
_COSMOS_GOMOD_MARKERS = (
    "github.com/cosmos/cosmos-sdk",
    "cosmossdk.io/",
    "github.com/cometbft/cometbft",
    "github.com/tendermint/tendermint",
    "github.com/cosmos/ibc-go",
    "github.com/CosmWasm/wasmd",
    # Sei vendors its forks in-tree under these module paths:
    "sei-protocol/sei-cosmos",
    "sei-protocol/sei-tendermint",
    "sei-protocol/sei-chain",
)

# Directories we never descend when sniffing go.mod / layout markers.
_WALK_SKIP = {
    ".git", "node_modules", "vendor", "third_party", "testdata",
    ".auditooor", "prior_audits", "reference", "docs", "poc-tests",
    "agent_outputs", "fuzz_runs", "cost_runs", "mining_rounds",
    "deep_counterexamples", "monitoring",
}

_ENV_DISABLE = "AUDITOOOR_FCC_GO_ENTRYPOINT_SCOPE"

# Per-ws memo so the (bounded) filesystem sniff runs once.
_WS_COSMOS_CACHE: dict = {}


def _env_narrowing_enabled() -> bool:
    """The narrowing is on by default; ``...=0/false/no/off`` disables it."""
    v = str(os.environ.get(_ENV_DISABLE, "")).strip().lower()
    return v not in ("0", "false", "no", "off")


def _iter_gomods(ws: Path, cap: int = 200):
    """Yield up to ``cap`` go.mod paths under ``ws`` (bounded, skip-listed walk)."""
    n = 0
    for dp, dns, fns in os.walk(ws):
        dns[:] = [d for d in dns if d not in _WALK_SKIP and not d.startswith(".")]
        if "go.mod" in fns:
            yield Path(dp) / "go.mod"
            n += 1
            if n >= cap:
                return


def _has_cosmos_gomod(ws: Path) -> bool:
    for gm in _iter_gomods(ws):
        try:
            txt = gm.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        low = txt.lower()
        if any(m.lower() in low for m in _COSMOS_GOMOD_MARKERS):
            return True
    return False


def _has_cosmos_layout(ws: Path) -> bool:
    """Fallback structural signal: the canonical Cosmos module layout - an ``x/``
    module dir AND (an ``app/`` dir OR at least one ``msg_server*.go``). Bounded."""
    has_x = False
    has_app = False
    has_msgserver = False
    depth_root = str(ws)
    for dp, dns, fns in os.walk(ws):
        dns[:] = [d for d in dns if d not in _WALK_SKIP and not d.startswith(".")]
        # limit depth for the layout sniff (entry dirs are shallow)
        rel_depth = dp[len(depth_root):].count(os.sep)
        if rel_depth > 6:
            dns[:] = []
            continue
        base = os.path.basename(dp)
        if base == "x":
            has_x = True
        if base == "app":
            has_app = True
        for f in fns:
            if f.startswith("msg_server") and f.endswith(".go"):
                has_msgserver = True
        if has_x and (has_app or has_msgserver):
            return True
    return has_x and (has_app or has_msgserver)


def is_cosmos_go_workspace(ws) -> bool:
    """True iff ``ws`` is CONFIDENTLY a Cosmos-SDK / CometBFT Go-L1 workspace, so the
    Go attack surface should be narrowed to true entry points. Memoized. Any
    uncertainty returns False (=> keep every-exported = the safe/stricter direction)."""
    if not _env_narrowing_enabled():
        return False
    try:
        ws = Path(ws).resolve()
    except (OSError, ValueError):
        return False
    key = str(ws)
    if key in _WS_COSMOS_CACHE:
        return _WS_COSMOS_CACHE[key]
    verdict = False
    try:
        if ws.is_dir():
            verdict = _has_cosmos_gomod(ws) or _has_cosmos_layout(ws)
    except OSError:
        verdict = False
    _WS_COSMOS_CACHE[key] = verdict
    return verdict


# --------------------------------------------------------------------------
# Function-level classifier: is a Go function an external ENTRY point?
# --------------------------------------------------------------------------
# Exact method-NAME families (case-sensitive - these are Go framework method
# names). A method with one of these names is an entry point regardless of its
# receiver / file (an ``AnteHandle`` anywhere is ante surface).
_ABCI_CONSENSUS_NAMES = frozenset({
    # CometBFT ABCI(++) Application interface + Sei V2 variants.
    "InitChain", "PrepareProposal", "ProcessProposal", "ExtendVote",
    "VerifyVoteExtension", "FinalizeBlock", "Commit", "CheckTx", "DeliverTx",
    "BeginBlock", "EndBlock", "Midblock", "MidBlock",
    "Info", "Query", "ListSnapshots", "OfferSnapshot", "LoadSnapshotChunk",
    "ApplySnapshotChunk", "PrepareProposalHandler", "ProcessProposalHandler",
    "PreBlocker", "PreBlock",
})
_MODULE_LIFECYCLE_NAMES = frozenset({
    "BeginBlocker", "EndBlocker", "Midblocker",
})
_ANTE_NAMES = frozenset({"AnteHandle", "PostHandle"})
_IBC_CALLBACK_NAMES = frozenset({
    "OnRecvPacket", "OnAcknowledgementPacket", "OnTimeoutPacket",
    "OnChanOpenInit", "OnChanOpenTry", "OnChanOpenAck", "OnChanOpenConfirm",
    "OnChanCloseInit", "OnChanCloseConfirm", "OnTimeoutPacketClose",
})
_GENESIS_NAMES = frozenset({
    "InitGenesis", "ExportGenesis", "ValidateGenesis", "DefaultGenesisState",
})
_PRECOMPILE_DISPATCH_NAMES = frozenset({"Run", "Execute", "RequiredGas"})
# EVM-callable dispatch surface of a precompile: the ONLY methods an EVM caller can
# trigger (Run / Execute / RequiredGas / RunAndCalculateGas). Non-dispatch exported
# methods that share a precompile package - EVMKeeper/Address/GetABI/MustGetABI/Type
# accessors, keeper-handle getters (BankK/EVMK/...), event builders (Build*Event /
# Emit*Event) - are internal helpers reached only THROUGH the dispatch method, exactly
# like a Solidity ``internal``. Counting them (and their per-version legacy copies)
# inflated the denominator. The precompile-dedup pass (dedup_precompile_entry_points)
# collapses these to the dispatch surface once per precompile.
_PRECOMPILE_EVM_DISPATCH_NAMES = frozenset({
    "Run", "Execute", "RequiredGas", "RunAndCalculateGas",
})
_WASM_DISPATCH_NAMES = frozenset({
    "Instantiate", "Execute", "Query", "Sudo", "Reply", "Migrate",
    "OnRecvPacket", "IBCReceivePacket",
})
_MEMPOOL_P2P_NAMES = frozenset({
    "Receive", "ReceiveEnvelope", "AddPeer", "RemovePeer", "InitPeer",
    "ReapMaxBytesMaxGas", "ReapMaxTxs", "CheckTxCallback",
})
_HOOK_NAMES = frozenset({
    "AfterValidatorCreated", "AfterValidatorRemoved", "AfterValidatorBonded",
    "AfterValidatorBeginUnbonding", "BeforeValidatorModified",
    "BeforeDelegationCreated", "BeforeDelegationSharesModified",
    "BeforeDelegationRemoved", "AfterDelegationModified",
    "BeforeValidatorSlashed", "AfterEpochEnd", "BeforeEpochStart",
    "AfterValidatorSlashed",
})
_STATELESS_VALIDATION_NAMES = frozenset({"ValidateBasic"})

# Union of pure name-matched entry families (receiver/file-agnostic).
_ENTRY_METHOD_NAMES = (
    _ABCI_CONSENSUS_NAMES | _MODULE_LIFECYCLE_NAMES | _ANTE_NAMES
    | _IBC_CALLBACK_NAMES | _GENESIS_NAMES | _WASM_DISPATCH_NAMES
    | _MEMPOOL_P2P_NAMES | _HOOK_NAMES | _STATELESS_VALIDATION_NAMES
)

# Receiver-type regexes that denote an entry surface regardless of method name.
_ENTRY_RECEIVER_RE = re.compile(r"(?i)(msgserver|queryserver|querier)")

# Msg-handler signature: a ``*...Msg<X>Response`` RETURN - the unambiguous tx-handler
# convention (``func ... (goCtx, msg *types.MsgSend) (*types.MsgSendResponse, error)``).
# Requiring ``Response`` (not just any ``Msg<X>`` mention) is deliberate: it keeps every
# real handler (they all return a ``*Msg<X>Response``) AND every ``msgServer``-receiver
# method (caught by the receiver family below regardless), while NOT promoting proto/Msg
# BOILERPLATE - ``(msg MsgSend) Type()``/``Route()``/``GetSigners()`` mention ``MsgSend``
# but are not handlers and return string/[]byte, never a ``Msg<X>Response``.
_MSG_HANDLER_SIG_RE = re.compile(r"\bMsg[A-Z]\w*Response\b")

# EVM-RPC API service receiver (evmrpc/): registered JSON-RPC service methods
# conventionally live on a ``*API`` (also *Backend/*Handler) receiver.
_RPC_API_RECEIVER_RE = re.compile(r"(?i)(api|backend)$")

# Entry-boundary FILE basenames (an exported method here is entry surface even if
# its name is unconventional - the conservative-inclusive net, family 13). The
# net is gated below to skip ``*Keeper``-receiver methods (which are the internal
# helpers that share a boundary file, e.g. ``(k *Keeper) GetGasPool`` in
# ``msg_server.go``); genuine handlers live on ``msgServer``/``App``/``*Decorator``
# receivers (caught by family 1/name) or take a ``Msg`` (caught by the sig family).
_BOUNDARY_FILE_RE = re.compile(
    r"(?i)(^|[_/])("
    r"msg_server|abci|ante|handler|genesis|proposal|ibc_module|module_ibc"
    r")[_a-z0-9]*\.go$"
)

# Internal-helper receiver types that never make a fn an entry point on their own
# (they are the Go analog of Solidity ``internal``). A method on one of these is
# surface ONLY via an affirmative family (name / msg-signature / boundary package),
# never via the boundary-FILE net.
_INTERNAL_RECEIVER_RE = re.compile(r"(?i)keeper$")

# Entry-boundary PACKAGE path segments (any exported method under here is entry).
_BOUNDARY_PATH_SEGMENTS = ("/precompiles/", "precompiles/")


def _norm_path(rel: str) -> str:
    return str(rel or "").replace("\\", "/").lstrip("./")


def is_go_entry_point(name: str, receiver: str, rel_path: str, sig: str) -> bool:
    """True iff a Go function is an EXTERNAL entry point (true attack surface).

    ``name``     : function/method name (already known exported by the caller).
    ``receiver`` : receiver TYPE name (``""`` for a free function).
    ``rel_path`` : ws-relative source path.
    ``sig``      : signature text (decl + a few lines).

    Conservative-inclusive: returns True when ANY entry family matches; a fn is
    treated as an internal helper (False) only when it matches none.
    """
    nm = name or ""
    rv = receiver or ""
    rel = _norm_path(rel_path)
    sg = sig or ""

    # Family 1: tx msg handler - receiver is a msgServer/queryServer, OR the
    # signature carries the Msg<X>/Msg<X>Response handler convention.
    if _ENTRY_RECEIVER_RE.search(rv):
        return True
    if _MSG_HANDLER_SIG_RE.search(sg):
        return True

    # Families 2-6, 10-12: exact framework method names (receiver/file-agnostic).
    if nm in _ENTRY_METHOD_NAMES:
        return True

    # Family 7: EVM precompile dispatch (Run/Execute/RequiredGas) OR anything
    # exported under precompiles/ (boundary package, over-inclusive = safe).
    low_rel = rel.lower()
    if any(seg in low_rel for seg in _BOUNDARY_PATH_SEGMENTS):
        return True
    if nm in _PRECOMPILE_DISPATCH_NAMES:
        return True

    # Family 8: evmrpc/ registered API service methods.
    if "evmrpc/" in low_rel and _RPC_API_RECEIVER_RE.search(rv):
        return True

    # Family 13: conservative-inclusive boundary-FILE net - any exported method in
    # a known entry-boundary file is surface even if its name is unconventional,
    # EXCEPT a ``*Keeper``-receiver helper (those are internal; a real handler on a
    # Keeper receiver takes a Msg and is already caught by the signature family).
    base = low_rel.rsplit("/", 1)[-1]
    if _BOUNDARY_FILE_RE.search(base) and not _INTERNAL_RECEIVER_RE.search(rv):
        return True

    return False


# Receiver-type extractor for a Go func decl line:
#   func (s *msgServer) EVMTransaction(...)   -> "msgServer"
#   func (app *App) BeginBlock(...)           -> "App"
#   func NewKeeper(...)                        -> "" (free function)
_GO_RECEIVER_RE = re.compile(r"\bfunc\s*\(\s*\w+\s+\*?([A-Za-z_]\w*)\s*\)")


def extract_go_receiver(decl_line: str) -> str:
    m = _GO_RECEIVER_RE.search(decl_line or "")
    return m.group(1) if m else ""


# ==========================================================================
# COLLECTION-LEVEL entry-surface reductions (Go/Cosmos only, language-gated).
# These run over the WHOLE Go entry-fn set AFTER per-fn classification, because
# they need cross-fn context (dedup, fork-diff, closure) that a per-fn boolean
# cannot express. Each is conservative-inclusive / fail-open: on ANY ambiguity
# they KEEP the fn (larger denominator = never-false-pass).
#
# The callers pass a minimal duck-typed row/object exposing ``.name``, ``.file``
# (ws-relative), ``.line`` (and, for closure, ``.classification`` + ``.end_line``).
# The functions return the SUBSET to KEEP plus a small detail dict for a visible
# removed-count (the reclassification is auditable, never silent).
# ==========================================================================

def _norm_rel(p: str) -> str:
    return str(p or "").replace("\\", "/").lstrip("./")


# ``precompiles/<name>/...`` OR ``precompiles/<name>/legacy/vNNN/...`` OR
# ``precompiles/<name>/versions/...`` - group key = the precompile <name> so every
# per-version copy collapses to one precompile. The segment right after
# ``precompiles/`` is the precompile identity.
_PRECOMPILE_SEG_RE = re.compile(r"(?:^|/)precompiles/([^/]+)/")
# Version/legacy subdir markers under a precompile (historical frozen copies).
_PRECOMPILE_VERSION_RE = re.compile(r"(?:^|/)precompiles/[^/]+/(?:legacy|versions)/")


def _precompile_group(rel: str):
    """Return the precompile group key for a ``precompiles/<name>/...`` path, else
    None (the fn is not under a precompile package)."""
    m = _PRECOMPILE_SEG_RE.search(_norm_rel(rel))
    return m.group(1) if m else None


def dedup_precompile_entry_points(fns):
    """LEVER 1 - precompile version-dedup.

    Collapse the EVM-callable dispatch surface of each precompile to once-per-
    (precompile, dispatch-method-name), and DROP non-dispatch accessors under
    ``precompiles/`` (EVMKeeper / GetABI / MustGetABI / Address / Type / keeper
    handles / event builders) - they are internal helpers reached only through the
    dispatch method (Solidity-``internal`` analog), and their per-version ``legacy/
    vNNN/`` copies are duplicates of the same historical dispatch.

    NEVER-FALSE-PASS / bias-to-include:
      - Only fns UNDER ``precompiles/`` are affected; every other Go entry fn passes
        through untouched.
      - Within a precompile, the KEEP key is (group, dispatch_name). The FIRST
        occurrence (the live ``precompiles/<name>/<name>.go`` sorts before its
        ``legacy/vNNN`` copies) is kept; a NET-NEW dispatch method that appears only
        in a version dir (no live copy) is STILL kept once (bias-to-include on the
        dispatch surface).
      - A precompile whose ONLY exported methods are non-dispatch accessors (no
        Run/Execute/RequiredGas found anywhere for it) keeps its FIRST non-legacy
        accessor as a conservative fallback, so a precompile is never dropped to
        zero surface (never-false-pass: an unrecognised dispatch convention still
        leaves one countable unit for that precompile).

    Returns ``(kept_fns, detail)``.
    """
    pc_idx = []  # indices of fns under precompiles/
    non_pc = []  # fns not under precompiles/ (pass through)
    for f in fns:
        if _precompile_group(_norm_rel(getattr(f, "file", ""))) is not None:
            pc_idx.append(f)
        else:
            non_pc.append(f)
    if not pc_idx:
        return list(fns), {"applied": False, "reason": "no-precompile-fns",
                           "removed": 0}

    # Stable order: live (non-legacy) files before legacy/versions, then by file+line,
    # so the FIRST kept per (group, name) is the live dispatch method.
    def _sort_key(f):
        rel = _norm_rel(getattr(f, "file", ""))
        is_ver = 1 if _PRECOMPILE_VERSION_RE.search(rel) else 0
        return (is_ver, rel, int(getattr(f, "line", 0) or 0))

    pc_sorted = sorted(pc_idx, key=_sort_key)

    # First pass: which groups have a genuine EVM-dispatch method anywhere?
    groups_with_dispatch = set()
    for f in pc_sorted:
        if getattr(f, "name", "") in _PRECOMPILE_EVM_DISPATCH_NAMES:
            groups_with_dispatch.add(_precompile_group(_norm_rel(f.file)))

    kept = []
    seen_dispatch = set()  # (group, dispatch_name)
    fallback_kept = set()  # groups that took the no-dispatch fallback
    dropped_accessor = 0
    dropped_version_dup = 0
    for f in pc_sorted:
        grp = _precompile_group(_norm_rel(f.file))
        nm = getattr(f, "name", "")
        if nm in _PRECOMPILE_EVM_DISPATCH_NAMES:
            key = (grp, nm)
            if key in seen_dispatch:
                dropped_version_dup += 1
                continue
            seen_dispatch.add(key)
            kept.append(f)
            continue
        # non-dispatch accessor under a precompile.
        if grp in groups_with_dispatch:
            # dispatch surface already represents this precompile - accessor is an
            # internal helper (covered transitively). Drop it.
            dropped_accessor += 1
            continue
        # never-false-pass fallback: this precompile has NO recognised dispatch
        # method anywhere - keep ONE (the first, non-legacy) accessor so the
        # precompile is not silently dropped to zero surface.
        if grp not in fallback_kept:
            fallback_kept.add(grp)
            kept.append(f)
        else:
            dropped_accessor += 1

    removed = len(pc_idx) - len(kept)
    detail = {
        "applied": True,
        "precompile_fns_in": len(pc_idx),
        "precompile_fns_kept": len(kept),
        "removed": removed,
        "dropped_non_dispatch_accessors": dropped_accessor,
        "dropped_version_legacy_duplicates": dropped_version_dup,
        "groups_with_dispatch": len(groups_with_dispatch),
        "no_dispatch_fallback_groups": len(fallback_kept),
    }
    return non_pc + kept, detail


def prune_unmodified_fork_entry_points(ws, fns, fork_scope_fn):
    """LEVER 2 - go-ethereum (and any resolved fork) fork-delta prune.

    Drop Go entry fns that live in a fork file PROVEN unmodified-vs-upstream by the
    existing fork-base machinery (``_apply_fork_scope`` in workspace-coverage-
    heatmap.py, injected as ``fork_scope_fn`` so this module stays stdlib-pure and
    reuses - not reimplements - the clone+diff logic). This removes the generic-name
    collisions (upstream ``trie.Commit`` / ``EVM.Run`` / ``genesis.Commit`` counted
    only because their name matches an ABCI/precompile-dispatch name) that are pure
    unmodified-upstream internals no Sei delta touches.

    NEVER-FALSE-PASS (the operator flagged this class of change as previously
    "fucked things up" when done carelessly - so the guard is strict):
      - The prune fires ONLY for files ``_apply_fork_scope`` PROVED unmodified
        (fork_bases.json present + upstream cloned + diffed). If fork-base
        resolution is unavailable / unresolved / clone-failed / lib-missing,
        ``_apply_fork_scope`` FAILS OPEN (keeps all of that fork's rows), and so
        does this pass - the LARGER denominator is kept.
      - We NEVER drop a fn whose file is not under a resolved fork prefix
        (``_apply_fork_scope`` passes those rows through untouched).
      - A prune is credited ONLY when the injected helper actually reports
        ``applied=True`` for the fork; otherwise removed=0.

    Returns ``(kept_fns, detail)``.
    """
    if fork_scope_fn is None:
        return list(fns), {"applied": False, "reason": "no-fork-scope-helper",
                           "removed": 0}
    # Build the file->fns index so we prune whole files by the kept-file verdict.
    rows = []
    seen_files = {}
    for f in fns:
        rel = _norm_rel(getattr(f, "file", ""))
        if rel not in seen_files:
            seen_files[rel] = True
            rows.append({"file": rel})
    try:
        kept_rows, detail = fork_scope_fn(ws, rows)
    except Exception as exc:  # never let an enrichment failure break the gate
        return list(fns), {"applied": False, "reason": f"fork-scope-error:{exc}",
                           "removed": 0}
    if not isinstance(detail, dict) or not detail.get("applied"):
        # no fork_bases / degraded -> fail open (keep all).
        return list(fns), {"applied": False,
                           "reason": (detail or {}).get("reason", "not-applied"),
                           "removed": 0}
    kept_files = {_norm_rel(r.get("file", "")) for r in kept_rows}
    kept_fns = [f for f in fns if _norm_rel(getattr(f, "file", "")) in kept_files]
    removed = len(fns) - len(kept_fns)
    out_detail = {
        "applied": True,
        "removed": removed,
        "files_in": len(rows),
        "files_kept": len(kept_files),
        "forks": detail.get("forks", []),
    }
    return kept_fns, out_detail


# --------------------------------------------------------------------------
# LEVER 3 - call-graph closure crediting (Go-only, language-gated).
# --------------------------------------------------------------------------
# A COVERED entry point's per-function attack analysis transitively covers the
# functions it calls. If a genuinely-covered (real-attack) entry point reaches
# another (currently untouched/hollow) entry fn through a REAL call path, credit
# that fn covered too. The call graph is derived from the Go data-flow slices in
# ``<ws>/.auditooor/dataflow_paths.jsonl`` - every DefUsePath is an SSA/CHA-backed
# proof that data flowed from ``source.fn`` through each ``hop.fn`` to ``sink.fn``,
# so those (from -> to) pairs are REAL edges (never invented). A graph that MISSES
# edges only UNDER-credits (safe); it can never over-credit.

def _fn_qual_basename(qual: str) -> str:
    """Last path/method component of a fully-qualified Go fn id, e.g.
    ``github.com/x/pkg.(*T).Foo`` -> ``Foo`` ; ``pkg.Bar`` -> ``Bar``."""
    s = str(qual or "")
    # strip a trailing method on a (recv) form and package path
    tail = s.rsplit(".", 1)[-1]
    return tail.strip("()* ")


def build_go_callgraph_edges(dataflow_paths):
    """Return a set of (caller_key, callee_key) edges from Go DefUsePath records.

    ``dataflow_paths`` is an iterable of parsed DefUsePath dicts (schema
    dataflow_path.v1). Only ``language == 'go'``, non-degraded records contribute.
    Node keys are ``(basename_of_fn, normalized_abs_or_rel_file)`` so they can be
    matched to fcc ``Fn`` records by (name, file-suffix). Edges are the ordered
    (source.fn -> hop.fn ...-> sink.fn) chain of each path - each adjacent pair is
    a proven inter-procedural reach.
    """
    edges = set()
    for rec in dataflow_paths or []:
        if not isinstance(rec, dict):
            continue
        if str(rec.get("language") or "").lower() != "go":
            continue
        if rec.get("degraded"):
            continue
        chain = []
        src = rec.get("source") or {}
        if isinstance(src, dict) and src.get("fn"):
            chain.append((_fn_qual_basename(src.get("fn")),
                          _norm_rel(src.get("file") or "")))
        for h in (rec.get("hops") or []):
            if isinstance(h, dict) and h.get("fn"):
                chain.append((_fn_qual_basename(h.get("fn")),
                              _norm_rel(h.get("file") or "")))
        snk = rec.get("sink") or {}
        if isinstance(snk, dict) and snk.get("fn"):
            chain.append((_fn_qual_basename(snk.get("fn")),
                          _norm_rel(snk.get("file") or "")))
        for a, b in zip(chain, chain[1:]):
            if a != b:
                edges.add((a, b))
    return edges


def _fn_node_key(f):
    return (_fn_qual_basename(getattr(f, "name", "")),
            _norm_rel(getattr(f, "file", "")))


def _file_suffix_match(a_file, b_file):
    """True if two file paths refer to the same file (one is a suffix of the other).
    DefUsePath files are absolute; fcc files are ws-relative."""
    if not a_file or not b_file:
        return False
    return a_file.endswith(b_file) or b_file.endswith(a_file)


def credit_closure_reachable(fns, dataflow_paths, is_covered):
    """LEVER 3 - credit an entry fn covered when a genuinely-covered entry fn
    reaches it through a real Go call path.

    ``fns``            : the Go entry-fn objects (kept denominator).
    ``dataflow_paths`` : parsed Go DefUsePath dicts (the real call graph).
    ``is_covered(f)``  : predicate - is ``f`` already genuinely covered (real-attack)?

    Returns ``(newly_credited_fns, detail)`` - the list of fn objects that should be
    marked covered (the caller applies the classification + evidence) and a detail
    dict. NEVER-FALSE-PASS: an fn is credited ONLY if there is a directed path in the
    REAL (proven) call graph FROM a genuinely-covered fn TO it. No call graph => no
    edges => zero credited (helpers stay as-is; the entry-point denominator is
    already correct). The graph is conservative (SSA/CHA def-use backed) - missing
    edges only under-credit.
    """
    edges = build_go_callgraph_edges(dataflow_paths)
    if not edges:
        return [], {"applied": False, "reason": "no-go-callgraph-edges",
                    "credited": 0, "edges": 0}

    # Map node keys (basename, file) -> fcc fns. Because DefUsePath files are
    # absolute and fcc files ws-relative, match by basename + file-suffix.
    # Build adjacency over node keys.
    adj = {}
    for a, b in edges:
        adj.setdefault(a, set()).add(b)

    # Seed frontier = graph nodes that correspond to a genuinely-covered fcc fn.
    fn_by_name = {}
    for f in fns:
        fn_by_name.setdefault(_fn_qual_basename(getattr(f, "name", "")), []).append(f)

    def _node_matches_covered(node):
        nm, nf = node
        for f in fn_by_name.get(nm, []):
            if is_covered(f) and _file_suffix_match(nf, _norm_rel(f.file)):
                return True
        return False

    # BFS over the real call graph starting from covered nodes.
    from collections import deque
    seed = [n for n in adj if _node_matches_covered(n)]
    reached = set()
    dq = deque(seed)
    while dq:
        n = dq.popleft()
        for m in adj.get(n, ()):  # noqa: B007
            if m not in reached:
                reached.add(m)
                dq.append(m)

    # Credit an fcc fn iff its node was REACHED and it is not already covered.
    credited = []
    for f in fns:
        if is_covered(f):
            continue
        nm = _fn_qual_basename(getattr(f, "name", ""))
        ff = _norm_rel(f.file)
        for (rnm, rnf) in reached:
            if rnm == nm and _file_suffix_match(rnf, ff):
                credited.append(f)
                break
    detail = {
        "applied": True,
        "edges": len(edges),
        "reached_nodes": len(reached),
        "credited": len(credited),
    }
    return credited, detail


# ==========================================================================
# COVERAGE_REPORT DENOMINATOR narrowing (single source of truth).
# ==========================================================================
# Extracted from tools/workspace-coverage-heatmap.py (Lane
# CAP-HUNT-COVERAGE-SCOPE-NARROW, commit c9ed88aa60) so `hunt-coverage-gate.py`'s
# OWN live in-scope enumeration (built independently from
# `.auditooor/inscope_units.jsonl`) can apply the IDENTICAL narrowing predicate
# before comparing against the coverage_report's (already-narrowed) total - the
# two call sites (workspace-coverage-heatmap.py's `build_coverage_report` and
# hunt-coverage-gate.py's `_live_denominator`) now both call THIS function, so
# they can never drift apart again (Lane CAP-HUNT-GATE-NARROWING-CONSISTENT).
#
# This module stays stdlib-pure/import-only; the two caller-specific pieces
# (the ``unit -> file_key`` split convention and the generic per-extension
# function-declaration regex table) are INJECTED by the caller rather than
# reimplemented here, so there is exactly one definition of each in the
# codebase (``tools/workspace-coverage-heatmap.py``'s ``_unit_file_key`` /
# ``_GENERIC_FN_RE_BY_EXT``).
#
# Every never-false-pass constraint from the original Lane D docstring still
# applies verbatim - see the module-level narrative above.

_ENV_COVERAGE_SCOPE_NARROW_DISABLE = "AUDITOOOR_COVERAGE_SCOPE_NARROW"

# Hard crown-jewel allowlist: a unit whose file path contains ANY of these
# segments is NEVER excluded by this narrowing pass, regardless of any other
# classification. Checked unconditionally, last, after every exclusion.
COVERAGE_SCOPE_NARROW_CROWN_JEWEL_SEGMENTS = (
    "/precompiles/", "precompiles/",
    "/x/evm/", "x/evm/",
    "/evmrpc/", "evmrpc/",
    "/giga/executor/", "giga/executor/",
)

# Documented SCOPE.md path carve-outs (test/mock fixtures + explicitly OOS
# trusted-infrastructure paths). Each is a literal path-segment match against
# the ws-relative unit file path - NOT a keyword grep over file CONTENT.
COVERAGE_SCOPE_NARROW_DOCUMENTED_OOS_SEGMENTS = (
    # Solidity test/mock fixture contracts bundled with the Go fork (not a
    # production surface; "Testnet + mock files are NOT covered by Primacy
    # of Impact" per SCOPE.md).
    "/contracts/src/", "contracts/src/",
    # Load-testing tooling, not a production/attack surface.
    "/loadtest/", "loadtest/",
)


def coverage_scope_narrow_enabled() -> bool:
    v = str(os.environ.get(_ENV_COVERAGE_SCOPE_NARROW_DISABLE, "")).strip().lower()
    return v not in ("0", "false", "no", "off")


def unit_is_crown_jewel(file_key: str) -> bool:
    low = ("/" + str(file_key or "").replace("\\", "/").lstrip("/")).lower()
    return any(seg in low for seg in COVERAGE_SCOPE_NARROW_CROWN_JEWEL_SEGMENTS)


def unit_is_documented_oos_path(file_key: str) -> bool:
    low = ("/" + str(file_key or "").replace("\\", "/").lstrip("/")).lower()
    return any(
        seg in low for seg in COVERAGE_SCOPE_NARROW_DOCUMENTED_OOS_SEGMENTS
    )


def load_fork_modified_sets(ws: Path) -> dict:
    """Materialize (local_name -> {"modified": set[str] | None}) from
    ``<ws>/.auditooor/fork_modified/*.json`` (schema
    ``auditooor.fork_modified.v1``, already produced by the fork-base
    resolution machinery; this function NEVER re-clones/re-diffs - it only
    reads what is already materialized on disk, so this dry-run-safe read
    path can never mutate a workspace). ``modified`` is the UNION of
    ``sei_modified_files`` + ``sei_added_files`` (both stay in-scope; only a
    file in NEITHER set - i.e. proven unmodified-upstream - is excludable).
    A fork with no materialized json, or a json that fails to parse, maps to
    ``None`` (fail-open: keep-all for that fork)."""
    out: dict = {}
    d = ws / ".auditooor" / "fork_modified"
    if not d.is_dir():
        return out
    for p in sorted(d.glob("*.json")):
        try:
            data = json.loads(p.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            continue
        if not isinstance(data, dict):
            continue
        name = str(data.get("local_name") or p.stem)
        modified = set(data.get("sei_modified_files") or []) | set(
            data.get("sei_added_files") or []
        )
        out[name] = {"modified": modified if modified or (
            data.get("modified_count") is not None
            or data.get("added_count") is not None
        ) else None}
    return out


def _resolve_go_unit_file_paths(
    ws: Path, go_units: list, unit_file_key_fn: Callable[[str], str]
) -> dict:
    """Map each ``.go`` unit's ``file_key`` (bare basename when unambiguous,
    else a ws-relative path per ``enumerate_units``' unit-key convention) to
    the REAL ws-relative path on disk, so classification/content reads (entry-
    point signature, fork-delta membership) operate on the actual file rather
    than a synthetic basename-only key. Bounded single walk; skips the same
    dirs `enumerate_units` prunes structurally (vendor/node_modules/.git/...)
    so this stays cheap even on a large Cosmos monorepo."""
    need_basenames = {
        unit_file_key_fn(u) for u in go_units if "/" not in unit_file_key_fn(u)
    }
    out: dict = {}
    for u in go_units:
        fk = unit_file_key_fn(u)
        if "/" in fk:
            out[fk] = fk  # already a real relpath (ambiguous-basename case)
    if not need_basenames:
        return out
    skip_dirs = {
        ".git", "node_modules", "vendor", "third_party", "testdata",
        ".auditooor", "prior_audits", "reference", "docs", "poc-tests",
        "agent_outputs", "fuzz_runs", "cost_runs", "mining_rounds",
        "deep_counterexamples", "monitoring", "build", "target", "out",
        "artifacts", "cache",
    }
    for dp, dns, fns in os.walk(ws):
        dns[:] = [d for d in dns if d not in skip_dirs and not d.startswith(".")]
        for fn in fns:
            if fn in need_basenames and fn not in out:
                rel = os.path.relpath(os.path.join(dp, fn), str(ws)).replace("\\", "/")
                out[fn] = rel
        if len(out) >= len(need_basenames) + sum(
            1 for u in go_units if "/" in unit_file_key_fn(u)
        ):
            break
    return out


def apply_go_cosmos_coverage_scope_narrowing(
    ws: Path,
    units: list,
    unit_file_key_fn: Callable[[str], str],
    fn_re_by_ext: dict,
) -> tuple:
    """Narrow a coverage-denominator ``units`` list to the same
    true-external-entry-point + fork-delta-unmodified-upstream scope
    ``function-coverage-completeness.py`` already applies. Returns
    ``(kept_units, detail)``; ``kept_units`` is ALWAYS a subset of ``units``
    (a strict subset only when narrowing actually applies) - every other unit
    (non-``.go``) passes through untouched.

    ``unit_file_key_fn``: caller-supplied ``unit -> file_key`` splitter (the
    ``"path::fn_name"`` convention used by both call sites - injected so this
    module never re-defines its own copy and cannot drift from the caller's).
    ``fn_re_by_ext``: caller-supplied ``{".go": <compiled regex>}`` table
    (the per-extension function-declaration matcher; only the ``.go`` entry
    is used here).

    See the module-level never-false-pass constraints documented above.
    """
    detail: dict = {
        "applied": False, "reason": "not-evaluated",
        "go_units_in": 0, "go_units_kept": 0, "excluded_total": 0,
        "excluded_by_reason": {}, "crown_jewel_protected": 0,
    }
    if not coverage_scope_narrow_enabled():
        detail["reason"] = "env-disabled"
        return list(units), detail
    try:
        if not is_cosmos_go_workspace(ws):
            detail["reason"] = "not-a-cosmos-go-workspace"
            return list(units), detail
    except Exception as exc:  # pragma: no cover - defensive fail-open
        detail["reason"] = f"workspace-classify-error:{exc}"
        return list(units), detail

    go_units = [u for u in units if unit_file_key_fn(u).lower().endswith(".go")]
    detail["go_units_in"] = len(go_units)
    if not go_units:
        detail["reason"] = "no-go-units"
        return list(units), detail

    fork_sets = load_fork_modified_sets(ws)
    # Unit file_keys are sometimes a bare basename (unambiguous case) rather
    # than the real ws-relative path - resolve the REAL on-disk path for every
    # go unit so path-segment classification (crown-jewel/documented-OOS/fork)
    # and content reads (entry-point signature) operate on the true location,
    # not a synthetic basename. Never changes the returned unit KEY (output is
    # always the original unit string); only used for classification.
    real_path_by_file_key = _resolve_go_unit_file_paths(ws, go_units, unit_file_key_fn)

    # Cache parsed (name, receiver, sig) per go file so a multi-unit file is
    # only read/regex-scanned once.
    file_fn_cache: dict = {}

    def _fn_receiver_and_sig(real_rel: str, fn_name: str) -> tuple:
        if real_rel not in file_fn_cache:
            idx: dict = {}
            full = ws / real_rel
            try:
                txt = full.read_text(encoding="utf-8", errors="replace")
            except OSError:
                txt = ""
            lines = txt.splitlines()
            fn_re = fn_re_by_ext.get(".go")
            if fn_re is not None:
                for i, ln in enumerate(lines):
                    m = fn_re.search(ln)
                    if not m:
                        continue
                    nm = m.group(1)
                    recv = extract_go_receiver(ln)
                    if nm not in idx:  # first decl wins (dedup by name)
                        idx[nm] = (recv, ln)
            file_fn_cache[real_rel] = idx
        return file_fn_cache[real_rel].get(fn_name, ("", ""))

    def _fork_unmodified(real_rel: str) -> bool:
        """True iff real_rel is PROVEN unmodified-upstream for a resolved
        fork (i.e. appears under ``src/<name>/`` for a fork with a
        materialized modified-set AND is in neither the modified nor added
        set). Any ambiguity => False (never-false-pass: only an
        affirmatively-proven-unmodified file is excludable this way)."""
        low = real_rel.replace("\\", "/")
        for name, info in fork_sets.items():
            prefix = f"src/{name}/"
            if not low.startswith(prefix):
                continue
            modified = info.get("modified")
            if modified is None:
                return False  # unresolved fork -> keep-all, never exclude
            rel_in_repo = low[len(prefix):]
            return rel_in_repo not in modified
        return False  # not under any resolved fork -> not excludable this way

    kept: list = []
    excluded_reasons: collections.Counter = collections.Counter()
    crown_jewel_protected = 0
    for u in go_units:
        file_key = unit_file_key_fn(u)
        fn_name = u.partition("::")[2]
        real_rel = real_path_by_file_key.get(file_key, file_key)

        # Constraint 2 (HARD, checked first as a short-circuit keep as well as
        # last as an override below): crown-jewel paths are NEVER excluded.
        if unit_is_crown_jewel(real_rel):
            kept.append(u)
            crown_jewel_protected += 1
            continue

        exclude_reason = None

        # Constraint 4a: documented SCOPE.md path carve-out.
        if unit_is_documented_oos_path(real_rel):
            exclude_reason = "documented-scope-md-oos-path"

        # Constraint 4b / 3: fork-delta unmodified-upstream (never fires for a
        # file in the modified/added set - _fork_unmodified is False for those).
        if exclude_reason is None and _fork_unmodified(real_rel):
            exclude_reason = "fork-delta-unmodified-upstream"

        # True-external-entry-point classification (only when not already
        # excluded above; an internal helper in an already-kept file is only
        # dropped when we can actually resolve receiver/sig for it).
        if exclude_reason is None and fn_name:
            receiver, decl_line = _fn_receiver_and_sig(real_rel, fn_name)
            if decl_line:
                sig = decl_line  # single-line signature window is sufficient
                try:
                    is_entry = is_go_entry_point(
                        fn_name, receiver, real_rel, sig
                    )
                except Exception:
                    is_entry = True  # fail-open: keep on classifier error
                if not is_entry:
                    exclude_reason = "internal-helper-not-entry-point"

        if exclude_reason is not None:
            # Constraint 2 override: crown-jewel allowlist wins even if some
            # other reason matched (defense in depth; the early continue above
            # already handles the common case).
            if unit_is_crown_jewel(real_rel):
                kept.append(u)
                crown_jewel_protected += 1
                continue
            excluded_reasons[exclude_reason] += 1
            continue
        kept.append(u)

    kept_go = kept
    excluded_total = len(go_units) - len(kept_go)

    # Constraint 1: fail-open when the exclusion set would be empty, or when
    # narrowing would drop the ENTIRE go surface (classifier failure signature
    # - never hand a downstream gate a narrowed-to-zero Go denominator).
    if excluded_total <= 0:
        detail["reason"] = "empty-exclusion-set"
        detail["go_units_kept"] = len(go_units)
        detail["crown_jewel_protected"] = crown_jewel_protected
        return list(units), detail
    if not kept_go:
        detail["reason"] = "narrowing-would-empty-go-surface-fail-open"
        detail["go_units_kept"] = len(go_units)
        detail["crown_jewel_protected"] = crown_jewel_protected
        return list(units), detail

    non_go = [u for u in units if not unit_file_key_fn(u).lower().endswith(".go")]
    result_units = non_go + kept_go
    detail.update({
        "applied": True,
        "reason": "narrowed",
        "go_units_kept": len(kept_go),
        "excluded_total": excluded_total,
        "excluded_by_reason": dict(excluded_reasons),
        "crown_jewel_protected": crown_jewel_protected,
    })
    return result_units, detail
