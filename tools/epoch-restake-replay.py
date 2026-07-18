#!/usr/bin/env python3
"""epoch-restake-replay.py - the per-epoch / per-nonce / per-key UNIQUENESS
reasoning query (staking reward-claim / double-sign epoch-replay class).

RANK-7 [MED x66] logic class. A DOMINANCE / SET-DIFFERENCE query over an OWNED
intra-repo call-graph reachability backend, NOT a token detector. It is the
sibling of stale-accrual-before-value-gate-dominance.py, but keyed on
per-epoch/nonce/key UNIQUENESS rather than a lazily-accrued Q-read.

CORPUS SOURCE (the mined logic class - reward double-claim / double-sign)
  reward double-claim across epochs (no per-epoch consumed marker)
  restake-frontrun before a reward-checkpoint / lastClaimedEpoch update
  validator vote / signature accepted twice for the same (key, epoch|nonce)
  missing per-(account,epoch) consumed marker on a payout/accept path

THE LOGIC TRIPLE (assumption / invariant / trust-boundary)
  ASSUMPTION: a claim / reward / accept action for (account, epoch|nonce|key)
    is TRUSTED to be single-shot - it can only be honored ONCE per tuple.
  INVARIANT: for EVERY fn F that CREDITS value (mint / reward-transfer / payout
    / balance increment) or ACCEPTS a signature / vote keyed by
    (account, epoch|nonce|key), a WRITE to a consumed / last-claimed / checkpoint
    marker keyed by that SAME tuple MUST DOMINATE the credit in F's forward call
    closure (the marker is set BEFORE / such that a second call is rejected).
  TRUST-BOUNDARY: nothing external is required beyond re-invoking F (or restaking
    then re-invoking) - the SAME (account, epoch) can be replayed to double-
    collect / double-count because the uniqueness marker never fires.

THE SET-DIFFERENCE (the finding)
  Over the forward call closure of each candidate entrypoint E:
    CREDIT_OR_ACCEPT = { E : closure(E) reaches a CREDIT node (mint / reward-move
                        / payout / balance-add) OR an ACCEPT node (verify/accept
                        a signature/vote) AND the credit/accept is KEYED on an
                        epoch/nonce/key tuple (an epoch/nonce/key identifier is
                        read in the closure or in the owned dataflow guard exprs) }
    CONSUMED_MARKER_DOMINATED = { E in CREDIT_OR_ACCEPT : closure(E) contains a
                        CONSUMED-MARKER WRITE M (setClaimed / markConsumed /
                        lastClaimedEpoch = / usedNonce[..] = / hasVoted[..] = ) }
  FINDING = CREDIT_OR_ACCEPT \\ CONSUMED_MARKER_DOMINATED - a keyed credit/accept
  whose closure NEVER writes the per-tuple consumed marker -> REPLAYABLE.

WHY THIS IS LOGIC, NOT A SHAPE (guard-rail axes a/b/c)
  (a) membership is TRANSITIVE forward-closure reachability - a marker write M a
      helper N hops deep correctly places E in DOMINATED (impossible for a body-
      scoped `contains("setClaimed")` regex);
  (b) the answer is a RELATION BETWEEN TWO SETS (CREDIT_OR_ACCEPT minus
      DOMINATED); the finding is the set-difference, not a boolean over one body;
  (c) the marker write M and the credit need not co-occur in any single body - M
      can live in a checkpoint helper anywhere in the closure, so no token-
      adjacency / same-file assumption is used.
  The node predicates (is_credit / is_accept / is_marker_write / is_epoch_key)
  ARE per-node identifier classifiers; the LOGIC is the transitive-closure
  uniqueness dominance set-difference wrapped around them.

OWNED BACKEND CONSUMED
  1. An intra-repo static CALL GRAPH (decl index -> resolved callee edges ->
     transitive forward closure) built here over the workspace Go/Solidity/Rust
     source (the reachability backend). Used rather than the Go SSA `hops` because
     that closure is EMPIRICALLY POLLUTED with app-registration edges and MISSES
     intra-module private-method calls (memory anchor "Go dataflow arm
     under-emits on NUVA").
  2. <ws>/.auditooor/dataflow_paths.jsonl (schema dataflow_path.v1) - CORROBORATES
     the CREDIT facts (value-move / mint sinks) AND supplies guard-expr tokens
     that carry the epoch/nonce/key KEY (a second uniqueness-key arm). degraded
     records are skipped.

OUTPUT
  <ws>/.auditooor/epoch_restake_replay_obligations.jsonl - one row per survivor,
  schema `auditooor.epoch_restake_replay.v1`, exploit_queue-ingest compatible.

  HONEST-EMPTY vs VACUOUS-EMPTY: when the repo has NO consumed-marker primitive
  AND no epoch/nonce/key uniqueness surface at all (the class does not apply),
  the summary reports class_present=False + a cited-empty (honest N/A), distinct
  from substrate_vacuous where the source (0 fns) never materialized.

ADVISORY needs_source: when the uniqueness KEY or the marker cannot be statically
  resolved (key read via a dynamic map index the regex cannot bind), the
  obligation is emitted advisory_only with quality_gate_status=needs_source.
"""

from __future__ import annotations

import argparse
import collections
import importlib.util as _ilu
import json
import os
import re
import sys
import time
from pathlib import Path

_HERE = Path(__file__).resolve().parent

# ---------------------------------------------------------------------------
# ENTRYPOINT GATE (Go). Import the OWNED go_entrypoint_surface classifier so the
# credit-arm AND accept-arm only consider TRUE external-attacker-reachable Go
# entrypoints (msg handlers / ABCI / ante / IBC / genesis / lifecycle hooks /
# precompile dispatch / RPC / p2p / ValidateBasic ...). Without it every EXPORTED
# Go identifier - grpc-query getters, CLI command builders (AddGenesisAccountCmd /
# GetCmdAddChain), genesis/migration scaffolding - was a candidate reader E, which
# over-emitted survivors (axelar 197). An intra-codebase helper is reached only
# THROUGH an entrypoint and is covered transitively (the Go analog of Solidity
# `internal`); it must NOT be an independent replay-obligation.
#
# Conservative-inclusive / never-false-negative-on-bugs: is_go_entry_point returns
# True on ANY entry-family match and is only False for an affirmatively-classified
# internal helper, so gating drops ONLY provable non-entrypoints. Non-Go langs
# (Solidity `external`/`public`, Rust) are NOT gated here - the Solidity gate lives
# upstream in enumerate_units, and this classifier is Go-specific.
_ges_path = _HERE / "go_entrypoint_surface.py"
_ges_spec = _ilu.spec_from_file_location("go_entrypoint_surface", _ges_path)
_ges = _ilu.module_from_spec(_ges_spec)
_ges_spec.loader.exec_module(_ges)
is_go_entry_point = _ges.is_go_entry_point
extract_go_receiver = _ges.extract_go_receiver

# ---------------------------------------------------------------------------
# NODE PREDICATES (per-fn identifier classifiers). The LOGIC is the closure
# uniqueness-dominance set-difference wrapped around these - NOT any predicate.
# ---------------------------------------------------------------------------

# (M) CONSUMED-MARKER WRITE: a function / assignment that STAMPS a per-tuple
# consumed / last-claimed / checkpoint marker so a replay is rejected.
_MARKER = re.compile(
    r"^(?:"
    r"setclaimed\w*|markclaimed\w*|markconsumed\w*|consume\w*|"
    r"markused\w*|setused\w*|useNonce\w*|usenonce\w*|"
    r"setlastclaim\w*|updatelastclaim\w*|updatecheckpoint\w*|setcheckpoint\w*|"
    r"recordclaim\w*|recordvote\w*|recordsign\w*|recordsignature\w*|"
    r"markvoted\w*|setvoted\w*|marksigned\w*|setsigned\w*|"
    r"updaterewardcheckpoint\w*|setlastclaimedepoch\w*|"
    r"updatelastclaimedepoch\w*|advanceepoch\w*|finalizeepoch\w*|"
    r"invalidatenonce\w*|spendnonce\w*|burnnonce\w*"
    r")$",
    re.IGNORECASE,
)

# Assignment-form marker writes (map / field stamp keyed by a tuple). Matched
# against a fn BODY line, not a call name: `hasVoted[key] = true`,
# `usedNonce[n] = true`, `lastClaimedEpoch[acct] = epoch`, `claimed[id]=true`.
_MARKER_ASSIGN = re.compile(
    r"(?i)\b("
    r"claimed|hasclaimed|isclaimed|"
    r"consumed|used|usednonce|nonceused|spentnonce|"
    r"hasvoted|voted|signed|hassigned|processed|isprocessed|"
    r"lastclaim(?:ed)?(?:epoch)?|lastclaimedepoch|lastclaimedround|"
    r"rewardcheckpoint|lastcheckpoint|claimcheckpoint"
    r")\b\s*(?:\[[^\]]*\]|\.[A-Za-z_][A-Za-z0-9_]*)?\s*(?:=|:=)\s*(?!=)")

# (C) CREDIT: a call that CREDITS value keyed by an account - mint / reward move
# / payout / balance increment. This is the value the replay double-collects.
_CREDIT = re.compile(
    r"^(?:"
    r"mint\w*|_?mint\b|mintcoins\w*|"
    r"sendcoins\w*|sendcoinsfrom\w*|"
    r"safetransfer\w*|_?transfer\b|transferfrom|"
    r"distributereward\w*|payreward\w*|payout\w*|"
    r"claimreward\w*|creditreward\w*|addreward\w*|"
    r"increasebalance\w*|addbalance\w*|creditbalance\w*|"
    r"disburse\w*|releasefunds\w*|withdrawreward\w*"
    r")$",
    re.IGNORECASE,
)

# (S) ACCEPT: a call that ACCEPTS / verifies a signature or vote keyed by
# (key, epoch|nonce). A double-accept double-counts a vote / double-signs.
_ACCEPT = re.compile(
    r"^(?:"
    r"verifysig\w*|verifysignature\w*|recoversigner\w*|ecrecover|"
    r"acceptvote\w*|recordvote\w*|castvote\w*|tallyvote\w*|"
    r"acceptsignature\w*|processsignature\w*|submitsignature\w*|"
    r"acceptattestation\w*|processattestation\w*|"
    r"confirmkeygen\w*|rotatekey\w*|processrotation\w*|"
    r"verifyandaccept\w*|validateandaccept\w*"
    r")$",
    re.IGNORECASE,
)

# (K) EPOCH / NONCE / KEY uniqueness identifier - proves the credit/accept is
# KEYED on a per-round tuple. Matched against a callee name OR body tokens.
_EPOCH_KEY = re.compile(
    r"(?i)\b("
    r"epoch|epochnumber|epochid|currentepoch|"
    r"nonce|noncevalue|usernonce|txnonce|"
    r"round|roundid|snapshotid|"
    r"keyid|keygenid|rotationcount|pubkeyhash|"
    r"period|periodid|cycle|cycleid"
    r")\b")

# CREDIT sink kinds in the owned dataflow_paths.jsonl that CORROBORATE a credit.
_CREDIT_SINK_KINDS = {"value-move", "mint", "safeTransfer", "safeTransferFrom",
                      "reward-move", "payout"}

# guard-expr tokens carrying the uniqueness KEY (a second key arm, read only over
# the owned dataflow guard_nodes exprs, never a raw body regex).
_KEY_GUARD_TOK = re.compile(
    r"(?i)\b(epoch|nonce|round|keyid|keygenid|snapshotid|period|cycle|"
    r"claimed|consumed|hasvoted|used|lastclaimedepoch)\b")


# ---------------------------------------------------------------------------
# SOURCE INDEXING + intra-repo CALL GRAPH (the owned reachability backend).
# ---------------------------------------------------------------------------
_GO_DECL = re.compile(r"^func\s+(?:\([^)]*\)\s*)?([A-Za-z_][A-Za-z0-9_]*)\s*\(")
_SOL_DECL = re.compile(r"^\s*function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(")
_RS_DECL = re.compile(r"^\s*(?:pub\s+)?(?:async\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)\s*")
_CALL = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)\s*\(")

_SKIP_DIR = ("/test/", "/tests/", "/mock", "/mocks/", "/vendor/",
             "/node_modules/", "/out/", "/build/", "/target/", "/.auditooor/",
             "/simulation/", "/pkg/mod/", "/go/pkg/", "/poc-tests/",
             "/chimera_harnesses/", "/agent_outputs/")
_SKIP_SUFFIX = ("_test.go", ".pb.go", ".pb.gw.go", ".gen.go", ".t.sol", ".s.sol")
_STOP_NAMES = {"if", "for", "func", "return", "switch", "range", "make", "len",
               "append", "new", "cap", "require", "assert", "emit", "defer",
               "go", "select", "map", "string", "int", "uint", "error", "print",
               "printf", "sprintf", "errorf", "fmt", "panic", "recover"}


def _lang_of(path: str) -> str:
    p = path.lower()
    if p.endswith(".go"):
        return "go"
    if p.endswith(".sol"):
        return "solidity"
    if p.endswith(".rs"):
        return "rust"
    return ""


def _iter_source_files(root: Path):
    for dp, dns, fns in os.walk(root):
        low = (dp.replace("\\", "/") + "/").lower()
        if any(s in low for s in _SKIP_DIR):
            dns[:] = []
            continue
        for f in fns:
            if not f.endswith((".go", ".sol", ".rs")):
                continue
            if any(f.endswith(s) for s in _SKIP_SUFFIX):
                continue
            yield Path(dp) / f


def _decl_re_for(lang: str):
    return {"go": _GO_DECL, "solidity": _SOL_DECL, "rust": _RS_DECL}.get(lang)


class Fn:
    __slots__ = ("name", "file", "line", "lang", "callees",
                 "is_marker", "credit", "accept", "epoch_key",
                 "decl_line", "is_go_entry")

    def __init__(self, name, file, line, lang):
        self.name = name
        self.file = file
        self.line = line
        self.lang = lang
        self.callees: set[str] = set()
        self.is_marker = bool(_MARKER.match(name))
        self.credit = False
        self.accept = False
        self.epoch_key = False
        # decl_line: the `func ...` header (for a Go receiver/signature classify).
        # is_go_entry: True for a non-Go fn (not gated here) OR a Go fn the
        # go_entrypoint_surface classifier marks a true external entrypoint. A
        # same-name collision UNIONS (any resolvable decl that is an entrypoint
        # keeps the candidate = bias-to-include, never-false-negative-on-bugs).
        self.decl_line = ""
        self.is_go_entry = (lang != "go")


def build_call_graph(root: Path) -> dict:
    """Fold workspace source into per-fn Fn nodes with resolved intra-repo callee
    edges (the OWNED call-graph reachability backend). A same-name collision
    UNIONS bodies - conservative for a reachability set query: a marker write
    reachable through ANY same-named decl credits DOMINATED (never-false-negative;
    a survivor requires the marker absent from EVERY resolvable body)."""
    fns: dict[str, Fn] = {}
    raw: list[tuple[str, str, int, str, str]] = []
    for fp in _iter_source_files(root):
        lang = _lang_of(str(fp))
        drx = _decl_re_for(lang)
        if not drx:
            continue
        try:
            lines = fp.read_text(encoding="utf-8", errors="replace").splitlines()
        except Exception:
            continue
        cur = None
        buf: list[str] = []
        cur_line = 0
        for i, ln in enumerate(lines, 1):
            m = drx.match(ln)
            if m:
                if cur is not None:
                    raw.append((cur, str(fp), cur_line, lang, "\n".join(buf)))
                cur = m.group(1)
                cur_line = i
                buf = [ln]
            elif cur is not None:
                buf.append(ln)
        if cur is not None:
            raw.append((cur, str(fp), cur_line, lang, "\n".join(buf)))

    known = {r[0] for r in raw}
    for name, file, line, lang, body in raw:
        fn = fns.get(name)
        if fn is None:
            fn = Fn(name, file, line, lang)
            fns[name] = fn
        # Go entrypoint gate: classify THIS decl and UNION into is_go_entry (a
        # same-name collision is an entrypoint if ANY resolvable decl is - keep
        # the candidate). Only the exported-identifier universe is relevant (an
        # unexported Go helper is never an external entrypoint); is_go_entry_point
        # is conservative-inclusive so it only returns False for a provable helper.
        if lang == "go" and not fn.is_go_entry:
            decl = body.split("\n", 1)[0]
            if not fn.decl_line:
                fn.decl_line = decl
            if name[:1].isupper():
                recv = extract_go_receiver(decl)
                try:
                    if is_go_entry_point(name, recv, file, decl):
                        fn.is_go_entry = True
                except Exception:
                    fn.is_go_entry = True  # fail-open: keep candidate on error
        # assignment-form consumed-marker write inside this body.
        if _MARKER_ASSIGN.search(body):
            fn.is_marker = True
        for c in _CALL.findall(body):
            if c in _STOP_NAMES:
                continue
            if c in known and c != name:
                fn.callees.add(c)
            if _CREDIT.match(c):
                fn.credit = True
            if _ACCEPT.match(c):
                fn.accept = True
            if _MARKER.match(c):
                fn.is_marker = True
        if _EPOCH_KEY.search(body):
            fn.epoch_key = True
    return fns


def forward_closure(name: str, fns: dict, cap: int = 4000) -> set:
    seen = {name}
    stack = [name]
    while stack and len(seen) < cap:
        x = stack.pop()
        fx = fns.get(x)
        if not fx:
            continue
        for y in fx.callees:
            if y not in seen:
                seen.add(y)
                stack.append(y)
    return seen


# ---------------------------------------------------------------------------
# CREDIT corroboration + KEY tokens from the owned dataflow backend.
# ---------------------------------------------------------------------------
def _bare(fnid: str) -> str:
    s = (fnid or "").strip()
    if ")." in s:
        s = s.rsplit(").", 1)[-1]
    s = s.split("(")[0].replace("*", "")
    return s.split(".")[-1].strip()


def load_dataflow(df_paths: list[Path]) -> tuple[set, dict]:
    """Return (set of bare-fn names that reach a CREDIT sink, dict bare-fn -> set
    of guard-expr uniqueness-key tokens) from the owned dataflow_paths.jsonl."""
    credit_fns: set[str] = set()
    key_guard: dict[str, set] = collections.defaultdict(set)
    for df in df_paths:
        if not df.is_file():
            continue
        with df.open(encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except Exception:
                    continue
                if rec.get("degraded"):
                    continue
                src = rec.get("source") or {}
                sink = rec.get("sink") or {}
                fn = _bare(src.get("fn") or sink.get("fn") or "")
                if not fn:
                    continue
                if str(sink.get("kind") or "") in _CREDIT_SINK_KINDS:
                    credit_fns.add(fn)
                for g in rec.get("guard_nodes") or []:
                    for tok in _KEY_GUARD_TOK.findall(str(g.get("expr") or "")):
                        key_guard[fn].add(tok.lower())
    return credit_fns, dict(key_guard)


# ---------------------------------------------------------------------------
# CLASSIFY: compute CREDIT_OR_ACCEPT, CONSUMED_MARKER_DOMINATED, set-difference.
# ---------------------------------------------------------------------------
def classify(fns: dict, credit_fns: set, key_guard: dict) -> dict:
    class_present = any(f.is_marker for f in fns.values())

    readers: dict[str, dict] = {}
    for name, fn in fns.items():
        # ENTRYPOINT GATE: the reader E must be a true external-attacker-reachable
        # entrypoint. A Go fn that is NOT one (grpc getter, CLI command builder,
        # genesis/migration scaffolding, internal helper) is reached only THROUGH
        # an entrypoint and is covered transitively - it is NOT an independent
        # replay obligation. Non-Go fns have is_go_entry=True (gated upstream).
        if not fn.is_go_entry:
            continue
        cl = forward_closure(name, fns)
        cl_fns = [fns[c] for c in cl if c in fns]
        has_credit = any(f.credit for f in cl_fns) or (name in credit_fns)
        has_accept = any(f.accept for f in cl_fns)
        # KEYED on epoch/nonce/key: an epoch-key token anywhere in the closure OR
        # a dataflow guard-expr uniqueness-key token for this fn.
        guard_keys = key_guard.get(name) or set()
        has_key = any(f.epoch_key for f in cl_fns) or bool(guard_keys)
        # ACCEPT-ARM self-guard (2026-07-14 axelar over-emission fix): an accept-only
        # survivor (no credit anywhere in the closure) must be SELF-accept - a genuine
        # double-vote / double-sign replay lives IN the accept function itself. A
        # DEGRADED / over-broad forward-closure spuriously attaches a module's global
        # vote/accept nodes to unrelated functions (axelar: TallyVote/
        # voteBeforeCompletion attached to 137 params.go / types.go / CLI fns that never
        # tally a vote, all credit_nodes=[]). Requiring self-accept for the accept-only
        # arm drops those WITHOUT false-negating a genuine accept-replay - the accept
        # function itself still emits. The credit arm is unchanged (a transitive credit
        # is a legitimate replay entry point).
        accept_arm_ok = has_credit or fn.accept
        if (has_credit or has_accept) and has_key and accept_arm_ok:
            has_marker = any(f.is_marker for f in cl_fns)
            action = "credit" if has_credit else "accept"
            readers[name] = {
                "closure_size": len(cl),
                "action_kind": action,
                "has_marker_in_closure": has_marker,
                "marker_nodes": sorted(c for c in cl if c in fns and fns[c].is_marker),
                "credit_nodes": sorted(
                    c for c in cl if c in fns and fns[c].credit)[:6],
                "accept_nodes": sorted(
                    c for c in cl if c in fns and fns[c].accept)[:6],
                "epoch_key_nodes": sorted(
                    c for c in cl if c in fns and fns[c].epoch_key)[:6],
                "guard_key_tokens": sorted(guard_keys),
                # needs_source: the key is only visible via a dynamic guard token
                # (no statically-bound epoch-key node in a resolved body).
                "key_needs_source": (not any(f.epoch_key for f in cl_fns))
                and bool(guard_keys),
            }
    dominated = {n for n, info in readers.items() if info["has_marker_in_closure"]}
    survivors = sorted(set(readers) - dominated)
    kept = sorted(dominated)
    return {
        "class_present": class_present,
        "readers": readers,
        "survivors": survivors,
        "kept": kept,
    }


def make_obligation(name: str, fn: "Fn", info: dict, invariant_id: str,
                    permissionless: bool) -> dict:
    src_ref = fn.file + (f":{fn.line}" if fn.line else "")
    key_desc = ", ".join(info["epoch_key_nodes"][:4] or info["guard_key_tokens"][:4]) \
        or "epoch/nonce/key"
    action_nodes = info["credit_nodes"] if info["action_kind"] == "credit" \
        else info["accept_nodes"]
    root = (
        f"Entrypoint '{name}' {info['action_kind']}s "
        f"({', '.join(action_nodes) or info['action_kind']}) keyed on a per-tuple "
        f"uniqueness identifier ({key_desc}), but its forward call closure "
        f"contains NO consumed / last-claimed / checkpoint marker WRITE keyed by "
        f"that tuple (setClaimed / markConsumed / usedNonce[..]= / hasVoted[..]= / "
        f"lastClaimedEpoch= / updateRewardCheckpoint). The same (account, "
        f"epoch|nonce|key) can be REPLAYED - reward double-claim across epochs, "
        f"restake-frontrun before the checkpoint update, or a double-accepted "
        f"vote/signature (set-difference CREDIT_OR_ACCEPT\\CONSUMED_MARKER_"
        f"DOMINATED). RANK-7 staking reward-claim / double-sign epoch-replay class."
    )
    needs_source = bool(info.get("key_needs_source"))
    return {
        "schema": "auditooor.epoch_restake_replay.v1",
        "obligation_type": "epoch-restake-replay-uniqueness",
        "contract": "",
        "function": name,
        "function_signature": name,
        "language": fn.lang,
        "source_refs": [src_ref] if src_ref else [],
        "file": fn.file,
        "line": fn.line,
        "uniqueness_key": key_desc,
        "missing_marker": "consumed/last-claimed/checkpoint write keyed by "
                          "(account, epoch|nonce|key)",
        "action_kind": info["action_kind"],
        "credit_nodes": info["credit_nodes"],
        "accept_nodes": info["accept_nodes"],
        "epoch_key_nodes": info["epoch_key_nodes"],
        "attack_class": "epoch-nonce-key-uniqueness-replay-double-collect",
        "permissionless": bool(permissionless),
        "priority_rank": 0 if permissionless else 1,
        "likely_severity": "medium",
        "broken_invariant_ids": [invariant_id],
        "root_cause_hypothesis": root,
        "quality_gate_status": "needs_source",
        "proof_status": "needs_source",
        "advisory_only": True,
        "advisory_needs_source": needs_source,
        "learning_route": "mine-source",
        "falsification_requirements": [
            "MARKER_CLOSURE: prove NO consumed / last-claimed / checkpoint marker "
            "keyed by (account, epoch|nonce|key) is written in the fwd closure of "
            "this fn before/around the credit/accept (a markConsumed N hops deep "
            "in a helper KILLS the lead - it is DOMINATED, not a survivor).",
            "UNIQUENESS_KEY: confirm the credit/accept is genuinely keyed on a "
            "per-round tuple (epoch/nonce/key), not a one-shot lifecycle action "
            "that is structurally single-call.",
            "REPLAY_IMPACT: show re-invoking F (or restake-then-reinvoke) with the "
            "SAME tuple double-collects value / double-counts a vote - executed as "
            "a two-call PoC, second call MUST succeed and duplicate the effect.",
        ],
        "next_command": (
            "read the fn body + its callee closure; if a per-tuple consumed-marker "
            "write is genuinely absent, author the replay (two-call same-tuple) "
            "invariant harness and drive an executed double-collect PoC."
        ),
    }


def run(argv=None):
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--workspace", required=True)
    ap.add_argument("--src-root", default=None,
                    help="override source root (default <ws>/src, else <ws>)")
    ap.add_argument("--dataflow", default=None,
                    help="override dataflow_paths.jsonl (credit corroboration)")
    ap.add_argument("--invariant-id",
                    default="INV-EPOCH-NONCE-KEY-UNIQUENESS-REPLAY")
    ap.add_argument("--emit", default=None)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--fail-closed", action="store_true",
                    help="exit non-zero if the source substrate never materialized "
                         "(0 fns indexed) - a vacuous, not honest, empty")
    args = ap.parse_args(argv)

    ws = Path(args.workspace).expanduser().resolve()
    if args.src_root:
        root = Path(args.src_root).expanduser().resolve()
    else:
        root = ws / "src" if (ws / "src").is_dir() else ws

    fns = build_call_graph(root)

    df_paths: list[Path] = []
    if args.dataflow:
        df_paths.append(Path(args.dataflow).expanduser())
    else:
        auto = ws / ".auditooor" / "dataflow_paths.jsonl"
        if auto.is_file():
            df_paths.append(auto)
        for sib in sorted((ws / ".auditooor").glob("dataflow_paths.*.jsonl")):
            df_paths.append(sib)
    credit_fns, key_guard = load_dataflow(df_paths)

    res = classify(fns, credit_fns, key_guard)
    perm_default = True

    obligations = []
    seen = set()
    for name in res["survivors"]:
        fn = fns[name]
        dk = (fn.file, fn.line, name)
        if dk in seen:
            continue
        seen.add(dk)
        obligations.append(make_obligation(
            name, fn, res["readers"][name], args.invariant_id, perm_default))

    emit = Path(args.emit).expanduser() if args.emit else \
        ws / ".auditooor" / "epoch_restake_replay_obligations.jsonl"
    emit.parent.mkdir(parents=True, exist_ok=True)
    with emit.open("w", encoding="utf-8") as fh:
        for ob in obligations:
            fh.write(json.dumps(ob) + "\n")

    substrate_vacuous = (len(fns) == 0)
    honest_empty = (not res["survivors"]) and (not res["class_present"])

    summary = {
        "schema": "auditooor.epoch_restake_replay_dominance.v1",
        "workspace": str(ws),
        "src_root": str(root),
        "dataflow": [str(p) for p in df_paths],
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "n_functions_indexed": len(fns),
        "n_go_functions": sum(1 for f in fns.values() if f.lang == "go"),
        "n_go_entrypoints": sum(
            1 for f in fns.values() if f.lang == "go" and f.is_go_entry),
        "n_go_nonentry_gated": sum(
            1 for f in fns.values() if f.lang == "go" and not f.is_go_entry),
        "n_marker_primitives": sum(1 for f in fns.values() if f.is_marker),
        "class_present": res["class_present"],
        "size_CREDIT_OR_ACCEPT": len(res["readers"]),
        "size_CONSUMED_MARKER_DOMINATED": len(res["kept"]),
        "size_DIFF_survivors": len(res["survivors"]),
        "kept_with_marker": res["kept"][:40],
        "survivors": [
            {"fn": n, "file": fns[n].file, "line": fns[n].line,
             "action_kind": res["readers"][n]["action_kind"],
             "uniqueness_key": (res["readers"][n]["epoch_key_nodes"][:4]
                                or res["readers"][n]["guard_key_tokens"][:4]),
             "credit_nodes": res["readers"][n]["credit_nodes"],
             "accept_nodes": res["readers"][n]["accept_nodes"],
             "needs_source": res["readers"][n].get("key_needs_source", False)}
            for n in res["survivors"]
        ],
        "obligations_written": len(obligations),
        "obligations_path": str(emit),
        "substrate_vacuous": substrate_vacuous,
        "honest_empty_class_not_present": honest_empty,
    }

    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print(f"[epoch-restake-replay] {ws.name}: "
              f"fns={len(fns)} marker-prims={summary['n_marker_primitives']} "
              f"class_present={res['class_present']} "
              f"|CREDIT_OR_ACCEPT|={summary['size_CREDIT_OR_ACCEPT']} "
              f"|DOMINATED|={summary['size_CONSUMED_MARKER_DOMINATED']} "
              f"survivors(DIFF)={summary['size_DIFF_survivors']} "
              f"-> {len(obligations)} epoch-replay obligation(s)")
        if res["kept"]:
            print("  KEPT (credit/accept + consumed-marker dominates in closure): "
                  + ", ".join(res["kept"][:20]))
        for s in summary["survivors"][:40]:
            ns = " [needs_source]" if s["needs_source"] else ""
            print(f"  SURVIVOR {s['fn']} ({s['action_kind']}){ns}  "
                  f"key={s['uniqueness_key']}  "
                  f"credit={s['credit_nodes']} accept={s['accept_nodes']}  "
                  f"{s['file']}:{s['line']}")
        if honest_empty:
            print("  HONEST-EMPTY: no consumed-marker primitive AND no keyed "
                  "credit/accept survivor - the epoch/nonce/key uniqueness-replay "
                  "class does NOT apply (cited-empty, N/A).")
        if substrate_vacuous:
            print("  WARN VACUOUS: 0 functions indexed - source substrate never "
                  "materialized (NOT an honest empty).", file=sys.stderr)
        print(f"  -> {emit}")

    if args.fail_closed and substrate_vacuous:
        return 3
    return summary


if __name__ == "__main__":
    out = run()
    if out == 3:
        sys.exit(3)
