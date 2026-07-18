#!/usr/bin/env python3
"""permanent-freeze-dos.py - the permanent fund-freeze DoS reasoning query
(RANK-3 logic dimension, HIGH x80).

LOGIC CAPABILITY. This is a DOMINANCE + NO-SIBLING-BYPASS relation over the forward
call-closure of a fund-EXIT function, NOT a grep for `for` or `revert`. Guard-rail:
`body_contains('for') or body_contains('revert')` is REJECTED - it cannot tell a
harmless bounded loop from an attacker-growable one, cannot prove the node DOMINATES
the value-release, and cannot see the sibling admin force-exit that makes the freeze
recoverable (and therefore NOT a permanent freeze).

THE INVARIANT (a fund-exit path must not be permanently blockable)
  A withdrawal / redeem / claim / exit / unstake / settlement path releases user
  value. It becomes a PERMANENT freeze when an attacker-influenced condition forces a
  revert or an unbounded loop / stuck queue on EVERY future call to that path, with
  NO admin recovery and no alternate exit. The trust boundary requires: for every
  exit function F, if a revert-or-unbounded-loop node R lies in F's forward closure,
  then EITHER R is unreachable under attacker-influenced state, OR R does NOT dominate
  the value-release (a release path bypasses R), OR a sibling recovery path (admin
  force-exit / skip / alternate withdraw) releases the funds around R.

  Set relation computed (a SURVIVOR is an entrypoint-reachable exit fn F holding a
  node R such that all three hold):
    SURVIVORS = { F in EXIT_FNS :
                    exists R in REVERT_OR_LOOP(closure(F)) with
                      (a) attacker_influenced(R)                  # settable/growable
                      AND (b) dominates_release(R, F)             # on every path
                      AND (c) NOT has_sibling_recovery(F)         # no bypass }

WHY THIS IS LOGIC, NOT A SHAPE (guard-rail satisfied on three relational axes)
  (a) INFLUENCE is a taint fact: R's revert-condition / loop-bound is data-dependent
      on an element an attacker can set or GROW - a per-user array `.length` that has
      a reachable `.push`/`append` site, a pushable queue, a transfer to an
      element of a caller-supplied address array (revert-on-receive griefing), or a
      griefable dust balance in a `require(x == 0)`. A constant / admin-only bound is
      NOT attacker-influenced (goes to KEPT).
  (b) DOMINANCE is a control-flow fact: R clears the node ONLY if the value-release
      cannot happen without first executing R. A release that occurs at an outer
      scope BEFORE R, or in an independent branch, means R does NOT dominate (KEPT).
  (c) NO-SIBLING-BYPASS is a relation between F and the rest of its contract: if
      another function in the same contract is an admin/emergency/alternate exit that
      releases the same value WITHOUT R, the freeze is recoverable -> KEPT. Adding
      such a sibling makes a survivor DISAPPEAR (the non-vacuous mutation).

SELF-CONTAINED SUBSTRATE (do-NOT #10: reuse, do not rebuild an engine)
  The owned tools/go-dataflow.py arm does not emit a revert/loop-DoS sink kind and its
  Go call-edge set under-emits deep closures (MEMORY: "Go dataflow arm under-emits").
  So this tool: (1) CONSUMES <ws>/.auditooor/dataflow_paths*.jsonl as advisory call
  edges when present, AND (2) runs its OWN SSA-free source pass over the in-scope
  Solidity + Go tree to build a name-based call graph, locate exit fns and
  revert/loop sinks, slice attacker-influence, test release-dominance, and scan for
  sibling recovery. The ideal go-dataflow / slither-arm extension is documented in
  agent_outputs/WIRING_SPEC_permanent_freeze_dos.md.

OUTPUT
  <ws>/.auditooor/permanent_freeze_dos_obligations.jsonl - one row per survivor,
  schema `auditooor.permanent_freeze_dos.v1`. A --json summary reports |exit fns|,
  |revert/loop-in-closure|, |attacker-influenced|, |no-recovery|, |survivors| and the
  KEPT witness set (nodes removed by the influence / dominance / sibling filters) to
  prove the filters ran non-vacuously. Honest cited-empty (survivors=0 with a
  non-empty KEPT witness) vs substrate_vacuous (no exit fn found at all) are
  distinguished. Every survivor is advisory_only=needs_source: a CONFIRMED finding
  needs an EXECUTED restart-survival PoC (R82) proving the exit stays blocked on every
  future call with no recovery - that is a downstream hunt obligation, not asserted
  here. Nodes whose attacker-influence is unproven are emitted advisory needs_source
  in a separate bucket, never counted as strict survivors.
"""

from __future__ import annotations

import argparse
import collections
import json
import re
import sys
import time
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_REPO_ROOT = _HERE.parent

if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

# ---------------------------------------------------------------------------
# scope OOS guard (single source of truth); degrade to a conservative default.
# ---------------------------------------------------------------------------
try:
    from lib.scope_exclusion import is_oos  # type: ignore
except Exception:  # pragma: no cover
    _LIB = _HERE / "lib"
    if str(_LIB) not in sys.path:
        sys.path.insert(0, str(_LIB))
    try:
        from scope_exclusion import is_oos  # type: ignore
    except Exception:
        def is_oos(rel: str, **_) -> bool:  # type: ignore[misc]
            n = ("/" + str(rel).replace("\\", "/")).lower()
            return any(m in n for m in (
                "/test/", "/tests/", "_test.", "/mock", "/mocks/", "/vendor/",
                "/node_modules/", "/out/", "/build/", "/target/", "/.auditooor/",
                "/simulation/", "/script/", "/scripts/",
            ))

_VENDOR_MARKERS = ("/pkg/mod/", "/go/pkg/", "/vendor/", "/node_modules/",
                   "/lib/forge-std/", "/lib/openzeppelin", "/out/", "/cache/")
_CODEGEN_SUFFIXES = (".pb.go", ".pb.gw.go", ".gen.go", ".t.sol")

# ---------------------------------------------------------------------------
# lexicons
# ---------------------------------------------------------------------------
# a fund-EXIT function name (the value-release entrypoint family).
_EXIT_NAME_RE = re.compile(
    r"(?i)(withdraw|redeem|unstake|unbond|claim|cashout|cash_out|payout|"
    r"pay_out|exit|settle|swapout|swap_out|release|unlock|collect|harvest|"
    r"dequeue|processqueue|process_queue|finalizewithdraw|complete)")
# names that LOOK like exit but are not a value-release (reduce FPs).
_EXIT_NAME_DENY_RE = re.compile(
    r"(?i)(claimownership|claim_ownership|claimrole|releaseversion|"
    r"unlockowner|settleadmin)")

# value-RELEASE tokens (the actual movement of user funds out).
_RELEASE_TOKENS_SOL = (
    ".transfer(", ".safetransfer(", ".safetransferfrom(", ".send(",
    ".call{value", ".call{ value", "payable(", "sendvalue(", "_burn(",
    ".withdraw(",
)
_RELEASE_TOKENS_GO = (
    "sendcoins", "sendcoinsfrommoduletoaccount", "sendcoinsfrommoduletomodule",
    "sendcoinsfromaccounttomodule", "delegatecoins", "undelegatecoins",
    ".send(", "banksend", "transfercoins",
)

# REVERT sink tokens.
_REVERT_TOKENS_SOL = ("revert", "require(", "require (", "assert(")
_REVERT_TOKENS_GO = ("panic(", "return err", "return nil, err", "return err",
                     "sdkerrors", "errorsmod.wrap", "return fmt.errorf",
                     "return status.error")

# LOOP sink tokens.
_LOOP_RE_SOL = re.compile(r"\b(for|while)\s*\(")
_LOOP_RE_GO = re.compile(r"\bfor\b")

# admin / emergency / alternate-exit recovery signals (a sibling bypass).
_RECOVERY_MOD_RE = re.compile(
    r"(?i)\b(onlyowner|onlyadmin|onlygovernance|onlygov|onlyrole|"
    r"onlymanager|onlyguardian|onlyauthority|auth\b|restricted|"
    r"onlyemergency|onlykeeper)\b")
_RECOVERY_NAME_RE = re.compile(
    r"(?i)(emergency|rescue|sweep|force|skip|admin|recover|salvage|drain|"
    r"escapehatch|escape_hatch)")

# attacker-growable collection: a push/append site anywhere reachable.
_PUSH_RE_SOL = re.compile(r"([A-Za-z_]\w*)\s*(?:\[[^\]]*\])*\s*\.push\s*\(")
_APPEND_RE_GO = re.compile(r"=\s*append\s*\(\s*([A-Za-z_][\w\.]*)\s*,")
# loop bound referencing a collection length.
_LEN_SOL_RE = re.compile(r"([A-Za-z_]\w*)\s*\.length\b")
_LEN_GO_RE = re.compile(r"(?:len\(\s*([A-Za-z_][\w\.]*)\s*\)|range\s+([A-Za-z_][\w\.]*))")

# a griefable-dust revert condition is specifically a require that some settable
# ACCUMULATOR be ZERO (an attacker keeps dust non-zero to permanently fail the guard).
# It is NOT a benign `require(amount != 0)` input check - that is the opposite polarity
# and does not freeze. So the classifier needs BOTH an accumulator token AND a
# requiring-zero comparison on the same line.
_DUST_ACCUM_TOKENS = ("balanceof", "balances[", "totaldebt", "totalsupply",
                      "totalassets", "shares[", "deposits[", "pending[",
                      "outstanding", "totalborrow", "totaldebtshares")
_DUST_ZERO_RE = re.compile(r"==\s*0\b|\bisZero\s*\(|\.isZero\(")
_EXTCALL_SUCCESS_HINTS = ("success", "!sent", "!ok", "require(sent",
                          "require(success", "require(ok")

_FUNC_RE_GO = re.compile(r"^\s*func\s+(?:\(\s*\w+\s+[\*\w\.]+\s*\)\s+)?(\w+)\s*\(")
_RECV_RE_GO = re.compile(r"^\s*func\s+\(\s*\w+\s+\*?([\w\.]+)\s*\)")
_PKG_RE_GO = re.compile(r"^\s*package\s+(\w+)")
_CONTRACT_RE_SOL = re.compile(r"^\s*(?:abstract\s+)?(?:contract|library)\s+(\w+)")
_FUNC_RE_SOL = re.compile(r"^\s*function\s+(\w+)\s*\(")
_IDENT_RE = re.compile(r"[A-Za-z_]\w*")
_CALL_RE = re.compile(r"(?:([A-Za-z_][\w\.\)\]]*?)\.)?([A-Za-z_]\w*)\s*\(")
_CTRL = {"if", "for", "while", "switch", "return", "go", "defer", "func",
         "require", "assert", "revert", "emit", "else", "catch"}


def _walk_files(src_root: Path, include_oos: bool):
    for p in sorted(list(src_root.rglob("*.sol")) + list(src_root.rglob("*.go"))):
        low = str(p).replace("\\", "/").lower()
        if any(m in low for m in _VENDOR_MARKERS):
            continue
        if low.endswith("_test.go") or low.endswith(".t.sol"):
            continue
        if any(low.endswith(s) for s in _CODEGEN_SUFFIXES):
            continue
        try:
            rel = p.relative_to(src_root)
        except Exception:
            rel = p
        if not include_oos and is_oos(str(rel)):
            continue
        yield p


class Fn:
    __slots__ = ("name", "contract", "lang", "file", "start", "end", "lines",
                 "header", "visibility", "modifiers", "callees", "params")

    def __init__(self, name, contract, lang, file, start, header):
        self.name = name
        self.contract = contract      # sol contract or go recv/pkg
        self.lang = lang              # "sol" | "go"
        self.file = file
        self.start = start
        self.end = start
        self.lines = []               # (lineno, text)
        self.header = header
        self.visibility = ""          # sol: external/public/internal/private
        self.modifiers = ""           # sol modifier list (from header)
        self.callees = set()
        self.params = set()


def _sol_visibility(header: str) -> str:
    for v in ("external", "public", "internal", "private"):
        if re.search(r"\b" + v + r"\b", header):
            return v
    return "public"  # sol default visibility for functions is public (pre-0.5 legacy)


def parse_file(path: Path):
    """Return (list[Fn], push_sites:set[str]). Brace-count body spans; works for both
    Solidity and Go (both are C-brace languages)."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return [], set()
    lang = "go" if str(path).endswith(".go") else "sol"
    lines = text.splitlines()
    fns: list[Fn] = []
    push_sites: set[str] = set()
    pkg = ""
    contract = ""
    cur = None
    depth = 0
    # multi-line header accumulation for solidity (function ... { may span lines).
    pending_header = ""
    pending_name = ""
    pending_start = 0
    for idx, raw in enumerate(lines, start=1):
        code = raw.split("//", 1)[0]
        if lang == "go" and not pkg:
            mp = _PKG_RE_GO.match(raw)
            if mp:
                pkg = mp.group(1)
        if lang == "sol":
            mc = _CONTRACT_RE_SOL.match(raw)
            if mc and cur is None:
                contract = mc.group(1)
            for m in _PUSH_RE_SOL.finditer(code):
                push_sites.add(m.group(1))
        else:
            for m in _APPEND_RE_GO.finditer(code):
                base = m.group(1).split(".")[-1]
                push_sites.add(base)

        if cur is None and not pending_name:
            if lang == "go":
                mf = _FUNC_RE_GO.match(raw)
                if mf:
                    recv = ""
                    mr = _RECV_RE_GO.match(raw)
                    if mr:
                        recv = mr.group(1).split(".")[-1]
                    cur = Fn(mf.group(1), recv or pkg, "go", str(path), idx, raw)
                    depth = raw.count("{") - raw.count("}")
                    cur.lines.append((idx, raw))
                    if depth <= 0 and "{" in raw:
                        cur.end = idx
                        fns.append(cur)
                        cur = None
                    continue
            else:
                mf = _FUNC_RE_SOL.match(raw)
                if mf:
                    pending_header = raw
                    pending_name = mf.group(1)
                    pending_start = idx
                    if "{" in raw:
                        cur = Fn(pending_name, contract, "sol", str(path),
                                 pending_start, pending_header)
                        cur.visibility = _sol_visibility(pending_header)
                        cur.modifiers = pending_header
                        depth = raw.count("{") - raw.count("}")
                        cur.lines.append((idx, raw))
                        pending_name = ""
                        pending_header = ""
                        if depth <= 0:
                            cur.end = idx
                            fns.append(cur)
                            cur = None
                    elif ";" in raw:  # interface / abstract decl, no body
                        pending_name = ""
                        pending_header = ""
                    continue
        elif pending_name:  # accumulating a multi-line sol header
            pending_header += " " + raw
            if "{" in raw:
                cur = Fn(pending_name, contract, "sol", str(path),
                         pending_start, pending_header)
                cur.visibility = _sol_visibility(pending_header)
                cur.modifiers = pending_header
                depth = raw.count("{") - raw.count("}")
                cur.lines.append((idx, raw))
                pending_name = ""
                pending_header = ""
                if depth <= 0:
                    cur.end = idx
                    fns.append(cur)
                    cur = None
            elif ";" in raw:
                pending_name = ""
                pending_header = ""
            continue
        else:
            cur.lines.append((idx, raw))
            depth += raw.count("{") - raw.count("}")
            if depth <= 0:
                cur.end = idx
                fns.append(cur)
                cur = None
    if cur is not None:
        cur.end = len(lines)
        fns.append(cur)
    return fns, push_sites


def _extract_callees(fn: Fn) -> set:
    callees = set()
    for _, raw in fn.lines:
        code = raw.split("//", 1)[0]
        for m in _CALL_RE.finditer(code):
            name = m.group(2)
            if name in _CTRL:
                continue
            callees.add(name)
    return callees


def _is_entrypoint(fn: Fn) -> bool:
    if fn.lang == "sol":
        return fn.visibility in ("external", "public")
    # go: exported (Capitalized) - a keeper/msgServer method is the exit entrypoint.
    return bool(fn.name) and fn.name[0].isupper()


def _release_tokens(lang):
    return _RELEASE_TOKENS_SOL if lang == "sol" else _RELEASE_TOKENS_GO


def _fn_release_lines(fn: Fn) -> list:
    toks = _release_tokens(fn.lang)
    out = []
    for lineno, raw in fn.lines:
        low = raw.split("//", 1)[0].lower()
        if lineno == fn.start:
            continue
        if any(t in low for t in toks):
            out.append(lineno)
    return out


class SinkNode:
    __slots__ = ("fn", "file", "line", "kind", "text", "influence", "operand",
                 "reachable", "dominates", "bound_ident")

    def __init__(self, fn, line, kind, text):
        self.fn = fn
        self.file = fn.file
        self.line = line
        self.kind = kind            # "revert" | "loop"
        self.text = text
        self.influence = "unproven"
        self.operand = ""
        self.reachable = False
        self.dominates = False
        self.bound_ident = ""


def find_sinks(fn: Fn, push_sites: set) -> list:
    """Locate revert / unbounded-loop sink nodes in the fn body and classify their
    attacker-influence against the growable-collection / revert-on-receive / dust
    heuristics."""
    nodes = []
    lang = fn.lang
    revert_toks = _REVERT_TOKENS_SOL if lang == "sol" else _REVERT_TOKENS_GO
    loop_re = _LOOP_RE_SOL if lang == "sol" else _LOOP_RE_GO
    len_re = _LEN_SOL_RE if lang == "sol" else _LEN_GO_RE
    for lineno, raw in fn.lines:
        if lineno == fn.start:
            continue
        code = raw.split("//", 1)[0]
        low = code.lower()
        # ---- LOOP node ----
        if loop_re.search(code):
            node = SinkNode(fn, lineno, "loop", code.strip()[:200])
            base = ""
            for m in len_re.finditer(code):
                base = (m.group(1) or (m.lastindex and m.group(m.lastindex)) or "")
                if base:
                    break
            base = base.split(".")[-1] if base else ""
            node.bound_ident = base
            if base and base in push_sites:
                node.influence = "growable-collection"
                node.operand = base
            elif base:
                # loop over a stored collection with no proven push -> unproven grow.
                node.influence = "unproven"
                node.operand = base
            # transfer-to-array-element inside the loop body is caught below via a
            # forward scan of the loop's brace block.
            nodes.append(node)
            continue
        # ---- REVERT node ----
        hit = None
        for t in revert_toks:
            if t in low:
                hit = t
                break
        if hit is None:
            continue
        node = SinkNode(fn, lineno, "revert", code.strip()[:200])
        # revert-on-receive: a require/assert on an external-call success flag.
        if any(h in low for h in _EXTCALL_SUCCESS_HINTS):
            node.influence = "revert-on-receive"
        elif any(h in low for h in _DUST_ACCUM_TOKENS) and _DUST_ZERO_RE.search(low):
            node.influence = "dust-grief"
            m = re.search(r"([A-Za-z_]\w*)\s*(?:\[|\.)", code)
            node.operand = m.group(1) if m else ""
        else:
            node.influence = "unproven"
        nodes.append(node)
    # second pass: mark a loop as revert-on-receive-in-loop if a release/transfer to
    # an array element occurs inside its brace block (push-payment griefing). Only
    # loops over a GROWABLE named collection qualify - a constant-bound loop paying
    # msg.sender its own funds is not attacker-influenced griefing.
    _mark_transfer_in_loop(fn, nodes, push_sites)
    return nodes


def _mark_transfer_in_loop(fn: Fn, nodes: list, push_sites: set):
    loops = [n for n in nodes if n.kind == "loop"
             and n.bound_ident and n.bound_ident in push_sites]
    if not loops:
        return
    rel = _release_tokens(fn.lang)
    body = {ln: raw for ln, raw in fn.lines}
    for n in loops:
        # find the loop's block end by brace counting from its line.
        depth = 0
        started = False
        end = n.line
        for ln in range(n.line, fn.end + 1):
            raw = body.get(ln, "")
            depth += raw.count("{") - raw.count("}")
            if "{" in raw:
                started = True
            if started and depth <= 0:
                end = ln
                break
        for ln in range(n.line + 1, end + 1):
            low = body.get(ln, "").lower()
            if any(t in low for t in rel) and ("[" in low or "elem" in low
                                               or "recipient" in low
                                               or "to]" in low or "[i]" in low):
                if n.influence in ("unproven", "growable-collection"):
                    n.influence = "revert-on-receive-in-loop"
                break


def forward_closure(root: str, callgraph: dict) -> set:
    seen = {root}
    stack = [root]
    while stack:
        cur = stack.pop()
        for nxt in callgraph.get(cur, ()):  # noqa: SIM118
            if nxt not in seen:
                seen.add(nxt)
                stack.append(nxt)
    return seen


def load_dataflow_edges(ws: Path):
    adir = ws / ".auditooor"
    edges = collections.defaultdict(set)
    n = 0
    if not adir.is_dir():
        return edges, n

    def _short(fn):
        s = fn or ""
        if ")." in s:
            s = s.rsplit(").", 1)[-1]
        s = s.split("(")[0].replace("*", "")
        return s.split(".")[-1]
    for p in sorted(adir.glob("dataflow_paths*.jsonl")):
        try:
            with p.open(encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except Exception:
                        continue
                    src = rec.get("source") or {}
                    sink = rec.get("sink") or {}
                    chain = ([src.get("fn")]
                             + [h.get("fn") for h in (rec.get("hops") or [])]
                             + [sink.get("fn")])
                    chain = [_short(c) for c in chain if c]
                    for a, b in zip(chain, chain[1:]):
                        if a and b and a != b:
                            edges[a].add(b)
                            n += 1
        except Exception:
            continue
    return edges, n


def has_sibling_recovery(exit_fn: Fn, contract_fns: list, blocking_node: SinkNode) -> bool:
    """A sibling recovery path exists when ANOTHER function in the same contract is an
    admin / emergency / alternate exit that releases the same value WITHOUT the
    blocking node's revert/loop shape. That makes the freeze recoverable => NOT a
    permanent freeze => the survivor is removed."""
    for g in contract_fns:
        if g is exit_fn:
            continue
        if g.contract != exit_fn.contract:
            continue
        admin_sig = bool(_RECOVERY_MOD_RE.search(g.modifiers or "")) or \
            bool(_RECOVERY_NAME_RE.search(g.name))
        if not admin_sig:
            continue
        # must actually release funds (an alternate exit), else it is unrelated admin.
        if not _fn_release_lines(g):
            continue
        # must NOT re-introduce the same blocking node kind on the same collection /
        # condition (a genuine bypass around R).
        g_low = " ".join(r.lower() for _, r in g.lines)
        if blocking_node.kind == "loop" and blocking_node.bound_ident:
            if (blocking_node.bound_ident.lower() + ".length") in g_low \
                    or ("range " + blocking_node.bound_ident.lower()) in g_low:
                continue  # sibling re-hits the same loop -> not a bypass
        return True
    return False


def dominates_release(node: SinkNode, exit_fn: Fn, closure_release_present: bool) -> str:
    """Return "" if R dominates a value-release (survivor-eligible), else a KEPT reason.
    Heuristic control-flow fact: R dominates unless a release occurs at an outer scope
    strictly BEFORE R in the exit fn body (release reachable without R), or no release
    exists in the closure at all (nothing to freeze)."""
    if not closure_release_present:
        return "no-release-in-closure"
    exit_releases = _fn_release_lines(exit_fn)
    # a release in the exit fn strictly before R at shallow depth => R not dominating.
    for rl in exit_releases:
        if rl < node.line:
            return "release-before-node"
    return ""


def make_obligation(exit_fn: Fn, node: SinkNode, invariant_id: str) -> dict:
    contract = exit_fn.contract or Path(exit_fn.file).stem
    src_ref = f"{node.file}:{node.line}"
    kind_desc = {
        "loop": ("an unbounded loop whose bound is an attacker-growable collection "
                 "length"),
        "revert": "a revert / require that an attacker can force on every call",
    }.get(node.kind, "a DoS node")
    infl_desc = {
        "growable-collection": "a per-user/queue collection the attacker can grow via "
                               "a reachable push/append, inflating the loop until it "
                               "exceeds the block gas limit",
        "revert-on-receive": "a require on an external-call success flag, so a single "
                             "revert-on-receive recipient blocks the payout path",
        "revert-on-receive-in-loop": "a transfer to a caller-influenced address inside "
                                     "the loop, so one hostile recipient reverts the "
                                     "whole batch and freezes every other user",
        "dust-grief": "a require on a settable/dust balance the attacker keeps non-zero "
                      "(or forces to zero) to permanently fail the exit guard",
        "unproven": "an influence channel that is not yet proven from source",
    }.get(node.influence, node.influence)
    root = (
        f"Fund-exit '{contract}.{exit_fn.name}' reaches {kind_desc} at {src_ref} "
        f"({infl_desc}). The node DOMINATES the value-release on every path and NO "
        f"sibling admin/emergency/alternate-exit releases the funds around it, so "
        f"once the attacker sets the condition the exit path reverts / gas-outs on "
        f"EVERY future call -> user funds frozen permanently with no recovery."
    )
    fr = [
        "INFLUENCE: prove the revert-condition / loop-bound is externally drivable to "
        "the failing value (a reachable push/append growing the collection, or a "
        "settable balance / hostile recipient) with no dominating clamp between "
        "ingress and the node.",
        "DOMINANCE: confirm no branch reaches the value-release without executing the "
        "node (an alternative payout path would defeat the freeze).",
        "NO-RECOVERY: confirm no admin force-exit / skip / alternate withdraw and no "
        "self-cure (the collection cannot be shrunk, the recipient cannot be skipped).",
        "RESTART-SURVIVAL (R82): drive an EXECUTED PoC showing the exit stays blocked "
        "on the NEXT call after the attacker sets the condition - a restart-survival "
        "PoC is the terminal verdict, prose is not.",
    ]
    return {
        "schema": "auditooor.permanent_freeze_dos.v1",
        "obligation_type": "permanent-freeze-dos",
        "contract": contract,
        "function": exit_fn.name,
        "function_signature": f"{contract}.{exit_fn.name}",
        "language": exit_fn.lang,
        "file": node.file,
        "line": node.line,
        "source_refs": [src_ref, f"{exit_fn.file}:{exit_fn.start}"],
        "exit_fn": exit_fn.name,
        "exit_fn_line": exit_fn.start,
        "dos_kind": node.kind,
        "node_text": node.text,
        "influence_class": node.influence,
        "operand": node.operand,
        "bound_ident": node.bound_ident,
        "dominates_release": True,
        "sibling_recovery_found": False,
        "attack_class": "permanent-freeze-dos",
        "likely_severity": "high",
        "broken_invariant_ids": [invariant_id],
        "root_cause_hypothesis": root,
        "quality_gate_status": "needs_source",
        "proof_status": "needs_source",
        "advisory_only": "needs_source",
        "learning_route": "mine-source",
        "falsification_requirements": fr,
        "next_command": (
            "read the exit fn + its closure; if the condition/bound is externally "
            "drivable, dominant, and unrecoverable, drive an EXECUTED restart-survival "
            "PoC (R82) proving the exit stays blocked on every future call."
        ),
    }


def analyze(fns: list, push_sites: set, ws: Path, invariant_id: str):
    for fn in fns:
        fn.callees = _extract_callees(fn)
    # Per-LANGUAGE call graphs: a Solidity exit fn cannot "reach" a Go keeper loop
    # (and vice versa). A single shared name-based graph collapses same-named fns
    # across languages and explodes the closure (cross-language bleed). Keep them
    # separate so the forward closure is language-honest.
    callgraphs: dict[str, dict] = {"sol": collections.defaultdict(set),
                                   "go": collections.defaultdict(set)}
    for fn in fns:
        callgraphs[fn.lang][fn.name] |= fn.callees
    df_edges, n_df = load_dataflow_edges(ws)
    # dataflow edges are advisory; apply to both language graphs (short-name keyed).
    for a, bs in df_edges.items():
        for lang in callgraphs:
            callgraphs[lang][a] |= bs

    # sinks per fn (compute once).
    fn_sinks: dict[int, list] = {}
    for fn in fns:
        fn_sinks[id(fn)] = find_sinks(fn, push_sites)

    exit_fns = [fn for fn in fns
                if _EXIT_NAME_RE.search(fn.name)
                and not _EXIT_NAME_DENY_RE.search(fn.name)
                and _is_entrypoint(fn)]

    survivors = []          # (exit_fn, node)
    kept_influence = []     # revert/loop node reachable but influence unproven
    kept_dominance = []     # node attacker-influenced but not dominating release
    kept_recovery = []      # node influenced+dominant but a sibling recovery exists
    all_reach_nodes = []    # every revert/loop node in some exit closure
    infl_nodes = []         # attacker-influenced subset

    seen_pair = set()
    for exit_fn in exit_fns:
        cg = callgraphs[exit_fn.lang]
        closure = forward_closure(exit_fn.name, cg)
        # closure fns are same-language only (the graph is per-language).
        closure_fns = [fn for fn in fns
                       if fn.lang == exit_fn.lang and fn.name in closure]
        # release present anywhere in closure?
        release_present = any(_fn_release_lines(fn) for fn in closure_fns)
        contract_fns = [fn for fn in fns if fn.contract == exit_fn.contract]
        for cfn in closure_fns:
            for node in fn_sinks[id(cfn)]:
                node.reachable = True
                key = (id(exit_fn), node.file, node.line, node.kind)
                if key in seen_pair:
                    continue
                seen_pair.add(key)
                all_reach_nodes.append((exit_fn, node))
                influenced = node.influence != "unproven"
                if not influenced:
                    kept_influence.append((exit_fn, node))
                    continue
                infl_nodes.append((exit_fn, node))
                # dominance: node must dominate the value-release.
                dom_reason = dominates_release(node, exit_fn, release_present)
                if dom_reason:
                    kept_dominance.append((exit_fn, node, dom_reason))
                    continue
                node.dominates = True
                # no sibling recovery.
                if has_sibling_recovery(exit_fn, contract_fns, node):
                    kept_recovery.append((exit_fn, node))
                    continue
                survivors.append((exit_fn, node))

    # dedup to DISTINCT physical DoS nodes: the name-based closure attributes one
    # physical revert/loop node to every exit fn whose closure reaches it (a cartesian
    # blow-up), so the honest headline is the count of distinct nodes, each attributed
    # to its first (alphabetical) reaching exit fn. The per-pair survivor list is kept
    # as a secondary metric.
    obligations = []
    survivor_nodes = []  # (exit_fn, node) one per physical node
    _seen = set()
    for exit_fn, node in sorted(survivors,
                                key=lambda t: (t[1].file, t[1].line, t[0].name)):
        dk = (node.file, node.line)
        if dk in _seen:
            continue
        _seen.add(dk)
        survivor_nodes.append((exit_fn, node))
        obligations.append(make_obligation(exit_fn, node, invariant_id))

    return {
        "callgraph_edges": sum(len(v) for g in callgraphs.values()
                               for v in g.values()),
        "n_dataflow_edges": n_df,
        "exit_fns": exit_fns,
        "survivors": survivor_nodes,
        "survivor_pairs": survivors,
        "kept_influence": kept_influence,
        "kept_dominance": kept_dominance,
        "kept_recovery": kept_recovery,
        "all_reach_nodes": all_reach_nodes,
        "infl_nodes": infl_nodes,
        "obligations": obligations,
    }


def _view(exit_fn: Fn, node: SinkNode, extra=None):
    v = {
        "exit_fn": f"{exit_fn.contract}.{exit_fn.name}",
        "lang": exit_fn.lang,
        "dos_kind": node.kind,
        "influence": node.influence,
        "operand": node.operand or node.bound_ident,
        "file": node.file,
        "line": node.line,
        "node": node.text[:120],
    }
    if extra:
        v.update(extra)
    return v


def run(argv=None):
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--workspace", required=True)
    ap.add_argument("--src-root", default=None,
                    help="source root to scan (default <ws>/src, else <ws>)")
    ap.add_argument("--include-oos", action="store_true")
    ap.add_argument("--invariant-id",
                    default="INV-FUND-EXIT-NO-PERMANENT-FREEZE-DOS")
    ap.add_argument("--emit", default=None,
                    help="output jsonl path (default "
                         "<ws>/.auditooor/permanent_freeze_dos_obligations.jsonl)")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--fail-closed", action="store_true",
                    help="exit non-zero if no exit-fn substrate was found at all "
                         "(the reasoner ran over an empty universe, NOT proven-clean)")
    args = ap.parse_args(argv)

    ws = Path(args.workspace).expanduser().resolve()
    if args.src_root:
        src_root = Path(args.src_root).expanduser().resolve()
    else:
        cand = ws / "src"
        src_root = cand if cand.is_dir() else ws

    fns: list[Fn] = []
    push_sites: set = set()
    for p in _walk_files(src_root, args.include_oos):
        file_fns, pushes = parse_file(p)
        fns.extend(file_fns)
        push_sites |= pushes

    res = analyze(fns, push_sites, ws, args.invariant_id)

    emit = Path(args.emit).expanduser() if args.emit else \
        ws / ".auditooor" / "permanent_freeze_dos_obligations.jsonl"
    emit.parent.mkdir(parents=True, exist_ok=True)
    with emit.open("w", encoding="utf-8") as fh:
        for ob in res["obligations"]:
            fh.write(json.dumps(ob) + "\n")

    substrate_vacuous = (len(res["exit_fns"]) == 0)
    cited_empty = (not substrate_vacuous and len(res["survivors"]) == 0)

    summary = {
        "schema": "auditooor.permanent_freeze_dos_summary.v1",
        "workspace": str(ws),
        "src_root": str(src_root),
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "n_fns": len(fns),
        "n_push_append_sites": len(push_sites),
        "n_callgraph_edges": res["callgraph_edges"],
        "n_dataflow_edges": res["n_dataflow_edges"],
        "n_exit_fns": len(res["exit_fns"]),
        "n_revert_loop_in_closure": len(res["all_reach_nodes"]),
        "n_attacker_influenced": len(res["infl_nodes"]),
        "n_no_recovery_survivors": len(res["survivor_pairs"]),
        "n_survivor_pairs": len(res["survivor_pairs"]),
        "n_survivors": len(res["survivors"]),
        "n_kept_influence_unproven": len(res["kept_influence"]),
        "n_kept_not_dominating": len(res["kept_dominance"]),
        "n_kept_sibling_recovery": len(res["kept_recovery"]),
        "influence_breakdown": dict(collections.Counter(
            n.influence for _, n in res["survivors"])),
        "exit_fn_names": sorted({f"{f.contract}.{f.name}" for f in res["exit_fns"]}),
        "survivors": [_view(e, n) for e, n in res["survivors"][:80]],
        "kept_influence_sample": [_view(e, n) for e, n in res["kept_influence"][:25]],
        "kept_not_dominating_sample": [
            _view(e, n, {"kept_reason": r}) for e, n, r in res["kept_dominance"][:25]],
        "kept_sibling_recovery_sample": [
            _view(e, n) for e, n in res["kept_recovery"][:25]],
        "obligations_written": len(res["obligations"]),
        "obligations_path": str(emit),
        "substrate_vacuous": substrate_vacuous,
        "cited_empty": cited_empty,
        "advisory_only": True,
    }

    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print(f"[permanent-freeze-dos] {ws.name}: "
              f"|exit fns|={summary['n_exit_fns']} "
              f"|revert/loop-in-closure|={summary['n_revert_loop_in_closure']} "
              f"|attacker-influenced|={summary['n_attacker_influenced']} "
              f"|no-recovery|={summary['n_no_recovery_survivors']} "
              f"SURVIVORS={summary['n_survivors']} "
              f"KEPT(influence-unproven={summary['n_kept_influence_unproven']}, "
              f"not-dominating={summary['n_kept_not_dominating']}, "
              f"sibling-recovery={summary['n_kept_sibling_recovery']}) "
              f"-> {len(res['obligations'])} obligation(s)")
        for s in summary["survivors"][:40]:
            print(f"  SURVIVOR {s['exit_fn']} [{s['dos_kind']}/{s['influence']}] "
                  f"operand={s['operand']}  {s['file']}:{s['line']}")
        for s in summary["kept_sibling_recovery_sample"][:8]:
            print(f"  KEPT-recoverable {s['exit_fn']} [{s['dos_kind']}] "
                  f"(sibling admin/alternate exit)  {s['file']}:{s['line']}")
        if substrate_vacuous:
            print("  SUBSTRATE-VACUOUS: no fund-exit function found (the reasoner "
                  "ran over an empty universe, NOT proven-clean).", file=sys.stderr)
        elif cited_empty:
            print(f"  CITED-EMPTY: 0 survivors over {summary['n_exit_fns']} exit fns "
                  f"({summary['n_kept_influence_unproven']} influence-unproven + "
                  f"{summary['n_kept_not_dominating']} not-dominating + "
                  f"{summary['n_kept_sibling_recovery']} sibling-recovery witnesses "
                  f"prove the filters ran non-vacuously).")
        print(f"  -> {emit}")

    if args.fail_closed and substrate_vacuous:
        return 3
    return summary


if __name__ == "__main__":
    out = run()
    if out == 3:
        sys.exit(3)
