#!/usr/bin/env python3
"""arch-delegation-trust-closure.py  (R3) - enforcement-DELEGATION trust-closure screen.

NORTH-STAR (w8mv5mpcw, applied inside this capability)
======================================================
"A TRUSTED ENFORCEMENT is bypassable or its private invariant is unsound."
  1. ENUMERATE the delegated-and-trusted safety property: every attacker-reachable
     entrypoint that mutates AUTHORITY / CONSERVATION / FRESHNESS state relies on
     SOME concrete enforcement (its own guard, or a sibling/callee's postcondition
     it TRUSTS) to be safe.
  2. STATE the private invariant: "every relied-upon safety property is anchored by
     a CONCRETE enforcement gate somewhere in its delegation closure" (an
     access/role/caller check, a timelock/freshness compare, or a cryptographic
     proof/signature verify).
  3. ATTACK the invariant: compute the transitive enforcement-DELEGATION closure of
     each root property and drive three bypass tests -
       (a) UNENFORCED-ROOT / responsibility-diffusion: the closure bottoms out with
           NO concrete enforcement gate at all (every module assumes a sibling
           already checked, none does);
       (b) DELEGATION-CYCLE: the closure contains a call cycle among un-guarded
           functions and no link independently establishes the property;
       (c) SWAPPABLE-SOLE-ANCHOR (env-gated): the SOLE enforcement gate keys on an
           address state var that has an in-scope setter (attacker-swappable node).

This is a GENERAL trust-enforcement INVARIANT screen, NOT a bug shape: it is
impact-agnostic ("every relied-upon safety property is concretely anchored"),
independent of the theft/DoS/governance-takeover payoff.

DEDUP (novel axis = transitive enforcement CLOSURE):
  - cross-module-trust-seam.py (A2): a SINGLE seam, guard-ABSENCE on ONE edge, no
    transitivity. R3 CONSUMES its rows (when present) as extra delegation edges but
    adds the multi-hop closure + unenforced-root + cycle verdicts A2 cannot express.
  - authority-blast-radius.py (A3): one role -> many sinks (present guard), not
    multi-hop property delegation.
  - enforcement-layer-census (B3): counts guard PRESENCE per layer, no closure/cycle.

ADVISORY-first, FAIL-OPEN, NO-AUTO-CREDIT: every emitted row carries
verdict="needs-fuzz" and advisory=True; the tool NEVER flips a gate, NEVER resolves
a unit, and NEVER fail-closes. The strict env AUDITOOOR_DELEGATION_CLOSURE_ENFORCE
only records a `would_block` advisory list in the accounting record; the process
still exits 0. A degraded/empty scan emits an empty artifact + status, exit 0.

Emits (under <ws>/.auditooor):
  delegation_trust_closure.jsonl            (one row per unenforced root property)
  delegation_trust_closure.accounting.json  (counts + status + config)

Usage:
  python3 tools/arch-delegation-trust-closure.py --ws <ws> [--target <file|dir>]
      [--max-rows N] [--print]
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

_HERE = Path(__file__).resolve().parent

OUT_JSONL = "delegation_trust_closure.jsonl"
OUT_ACCT = "delegation_trust_closure.accounting.json"

_ENFORCE_ENV = "AUDITOOOR_DELEGATION_CLOSURE_ENFORCE"
_SWAPPABLE_ENV = "AUDITOOOR_DELEGATION_CLOSURE_SWAPPABLE"
_ON = {"1", "true", "on", "yes"}

_SKIP_DIR_PARTS = {
    "node_modules", "lib", "out", "cache", "test", "tests", "mock", "mocks",
    "script", "scripts", "broadcast", "artifacts", "target", ".git",
    "forge-std", "openzeppelin", "solmate",
}

# ---------------------------------------------------------------------------
# Lexicons. Kept SHORT + GENERAL. The enforcement lexicon is ONLY ever matched
# INSIDE a guard condition (require/assert/if) or a modifier NAME - never over the
# whole body - so a sensitive-var NAME (e.g. a *_GUARDIAN_ROLE constant passed to a
# sink) can never accidentally anchor an otherwise-unguarded function.
# ---------------------------------------------------------------------------

# A concrete enforcement gate inside a guard CONDITION: authorization, timing, or
# cryptographic authenticity. NOT input sanitisation (address(0) / == 0 / length).
_ENF_COND = re.compile(
    r"(?:msg\.sender|tx\.origin|hasrole|onlyrole|_checkrole|_checkowner|"
    r"isowner|isauthorized|authorized|\bowner\b|\badmin\b|guardian|"
    r"onlyupdater|_authorizeupgrade|"
    r"block\.timestamp|block\.number|validat|deadline|timelock|delay|"
    r"merkleproof|verifycalldata|verifyproof|ecrecover|isvalidsignature|"
    r"_verify|checkproof|signature|"
    # ECONOMIC / SOLVENCY invariant guards. A permissionless value-mover that is
    # gated by a solvency/health require (a liquidation gated by
    # `require(!_isHealthy(...))`, or a borrow gated by
    # `require(totalBorrowAssets <= totalSupplyAssets)`) is CONCRETELY anchored - its
    # safety property is the enforced economic invariant, not an access role. These
    # tokens are only ever matched INSIDE a guard condition, so a bare accounting
    # variable elsewhere in a body can never spuriously anchor a function.
    r"ishealthy|healthy|unhealthy|solven|insolvent|baddebt|undercollateral|"
    r"totalborrowassets|totalborrowshares|totalsupplyassets|totalsupplyshares)",
    re.IGNORECASE,
)

# Enforcement MODIFIER name (a modifier that gates execution). A modifier that
# begins with `only` or names an authz/timing/reentrancy/pause gate anchors the fn.
# NB: modifier NAMES are single camelCase identifiers (afterTimelock, whenNotPaused,
# onlyAfterDelay) so the security token appears as a compound COMPONENT, not a
# word-boundary-delimited word - match the token as a SUBSTRING of the name.
_ENF_MODIFIER = re.compile(
    r"^(?:only\w*|.*(?:role|owner|admin|auth|guard|guardian|pause|paused|"
    r"whennotpaused|whenpaused|nonreentrant|restricted|timelock|delay|gated|"
    r"authorized|permissioned).*)$",
    re.IGNORECASE,
)

# Guard-helper CALLS that revert internally (count as an in-body anchor even
# though they are not written as require/if here). Includes the OZ AccessControl
# PUBLIC role mutators, which self-enforce `onlyRole(getRoleAdmin(role))` (grant/
# revoke) or a `_msgSender()` self-check (renounce). The leading `\b` deliberately
# EXCLUDES the UNGUARDED internal `_grantRole`/`_revokeRole` (those keep firing as
# the true-positive shape: an external fn that reaches the internal unguarded
# mutator with no other gate is exactly the unenforced-root R3 hunts).
_ENF_HELPER_CALL = re.compile(
    r"\b(?:_checkRole|_checkOwner|_authorizeUpgrade|_checkAuthorized|"
    r"_onlyRole|_requireAuth|_requireOwner|"
    r"grantRole|revokeRole|renounceRole)\s*\(",
    re.IGNORECASE,
)

# Severity-eligible SINK signatures (substring over a fn body, case-insensitive).
_SINK_AUTHORITY = re.compile(
    r"(?:_grantrole|_revokerole|\bgrantrole\b|\brevokerole\b|_setowner|"
    r"transferownership|_authorizeupgrade|upgradeto|_setimplementation|"
    r"setimplementation|_setadmin|\bsetadmin\b|renouncerole|"
    r"owner\s*=|admin\s*=|implementation\s*=|guardian\s*=|updater\s*=|"
    r"authority\s*=|pauser\s*=|_setroleadmin)",
    re.IGNORECASE,
)
_SINK_CONSERVATION = re.compile(
    r"(?:safetransfer|safetransferfrom|transferfrom|\.transfer\s*\(|"
    r"_mint\s*\(|_burn\s*\(|\bmint\s*\(|\bburn\s*\(|withdraw|deposit|"
    r"\.call\s*\{\s*value|\.send\s*\(|sweep|rescue|redeem|"
    r"totalsupply\s*=|balances\s*\[)",
    re.IGNORECASE,
)
_SINK_FRESHNESS = re.compile(
    r"(?:_setroot|\bsetroot\b|setprice|setoracle|updateoracle|setfeed|"
    r"setrate|root\s*=|price\s*=|_settimelock|timelock\s*=|rate\s*=)",
    re.IGNORECASE,
)

# A function that CONSTRUCTS state (factory/deploy/init) is a setup context, not a
# steady-state invariant mutation - its grantRole-on-a-fresh-instance is by design.
_CTOR_NAME = re.compile(
    r"^(?:deploy\w*|create\w*|clone\w*|initialize|initializ\w*|setup|__init\w*|"
    r"init)$",
    re.IGNORECASE,
)
_NEW_CONTRACT = re.compile(r"\bnew\s+[A-Z]\w*\s*[({]")

# A PRIVILEGED value-mover: an admin-style movement that acts on OTHER accounts /
# the global pool (must be authorized). A self-service deposit/claim/withdraw that
# only touches the CALLER'S own funds is NOT privileged.
# NB: `skim` is deliberately NOT in this set. A skim moves a stray balance to a
# FIXED configured recipient (`skimRecipient`) - the permissionless caller gains
# nothing, so it is a safe-by-design mover, not a privileged one (see
# _FIXED_RECIPIENT / _is_self_authorizing). Forcing every `skim` eligible produced a
# fleet false-positive on metamorpho/vault-v2 adapters.
_PRIV_MOVER = re.compile(
    r"(?:\bsweep\b|\brescue\b|\brecover\b|\bseize\b|\bliquidate\b|"
    r"withdrawto|withdrawfor|mintto|forcetransfer|distributeto|payoutto|"
    r"transferfrom\s*\(\s*(?!msg\.sender|_msgsender))",
    re.IGNORECASE,
)

# FIXED-DESTINATION admin payout: a value movement whose recipient is a CONFIGURED
# state var (skimRecipient / feeRecipient / performanceFeeRecipient / ...). When the
# closure only pays out to such a fixed recipient AND never pays the caller, a
# permissionless entrypoint gives the caller nothing to steal - it delegates no trust
# check, so R3 stays silent (same "safe value-mover" family as caller-self-service).
_FIXED_RECIPIENT = re.compile(r"\b\w*recipient\b", re.IGNORECASE)

# A payout to the CALLER: a value-move (transfer/mint/send/call{value}) whose target
# is msg.sender / _msgSender(). Its presence means the caller CAN gain, so the
# fixed-destination FP-guard must NOT apply (e.g. `liquidate` seizes to msg.sender and
# is instead anchored by its own solvency `require(!_isHealthy(...))`). `[^;{}]*`
# keeps the match inside a single statement so an unrelated `emit ...(_msgSender())`
# after a fixed-recipient transfer does not count as a caller payout.
_MSGSENDER_PAYOUT = re.compile(
    r"(?:safetransfer\w*|\.transfer|_mint|\bmint\b|_burn|\bsend\b|call\s*\{\s*value)"
    r"[^;{}]*\b(?:msg\.sender|_msgsender\s*\(\s*\))",
    re.IGNORECASE,
)

_KEYWORD_MODS = {
    "external", "public", "internal", "private", "view", "pure", "payable",
    "virtual", "override", "returns", "memory", "storage", "calldata",
    "constant", "immutable",
}


# ---------------------------------------------------------------------------
# Solidity source parsing (brace-balanced; no compiler needed).
# ---------------------------------------------------------------------------

def _strip_comments(text: str) -> str:
    """Remove // line comments and /* */ block comments (string-literal naive but
    adequate for guard/sink screening)."""
    out: List[str] = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            j = text.find("\n", i)
            if j == -1:
                break
            # preserve newlines for line-number fidelity
            out.append("\n" * text.count("\n", i, j))
            i = j
        elif c == "/" and i + 1 < n and text[i + 1] == "*":
            j = text.find("*/", i + 2)
            if j == -1:
                break
            out.append("\n" * text.count("\n", i, j + 2))
            i = j + 2
        else:
            out.append(c)
            i += 1
    return "".join(out)


def _balanced(text: str, open_idx: int, opener: str, closer: str) -> int:
    """Return index just past the matching closer for the opener at open_idx."""
    depth, j, n = 0, open_idx, len(text)
    while j < n:
        c = text[j]
        if c == opener:
            depth += 1
        elif c == closer:
            depth -= 1
            if depth == 0:
                return j + 1
        j += 1
    return -1


_CONTRACT_RE = re.compile(
    r"\b(?:abstract\s+)?(contract|library|interface)\s+([A-Za-z_]\w*)")
_FN_RE = re.compile(r"\b(function|constructor)\b(?:\s+([A-Za-z_]\w*))?")


def _contract_spans(text: str) -> List[Tuple[int, str, str]]:
    """Ordered (start_pos, kind, name) for each contract/library/interface decl."""
    return [(m.start(), m.group(1), m.group(2)) for m in _CONTRACT_RE.finditer(text)]


def _contract_at(spans: List[Tuple[int, str, str]], pos: int) -> Tuple[str, str]:
    kind, name = "?", "?"
    for start, k, nm in spans:
        if start <= pos:
            kind, name = k, nm
        else:
            break
    return kind, name


def _split_visibility_mods(header: str) -> Tuple[str, bool, List[str]]:
    """Parse a function header segment (text between the param-list `)` and the
    body `{`). Returns (visibility, is_view_or_pure, modifier_names)."""
    # Cut off the returns(...) clause so return TYPE identifiers are not mistaken
    # for modifiers.
    ret = re.search(r"\breturns\b", header)
    pre = header[: ret.start()] if ret else header
    visibility = "internal"
    for v in ("external", "public", "internal", "private"):
        if re.search(r"\b" + v + r"\b", pre):
            visibility = v
            break
    is_view = bool(re.search(r"\b(?:view|pure)\b", pre))
    mods: List[str] = []
    # modifier = identifier (optionally with (...)) that is not a keyword.
    for mm in re.finditer(r"([A-Za-z_]\w*)\s*(\([^;{]*?\))?", pre):
        name = mm.group(1)
        if name in _KEYWORD_MODS:
            continue
        mods.append(name)
    return visibility, is_view, mods


class Fn:
    __slots__ = ("name", "contract", "file", "line", "visibility", "is_view",
                 "modifiers", "body", "header")

    def __init__(self, name, contract, file, line, visibility, is_view,
                 modifiers, body, header):
        self.name = name
        self.contract = contract
        self.file = file
        self.line = line
        self.visibility = visibility
        self.is_view = is_view
        self.modifiers = modifiers
        self.body = body
        self.header = header


def _parse_file(path: Path, rel: str) -> List[Fn]:
    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    text = _strip_comments(raw)
    spans = _contract_spans(text)
    out: List[Fn] = []
    for m in _FN_RE.finditer(text):
        kw = m.group(1)
        name = m.group(2) if kw == "function" else "constructor"
        if kw == "function" and not name:
            continue
        # locate parameter list
        paren = text.find("(", m.end() if kw == "constructor" else m.end())
        if paren == -1:
            continue
        params_end = _balanced(text, paren, "(", ")")
        if params_end == -1:
            continue
        # header runs from params_end to the first top-level `{` (body) or `;`.
        semi = text.find(";", params_end)
        brace = text.find("{", params_end)
        if brace == -1 or (semi != -1 and semi < brace):
            continue  # declaration without a body (interface / abstract)
        header = text[params_end:brace]
        body_end = _balanced(text, brace, "{", "}")
        if body_end == -1:
            continue
        body = text[brace:body_end]
        line = text.count("\n", 0, m.start()) + 1
        _kind, cname = _contract_at(spans, m.start())
        vis, is_view, mods = _split_visibility_mods(header)
        out.append(Fn(name, cname, rel, line, vis, is_view, mods, body, header))
    return out


# ---------------------------------------------------------------------------
# Guard / sink predicates (the CORE enforcement predicate).
# ---------------------------------------------------------------------------

def _iter_guard_conditions(body: str):
    """Yield the CONDITION text of every require(...)/assert(...)/if(...) in body."""
    for kw in ("require", "assert", "if"):
        for mm in re.finditer(r"\b" + kw + r"\s*\(", body):
            op = body.find("(", mm.start())
            end = _balanced(body, op, "(", ")")
            if end != -1:
                yield body[op + 1:end - 1]


def _has_enforcement_guard(fn: Fn) -> bool:
    """CORE PREDICATE. True iff `fn` carries a concrete enforcement gate:
      - an enforcement modifier name, OR
      - a guard-helper call that reverts internally, OR
      - a require/assert/if whose CONDITION names an authorization/timing/crypto
        enforcement token (NOT mere input sanitisation)."""
    for mod in fn.modifiers:
        if _ENF_MODIFIER.match(mod):
            return True
    if _ENF_HELPER_CALL.search(fn.body):
        return True
    for cond in _iter_guard_conditions(fn.body):
        if _ENF_COND.search(cond):
            return True
    return False


def _sink_class(body: str) -> Optional[str]:
    if _SINK_AUTHORITY.search(body):
        return "authority"
    if _SINK_CONSERVATION.search(body):
        return "conservation"
    if _SINK_FRESHNESS.search(body):
        return "freshness"
    return None


def _is_construction(fn: Fn) -> bool:
    return bool(_CTOR_NAME.match(fn.name) or _NEW_CONTRACT.search(fn.body))


def _is_self_authorizing(closure_text: str) -> bool:
    """SAFE-VALUE-MOVER FP-guard (conservation/freshness only). Returns True when a
    permissionless value movement delegates NO trust check because the caller cannot
    gain, under either of two shapes:

      (1) FIXED-DESTINATION admin payout: the closure pays out only to a CONFIGURED
          recipient state var (`skimRecipient` / `feeRecipient` / `performanceFee-
          Recipient` / ...) and NEVER to the caller. A permissionless `skim` or an
          interest-accrual that mints fee shares to a fixed fee recipient gives the
          caller nothing to steal, so it is safe-by-design.
      (2) CALLER-SELF-SERVICE: a value movement bound to the CALLER'S own account
          (`msg.sender` / the OZ `_msgSender()` accessor) with NO privileged-mover
          token - you can only move your own funds.

    An admin mover that pays the CALLER on other accounts / the global pool
    (sweep/rescue/withdrawTo/transferFrom(other), or a liquidation that seizes to
    msg.sender) is NOT safe-by-design here and remains eligible - its safety must come
    from a concrete enforcement gate (a role check or an economic/solvency require)."""
    # (1) fixed-destination admin payout - caller gains nothing.
    if _FIXED_RECIPIENT.search(closure_text) and not _MSGSENDER_PAYOUT.search(closure_text):
        return True
    # (2) caller-self-service (own funds), no privileged mover.
    if _PRIV_MOVER.search(closure_text):
        return False
    if "msg.sender" in closure_text:
        return True
    return bool(re.search(r"_msgsender\s*\(", closure_text, re.IGNORECASE))


# ---------------------------------------------------------------------------
# Call graph + closure.
# ---------------------------------------------------------------------------

_CALL_INTERNAL = re.compile(r"(?<![.\w])([a-zA-Z_]\w*)\s*\(")
_CALL_MEMBER = re.compile(r"\.([a-zA-Z_]\w*)\s*\(")
_NON_CALL = {"require", "assert", "if", "for", "while", "return", "revert",
             "emit", "keccak256", "abi", "address", "new", "type", "uint256",
             "bytes", "bool", "string", "mapping", "delete", "sizeof"}


def _callees(body: str, names: Set[str]) -> Set[str]:
    out: Set[str] = set()
    for mm in _CALL_INTERNAL.finditer(body):
        nm = mm.group(1)
        if nm in _NON_CALL:
            continue
        if nm in names:
            out.add(nm)
    for mm in _CALL_MEMBER.finditer(body):
        nm = mm.group(1)
        if nm in names:
            out.add(nm)
    return out


def _closure(root: str, byname: Dict[str, List[Fn]], edges: Dict[str, Set[str]],
             max_fns: int = 400) -> Tuple[List[str], bool]:
    """BFS closure of function NAMES reachable from `root`. Returns
    (closure_names, has_cycle_among_unguarded)."""
    seen: Set[str] = set()
    order: List[str] = []
    stack = [root]
    while stack and len(seen) < max_fns:
        cur = stack.pop()
        if cur in seen:
            continue
        seen.add(cur)
        order.append(cur)
        for nxt in edges.get(cur, ()):  # type: ignore[arg-type]
            if nxt not in seen:
                stack.append(nxt)
    # cycle detection restricted to the closure sub-graph.
    has_cycle = _detect_cycle(root, seen, edges)
    return order, has_cycle


def _detect_cycle(root: str, nodes: Set[str], edges: Dict[str, Set[str]]) -> bool:
    color: Dict[str, int] = {}

    def dfs(u: str) -> bool:
        color[u] = 1
        for v in edges.get(u, ()):  # type: ignore[arg-type]
            if v not in nodes:
                continue
            c = color.get(v, 0)
            if c == 1:
                return True
            if c == 0 and dfs(v):
                return True
        color[u] = 2
        return False

    return dfs(root)


# ---------------------------------------------------------------------------
# Optional cross-module-trust-seam edge feed (A2 rows -> extra delegation edges).
# ---------------------------------------------------------------------------

def _load_a2_edges(ws: Path, byname: Dict[str, List[Fn]]) -> int:
    """Best-effort: fold A2 producer->consumer seams into extra delegation edges.
    Returns the number of edges added. Silently no-ops when the artifact is
    absent (R3 stands alone without it)."""
    jl = ws / ".auditooor" / "cross_module_trust_seams.jsonl"
    if not jl.is_file():
        return 0
    added = 0
    try:
        for ln in jl.read_text(encoding="utf-8").splitlines():
            ln = ln.strip()
            if not ln:
                continue
            row = json.loads(ln)
            cons = (row.get("unguarded_consumer_sink") or {}).get("fn")
            prod = (row.get("guarded_producer") or {}).get("fn")
            cons = _basename(cons)
            prod = _basename(prod)
            if cons in byname and prod in byname:
                added += 1
    except Exception:
        return 0
    return added


def _basename(fn: Optional[str]) -> Optional[str]:
    if not fn:
        return None
    # canonical names look like Contract.fn(args) -> take the fn stem.
    s = str(fn)
    if "(" in s:
        s = s.split("(", 1)[0]
    if "." in s:
        s = s.rsplit(".", 1)[1]
    return s


# ---------------------------------------------------------------------------
# Swappable-sole-anchor (env-gated, off by default).
# ---------------------------------------------------------------------------

_MSGSENDER_EQ_VAR = re.compile(
    r"msg\.sender\s*==\s*([A-Za-z_]\w*)|([A-Za-z_]\w*)\s*==\s*msg\.sender")


def _setter_vars(fns: List[Fn]) -> Set[str]:
    """State vars that have an in-scope writer of the form `var = ...` in a
    non-constructor function (attacker-reachable if that function is unguarded,
    but here we only need existence of a setter to call the anchor swappable)."""
    out: Set[str] = set()
    for fn in fns:
        if fn.name == "constructor":
            continue
        for mm in re.finditer(r"\b([A-Za-z_]\w*)\s*=\s*[^=]", fn.body):
            out.add(mm.group(1))
    return out


def _sole_anchor_swappable(closure_fns: List[Fn], setters: Set[str]) -> Optional[str]:
    anchors = [f for f in closure_fns if _has_enforcement_guard(f)]
    if len(anchors) != 1:
        return None
    a = anchors[0]
    for cond in _iter_guard_conditions(a.body):
        for mm in _MSGSENDER_EQ_VAR.finditer(cond):
            var = mm.group(1) or mm.group(2)
            if var and var in setters:
                return var
    return None


# ---------------------------------------------------------------------------
# Driver.
# ---------------------------------------------------------------------------

def _enumerate_sol(target: Path) -> List[Path]:
    if target.is_file():
        return [target] if target.suffix == ".sol" else []
    files: List[Path] = []
    for p in sorted(target.rglob("*.sol")):
        parts = set(pp.lower() for pp in p.parts)
        if parts & _SKIP_DIR_PARTS:
            continue
        low = p.name.lower()
        if low.endswith(".t.sol") or low.endswith(".s.sol"):
            continue
        if "mock" in low or "test" in low:
            continue
        files.append(p)
    return files


def screen(ws: Path, target: Optional[Path], max_rows: int = 2000) -> Dict[str, Any]:
    acct: Dict[str, Any] = {
        "workspace": str(ws),
        "detector": "R3-arch-delegation-trust-closure",
        "rows": 0,
        "files_scanned": 0,
        "functions": 0,
        "roots_examined": 0,
        "roots_anchored": 0,
        "candidates_eligible": 0,
        "a2_edges_available": 0,
        "swappable_enabled": os.environ.get(_SWAPPABLE_ENV, "").strip().lower() in _ON,
        "strict_enabled": os.environ.get(_ENFORCE_ENV, "").strip().lower() in _ON,
        "status": "not-run",
        "advisory": True,
    }
    rows: List[Dict[str, Any]] = []

    tgt = target if target is not None else ws
    if not tgt.exists():
        acct["status"] = "0-target-absent"
        return _write(ws, rows, acct)

    files = _enumerate_sol(tgt)
    acct["files_scanned"] = len(files)
    if not files:
        acct["status"] = "0-no-solidity"
        return _write(ws, rows, acct)

    all_fns: List[Fn] = []
    for fp in files:
        try:
            rel = str(fp.relative_to(ws))
        except ValueError:
            rel = str(fp)
        all_fns.extend(_parse_file(fp, rel))
    acct["functions"] = len(all_fns)
    if not all_fns:
        acct["status"] = "0-no-functions"
        return _write(ws, rows, acct)

    byname: Dict[str, List[Fn]] = {}
    for fn in all_fns:
        byname.setdefault(fn.name, []).append(fn)
    names = set(byname)

    # call-graph edges (name -> callee names). Merge every same-name overload's body.
    edges: Dict[str, Set[str]] = {}
    for nm, fns in byname.items():
        cs: Set[str] = set()
        for fn in fns:
            cs |= _callees(fn.body, names)
        cs.discard(nm)  # ignore trivial self-recursion for anchoring purposes
        edges[nm] = cs

    acct["a2_edges_available"] = _load_a2_edges(ws, byname)
    setters = _setter_vars(all_fns) if acct["swappable_enabled"] else set()

    seen_root: Set[Tuple[str, str, int]] = set()
    would_block: List[str] = []

    for fn in all_fns:
        # roots = external/public, non-view, non-constructor, non-construction.
        if fn.visibility not in ("external", "public"):
            continue
        if fn.is_view or fn.name == "constructor":
            continue
        if _is_construction(fn):
            continue
        key = (fn.contract, fn.name, fn.line)
        if key in seen_root:
            continue
        seen_root.add(key)
        acct["roots_examined"] += 1

        closure_names, has_cycle = _closure(fn.name, byname, edges)
        closure_fns: List[Fn] = []
        for cn in closure_names:
            closure_fns.extend(byname.get(cn, []))

        # severity-eligibility: does the closure touch an authority/conservation/
        # freshness sink?
        cls = None
        for cf in closure_fns:
            c = _sink_class(cf.body)
            if c:
                cls = c
                break
        if cls is None:
            continue
        # SELF-AUTHORIZING FP-guard for conservation/freshness: a caller-scoped
        # value movement (msg.sender's own funds, no privileged mover) delegates no
        # trust check. AUTHORITY roots are always eligible (grantRole/upgrade/etc.).
        if cls in ("conservation", "freshness"):
            closure_text = "\n".join(cf.body for cf in closure_fns)
            if _is_self_authorizing(closure_text):
                continue
        acct["candidates_eligible"] += 1

        anchored = any(_has_enforcement_guard(cf) for cf in closure_fns)
        if anchored:
            acct["roots_anchored"] += 1
            # (c) swappable-sole-anchor (env-gated) still applies to anchored roots.
            if acct["swappable_enabled"]:
                var = _sole_anchor_swappable(closure_fns, setters)
                if var:
                    rows.append(_row(fn, cls, closure_names, "swappable-sole-anchor",
                                     detail=f"sole enforcement gate keys on `{var}` "
                                            f"which has an in-scope setter (swappable)"))
                    would_block.append(f"{fn.contract}.{fn.name}")
            continue

        # (a)/(b): no concrete anchor anywhere in the delegation closure.
        violation = "delegation-cycle" if has_cycle else "unenforced-root"
        detail = ("the transitive enforcement-delegation closure contains a call "
                  "cycle among un-guarded functions and no link independently "
                  "establishes the property"
                  if has_cycle else
                  "the transitive enforcement-delegation closure bottoms out with "
                  "NO concrete enforcement gate (responsibility diffusion: every "
                  "function assumes a sibling/callee already checked)")
        rows.append(_row(fn, cls, closure_names, violation, detail=detail))
        would_block.append(f"{fn.contract}.{fn.name}")
        if len(rows) >= max_rows:
            acct["truncated"] = True
            break

    acct["rows"] = len(rows)
    acct["status"] = "ok"
    if acct["strict_enabled"]:
        # advisory-only: record what WOULD block; NEVER fail-close.
        acct["would_block"] = would_block
    return _write(ws, rows, acct)


def _row(fn: Fn, cls: str, closure_names: List[str], violation: str,
         detail: str) -> Dict[str, Any]:
    return {
        "id": f"r3-{violation}-{fn.contract}.{fn.name}",
        "violation": violation,
        "property_class": cls,
        "root_property": {
            "contract": fn.contract,
            "fn": fn.name,
            "file": fn.file,
            "line": fn.line,
        },
        "delegation_closure": closure_names,
        "closure_size": len(closure_names),
        "enforcement_anchor": None,
        "trust_chain": (
            f"{fn.contract}.{fn.name} mutates {cls} state and relies on its "
            f"delegation closure {closure_names} to enforce it; {detail}"
        ),
        "hacker_question": (
            f"For the {cls} safety property {fn.contract}.{fn.name} relies on, does "
            f"its enforcement delegation chain terminate at a module that actually "
            f"enforces it, or bottom out unenforced?"
        ),
        "verdict": "needs-fuzz",
        "confidence": "syntactic",
        "advisory": True,
    }


def _write(ws: Path, rows: List[Dict[str, Any]], acct: Dict[str, Any]) -> Dict[str, Any]:
    a = ws / ".auditooor"
    try:
        a.mkdir(parents=True, exist_ok=True)
        with (a / OUT_JSONL).open("w", encoding="utf-8") as fh:
            for r in rows:
                fh.write(json.dumps(r, ensure_ascii=False) + "\n")
        (a / OUT_ACCT).write_text(
            json.dumps(acct, ensure_ascii=False, indent=2), encoding="utf-8")
    except OSError:
        pass
    return acct


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="R3 enforcement-delegation trust-closure screen (advisory)")
    ap.add_argument("--ws", required=True,
                    help="workspace root (artifacts land in <ws>/.auditooor)")
    ap.add_argument("--target", default=None,
                    help="Solidity file or dir to scan (default: ws)")
    ap.add_argument("--max-rows", type=int, default=2000)
    ap.add_argument("--print", action="store_true",
                    help="print accounting json to stdout")
    args = ap.parse_args(argv)
    acct = screen(
        Path(args.ws),
        Path(args.target) if args.target else None,
        args.max_rows,
    )
    if args.print:
        print(json.dumps(acct, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
