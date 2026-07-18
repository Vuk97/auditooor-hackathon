#!/usr/bin/env python3
"""declared-control-mutator-completeness-screen.py - the DECLARED-CONTROL ->
COMPLETE-MUTATOR-SET screen (MQ-B02), the UNDER-BROAD dual of authority-blast-
radius (A3).

GENERAL LOGIC / TRUST-ENFORCEMENT class (never a bug SHAPE). It instantiates the
north-star method ("A TRUSTED ENFORCEMENT is bypassable or its private invariant
is unsound") for one delegated-and-trusted safety property that no per-function
detector owns:

  DELEGATED-TRUSTED INVARIANT : a declared GLOBAL CONTROL - a cap/ceiling/limit/
    quota/debt-ceiling/rate-limit (a "bound" control) or a pause/freeze/allowlist/
    KYC gate (a "gate" control) - is trusted to constrain EVERY mutation of the
    quantity Q it protects (a supply/allocation/debt/balance/total/reserve slot).
  PRIVATE INVARIANT           : the COMPLETE mutator-set of Q (every function that
    writes Q in a way the control is meant to constrain - increase / arbitrary set
    for a bound; any state-mutating write for a gate) each carries the control
    guard. The control is only sound if it covers the WHOLE writer-set, not a
    scattered subset.
  ATTACK                      : the control is UNDER-BROAD - at least one mutator
    (an admin / rescue / sweep / migration / alt-entrypoint / newer-sibling
    function) writes Q WITHOUT the control guard, so the declared cap can be
    exceeded / the pause can be bypassed through the un-covered writer. Because the
    control is enforced by a scatter of per-function guards and no single function
    owns the writer-set, one un-guarded mutator silently defeats the whole control.

This is the DUAL of A3 (authority-blast-radius): A3 flags an OVER-broad guard (one
role guarding sinks of DIFFERENT impact classes); MQ-B02 flags an UNDER-broad
control (a guard that fails to cover the complete mutator-set of the quantity it
protects).

Enforcement points = every write to a control-protected quantity Q. The screen
answers per point:
  {control_kind, control, protected_quantity, mutator_direction,
   has_control_guard, guarded_sibling_count, complete_mutator_set, is_init_fn}
and flags (WARN, verdict=needs-fuzz) ONLY when:
  - Q is an ESTABLISHED control-protected quantity (a bound comparison Q<op>CAP
    exists, or Q is written under >=2 gated functions), AND
  - >=1 OTHER writer of Q DOES carry the control guard (so the control is genuinely
    DECLARED + enforced on part of the writer-set - the dual-of-A3 signature), AND
  - THIS writer lacks the control guard, is not a constructor/initializer/fresh-slot
    creation, and (for a bound) writes Q in an increasing / arbitrary-set direction
    (a pure decrease can never exceed a cap).

ADVISORY-FIRST: every row carries verdict='needs-fuzz', advisory=True,
auto_credit=False. It NEVER auto-credits and NEVER fail-closes in default mode; the
opt-in env AUDITOOOR_DECLARED_CONTROL_STRICT (or --strict) only raises the exit
code.

Language-general: Solidity (.sol) and Go (.go). Silent on other trees.

Usage:
  --workspace <ws>   scan <ws>/src -> .auditooor/declared_control_mutator_completeness_hypotheses.jsonl + summary
  --source <dir>     scan an arbitrary dir, print rows as JSON
  --file <f>         scan a single .sol/.go file, print rows as JSON
  --check            re-read the emitted sidecar, print cert verdict (advisory)
  --strict           (or env) elevate exit code when an un-covered mutator exists
  --json             machine summary to stdout
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path

HYP_SCHEMA = "auditooor.declared_control_mutator_completeness_hypotheses.v1"
_SIDE_NAME = "declared_control_mutator_completeness_hypotheses.jsonl"
_STRICT_ENV = "AUDITOOOR_DECLARED_CONTROL_STRICT"
_CAPABILITY = "MQB02"

_SKIP_DIRS = {"target", ".git", "node_modules", "vendor", "_archive", "out",
              "cache", "lib", "__pycache__", "dist", "build", ".auditooor",
              "benches", "benchmarks", "script", "scripts", "deployments",
              "prior_audits", "reference"}
_TEST_HINT = re.compile(
    r"(^|/)(tests?|test_fixtures|mock|mocks|benches|benchmarks?|examples|fixtures)(/|$)")

# --- control lexicons -------------------------------------------------------
# A camel/underscore SEGMENT that denotes a BOUND control (a cap / ceiling /
# limit). Segment-based so the container `caps`/`_caps` (plural) is NOT a control
# but `absoluteCap` / `supplyCap` / `debtCeiling` / `rateLimit` are.
_CAP_SEGS = ("cap", "ceiling", "quota", "limit", "threshold", "hardcap",
             "softcap")
# name-suffixes that mark a single-token cap (`supplycap`, `debtceiling`).
_CAP_SUFFIX = ("cap", "ceiling", "quota", "limit", "threshold")
# a max-combo (maxSupply / maxDebt / maxBorrow ...) is a cap.
_MAX_COMBO = ("supply", "mint", "debt", "total", "borrow", "amount", "rate",
              "deposit", "shares", "assets")
# substrings that LOOK like a cap token but are NOT a control (denylist).
_CAP_DENY = ("capital", "capacity", "escape", "recap", "captur", "caption",
             "capab", "encaps", "handicap", "landscap", "capt")
# A GATE control lexicon (pause/freeze/allowlist/KYC).
_GATE_TOKENS = ("paused", "notpaused", "whennotpaused", "whenpaused", "frozen",
                "freeze", "isfrozen", "allowlist", "allowlisted", "whitelist",
                "whitelisted", "iswhitelisted", "isallowed", "kyc", "iskyc",
                "blocklist", "blacklist", "sanction", "isblocked", "onlyallowed",
                "permitted", "ispermitted", "gated")
# A protected-quantity name lexicon (a value slot a control is meant to bound /
# gate). Keeps the gate arm targeted on value state, not config noise.
_QUANTITY_KW = ("supply", "allocation", "debt", "balance", "total", "reserve",
                "shares", "amount", "assets", "liquidity", "collateral", "minted",
                "borrowed", "deposited", "staked", "outstanding", "accrued",
                "principal", "credit", "funds", "pool", "escrow", "locked")

# increasing / decreasing FUNCTION-NAME lexicons (classify an ambiguous
# accumulate/set write by the mutator's intent).
_DECREASE_FN = ("withdraw", "redeem", "burn", "deallocate", "decrease",
                "decrement", "remove", "exit", "repay", "unstake", "release",
                "deduct", "pull", "subtract", "reduce", "slash", "consume",
                "spend", "debit", "unwind", "settle", "close", "clear")
_INCREASE_FN = ("deposit", "mint", "supply", "allocate", "increase", "increment",
                "add", "borrow", "stake", "credit", "accrue", "fund",
                "contribute", "issue", "open", "grow", "topup", "top_up")

_RELOP_RE = re.compile(r"(<=|>=|==|!=|<|>)")
_INIT_NAME_RE = re.compile(
    r"^(constructor|initialize|__init|_init|init|new|setup|configure)", re.I)


def _mask_comments(text: str) -> str:
    """Blank out // and /* */ comments and string literals, preserving newlines /
    line length so line indices stay source-accurate. Errs toward SILENCE (a masked
    token can only DROP a would-be write/guard, never invent one)."""
    out = []
    i, n = 0, len(text)
    in_line = in_block = in_str = False
    quote = ""
    while i < n:
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if in_line:
            out.append("\n" if c == "\n" else " ")
            if c == "\n":
                in_line = False
            i += 1
        elif in_block:
            if c == "*" and nxt == "/":
                out.append("  ")
                i += 2
                in_block = False
            else:
                out.append("\n" if c == "\n" else " ")
                i += 1
        elif in_str:
            out.append(" ")
            if c == "\\":
                out.append(" ")
                i += 2
                continue
            if c == quote:
                in_str = False
            i += 1
        elif c in ('"', "'", "`"):
            in_str = True
            quote = c
            out.append(" ")
            i += 1
        elif c == "/" and nxt == "/":
            in_line = True
            out.append("  ")
            i += 2
        elif c == "/" and nxt == "*":
            in_block = True
            out.append("  ")
            i += 2
        else:
            out.append(c)
            i += 1
    return "".join(out)


# Machine-generated source (protobuf, abigen, mockgen, etc.) is NOT the audited
# attack surface: attackers reach protobuf state via msg-server handlers, never
# via the raw reflection Set/Clear/Get plumbing. Excluding it is standard audit
# practice and removes codegen noise from the advisory hunt corpus. Suffix
# fast-path + the Go/`go generate` "Code generated ... DO NOT EDIT" sentinel.
_GENERATED_SUFFIXES = (
    ".pb.go", ".pulsar.go", ".pb.gw.go", "_gen.go", ".gen.go", "_generated.go",
)
_GENERATED_SENTINEL = re.compile(r"Code generated .{0,80}?DO NOT EDIT", re.I)


def _is_generated_source(path: Path) -> bool:
    if path.name.lower().endswith(_GENERATED_SUFFIXES):
        return True
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            head = fh.read(4096)
    except (OSError, UnicodeError):
        return False
    return bool(_GENERATED_SENTINEL.search(head))


def _iter_source_files(root: Path):
    for dp, dn, fn in os.walk(root):
        dn[:] = [d for d in dn if d not in _SKIP_DIRS]
        if _TEST_HINT.search(dp.replace(os.sep, "/")):
            continue
        for f in fn:
            low = f.lower()
            if not (low.endswith(".sol") or low.endswith(".go")):
                continue
            if low.endswith("_test.go") or low.endswith(".t.sol"):
                continue
            if _TEST_HINT.search(f):
                continue
            p = Path(dp) / f
            if _is_generated_source(p):
                continue
            yield p


# --- function extraction (brace-matched, Solidity + Go) ---------------------
_FN_DECL_RE = re.compile(
    r"^\s*(?:"
    r"function\s+([A-Za-z_]\w*)"          # Solidity function foo
    r"|(constructor)\b"                     # Solidity constructor
    r"|(fallback|receive)\s*\("            # Solidity fallback/receive
    r"|func\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)"  # Go func (recv) Foo / func Foo
    r")")


def _fn_name(m):
    return m.group(1) or m.group(2) or m.group(3) or m.group(4)


def _functions(lines):
    """Yield (name, decl_idx, sig_text, [(abs_idx, line), ...]) for each fn."""
    i, n = 0, len(lines)
    while i < n:
        m = _FN_DECL_RE.match(lines[i])
        if not m:
            i += 1
            continue
        name = _fn_name(m) or "<anon>"
        depth = 0
        started = False
        body = []
        sig_parts = []
        j = i
        seen_brace = False
        while j < n:
            line = lines[j]
            if not seen_brace:
                sig_parts.append(line)
                if "{" in line:
                    seen_brace = True
            depth += line.count("{") - line.count("}")
            body.append((j, line))
            if "{" in line:
                started = True
            if started and depth <= 0:
                break
            j += 1
        yield name, i, "\n".join(sig_parts), body
        i = max(j, i + 1)


# --- token / field helpers --------------------------------------------------
def _field_base(expr: str) -> str:
    """Last identifier segment of a (possibly qualified / indexed) path
    (`caps[id].allocation` -> `allocation`)."""
    seg = re.sub(r"\[[^\]]*\]", "", expr)
    parts = [p.strip() for p in seg.split(".") if p.strip()]
    return parts[-1] if parts else seg.strip()


def _segments(name: str):
    """Split an identifier into lowercased camelCase / underscore segments
    (`absoluteCap` -> ['absolute','cap']; `_caps` -> ['caps'])."""
    s = re.sub(r"_", " ", name)
    s = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", s)
    return [w.lower() for w in s.split() if w]


def _is_cap_token(name: str) -> bool:
    nl = name.lower()
    if any(d in nl for d in _CAP_DENY):
        return False
    segs = _segments(name)
    if any(s in _CAP_SEGS for s in segs):
        return True
    if any(nl.endswith(suf) for suf in _CAP_SUFFIX) and nl not in _CAP_SEGS[:1]:
        # single-token cap (supplycap / debtceiling), but not the bare plural
        return True
    if "max" in segs and any(s in _MAX_COMBO for s in segs):
        return True
    return False


def _side_has_cap(expr: str) -> bool:
    """True iff any identifier on this side of a comparison is a cap token."""
    for m in re.finditer(r"[A-Za-z_]\w*", expr):
        if _is_cap_token(m.group(0)):
            return True
    return False


def _side_primary_field(expr: str) -> str:
    """The primary (bounded-quantity) field base of a comparison side: the last
    member-access chain's final segment, else the last bare identifier that is not
    a numeric / keyword."""
    # prefer a member-access chain (`_caps.allocation` -> allocation)
    chains = re.findall(r"[A-Za-z_]\w*(?:\s*\.\s*[A-Za-z_]\w*)+", expr)
    if chains:
        return _field_base(chains[-1])
    idents = [m.group(0) for m in re.finditer(r"[A-Za-z_]\w*", expr)
              if not m.group(0).isdigit()]
    return idents[-1] if idents else ""


_KEYWORDS = {"require", "assert", "if", "for", "while", "return", "revert",
             "true", "false", "uint256", "int256", "uint128", "uint", "int",
             "memory", "storage", "public", "external", "internal", "view",
             "type", "WAD", "wad"}


def _bound_pairs_in_line(line: str):
    """Yield (quantity_field, cap_name, is_guard_form) for each comparison on the
    line where exactly one side references a cap token and the other side's primary
    field is a non-cap quantity identifier. is_guard_form = the comparison sits in a
    require/assert/if/revert context."""
    guard_form = bool(re.search(r"\b(require|assert|if|revert)\b", line))
    # split the line on relops; walk adjacent (left, op, right) operand windows
    parts = _RELOP_RE.split(line)
    # parts = [operand, op, operand, op, operand, ...]
    out = []
    k = 1
    while k < len(parts) - 1:
        left = parts[k - 1]
        right = parts[k + 1]
        lcap = _side_has_cap(left)
        rcap = _side_has_cap(right)
        if lcap ^ rcap:  # exactly one side is the cap side
            if lcap:
                cap_expr, qty_expr = left, right
            else:
                cap_expr, qty_expr = right, left
            qty = _side_primary_field(qty_expr)
            # cap name = the cap token identifier on the cap side
            cap_name = ""
            for m in re.finditer(r"[A-Za-z_]\w*", cap_expr):
                if _is_cap_token(m.group(0)):
                    cap_name = m.group(0)
                    break
            if qty and cap_name and qty.lower() not in _KEYWORDS \
                    and not _is_cap_token(qty) and not qty.isdigit():
                out.append((qty, cap_name, guard_form))
        k += 2
    return out


# --- assignment / write extraction ------------------------------------------
_ASSIGN_RE = re.compile(
    r"([A-Za-z_][A-Za-z0-9_]*(?:\s*\.\s*[A-Za-z_][A-Za-z0-9_]*|\s*\[[^\]]*\])*)"
    r"\s*(\+=|-=|=)\s*([^=;][^;]*?)\s*(?:;|$)")
_INCDEC_RE = re.compile(
    r"(?:\+\+|--)\s*([A-Za-z_][\w.\[\]]*)|([A-Za-z_][\w.\[\]]*)\s*(?:\+\+|--)")


def _classify_direction(fn_name: str, lhs: str, op: str, rhs: str,
                        field: str) -> str:
    """Return 'increase' | 'decrease' | 'set' for a write to `field`."""
    fn = fn_name.lower()
    if op == "-=":
        return "decrease"
    if op == "+=":
        return "increase"
    r = rhs.strip()
    rl = r.lower()
    # `Q = 0` / `delete Q` -> a reset, treated as decrease (cannot exceed a cap)
    if rl in ("0", "0x0", "false"):
        return "decrease"
    # Go slice/map reset: `Q = nil` (drop the whole slice/map) or a
    # truncation-to-empty `Q = Q[:0]` (`h.batch = h.batch[:0]`). Both shrink the
    # container to empty and can never push it PAST a cap -> a reset/decrease, not
    # a needs-cover "set". (FP: sei dump_flatkv.go flush() `h.batch = h.batch[:0]`,
    # where add() is the cap-guarded sibling.)
    if rl == "nil":
        return "decrease"
    if re.search(r"\[\s*:\s*0\s*\]\s*$", r):
        return "decrease"
    fld_re = re.compile(r"\b" + re.escape(field) + r"\b")
    if fld_re.search(r):
        # accumulate form `Q = Q + x` / `Q = Q - x` (also `int256(Q) + change`).
        # Only a NUMERIC-LITERAL delta reveals the direction from the sign; a
        # VARIABLE delta (`+ change`) is signed-unknown -> defer to the fn name
        # (deallocate/withdraw = decrease even though the text says `+ change`).
        if re.search(r"-\s*\d", r) and not re.search(r"\+\s*\d", r):
            return "decrease"
        if re.search(r"\+\s*\d", r) and not re.search(r"-\s*\d", r):
            return "increase"
    # ambiguous accumulate or a direct arbitrary set: decide by the mutator's name
    if any(t in fn for t in _DECREASE_FN):
        return "decrease"
    if any(t in fn for t in _INCREASE_FN):
        return "increase"
    return "set"  # arbitrary set (a rescue/migrate `Q = x`) can exceed a cap


# A local/param scalar is NOT persistent state - a cap can never be "exceeded" by
# writing a transient stack variable (ERC4626 preview/deposit math computes local
# `assets`/`shares` bounded by maxAssets/maxShares - not a stateful cap breach).
_TYPE_DECL_RE = re.compile(
    r"^\s*(?:uint\d*|int\d*|bool|address|bytes\d*|string|"
    r"[A-Z]\w*)\s+(?:memory\s+|storage\s+|calldata\s+)?"
    r"([A-Za-z_]\w*)\s*(?:=|;|,)")
_GO_DECL_RE = re.compile(r"\b([A-Za-z_]\w*)\s*:=")
_GO_VAR_RE = re.compile(r"^\s*var\s+([A-Za-z_]\w*)\b")


def _collect_locals(sig_text, body):
    """Names that are function parameters or locally-declared scalars in this fn
    (so a BARE write to them is a transient, not a persistent-state mutation)."""
    locals_ = set()
    # params: identifiers in the first (...) group of the signature
    start = sig_text.find("(")
    if start >= 0:
        depth = 0
        end = start
        for k in range(start, len(sig_text)):
            if sig_text[k] == "(":
                depth += 1
            elif sig_text[k] == ")":
                depth -= 1
                if depth == 0:
                    end = k
                    break
        params = sig_text[start + 1:end]
        for grp in params.split(","):
            toks = re.findall(r"[A-Za-z_]\w*", grp)
            if toks:
                locals_.add(toks[-1])  # `uint256 assets` -> assets
    # Solidity named return values (`returns (uint256 assets)`) are locals too.
    for rm in re.finditer(r"\breturns\s*\(([^)]*)\)", sig_text):
        for grp in rm.group(1).split(","):
            toks = re.findall(r"[A-Za-z_]\w*", grp)
            if toks:
                locals_.add(toks[-1])
    for _idx, line in body:
        m = _TYPE_DECL_RE.match(line)
        if m:
            locals_.add(m.group(1))
        m = _GO_VAR_RE.match(line)
        if m:
            locals_.add(m.group(1))
        for gm in _GO_DECL_RE.finditer(line):
            locals_.add(gm.group(1))
        # for-loop init counters: `for (uint256 i; i < n; i++)` / `for i := 0;`
        for fm in re.finditer(
                r"\bfor\s*\(?\s*(?:uint\d*\s+|int\d*\s+|var\s+)?"
                r"([A-Za-z_]\w*)\s*(?::=|=|;)", line):
            locals_.add(fm.group(1))
    locals_.update({"i", "j", "k"})  # conventional loop indices
    return locals_


def _writes(body):
    """Yield (abs_idx, fn_local_line, field_base, direction_inputs) for every
    write in a function body: (idx, lhs, op, rhs, field)."""
    for abs_idx, line in body:
        for m in _ASSIGN_RE.finditer(line):
            lhs, op, rhs = m.group(1), m.group(2), m.group(3)
            yield abs_idx, lhs, op, rhs, _field_base(lhs)
        for m in _INCDEC_RE.finditer(line):
            tok = m.group(1) or m.group(2) or ""
            if tok:
                yield abs_idx, tok, "+=", "1", _field_base(tok)


def _is_persistent_write(lhs: str, field: str, locals_: set, lang: str) -> bool:
    """A write mutates persistent state iff it is a member/index access
    (`caps[id].allocation`, `x.total`) OR a BARE Solidity identifier that is NOT a
    local / param (a storage state variable like `totalSupply`). In Go persistent
    state is ALWAYS reached through a receiver/struct field or a store handle, so a
    BARE Go identifier is a transient local and never qualifies."""
    if "." in lhs or "[" in lhs:
        return True
    if lang == "go":
        return False
    return field not in locals_


# --- gate-control detection -------------------------------------------------
def _gate_tokens_in_sig(sig_text: str):
    """Gate modifiers on the function signature (whenNotPaused / onlyAllowed...)."""
    rem = sig_text.split("{", 1)[0]
    rem = re.sub(r"^\s*function\s+\w+\s*\([^)]*\)", " ", rem)
    found = set()
    for m in re.finditer(r"[A-Za-z_]\w*", rem):
        if m.group(0).lower() in ("function", "returns", "public", "external",
                                   "internal", "private", "view", "pure",
                                   "payable", "virtual", "override"):
            continue
        if any(t in m.group(0).lower() for t in _GATE_TOKENS):
            found.add(m.group(0))
    return found


def _gate_tokens_in_body(body):
    """Gate require/if in the body (`require(!paused)`, `if k.IsPaused(ctx)`)."""
    found = set()
    for _idx, line in body:
        if not re.search(r"\b(require|assert|if)\b", line):
            continue
        for m in re.finditer(r"[A-Za-z_]\w*", line):
            if any(t in m.group(0).lower() for t in _GATE_TOKENS):
                found.add(m.group(0))
    return found


def _fn_gate_tokens(sig_text, body):
    return _gate_tokens_in_sig(sig_text) | _gate_tokens_in_body(body)


# --- bound-control guard predicate (CORE) -----------------------------------
def has_bound_guard(body, sig_text, cap_names) -> bool:
    """CORE PREDICATE (bound). True iff the function re-checks the quantity against
    a declared cap: a comparison line referencing a cap token, OR a modifier whose
    name embeds a cap token. This IS the trusted enforcement of the control on this
    writer; its ABSENCE on a mutator is the under-broad violation."""
    # modifier guard (e.g. `withinCap` / `respectsLimit`)
    rem = sig_text.split("{", 1)[0]
    for m in re.finditer(r"[A-Za-z_]\w*", rem):
        if _is_cap_token(m.group(0)) and m.group(0) not in cap_names:
            # a cap-named modifier that is not itself a bound variable
            if not re.search(r"\(", rem[rem.find(m.group(0)):rem.find(m.group(0)) + 40] or ""):
                return True
    for _idx, line in body:
        if not _RELOP_RE.search(line):
            continue
        if _side_has_cap(line):
            return True
    return False


def _stable_id(rel, fn, field, line, kind):
    h = hashlib.sha1()
    h.update(f"{rel}|{fn}|{field}|{line}|{kind}".encode())
    return h.hexdigest()[:16]


def scan_file(path: Path, rel: str, file_text: str = None):
    raw = file_text if file_text is not None else path.read_text(
        encoding="utf-8", errors="ignore")
    text = _mask_comments(raw)
    lang = "go" if rel.lower().endswith(".go") else "solidity"
    lines = text.split("\n")
    fn_cache = list(_functions(lines))

    # --- pass 1: establish control-protected quantities -------------------
    # bound: quantity -> set(cap_names)  (a comparison Q<op>CAP exists)
    bound_qty = {}
    all_cap_names = set()
    for _name, _decl, _sig, body in fn_cache:
        for _idx, line in body:
            for qty, cap, _guard in _bound_pairs_in_line(line):
                bound_qty.setdefault(qty, set()).add(cap)
                all_cap_names.add(cap)

    # per-function facts
    fn_facts = []  # (name, decl_idx, sig, body, is_init, gate_tokens, writes[])
    for name, decl_idx, sig, body in fn_cache:
        is_init = bool(_INIT_NAME_RE.match(name))
        gates = _fn_gate_tokens(sig, body)
        locals_ = _collect_locals(sig, body)
        # keep only PERSISTENT-state writes (drop transient local/param scalars)
        writes = [w for w in _writes(body)
                  if _is_persistent_write(w[1], w[4], locals_, lang)]
        fn_facts.append((name, decl_idx, sig, body, is_init, gates, writes))

    # gate: quantity written under a gate; and which gate tokens establish it
    gate_qty_writers = {}   # quantity -> set(gate_token)   (written in a gated fn)
    gate_qty_gatedfns = {}  # quantity -> set(fn_name)
    for name, _d, _sig, _body, _init, gates, writes in fn_facts:
        if not gates:
            continue
        for _idx, _lhs, _op, _rhs, fld in writes:
            fl = fld.lower()
            if any(kw in fl for kw in _QUANTITY_KW):
                gate_qty_writers.setdefault(fld, set()).update(gates)
                gate_qty_gatedfns.setdefault(fld, set()).add(name)

    # --- pass 2: per-writer coverage of established controls ---------------
    # first, per quantity, which fns guard it (bound / gate) -> "declared+enforced"
    bound_guarded_writers = {}  # quantity -> set(fn_name) that write it AND guard
    for name, _d, sig, body, _init, _gates, writes in fn_facts:
        guarded = has_bound_guard(body, sig, all_cap_names)
        for _idx, _lhs, _op, _rhs, fld in writes:
            if fld in bound_qty and guarded:
                bound_guarded_writers.setdefault(fld, set()).add(name)

    rows = []
    for name, decl_idx, sig, body, is_init, gates, writes in fn_facts:
        bound_guarded = has_bound_guard(body, sig, all_cap_names)
        seen_here = set()  # (kind, field) dedupe within this fn
        for abs_idx, lhs, op, rhs, fld in writes:
            # ---------------- BOUND arm ----------------
            if fld in bound_qty and ("bound", fld) not in seen_here:
                direction = _classify_direction(name, lhs, op, rhs, fld)
                guarded_sibs = bound_guarded_writers.get(fld, set()) - {name}
                needs_cover = direction in ("increase", "set")
                fires = (needs_cover and (not bound_guarded)
                         and (not is_init) and bool(guarded_sibs))
                if needs_cover or fires:
                    seen_here.add(("bound", fld))
                    caps = sorted(bound_qty[fld])
                    rows.append(_row(
                        rel, name, fld, abs_idx, lang, "bound",
                        ",".join(caps), direction, bound_guarded,
                        len(guarded_sibs),
                        sorted(_all_writers(fn_facts, fld)), is_init, fires,
                        (f"`{name}` writes cap-controlled quantity `{fld}` "
                         f"({direction}) with no `{','.join(caps)}` bound-check, "
                         f"while sibling writer(s) {sorted(guarded_sibs)} DO enforce "
                         f"it; can a driver reach this mutator to push `{fld}` past "
                         f"the declared cap (under-broad control)?")))
            # ---------------- GATE arm ----------------
            fl = fld.lower()
            if (any(kw in fl for kw in _QUANTITY_KW)
                    and fld in gate_qty_writers
                    and ("gate", fld) not in seen_here):
                gated_here = bool(gates)
                gated_sibs = gate_qty_gatedfns.get(fld, set()) - {name}
                fires = ((not gated_here) and (not is_init)
                         and len(gate_qty_gatedfns.get(fld, set())) >= 2
                         and bool(gated_sibs))
                if fires or gated_here:
                    seen_here.add(("gate", fld))
                    gtoks = sorted(gate_qty_writers[fld])
                    rows.append(_row(
                        rel, name, fld, abs_idx, lang, "gate",
                        ",".join(gtoks), "gate-mutation", gated_here,
                        len(gated_sibs),
                        sorted(_all_writers(fn_facts, fld)), is_init, fires,
                        (f"`{name}` mutates gate-controlled quantity `{fld}` "
                         f"WITHOUT the `{','.join(gtoks)}` gate, while "
                         f"{sorted(gated_sibs)} are gated; can this un-gated "
                         f"mutator move `{fld}` while the protocol is "
                         f"paused/frozen/allowlist-restricted (under-broad gate)?")))
    return rows


def _all_writers(fn_facts, field):
    out = set()
    for name, _d, _sig, _body, _init, _gates, writes in fn_facts:
        for _idx, _lhs, _op, _rhs, fld in writes:
            if fld == field:
                out.add(name)
    return out


def _row(rel, name, fld, abs_idx, lang, kind, control, direction, guarded,
         guarded_sibs, mutator_set, is_init, fires, question):
    return {
        "schema": HYP_SCHEMA,
        "capability": _CAPABILITY,
        "id": _stable_id(rel, name, fld, abs_idx, kind),
        "file": rel,
        "line": abs_idx + 1,
        "function": name,
        "lang": lang,
        "control_kind": kind,
        "control": control,
        "protected_quantity": fld,
        "mutator_direction": direction,
        "has_control_guard": guarded,
        "guarded_sibling_count": guarded_sibs,
        "complete_mutator_set": mutator_set,
        "is_init_fn": is_init,
        "fires": fires,
        "verdict": "needs-fuzz",
        "advisory": True,
        "auto_credit": False,
        "question": question,
    }


def scan_tree(root: Path):
    rows = []
    for p in _iter_source_files(root):
        try:
            rel = str(p.relative_to(root))
        except ValueError:
            rel = str(p)
        try:
            rows.extend(scan_file(p, rel))
        except Exception:
            continue
    return rows


def _emit_sidecar(ws: Path, rows):
    outdir = ws / ".auditooor"
    outdir.mkdir(parents=True, exist_ok=True)
    out = outdir / _SIDE_NAME
    with out.open("w") as fh:
        for r in rows:
            fh.write(json.dumps(r) + "\n")
    return out


def _summary(rows):
    fired = [r for r in rows if r.get("fires")]
    return {
        "schema": HYP_SCHEMA,
        "capability": _CAPABILITY,
        "enforcement_points": len(rows),
        "fired": len(fired),
        "bound_points": sum(1 for r in rows if r.get("control_kind") == "bound"),
        "gate_points": sum(1 for r in rows if r.get("control_kind") == "gate"),
        "guarded_silent": sum(1 for r in rows if r.get("has_control_guard")),
        "verdict": "needs-fuzz" if fired else "clean-advisory",
        "advisory": True,
        "auto_credit": False,
    }


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="MQ-B02 declared-control -> complete-mutator-set screen (advisory)")
    ap.add_argument("--workspace", "--ws")
    ap.add_argument("--source")
    ap.add_argument("--file")
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--strict", action="store_true")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    strict = args.strict or os.environ.get(_STRICT_ENV, "").strip() not in ("", "0", "false")

    if args.file:
        p = Path(args.file)
        rows = scan_file(p, p.name)
        print(json.dumps(rows, indent=2))
        return 0

    if args.source:
        rows = scan_tree(Path(args.source))
        print(json.dumps(rows, indent=2))
        return 0

    if not args.workspace:
        ap.error("one of --workspace / --source / --file is required")

    ws = Path(args.workspace)
    if not ws.is_absolute():
        cand = Path("/Users/wolf/audits") / args.workspace
        if cand.exists():
            ws = cand
    side = ws / ".auditooor" / _SIDE_NAME

    if args.check:
        rows = []
        if side.exists():
            rows = [json.loads(l) for l in side.read_text().splitlines() if l.strip()]
        summ = _summary(rows)
        summ["source"] = "sidecar"
        print(json.dumps(summ, indent=2))
        return 1 if (strict and summ["fired"]) else 0

    src = ws / "src"
    root = src if src.exists() else ws
    rows = scan_tree(root)
    _emit_sidecar(ws, rows)
    summ = _summary(rows)
    print(json.dumps(summ, indent=2))
    return 1 if (strict and summ["fired"]) else 0


if __name__ == "__main__":
    sys.exit(main())
