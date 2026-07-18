#!/usr/bin/env python3
"""lifecycle-transition-graph-screen.py - the LIFECYCLE-TRANSITION-GRAPH screen (MQ-B01).

GENERAL LOGIC / TRUST-ENFORCEMENT class (never a bug SHAPE). It instantiates the
north-star method ("A TRUSTED ENFORCEMENT is bypassable or its private invariant
is unsound") for one delegated-and-trusted safety property that no per-function
detector owns:

  DELEGATED-TRUSTED INVARIANT : a persisted lifecycle/status field of an object
    (order / game / withdrawal / proposal / market / position) only advances
    along the protocol's INTENDED transition graph - the set of legal
    (from-status -> guarded-action -> to-status) edges.
  PRIVATE INVARIANT           : every function that WRITES the status field first
    asserts the current (from-)status is a legal predecessor of the target edge
    (a from-status guard). The guard closure IS the trusted enforcement of the
    graph.
  ATTACK                      : a driver-reachable function writes the status
    field with NO from-status guard, producing an OUT-OF-GRAPH edge that
    re-activates a terminal/settled/cancelled object, skips a mandatory phase, or
    re-opens a finalized record. Because the graph is enforced by a scatter of
    per-function guards and no single function owns it, one un-guarded writer is
    an out-of-graph transition the state machine never intended.

Enforcement points = every write to a lifecycle/status field. Per point the
screen answers:
  {status_field, to_status, to_status_kind, has_from_status_guard,
   field_guarded_elsewhere, is_init_fn}
and flags (WARN, verdict=needs-fuzz) ONLY when the write has NO from-status guard
in its function AND (the written value re-activates the object OR the SAME field
is a guarded state machine elsewhere in the contract) AND the function is not a
constructor / initializer. It is ADVISORY-FIRST: every row carries
verdict='needs-fuzz', advisory=True, auto_credit=False. It NEVER auto-credits and
NEVER fail-closes in default mode; the opt-in env AUDITOOOR_LIFECYCLE_GRAPH_STRICT
(or --strict) only raises the exit code.

Language-general: implemented for Solidity (.sol) and Go (.go), the two fleet
languages where a persisted status enum + guarded state machine live. Silent on
other trees.

Usage:
  --workspace <ws>   scan <ws>/src -> .auditooor/lifecycle_transition_graph_hypotheses.jsonl + summary
  --source <dir>     scan an arbitrary dir, print rows as JSON
  --file <f>         scan a single .sol/.go file, print rows as JSON
  --check            re-read the emitted sidecar, print cert verdict (advisory)
  --strict           (or env) elevate exit code when an un-guarded out-of-graph edge exists
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

HYP_SCHEMA = "auditooor.lifecycle_transition_graph_hypotheses.v1"
_SIDE_NAME = "lifecycle_transition_graph_hypotheses.jsonl"
_STRICT_ENV = "AUDITOOOR_LIFECYCLE_GRAPH_STRICT"
_CAPABILITY = "MQB01"

_SKIP_DIRS = {"target", ".git", "node_modules", "vendor", "_archive", "out",
              "cache", "lib", "__pycache__", "dist", "build", ".auditooor",
              "benches", "benchmarks", "script", "scripts", "deployments"}
_TEST_HINT = re.compile(
    r"(^|/)(tests?|test_fixtures|mock|mocks|benches|benchmarks?|examples|fixtures)(/|$)")

# --- lifecycle lexicons -----------------------------------------------------
# A field name that denotes a persisted lifecycle/status slot.
_FIELD_KW = ("status", "state", "phase", "stage", "lifecycle", "finalized",
             "finalised", "settled", "resolved", "cancel", "closed", "executed",
             "redeemed", "liquidated", "disputed", "challenged", "filled",
             "claimed", "withdrawn", "initialized", "active", "paused", "step")
# A written value that RE-ACTIVATES / rewinds the object to an earlier phase
# (backward / out-of-graph edge candidate).
_REACTIVATING_KW = ("open", "active", "creat", "pending", "none", "init", "live",
                    "start", "new", "queued", "inprogress", "in_progress", "ready",
                    "unresolved", "unset", "idle", "registered", "proposed",
                    "submitted", "unchallenged", "reopen", "reopened")
# A written value that FINALIZES the object (terminal / settled edge).
_TERMINAL_KW = ("final", "settl", "resolv", "cancel", "clos", "terminat",
                "complet", "redeem", "execut", "expire", "defeat", "kill",
                "dead", "slash", "liquidat", "withdrawn", "claimed",
                "defender_wins", "challenger_wins", "won", "lost", "success",
                "fail", "rejected", "accepted", "disputed", "wins")
# terminal-semantic field names (a bool that, when true, finalizes; when false,
# re-opens). Used to classify bool writes.
_TERMINAL_FIELD_KW = ("finaliz", "finalis", "settl", "resolv", "clos", "execut",
                      "redeem", "liquidat", "cancel", "withdrawn", "claimed",
                      "disputed", "expire", "terminat", "complet")

_RELOP_RE = re.compile(r"(==|!=|<=|>=|<|>)")


def _mask_comments(text: str) -> str:
    """Blank out // and /* */ comments (and Go // ), preserving newlines / line
    length so line indices stay source-accurate. Errs toward SILENCE (a masked
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
            out.append(c)
            if c == "\\":
                out.append(nxt)
                i += 2
                continue
            if c == quote:
                in_str = False
            i += 1
        elif c in ('"', "'"):
            in_str = True
            quote = c
            out.append(c)
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

_INIT_NAME_RE = re.compile(
    r"^(constructor|initialize|__init|_init|init|new|setup|configure"
    r"|submit|create|register)", re.I)


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


def _strip_first_parens(sig: str) -> str:
    """Return sig with the first balanced (...) group removed (the param list),
    so a status keyword left in the remainder is a MODIFIER, not a param type."""
    start = sig.find("(")
    if start < 0:
        return sig
    depth = 0
    for k in range(start, len(sig)):
        if sig[k] == "(":
            depth += 1
        elif sig[k] == ")":
            depth -= 1
            if depth == 0:
                return sig[:start] + " " + sig[k + 1:]
    return sig[:start]


# --- assignment / write extraction ------------------------------------------
# lhs = a (possibly qualified / indexed) path; rhs to `;` (Solidity) OR end-of-line
# (Go has no statement terminator). Not `==`. finditer runs per single line, so `$`
# is the end of that line.
_ASSIGN_RE = re.compile(
    r"([A-Za-z_][A-Za-z0-9_]*(?:\s*\.\s*[A-Za-z_][A-Za-z0-9_]*|\s*\[[^\]]*\])*)"
    r"\s*=\s*([^=;][^;]*?)\s*(?:;|$)")


def _field_base(lhs: str) -> str:
    """Last identifier segment of a qualified lhs (claimData[0].status -> status)."""
    seg = re.sub(r"\[[^\]]*\]", "", lhs)
    parts = [p.strip() for p in seg.split(".") if p.strip()]
    return parts[-1] if parts else seg.strip()


def _is_status_field(field: str, enum_fields: set) -> bool:
    fl = field.lower()
    if field in enum_fields:
        return True
    return any(kw in fl for kw in _FIELD_KW)


def _classify_value(field: str, rhs: str, enum_members: dict) -> str:
    """Return 'reactivating' | 'terminal' | 'unknown' for a to-status write."""
    r = rhs.strip().strip("()").strip()
    rl = r.lower()
    # bool literal: interpret via the field's terminal semantics
    if rl in ("true", "false"):
        fl = field.lower()
        if any(kw in fl for kw in _TERMINAL_FIELD_KW):
            # e.g. finalized=false re-opens; finalized=true finalizes
            return "reactivating" if rl == "false" else "terminal"
        if any(kw in fl for kw in ("active", "open", "live")):
            return "reactivating" if rl == "true" else "terminal"
        return "unknown"
    # numeric 0 tends to be the initial / None state
    if rl in ("0", "0x0"):
        return "reactivating"
    # enum member text (Enum.MEMBER or a bare MEMBER) - match lexicons
    token = r.split(".")[-1] if "." in r else r
    token = re.split(r"[^A-Za-z0-9_]", token)[0]
    tl = token.lower()
    # look up the declared enum member's own kind if we recorded it
    if token in enum_members:
        return enum_members[token]
    if any(kw in tl for kw in _REACTIVATING_KW):
        return "reactivating"
    if any(kw in tl for kw in _TERMINAL_KW):
        return "terminal"
    return "unknown"


def _collect_enums(text: str):
    """Parse enum declarations. Return (enum_field_names, enum_member_kind,
    enum_types, enum_all_members):
      - enum_field_names : storage fields declared with an enum type (status field
        even when its NAME is not a lexicon keyword),
      - enum_member_kind : member ident -> 'reactivating'/'terminal' by its own
        name lexicon (classifies a bare-`MEMBER` write),
      - enum_types       : declared enum type names,
      - enum_all_members : every declared enum member ident (accepts an enum-member
        write value even when its lexicon kind is 'unknown')."""
    member_kind = {}
    enum_types = set()
    all_members = set()
    # Solidity: enum Name { A, B, C }
    for m in re.finditer(r"\benum\s+([A-Za-z_]\w*)\s*\{([^}]*)\}", text):
        enum_types.add(m.group(1))
        for raw in m.group(2).split(","):
            mem = raw.strip()
            mem = re.split(r"[^A-Za-z0-9_]", mem)[0] if mem else ""
            if not mem:
                continue
            all_members.add(mem)
            ml = mem.lower()
            if any(kw in ml for kw in _REACTIVATING_KW):
                member_kind[mem] = "reactivating"
            elif any(kw in ml for kw in _TERMINAL_KW):
                member_kind[mem] = "terminal"
    # Go: type Name <int-ish> ... ; const ( A Name = iota ; B ; ... ) - best effort:
    # collect const idents typed with a status-like type name.
    for m in re.finditer(r"\btype\s+([A-Za-z_]\w*)\s+(?:u?int\w*|string|byte)\b", text):
        tn = m.group(1)
        if any(kw in tn.lower() for kw in ("status", "state", "phase", "stage")):
            enum_types.add(tn)
    # storage fields declared with an enum type: `EnumType [modifiers] name`
    enum_fields = set()
    if enum_types:
        etypes = "|".join(re.escape(t) for t in enum_types)
        for m in re.finditer(
                r"\b(?:" + etypes + r")\s+(?:public\s+|internal\s+|private\s+|"
                r"immutable\s+|constant\s+|memory\s+|storage\s+)*([A-Za-z_]\w*)\s*[;=]",
                text):
            enum_fields.add(m.group(1))
    return enum_fields, member_kind, enum_types, all_members


def _accept_value(rhs: str, enum_types: set, enum_all_members: set) -> bool:
    """A lifecycle TRANSITION writes a status LITERAL, not a computed expression.
    Accept: bool literal, a bare identifier (status var / bare enum member), an
    `Enum.Member` reference, a small int literal, or zero. Reject anything with
    operators / calls / casts (timestamps, addresses, ternaries, comparisons) -
    those are not a state-machine edge and were the FP source (resolvedAt, disputed,
    stepPos on the optimism dispute game)."""
    r = rhs.strip().strip("()").strip()
    if r in ("true", "false"):
        return True
    if re.fullmatch(r"[A-Za-z_]\w*", r):
        return True
    m = re.fullmatch(r"([A-Za-z_]\w*)\s*\.\s*([A-Za-z_]\w*)", r)
    if m:
        # accept only a genuine enum-member reference (declared type or member, or
        # a Status/State/Phase-typed selector) - REJECT globals like block.timestamp
        left, right = m.group(1), m.group(2)
        if left in enum_types or right in enum_all_members:
            return True
        if any(kw in left.lower() for kw in ("status", "state", "phase", "stage")):
            return True
        return False
    if re.fullmatch(r"\d+", r) and int(r) < 64:
        return True
    if re.fullmatch(r"0x0+", r):
        return True
    return False


# --- delegated-guard helpers (private-helper / computed-transition delegation)
_CTRL_CALLEES = {"require", "assert", "if", "for", "while", "revert", "emit",
                 "return", "switch", "catch", "else", "do"}
# a helper whose value COMPUTES the next state (legality delegated to it):
# get*Transition / *StateTransition / next*State*  -> the written to-status is a
# trusted transition output, not a caller-controlled literal.
_TRANSITION_HELPER_RE = re.compile(
    r"\b\w*transition\w*\s*\(|\b(?:get|next|compute|derive|resolve)\w*"
    r"(?:state|status|phase|stage)\w*\s*\(", re.I)


def _iter_calls(line: str):
    """Yield (callee, arg_substring) for each balanced single-line call."""
    for cm in re.finditer(r"\b([A-Za-z_]\w*)\s*\(", line):
        callee = cm.group(1)
        depth = 0
        start = cm.end() - 1
        k = start
        while k < len(line):
            ch = line[k]
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    yield callee, line[start + 1:k]
                    break
            k += 1


def _refs_enum_member(argstr: str, enum_types, enum_all_members) -> bool:
    """True iff an argument references a status enum member (State.X / bare
    MEMBER) - the mark of a delegated from-status guard (e.g. _checkState(self,
    State.Opened) reverts on mismatch)."""
    if not (enum_types or enum_all_members):
        return False
    for m in re.finditer(r"\b([A-Za-z_]\w*)\s*\.\s*([A-Za-z_]\w*)", argstr):
        if enum_types and m.group(1) in enum_types:
            return True
        if enum_all_members and m.group(2) in enum_all_members:
            return True
    if enum_all_members:
        for m in re.finditer(r"\b([A-Za-z_]\w*)\b", argstr):
            if m.group(1) in enum_all_members:
                return True
    return False


def _has_delegated_from_status_guard(body, field, sig_text, enum_types,
                                     enum_all_members, rhs) -> bool:
    """A from-status guard whose enforcement is DELEGATED, not inline:
      (a) a call to a private view/pure helper that is PASSED a status-typed /
          enum-member argument (e.g. `_checkState(self, State.Opened)`) - the
          helper reverts when the current status is not that predecessor; OR
      (b) the written to-status is itself the OUTPUT of a state-transition helper
          (e.g. `(cur, next) = self.getStateTransition(cfg); self.state = next;`)
          - legality is delegated to the transition function, so the write is
          never an out-of-graph edge.
    """
    # (a) enum-member argument passed to a (non-control) helper call
    if enum_types or enum_all_members:
        for _idx, line in body:
            for callee, args in _iter_calls(line):
                if callee in _CTRL_CALLEES:
                    continue
                if _refs_enum_member(args, enum_types, enum_all_members):
                    return True
    # (b) to-status value is bound from a transition-computing helper
    if rhs:
        rv = rhs.strip().strip("()").strip()
        if re.fullmatch(r"[A-Za-z_]\w*", rv):
            rv_re = re.compile(r"\b" + re.escape(rv) + r"\b")
            for _idx, line in body:
                if "=" not in line or not rv_re.search(line):
                    continue
                if _TRANSITION_HELPER_RE.search(line):
                    return True
    return False


def _writes_fresh_slot(body, lhs: str) -> bool:
    """True iff the write targets a FRESHLY-created / just-incremented index slot
    (`id = ++count; slot = coll[id]; slot.status = ...` OR a direct
    `coll[++count].status = ...`). Creating a brand-new record is an INIT edge,
    not an out-of-graph re-activation of an existing object."""
    # names touched by an increment (`++x`, `x++`, `x += 1`) and any name assigned
    # on a line that contains such an increment.
    fresh = set()
    inc_re = re.compile(r"(?:\+\+|--)\s*([\w.]+)|([\w.]+)\s*(?:\+\+|--)"
                        r"|([\w.]+)\s*\+=\s*1\b")
    for _idx, line in body:
        hit = False
        for m in inc_re.finditer(line):
            hit = True
            tok = m.group(1) or m.group(2) or m.group(3) or ""
            base = tok.split(".")[-1]
            if base:
                fresh.add(base)
        if hit:
            am = re.match(r"\s*([A-Za-z_][\w.]*)\s*=", line)
            if am:
                fresh.add(am.group(1).split(".")[-1])
    if not fresh:
        return False
    fresh_re = re.compile(r"\b(?:" + "|".join(re.escape(f) for f in fresh) + r")\b")
    # the write's base identifier
    base_seg = re.sub(r"\[[^\]]*\]", "", lhs)
    base_var = [p.strip() for p in base_seg.split(".") if p.strip()]
    base_var = base_var[0] if base_var else ""
    # (i) the write lhs is directly indexed by a fresh counter
    for m in re.finditer(r"\[([^\]]*)\]", lhs):
        if fresh_re.search(m.group(1)):
            return True
    # (ii) the write's base var is bound from an indexed access keyed by a fresh
    #      counter (`newProposal = self.proposals[newProposalId]`)
    if base_var:
        bind_re = re.compile(r"\b" + re.escape(base_var) + r"\b\s*=\s*[^;]*\[([^\]]*)\]")
        for _idx, line in body:
            for m in bind_re.finditer(line):
                if fresh_re.search(m.group(1)):
                    return True
    return False


# --- guard detection (the CORE trusted-enforcement predicate) ---------------
def has_from_status_guard(body, field: str, sig_text: str = "",
                          enum_types=None, enum_all_members=None,
                          rhs: str = None) -> bool:
    """CORE PREDICATE. True iff the function asserts the current (from-)status
    before the write - i.e. the trusted graph enforcement is present.

    A guard is:
      - a require(...)/assert(...) / if(...) revert|return / Go `if ... { return }`
        line that references the status field name with a relational operator
        (status != X, status == Y), OR a bool require(field)/require(!field), OR
      - a MODIFIER on the function whose name embeds a lifecycle keyword
        (onlyInProgress / whenNotFinalized / ...), OR
      - a DELEGATED guard: a status enum-member argument passed to a private
        helper (`_checkState(self, State.Opened)`), or a to-status value that is
        the output of a state-transition helper (`getStateTransition`).
    """
    fl = field.lower()
    # modifier guard: a status keyword appears in modifier position of the sig
    if sig_text:
        rem = _strip_first_parens(sig_text)
        rem = rem.split("{", 1)[0]
        rem = re.sub(r"\breturns\b\s*\([^)]*\)", " ", rem)
        rem = re.sub(r"\bfunction\s+\w+", " ", rem)
        reml = rem.lower()
        if any(kw in reml for kw in _FIELD_KW) or any(kw in reml for kw in _TERMINAL_KW):
            return True
    fld_re = re.compile(r"\b" + re.escape(field) + r"\b")
    for _idx, line in body:
        if not fld_re.search(line):
            continue
        is_guard_form = bool(
            re.search(r"\b(require|assert)\s*\(", line) or
            re.search(r"\bif\s*\(", line) or
            ("revert" in line) or
            re.search(r"\breturn\b.*\berr", line))
        if not is_guard_form:
            continue
        # relational check on the field, or a bool require(field)/require(!field)
        if _RELOP_RE.search(line):
            return True
        if re.search(r"\b(require|assert)\s*\(\s*!?\s*" + re.escape(field) + r"\b", line):
            return True
        if re.search(r"\bif\s*\(\s*!?\s*[\w.\[\]]*" + re.escape(field) + r"\b\s*\)", line):
            return True
    # delegated enforcement (private-helper check / computed transition output)
    if _has_delegated_from_status_guard(
            body, field, sig_text, enum_types, enum_all_members, rhs):
        return True
    return False


def _stable_id(rel, fn, field, line):
    h = hashlib.sha1()
    h.update(f"{rel}|{fn}|{field}|{line}".encode())
    return h.hexdigest()[:16]


def scan_file(path: Path, rel: str, file_text: str = None):
    raw = file_text if file_text is not None else path.read_text(
        encoding="utf-8", errors="ignore")
    text = _mask_comments(raw)
    lang = "go" if rel.lower().endswith(".go") else "solidity"
    lines = text.split("\n")
    enum_fields, enum_members, enum_types, enum_all_members = _collect_enums(text)

    # First pass: which status fields are guarded SOMEWHERE in the file (evidence
    # of an intended, enforced transition graph the write may bypass).
    guarded_fields = set()
    fn_cache = list(_functions(lines))
    for name, _decl, sig, body in fn_cache:
        # candidate fields = every status-field written OR compared in this fn
        for _idx, line in body:
            for m in _ASSIGN_RE.finditer(line):
                fld = _field_base(m.group(1))
                if _is_status_field(fld, enum_fields):
                    if has_from_status_guard(body, fld, sig, enum_types,
                                             enum_all_members, m.group(2)):
                        guarded_fields.add(fld)
            # also a pure comparison guard with no write in this fn
            if _RELOP_RE.search(line) and re.search(r"\b(require|assert|if)\b", line):
                for kw in _FIELD_KW:
                    mm = re.search(r"\b(" + kw + r"\w*)\b", line, re.I)
                    if mm:
                        guarded_fields.add(mm.group(1))

    rows = []
    for name, decl_idx, sig, body in fn_cache:
        name_is_init = bool(_INIT_NAME_RE.match(name))
        for abs_idx, line in body:
            for m in _ASSIGN_RE.finditer(line):
                lhs = m.group(1)
                rhs = m.group(2)
                fld = _field_base(lhs)
                if not _is_status_field(fld, enum_fields):
                    continue
                # a lifecycle EDGE writes a status LITERAL, not a computed value
                # (timestamp / address / ternary / comparison) - reject the rest.
                if not _accept_value(rhs, enum_types, enum_all_members):
                    continue
                # INIT = an init-lexicon fn name OR a write to a freshly created /
                # just-incremented index slot (creating a new record, not a
                # re-activation of an existing one).
                is_init = name_is_init or _writes_fresh_slot(body, lhs)
                kind = _classify_value(fld, rhs, enum_members)
                guarded = has_from_status_guard(body, fld, sig, enum_types,
                                                enum_all_members, rhs)
                guarded_elsewhere = fld in guarded_fields
                reactivating = (kind == "reactivating")
                fires = ((not guarded)
                         and (reactivating or guarded_elsewhere)
                         and (not is_init))
                rows.append({
                    "schema": HYP_SCHEMA,
                    "capability": _CAPABILITY,
                    "id": _stable_id(rel, name, fld, abs_idx),
                    "file": rel,
                    "line": abs_idx + 1,
                    "function": name,
                    "lang": lang,
                    "status_field": fld,
                    "to_status": rhs.strip().strip("()").strip()[:80],
                    "to_status_kind": kind,
                    "has_from_status_guard": guarded,
                    "field_guarded_elsewhere": guarded_elsewhere,
                    "is_init_fn": is_init,
                    "fires": fires,
                    "verdict": "needs-fuzz",
                    "advisory": True,
                    "auto_credit": False,
                    "question": (
                        f"`{name}` writes lifecycle field `{fld}` <- "
                        f"{rows_val(rhs)} ({kind}) with no from-status guard; can a "
                        f"driver reach this from a terminal/settled state to force an "
                        f"out-of-graph transition (re-open/re-activate/skip-phase)?"),
                })
                break  # one row per (field, line) assignment
    return rows


def rows_val(rhs: str) -> str:
    return rhs.strip().strip("()").strip()[:48]


def scan_tree(root: Path):
    rows = []
    for p in _iter_source_files(root):
        try:
            rel = str(p.relative_to(root))
        except ValueError:
            rel = str(p)
        rows.extend(scan_file(p, rel))
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
        "guarded_silent": sum(1 for r in rows if r.get("has_from_status_guard")),
        "verdict": "needs-fuzz" if fired else "clean-advisory",
        "advisory": True,
        "auto_credit": False,
    }


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="MQ-B01 lifecycle-transition-graph screen (advisory)")
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
