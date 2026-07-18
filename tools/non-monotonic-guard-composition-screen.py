#!/usr/bin/env python3
"""non-monotonic-guard-composition-screen.py - the NON-MONOTONIC GUARD COMPOSITION
screen (EXT2-06). A GENERAL, impact-agnostic enforcement-layer detector.

GENERAL ENFORCEMENT CLASS (never a bug SHAPE). It instantiates the north-star
method ("A TRUSTED ENFORCEMENT is bypassable / its private invariant is unsound")
for one delegated-and-trusted safety property that no per-function or single-call
detector owns:

  DELEGATED-TRUSTED INVARIANT : a monotonicity / ceiling / floor / single-action
    restriction over the NET trajectory of a state slot R - "R may only increase"
    (cannot lower an expiry / timelock), "R may only decrease" (cannot raise a cap
    once set), "this one-shot action fires at most once" (a claimed / initialized /
    used latch). The designer BELIEVES the restriction is atomic.
  PRIVATE INVARIANT           : the restriction must hold over the CUMULATIVE net
    effect of every reachable transition of R, not merely on one call's delta.
  ATTACK                      : the guard is enforced on the PER-CALL delta while
    the invariant lives over the NET trajectory - the guard compares the incoming
    value to R's CURRENT stored value (a reference that is itself attacker-mutable
    across calls). A sequence of individually-permitted transitions (raise-then-
    lower / increase-then-decrease / set-then-reset) composes to reach a globally-
    forbidden net state that no single call could reach. Because the enforcement is
    stateless per-call, single-call static checks and modifier audits cannot see the
    cross-call composition.

ANCHOR (real, severity-graded): Code4rena 2024-08-wildcat M-05 - a role provider
first INCREASES an expiry (gaining control / becoming the last setter), then
DECREASES it, bypassing the single-action restriction meant to prevent lowering an
expiry set by another provider. Every individual call passes its own authorized,
per-call-sound guard; the root cause is composition over the net trajectory.

WHY NET-NEW vs the wired arsenal (verified: all three emit ZERO on the Wildcat M-05
shape - numeric slot, guard PRESENT):
  * lifecycle-transition-graph (MQB01) flags a MISSING from-status guard on an
    ENUM status field (has_from_status_guard=false). Here the guard is PRESENT and
    the slot is numeric -> MQB01 emits nothing.
  * declared-control-mutator-completeness (MQB02) fires when >=1 writer LACKS the
    control guard (under-broad). This class requires the guard to be PRESENT and
    per-call sound; the reference is a SELF slot (new-vs-current), not a named CAP
    token, and the defect is cross-call COMPOSITION, which MQB02 has no notion of.
  * ordering-dependent-invariant (E9) is refresher-domination / stale-accumulator
    (a refresh-before-read relation), not raise-before-lower composition.
The distinguishing enforcement shape: a guard that IS present and per-call sound but
compares against a reference that is the SAME mutable slot it (or a sibling) writes,
so composing individually-legal transitions reaches a net-forbidden state.

Enforcement points = every per-call directional / one-shot restriction guard. The
screen answers per point:
  {arm, slot, direction, guard_reference_is_self_mutable_slot, guard_form,
   composition_shape, escape_writers, guarded_fn_is_external}
and flags (WARN, verdict=needs-fuzz) ONLY when a composition escape exists:

  ARM A (directional ratchet / ceiling / floor):
    - a function F carries a directional SELF guard `input <op> R` (op in
      <,<=,>,>=) where R is a persistently-written state slot and the OTHER side is
      caller-controlled (a function parameter) - establishing a per-call
      monotone/bound intent on R; AND
    - the SAME slot R is moved toward the RESTRICTED side by a DIFFERENT,
      externally-reachable writer (an opposite-direction move, an unconstrained set,
      or a reset) that does NOT itself carry the same-direction self guard and is not
      a two-step apply of a pending value - so raise-then-lower / floor-then-drain
      composes.

  ARM B (resettable one-shot latch / single-action):
    - a function W1 guards on a boolean slot F being un-set (`require(!F)` /
      `F == false` / `if (F) revert`) and LATCHES it (`F = true`); AND
    - a DIFFERENT externally-reachable writer W2 RESETS F (`F = false` /
      `delete F`) - so do-then-reset-then-redo performs the one-shot action twice.

ADVISORY-FIRST: every row carries verdict='needs-fuzz', advisory=True,
auto_credit=False. It NEVER auto-credits and NEVER fail-closes in default mode; the
opt-in env AUDITOOOR_NONMONO_STRICT (or --strict) only raises the exit code when a
severity-eligible point fires.

Language-general: Solidity (.sol) and Go (.go). Silent on other trees. Machine-
generated / test / sim / chimera code is excluded via the shared
lib.synthetic_target_exclusion predicates AND the sibling _is_generated_source.

Usage:
  --workspace <ws>   scan <ws>/src -> .auditooor/<sidecar>.jsonl + summary
  --source <dir>     scan an arbitrary dir, print rows as JSON (NO sidecar)
  --file <f>         scan a single .sol/.go file, print rows as JSON
  --check            re-read the emitted sidecar, print cert verdict (advisory)
  --strict           (or env) elevate exit code when a composition escape fires
  --json             machine summary to stdout
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import sys
from pathlib import Path

TOOLS_DIR = Path(__file__).resolve().parent

HYP_SCHEMA = "auditooor.non_monotonic_guard_composition_hypotheses.v1"
_SIDE_NAME = "non_monotonic_guard_composition_hypotheses.jsonl"
_STRICT_ENV = "AUDITOOOR_NONMONO_STRICT"
_CAPABILITY = "EXT2_06"


# --------------------------------------------------------------------------- #
# Reuse: the shared exclusion predicates + the sibling _is_generated_source.
# The .sol/.go WALK must skip machine-generated + test/sim/chimera code via BOTH
# lib.synthetic_target_exclusion AND declared-control-mutator-completeness-screen.
# --------------------------------------------------------------------------- #
def _load_module(filename: str, modname: str):
    path = TOOLS_DIR / filename
    if not path.is_file():
        return None
    spec = importlib.util.spec_from_file_location(modname, path)
    if spec is None or spec.loader is None:
        return None
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)  # type: ignore[union-attr]
    except Exception:
        return None
    return mod


if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

try:
    from lib.synthetic_target_exclusion import (  # noqa: E402
        is_chimera_mutation_harness_path,
        is_codegen_path,
        is_test_target_path,
    )
except Exception:  # pragma: no cover - degrade to permissive stubs if lib absent
    def is_chimera_mutation_harness_path(_p):  # type: ignore
        return False

    def is_codegen_path(_p, _ws=None):  # type: ignore
        return False

    def is_test_target_path(_p):  # type: ignore
        return False

_MQB02 = _load_module(
    "declared-control-mutator-completeness-screen.py", "_nonmono_mqb02")


def _sibling_is_generated_source(path: Path) -> bool:
    """Reuse declared-control-mutator-completeness-screen.py::_is_generated_source.
    Falls back to a byte-identical local check if the sibling is unavailable."""
    fn = getattr(_MQB02, "_is_generated_source", None)
    if fn is not None:
        try:
            return bool(fn(path))
        except Exception:
            pass
    if path.name.lower().endswith(
            (".pb.go", ".pulsar.go", ".pb.gw.go", "_gen.go", ".gen.go",
             "_generated.go")):
        return True
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            head = fh.read(4096)
    except (OSError, UnicodeError):
        return False
    return bool(re.search(r"Code generated .{0,80}?DO NOT EDIT", head, re.I))


_SKIP_DIRS = {"target", ".git", "node_modules", "vendor", "_archive", "out",
              "cache", "lib", "__pycache__", "dist", "build", ".auditooor",
              "benches", "benchmarks", "script", "scripts", "deployments",
              "prior_audits", "reference", "crytic-export", "cache_forge"}


def _iter_source_files(root: Path):
    for dp, dn, fn in os.walk(root):
        dn[:] = [d for d in dn if d not in _SKIP_DIRS]
        rel_dir = dp.replace(os.sep, "/")
        for f in fn:
            low = f.lower()
            if not (low.endswith(".sol") or low.endswith(".go")):
                continue
            p = Path(dp) / f
            rel = rel_dir + "/" + f
            # shared exclusion predicates (test / sim / chimera / codegen path)
            if (is_test_target_path(rel) or is_chimera_mutation_harness_path(rel)
                    or is_codegen_path(rel)):
                continue
            # sibling codegen-sentinel / suffix check (reads the header)
            if _sibling_is_generated_source(p):
                continue
            yield p


# --------------------------------------------------------------------------- #
# Comment / string masking (blank comments + literals, keep line geometry).
# --------------------------------------------------------------------------- #
def _mask_comments(text: str) -> str:
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


# --------------------------------------------------------------------------- #
# Function extraction (brace-matched, Solidity + Go).
# --------------------------------------------------------------------------- #
_FN_DECL_RE = re.compile(
    r"^\s*(?:"
    r"function\s+([A-Za-z_]\w*)"                 # Solidity function foo
    r"|(constructor)\b"                          # Solidity constructor
    r"|(fallback|receive)\s*\("                  # Solidity fallback/receive
    r"|func\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)"   # Go func (recv) Foo / func Foo
    r")")

_INIT_NAME_RE = re.compile(
    r"^(constructor|initialize|__init|_init|init|setup|configure)", re.I)
_RELOP_RE = re.compile(r"(<=|>=|==|!=|<|>)")


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


# --------------------------------------------------------------------------- #
# Field / write helpers.
# --------------------------------------------------------------------------- #
def _field_base(expr: str) -> str:
    seg = re.sub(r"\[[^\]]*\]", "", expr)
    parts = [p.strip() for p in seg.split(".") if p.strip()]
    return parts[-1] if parts else seg.strip()


_ASSIGN_RE = re.compile(
    r"([A-Za-z_][A-Za-z0-9_]*(?:\s*\.\s*[A-Za-z_][A-Za-z0-9_]*|\s*\[[^\]]*\])*)"
    r"\s*(\+=|-=|=)\s*([^=;][^;]*?)\s*(?:;|$)")
_INCDEC_RE = re.compile(
    r"(?:\+\+|--)\s*([A-Za-z_][\w.\[\]]*)|([A-Za-z_][\w.\[\]]*)\s*(?:\+\+|--)")
_DELETE_RE = re.compile(r"\bdelete\s+([A-Za-z_][\w.\[\]]*)")

_DECREASE_FN = ("withdraw", "redeem", "burn", "deallocate", "decrease",
                "decrement", "remove", "exit", "repay", "unstake", "release",
                "deduct", "pull", "subtract", "reduce", "slash", "consume",
                "spend", "debit", "unwind", "lower", "revoke", "cancel")
_INCREASE_FN = ("deposit", "mint", "supply", "allocate", "increase", "increment",
                "add", "borrow", "stake", "credit", "accrue", "fund", "raise",
                "contribute", "issue", "grow", "topup", "top_up", "extend",
                "bump")


def _classify_direction(fn_name: str, lhs: str, op: str, rhs: str,
                        field: str) -> str:
    """Return 'increase' | 'decrease' | 'set' | 'reset' for a write to `field`."""
    fn = fn_name.lower()
    if op == "-=":
        return "decrease"
    if op == "+=":
        return "increase"
    r = rhs.strip()
    rl = r.lower()
    if rl in ("0", "0x0", "false", "nil"):
        return "reset"
    if re.search(r"\[\s*:\s*0\s*\]\s*$", r):
        return "reset"
    fld_re = re.compile(r"\b" + re.escape(field) + r"\b")
    if fld_re.search(r):
        if re.search(r"-\s*\d", r) and not re.search(r"\+\s*\d", r):
            return "decrease"
        if re.search(r"\+\s*\d", r) and not re.search(r"-\s*\d", r):
            return "increase"
    if any(t in fn for t in _DECREASE_FN):
        return "decrease"
    if any(t in fn for t in _INCREASE_FN):
        return "increase"
    return "set"


_TYPE_DECL_RE = re.compile(
    r"^\s*(?:uint\d*|int\d*|bool|address|bytes\d*|string|"
    r"[A-Z]\w*)\s+(?:memory\s+|storage\s+|calldata\s+)?"
    r"([A-Za-z_]\w*)\s*(?:=|;|,)")
_GO_DECL_RE = re.compile(r"\b([A-Za-z_]\w*)\s*:=")
_GO_VAR_RE = re.compile(r"^\s*var\s+([A-Za-z_]\w*)\b")


def _params(sig_text: str):
    """Return the set of parameter names declared in the fn signature."""
    out = set()
    start = sig_text.find("(")
    if start < 0:
        return out
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
    for grp in sig_text[start + 1:end].split(","):
        toks = re.findall(r"[A-Za-z_]\w*", grp)
        if toks:
            out.add(toks[-1])
    return out


def _collect_locals(sig_text, body):
    locals_ = set(_params(sig_text))
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
        for fm in re.finditer(
                r"\bfor\s*\(?\s*(?:uint\d*\s+|int\d*\s+|var\s+)?"
                r"([A-Za-z_]\w*)\s*(?::=|=|;)", line):
            locals_.add(fm.group(1))
    locals_.update({"i", "j", "k"})
    return locals_


def _is_persistent_write(lhs: str, field: str, locals_: set, lang: str) -> bool:
    if "." in lhs or "[" in lhs:
        return True
    if lang == "go":
        return False
    return field not in locals_


def _writes(body):
    """Yield (abs_idx, lhs, op, rhs, field_base) for every write in a body."""
    for abs_idx, line in body:
        for m in _ASSIGN_RE.finditer(line):
            lhs, op, rhs = m.group(1), m.group(2), m.group(3)
            yield abs_idx, lhs, op, rhs, _field_base(lhs)
        for m in _INCDEC_RE.finditer(line):
            tok = m.group(1) or m.group(2) or ""
            if tok:
                yield abs_idx, tok, "+=", "1", _field_base(tok)
        for m in _DELETE_RE.finditer(line):
            tok = m.group(1)
            yield abs_idx, tok, "=", "0", _field_base(tok)


# --------------------------------------------------------------------------- #
# Visibility (external entry vs internal helper).
# --------------------------------------------------------------------------- #
def _visibility(sig_text: str, lang: str, name: str) -> str:
    """'external' when the function is an independent attacker-reachable entry
    point, else 'internal'. Solidity: internal/private keyword -> internal, else
    external (external/public/unspecified interface impls). Go: lowercase-initial
    receiver method / func -> internal (unexported), Capitalized -> external."""
    head = sig_text.split("{", 1)[0]
    if lang == "go":
        return "external" if name[:1].isupper() else "internal"
    if re.search(r"\b(internal|private)\b", head):
        return "internal"
    return "external"


# --------------------------------------------------------------------------- #
# Guard / branch comparison extraction.
# --------------------------------------------------------------------------- #
_GUARD_KW_RE = re.compile(r"\b(require|assert|if|revert|while)\b")


def _side_field_base(expr: str) -> str:
    chains = re.findall(r"[A-Za-z_]\w*(?:\s*\.\s*[A-Za-z_]\w*|\s*\[[^\]]*\])+", expr)
    if chains:
        return _field_base(chains[-1])
    idents = [m.group(0) for m in re.finditer(r"[A-Za-z_]\w*", expr)
              if not m.group(0).isdigit()]
    return _field_base(idents[-1]) if idents else ""


def _side_idents(expr: str):
    return {m.group(0) for m in re.finditer(r"[A-Za-z_]\w*", expr)}


_OPERAND_CHAIN_RE = re.compile(
    r"[A-Za-z_]\w*(?:\s*\.\s*[A-Za-z_]\w*|\s*\[[^\]]*\])*")


def _last_operand(expr: str) -> str:
    """The operand adjacent to a relop on the LEFT side of a comparison: the LAST
    identifier-chain in the (possibly `if (a && b > ...` prefixed) chunk."""
    chains = _OPERAND_CHAIN_RE.findall(expr or "")
    return chains[-1].strip() if chains else ""


def _first_operand(expr: str) -> str:
    """The operand adjacent to a relop on the RIGHT side: the FIRST chain."""
    chains = _OPERAND_CHAIN_RE.findall(expr or "")
    return chains[0].strip() if chains else ""


def _side_root_ident(expr: str) -> str:
    """The ROOT identifier of an access chain (`config[id].cap` -> `config`,
    `req.unlockAt` -> `req`, `timelock` -> `timelock`)."""
    m = re.search(r"[A-Za-z_]\w*", expr)
    return m.group(0) if m else ""


def _side_is_storage_read(expr: str, state_slots: set, locals_: set) -> bool:
    """A comparison side is a STORAGE slot read iff its final field-base is a known
    persistently-written slot AND its ROOT identifier is NOT a function local/param.

    The root-local test is what separates a real state read (`timelock`,
    `expiry[who]`, `config[id].cap`) from a MEMORY / stack struct copy that merely
    shares a field name (`TRequest memory req; ... req.unlockAt`) - the latter is a
    transient read, never the enforcement point of a monotone restriction."""
    fb = _side_field_base(expr)
    if not fb or fb not in state_slots:
        return False
    root = _side_root_ident(expr)
    if root and root in locals_:
        return False
    return True


_MONO_OPS = {"<", "<=", ">", ">="}


def _guard_comparisons(body):
    """Yield (abs_idx, left_expr, op, right_expr) for each relational comparison
    that appears inside a guard / branch context (require / assert / if / revert /
    while) on the line."""
    for abs_idx, line in body:
        if not _GUARD_KW_RE.search(line):
            continue
        parts = _RELOP_RE.split(line)
        k = 1
        while k < len(parts) - 1:
            left, op, right = parts[k - 1], parts[k], parts[k + 1]
            yield abs_idx, left, op, right
            k += 2


def _ratchet_direction(r_on_left: bool, op: str) -> str:
    """Direction the guard CHECKS (the permitted / immediate side) relative to the
    stored slot R. 'up' = R may only rise (new >= old); 'down' = R may only fall."""
    if r_on_left:
        # R op new
        return "up" if op in ("<", "<=") else "down"
    # new op R
    return "down" if op in ("<", "<=") else "up"


def _directional_self_guard(left, op, right, state_slots, params, locals_=frozenset()):
    """CORE PREDICATE (ARM A). Classify a single guard comparison as a directional
    SELF-referential guard, or return None.

    Fires (returns (slot, direction)) iff:
      * op is a monotone relational op (<, <=, >, >=),
      * exactly ONE side is a read of a persistently-written state slot R (its root
        identifier is a state variable, not a memory/stack local),
      * the OTHER side references a function PARAMETER (caller-controlled new value).

    This is the net-new signature: the guard compares an attacker-supplied value to
    the CURRENT value of the very slot the protocol mutates (self-referential delta),
    NOT to a fixed named cap constant (that is MQB02's turf).
    """
    if op not in _MONO_OPS:
        return None
    # Isolate the operand ADJACENT to the operator on each side (a split chunk may
    # carry an `if (cond &&` prefix whose root ident would mislead the state test).
    lop = _last_operand(left)
    rop = _first_operand(right)
    l_slot = _side_is_storage_read(lop, state_slots, locals_)
    r_slot = _side_is_storage_read(rop, state_slots, locals_)
    if l_slot == r_slot:  # need exactly one side to be the stored slot
        return None
    if l_slot:
        slot = _side_field_base(lop)
        other = right          # scan the WHOLE opposite chunk for a parameter
        r_on_left = True
    else:
        slot = _side_field_base(rop)
        other = left
        r_on_left = False
    if not (params & _side_idents(other)):
        return None  # new value must be caller-controlled
    return slot, _ratchet_direction(r_on_left, op)


# --------------------------------------------------------------------------- #
# One-shot latch / reset extraction (ARM B).
# --------------------------------------------------------------------------- #
_UNSET_GUARD_RE = re.compile(
    r"(?:require|assert|if)\s*\(\s*!?\s*"
    r"([A-Za-z_][\w.\[\]]*)\s*(==\s*false|!=\s*true)?\s*\)")
_BANG_RE = re.compile(r"!\s*([A-Za-z_][\w.\[\]]*)")


def _latch_unset_fields(body):
    """Fields tested for the UN-set (false) state in a guard: !F / F==false /
    F!=true / if (F) revert-else. Returns the set of field-bases."""
    out = set()
    for _idx, line in body:
        if not _GUARD_KW_RE.search(line):
            continue
        for bm in _BANG_RE.finditer(line):
            out.add(_field_base(bm.group(1)))
        for m in re.finditer(
                r"([A-Za-z_][\w.\[\]]*)\s*(==\s*false|!=\s*true)", line):
            out.add(_field_base(m.group(1)))
    return out


def _bool_writes(body):
    """Return (sets_true, sets_false) field-base sets written with true/false/delete."""
    sets_true, sets_false = set(), set()
    for abs_idx, line in body:
        for m in _ASSIGN_RE.finditer(line):
            lhs, op, rhs = m.group(1), m.group(2), m.group(3)
            rl = rhs.strip().lower()
            if op == "=" and rl == "true":
                sets_true.add(_field_base(lhs))
            elif op == "=" and rl in ("false",):
                sets_false.add(_field_base(lhs))
        for m in _DELETE_RE.finditer(line):
            sets_false.add(_field_base(m.group(1)))
    return sets_true, sets_false


# --------------------------------------------------------------------------- #
# Two-step-apply detection (a pending-value application is NOT an escape).
# --------------------------------------------------------------------------- #
_PENDING_RHS_RE = re.compile(r"\bpending\w*|\.value\b|\.validAt\b", re.I)


def _write_reads_pending(rhs: str) -> bool:
    return bool(_PENDING_RHS_RE.search(rhs or ""))


def _stable_id(rel, fn, slot, line, arm):
    h = hashlib.sha1()
    h.update(f"{rel}|{fn}|{slot}|{line}|{arm}".encode())
    return h.hexdigest()[:16]


# --------------------------------------------------------------------------- #
# Core file scan.
# --------------------------------------------------------------------------- #
def scan_file(path: Path, rel: str, file_text: str = None):
    raw = file_text if file_text is not None else path.read_text(
        encoding="utf-8", errors="ignore")
    text = _mask_comments(raw)
    lang = "go" if rel.lower().endswith(".go") else "solidity"
    lines = text.split("\n")
    fn_cache = list(_functions(lines))

    # --- pass 1: per-function facts ---------------------------------------
    fn_facts = []
    for name, decl_idx, sig, body in fn_cache:
        locals_ = _collect_locals(sig, body)
        params = _params(sig)
        is_init = bool(_INIT_NAME_RE.match(name))
        vis = _visibility(sig, lang, name)
        head = sig.split("{", 1)[0]
        is_view = lang == "solidity" and bool(
            re.search(r"\b(view|pure)\b", head))
        writes = [w for w in _writes(body)
                  if _is_persistent_write(w[1], w[4], locals_, lang)]
        fn_facts.append({
            "name": name, "decl": decl_idx, "sig": sig, "body": body,
            "params": params, "locals": locals_, "is_init": is_init,
            "vis": vis, "is_view": is_view, "writes": writes,
            "unset_fields": _latch_unset_fields(body),
        })

    # state slots = any persistently-written field-base in the file
    state_slots = set()
    for fi in fn_facts:
        for w in fi["writes"]:
            state_slots.add(w[4])

    # --- pass 1b: directional self guards per fn --------------------------
    for fi in fn_facts:
        # slots this fn ACCUMULATES/CONSUMES in place (`+=` / `-=`). A directional
        # comparison against such a slot is a bound / sufficiency / underflow guard
        # (the compared operand is a DELTA applied to the slot), NOT a monotone
        # REPLACEMENT restriction - that is MQB02 / underflow turf, so it is dropped
        # here. A genuine "cannot lower / cannot raise" restriction gates a
        # replacement `slot = newVal` (possibly via a helper, so an in-fn write is
        # not required). This suppresses the benign ERC20 `allowance -= amount` /
        # accounting `totalShares += shares` shape.
        accum_slots = {w[4] for w in fi["writes"] if w[2] in ("+=", "-=")}
        guards = []  # (slot, direction, line)
        # A view/pure function cannot enforce a state-transition restriction - its
        # comparison against a slot is read-logic, never a monotone enforcement point.
        if not fi["is_view"]:
            for abs_idx, left, op, right in _guard_comparisons(fi["body"]):
                hit = _directional_self_guard(
                    left, op, right, state_slots, fi["params"], fi["locals"])
                if hit and hit[0] not in accum_slots:
                    guards.append((hit[0], hit[1], abs_idx))
        fi["self_guards"] = guards
        # slots this fn guards in each direction (for opposite-guard escape test)
        fi["guard_dirs"] = {}
        for slot, direction, _ln in guards:
            fi["guard_dirs"].setdefault(slot, set()).add(direction)
        # bool writes
        st, sf = _bool_writes(fi["body"])
        fi["sets_true"], fi["sets_false"] = st, sf

    # per-slot writer index (for escape search)
    #   writer entry: (fn_index, direction, external, reads_pending, same_dir_guard?)
    slot_writers = {}
    for idx, fi in enumerate(fn_facts):
        for abs_idx, lhs, op, rhs, fld in fi["writes"]:
            direction = _classify_direction(fi["name"], lhs, op, rhs, fld)
            slot_writers.setdefault(fld, []).append({
                "fi": idx, "direction": direction,
                "external": fi["vis"] == "external",
                "reads_pending": _write_reads_pending(rhs),
                "line": abs_idx,
            })

    rows = []

    # ===================== ARM A: directional composition ================= #
    for idx, fi in enumerate(fn_facts):
        seen = set()
        for slot, direction, gline in fi["self_guards"]:
            if (slot, "A") in seen:
                continue
            seen.add((slot, "A"))
            escapes = _find_escape_writers(
                slot, direction, idx, slot_writers, fn_facts)
            fires = bool(escapes) and not fi["is_init"]
            comp = ("raise-then-lower" if direction == "up"
                    else "floor-then-drop")
            rows.append(_row(
                rel, fi["name"], slot, gline, lang, "directional",
                direction, fires, comp,
                escape_writers=sorted({fn_facts[e]["name"] for e in escapes}),
                guarded_external=(fi["vis"] == "external"),
                question=(
                    f"`{fi['name']}` enforces a per-call {direction}-only "
                    f"restriction on `{slot}` (guard compares a caller value to the "
                    f"current stored `{slot}`), but sibling writer(s) "
                    f"{sorted({fn_facts[e]['name'] for e in escapes}) or '[none]'} "
                    f"move `{slot}` the other way without that restriction. Can a "
                    f"driver compose individually-legal transitions "
                    f"({comp}) to reach a net `{slot}` state the guard is meant to "
                    f"forbid (per-call delta vs net-trajectory invariant)?")))

    # ===================== ARM B: resettable one-shot latch =============== #
    for idx, fi in enumerate(fn_facts):
        latched = fi["unset_fields"] & fi["sets_true"]
        for slot in sorted(latched):
            resetters = [
                fn_facts[w["fi"]]["name"]
                for w in slot_writers.get(slot, [])
                if w["fi"] != idx
                and w["direction"] == "reset"
                and w["external"]
                and not fn_facts[w["fi"]]["is_init"]
            ]
            # also count explicit sets_false in a different, external, non-init fn
            for j, fj in enumerate(fn_facts):
                if j == idx or fj["is_init"] or fj["vis"] != "external":
                    continue
                if slot in fj["sets_false"] and fj["name"] not in resetters:
                    resetters.append(fj["name"])
            resetters = sorted(set(resetters))
            # The latch HOLDER may legitimately be an `initialize()` (that is the
            # canonical one-shot); only the RESETTER is init-excluded (a reset via
            # constructor is not an attacker step). So do NOT init-gate the holder.
            fires = bool(resetters)
            gline = fi["decl"]
            for abs_idx, line in fi["body"]:
                if _GUARD_KW_RE.search(line) and (
                        "!" in line or "false" in line.lower()):
                    gline = abs_idx
                    break
            rows.append(_row(
                rel, fi["name"], slot, gline, lang, "one-shot-latch",
                "latch", fires, "set-then-reset",
                escape_writers=resetters,
                guarded_external=(fi["vis"] == "external"),
                question=(
                    f"`{fi['name']}` treats `{slot}` as a one-shot latch "
                    f"(guards on it being un-set, then sets it), but "
                    f"{resetters or '[none]'} reset `{slot}`. Can do-then-reset-"
                    f"then-redo perform the single-action restriction more than "
                    f"once (per-call latch vs net one-shot invariant)?")))

    return rows


def _find_escape_writers(slot, direction, guard_fi, slot_writers, fn_facts):
    """Return the set of fn indices whose write to `slot` is a composition escape
    relative to a `direction`-only guard in fn `guard_fi`:

      * a DIFFERENT function (not the guard fn),
      * externally reachable, non-init,
      * NOT a two-step apply of a pending value,
      * NOT itself carrying the SAME-direction self guard on `slot`,
      * moving `slot` toward the RESTRICTED side: for an up-guard that is a
        decrease / reset / unconstrained set / an opposite (down) guarded write;
        for a down-guard an increase / reset / set / opposite (up) guarded write.
    """
    escapes = set()
    restricted_dirs = ({"decrease", "reset", "set"} if direction == "up"
                       else {"increase", "reset", "set"})
    for w in slot_writers.get(slot, []):
        j = w["fi"]
        if j == guard_fi:
            continue
        fj = fn_facts[j]
        if fj["is_init"] or not w["external"] or w["reads_pending"]:
            continue
        same_dir_guard = direction in fj["guard_dirs"].get(slot, set())
        if same_dir_guard:
            continue
        if w["direction"] in restricted_dirs:
            escapes.add(j)
    return escapes


def _row(rel, name, slot, abs_idx, lang, arm, direction, fires, comp,
         escape_writers, guarded_external, question):
    return {
        "schema": HYP_SCHEMA,
        "capability": _CAPABILITY,
        "id": _stable_id(rel, name, slot, abs_idx, arm),
        "file": rel,
        "line": abs_idx + 1,
        "function": name,
        "lang": lang,
        "arm": arm,
        "slot": slot,
        "direction": direction,
        "composition_shape": comp,
        "guard_reference_is_self_mutable_slot": True,
        "guarded_fn_is_external": guarded_external,
        "escape_writers": escape_writers,
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
        "directional_points": sum(1 for r in rows if r.get("arm") == "directional"),
        "latch_points": sum(1 for r in rows if r.get("arm") == "one-shot-latch"),
        "verdict": "needs-fuzz" if fired else "clean-advisory",
        "advisory": True,
        "auto_credit": False,
    }


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="EXT2-06 non-monotonic guard composition screen (advisory)")
    ap.add_argument("--workspace", "--ws")
    ap.add_argument("--source")
    ap.add_argument("--file")
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--strict", action="store_true")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    strict = args.strict or os.environ.get(_STRICT_ENV, "").strip() not in (
        "", "0", "false")

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
            rows = [json.loads(l) for l in side.read_text().splitlines()
                    if l.strip()]
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
