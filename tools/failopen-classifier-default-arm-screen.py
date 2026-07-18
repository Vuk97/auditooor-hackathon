#!/usr/bin/env python3
"""failopen-classifier-default-arm-screen.py - the FAIL-OPEN CLASSIFIER DEFAULT
ARM screen (EXT2-03 / code+sidecar key EXT2_03). The kora-lib class
(GHSA-x442-m7cc-hr92): "Unrecognized Instruction Types Create Empty Stubs That
Bypass Fee Payer Policy".

GENERAL LOGIC / ENFORCEMENT-COMPOSITION class (never a bug SHAPE). It audits the
DEFAULT / unknown / catch-all arm of every dispatch that maps UNTRUSTED input to a
set of known variants and whose OUTPUT is consumed by a separate policy / spend /
authorization checker. The net-new axis: reviewers naturally inspect the enumerated
arms; the bug hides in the arm nobody enumerates.

  COMPOSED INVARIANT  : a parser/classifier maps untrusted input -> one of N known
    variants; a SEPARATE downstream enforcer (fee-payer policy, spend cap, ACL,
    touched-account check) evaluates the classifier's OUTPUT and is TRUSTED to be
    the last line of defence.
  PRIVATE INVARIANT   : an UNRECOGNISED variant must be REJECTED (Err / panic /
    revert / abort / non-nil error) so it never reaches the enforcer as "nothing to
    check".
  ATTACK              : the default / `_ =>` / `default:` / catch-all arm instead
    CONSTRUCTS AN EMPTY / ZERO / DEFAULT stub - an empty touched-account set, a
    zero fee, a no-op, `Ok(())`, `Ok(vec![])`, `HashSet::new()`, `return nil, nil`,
    `Default::default()` - and the downstream policy evaluates that empty stub as
    COMPLIANT. "I do not recognise this" silently collapses into "this is allowed".
    kora-lib: an unknown Solana instruction parsed to an EMPTY touched-account set,
    so the fee-payer policy (which forbids the fee payer from being touched) saw
    nothing to forbid and signed/paid for an attacker-crafted instruction.

The classifier and the checker are SEPARATE layers; the classifier failing OPEN
silently disarms an otherwise-correct checker. No standard detector (reentrancy /
access-control / oracle / CEI / unchecked-return / missing-guard) models a
classifier's unknown-variant arm - the enumerated arms carry a guard, so a
missing-guard scan is satisfied. This is a SOUNDNESS audit of the arm nobody reads.

DETECTION - the "empty-stub asymmetry". A dispatch is an enforcement point when it
is a VALUE-producing multi-way classifier:
  * Rust `match <scrutinee> { .. }`  |  Go `switch { .. }`  (canonical dispatch forms)
  * has an explicit DEFAULT / catch-all arm (`_ =>`, bare-binding `other =>`, `..`,
    Go `default:`), AND
  * has >=2 enumerated arms, at least one of which is SUBSTANTIVE (its result
    expression CONSTRUCTS a non-empty value: `Some(x)`, `vec![x]`, `HashSet::from`,
    a struct literal with fields, a parse/decode call, a non-empty Go composite).
The screen classifies the DEFAULT arm's result: REJECT (Err/panic/revert/abort/
non-nil error), PERMISSIVE-EMPTY (empty collection / Default::default / unit /
None / nil-with-no-error / zero-value struct), or SUBSTANTIVE (a real fallback).
It FIRES (WARN, verdict=needs-fuzz) ONLY when:
    default_disposition == permissive_empty  AND  >=1 substantive enumerated arm
i.e. the KNOWN variants produce content but the UNKNOWN variant produces an empty
stub - the kora signature. A default that REJECTS is emitted as a documented sound
enforcement point (fires=False); a default that returns a real fallback is
substantive (fires=False). Side-effect-only switches (no value returned) are not
value-classifiers and are never rows - no FP-spray.

Because the fire is driven by the DEFAULT arm's emptiness relative to substantive
siblings (not by any impact keyword), it is IMPACT-AGNOSTIC and GENERAL: it audits
the unhandled arm of EVERY parser->policy composition, not a single bug shape.

ADVISORY-FIRST: every row carries verdict='needs-fuzz', advisory=True,
auto_credit=False. It NEVER auto-credits and NEVER fail-closes in default mode; the
opt-in env AUDITOOOR_FAILOPEN_CLASSIFIER_STRICT (or --strict) only raises the exit
code when a fired point is ALSO in a recognisable classifier/policy context
(classifier_context=True) - the severity-eligible subset.

Language: Rust (.rs) `match`, Go (.go) `switch`. Silent on other trees. (Solidity /
Move high-level have no match/switch; the general question there = if/else-if
default branch, deliberately OUT of this screen's scope to avoid if/else FP-spray -
see the hacker-Q it emits per fired point.)

Usage:
  --workspace <ws>  scan <ws>/src -> .auditooor/failopen_classifier_default_arm_hypotheses.jsonl + summary
  --source <dir>    scan an arbitrary dir, print rows as JSON (NO sidecar)
  --file <f>        scan a single file, print rows as JSON
  --check           re-read the emitted sidecar, print cert verdict (advisory)
  --strict          (or env) elevate exit code when a severity-eligible point fired
  --json            machine summary to stdout
"""
from __future__ import annotations

import argparse
import bisect
import hashlib
import json
import os
import re
import sys
from pathlib import Path

TOOLS_DIR = Path(__file__).resolve().parent
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

# --- shared synthetic/codegen exclusion (mandated reuse) --------------------
try:
    from lib.synthetic_target_exclusion import (  # noqa: E402
        is_chimera_mutation_harness_path,
        is_codegen_path,
        is_test_target_path,
    )
except Exception:  # pragma: no cover - defensive fallback keeps the screen usable
    def is_test_target_path(_p):  # type: ignore
        return False

    def is_codegen_path(_p, workspace=None):  # type: ignore
        return False

    def is_chimera_mutation_harness_path(_p):  # type: ignore
        return False

# reuse declared-control-mutator-completeness-screen._is_generated_source for the
# .go/.sol codegen sentinel walk (mandated). Loaded by path (hyphenated filename).
def _load_generated_source_fn():
    import importlib.util
    tgt = TOOLS_DIR / "declared-control-mutator-completeness-screen.py"
    try:
        spec = importlib.util.spec_from_file_location("_dcmcs_screen", tgt)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)  # type: ignore
        return mod._is_generated_source
    except Exception:
        # local mirror (same predicate) if the sibling tool can't be imported.
        _suffixes = (".pb.go", ".pulsar.go", ".pb.gw.go", "_gen.go", ".gen.go",
                     "_generated.go")
        _sentinel = re.compile(r"Code generated .{0,80}?DO NOT EDIT", re.I)

        def _fallback(path: Path) -> bool:
            if path.name.lower().endswith(_suffixes):
                return True
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as fh:
                    return bool(_sentinel.search(fh.read(4096)))
            except (OSError, UnicodeError):
                return False
        return _fallback


_is_generated_source = _load_generated_source_fn()

HYP_SCHEMA = "auditooor.failopen_classifier_default_arm_hypotheses.v1"
_SIDE_NAME = "failopen_classifier_default_arm_hypotheses.jsonl"
_STRICT_ENV = "AUDITOOOR_FAILOPEN_CLASSIFIER_STRICT"
_CAPABILITY = "EXT2_03"

_SKIP_DIRS = {"target", ".git", "node_modules", "vendor", "_archive", "out",
              "cache", "__pycache__", "dist", "build", ".auditooor",
              "benches", "benchmarks", "script", "scripts", "deployments",
              "prior_audits", "reference", "audits", "docs", "testdata",
              "chimera_harnesses", "simulation", "simapp"}
_SRC_EXT = (".rs", ".go")


def _iter_source_files(root: Path):
    root = Path(root)
    for dp, dn, fn in os.walk(root):
        dn[:] = [d for d in dn if d not in _SKIP_DIRS]
        for f in fn:
            low = f.lower()
            if not low.endswith(_SRC_EXT):
                continue
            p = Path(dp) / f
            try:
                rel = str(p.relative_to(root))
            except ValueError:
                rel = str(p)
            # mandated exclusions: test / codegen / chimera + generated sentinel
            if is_test_target_path(rel) or is_test_target_path(str(p)):
                continue
            if is_chimera_mutation_harness_path(rel):
                continue
            if is_codegen_path(rel) or is_codegen_path(str(p)):
                continue
            if _is_generated_source(p):
                continue
            yield p


# --- comment / string masking (byte-for-byte length + newline preserving) ---
def _char_literal_end(text: str, i: int) -> int:
    """If text[i]=="'" opens a Rust/Go CHAR/RUNE literal, return the index of its
    closing quote; else -1 (a Rust lifetime `'a` / label, which must NOT be masked
    as a string - that was the newline-eating bug that shifted line numbers)."""
    n = len(text)
    if i + 1 >= n:
        return -1
    if text[i + 1] == "\\":                     # escaped char literal '\n' / '\'' / '\u{..}'
        end = text.find("'", i + 2, min(n, i + 14))
        if end != -1 and "\n" not in text[i:end]:
            return end
        return -1
    # simple 'x' - closing quote exactly two chars along, not a lifetime `'a ...`
    if i + 2 < n and text[i + 2] == "'" and text[i + 1] not in ("'", "\n"):
        return i + 2
    return -1


def _mask_comments(text: str) -> str:
    """Blank out comments, string and char literals with spaces, PRESERVING every
    newline (so char offset -> line number is stable) and total length."""
    out = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if c == "/" and nxt == "/":
            i += 2
            out.append("  ")
            while i < n and text[i] != "\n":
                out.append(" ")
                i += 1
        elif c == "/" and nxt == "*":
            i += 2
            out.append("  ")
            while i < n and not (text[i] == "*" and text[i + 1:i + 2] == "/"):
                out.append("\n" if text[i] == "\n" else " ")
                i += 1
            if i < n:
                out.append("  ")
                i += 2
        elif c in ('"', "`"):
            quote = c
            out.append(" ")
            i += 1
            while i < n and text[i] != quote:
                if quote == '"' and text[i] == "\\":
                    out.append(" ")
                    i += 1
                    if i < n:
                        out.append("\n" if text[i] == "\n" else " ")
                        i += 1
                    continue
                out.append("\n" if text[i] == "\n" else " ")
                i += 1
            if i < n:
                out.append(" ")
                i += 1
        elif c == "'":
            close = _char_literal_end(text, i)
            if close != -1:
                for k in range(i, close + 1):
                    out.append("\n" if text[k] == "\n" else " ")
                i = close + 1
            else:                               # Rust lifetime / label - leave as-is
                out.append(c)
                i += 1
        else:
            out.append(c)
            i += 1
    return "".join(out)


# --- function extraction (brace-matched; Rust fn / Go func) -----------------
_FN_DECL_RE = re.compile(
    r"^\s*(?:"
    r"(?:pub\s+|pub\([^)]*\)\s+)?(?:async\s+|unsafe\s+|const\s+|extern\s+\"[^\"]*\"\s+)*fn\s+([A-Za-z_]\w*)"
    r"|func\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)"
    r")")


def _fn_ranges(lines):
    """Yield (name, start_idx, end_idx) for each brace-matched fn body (0-indexed
    inclusive line range)."""
    i, n = 0, len(lines)
    ranges = []
    while i < n:
        m = _FN_DECL_RE.match(lines[i])
        if not m:
            i += 1
            continue
        name = m.group(1) or m.group(2) or "<anon>"
        depth = 0
        started = False
        j = i
        while j < n:
            depth += lines[j].count("{") - lines[j].count("}")
            if "{" in lines[j]:
                started = True
            if started and depth <= 0:
                break
            j += 1
        ranges.append((name, i, j))
        i = max(j, i + 1) if not started else i + 1
    return ranges


def _enclosing_fn(ranges, line_idx):
    """Innermost fn range containing line_idx, else None."""
    best = None
    best_span = None
    for name, s, e in ranges:
        if s <= line_idx <= e:
            span = e - s
            if best_span is None or span < best_span:
                best, best_span = name, span
    return best


# --- brace matching ---------------------------------------------------------
_OPEN = {"(": ")", "[": "]", "{": "}"}
_CLOSE = {v: k for k, v in _OPEN.items()}


def _match_bracket(text: str, open_idx: int):
    """Index of the bracket matching text[open_idx]. -1 if unbalanced."""
    opener = text[open_idx]
    closer = _OPEN[opener]
    depth = 0
    for k in range(open_idx, len(text)):
        ch = text[k]
        if ch == opener:
            depth += 1
        elif ch == closer:
            depth -= 1
            if depth == 0:
                return k
    return -1


def _first_arm_brace(text: str, start: int):
    """Index of the `{` that opens a match/switch arm BLOCK at/after `start`,
    skipping brackets that belong to the scrutinee. Returns the index of a `{`
    whose block content contains a top-level `=>` (Rust) or `case`/`default` (Go),
    else the first plain `{`. -1 if none."""
    i = start
    n = len(text)
    while i < n:
        ch = text[i]
        if ch in ("(", "["):
            j = _match_bracket(text, i)
            if j < 0:
                return -1
            i = j + 1
            continue
        if ch == "{":
            return i
        if ch == ";":
            return -1
        i += 1
    return -1


# --- arm result-expression + disposition classification (CORE #2) -----------
_RUST_EMPTY_ATOMS = (
    r"\(\s*\)",                      # unit ()
    r"\{\s*\}",                      # empty block {}
    r"vec!\s*\[\s*\]",
    r"(?:std::\w+::)?Vec::(?:new|with_capacity)\s*\(",
    r"VecDeque::(?:new|with_capacity)\s*\(",
    r"(?:Hash|BTree|Index|Ordered)Set::(?:new|with_capacity|default)\s*\(",
    r"(?:Hash|BTree|Index|Ordered)Map::(?:new|with_capacity|default)\s*\(",
    r"String::new\s*\(",
    r"[A-Za-z_]\w*::default\s*\(\s*\)",
    r"Default::default\s*\(\s*\)",
    r"None\b",
)
_RUST_EMPTY_RE = re.compile(r"^\s*(?:" + "|".join(_RUST_EMPTY_ATOMS) + r")\s*[\),;]*\s*$")
# reject tokens (present ANYWHERE in the arm body -> the arm rejects)
_RUST_REJECT_RE = re.compile(
    r"\breturn\s+Err\b|(?<![.\w])Err\s*\(|\bResult::Err\b|\bpanic!|\bunreachable!"
    r"|\btodo!|\bunimplemented!|\bbail!|\banyhow::bail\b|\bassert!\s*\(\s*false"
    r"|\bassert!\s*\(\s*false\b|\brevert\b|\babort\b|\bError::")
# substantive value construction in the arm's result expression
_RUST_SUBSTANTIVE_RE = re.compile(
    r"vec!\s*\[\s*[^\]\s]"                       # vec![x]
    r"|Some\s*\(\s*(?!None|\)|Default::default)[^)]"  # Some(x) (not Some(None)/empty)
    r"|Ok\s*\(\s*Some\s*\("                      # Ok(Some(..))
    r"|(?:Hash|BTree|Index)Set::from\s*\("       # HashSet::from([..])
    r"|(?:Hash|BTree|Index)Map::from\s*\("
    r"|\.collect\s*\(\s*\)"                       # ....collect()
    r"|[A-Z]\w*\s*\{\s*[A-Za-z_]\w*\s*[:,]"     # StructLit { field: .. }
    r"|[A-Z]\w*::new\s*\(\s*[^)\s]"             # Ctor::new(arg)
    r"|\b(?:parse|decode|deserialize|extract|from_bytes|try_from|read_)\w*\s*\(")


def _rust_result_expr(body: str) -> str:
    """The arm's result (tail) expression. For a brace body `{ ..; tail }` -> the
    tail (last non-`;`-terminated segment); for an expr body -> the whole body."""
    b = body.strip()
    if b.startswith("{"):
        j = _match_bracket(b, 0)
        inner = b[1:j] if j > 0 else b[1:]
        inner = inner.strip()
        # split off the tail: last top-level statement not ending in ';'
        segs = _split_top_level(inner, ";")
        if not segs:
            return "()"
        tail = segs[-1].strip()
        # if the block ends with a trailing ';', the value is unit
        if inner.rstrip().endswith(";") or not tail:
            return "()"
        return tail
    return b


def _classify_rust_arm(body: str) -> str:
    """One of reject / permissive_empty / substantive / other."""
    if _RUST_REJECT_RE.search(body):
        return "reject"
    expr = _rust_result_expr(body)
    # strip one wrapping Ok(...)/Some(...)/return of an empty payload for emptiness
    stripped = expr.strip()
    m = re.match(r"^(?:return\s+)?(Ok|Some)\s*\((.*)\)\s*$", stripped, re.S)
    inner_for_empty = m.group(2).strip() if m else re.sub(r"^return\s+", "", stripped)
    if _RUST_EMPTY_RE.match(expr) or _RUST_EMPTY_RE.match(inner_for_empty) \
            or re.match(r"^(?:return\s+)?Ok\s*\(\s*\(\s*\)\s*\)\s*$", stripped) \
            or re.match(r"^(?:return\s+)?Ok\s*\(\s*None\s*\)\s*$", stripped):
        return "permissive_empty"
    if _RUST_SUBSTANTIVE_RE.search(expr):
        return "substantive"
    return "other"


# Go
_GO_REJECT_RE = re.compile(
    r"\breturn\b[^\n]*\b(?:err|Err|Errorf|errors\.New|fmt\.Errorf|ErrUnknown|"
    r"ErrInvalid|ErrUnsupported)\b|\bpanic\s*\(")
_GO_EMPTY_RETURN_RE = re.compile(
    r"\breturn\s+("
    r"nil(?:\s*,\s*nil)?"                       # return nil / return nil, nil
    r"|(?:&\s*)?[A-Za-z_][\w.]*\s*\{\s*\}(?:\s*,\s*nil)?"  # T{} / &T{} [, nil]
    r"|\[\]\s*[A-Za-z_][\w.]*\s*\{\s*\}(?:\s*,\s*nil)?"    # []T{}
    r"|map\[[^\]]*\][^{]*\{\s*\}(?:\s*,\s*nil)?"           # map[..]..{}
    r"|\"\"(?:\s*,\s*nil)?"                                # "" (empty string)
    r"|0(?:\s*,\s*nil)?"                                   # 0
    r")\s*$", re.M)
_GO_SUBSTANTIVE_RETURN_RE = re.compile(
    r"return\s+(?:&\s*)?[A-Za-z_][\w.]*\s*\{[^}]*[A-Za-z_]\w*\s*:"   # &T{field: ..}
    r"|return\s+\[\][A-Za-z_][\w.]*\s*\{[^}]*[^\s}]"                 # non-empty []T{..}
    r"|\bappend\s*\("
    r"|return\s+[A-Za-z_][\w.]*\s*\([^)]*\S"                         # constructor/parse call
    r"|return\s+(?!nil\b|err\b|0\b)[A-Za-z_][\w.]*(?:\.[A-Za-z_]\w*)+(?:\s*,\s*nil)?\s*$",
    re.M)                                                            # x.Field / pkg.Val


def _classify_go_case(body: str) -> str:
    """One of reject / permissive_empty / substantive / other (no value returned)."""
    if _GO_REJECT_RE.search(body):
        return "reject"
    if _GO_SUBSTANTIVE_RETURN_RE.search(body):
        return "substantive"
    if _GO_EMPTY_RETURN_RE.search(body):
        return "permissive_empty"
    return "other"


# --- top-level splitter (bracket-aware) -------------------------------------
def _split_top_level(text: str, sep: str):
    out = []
    depth = 0
    start = 0
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if ch in _OPEN:
            depth += 1
        elif ch in _CLOSE:
            depth = max(0, depth - 1)
        elif ch == sep and depth == 0:
            out.append(text[start:i])
            start = i + 1
        i += 1
    out.append(text[start:])
    return out


# --- Rust match arm parsing (CORE #1) ---------------------------------------
def _split_rust_arms(inner: str):
    """Yield (pattern, body, body_offset_in_inner) for each arm of a match block's
    inner content."""
    n = len(inner)
    arm_start = 0
    i = 0
    depth = 0
    arms = []
    while i < n:
        ch = inner[i]
        if ch in _OPEN:
            depth += 1
            i += 1
            continue
        if ch in _CLOSE:
            depth = max(0, depth - 1)
            i += 1
            continue
        if depth == 0 and ch == "=" and i + 1 < n and inner[i + 1] == ">":
            pattern = inner[arm_start:i]
            # parse body
            k = i + 2
            while k < n and inner[k] in " \t\r\n":
                k += 1
            if k < n and inner[k] == "{":
                j = _match_bracket(inner, k)
                if j < 0:
                    break
                body = inner[k:j + 1]
                body_off = k
                # consume optional trailing comma
                m = j + 1
                while m < n and inner[m] in " \t\r\n":
                    m += 1
                if m < n and inner[m] == ",":
                    m += 1
                arm_start = m
                i = m
            else:
                # expr body until top-level comma
                d2 = 0
                m = k
                while m < n:
                    c2 = inner[m]
                    if c2 in _OPEN:
                        d2 += 1
                    elif c2 in _CLOSE:
                        d2 = max(0, d2 - 1)
                    elif c2 == "," and d2 == 0:
                        break
                    m += 1
                body = inner[k:m]
                body_off = k
                arm_start = m + 1
                i = m + 1
            arms.append((pattern.strip(), body, body_off))
            continue
        i += 1
    return arms


_RUST_CATCHALL_BIND_RE = re.compile(r"^[a-z_][A-Za-z0-9_]*$")


def _rust_arm_is_default(pattern: str) -> bool:
    p = pattern.strip()
    if " if " in p:                 # guarded catch-all is conditional, not a default
        return False
    if p == "_":
        return True
    if p == ".." or p.endswith("..") and p.replace(".", "").strip() == "":
        return True
    # bare lowercase identifier binding (e.g. `other =>`, `unknown =>`)
    if _RUST_CATCHALL_BIND_RE.match(p) and p not in (
            "true", "false", "none", "nil"):
        return True
    return False


# --- Go switch case parsing (CORE #1 Go) ------------------------------------
_GO_LABEL_RE = re.compile(r"\b(case|default)\b")


def _split_go_cases(inner: str):
    """Yield (is_default, body, body_offset_in_inner) for each case/default of a
    switch block's inner content."""
    n = len(inner)
    labels = []  # (is_default, label_end_offset)
    i = 0
    depth = 0
    while i < n:
        ch = inner[i]
        if ch in _OPEN:
            depth += 1
            i += 1
            continue
        if ch in _CLOSE:
            depth = max(0, depth - 1)
            i += 1
            continue
        if depth == 0 and (ch == "c" or ch == "d"):
            m = _GO_LABEL_RE.match(inner, i)
            if m and (i == 0 or not (inner[i - 1].isalnum() or inner[i - 1] == "_")):
                kw = m.group(1)
                # find the terminating ':' at depth 0
                j = m.end()
                d2 = 0
                while j < n:
                    cj = inner[j]
                    if cj in _OPEN:
                        d2 += 1
                    elif cj in _CLOSE:
                        d2 = max(0, d2 - 1)
                    elif cj == ":" and d2 == 0:
                        # not the ':=' assignment nor '::'
                        if inner[j + 1:j + 2] != "=" and inner[j - 1:j] != ":":
                            break
                    j += 1
                labels.append((kw == "default", j + 1))
                i = j + 1
                continue
        i += 1
    cases = []
    for idx, (is_def, body_off) in enumerate(labels):
        end = labels[idx + 1][1] if idx + 1 < len(labels) else n
        # trim the trailing label keyword text of the next label from this body
        if idx + 1 < len(labels):
            # body runs up to the start of the next label keyword; recompute start
            nxt_off = labels[idx + 1][1]
            # find the keyword start preceding nxt_off
            kstart = inner.rfind("case", body_off, nxt_off)
            dstart = inner.rfind("default", body_off, nxt_off)
            cut = max(kstart, dstart)
            end = cut if cut > body_off else nxt_off
        body = inner[body_off:end]
        cases.append((is_def, body, body_off))
    return cases


# --- classifier / policy context amplifier ----------------------------------
_CTX_RE = re.compile(
    r"parse|classif|dispatch|route|handl|instruction|opcode|program|message|"
    r"\bmsg\b|variant|kind|policy|permission|authoriz|access|command|action|"
    r"selector|decode|resolve|touched|account|fee|spend|payer|whitelist|allow",
    re.I)


def _classifier_context(scrutinee: str, fn_name: str) -> bool:
    return bool(_CTX_RE.search(scrutinee or "")) or bool(_CTX_RE.search(fn_name or ""))


# --- CORE PREDICATE (load-bearing; monkeypatched in the non-vacuity test) ----
def _default_arm_fails_open(default_disposition: str,
                            substantive_siblings: int) -> bool:
    """FIRE iff the DEFAULT arm constructs a permissive EMPTY stub while >=1
    enumerated arm is SUBSTANTIVE - the known variants produce content but the
    unknown variant produces emptiness the downstream policy reads as compliant
    (the kora-lib signature). A default that REJECTS or returns a real fallback,
    or a dispatch with no substantive sibling, never fires."""
    return default_disposition == "permissive_empty" and substantive_siblings >= 1


# --- offset <-> line --------------------------------------------------------
def _line_starts(text: str):
    starts = [0]
    for i, ch in enumerate(text):
        if ch == "\n":
            starts.append(i + 1)
    return starts


def _line_of(starts, offset):
    return bisect.bisect_right(starts, offset) - 1  # 0-indexed


def _lang_of(rel: str) -> str:
    return "go" if rel.lower().endswith(".go") else "rust"


def _stable_id(rel, fn, line, scrutinee):
    h = hashlib.sha1()
    h.update(f"{rel}|{fn}|{line}|{scrutinee}".encode())
    return h.hexdigest()[:16]


def _short(s: str, n: int = 80) -> str:
    s = " ".join((s or "").split())
    return s[:n]


# --- per-dispatch analysis --------------------------------------------------
def _analyze_dispatch(kind, scrutinee, default_disp, default_off, enumerated,
                      substantive, rel, lang, starts, fn_ranges):
    """Build a row for one dispatch, or None if it is not an enforcement point."""
    if default_disp is None:
        return None                    # no explicit default arm -> not this class
    if lang == "go" and not (scrutinee or "").strip():
        return None                    # conditionless `switch {}` is a guard-chain,
        #                                not an untrusted-variant classifier
    if enumerated < 2:
        return None                    # not a multi-way classifier
    if substantive < 1:
        return None                    # no substantive variant -> not a content classifier
    if default_disp == "substantive":
        return None                    # default itself is a real fallback (not fail-open)
    default_line = _line_of(starts, default_off)
    fn_name = _enclosing_fn(fn_ranges, default_line) or "<module>"
    ctx = _classifier_context(scrutinee, fn_name)
    fires = _default_arm_fails_open(default_disp, substantive)
    return _row(rel, fn_name, lang, kind, scrutinee, default_line, default_disp,
                enumerated, substantive, ctx, fires)


def _row(rel, fn_name, lang, kind, scrutinee, default_line, default_disp,
         enumerated, substantive, ctx, fires):
    if fires:
        q = (f"the `{kind}` on `{_short(scrutinee, 60)}` has {enumerated} enumerated "
             f"arms ({substantive} construct a non-empty value) but its DEFAULT / "
             f"catch-all arm (line {default_line + 1}) returns a PERMISSIVE EMPTY "
             f"stub - does an UNRECOGNISED variant get REJECTED, or does this empty "
             f"stub (empty set / zero / no-op / nil-no-error) reach a downstream "
             f"policy/fee/ACL check that reads it as COMPLIANT? Fuzz an unknown "
             f"variant end-to-end through the enforcer (kora-lib GHSA-x442-m7cc-hr92)."
             + ("" if lang != "solidity" else
                " (Solidity if/else-default equivalent - inspect manually.)"))
    elif default_disp == "reject":
        q = (f"enforcement point: the `{kind}` on `{_short(scrutinee, 60)}` REJECTS "
             f"the unrecognised variant in its default arm (line {default_line + 1}) - "
             f"sound (fails closed). Documented for completeness.")
    else:
        q = (f"enforcement point: `{kind}` default arm (line {default_line + 1}) "
             f"disposition={default_disp}; {substantive}/{enumerated} substantive "
             f"siblings. Documented for completeness.")
    return {
        "schema": HYP_SCHEMA,
        "capability": _CAPABILITY,
        "id": _stable_id(rel, fn_name, default_line, scrutinee),
        "file": rel,
        "line": default_line + 1,
        "function": fn_name,
        "lang": lang,
        "dispatch_kind": kind,
        "scrutinee": _short(scrutinee, 120),
        "default_arm_line": default_line + 1,
        "default_disposition": default_disp,
        "enumerated_arms": enumerated,
        "substantive_siblings": substantive,
        "has_substantive_sibling": substantive >= 1,
        "classifier_context": ctx,
        "severity_eligible": bool(fires and ctx),
        "fires": fires,
        "verdict": "needs-fuzz",
        "advisory": True,
        "auto_credit": False,
        "question": q,
    }


# --- dispatch discovery per language ----------------------------------------
_RUST_MATCH_RE = re.compile(r"(?<![\w.])match\b")
_GO_SWITCH_RE = re.compile(r"(?<![\w.])switch\b")


def _rust_dispatches(text):
    """Yield (scrutinee, default_disp, default_off, enumerated, substantive)."""
    for m in _RUST_MATCH_RE.finditer(text):
        kw_end = m.end()
        brace = _first_arm_brace(text, kw_end)
        if brace < 0:
            continue
        scrutinee = text[kw_end:brace].strip()
        close = _match_bracket(text, brace)
        if close < 0:
            continue
        inner = text[brace + 1:close]
        if "=>" not in inner:
            continue
        arms = _split_rust_arms(inner)
        if not arms:
            continue
        enumerated = 0
        substantive = 0
        default_disp = None
        default_off = None
        for pattern, body, body_off in arms:
            if _rust_arm_is_default(pattern):
                default_disp = _classify_rust_arm(body)
                default_off = brace + 1 + body_off
            else:
                enumerated += 1
                if _classify_rust_arm(body) == "substantive":
                    substantive += 1
        yield scrutinee, default_disp, default_off, enumerated, substantive


def _go_dispatches(text):
    for m in _GO_SWITCH_RE.finditer(text):
        kw_end = m.end()
        brace = _first_arm_brace(text, kw_end)
        if brace < 0:
            continue
        scrutinee = text[kw_end:brace].strip()
        close = _match_bracket(text, brace)
        if close < 0:
            continue
        inner = text[brace + 1:close]
        cases = _split_go_cases(inner)
        if not cases:
            continue
        enumerated = 0
        substantive = 0
        default_disp = None
        default_off = None
        for is_def, body, body_off in cases:
            if is_def:
                default_disp = _classify_go_case(body)
                default_off = brace + 1 + body_off
            else:
                enumerated += 1
                if _classify_go_case(body) == "substantive":
                    substantive += 1
        yield scrutinee, default_disp, default_off, enumerated, substantive


def scan_file(path: Path, rel: str, file_text: str = None):
    raw = file_text if file_text is not None else Path(path).read_text(
        encoding="utf-8", errors="ignore")
    text = _mask_comments(raw)
    lang = _lang_of(rel)
    starts = _line_starts(text)
    fn_ranges = _fn_ranges(text.split("\n"))
    rows = []
    gen = _rust_dispatches(text) if lang == "rust" else _go_dispatches(text)
    kind = "match" if lang == "rust" else "switch"
    for scrutinee, default_disp, default_off, enumerated, substantive in gen:
        row = _analyze_dispatch(kind, scrutinee, default_disp, default_off,
                                enumerated, substantive, rel, lang, starts, fn_ranges)
        if row is not None:
            rows.append(row)
    return rows


def scan_tree(root: Path):
    root = Path(root)
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
    sev = [r for r in fired if r.get("severity_eligible")]
    return {
        "schema": HYP_SCHEMA,
        "capability": _CAPABILITY,
        "enforcement_points": len(rows),
        "fired": len(fired),
        "severity_eligible": len(sev),
        "reject_defaults": sum(1 for r in rows if r.get("default_disposition") == "reject"),
        "permissive_defaults": sum(
            1 for r in rows if r.get("default_disposition") == "permissive_empty"),
        "rust_points": sum(1 for r in rows if r.get("lang") == "rust"),
        "go_points": sum(1 for r in rows if r.get("lang") == "go"),
        "verdict": "needs-fuzz" if fired else "clean-advisory",
        "advisory": True,
        "auto_credit": False,
    }


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="EXT2-03 fail-open classifier default-arm screen (advisory)")
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
        return 1 if (strict and any(r["severity_eligible"] for r in rows)) else 0

    if args.source:
        rows = scan_tree(Path(args.source))
        print(json.dumps(rows, indent=2))
        return 1 if (strict and any(r["severity_eligible"] for r in rows)) else 0

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
        return 1 if (strict and summ["severity_eligible"]) else 0

    src = ws / "src"
    root = src if src.exists() else ws
    rows = scan_tree(root)
    _emit_sidecar(ws, rows)
    summ = _summary(rows)
    print(json.dumps(summ, indent=2))
    return 1 if (strict and summ["severity_eligible"]) else 0


if __name__ == "__main__":
    sys.exit(main())
