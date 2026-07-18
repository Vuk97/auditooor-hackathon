#!/usr/bin/env python3
"""Generic, language-aware MUTATION ENGINE (Rule R80 / R81 substrate).

PRINCIPLE
---------
Coverage is only real if it is MUTATION-VERIFIED: inject ONE bug into a
function's body and the harness/PoC that claims to "cover" it MUST now FAIL.
If it passes both with and without the bug, the coverage is VACUOUS (hollow),
regardless of whether the proof is a Halmos property, an Echidna invariant, a
Foundry test, or an agent attack. This engine produces the mutants needed to
run that verification.

WHAT THIS TOOL IS
-----------------
Given a source FILE and a target FUNCTION (by file:line OR by name), this engine
emits N mutants. Each mutant is a copy of the source with EXACTLY ONE mutation
operator applied inside that function's body, plus a human-readable label and the
1-based line number that changed. The engine is the GENERATOR half; an external
runner (the harness re-run) is the ORACLE half that decides vacuity.

RELATED TOOLS (tool-dedup rule, codified 2026-05-28)
----------------------------------------------------
A `find tools/ -iname '*mutation*'` + grep of the honesty gates was run before
building this. The existing references are all CONSUMERS of a
mutation-verification *record*, not a mutant GENERATOR:

  - tools/finding-evidence-honesty-check.py (R80): `_has_mutation_record()` only
    DETECTS whether a `*mutation*.json{,l}` artifact or an in-draft
    "mutation-verified" marker EXISTS. It never produces mutants and cannot tell
    a real record from a fabricated one.
  - tools/audit-honesty-check.py (R80 whole-workspace): references the
    "mutation-verified non-vacuous harness" principle in prose; no generator.
  - tools/dispatch-agent-with-prebriefing.py: injects the
    "must be mutation-verified" mandate into worker briefs; no generator.
  - tools/evm-0day-proof-pipeline.py: locates vault mutation FUNCTIONS (i.e.
    state-mutating fns) for proof scoping; unrelated to mutation TESTING.

GAP THIS TOOL FILLS: there was no engine that mechanically APPLIES bug-injecting
mutations to a function body so the honesty gates can be backed by a real,
reproducible mutation-verification record instead of an asserted one. This tool
is that generator. Its JSON output is designed to seed the very
`*mutation*.json` artifact that R80's `_has_mutation_record()` looks for.

GENERICITY
----------
- ANY workspace via --workspace (zero workspace hardcoding; morpho appears only
  in tests / smoke anchors).
- Language-aware: Solidity is first-class. Rust / Go / Move / Cairo share the
  same operator CLASSES (relational, arithmetic, rounding, guard-removal,
  boundary, boolean, assignment); their per-language literal tables are
  extensible via env hooks (AUDITOOOR_MUTATION_OPS_<LANG>) without code changes.

MUTATION OPERATOR CLASSES (extensible)
--------------------------------------
  relational     <  -> <=,  >  -> >=,  == -> !=,  <= -> <,  >= -> >,  != -> ==
  arithmetic     +  -> -,   -  -> +,   *  -> /,   /  -> *
  rounding       mulDivUp <-> mulDivDown, ceilDiv <-> div, drop the "+ 1"/"+(d-1)"
  guard_removal  delete ONE require(...) / if (...) revert / assert(...) / ensure!
  boundary       numeric literal +/-1, and -> 0
  boolean        && <-> ||, negate a condition (wrap with !)
  assignment     += <-> -=, *= <-> /=

OUTPUT
------
JSON {schema, source_file, language, function, operator_classes, mutants:[...]}
where each mutant is:
  {mutant_id, operator, operator_class, file, line, label,
   original_line, mutated_line, mutated_source}  (full file text by default;
   omit the heavy `mutated_source` with --no-source to get patches only).

USAGE
-----
  mutation-engine.py <source_file> --function <name|file:line>
      [--workspace <ws>] [--language auto|solidity|rust|go|move|cairo]
      [--classes relational,arithmetic,...] [--max N] [--no-source]
      [--out <dir>] [--json]

Exit codes: 0 when >=1 mutant emitted; 3 when the function is found but no
operator applies (a legitimately un-mutatable body); 2 on error.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

SCHEMA = "auditooor.mutation_engine.v1"

# ---------------------------------------------------------------------------
# Language detection
# ---------------------------------------------------------------------------
_EXT_LANG = {
    ".sol": "solidity",
    ".rs": "rust",
    ".go": "go",
    ".move": "move",
    ".cairo": "cairo",
}


def detect_language(path: Path, override: str = "auto") -> str:
    if override and override != "auto":
        return override
    return _EXT_LANG.get(path.suffix.lower(), "solidity")


# ---------------------------------------------------------------------------
# Operator tables (extensible). Each entry: (regex, replacement, label_fmt).
# Regexes operate on a single source line. `replacement` may be a str or a
# callable(match)->str. `label_fmt` is a short human description.
#
# The tables below are deliberately conservative token-level rewrites so a
# mutant stays syntactically valid for the common case. Per-language extension
# happens via env AUDITOOOR_MUTATION_OPS_<LANG> = newline list of
#   class|pattern|replacement|label
# entries appended to the defaults.
# ---------------------------------------------------------------------------

# Word-ish boundaries that work across the supported C-family + Rust + Cairo.
def _op(pat: str, repl, label: str):
    return (re.compile(pat), repl, label)


# Relational operators (shared across all languages).
_RELATIONAL = [
    _op(r"(?<![<>=!])<=(?!=)", ">=", "relational: <= -> >="),
    _op(r"(?<![<>=!])>=(?!=)", "<=", "relational: >= -> <="),
    _op(r"(?<![<>=!])<(?![=<])", ">", "relational: < -> >"),
    _op(r"(?<![<>=!])>(?![=>])", "<", "relational: > -> <"),
    _op(r"==", "!=", "relational: == -> !="),
    _op(r"!=", "==", "relational: != -> =="),
]

# Arithmetic operators. Multiplication/division are token-guarded to avoid
# matching pointer derefs / comment markers; we only mutate when surrounded by
# word/paren/space on both sides.
_ARITHMETIC = [
    _op(r"(?<=[\w\)\]])\s*\+\s*(?=[\w\(])", " - ", "arithmetic: + -> -"),
    _op(r"(?<=[\w\)\]])\s*-\s*(?=[\w\(])", " + ", "arithmetic: - -> +"),
    _op(r"(?<=[\w\)\]])\s*\*\s*(?=[\w\(])", " / ", "arithmetic: * -> /"),
    _op(r"(?<=[\w\)\]])\s*/\s*(?=[\w\(])", " * ", "arithmetic: / -> *"),
]

# Boolean / logical.
_BOOLEAN = [
    _op(r"&&", "||", "boolean: && -> ||"),
    _op(r"\|\|", "&&", "boolean: || -> &&"),
]

# Assignment compound operators.
_ASSIGNMENT = [
    _op(r"\+=", "-=", "assignment: += -> -="),
    _op(r"-=", "+=", "assignment: -= -> +="),
    _op(r"\*=", "/=", "assignment: *= -> /="),
    _op(r"/=", "*=", "assignment: /= -> *="),
]

# Rounding (Solidity-flavored names, plus generic ceil/floor). Rust/Move/Cairo
# names extend via env.
_ROUNDING = [
    _op(r"\bmulDivUp\b", "mulDivDown", "rounding: mulDivUp -> mulDivDown"),
    _op(r"\bmulDivDown\b", "mulDivUp", "rounding: mulDivDown -> mulDivUp"),
    _op(r"\bdivUp\b", "divDown", "rounding: divUp -> divDown"),
    _op(r"\bdivDown\b", "divUp", "rounding: divDown -> divUp"),
    _op(r"\bceilDiv\b", "div", "rounding: ceilDiv -> div"),
    # Drop the "+ 1" / "+ (d - 1)" round-up bias.
    _op(r"\+\s*1\b(?=\s*\))", "+ 0", "rounding: drop +1 round-up bias"),
    _op(r"\+\s*\(\s*d\s*-\s*1\s*\)", "+ 0", "rounding: drop +(d-1) round-up bias"),
]

# Guard removal: comment out ONE require / revert-if / assert / ensure! line.
# Handled specially (whole-line operation), not via inline regex replace.
_GUARD_PATTERNS = {
    "solidity": [
        re.compile(r"^\s*require\s*\("),
        re.compile(r"^\s*assert\s*\("),
        re.compile(r"^\s*if\s*\(.*\)\s*revert\b"),
        re.compile(r"^\s*revert\b"),
        re.compile(r"^\s*_check\w*\s*\("),
    ],
    "rust": [
        re.compile(r"^\s*assert!?\s*\("),
        re.compile(r"^\s*ensure!\s*\("),
        re.compile(r"^\s*require!\s*\("),
        re.compile(r"^\s*debug_assert!?\s*\("),
    ],
    "go": [
        re.compile(r"^\s*if\s+.*\{\s*$"),  # conservative: guard-ish if
        re.compile(r"^\s*panic\s*\("),
    ],
    "move": [
        re.compile(r"^\s*assert!\s*\("),
        re.compile(r"^\s*abort\b"),
    ],
    "cairo": [
        re.compile(r"^\s*assert\s*\("),
        re.compile(r"^\s*assert!\s*\("),
    ],
}

_LINE_COMMENT = {
    "solidity": "//",
    "rust": "//",
    "go": "//",
    "move": "//",
    "cairo": "//",
}

# Boundary: numeric literal +/- 1, and literal -> 0. Applied inline.
_BOUNDARY_LITERAL = re.compile(r"(?<![\w.])(\d+)(?![\w.])")

_CLASS_TABLES = {
    "relational": _RELATIONAL,
    "arithmetic": _ARITHMETIC,
    "boolean": _BOOLEAN,
    "assignment": _ASSIGNMENT,
    "rounding": _ROUNDING,
}

ALL_CLASSES = ["relational", "arithmetic", "rounding", "guard_removal",
               "boundary", "boolean", "assignment", "value_mutation"]


def _env_extra_ops(language: str) -> dict:
    """Per-language operator extension via env.

    AUDITOOOR_MUTATION_OPS_<LANG> = newline-separated `class|pattern|replacement|label`.
    """
    key = f"AUDITOOOR_MUTATION_OPS_{language.upper()}"
    raw = os.environ.get(key, "")
    extra: dict = {}
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("|", 3)
        if len(parts) != 4:
            continue
        cls, pat, repl, label = parts
        try:
            extra.setdefault(cls, []).append(_op(pat, repl, label))
        except re.error:
            continue
    return extra


# ---------------------------------------------------------------------------
# Function-body extraction
# ---------------------------------------------------------------------------
_FUNC_DECL = {
    # language -> regex with a `name` group on the declaration line.
    "solidity": re.compile(r"\bfunction\s+(?P<name>\w+)\s*\("),
    "rust": re.compile(r"\bfn\s+(?P<name>\w+)\s*[\(<]"),
    "go": re.compile(r"\bfunc\s+(?:\([^)]*\)\s*)?(?P<name>\w+)\s*\("),
    "move": re.compile(r"\bfun\s+(?P<name>\w+)\s*[\(<]"),
    "cairo": re.compile(r"\bfn\s+(?P<name>\w+)\s*[\(<]"),
}


def _find_function_span(lines: list[str], language: str, *,
                        name: str | None, line_hint: int | None) -> tuple[int, int, str]:
    """Return (start_idx, end_idx, fn_name) 0-based inclusive body span.

    Span runs from the declaration line through the matching closing brace
    (brace-balanced). Works for C-family + Rust + Cairo + Move (all brace-bodied).
    line_hint is a 1-based line guaranteed to be inside/at the function.
    """
    decl_re = _FUNC_DECL.get(language, _FUNC_DECL["solidity"])

    decl_idx = None
    fn_name = name or ""
    if line_hint is not None:
        # Walk upward from the hint to the nearest declaration line.
        for i in range(min(line_hint - 1, len(lines) - 1), -1, -1):
            m = decl_re.search(lines[i])
            if m:
                decl_idx = i
                fn_name = m.group("name")
                break
    elif name is not None:
        for i, ln in enumerate(lines):
            m = decl_re.search(ln)
            if m and m.group("name") == name:
                decl_idx = i
                fn_name = name
                break

    if decl_idx is None:
        raise LookupError("function not found")

    # Find the opening brace (may be on a later line for multi-line signatures).
    brace_idx = None
    for i in range(decl_idx, len(lines)):
        if "{" in lines[i]:
            brace_idx = i
            break
    if brace_idx is None:
        # bodyless (interface / abstract) — span is just the decl line.
        return decl_idx, decl_idx, fn_name

    depth = 0
    end_idx = brace_idx
    for i in range(brace_idx, len(lines)):
        for ch in lines[i]:
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    end_idx = i
                    break
        if depth == 0:
            break
    return decl_idx, end_idx, fn_name


# ---------------------------------------------------------------------------
# Mutation application
# ---------------------------------------------------------------------------
def _apply_inline(lines: list[str], body_start: int, body_end: int,
                  table) -> list[tuple[int, str, str, str]]:
    """Apply each inline operator to the FIRST eligible occurrence per line.

    Returns list of (line_idx, original_line, mutated_line, label).
    Only the first match on a line is mutated, yielding one mutant per
    (line, operator) so each mutant carries exactly one change.
    """
    out = []
    for idx in range(body_start, body_end + 1):
        original = lines[idx]
        for regex, repl, label in table:
            m = regex.search(original)
            if not m:
                continue
            mutated = original[:m.start()] + (repl if isinstance(repl, str)
                                              else repl(m)) + original[m.end():]
            if mutated != original:
                out.append((idx, original, mutated, label))
    return out


def _apply_boundary(lines: list[str], body_start: int, body_end: int):
    out = []
    for idx in range(body_start, body_end + 1):
        original = lines[idx]
        m = _BOUNDARY_LITERAL.search(original)
        if not m:
            continue
        val = int(m.group(1))
        # literal -> literal+1
        plus = original[:m.start()] + str(val + 1) + original[m.end():]
        if plus != original:
            out.append((idx, original, plus, f"boundary: {val} -> {val + 1}"))
        # literal -> 0 (only if not already 0)
        if val != 0:
            zero = original[:m.start()] + "0" + original[m.end():]
            out.append((idx, original, zero, f"boundary: {val} -> 0"))
    return out


def _apply_guard_removal(lines: list[str], body_start: int, body_end: int,
                         language: str):
    out = []
    pats = _GUARD_PATTERNS.get(language, _GUARD_PATTERNS["solidity"])
    comment = _LINE_COMMENT.get(language, "//")
    for idx in range(body_start, body_end + 1):
        original = lines[idx]
        for pat in pats:
            if pat.search(original):
                # Comment out the guard line (preserve indentation).
                indent = original[:len(original) - len(original.lstrip())]
                mutated = f"{indent}{comment} MUTANT-GUARD-REMOVED: {original.strip()}"
                out.append((idx, original, mutated, "guard_removal: disable one guard"))
                break
    return out


# value_mutation (Solidity): single-statement ECONOMIC functions (balance sweeps,
# fee getters/quoters) have NO relational/arithmetic operator, so the other
# classes produce 0 mutants - a `no-mutants` verdict that left genuine economic
# invariants unverifiable. These operators add the missing behaviour-changing
# mutants, type-safely:
#   (a) value-send weaken: `.sendValue(X)` / `.transfer(X)` / `{value: X}` -> halve
#       the amount (always uint -> uint, compiles). A conservation invariant kills it.
#   (b) numeric-return zeroing: `return <expr>;` -> `return 0;` ONLY when the
#       function signature declares a numeric return (uint/int), so the mutant
#       always compiles (no false compile-fail kill). A "quote == fee" invariant
#       kills it.
_VALUE_SEND_RE = re.compile(
    r"\.(sendValue|transfer)\(\s*(.+?)\s*\)\s*;")
_VALUE_BRACE_RE = re.compile(
    r"\{\s*value\s*:\s*([^},]+)\}")
_RETURN_RE = re.compile(r"^(\s*return\s+)(.+?)\s*;\s*$")
_NUMERIC_RETURN_RE = re.compile(r"returns\s*\(\s*(?:uint|int)\d*\b")


def _fn_returns_numeric(lines: list[str], decl_idx: int, body_start: int) -> bool:
    hi = max(decl_idx, min(body_start, len(lines) - 1))
    header = " ".join(lines[decl_idx:hi + 1]).split("{", 1)[0]
    return bool(_NUMERIC_RETURN_RE.search(header))


def _apply_value_mutation(lines: list[str], decl_idx: int, body_end: int,
                          language: str):
    if language != "solidity":
        return []
    # locate the body-open brace so the signature (which may span multiple lines,
    # carrying `returns (uint256)`) is read in full for the numeric-return check.
    brace_idx = decl_idx
    for i in range(decl_idx, min(body_end + 1, len(lines))):
        if "{" in lines[i]:
            brace_idx = i
            break
    out = []
    numeric_ret = _fn_returns_numeric(lines, decl_idx, brace_idx)
    for idx in range(decl_idx, body_end + 1):
        original = lines[idx]
        # (a) value-send weaken
        m = _VALUE_SEND_RE.search(original)
        if m:
            arg = m.group(2)
            mutated = (original[:m.start()]
                       + f".{m.group(1)}(({arg}) / 2);"
                       + original[m.end():])
            if mutated != original:
                out.append((idx, original, mutated, "value_mutation: halve value-send amount"))
        mb = _VALUE_BRACE_RE.search(original)
        if mb:
            mutated = (original[:mb.start()] + "{value: (" + mb.group(1).strip() + ") / 2}"
                       + original[mb.end():])
            if mutated != original:
                out.append((idx, original, mutated, "value_mutation: halve {value:} amount"))
        # (b) numeric-return zeroing (only when the function returns a number)
        if numeric_ret:
            mr = _RETURN_RE.match(original)
            if mr and mr.group(2).strip() not in ("0", "0;"):
                mutated = f"{mr.group(1)}0;"
                if mutated != original:
                    out.append((idx, original, mutated, "value_mutation: return 0"))
    return out


def generate_mutants(source: str, language: str, *, name: str | None,
                     line_hint: int | None, classes: list[str],
                     max_mutants: int | None) -> tuple[list[dict], str, tuple[int, int]]:
    lines = source.splitlines(keepends=False)
    decl_idx, end_idx, fn_name = _find_function_span(
        lines, language, name=name, line_hint=line_hint)

    extra = _env_extra_ops(language)
    raw: list[tuple[int, str, str, str, str]] = []  # (idx, orig, mut, label, class)

    for cls in classes:
        if cls == "guard_removal":
            for t in _apply_guard_removal(lines, decl_idx, end_idx, language):
                raw.append((*t, "guard_removal"))
        elif cls == "boundary":
            for t in _apply_boundary(lines, decl_idx, end_idx):
                raw.append((*t, "boundary"))
        elif cls == "value_mutation":
            for t in _apply_value_mutation(lines, decl_idx, end_idx, language):
                raw.append((*t, "value_mutation"))
        else:
            table = list(_CLASS_TABLES.get(cls, []))
            table += extra.get(cls, [])
            for t in _apply_inline(lines, decl_idx, end_idx, table):
                raw.append((*t, cls))

    # De-dup identical (line, mutated_line) pairs; stable order.
    seen = set()
    mutants: list[dict] = []
    for idx, orig, mut, label, cls in raw:
        key = (idx, mut)
        if key in seen:
            continue
        seen.add(key)
        new_lines = lines.copy()
        new_lines[idx] = mut
        mutants.append({
            "mutant_id": f"{fn_name}__m{len(mutants):03d}",
            "operator": label,
            "operator_class": cls,
            "line": idx + 1,
            "label": f"{fn_name}:{idx + 1} {label}",
            "original_line": orig,
            "mutated_line": mut,
            "_mutated_source": "\n".join(new_lines) + ("\n" if source.endswith("\n") else ""),
        })
        if max_mutants and len(mutants) >= max_mutants:
            break

    return mutants, fn_name, (decl_idx + 1, end_idx + 1)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def _parse_function_arg(arg: str) -> tuple[str | None, int | None]:
    """`--function` may be a name, a `file:line`, or a bare `:line` / `line`."""
    if ":" in arg:
        _, _, tail = arg.rpartition(":")
        if tail.isdigit():
            return None, int(tail)
    if arg.isdigit():
        return None, int(arg)
    return arg, None


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Generic language-aware mutation engine (R80/R81).")
    ap.add_argument("source_file")
    ap.add_argument("--function", required=True,
                    help="target function: name, file:line, or bare line number")
    ap.add_argument("--workspace", default=None, help="workspace root (generic; any ws)")
    ap.add_argument("--language", default="auto",
                    choices=["auto", "solidity", "rust", "go", "move", "cairo"])
    ap.add_argument("--classes", default=",".join(ALL_CLASSES),
                    help="comma-separated operator classes")
    ap.add_argument("--max", type=int, default=None, help="cap number of mutants")
    ap.add_argument("--no-source", action="store_true",
                    help="omit full mutated_source (emit patch metadata only)")
    ap.add_argument("--out", default=None,
                    help="dir to write each mutant source as a file + a manifest.json")
    ap.add_argument("--json", action="store_true", help="emit JSON to stdout")
    args = ap.parse_args(argv)

    src_path = Path(args.source_file)
    if not src_path.is_file():
        print(json.dumps({"schema": SCHEMA, "error": f"source not found: {src_path}"}))
        return 2

    try:
        source = src_path.read_text(encoding="utf-8")
    except Exception as e:  # noqa: BLE001
        print(json.dumps({"schema": SCHEMA, "error": f"read failed: {e}"}))
        return 2

    language = detect_language(src_path, args.language)
    name, line_hint = _parse_function_arg(args.function)
    classes = [c.strip() for c in args.classes.split(",") if c.strip()]

    try:
        mutants, fn_name, span = generate_mutants(
            source, language, name=name, line_hint=line_hint,
            classes=classes, max_mutants=args.max)
    except LookupError:
        print(json.dumps({"schema": SCHEMA,
                          "error": f"function not found: {args.function}"}))
        return 2

    out_files = []
    if args.out:
        out_dir = Path(args.out)
        out_dir.mkdir(parents=True, exist_ok=True)
        for mut in mutants:
            fp = out_dir / f"{mut['mutant_id']}{src_path.suffix}"
            fp.write_text(mut["_mutated_source"], encoding="utf-8")
            out_files.append(str(fp))

    payload_mutants = []
    for mut in mutants:
        m = dict(mut)
        if args.no_source:
            m.pop("_mutated_source", None)
        else:
            m["mutated_source"] = m.pop("_mutated_source")
        payload_mutants.append(m)

    payload = {
        "schema": SCHEMA,
        "source_file": str(src_path),
        "workspace": args.workspace,
        "language": language,
        "function": fn_name,
        "function_span": {"start_line": span[0], "end_line": span[1]},
        "operator_classes": classes,
        "mutant_count": len(payload_mutants),
        "mutants": payload_mutants,
        "out_files": out_files,
    }

    if args.out:
        (Path(args.out) / "manifest.json").write_text(
            json.dumps({**payload, "mutants": [
                {k: v for k, v in m.items() if k != "mutated_source"}
                for m in payload_mutants]}, indent=2),
            encoding="utf-8")

    if args.json or not args.out:
        # Default to JSON on stdout (drop heavy source unless explicitly kept).
        out = dict(payload)
        if not args.json:
            out["mutants"] = [{k: v for k, v in m.items() if k != "mutated_source"}
                              for m in payload_mutants]
        print(json.dumps(out, indent=2))

    if not mutants:
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
