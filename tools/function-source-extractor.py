#!/usr/bin/env python3
# <!-- r36-rebuttal: lane FIX-BODY-PACK-EXTRACTOR registered via agent-pathspec-register.py -->
"""Language-agnostic function-BODY extractor for body-carrying hunt packs.

WHY: pre_flight_packs carry corpus intel + a source POINTER but NO function body, so a
pack-fed hunt must either read the whole file (token-heavy) or hallucinate (measured: pack-only
= 5/10 false-positive HIGHs, optimism 2026-06-16). This extracts the REAL function body
mechanically so a pack becomes a token-efficient AND quality-preserving source substitute.

GENERIC across Solidity / Go / Rust (all are `{ ... }`-bodied): from the declaration line,
find the opening brace and balance to its match (cap-bounded). An abstract/interface decl that
ends in `;` before any `{` yields just the signature. No language parser, no LLM - works for any
workspace + any brace-delimited language.

CLI:
  python3 tools/function-source-extractor.py --workspace <ws> [--out <jsonl>] [--max-lines N]
Reads the authoritative per-function list (.auditooor/function_coverage_completeness.json if
present, else nothing) and emits one {file, fn, lang, line, end_line, body} row per function.
Exit 0 ok; 2 usage / no function list.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_MAX_LINES_DEFAULT = 400  # hard cap so a brace-miscount (string/comment) cannot run away


def extract_body(lines: list, decl_line_1based: int, max_lines: int = _MAX_LINES_DEFAULT) -> tuple:
    """Return (body_text, end_line_1based). lines is the 0-based file line list.
    Balances braces from the declaration line; falls back to the single signature line for
    a `;`-terminated (abstract/interface/no-body) declaration."""
    i = decl_line_1based - 1
    if i < 0 or i >= len(lines):
        return "", decl_line_1based
    out = []
    depth = 0
    started = False
    j = i
    end = decl_line_1based
    while j < len(lines) and (j - i) < max_lines:
        ln = lines[j]
        out.append(ln)
        end = j + 1
        for ch in ln:
            if ch == "{":
                depth += 1
                started = True
            elif ch == "}":
                depth -= 1
        if started and depth <= 0:
            break
        if not started and ln.rstrip().endswith(";"):
            break  # abstract / interface / no-body decl
        j += 1
    return "\n".join(out), end


import re as _re
_IDENT = _re.compile(r"\b([A-Za-z_][A-Za-z0-9_]{2,})\b")
# A same-file DEFINITION of a referenced symbol (guard/modifier/callee) - all brace-bodied langs.
_DEF_PAT = "(?:function|modifier|func|fn)\\s+{name}\\b"


_MAX_CROSS_FILE_DEPS = 6    # cap on additional deps resolved from sibling files
_MAX_TOTAL_LINES_EXT = 200  # additional lines budget for sibling-file deps


def _sibling_source_files(p: Path, ws: Path) -> list:
    """Return sibling source files in the same directory, bounded to the workspace.
    Only .sol / .go / .rs files; excludes the file itself; does NOT recurse."""
    d = p.parent
    # Safety: never leave the workspace tree
    try:
        d.relative_to(ws)
    except ValueError:
        return []
    exts = {".sol", ".go", ".rs"}
    siblings = []
    try:
        for sib in sorted(d.iterdir()):
            if sib == p:
                continue
            if sib.suffix in exts and sib.is_file():
                siblings.append(sib)
    except OSError:
        pass
    return siblings


def extract_self_contained(ws: Path, rel_or_abs_file: str, line: int,
                           max_lines: int = _MAX_LINES_DEFAULT, max_deps: int = 12,
                           max_total_lines: int = 320):
    """Return (text, end_line, dep_count): the target body PLUS the bodies of referenced SAME-FILE
    definitions (the guards/modifiers/callees the agent would otherwise have to Read for), and
    ALSO any still-unresolved names found in SAME-DIRECTORY sibling source files (bounded).

    Same-file phase (existing): resolves guards/modifiers/callees within the primary file.
    Sibling-scan phase (new): for identifiers NOT resolved in-file, scans sibling files in the
    same directory (same package for Go, sibling modules for Rust, same dir for Solidity).
    Uses the same _DEF_PAT regex + extract_body brace-matcher - no language-specific parsing.

    STRICT BOUNDS:
    - Same-directory only; no recursion beyond one level.
    - Cross-file deps capped at _MAX_CROSS_FILE_DEPS (6) additional entries.
    - Total additional lines from sibling scan capped at _MAX_TOTAL_LINES_EXT (200).
    - Never reads outside the workspace root.
    - Deduplicates: a name already resolved in-file is skipped in sibling scan.

    This makes the pack SELF-CONTAINED so a hunt agent needs no file read - capturing the
    ~10-15x token win without the bare-body over-flagging (it can see the guards inline).
    """
    p = Path(rel_or_abs_file)
    if not p.is_absolute():
        p = ws / rel_or_abs_file
    if not p.is_file():
        return "", line, 0
    try:
        lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return "", line, 0
    body, end = extract_body(lines, line, max_lines)
    if not body.strip():
        return "", line, 0
    # identifiers referenced in the body
    names = []
    seen_n = set()
    for m in _IDENT.finditer(body):
        n = m.group(1)
        if n in seen_n:
            continue
        seen_n.add(n)
        names.append(n)
    target_start = line  # do not re-embed the target itself
    deps = []
    resolved_names: set = set()  # names resolved in-file (skip in sibling scan)
    total = len(body.splitlines())

    # --- Phase 1: same-file resolution (original behaviour) ---
    for n in names:
        if len(deps) >= max_deps or total >= max_total_lines:
            break
        pat = _re.compile(_DEF_PAT.format(name=_re.escape(n)))
        for j, ln in enumerate(lines):
            if j + 1 == target_start:
                continue  # skip the target's own decl line
            if pat.search(ln):
                dbody, _de = extract_body(lines, j + 1, 120)
                if dbody.strip() and dbody != body:
                    deps.append(f"// [{n}] (same-file def, {p.name}:{j+1})\n{dbody}")
                    resolved_names.add(n)
                    total += len(dbody.splitlines())
                break

    # --- Phase 2: bounded same-directory sibling scan ---
    sibling_budget_lines = total + _MAX_TOTAL_LINES_EXT
    cross_file_count = 0
    unresolved = [n for n in names if n not in resolved_names]

    if unresolved and cross_file_count < _MAX_CROSS_FILE_DEPS:
        sibling_files = _sibling_source_files(p, ws)
        # Pre-build compiled patterns for unresolved names only
        unresolved_pats = {}
        for n in unresolved:
            unresolved_pats[n] = _re.compile(_DEF_PAT.format(name=_re.escape(n)))

        for sib in sibling_files:
            if cross_file_count >= _MAX_CROSS_FILE_DEPS or total >= sibling_budget_lines:
                break
            try:
                sib_lines = sib.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue
            for n, pat in list(unresolved_pats.items()):
                if cross_file_count >= _MAX_CROSS_FILE_DEPS or total >= sibling_budget_lines:
                    break
                for j, ln in enumerate(sib_lines):
                    if pat.search(ln):
                        dbody, _de = extract_body(sib_lines, j + 1, 120)
                        if dbody.strip():
                            deps.append(
                                f"// [{n}] (sibling-file def, {sib.name}:{j+1})\n{dbody}"
                            )
                            resolved_names.add(n)
                            del unresolved_pats[n]  # resolved - don't search again
                            total += len(dbody.splitlines())
                            cross_file_count += 1
                        break

    text = body
    if deps:
        text += "\n\n// ===== referenced same-file definitions (guards/callees/modifiers) =====\n" + "\n\n".join(deps)
    return text, end, len(deps)


def _load_function_list(ws: Path) -> list:
    """Authoritative per-function list (name/file/line/lang) from the coverage artifact."""
    cov = ws / ".auditooor" / "function_coverage_completeness.json"
    if not cov.is_file():
        return []
    try:
        d = json.loads(cov.read_text(encoding="utf-8", errors="replace"))
    except (json.JSONDecodeError, ValueError):
        return []
    return [f for f in (d.get("functions") or []) if f.get("file") and f.get("line")]


def extract_for_function(ws: Path, rel_or_abs_file: str, line: int, max_lines: int = _MAX_LINES_DEFAULT):
    """Public helper for callers (e.g. the hunt-batch builder): returns (body, end_line) or ('',line)."""
    p = Path(rel_or_abs_file)
    if not p.is_absolute():
        p = ws / rel_or_abs_file
    if not p.is_file():
        return "", line
    try:
        lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return "", line
    return extract_body(lines, line, max_lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Language-agnostic function-body extractor")
    ap.add_argument("--workspace", "--ws", required=True)
    ap.add_argument("--out", default=None)
    ap.add_argument("--max-lines", type=int, default=_MAX_LINES_DEFAULT)
    args = ap.parse_args(argv)
    ws = Path(args.workspace).expanduser().resolve()
    if not ws.is_dir():
        print(f"[fn-source-extractor] ERR workspace not found: {ws}", file=sys.stderr)
        return 2
    fns = _load_function_list(ws)
    if not fns:
        print("[fn-source-extractor] ERR no function list (.auditooor/function_coverage_completeness.json)", file=sys.stderr)
        return 2
    out = Path(args.out) if args.out else ws / ".auditooor" / "function_source_extracts.jsonl"
    rows = []
    empty = 0
    for f in fns:
        body, end = extract_for_function(ws, f["file"], int(f["line"]), args.max_lines)
        if not body.strip():
            empty += 1
        rows.append({"file": f["file"], "fn": f.get("name"), "lang": f.get("lang"),
                     "line": f["line"], "end_line": end, "body": body})
    out.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    print(f"[fn-source-extractor] extracted {len(rows)} function bodies ({empty} empty) -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
