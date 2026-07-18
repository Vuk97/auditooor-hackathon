#!/usr/bin/env python3
"""
detector-dedupe.py — flag semantically-similar Rust detectors (Phase 13, PR #84).

Companion to tools/pattern-dedupe.py (which dedupes YAML DSL patterns).
This tool targets the Rust-side detectors under detectors/rust_wave1/r94_loop_*.py
and uses Jaccard overlap on a token "anchor signature" extracted from each file:

    - identifier tokens from the source of every regex literal (re.compile(r"..."))
    - identifier tokens from the fn-name regex (the _FN_NAME_RE alternation)
    - words from the docstring's "Class:" line (when present)
    - words from the message= string in hits.append(...)

Pairs whose Jaccard >= --threshold are reported with a verdict suggestion.
This tool is a PROPOSAL GENERATOR — it never modifies detector files.

Usage:
    python3 tools/detector-dedupe.py                  # threshold 70%, write report
    python3 tools/detector-dedupe.py --threshold 80   # stricter
    python3 tools/detector-dedupe.py --min-shared 5   # require >=5 shared tokens
    python3 tools/detector-dedupe.py --stdout         # print, do not write file
"""

from __future__ import annotations

import argparse
import ast
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DET_DIR = ROOT / "detectors" / "rust_wave1"
REPORT = ROOT / "docs" / "DETECTOR_DEDUPE_REPORT.md"

# Identifier-ish tokens. We deliberately keep snake_case / camelCase fragments
# whole (so `execute_from_executor` is one token, not three) — the regex literals
# in these detectors are already function-name alternations, and splitting them
# would explode false-positive pair scores.
_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{2,}")

# Stop-words that appear in nearly every detector message and would inflate
# Jaccard without carrying signal.
_STOP = {
    "the", "and", "for", "via", "with", "from", "into", "onto", "this", "that",
    "fn", "pub", "self", "let", "mut", "ref", "use", "mod", "pub_fn",
    "see", "solodit", "class", "rust_only", "both", "rust", "source",
    "flags", "detector", "fires", "without", "missing", "before", "after",
    "when", "where", "which", "what", "than", "then", "also", "still",
    "must", "may", "can", "not", "but", "any", "all", "one", "two",
    "function", "functions", "contract", "method", "value", "values",
    "true", "false", "none", "some", "ok", "err", "result", "option",
    "string", "str", "bool", "u8", "u16", "u32", "u64", "i8", "i16", "i32", "i64",
    "usize", "isize", "vec", "box", "rc", "arc", "cell", "mutex",
    "msg", "message", "severity", "high", "medium", "low", "info", "critical",
    "snippet", "line", "col", "hits", "append", "return", "continue",
    "import", "from", "future", "annotations",
}


def _tokens(text: str) -> set[str]:
    return {t.lower() for t in _IDENT_RE.findall(text) if t.lower() not in _STOP}


def _docstring(mod: ast.Module) -> str:
    if (mod.body and isinstance(mod.body[0], ast.Expr)
            and isinstance(mod.body[0].value, ast.Constant)
            and isinstance(mod.body[0].value.value, str)):
        return mod.body[0].value.value
    return ""


def _class_line(doc: str) -> str:
    for ln in doc.splitlines():
        s = ln.strip()
        if s.lower().startswith("class:"):
            return s.split(":", 1)[1].strip()
    return ""


def extract_anchor(path: Path) -> dict:
    """Pull the anchor signature out of one detector file."""
    src = path.read_text(encoding="utf-8", errors="replace")
    try:
        mod = ast.parse(src, filename=str(path))
    except SyntaxError:
        return {"slug": path.stem, "tokens": set(), "regex_count": 0,
                "fn_regex": "", "klass": "", "error": "syntax"}

    doc = _docstring(mod)
    klass = _class_line(doc)

    regex_sources: list[str] = []
    fn_name_regex = ""
    msg_strings: list[str] = []

    # Walk module: re.compile(r"...") at module level + hits.append({...message=...})
    # inside any function body.
    def walk(node: ast.AST):
        for child in ast.walk(node):
            # re.compile("...") / re.compile(r"...")
            if (isinstance(child, ast.Call)
                    and isinstance(child.func, ast.Attribute)
                    and child.func.attr == "compile"
                    and isinstance(child.func.value, ast.Name)
                    and child.func.value.id == "re"
                    and child.args
                    and isinstance(child.args[0], ast.Constant)
                    and isinstance(child.args[0].value, str)):
                regex_sources.append(child.args[0].value)
            # f-string / plain-string message kwarg in hits.append({"message": ...})
            if (isinstance(child, ast.Dict)):
                for k, v in zip(child.keys, child.values):
                    if (isinstance(k, ast.Constant)
                            and k.value == "message"):
                        if isinstance(v, ast.Constant) and isinstance(v.value, str):
                            msg_strings.append(v.value)
                        elif isinstance(v, ast.JoinedStr):
                            for piece in v.values:
                                if (isinstance(piece, ast.Constant)
                                        and isinstance(piece.value, str)):
                                    msg_strings.append(piece.value)

    walk(mod)

    # The fn-name regex is conventionally bound to a name ending in _FN_NAME_RE
    # or just FN_NAME_RE; pick the source whose enclosing assignment matches.
    for node in ast.walk(mod):
        if isinstance(node, ast.Assign):
            for tgt in node.targets:
                if (isinstance(tgt, ast.Name)
                        and tgt.id.upper().endswith("FN_NAME_RE")
                        and isinstance(node.value, ast.Call)
                        and node.value.args
                        and isinstance(node.value.args[0], ast.Constant)
                        and isinstance(node.value.args[0].value, str)):
                    fn_name_regex = node.value.args[0].value

    tokens: set[str] = set()
    for r in regex_sources:
        tokens |= _tokens(r)
    tokens |= _tokens(fn_name_regex)
    tokens |= _tokens(klass)
    for m in msg_strings:
        tokens |= _tokens(m)

    return {
        "slug": path.stem,
        "tokens": tokens,
        "regex_count": len(regex_sources),
        "fn_regex": fn_name_regex,
        "klass": klass,
    }


def jaccard(a: set[str], b: set[str]) -> float:
    if not a and not b:
        return 0.0
    inter = a & b
    union = a | b
    return len(inter) / len(union) if union else 0.0


def verdict(score: float) -> str:
    if score >= 0.90:
        return "true duplicate"
    if score >= 0.80:
        return "consider merging"
    return "review"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--threshold", type=float, default=70.0,
                    help="Jaccard threshold in percent (default 70).")
    ap.add_argument("--min-shared", type=int, default=3,
                    help="Require at least N shared tokens to flag (default 3).")
    ap.add_argument("--stdout", action="store_true",
                    help="Print report to stdout instead of writing the file.")
    ap.add_argument("--glob", default="r94_loop_*.py",
                    help="Glob under detectors/rust_wave1/ (default r94_loop_*.py).")
    args = ap.parse_args()

    thresh = args.threshold / 100.0 if args.threshold > 1 else args.threshold

    files = sorted(DET_DIR.glob(args.glob))
    if not files:
        print(f"[detector-dedupe] no files matched {args.glob} in {DET_DIR}",
              file=sys.stderr)
        return 1

    anchors = [extract_anchor(f) for f in files]
    anchors = [a for a in anchors if a["tokens"]]  # drop empty ones

    pairs = []
    for i in range(len(anchors)):
        for j in range(i + 1, len(anchors)):
            ti, tj = anchors[i]["tokens"], anchors[j]["tokens"]
            shared = ti & tj
            if len(shared) < args.min_shared:
                continue
            score = jaccard(ti, tj)
            if score >= thresh:
                pairs.append((score, anchors[i]["slug"], anchors[j]["slug"],
                              len(shared), len(ti | tj)))
    pairs.sort(reverse=True)

    lines = []
    lines.append("# Detector dedupe report")
    lines.append("")
    lines.append(f"- Detectors scanned: **{len(anchors)}** "
                 f"(glob `{args.glob}` under `detectors/rust_wave1/`)")
    lines.append(f"- Threshold: **{thresh * 100:.0f}%** Jaccard "
                 f"(over fn-name + regex + message tokens)")
    lines.append(f"- Min shared tokens: **{args.min_shared}**")
    lines.append(f"- Candidate dupe pairs: **{len(pairs)}**")
    lines.append("")
    lines.append("Generated by `tools/detector-dedupe.py` — proposal only, "
                 "no detector files are modified.")
    lines.append("")
    lines.append("## Verdict legend")
    lines.append("")
    lines.append("- **true duplicate** — Jaccard >= 90%; almost certainly the same detector.")
    lines.append("- **consider merging** — 80-90%; large semantic overlap, audit before merging.")
    lines.append("- **review** — 70-80%; shared vocabulary, may be intentionally distinct.")
    lines.append("")
    if not pairs:
        lines.append("_No pairs exceeded the threshold._")
    else:
        lines.append("## Candidate pairs")
        lines.append("")
        lines.append("| # | Similarity | Shared / Union | Detector A | Detector B | Verdict |")
        lines.append("|---:|---:|---:|---|---|---|")
        for n, (score, a, b, shared, union) in enumerate(pairs, 1):
            lines.append(f"| {n} | {score * 100:.1f}% | {shared}/{union} "
                         f"| `{a}` | `{b}` | {verdict(score)} |")
    report = "\n".join(lines) + "\n"

    if args.stdout:
        sys.stdout.write(report)
    else:
        REPORT.parent.mkdir(parents=True, exist_ok=True)
        REPORT.write_text(report, encoding="utf-8")
        print(f"[detector-dedupe] scanned {len(anchors)} detectors, "
              f"flagged {len(pairs)} pair(s) at >= {thresh * 100:.0f}% "
              f"-> {REPORT.relative_to(ROOT)}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
