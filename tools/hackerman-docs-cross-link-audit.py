#!/usr/bin/env python3
"""hackerman-docs-cross-link-audit.py — focused cross-link audit for hackerman docs.

Walks the hackerman / wave / PR_726 doc family and verifies every internal
Markdown link target resolves to an on-disk file. Emits a per-doc verdict
(clean vs broken-links) and a summary report.

Scope:
    docs/HACKERMAN*.md
    docs/WAVE*.md
    docs/PR_726*.md

Out of scope (skipped):
    - http(s)://, mailto:, ftp://, ssh://, data:, javascript:, tel:, #anchor-only
    - link-reference style: [text][ref]

Usage:
    python3 tools/hackerman-docs-cross-link-audit.py
    python3 tools/hackerman-docs-cross-link-audit.py --strict
    python3 tools/hackerman-docs-cross-link-audit.py --json
    python3 tools/hackerman-docs-cross-link-audit.py --report-out docs/HACKERMAN_DOCS_CROSS_LINK_AUDIT_2026-05-16.md

PR #726 / Wave-1 hackerman-capability-lift.
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import sys
from typing import Iterable

REPO = pathlib.Path(__file__).resolve().parent.parent

DEFAULT_GLOBS = (
    "docs/HACKERMAN*.md",
    "docs/WAVE*.md",
    "docs/PR_726*.md",
)

INLINE_LINK = re.compile(r"\[(?:[^\]]*)\]\(([^)]+)\)")

SKIP_PREFIXES = (
    "http://", "https://", "mailto:", "ftp://", "ftps://", "tel:",
    "ssh://", "git://", "data:", "javascript:", "#",
)


def iter_target_docs(root: pathlib.Path, globs: Iterable[str]) -> list[pathlib.Path]:
    out: list[pathlib.Path] = []
    for g in globs:
        for p in sorted(root.glob(g)):
            if p.is_file() and p.suffix == ".md":
                out.append(p)
    # de-dupe while preserving order
    seen: set[pathlib.Path] = set()
    unique: list[pathlib.Path] = []
    for p in out:
        if p in seen:
            continue
        seen.add(p)
        unique.append(p)
    return unique


def extract_links(md_path: pathlib.Path):
    """Yield (line_no, raw_target) tuples for every inline link, skipping fenced code."""
    try:
        text = md_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return
    in_fence = False
    for lineno, line in enumerate(text.splitlines(), 1):
        stripped = line.lstrip()
        if stripped.startswith("```") or stripped.startswith("~~~"):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        for m in INLINE_LINK.finditer(line):
            target = m.group(1).strip()
            if " " in target:
                target = target.split(" ", 1)[0]
            if not target:
                continue
            yield lineno, target


def classify_target(src_md: pathlib.Path, target: str, root: pathlib.Path) -> str:
    """Return one of: 'skip-external', 'skip-anchor-only', 'exists', 'broken'."""
    if target.startswith(SKIP_PREFIXES):
        # leading '#' is anchor-only; treat as a no-op
        if target.startswith("#"):
            return "skip-anchor-only"
        return "skip-external"
    path_part = target.split("#", 1)[0]
    if not path_part:
        return "skip-anchor-only"
    p = pathlib.Path(path_part)
    if p.is_absolute():
        candidate = p
    else:
        candidate = (src_md.parent / p).resolve()
    return "exists" if candidate.exists() else "broken"


def audit(root: pathlib.Path, globs: Iterable[str]) -> dict:
    docs = iter_target_docs(root, globs)
    per_doc: list[dict] = []
    total_links = 0
    total_broken = 0
    total_skipped_external = 0
    total_skipped_anchor = 0

    for md in docs:
        rel = str(md.relative_to(root))
        links_checked = 0
        broken: list[dict] = []
        skipped_external = 0
        skipped_anchor = 0
        for lineno, target in extract_links(md):
            status = classify_target(md, target, root)
            if status == "skip-external":
                skipped_external += 1
                continue
            if status == "skip-anchor-only":
                skipped_anchor += 1
                continue
            links_checked += 1
            if status == "broken":
                broken.append({"line": lineno, "target": target})
        verdict = "clean" if not broken else "broken-links"
        per_doc.append({
            "doc": rel,
            "verdict": verdict,
            "links_checked": links_checked,
            "broken": broken,
            "skipped_external": skipped_external,
            "skipped_anchor_only": skipped_anchor,
        })
        total_links += links_checked
        total_broken += len(broken)
        total_skipped_external += skipped_external
        total_skipped_anchor += skipped_anchor

    return {
        "root": str(root),
        "globs": list(globs),
        "docs_audited": len(docs),
        "total_links_checked": total_links,
        "total_broken_links": total_broken,
        "total_skipped_external": total_skipped_external,
        "total_skipped_anchor_only": total_skipped_anchor,
        "per_doc": per_doc,
    }


def render_markdown(result: dict) -> str:
    lines: list[str] = []
    lines.append("# Hackerman Docs Cross-Link Audit - 2026-05-16")
    lines.append("")
    lines.append("Generated by `tools/hackerman-docs-cross-link-audit.py`. Do not edit by hand.")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- Docs audited: **{result['docs_audited']}**")
    lines.append(f"- Internal links checked: **{result['total_links_checked']}**")
    lines.append(f"- Broken links: **{result['total_broken_links']}**")
    lines.append(f"- External links skipped: **{result['total_skipped_external']}**")
    lines.append(f"- Anchor-only links skipped: **{result['total_skipped_anchor_only']}**")
    lines.append("")
    clean = [d for d in result["per_doc"] if d["verdict"] == "clean"]
    broken_docs = [d for d in result["per_doc"] if d["verdict"] == "broken-links"]
    lines.append(f"- Docs verdict `clean`: **{len(clean)}**")
    lines.append(f"- Docs verdict `broken-links`: **{len(broken_docs)}**")
    lines.append("")
    if broken_docs:
        lines.append("## Broken Links")
        lines.append("")
        lines.append("| Source | Line | Target |")
        lines.append("|--------|------|--------|")
        for d in broken_docs:
            for b in d["broken"]:
                tgt_cell = str(b["target"]).replace("|", "\\|")
                lines.append(f"| `{d['doc']}` | {b['line']} | `{tgt_cell}` |")
        lines.append("")
    lines.append("## Per-Doc Verdict")
    lines.append("")
    lines.append("| Source | Verdict | Links Checked | Broken |")
    lines.append("|--------|---------|---------------|--------|")
    for d in result["per_doc"]:
        lines.append(
            f"| `{d['doc']}` | {d['verdict']} | {d['links_checked']} | {len(d['broken'])} |"
        )
    lines.append("")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Hackerman docs cross-link audit.")
    ap.add_argument("--root", default=str(REPO), help="Repo root (default: auto).")
    ap.add_argument(
        "--glob",
        action="append",
        default=None,
        help="Doc glob (repeatable). Defaults to hackerman/wave/PR_726 set.",
    )
    ap.add_argument("--strict", action="store_true",
                    help="Exit 1 if any broken links are found.")
    ap.add_argument("--json", action="store_true",
                    help="Emit JSON to stdout instead of markdown summary.")
    ap.add_argument("--report-out", default=None,
                    help="Write a markdown summary report to this path.")
    args = ap.parse_args(argv)

    root = pathlib.Path(args.root).resolve()
    globs = args.glob or list(DEFAULT_GLOBS)
    result = audit(root, globs)

    if args.report_out:
        out_path = pathlib.Path(args.report_out)
        if not out_path.is_absolute():
            out_path = root / out_path
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(render_markdown(result), encoding="utf-8")

    if args.json:
        json.dump(result, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
    else:
        sys.stdout.write(
            f"hackerman-docs-cross-link-audit: docs={result['docs_audited']} "
            f"links_checked={result['total_links_checked']} "
            f"broken={result['total_broken_links']}\n"
        )
        for d in result["per_doc"]:
            if d["verdict"] == "broken-links":
                for b in d["broken"]:
                    sys.stdout.write(
                        f"  BROKEN {d['doc']}:{b['line']} -> {b['target']}\n"
                    )

    if args.strict and result["total_broken_links"]:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
