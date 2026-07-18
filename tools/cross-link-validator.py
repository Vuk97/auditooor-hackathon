#!/usr/bin/env python3
"""cross-link-validator.py — verify markdown cross-references across the repo.

Walks every committed-doc markdown file under the repo (skipping _archive/,
agent_outputs/, external/, logs/, node_modules/, .git/, obsidian-vault/,
__pycache__/), extracts link targets, and reports any references that point at
files which do not exist.

Usage:
    python3 tools/cross-link-validator.py                   # default scan
    python3 tools/cross-link-validator.py --fix-suggestions # include Levenshtein near-matches
    python3 tools/cross-link-validator.py --scope full      # also validate out-of-repo paths
    python3 tools/cross-link-validator.py --strict          # exit non-zero if any broken

Writes docs/CROSS_LINK_REPORT.md by default. Use --report-out for a temporary
or caller-owned report path.

Phase 14 of PR #84.
"""
import argparse
import os
import pathlib
import re
import sys
from difflib import get_close_matches

REPO = pathlib.Path(__file__).resolve().parent.parent
SKIP_DIRS = {
    "_archive",
    "agent_outputs",
    "external",
    "logs",
    "node_modules",
    ".git",
    ".auditooor",
    ".venv",
    "auditooor-loop",
    "obsidian-vault",
    "__pycache__",
}
# Ephemeral per-engagement artifact trees: these are NOT curated documentation -
# they are agent-run outputs / generated advisory reports / session state whose
# thousands of internal (often intentionally-stale) links are noise the docs gate
# was never meant to validate.  They are SCAN-skipped (not walked for OUTGOING
# links) but remain in the filesystem index below, so genuine doc -> artifact
# links (e.g. docs/next-loop/*.md referencing reports/*.md) still resolve.
# (2026-07-07: repo-root scan pulled in 16363 "docs" - ~15000 from these trees -
# reporting 9091 broken links and taking minutes; real doc corpus is ~1600.)
SCAN_ONLY_SKIP_DIRS = {"audit", "reports", ".claude"}

# Scraped third-party corpora with refs into their own original repos — out of scope.
SKIP_PATH_PREFIXES = ("patterns/fixtures/auto/",)

# Matches: [text](target) — captures target. Ignores images ![..](..) by filtering later if needed.
INLINE_LINK = re.compile(r"\[(?:[^\]]*)\]\(([^)]+)\)")
# Matches: [text][ref] style — we don't validate those (need link-defs resolution); skipped.

# Skip schemes we don't verify
SKIP_PREFIXES = ("http://", "https://", "mailto:", "ftp://", "ftps://", "tel:",
                 "ssh://", "git://", "data:", "javascript:", "#")


def iter_md_files(root: pathlib.Path):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [name for name in dirnames
                       if name not in SKIP_DIRS and name not in SCAN_ONLY_SKIP_DIRS]
        current = pathlib.Path(dirpath)
        for filename in filenames:
            if not filename.endswith(".md"):
                continue
            p = current / filename
            rel = p.relative_to(root)
            rel_str = str(rel)
            if any(rel_str.startswith(prefix) for prefix in SKIP_PATH_PREFIXES):
                continue
            yield p


def extract_links(md_path: pathlib.Path):
    """Yield (line_no, target) tuples for every inline link in the file."""
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
            # strip optional title: "path "Title""
            if " " in target:
                target = target.split(" ", 1)[0]
            if not target:
                continue
            yield lineno, target


def _is_within(path: pathlib.Path, root: pathlib.Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
    except ValueError:
        return False
    return True


def target_status(src_md: pathlib.Path, target: str, root: pathlib.Path, scope: str) -> str:
    """Resolve target and return exists, broken, or skipped_out_of_repo."""
    # strip fragment
    path_part = target.split("#", 1)[0]
    if not path_part:
        return "exists"  # pure #anchor on same page — not validated
    p = pathlib.Path(path_part)
    if p.is_absolute():
        candidate = p
    else:
        candidate = (src_md.parent / p).resolve()
    if scope == "repo-only" and not _is_within(candidate, root):
        return "skipped_out_of_repo"
    return "exists" if candidate.exists() else "broken"


def build_fs_index(root: pathlib.Path):
    """Flat list of every file in-scope, for Levenshtein near-miss suggestions.

    Returns (idx, basenames) where `basenames` maps each file's basename ->
    its relative path.  The basename map is built ONCE here rather than
    re-derived inside suggest() on every broken link - with a large tree
    (16k+ files) and thousands of broken links, rebuilding a 16k-entry dict
    per link cost ~148M Path() constructions and turned an advisory report
    into a multi-minute stall (2026-07-07).
    """
    idx = []
    basenames: dict[str, str] = {}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [name for name in dirnames if name not in SKIP_DIRS]
        current = pathlib.Path(dirpath)
        for filename in filenames:
            p = current / filename
            rel = p.relative_to(root)
            rel_str = str(rel)
            if any(rel_str.startswith(prefix) for prefix in SKIP_PATH_PREFIXES):
                continue
            idx.append(rel_str)
            basenames.setdefault(filename, rel_str)
    return idx, basenames


def suggest(target: str, fs_index, basenames, basename_keys):
    path_part = target.split("#", 1)[0]
    base = pathlib.Path(path_part).name
    if not base:
        return ""
    # match on basename first (keys precomputed once), then full-path fuzzy
    hits = get_close_matches(base, basename_keys, n=1, cutoff=0.75)
    if hits:
        return basenames[hits[0]]
    hits = get_close_matches(path_part, fs_index, n=1, cutoff=0.75)
    return hits[0] if hits else ""


def main():
    ap = argparse.ArgumentParser(description="Validate markdown cross-refs.")
    ap.add_argument("--fix-suggestions", action="store_true",
                    help="Include Levenshtein near-match suggestions in the report.")
    ap.add_argument("--strict", action="store_true",
                    help="Exit 1 if any broken links are found.")
    ap.add_argument("--root", default=str(REPO), help="Repo root (default: auto).")
    ap.add_argument("--scope", choices=("repo-only", "full"), default="repo-only",
                    help="repo-only skips out-of-repo filesystem links; full validates them.")
    ap.add_argument("--report-out", help="Report path, relative to --root unless absolute.")
    ap.add_argument("--path", action="append", default=[], metavar="PATH",
                    help="Validate only this Markdown file, relative to --root. Repeatable.")
    args = ap.parse_args()

    root = pathlib.Path(args.root).resolve()
    if args.path:
        md_files = []
        for value in args.path:
            candidate = (root / value).resolve()
            if not _is_within(candidate, root):
                ap.error(f"--path escapes --root: {value}")
            if not candidate.is_file() or candidate.suffix != ".md":
                ap.error(f"--path must name an existing Markdown file: {value}")
            md_files.append(candidate)
    else:
        md_files = list(iter_md_files(root))

    total_links = 0
    broken = []  # list of (src_rel, lineno, target)
    skipped_out_of_repo = []  # list of (src_rel, lineno, target)

    for md in md_files:
        for lineno, target in extract_links(md):
            if target.startswith(SKIP_PREFIXES):
                continue
            status = target_status(md, target, root, args.scope)
            if status == "skipped_out_of_repo":
                skipped_out_of_repo.append((str(md.relative_to(root)), lineno, target))
                continue
            total_links += 1
            if status == "broken":
                broken.append((str(md.relative_to(root)), lineno, target))

    # Suggestion fuzzy-match is O(broken x candidates); on a large tree with
    # thousands of broken links this dominates runtime.  The report is advisory
    # (suggestions are hints), so cap the number of links we compute a fix hint
    # for and disclose the cap in the report - never silently truncate.
    MAX_SUGGESTION_LINKS = 500
    fs_index, basenames = build_fs_index(root) if args.fix_suggestions else ([], {})
    basename_keys = list(basenames.keys())
    suggestion_capped = args.fix_suggestions and len(broken) > MAX_SUGGESTION_LINKS

    # Write report
    if args.report_out:
        report = pathlib.Path(args.report_out)
        if not report.is_absolute():
            report = root / report
    else:
        report = root / "docs" / "CROSS_LINK_REPORT.md"
    report.parent.mkdir(parents=True, exist_ok=True)
    lines = []
    lines.append("# Cross-Link Validation Report")
    lines.append("")
    lines.append("Generated by `tools/cross-link-validator.py`. Do not edit by hand.")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- Docs scanned: **{len(md_files)}**")
    lines.append(f"- Links checked: **{total_links}**")
    lines.append(f"- Out-of-repo links skipped: **{len(skipped_out_of_repo)}**")
    lines.append(f"- Broken: **{len(broken)}**")
    lines.append("")
    if broken:
        lines.append("## Broken Links")
        lines.append("")
        if args.fix_suggestions:
            if suggestion_capped:
                lines.append(f"> Fix-suggestions computed for the first **{MAX_SUGGESTION_LINKS}** "
                             f"of {len(broken)} broken links (fuzzy-match cap); remaining rows "
                             f"show `-` (meaning not-computed, NOT \"no suggestion found\"). "
                             f"Re-run on a smaller `--root` for full hints.")
                lines.append("")
            lines.append("| Source | Line | Target | Suggested Fix |")
            lines.append("|--------|------|--------|---------------|")
        else:
            lines.append("| Source | Line | Target |")
            lines.append("|--------|------|--------|")
        for i, (src, lineno, target) in enumerate(sorted(broken)):
            tgt_cell = target.replace("|", "\\|")
            src_cell = src.replace("|", "\\|")
            if args.fix_suggestions and i < MAX_SUGGESTION_LINKS:
                hint = suggest(target, fs_index, basenames, basename_keys).replace("|", "\\|")
                lines.append(f"| `{src_cell}` | {lineno} | `{tgt_cell}` | {('`' + hint + '`') if hint else '-'} |")
            elif args.fix_suggestions:
                lines.append(f"| `{src_cell}` | {lineno} | `{tgt_cell}` | - |")
            else:
                lines.append(f"| `{src_cell}` | {lineno} | `{tgt_cell}` |")
        lines.append("")
    else:
        lines.append("No broken links found.")
        lines.append("")

    report.write_text("\n".join(lines), encoding="utf-8")

    # stdout summary
    print(
        f"[cross-link] {len(md_files)} docs, {total_links} links, "
        f"{len(skipped_out_of_repo)} out-of-repo skipped, {len(broken)} broken"
    )
    try:
        report_display = report.relative_to(root)
    except ValueError:
        report_display = report
    print(f"[cross-link] report: {report_display}")

    if args.strict and broken:
        sys.exit(1)


if __name__ == "__main__":
    main()
