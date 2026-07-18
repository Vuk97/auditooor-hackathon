#!/usr/bin/env python3
"""docs-check-auto-fix-broken.py - classify and auto-fix the cross-link rot
NEG-D's archive sweep introduced.

Reads `docs/CROSS_LINK_REPORT.md` (or regenerates it via
`tools/cross-link-validator.py`), classifies every broken link into the
four buckets the lane brief documents, and rewrites the links in-place
where safe.

Bucket policy (mirrors NEG-D auto-rewriter intent):
- CASE-A: source is a keep-list doc (or any non-archive doc) and the
  target's basename matches a file living under `docs/archive/2026-04/`
  or `docs/archive/2026-05/`. Rewrite the link to the new archive path,
  honouring the source's relative location.
- CASE-B: source itself lives under `docs/archive/<YYYY-MM>/` and the
  target's basename can be found inside the same archive bucket
  (or the other archive bucket). Rewrite to the sibling archive path.
- CASE-C: target basename has no match anywhere in the repo. Genuinely
  deleted; leave the broken link in place and document it.
- CASE-D: source is one of the WF-1 sec-5a stale-as-design top-level
  docs (`CLAUDE.md`, `INDEX.md`); these are operator-curated and we
  leave them as-is per the lane brief.

Notes:
- We never touch links inside fenced code blocks (the validator
  already skips them, and so do we).
- We never delete a link; if we cannot resolve a safe rewrite we mark
  CASE-C and leave the markdown line untouched.
- Idempotent: running twice produces no further edits once `make
  docs-check` reports zero remaining auto-fixable rows.
"""

from __future__ import annotations

import argparse
import collections
import json
import os
import pathlib
import re
import sys
from typing import Dict, List, Optional, Tuple

REPO = pathlib.Path(__file__).resolve().parent.parent
REPORT_PATH = REPO / "docs" / "CROSS_LINK_REPORT.md"

ARCHIVE_BUCKETS = (
    REPO / "docs" / "archive" / "2026-04",
    REPO / "docs" / "archive" / "2026-05",
)

# Directories we search for repo-resolvable basenames when the link
# cannot be matched inside an archive bucket. Mirrors
# cross-link-validator.SKIP_DIRS in spirit.
SEARCH_SKIP_DIRS = {
    ".git",
    ".auditooor",
    ".venv",
    "_archive",
    "agent_outputs",
    "auditooor-loop",
    "external",
    "logs",
    "node_modules",
    "obsidian-vault",
    "__pycache__",
    ".pytest_cache",
    ".audit_logs",
}

# CASE-D: stale-as-design per WF-1 sec-5a (top-level docs the operator
# curates by hand). Listed in the lane brief as "11 unavoidable
# residuals from CLAUDE.md / INDEX.md".
CASE_D_SOURCES = {"CLAUDE.md", "INDEX.md"}

# Inline-link regex (mirrors cross-link-validator.py).
INLINE_LINK_RE = re.compile(r"(\[(?:[^\]]*)\])\(([^)]+)\)")
FENCE_RE = re.compile(r"^\s*(```|~~~)")

ROW_RE = re.compile(r"^\|\s*`([^`]+)`\s*\|\s*(\d+)\s*\|\s*`([^`]+)`\s*\|")


def load_broken_rows(report_path: pathlib.Path) -> List[Tuple[str, int, str]]:
    rows: List[Tuple[str, int, str]] = []
    if not report_path.exists():
        return rows
    text = report_path.read_text(encoding="utf-8", errors="replace")
    for line in text.splitlines():
        m = ROW_RE.match(line)
        if not m:
            continue
        src, lineno, target = m.group(1), int(m.group(2)), m.group(3)
        rows.append((src, lineno, target))
    return rows


def build_archive_basename_index() -> Dict[str, List[pathlib.Path]]:
    """basename -> list of absolute paths inside the archive buckets."""
    idx: Dict[str, List[pathlib.Path]] = collections.defaultdict(list)
    for bucket in ARCHIVE_BUCKETS:
        if not bucket.exists():
            continue
        for p in bucket.iterdir():
            if p.is_file():
                idx[p.name].append(p)
    return idx


def build_repo_basename_index() -> Dict[str, List[pathlib.Path]]:
    """basename -> list of absolute paths anywhere in the repo (modulo
    SEARCH_SKIP_DIRS). Used as a fallback when the archive lookup misses
    so we can repair `../tools/...` style links from inside the archive
    buckets (the relative depth changed when the doc moved into archive/)."""
    idx: Dict[str, List[pathlib.Path]] = collections.defaultdict(list)
    for dirpath, dirnames, filenames in os.walk(REPO):
        dirnames[:] = [d for d in dirnames if d not in SEARCH_SKIP_DIRS]
        current = pathlib.Path(dirpath)
        for filename in filenames:
            idx[filename].append(current / filename)
    return idx


def classify_link(
    src_rel: str,
    target: str,
    archive_index: Dict[str, List[pathlib.Path]],
    repo_index: Dict[str, List[pathlib.Path]],
) -> Tuple[str, Optional[pathlib.Path]]:
    """Return (case, resolved_target_abs).

    case in {"CASE-A", "CASE-B", "CASE-C", "CASE-D"}.
    resolved_target_abs is None for CASE-C / CASE-D.

    - CASE-A: source is a non-archive doc and target resolves under
      docs/archive/ buckets (i.e. NEG-D moved it).
    - CASE-B: source itself lives inside docs/archive/<YYYY-MM>/ AND
      the target resolves either to a sibling archive doc or to a
      live repo path (the relative depth changed when the source
      doc moved into the archive bucket; rewrite to the now-correct
      path).
    - CASE-C: no plausible target found in the repo.
    - CASE-D: source is a WF-1 sec-5a stale-as-design top-level doc.
    """
    src_top = src_rel.split("/", 1)[0]
    if src_rel in CASE_D_SOURCES or src_top in CASE_D_SOURCES:
        return ("CASE-D", None)

    # Target basename without fragment.
    path_part = target.split("#", 1)[0]
    base = pathlib.PurePosixPath(path_part).name
    if not base:
        return ("CASE-C", None)

    src_in_archive = src_rel.startswith("docs/archive/")
    archive_matches = archive_index.get(base, [])
    repo_matches = repo_index.get(base, [])

    # CASE-A only fires when source is OUTSIDE archive. The target
    # basename must resolve to an archived file (NEG-D moved it).
    if not src_in_archive:
        if archive_matches:
            return ("CASE-A", archive_matches[0])
        return ("CASE-C", None)

    # Source is inside the archive. Prefer sibling-archive match
    # (CASE-B same-bucket -> other-bucket -> repo-wide fallback).
    if archive_matches:
        src_bucket = pathlib.PurePosixPath(src_rel).parts[2]  # e.g. "2026-05"
        same_bucket = [p for p in archive_matches if p.parent.name == src_bucket]
        chosen = same_bucket[0] if same_bucket else archive_matches[0]
        return ("CASE-B", chosen)

    # Fallback: source is in archive, target is not archived but lives
    # elsewhere in the repo. The original link used a depth that no
    # longer matches now that the source moved into archive/<YYYY-MM>/.
    # Pick the unambiguous repo-wide match if available.
    if len(repo_matches) == 1:
        return ("CASE-B", repo_matches[0])
    if len(repo_matches) > 1:
        # Try the original target path interpreted relative to the
        # repo root (strip leading "../" or "./" segments). If exactly
        # one candidate ends with that suffix, pick it.
        stripped = path_part
        while stripped.startswith("../") or stripped.startswith("./"):
            stripped = stripped.split("/", 1)[1] if "/" in stripped else ""
        if stripped:
            suffix_hits = [
                p for p in repo_matches
                if str(p.relative_to(REPO)).replace(os.sep, "/").endswith(stripped)
            ]
            if len(suffix_hits) == 1:
                return ("CASE-B", suffix_hits[0])
        # Apply preference order for the common ambiguous bases. The
        # original link was bare (no directory) so it was meant to
        # resolve from the source doc's *original* directory (most
        # archive sources came from `docs/<NAME>.md`). Therefore prefer
        # `docs/<NAME>` for bare links, then repo-root, then deeper
        # paths. For `../<NAME>` links from inside docs/archive/<YYYY-MM>/
        # the original resolved at `docs/<NAME>`, so the same preference
        # applies.
        preferred: List[pathlib.Path] = []
        for p in repo_matches:
            rel = str(p.relative_to(REPO)).replace(os.sep, "/")
            parts = rel.split("/")
            # Skip dot-dirs (`.kimi/...`, `.pytest_cache/...`).
            if any(seg.startswith(".") for seg in parts[:-1]):
                continue
            # Skip deep nested sub-trees that are unlikely link targets.
            if parts[0] in {"projects", "_archive", "obsidian-vault",
                             "external", "auditooor-loop", "node_modules"}:
                continue
            preferred.append(p)
        # Re-rank: prefer docs/<NAME>, then repo-root <NAME>, then others.
        ranked = sorted(
            preferred,
            key=lambda p: (
                0 if str(p.relative_to(REPO)).replace(os.sep, "/").startswith("docs/") else
                1 if "/" not in str(p.relative_to(REPO)).replace(os.sep, "/") else
                2,
                str(p.relative_to(REPO)),
            ),
        )
        if ranked:
            return ("CASE-B", ranked[0])
        # All candidates filtered out: ambiguous - leave for manual review.
        return ("CASE-C", None)

    return ("CASE-C", None)


def relpath_from_source(src_rel: str, archive_abs: pathlib.Path) -> str:
    """Return a POSIX-style relative path the rewriter can paste."""
    src_dir = (REPO / src_rel).parent
    rel = os.path.relpath(archive_abs, start=src_dir)
    return rel.replace(os.sep, "/")


def rewrite_source_file(
    src_rel: str,
    fixes: List[Tuple[int, str, str]],
) -> int:
    """Rewrite the markdown source. fixes = [(lineno, old_target, new_target), ...].

    Returns the number of links actually rewritten.
    """
    abs_path = REPO / src_rel
    if not abs_path.exists():
        return 0
    text = abs_path.read_text(encoding="utf-8", errors="replace")
    new_lines: List[str] = []
    in_fence = False
    rewrites_applied = 0
    # Index fixes by lineno for fast lookup; multiple fixes on the same
    # line are allowed.
    fixes_by_line: Dict[int, List[Tuple[str, str]]] = collections.defaultdict(list)
    for lineno, old_t, new_t in fixes:
        fixes_by_line[lineno].append((old_t, new_t))

    for idx, line in enumerate(text.splitlines(keepends=False), start=1):
        if FENCE_RE.match(line):
            in_fence = not in_fence
            new_lines.append(line)
            continue
        if in_fence or idx not in fixes_by_line:
            new_lines.append(line)
            continue
        updated = line
        for old_t, new_t in fixes_by_line[idx]:
            # Strip optional URL title from old_t to mirror validator.
            normalised = old_t.split(" ", 1)[0]
            # Build matching token (target may itself contain '(', ')', so
            # we use a simple substring replace bracketed by '](...)' to
            # keep this safe against accidental collateral.
            old_token = f"]({normalised})"
            new_token = f"]({new_t})"
            if old_token in updated:
                updated = updated.replace(old_token, new_token, 1)
                rewrites_applied += 1
                continue
            # Some links carry a fragment; try with the original target.
            old_token_full = f"]({old_t})"
            new_token_full = f"]({new_t})"
            if old_token_full in updated:
                updated = updated.replace(old_token_full, new_token_full, 1)
                rewrites_applied += 1
        new_lines.append(updated)

    if rewrites_applied:
        # Preserve trailing newline if the original had one.
        ending = "\n" if text.endswith("\n") else ""
        abs_path.write_text("\n".join(new_lines) + ending, encoding="utf-8")
    return rewrites_applied


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--report",
        default=str(REPORT_PATH),
        help="Path to docs/CROSS_LINK_REPORT.md (must already exist).",
    )
    ap.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the disposition table without rewriting any file.",
    )
    ap.add_argument(
        "--audit-out",
        default=None,
        help="If set, write a JSON audit log to this path.",
    )
    ap.add_argument(
        "--cases",
        default="A,B",
        help="Comma list of cases to actually rewrite (default: A,B). "
             "CASE-C / CASE-D are never rewritten.",
    )
    args = ap.parse_args()

    rewrite_cases = {("CASE-" + c.strip().upper()) for c in args.cases.split(",")}
    rewrite_cases.discard("CASE-C")
    rewrite_cases.discard("CASE-D")

    report_path = pathlib.Path(args.report).resolve()
    if not report_path.exists():
        print(f"[auto-fix] error: {report_path} does not exist. "
              f"Run `make docs-check` first.", file=sys.stderr)
        return 2

    rows = load_broken_rows(report_path)
    if not rows:
        print("[auto-fix] no broken-link rows in report; nothing to do.")
        return 0

    archive_index = build_archive_basename_index()
    repo_index = build_repo_basename_index()

    per_source: Dict[str, List[Tuple[int, str, str, str]]] = collections.defaultdict(list)
    audit_entries: List[Dict] = []
    counts: Dict[str, int] = collections.Counter()

    for src_rel, lineno, target in rows:
        case, resolved_abs = classify_link(src_rel, target, archive_index, repo_index)
        counts[case] += 1
        new_target = ""
        if case in rewrite_cases and resolved_abs is not None:
            new_target = relpath_from_source(src_rel, resolved_abs)
            per_source[src_rel].append((lineno, target, new_target, case))
        audit_entries.append({
            "source": src_rel,
            "line": lineno,
            "target": target,
            "case": case,
            "new_target": new_target,
            "resolved_target": str(resolved_abs.relative_to(REPO))
                if resolved_abs is not None else None,
        })

    print("[auto-fix] disposition counts:")
    for c in sorted(counts):
        print(f"  {c}: {counts[c]}")

    rewrites_total = 0
    files_touched = 0
    if not args.dry_run:
        for src_rel, fixes in per_source.items():
            fix_pairs = [(ln, ot, nt) for (ln, ot, nt, _case) in fixes]
            applied = rewrite_source_file(src_rel, fix_pairs)
            rewrites_total += applied
            if applied:
                files_touched += 1
        print(f"[auto-fix] rewrote {rewrites_total} link(s) across {files_touched} file(s).")
    else:
        plan_count = sum(len(v) for v in per_source.values())
        print(f"[auto-fix] dry-run: would rewrite {plan_count} link(s) "
              f"across {len(per_source)} file(s).")

    if args.audit_out:
        audit_path = pathlib.Path(args.audit_out)
        audit_path.parent.mkdir(parents=True, exist_ok=True)
        audit_path.write_text(
            json.dumps({
                "schema": "auditooor.docs_check_auto_fix_broken.v1",
                "report_source": str(report_path.relative_to(REPO))
                    if REPO in report_path.parents else str(report_path),
                "counts": dict(counts),
                "rewrites_applied": 0 if args.dry_run else rewrites_total,
                "files_touched": 0 if args.dry_run else files_touched,
                "entries": audit_entries,
            }, indent=2, sort_keys=True),
            encoding="utf-8",
        )
        print(f"[auto-fix] audit log: {audit_path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
