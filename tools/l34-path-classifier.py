#!/usr/bin/env python3
"""L34 path classifier - distinguish draft files from tracker/ledger metadata.

L34 (draft-modification-requires-operator-authorization) gates per-draft edits
to submission folders. iter17 YYYYY auto-executed SUBMISSIONS.md tracker edits
without per-draft authorization because trackers are operator-facing metadata,
not draft content. This tool codifies the 5-bucket classification so future
agents can mechanically decide whether a write requires per-draft auth.

R36 (parallel-worktree-commit-pathspec-discipline) interaction: edits to this
file are tracked via tools/agent-pathspec-register.py and the resulting
.auditooor/agent_pathspec.json declaration. CAP-GAP-96 edit lane:
lane-CAP-FIX-W13-l34-killed-bucket.

Classification buckets:
  - draft-file       (per-draft op auth REQUIRED): submissions/<status>/<slug>/<slug>.md
                     and its .md.hash / hardening / hackenproof-plain / -poc.zip
                     siblings INSIDE per-finding folders.
  - tracker-file     (auto-executable): submissions/SUBMISSIONS.md and any flat
                     metadata .md at status-dir level whose stem matches
                     SUBMISSIONS|README|TRACKER|INDEX (plus .hash siblings).
  - workspace-ledger (auto-executable): files under <workspace>/.auditooor/.
  - lesson-anchor    (auto-executable): files under submissions/_lessons-learned/
                     OR under post-decision dirs (_killed/, _oos_rejected/,
                     _superseded/, superseded/) - per CAP-GAP-96 these are
                     post-promotion-decision content, not active drafts.
  - out-of-scope     (no L34 relevance): paths outside submissions/ and not
                     workspace-ledger.

Output schema: auditooor.l34_path_classifier.v1

Usage:
  python3 tools/l34-path-classifier.py <path> [--json]
  python3 tools/l34-path-classifier.py --batch <path1> <path2> ... [--json]
  python3 tools/l34-path-classifier.py --glob 'submissions/**/*.md' [--workspace <ws>] [--json]

Exit codes:
  0 - classification produced for every input path
  1 - input error / no paths supplied
  2 - glob matched zero paths

Empirical anchor (iter17 YYYYY, 2026-05-23): SUBMISSIONS.md tracker edits in
spark / hyperbridge / polymarket workspaces auto-executed without operator
interruption because trackers carry operator-facing metadata, not finding
content. L34 v2 codifies that distinction; this tool is the canonical helper.
"""

from __future__ import annotations

import argparse
import fnmatch
import glob
import json
import sys
from pathlib import Path
from typing import Any


SCHEMA = "auditooor.l34_path_classifier.v1"
TOOL_VERSION = "1.0.0"


# Status directory names recognized as "draft-bearing".
# Mirror tools/submission-folder-structure-check.py defaults plus the wider
# set we see in the wild. Override via AUDITOOOR_R41_STATUS_DIRS env (the
# R41 rule's env hook) is intentionally NOT consumed here - L34 is its own
# concern and the canonical list is the union of every status dir name we
# have observed across workspaces.
DRAFT_STATUS_DIRS = frozenset({
    "staging",
    "paste_ready",
    "ready",
    "filed",
    "submitted",
    "packaged",
    "superseded",
    "held",
    "_killed",
    "_oos_rejected",
    "_pre_rejected",
    "_triage",
    "clean",
    "engage_candidates",
    "final_dispositions",
    "llm_review",
})

# Sub-directory names that live UNDER submissions/ but are NOT draft folders.
# Any path whose first segment after submissions/ matches one of these is
# routed to its dedicated bucket regardless of file extension.
# r36-rebuttal: edit declared in agent_pathspec.json via tools/agent-pathspec-register.py
LESSON_ANCHOR_DIRS = frozenset({
    "_lessons-learned",
    "_lessons_learned",
    "lessons-learned",
    "lessons_learned",
})

# Status directories that hold POST-PROMOTION-DECISION content. Files under
# these dirs are semantically equivalent to lesson-anchor material (kill
# rationales, OOS rejection notes, supersede dispositions); they are NOT
# active drafts and do NOT require per-draft operator authorization.
# CAP-GAP-96 (codified 2026-05-27): Hyperbridge bandwidth-fot-over-credit
# kill + c4-solver-controlled-output-call kill both wanted to write in-folder
# DISPOSITION.md / KILL_RATIONALE.md but were blocked by the prior
# draft-file classification. This frozenset short-circuits the
# DRAFT_STATUS_DIRS branch so post-decision dirs route to lesson-anchor.
# These names also remain in DRAFT_STATUS_DIRS so flat tracker metadata
# at the status-dir root (SUBMISSIONS.md / README.md) still classifies
# correctly via the existing tracker-stem branch.
# r36-rebuttal: agent_pathspec.json declares this edit under lane-CAP-FIX-W13-l34-killed-bucket
POST_DECISION_DIRS = frozenset({
    "_killed",
    "_oos_rejected",
    "_superseded",
    # `superseded` (no leading underscore) is also a documented status dir
    # in the spark workspace; treat as post-decision when used.
    "superseded",
})

# File-stem set that identifies a tracker/metadata file living flat in the
# submissions/ root or flat in a status dir. Comparison is case-insensitive.
TRACKER_STEMS = frozenset({
    "submissions",
    "readme",
    "tracker",
    "index",
})

# Extensions that count as tracker-file metadata when the stem matches.
TRACKER_EXTENSIONS = frozenset({
    ".md",
    ".json",
    ".jsonl",
    ".yaml",
    ".yml",
    ".csv",
    ".tsv",
})

# .hash sidecar is always classified as its parent file.
HASH_SUFFIX = ".hash"
BACKUP_SUFFIXES = (".backup-old", ".bak", ".old")


def _normalize(path: str | Path) -> Path:
    """Return a Path object; expand ~ but do NOT resolve symlinks (the path
    may not exist yet - we classify the intended write target)."""
    return Path(path).expanduser()


def _strip_hash_suffix(path: Path) -> Path:
    """If path ends in .hash, return its parent file path for classification.
    .md.hash sidecars inherit the parent file's classification verdict."""
    if path.suffix == HASH_SUFFIX:
        return path.with_suffix("")
    return path


def _strip_backup_suffix(name: str) -> str:
    """Strip .bak / .backup-old / etc. so SUBMISSIONS.md.backup-old still
    classifies as a tracker-file."""
    lower = name.lower()
    for suffix in BACKUP_SUFFIXES:
        if lower.endswith(suffix):
            return name[: -len(suffix)]
        # multi-segment .bak-FOO style
        if f"{suffix}-" in lower:
            idx = lower.find(f"{suffix}-")
            return name[:idx]
    return name


def _find_submissions_anchor(path: Path) -> tuple[int, list[str]] | None:
    """Locate the 'submissions' segment in the path's parts and return
    (index, parts_after_submissions). Returns None if no submissions/ anchor
    exists."""
    parts = list(path.parts)
    for i, part in enumerate(parts):
        if part == "submissions":
            return i, parts[i + 1 :]
    return None


def _is_workspace_ledger(path: Path) -> bool:
    """Workspace-ledger = anything under a .auditooor/ directory."""
    return any(part == ".auditooor" for part in path.parts)


def _classify_one(raw_path: str | Path) -> dict[str, Any]:
    """Classify a single path. Pure function - no filesystem access required
    (we classify paths that may not exist yet)."""
    original = str(raw_path)
    path = _normalize(raw_path)

    # Existing directory paths are container nodes, not file-write targets.
    # Keep them out of draft/tracker auth decisions when batch/glob callers
    # accidentally include directories alongside files.
    if path.exists() and path.is_dir():
        return _result(
            original,
            "out-of-scope",
            requires_auth=False,
            reason="path resolves to an existing directory; L34 classifies "
                   "file write targets, not container directories.",
        )

    # .hash sidecar inherits parent classification.
    classify_target = _strip_hash_suffix(path)

    # Workspace-ledger takes precedence over submissions/ membership
    # (.auditooor/ never lives under submissions/ but be defensive).
    if _is_workspace_ledger(classify_target):
        return _result(
            original,
            "workspace-ledger",
            requires_auth=False,
            reason="path lives under a .auditooor/ workspace-state directory; "
                   "auto-executable for state-machine edits.",
        )

    anchor = _find_submissions_anchor(classify_target)
    if anchor is None:
        return _result(
            original,
            "out-of-scope",
            requires_auth=False,
            reason="path is not under any submissions/ directory and not a "
                   "workspace-ledger; L34 does not apply.",
        )

    _, tail = anchor
    if not tail:
        # The path IS the submissions/ directory itself (no trailing segments).
        return _result(
            original,
            "out-of-scope",
            requires_auth=False,
            reason="path is the submissions/ directory itself; not a file.",
        )

    head = tail[0]
    head_stem = _strip_backup_suffix(head)

    # Case 1: lesson anchor (_lessons-learned/ etc.).
    # r36-rebuttal: tools/agent-pathspec-register.py declared this edit
    if head in LESSON_ANCHOR_DIRS:
        return _result(
            original,
            "lesson-anchor",
            requires_auth=False,
            reason=f"file lives under submissions/{head}/; classified as "
                   "lesson anchor (auto-executable post-mortem material).",
        )

    # Case 1b: post-decision status dir (_killed/, _oos_rejected/,
    # _superseded/, superseded/). Per CAP-GAP-96 these hold post-promotion-
    # decision content (kill rationale, OOS rejection notes, supersede
    # dispositions) and are semantically equivalent to lesson-anchor
    # material. The whole subtree (per-finding folder + flat files at the
    # status-dir root) routes to lesson-anchor, EXCEPT flat tracker-stem
    # metadata which falls through to Case 2-equivalent tracker-file
    # classification so SUBMISSIONS.md/README.md inside _killed/ still
    # classify as tracker-file.
    if head in POST_DECISION_DIRS:
        inner_path = tail[1:]
        # 1b.i. Flat metadata at status-dir root: route to tracker-file
        # when the stem matches; otherwise lesson-anchor.
        if len(inner_path) == 1:
            inner_head = inner_path[0]
            inner_head_stem = _strip_backup_suffix(inner_head)
            p = Path(inner_head_stem)
            stem_lower = p.stem.lower()
            ext_lower = p.suffix.lower()
            if stem_lower in TRACKER_STEMS and ext_lower in TRACKER_EXTENSIONS:
                return _result(
                    original,
                    "tracker-file",
                    requires_auth=False,
                    reason=f"file '{inner_head}' lives flat in "
                           f"submissions/{head}/ and matches tracker stem "
                           "(SUBMISSIONS|README|TRACKER|INDEX); "
                           "auto-executable for metadata edits.",
                )
            return _result(
                original,
                "lesson-anchor",
                requires_auth=False,
                reason=f"file lives flat in submissions/{head}/ "
                       "(post-decision dir per CAP-GAP-96); classified as "
                       "lesson anchor (auto-executable post-mortem material).",
            )
        # 1b.ii. Per-finding folder under post-decision dir: route to
        # lesson-anchor. Covers <slug>.md, DISPOSITION.md, KILL_RATIONALE.md,
        # .md.hash sidecars, .hardening.md, .hackenproof-plain.{txt,json},
        # -poc.zip, .poc-transcript.txt - all are post-decision artifacts.
        inner_head = inner_path[0]
        return _result(
            original,
            "lesson-anchor",
            requires_auth=False,
            reason=f"file lives inside per-finding folder "
                   f"submissions/{head}/{inner_head}/ (post-decision dir "
                   "per CAP-GAP-96); classified as lesson anchor "
                   "(auto-executable post-mortem material). DISPOSITION.md, "
                   "KILL_RATIONALE.md, and the disposed <slug>.md itself are "
                   "all writeable without per-draft operator authorization.",
        )

    # Case 2: flat tracker file at submissions/ root.
    if len(tail) == 1:
        return _classify_flat_metadata(
            original,
            head,
            head_stem,
            location="submissions/",
        )

    # Case 3: under a status directory.
    if head in DRAFT_STATUS_DIRS:
        # Sub-cases inside a status dir:
        inner_path = tail[1:]
        inner_head = inner_path[0]
        inner_head_stem = _strip_backup_suffix(inner_head)

        # 3a. Flat metadata file at status-dir root
        #     (submissions/<status>/SUBMISSIONS.md, README.md, etc.).
        if len(inner_path) == 1:
            return _classify_flat_metadata(
                original,
                inner_head,
                inner_head_stem,
                location=f"submissions/{head}/",
                draft_fallback_reason=(
                    f"file lives flat in submissions/{head}/ (status dir) "
                    "and is not a tracker stem; treated as draft-file per "
                    "L34 fall-through. NB: R41 (Check #85) prefers per-finding "
                    "folders for drafts; this flat shape is itself non-compliant."
                ),
            )

        # 3b. Deeper than one segment under a status dir:
        #     submissions/<status>/<slug>/<filename>.
        #     The whole per-finding folder is draft-bearing.
        return _result(
            original,
            "draft-file",
            requires_auth=True,
            reason=f"file lives inside per-finding folder "
                   f"submissions/{head}/{inner_head}/ (status dir); "
                   "L34 per-draft operator authorization REQUIRED.",
        )

    # Case 4: under submissions/ but the first segment is unknown -
    # neither a status dir nor _lessons-learned. Treat as draft-file by
    # default (safer than auto-executable). Operators can extend
    # DRAFT_STATUS_DIRS or LESSON_ANCHOR_DIRS for new conventions.
    return _result(
        original,
        "draft-file",
        requires_auth=True,
        reason=f"file lives under submissions/{head}/ but the first segment "
               f"is not a recognized status dir or lesson-anchor dir; "
               "defaulting to draft-file (per-draft op auth REQUIRED). "
               "If this is metadata, extend DRAFT_STATUS_DIRS / "
               "LESSON_ANCHOR_DIRS in tools/l34-path-classifier.py.",
    )


def _classify_flat_metadata(
    original: str,
    filename: str,
    stem_with_backup_stripped: str,
    *,
    location: str,
    draft_fallback_reason: str | None = None,
) -> dict[str, Any]:
    """Classify a flat file (one segment) at submissions/ or submissions/<status>/ root.
    Tracker stems route to tracker-file; everything else falls through to draft-file
    (or out-of-scope when the operator passed a non-file shape)."""
    p = Path(stem_with_backup_stripped)
    stem_lower = p.stem.lower()
    ext_lower = p.suffix.lower()
    if stem_lower in TRACKER_STEMS and ext_lower in TRACKER_EXTENSIONS:
        return _result(
            original,
            "tracker-file",
            requires_auth=False,
            reason=f"file '{filename}' lives flat in {location} and matches "
                   "tracker stem (SUBMISSIONS|README|TRACKER|INDEX); "
                   "auto-executable for metadata edits.",
        )
    # Fall through. At submissions/ root we treat as draft-file by default
    # because flat .md files there are usually legacy single-file drafts
    # (e.g. polymarket pre-R41 layout).
    fallback_reason = draft_fallback_reason or (
        f"file '{filename}' lives flat in {location} but does not match a "
        "tracker stem; treated as draft-file per L34 fall-through (operator "
        "auth REQUIRED). NB: R41 (Check #85) requires per-finding folders."
    )
    return _result(
        original,
        "draft-file",
        requires_auth=True,
        reason=fallback_reason,
    )


def _result(
    path: str,
    bucket: str,
    *,
    requires_auth: bool,
    reason: str,
) -> dict[str, Any]:
    return {
        "path": path,
        "bucket": bucket,
        "requires_per_draft_op_auth": requires_auth,
        "reason": reason,
    }


def _expand_glob(pattern: str, workspace: Path | None) -> list[str]:
    """Expand a glob pattern relative to workspace (or cwd if workspace is None).
    Returns a sorted list of unique matches; recursive ** is supported via the
    standard glob module."""
    if workspace is not None:
        # Use glob.glob with root_dir for relative patterns.
        if Path(pattern).is_absolute():
            matches = glob.glob(pattern, recursive=True)
        else:
            matches = glob.glob(
                str(workspace / pattern),
                recursive=True,
            )
    else:
        matches = glob.glob(pattern, recursive=True)
    return sorted(set(matches))


def _emit(records: list[dict[str, Any]], as_json: bool) -> None:
    payload = {
        "schema": SCHEMA,
        "tool_version": TOOL_VERSION,
        "results": records,
        "summary": _summarize(records),
    }
    if as_json:
        json.dump(payload, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
        return

    # Human-readable plaintext
    for rec in records:
        marker = "AUTH" if rec["requires_per_draft_op_auth"] else "auto"
        sys.stdout.write(f"[{marker}] {rec['bucket']:18s} {rec['path']}\n")
        sys.stdout.write(f"        {rec['reason']}\n")
    sys.stdout.write("\n")
    s = payload["summary"]
    sys.stdout.write(
        f"summary: {s['total']} path(s); "
        f"draft-file={s['draft_file']} (auth required), "
        f"tracker-file={s['tracker_file']}, "
        f"workspace-ledger={s['workspace_ledger']}, "
        f"lesson-anchor={s['lesson_anchor']}, "
        f"out-of-scope={s['out_of_scope']}\n"
    )


def _summarize(records: list[dict[str, Any]]) -> dict[str, int]:
    counts = {
        "total": len(records),
        "draft_file": 0,
        "tracker_file": 0,
        "workspace_ledger": 0,
        "lesson_anchor": 0,
        "out_of_scope": 0,
    }
    for rec in records:
        bucket = rec["bucket"].replace("-", "_")
        if bucket in counts:
            counts[bucket] += 1
    return counts


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "paths",
        nargs="*",
        help="One or more file paths to classify (positional).",
    )
    parser.add_argument(
        "--batch",
        nargs="+",
        default=None,
        help="Batch-classify multiple paths (alternative to positional).",
    )
    parser.add_argument(
        "--glob",
        default=None,
        help="Glob pattern to expand and classify (recursive ** supported).",
    )
    parser.add_argument(
        "--workspace",
        default=None,
        help="Workspace root for relative globs (default: cwd).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit structured JSON instead of human-readable text.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    # Aggregate paths from positional / --batch / --glob.
    paths: list[str] = []
    if args.paths:
        paths.extend(args.paths)
    if args.batch:
        paths.extend(args.batch)
    if args.glob:
        workspace = Path(args.workspace).expanduser() if args.workspace else None
        matches = _expand_glob(args.glob, workspace)
        if not matches:
            sys.stderr.write(f"l34-path-classifier: glob '{args.glob}' matched zero paths\n")
            return 2
        paths.extend(matches)

    if not paths:
        parser.print_usage(sys.stderr)
        sys.stderr.write("l34-path-classifier: no paths supplied\n")
        return 1

    records = [_classify_one(p) for p in paths]
    _emit(records, as_json=args.json)
    return 0


if __name__ == "__main__":
    sys.exit(main())
