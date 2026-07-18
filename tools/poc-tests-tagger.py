#!/usr/bin/env python3
"""PoC artifact retention tagger - write .poc-status sentinels in audit
workspace poc-tests/ directories so future agents and the operator can
classify, retain, or gc PoC dirs without re-deriving their disposition
from scratch.

Background
----------
Audit workspaces accumulate `poc-tests/<finding-slug>/` directories at
the same rate they accumulate `submissions/<status>/<slug>/` drafts. A
filed Critical leaves a runnable harness; a killed-as-dupe leaves an
engineering record that is no longer load-bearing; a dropped-OOS leaves
artifacts that can be garbage-collected. Without a sentinel, every new
agent must re-walk `submissions/<status>/` and grep transcripts to
classify each PoC dir - wasted cycles AND a missed-retention risk
(killed PoCs occupy disk indefinitely).

This tool writes `<poc-tests/<slug>/.poc-status` JSON sentinels with the
schema `auditooor.poc_status.v1`. The classifier walks the workspace's
`submissions/<status>/` tree once and emits one sentinel per PoC dir.

Status enum
-----------
- ``filed-evidence`` - the PoC backs a filed (or paste_ready / packaged /
  ready - in-flight) submission. Retain forever. The PoC is load-bearing
  for the on-chain dispute / verification record.
- ``engineering-record`` - the PoC has a staging draft (in-progress) OR
  no submission match (legacy / scratch). Retain for now; reclassify on
  next promotion cycle.
- ``dropped`` - the PoC backs a `_killed` or `_oos_rejected` submission.
  Eligible for GC after the configured TTL.
- ``superseded`` - explicit operator tag for a PoC that has been replaced
  by a sibling V3-grade rebuild. Never auto-classified; set via
  ``--status superseded --slug ...``.

Slug normalization
------------------
PoC directory names use dashes (``arbitrum_orbit_unconfirmed_node`` or
``arbitrum-orbit-unconfirmed-node``) while submission folders typically
have a workspace-prefix (``hb-`` / ``ds-`` / ``sp-``) and a SEVERITY
suffix (``-HIGH`` / ``-MEDIUM`` / ``-KILLED-...``). The classifier
normalizes by:

  1. Replacing underscores with dashes (or vice versa) on the PoC dir.
  2. Stripping common workspace prefixes from submission dirs.
  3. Stripping severity / status suffixes from submission dirs.
  4. Checking whether the normalized PoC dir name is a SUBSTRING of the
     normalized submission dir name (or vice versa).

This is intentionally permissive: false positives produce a richer
classification than false negatives, and the operator can override with
``--status <enum> --slug <name>`` for any edge case.

Usage
-----
    # Auto-classify every poc-tests/ dir against submissions/.
    python3 tools/poc-tests-tagger.py --workspace ~/audits/hyperbridge --auto-classify

    # Explicit per-slug tag (overrides any auto classification).
    python3 tools/poc-tests-tagger.py --workspace ~/audits/hyperbridge \\
        --status superseded --slug univ3_univ4_wrapper_refund

    # GC dry-run (default; reports what WOULD be removed).
    python3 tools/poc-tests-tagger.py --workspace ~/audits/hyperbridge \\
        --gc-dropped --older-than 30d

    # GC with --confirm to actually rm -rf.
    python3 tools/poc-tests-tagger.py --workspace ~/audits/hyperbridge \\
        --gc-dropped --older-than 30d --confirm

Sentinel shape (``.poc-status`` JSON)
-------------------------------------
    {
      "schema": "auditooor.poc_status.v1",
      "status": "filed-evidence" | "engineering-record" | "dropped" | "superseded",
      "finding_slug": "<dir-name>",
      "classified_at": "2026-05-25T18:52:34Z",
      "cross_reference": "submissions/filed/hb-arbitrum-orbit-unconfirmed-node-HIGH",
      "classification_mode": "auto" | "explicit"
    }

Exit codes
----------
  0 - operation succeeded (classification or GC).
  1 - workspace missing or malformed inputs.
  2 - clobber refusal without --force (existing .poc-status present).
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA = "auditooor.poc_status.v1"
TOOL_VERSION = "1.0.0"

# Status values are a closed enum; we refuse any other string.
VALID_STATUSES = frozenset({
    "filed-evidence",
    "engineering-record",
    "dropped",
    "superseded",
})

# Submission status dirs that map to each classification.
# Order matters for ambiguity tie-breaks: filed > paste_ready > ready /
# packaged > staging > _killed / _oos_rejected.
STATUS_TO_CLASS = (
    ("filed", "filed-evidence"),
    ("paste_ready", "filed-evidence"),
    ("ready", "filed-evidence"),
    ("packaged", "filed-evidence"),
    ("submitted", "filed-evidence"),
    ("staging", "engineering-record"),
    ("held", "engineering-record"),
    ("superseded", "superseded"),
    ("_killed", "dropped"),
    ("_oos_rejected", "dropped"),
    ("_pre_rejected", "dropped"),
)

# Workspace-prefix patterns commonly seen on submission folders. We
# strip these BEFORE doing substring matching against PoC dir names.
WORKSPACE_PREFIX_RE = re.compile(r"^(hb|ds|sp|dy|pm|tg|mz|az|hy)-", re.IGNORECASE)

# Severity / status suffix patterns commonly appended to submission
# folder names. We strip these BEFORE substring matching.
SEVERITY_SUFFIX_RE = re.compile(
    r"-(?:CRITICAL|HIGH|MEDIUM|LOW|INFO|INFORMATIONAL|"
    r"KILLED(?:-[A-Za-z0-9_.\-]+)?|"
    r"OOS|REJECTED|DUPE(?:-[A-Za-z0-9_.\-]+)?|"
    r"SHORT|V[0-9]+|FINAL|DRAFT)$",
    re.IGNORECASE,
)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _norm_slug(name: str) -> str:
    """Lower-case, underscore->dash normalization."""
    return name.lower().replace("_", "-").strip("-")


def _strip_submission_decorations(name: str) -> str:
    """Strip workspace prefix and severity / status suffix from a submission
    folder name so the remaining stem can be substring-matched against PoC
    dir names. Order: strip prefix first, then iteratively strip suffixes
    until none match.
    """
    stem = _norm_slug(name)
    stem = WORKSPACE_PREFIX_RE.sub("", stem, count=1)
    # The suffix RE may apply multiple times (e.g. ``foo-KILLED-dupe-X``
    # has a KILLED-... suffix, but stripping leaves ``foo`` which is
    # already clean). Iterate until stable.
    while True:
        new_stem = SEVERITY_SUFFIX_RE.sub("", stem, count=1)
        if new_stem == stem:
            break
        stem = new_stem
    return stem


def parse_duration(spec: str) -> int:
    """Parse strings like ``30d``, ``12h``, ``45m``, ``900s`` -> seconds."""
    match = re.fullmatch(r"(\d+)([smhd])", spec.strip().lower())
    if not match:
        raise ValueError(
            f"invalid duration {spec!r}; expected <int>{{s|m|h|d}}"
        )
    value, unit = int(match.group(1)), match.group(2)
    return {"s": value, "m": value * 60, "h": value * 3600, "d": value * 86400}[unit]


class Workspace:
    """Helper wrapping a single audit workspace."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.poc_dir = root / "poc-tests"
        self.submissions_dir = root / "submissions"

    def validate(self) -> str | None:
        if not self.root.exists():
            return f"workspace not found: {self.root}"
        if not self.poc_dir.exists():
            return f"poc-tests/ not found under workspace: {self.poc_dir}"
        return None

    def poc_subdirs(self) -> list[Path]:
        if not self.poc_dir.exists():
            return []
        out: list[Path] = []
        for child in sorted(self.poc_dir.iterdir()):
            if not child.is_dir():
                continue
            # Skip hidden dirs (e.g. .git, .pytest_cache).
            if child.name.startswith("."):
                continue
            out.append(child)
        return out

    def submission_subdirs(self, status: str) -> list[Path]:
        status_root = self.submissions_dir / status
        if not status_root.exists():
            return []
        return [
            child
            for child in sorted(status_root.iterdir())
            if child.is_dir() and not child.name.startswith(".")
        ]


def _match_poc_to_submission(
    poc_name: str, submission_name: str
) -> bool:
    """Decide whether a PoC dir name matches a submission folder name
    after slug normalization.
    """
    poc_norm = _norm_slug(poc_name)
    sub_norm = _strip_submission_decorations(submission_name)
    if not poc_norm or not sub_norm:
        return False
    # Exact match after normalization.
    if poc_norm == sub_norm:
        return True
    # Substring match - PoC name is a token-prefix of the submission
    # stem (or vice versa). This covers cases where the PoC dir uses a
    # shorter form (``optimism_l2oracle_unfinalized_output``) and the
    # submission has a longer descriptive suffix.
    if poc_norm in sub_norm:
        return True
    if sub_norm in poc_norm:
        return True
    return False


def classify_poc(
    workspace: Workspace, poc_dir: Path
) -> tuple[str, str | None]:
    """Auto-classify a single PoC dir.

    Returns ``(status, cross_reference_relpath)`` where ``status`` is
    one of the four enum values and ``cross_reference_relpath`` is
    relative to the workspace root (or None if no match found).
    """
    poc_name = poc_dir.name
    for status_dir, classification in STATUS_TO_CLASS:
        for candidate in workspace.submission_subdirs(status_dir):
            if _match_poc_to_submission(poc_name, candidate.name):
                rel = candidate.relative_to(workspace.root)
                return classification, str(rel)
    # No match - this is the legacy / scratch case.
    return "engineering-record", None


def write_sentinel(
    poc_dir: Path,
    *,
    status: str,
    cross_reference: str | None,
    mode: str,
    force: bool = False,
) -> tuple[bool, str]:
    """Write the ``.poc-status`` sentinel into ``poc_dir``.

    Returns ``(written, message)``. If a sentinel already exists and
    ``force`` is False, returns ``(False, "exists")`` so the caller can
    skip without clobbering.
    """
    if status not in VALID_STATUSES:
        raise ValueError(
            f"invalid status {status!r}; want one of {sorted(VALID_STATUSES)}"
        )
    sentinel = poc_dir / ".poc-status"
    if sentinel.exists() and not force:
        return False, "exists"
    payload = {
        "schema": SCHEMA,
        "status": status,
        "finding_slug": poc_dir.name,
        "classified_at": utc_now_iso(),
        "cross_reference": cross_reference,
        "classification_mode": mode,
        "tool_version": TOOL_VERSION,
    }
    sentinel.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    return True, "written"


def read_sentinel(poc_dir: Path) -> dict[str, Any] | None:
    sentinel = poc_dir / ".poc-status"
    if not sentinel.exists():
        return None
    try:
        return json.loads(sentinel.read_text())
    except (json.JSONDecodeError, OSError):
        return None


def cmd_auto_classify(args: argparse.Namespace) -> int:
    workspace = Workspace(Path(args.workspace).expanduser().resolve())
    err = workspace.validate()
    if err:
        print(f"error: {err}", file=sys.stderr)
        return 1

    results: list[dict[str, Any]] = []
    for poc_dir in workspace.poc_subdirs():
        status, cross_ref = classify_poc(workspace, poc_dir)
        written, message = write_sentinel(
            poc_dir,
            status=status,
            cross_reference=cross_ref,
            mode="auto",
            force=args.force,
        )
        results.append({
            "slug": poc_dir.name,
            "status": status,
            "cross_reference": cross_ref,
            "written": written,
            "message": message,
        })

    if args.json:
        print(json.dumps({
            "schema": SCHEMA + ".batch",
            "workspace": str(workspace.root),
            "tool_version": TOOL_VERSION,
            "total": len(results),
            "results": results,
        }, indent=2, sort_keys=True))
    else:
        for rec in results:
            tag = "WROTE" if rec["written"] else f"SKIP ({rec['message']})"
            print(
                f"{tag:18} {rec['status']:20} {rec['slug']:50} "
                f"<- {rec['cross_reference'] or '(no match)'}"
            )
        print(
            f"\nTotal: {len(results)} dir(s); "
            f"{sum(1 for r in results if r['written'])} new sentinel(s) written."
        )
    return 0


def cmd_explicit_tag(args: argparse.Namespace) -> int:
    workspace = Workspace(Path(args.workspace).expanduser().resolve())
    err = workspace.validate()
    if err:
        print(f"error: {err}", file=sys.stderr)
        return 1
    if args.status not in VALID_STATUSES:
        print(
            f"error: invalid --status {args.status!r}; "
            f"want one of {sorted(VALID_STATUSES)}",
            file=sys.stderr,
        )
        return 1
    poc_dir = workspace.poc_dir / args.slug
    if not poc_dir.exists():
        print(
            f"error: poc-tests dir not found: {poc_dir}",
            file=sys.stderr,
        )
        return 1
    written, message = write_sentinel(
        poc_dir,
        status=args.status,
        cross_reference=None,
        mode="explicit",
        force=args.force,
    )
    if not written and message == "exists":
        print(
            f"error: .poc-status already present at {poc_dir}; "
            f"re-run with --force to overwrite.",
            file=sys.stderr,
        )
        return 2
    print(f"WROTE {args.status:20} {args.slug}")
    return 0


def cmd_gc_dropped(args: argparse.Namespace) -> int:
    workspace = Workspace(Path(args.workspace).expanduser().resolve())
    err = workspace.validate()
    if err:
        print(f"error: {err}", file=sys.stderr)
        return 1
    try:
        ttl_seconds = parse_duration(args.older_than)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    cutoff = time.time() - ttl_seconds

    to_remove: list[tuple[Path, dict[str, Any], float]] = []
    skipped: list[tuple[Path, str]] = []
    for poc_dir in workspace.poc_subdirs():
        sentinel_data = read_sentinel(poc_dir)
        if sentinel_data is None:
            skipped.append((poc_dir, "no .poc-status sentinel"))
            continue
        if sentinel_data.get("status") != "dropped":
            skipped.append((poc_dir, f"status={sentinel_data.get('status')}"))
            continue
        # Use the sentinel's mtime as the dropped-at timestamp.
        sentinel_path = poc_dir / ".poc-status"
        mtime = sentinel_path.stat().st_mtime
        if mtime > cutoff:
            skipped.append((poc_dir, f"mtime newer than {args.older_than} cutoff"))
            continue
        to_remove.append((poc_dir, sentinel_data, mtime))

    mode = "DRY-RUN" if not args.confirm else "REMOVE"
    # Perform the destructive op FIRST (if --confirm) so both output
    # modes report the same post-state. Capture removed dirs for the
    # report.
    removed_paths: list[str] = []
    if args.confirm:
        for poc_dir, _, _ in to_remove:
            shutil.rmtree(poc_dir)
            removed_paths.append(str(poc_dir))

    if args.json:
        print(json.dumps({
            "schema": SCHEMA + ".gc",
            "workspace": str(workspace.root),
            "tool_version": TOOL_VERSION,
            "mode": mode,
            "older_than": args.older_than,
            "to_remove": [
                {
                    "slug": p.name,
                    "path": str(p),
                    "mtime_unix": int(m),
                    "status": d.get("status"),
                }
                for p, d, m in to_remove
            ],
            "removed": removed_paths,
            "skipped": [{"slug": p.name, "reason": r} for p, r in skipped],
        }, indent=2, sort_keys=True))
    else:
        for poc_dir, sentinel_data, mtime in to_remove:
            age_days = (time.time() - mtime) / 86400
            print(
                f"{mode:10} {poc_dir.name:50} "
                f"age={age_days:.1f}d status=dropped"
            )
        if not to_remove:
            print(f"({mode}) no dirs eligible for gc")
        for removed in removed_paths:
            print(f"removed: {removed}")
        print(
            f"\nTotal: {len(to_remove)} dir(s) eligible; "
            f"{len(skipped)} skipped."
        )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Write or garbage-collect .poc-status sentinels in an audit "
            "workspace poc-tests/ tree."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--workspace",
        required=True,
        help="Path to audit workspace (e.g. ~/audits/hyperbridge).",
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--auto-classify",
        action="store_true",
        help=(
            "Walk every poc-tests/<slug>/ dir and write a .poc-status "
            "sentinel by cross-referencing submissions/<status>/<slug>/."
        ),
    )
    mode.add_argument(
        "--status",
        choices=sorted(VALID_STATUSES),
        help="Explicit status to tag a single PoC dir; pair with --slug.",
    )
    mode.add_argument(
        "--gc-dropped",
        action="store_true",
        help=(
            "Garbage-collect poc-tests/<slug>/ dirs whose .poc-status is "
            "'dropped' and older than --older-than. Default --dry-run."
        ),
    )
    parser.add_argument(
        "--slug",
        help="PoC dir name (required when using --status).",
    )
    parser.add_argument(
        "--older-than",
        default="30d",
        help="GC TTL (default: 30d). Format: <int>{s|m|h|d}.",
    )
    parser.add_argument(
        "--confirm",
        action="store_true",
        help="Actually delete in --gc-dropped mode (default is dry-run).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help=(
            "No-op for --gc-dropped (already the default). Present for "
            "operator self-documentation."
        ),
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing .poc-status sentinels.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON instead of human-readable text.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.status is not None:
        if not args.slug:
            print(
                "error: --status requires --slug <name>",
                file=sys.stderr,
            )
            return 1
        return cmd_explicit_tag(args)
    if args.auto_classify:
        return cmd_auto_classify(args)
    if args.gc_dropped:
        return cmd_gc_dropped(args)
    print("error: no mode selected", file=sys.stderr)  # pragma: no cover
    return 1


if __name__ == "__main__":
    sys.exit(main())
