#!/usr/bin/env python3
"""PR #726 Wave-1: create an annotated git tag marking the close of a Wave.

The tag annotation body bundles a deterministic corpus-stats snapshot plus
an explicit Wave-2 readiness verdict so the close-point is identifiable
forever (``git show wave-1-final`` shows shape histogram, total records,
hackerman_v1_total, quarantine total + a verdict line).

Design notes:

* Read-only against the working tree. Writes ONLY one annotated git ref
  (``refs/tags/<wave-name>``). Never pushes (operator decision).
* Idempotent: if the tag already exists and points at the current HEAD,
  the run is a no-op (status=already-present-same-sha). If it points
  elsewhere, the run REFUSES (status=already-present-different-sha, rc=2)
  unless ``--force`` is passed.
* The tag is ALWAYS annotated (``git tag -a``). Lightweight tags are
  rejected by Test #5 and would lose the corpus snapshot.
* Corpus stats are sourced by invoking ``tools/hackerman-corpus-stats.py
  --json --skip-gates`` in a subprocess. Gate subprocesses are skipped to
  keep the tag-close fast (gates are checked by ``make hackerman-all``
  before promoting a wave to ``-final``).
* Wave-2 readiness verdict is computed from the snapshot: PASS when
  ``total_records > 0`` AND ``hackerman_v1_total > 0`` AND there is at
  least one non-quarantine subtree; otherwise FAIL with a one-line reason.

Wired into Makefile as:

    make hackerman-tag-wave-close WAVE=wave-1-final

Exit codes:

  0  - tag created (or already present at this HEAD).
  2  - tag already exists pointing at a different SHA (and --force not set).
  3  - git tag invocation failed.
  4  - corpus-stats snapshot subprocess failed (annotation body would be
       incomplete; refuse to create a half-empty tag).
  5  - not a git repo / unable to resolve HEAD.

Schema: ``auditooor.hackerman_tag_wave_close.v1``.
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMA = "auditooor.hackerman_tag_wave_close.v1"
DEFAULT_WAVE = "wave-1-final"
WAVE_NAME_RE = re.compile(r"^wave-[0-9]+(?:-[a-z0-9]+)*$")


# ---------------------------------------------------------------------------
# Git helpers.
# ---------------------------------------------------------------------------


def _git_binary() -> str:
    """Resolve the real git binary. Honors ``AUDITOOOR_REAL_GIT`` so the tool
    works behind the MCP-gated git wrapper at ``~/.auditooor/bin/git`` (the
    wrapper rejects commit/push without a fresh recall token; this tool only
    invokes read-only sub-commands plus ``git tag``, which is not gated, but
    we still prefer the real binary for hermetic test reproduction)."""
    override = os.environ.get("AUDITOOOR_HACKERMAN_TAG_GIT")
    if override:
        return override
    real = os.environ.get("AUDITOOOR_REAL_GIT")
    if real and os.path.exists(real):
        return real
    if os.path.exists("/usr/bin/git"):
        return "/usr/bin/git"
    return "git"


def _git(args: list[str], cwd: Path) -> tuple[int, str, str]:
    """Run a git command. Returns (rc, stdout, stderr) - never raises."""
    try:
        proc = subprocess.run(
            [_git_binary(), *args],
            cwd=str(cwd),
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:  # noqa: BLE001
        return -1, "", f"git invocation failed: {exc}"
    return int(proc.returncode), proc.stdout or "", proc.stderr or ""


def resolve_head(repo: Path) -> tuple[str | None, str | None]:
    """Return (branch_name, head_sha) for the repo HEAD. Branch may be None
    if HEAD is detached."""
    rc, sha, _ = _git(["rev-parse", "HEAD"], repo)
    if rc != 0:
        return None, None
    head_sha = sha.strip() or None
    rc, br, _ = _git(["rev-parse", "--abbrev-ref", "HEAD"], repo)
    branch: str | None = None
    if rc == 0:
        b = br.strip()
        if b and b != "HEAD":
            branch = b
    return branch, head_sha


def tag_exists(repo: Path, tag: str) -> str | None:
    """If tag exists, return the SHA it points to (peeled); else None."""
    rc, out, _ = _git(["rev-parse", "--verify", "--quiet", f"refs/tags/{tag}^{{commit}}"], repo)
    if rc != 0:
        return None
    sha = out.strip()
    return sha or None


def tag_is_annotated(repo: Path, tag: str) -> bool:
    """``git cat-file -t refs/tags/<tag>`` returns 'tag' for annotated and
    'commit' for lightweight."""
    rc, out, _ = _git(["cat-file", "-t", f"refs/tags/{tag}"], repo)
    if rc != 0:
        return False
    return out.strip() == "tag"


# ---------------------------------------------------------------------------
# Corpus snapshot.
# ---------------------------------------------------------------------------


def collect_corpus_snapshot(
    repo: Path,
    *,
    stats_tool: Path | None = None,
    skip_corpus: bool = False,
) -> dict[str, Any]:
    """Invoke hackerman-corpus-stats in --json --skip-gates mode and return a
    summary dict. Returns ``{"status": "skipped"}`` if ``skip_corpus`` or the
    tool is missing - the annotation will still render but flag SKIPPED."""
    if skip_corpus:
        return {"status": "skipped", "reason": "skip-corpus flag"}
    tool = stats_tool or (repo / "tools" / "hackerman-corpus-stats.py")
    if not tool.is_file():
        return {"status": "skipped", "reason": f"stats tool missing: {tool}"}
    try:
        proc = subprocess.run(
            [sys.executable, str(tool), "--json", "--skip-gates"],
            cwd=str(repo),
            capture_output=True,
            text=True,
            check=False,
            timeout=180,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:  # noqa: BLE001
        return {"status": "error", "reason": f"subprocess failed: {exc}"}
    if proc.returncode != 0:
        return {
            "status": "error",
            "reason": f"stats tool exited rc={proc.returncode}",
            "stderr_tail": (proc.stderr or "")[-400:],
        }
    try:
        data = json.loads(proc.stdout)
    except (json.JSONDecodeError, ValueError) as exc:
        return {"status": "error", "reason": f"stats JSON parse failed: {exc}"}
    stats = data.get("stats") if isinstance(data, dict) else None
    if not isinstance(stats, dict):
        return {"status": "error", "reason": "stats payload missing 'stats' key"}
    quarantine_total = 0
    q = stats.get("quarantine")
    if isinstance(q, dict):
        quarantine_total = int(q.get("total") or 0)
    subtrees = stats.get("subtrees") or []
    non_quarantine_subtrees = 0
    if isinstance(subtrees, list):
        for row in subtrees:
            if not isinstance(row, dict):
                continue
            name = str(row.get("subtree") or "")
            if not name.startswith("_QUARANTINE_"):
                non_quarantine_subtrees += 1
    return {
        "status": "ok",
        "total_records": int(stats.get("total_records") or 0),
        "hackerman_v1_total": int(stats.get("hackerman_v1_total") or 0),
        "quarantine_total": quarantine_total,
        "non_quarantine_subtree_count": non_quarantine_subtrees,
        "shape_counts": stats.get("shape_counts") or {},
    }


# ---------------------------------------------------------------------------
# Wave-2 readiness verdict.
# ---------------------------------------------------------------------------


def wave2_readiness(snapshot: dict[str, Any]) -> tuple[str, str]:
    """Return (verdict, reason) where verdict in {READY, NOT-READY, UNKNOWN}."""
    status = str(snapshot.get("status") or "")
    if status == "skipped":
        return "UNKNOWN", f"corpus snapshot skipped: {snapshot.get('reason')}"
    if status == "error":
        return "UNKNOWN", f"corpus snapshot error: {snapshot.get('reason')}"
    total = int(snapshot.get("total_records") or 0)
    v1 = int(snapshot.get("hackerman_v1_total") or 0)
    sub = int(snapshot.get("non_quarantine_subtree_count") or 0)
    if total <= 0:
        return "NOT-READY", "total_records == 0"
    if v1 <= 0:
        return "NOT-READY", "hackerman_v1_total == 0"
    if sub <= 0:
        return "NOT-READY", "no non-quarantine subtrees"
    return "READY", (
        f"total_records={total} hackerman_v1_total={v1} "
        f"non_quarantine_subtrees={sub}"
    )


# ---------------------------------------------------------------------------
# Annotation body.
# ---------------------------------------------------------------------------


def _now_iso(override: str | None = None) -> str:
    if override:
        return override
    env = os.environ.get("AUDITOOOR_HACKERMAN_TAG_GENERATED_AT")
    if env:
        return env
    return datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")


def build_annotation(
    wave: str,
    branch: str | None,
    head_sha: str,
    snapshot: dict[str, Any],
    *,
    generated_at: str,
    pr_ref: str | None = None,
) -> str:
    """Render the multi-line annotated-tag message body."""
    verdict, reason = wave2_readiness(snapshot)
    lines: list[str] = []
    lines.append(f"{wave}: Wave close marker (schema {SCHEMA})")
    lines.append("")
    lines.append(f"generated_at: {generated_at}")
    lines.append(f"branch: {branch or '<detached>'}")
    lines.append(f"head_sha: {head_sha}")
    if pr_ref:
        lines.append(f"pr_ref: {pr_ref}")
    lines.append("")
    lines.append("## Corpus snapshot")
    status = str(snapshot.get("status") or "<missing>")
    lines.append(f"status: {status}")
    if status == "ok":
        lines.append(f"total_records: {snapshot.get('total_records')}")
        lines.append(f"hackerman_v1_total: {snapshot.get('hackerman_v1_total')}")
        lines.append(f"quarantine_total: {snapshot.get('quarantine_total')}")
        lines.append(
            f"non_quarantine_subtree_count: {snapshot.get('non_quarantine_subtree_count')}"
        )
        sc = snapshot.get("shape_counts") or {}
        if isinstance(sc, dict) and sc:
            parts = ", ".join(f"{k}={sc[k]}" for k in sorted(sc.keys()))
            lines.append(f"shape_counts: {parts}")
    else:
        lines.append(f"reason: {snapshot.get('reason') or '<missing>'}")
    lines.append("")
    lines.append("## Wave-2 readiness")
    lines.append(f"verdict: {verdict}")
    lines.append(f"reason: {reason}")
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Tag creation orchestration.
# ---------------------------------------------------------------------------


def create_tag(
    repo: Path,
    wave: str,
    annotation: str,
    *,
    target_sha: str,
    force: bool = False,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Drive ``git tag -a <wave> -m <annotation> <target_sha>`` and return a
    structured result. Idempotent on same-SHA. Refuses different-SHA without
    ``force``."""
    existing = tag_exists(repo, wave)
    if existing == target_sha:
        return {
            "status": "already-present-same-sha",
            "tag": wave,
            "target_sha": target_sha,
            "rc": 0,
        }
    if existing is not None and not force:
        return {
            "status": "already-present-different-sha",
            "tag": wave,
            "existing_sha": existing,
            "target_sha": target_sha,
            "rc": 2,
        }
    if dry_run:
        return {
            "status": "dry-run",
            "tag": wave,
            "target_sha": target_sha,
            "rc": 0,
        }
    # ``--cleanup=verbatim`` preserves ``#``-prefixed lines (markdown
    # headings) which the default ``strip`` mode otherwise removes; the
    # corpus snapshot + Wave-2 readiness sections rely on those headings.
    args = ["tag", "-a", "--cleanup=verbatim", wave, "-m", annotation, target_sha]
    if force and existing is not None:
        # ``-f`` to overwrite existing.
        args = ["tag", "-a", "-f", "--cleanup=verbatim", wave, "-m", annotation, target_sha]
    rc, _, stderr = _git(args, repo)
    if rc != 0:
        return {
            "status": "git-tag-failed",
            "tag": wave,
            "rc": 3,
            "stderr_tail": stderr[-400:],
        }
    if not tag_is_annotated(repo, wave):
        return {
            "status": "created-but-not-annotated",
            "tag": wave,
            "rc": 3,
        }
    return {
        "status": "created",
        "tag": wave,
        "target_sha": target_sha,
        "rc": 0,
    }


# ---------------------------------------------------------------------------
# CLI.
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="hackerman-tag-wave-close")
    parser.add_argument(
        "--wave-name",
        default=DEFAULT_WAVE,
        help=f"Annotated-tag name to create (default: {DEFAULT_WAVE}).",
    )
    parser.add_argument(
        "--repo",
        type=Path,
        default=REPO_ROOT,
        help="Repository root (default: this tool's repo root).",
    )
    parser.add_argument(
        "--pr-ref",
        default=None,
        help="Optional PR reference to include in the annotation body (e.g. PR #726).",
    )
    parser.add_argument(
        "--generated-at",
        default=None,
        help="Override the generated_at timestamp.",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite an existing tag pointing at a different SHA.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Compute everything but do not write the tag.",
    )
    parser.add_argument(
        "--skip-corpus",
        action="store_true",
        help="Skip the corpus-stats subprocess (annotation will note SKIPPED).",
    )
    parser.add_argument(
        "--stats-tool",
        type=Path,
        default=None,
        help="Override path to hackerman-corpus-stats.py (mainly for tests).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit a JSON result envelope instead of plain text.",
    )
    args = parser.parse_args(argv)

    wave = args.wave_name.strip()
    if not WAVE_NAME_RE.match(wave):
        sys.stderr.write(
            f"[hackerman-tag-wave-close] invalid wave name {wave!r}; "
            "expected pattern ^wave-[0-9]+(-[a-z0-9]+)*$\n"
        )
        return 2

    repo = args.repo.resolve()
    if not (repo / ".git").exists():
        sys.stderr.write(f"[hackerman-tag-wave-close] not a git repo: {repo}\n")
        return 5

    branch, head_sha = resolve_head(repo)
    if not head_sha:
        sys.stderr.write("[hackerman-tag-wave-close] unable to resolve HEAD\n")
        return 5

    snapshot = collect_corpus_snapshot(
        repo, stats_tool=args.stats_tool, skip_corpus=args.skip_corpus
    )
    if snapshot.get("status") == "error" and not args.skip_corpus:
        sys.stderr.write(
            f"[hackerman-tag-wave-close] corpus snapshot error: {snapshot.get('reason')}\n"
        )
        return 4

    generated_at = _now_iso(args.generated_at)
    annotation = build_annotation(
        wave,
        branch,
        head_sha,
        snapshot,
        generated_at=generated_at,
        pr_ref=args.pr_ref,
    )

    result = create_tag(
        repo,
        wave,
        annotation,
        target_sha=head_sha,
        force=args.force,
        dry_run=args.dry_run,
    )

    verdict, reason = wave2_readiness(snapshot)
    envelope = {
        "schema": SCHEMA,
        "generated_at": generated_at,
        "wave": wave,
        "branch": branch,
        "head_sha": head_sha,
        "pr_ref": args.pr_ref,
        "tag_result": result,
        "wave2_readiness": {"verdict": verdict, "reason": reason},
        "annotation_body": annotation,
        "corpus_snapshot": snapshot,
    }

    if args.json:
        sys.stdout.write(json.dumps(envelope, indent=2, sort_keys=True) + "\n")
    else:
        sys.stdout.write(
            f"[hackerman-tag-wave-close] wave={wave} status={result['status']} "
            f"head={head_sha[:12]} verdict={verdict}\n"
        )
        if result["status"] in {"created", "already-present-same-sha", "dry-run"}:
            sys.stdout.write(annotation)
        else:
            sys.stdout.write(
                f"reason: {result.get('stderr_tail') or result.get('existing_sha') or result.get('status')}\n"
            )

    return int(result.get("rc") or 0)


if __name__ == "__main__":
    raise SystemExit(main())
