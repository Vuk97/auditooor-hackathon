#!/usr/bin/env python3
"""llm-pr-review-merge-hook.py — auto-grade dual-LLM PR reviews on merge.

Background
----------
``tools/llm-pr-review.py`` (PR #179) posts a Kimi+Minimax dual-review comment
on every PR. ``tools/llm-calibration-log.py`` (PR #187) tracks per-(provider,
task_type, task_ref, verdict) accuracy. Today the supervisor (Claude) has to
hand-call ``llm-calibration-log.py log <provider> pr-review "PR #N" TRUE``
after every merged PR. PR #198 backfilled missed sessions after-the-fact by
parsing PR comments.

This hook closes the loop: parse the dual-review comment, observe the merge
state, and append a row per provider to the calibration ledger automatically.

Grading rule
------------
- AGREED-MERGE-OK + PR merged              -> both providers TRUE
- AGREED-NEEDS-FIX + PR merged              -> both providers TRUE
                                               (consensus correctly flagged
                                                + the fix shipped)
- AGREED-NEEDS-REWORK + PR merged           -> both providers TRUE
- AGREED-OFF-SCOPE + PR merged              -> both providers TRUE
                                               (consensus flagged scope, fix shipped)
- DISAGREED + PR merged unchanged           -> the MERGE-OK voter is TRUE,
                                               the NEEDS-* voter is FALSE
                                               (merged-as-is means the
                                               flagged issue was either
                                               absent or accepted)
- DISAGREED + PR merged AFTER fix-up commit -> the NEEDS-* voter is TRUE,
                                               the MERGE-OK voter is FALSE
                                               (fix-up = flag was right)
                                               *Heuristic: more than 1 commit
                                                between review-comment and
                                                merge.*

  CAVEAT for the DISAGREED-merged-as-is branch: a PR can merge WITH a real
  bug that the maintainer chose to ship anyway (deferred follow-up). The
  fix-up heuristic cannot detect this case — the resulting grade will mark
  the NEEDS-* voter FALSE when humans would mark them TRUE. The supervisor
  can override by manually appending a fresh row with the same
  (provider, task_ref); ``_dedupe_keep_latest`` in
  ``tools/llm-calibration-log.py`` makes the latest row authoritative.
  This is also why the hook is idempotent on (provider, task_ref) by
  default — manually-corrected rows survive re-runs.
- Closed unmerged                           -> both INDETERMINATE
- Open / no review comment                  -> skipped

Subcommands
-----------
    process <PR#> [--ledger PATH] [--dry-run]
        Fetch a single PR + comments, find the dual-LLM review comment, log
        outcomes (one row per provider).

    process-recent [--since DATE] [--limit N] [--ledger PATH] [--dry-run]
        Process every merged PR since DATE (YYYY-MM-DD or ISO-8601). DATE
        defaults to 7 days ago. Skips PRs already present in the ledger
        for the same (provider, task_ref) pair so re-runs are idempotent.

Hard rules
----------
- Stdlib only (argparse, json, re, subprocess, importlib).
- READ-ONLY on PR data; WRITE-ONLY on the ledger.
- No PR mutation, no comment posting, no merge actions.
- Idempotent: re-processing a PR does not double-log if a row with the same
  ``(provider, task_ref)`` already exists.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import pathlib
import re
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from typing import Any

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
CALIBRATION_TOOL = REPO_ROOT / "tools" / "llm-calibration-log.py"

# Verdict categories used by tools/llm-pr-review.py.
VERDICT_TOKENS = ("MERGE-OK", "NEEDS-FIX", "NEEDS-REWORK", "OFF-SCOPE")

# Match a per-provider verdict line in either the legacy comment format
# (``**Kimi K2.6 verdict:** ... VERDICT: MERGE-OK``) or the new format
# (``### Kimi: `MERGE-OK` ``). The PROVIDER group is normalised lowercase.
PROVIDER_VERDICT_RES = (
    # New format: "### Kimi: `MERGE-OK`" / "### Minimax: `NEEDS-FIX`"
    re.compile(
        r"###\s+(?P<provider>Kimi|Minimax)\s*:\s*`(?P<verdict>"
        r"MERGE-OK|NEEDS-FIX|NEEDS-REWORK|OFF-SCOPE)`",
        re.IGNORECASE,
    ),
    # Legacy format: "**Kimi K2.6 verdict:**\n```\nVERDICT: MERGE-OK\n...".
    # Search up to ~400 chars after the provider header (covers a fenced
    # block). DOTALL so `.` crosses newlines; non-greedy so we stop at the
    # first VERDICT line in this block.
    re.compile(
        r"\*\*(?P<provider>Kimi|Minimax)[^\n]*verdict[^\n]*\*\*"
        r".{0,400}?VERDICT\s*:\s*(?P<verdict>"
        r"MERGE-OK|NEEDS-FIX|NEEDS-REWORK|OFF-SCOPE)",
        re.IGNORECASE | re.DOTALL,
    ),
)

# Match the consensus tag. Both formats share the literal "**Consensus:**"
# (the colon is *inside* the bold). The verdict that follows may be
# unfenced (legacy: "AGREED-MERGE") or backtick-fenced (new:
# "`AGREED-MERGE-OK`").
CONSENSUS_RE = re.compile(
    r"\*\*Consensus:\*\*\s*`?(?P<consensus>"
    r"AGREED-MERGE-OK|AGREED-MERGE|AGREED-NEEDS-FIX|AGREED-NEEDS-REWORK|"
    r"AGREED-OFF-SCOPE|DISAGREED|LLM-FAILURE)`?",
    re.IGNORECASE,
)

# Hint that a comment is one of the dual-LLM review comments. Keep this
# permissive — the per-provider regex is the authoritative parse.
REVIEW_COMMENT_MARKERS = (
    "Multi-LLM review",
    "Dual-LLM PR Review",
    "Dual-LLM Review",
)


# ---------------------------------------------------------------------------
# Calibration-tool import (hyphenated filename -> importlib)
# ---------------------------------------------------------------------------

def _load_calibration_module():
    """Load tools/llm-calibration-log.py as a module via importlib."""
    cache_key = "_llm_pr_review_merge_hook_calibration"
    if cache_key in sys.modules:
        return sys.modules[cache_key]
    if not CALIBRATION_TOOL.is_file():
        raise FileNotFoundError(
            f"required dependency missing: {CALIBRATION_TOOL}"
        )
    spec = importlib.util.spec_from_file_location(cache_key, CALIBRATION_TOOL)
    if spec is None or spec.loader is None:
        raise ImportError(f"could not load spec for {CALIBRATION_TOOL}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[cache_key] = mod
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------
# Comment parsing
# ---------------------------------------------------------------------------

def find_review_comment(comments: list[dict]) -> dict | None:
    """Return the first dual-LLM-review comment, or None.

    A "review comment" is one whose body matches at least one provider
    verdict regex AND contains a ``**Consensus**`` line. We pick the
    EARLIEST such comment so subsequent re-runs of the dispatcher don't
    overwrite the original verdict pair (the reviewer-of-record).
    """
    candidates = []
    for c in comments:
        body = c.get("body", "") or ""
        if not any(m in body for m in REVIEW_COMMENT_MARKERS):
            # Permissive fallback: accept if at least one provider regex hits
            # AND a consensus line is present.
            if not CONSENSUS_RE.search(body):
                continue
            if not any(r.search(body) for r in PROVIDER_VERDICT_RES):
                continue
        if not CONSENSUS_RE.search(body):
            continue
        if not any(r.search(body) for r in PROVIDER_VERDICT_RES):
            continue
        candidates.append(c)
    if not candidates:
        return None
    # Pick earliest by createdAt where available; fall back to list order.
    def _key(c):
        return c.get("createdAt") or ""
    return sorted(candidates, key=_key)[0]


def parse_review_comment(body: str) -> dict[str, Any]:
    """Extract verdicts + consensus from a review-comment body.

    Returns a dict with::

        {
          "kimi": "MERGE-OK" | "NEEDS-FIX" | ... | None,
          "minimax": "MERGE-OK" | ... | None,
          "consensus": "AGREED-MERGE-OK" | "DISAGREED" | ... | None,
        }

    Provider keys are always lowercase. ``None`` values mean "not parsed";
    callers should treat them as INDETERMINATE for grading.
    """
    out: dict[str, Any] = {"kimi": None, "minimax": None, "consensus": None}
    for regex in PROVIDER_VERDICT_RES:
        for m in regex.finditer(body):
            prov = m.group("provider").lower()
            verdict = m.group("verdict").upper()
            # First-match-wins per provider (legacy regex may match before
            # the new regex; we don't want a later block to clobber).
            if out.get(prov) is None:
                out[prov] = verdict
    cm = CONSENSUS_RE.search(body)
    if cm:
        cons = cm.group("consensus").upper()
        # Normalise legacy "AGREED-MERGE" -> "AGREED-MERGE-OK" so downstream
        # logic doesn't have to special-case it.
        if cons == "AGREED-MERGE":
            cons = "AGREED-MERGE-OK"
        out["consensus"] = cons
    return out


# ---------------------------------------------------------------------------
# Grading
# ---------------------------------------------------------------------------

def grade_outcome(
    parsed: dict[str, Any],
    pr_state: str,
    fix_up_after_review: bool = False,
) -> dict[str, str]:
    """Score per-provider verdicts against the merge outcome.

    Args:
      parsed: output of :func:`parse_review_comment`.
      pr_state: "MERGED", "CLOSED", or "OPEN".
      fix_up_after_review: True when extra commits landed AFTER the
        review-comment timestamp (heuristic: flag-was-right).

    Returns:
      ``{"kimi": "TRUE"|"FALSE"|"INDETERMINATE", "minimax": ...}``

    Open PRs => both INDETERMINATE (outcome not decided yet).
    Closed-unmerged PRs => both INDETERMINATE (flag may have been right
    OR scope-rejected; can't grade mechanically).
    """
    state = (pr_state or "").upper()
    if state != "MERGED":
        # OPEN or CLOSED-unmerged: cannot grade.
        return {"kimi": "INDETERMINATE", "minimax": "INDETERMINATE"}

    consensus = parsed.get("consensus")
    kimi = parsed.get("kimi")
    minimax = parsed.get("minimax")

    def _verdict(prov_verdict: str | None, is_correct: bool) -> str:
        if prov_verdict is None:
            return "INDETERMINATE"
        return "TRUE" if is_correct else "FALSE"

    if consensus is None:
        # No consensus line parsed -> can't grade.
        return {"kimi": "INDETERMINATE", "minimax": "INDETERMINATE"}

    if consensus.startswith("AGREED-"):
        # Both agreed on the same verdict; merge happened (or merge-with-fix
        # for NEEDS-FIX). In both cases the agreed-on call was confirmed.
        return {
            "kimi": _verdict(kimi, True),
            "minimax": _verdict(minimax, True),
        }

    if consensus == "DISAGREED":
        # Whichever side aligned with the merge state is TRUE; the other is
        # FALSE. "Aligned with merge state" =
        #   * merged-as-is  -> MERGE-OK voter was right
        #   * merged-after-fix -> NEEDS-* voter was right
        merge_ok_is_correct = not fix_up_after_review
        kimi_correct = (kimi == "MERGE-OK") == merge_ok_is_correct
        minimax_correct = (minimax == "MERGE-OK") == merge_ok_is_correct
        # Special case: an UNPARSED side stays INDETERMINATE.
        return {
            "kimi": _verdict(kimi, kimi_correct),
            "minimax": _verdict(minimax, minimax_correct),
        }

    # LLM-FAILURE or unknown consensus -> can't grade mechanically.
    return {"kimi": "INDETERMINATE", "minimax": "INDETERMINATE"}


# ---------------------------------------------------------------------------
# gh helpers (subprocess wrappers; tests stub these)
# ---------------------------------------------------------------------------

def _gh_json(args: list[str]) -> Any:
    """Run a `gh` command expected to return JSON. Raises on failure."""
    proc = subprocess.run(
        ["gh", *args],
        capture_output=True,
        text=True,
        timeout=60,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"gh {' '.join(args)} failed: {proc.stderr.strip()}")
    return json.loads(proc.stdout)


def fetch_pr(number: int) -> dict:
    """Return the PR meta + comments + commits as a dict.

    Read-only. Pulls the fields the hook needs in one shot to keep API usage
    minimal.
    """
    return _gh_json([
        "pr", "view", str(number),
        "--json", "number,state,mergedAt,comments,commits",
    ])


def list_recent_merged(since_iso: str, limit: int = 200) -> list[dict]:
    """Return PRs merged at-or-after ``since_iso``.

    ``gh pr list --search "merged:>=DATE"`` filters server-side. The list is
    sorted newest-first by GitHub's default; we leave that ordering intact.
    """
    return _gh_json([
        "pr", "list",
        "--state", "merged",
        "--limit", str(limit),
        "--search", f"merged:>={since_iso[:10]}",
        "--json", "number,title,mergedAt",
    ])


# ---------------------------------------------------------------------------
# Fix-up detection
# ---------------------------------------------------------------------------

def _parse_iso(ts: str | None) -> datetime | None:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None


def detect_fix_up(pr_data: dict, review_comment: dict) -> bool:
    """Return True if commits landed AFTER the review-comment timestamp.

    Heuristic for the DISAGREED grading branch: if the maintainer pushed
    additional commits AFTER the dual-review comment was posted, the
    NEEDS-* side is presumed correct (the flag prompted a fix).
    """
    review_at = _parse_iso(review_comment.get("createdAt"))
    if review_at is None:
        return False
    commits = pr_data.get("commits") or []
    for c in commits:
        committed_at = _parse_iso(c.get("committedDate")) or _parse_iso(
            (c.get("authoredDate") if isinstance(c, dict) else None)
        )
        if committed_at and committed_at > review_at:
            return True
    return False


# ---------------------------------------------------------------------------
# Ledger I/O wrapper
# ---------------------------------------------------------------------------

def existing_pr_review_refs(
    cal_module, ledger_path: pathlib.Path | None
) -> set[tuple[str, str]]:
    """Return the set of (provider, task_ref) pairs already in the ledger
    for ``task_type == "pr-review"``. Used for idempotent re-runs.
    """
    try:
        rows = cal_module.load_entries(ledger_path)
    except (ValueError, FileNotFoundError):
        return set()
    seen: set[tuple[str, str]] = set()
    for r in rows:
        if r.get("task_type") == "pr-review":
            prov = r.get("provider", "")
            ref = r.get("task_ref", "")
            if prov and ref:
                seen.add((prov, ref))
    return seen


def append_outcome(
    cal_module,
    *,
    provider: str,
    pr_number: int,
    verdict: str,
    evidence: str,
    operator: str,
    session_id: str,
    ledger_path: pathlib.Path | None,
    dry_run: bool,
) -> dict:
    """Append one calibration row (or print it, if dry-run)."""
    entry = {
        "ts": cal_module._utcnow_iso(),
        "provider": provider,
        "task_type": "pr-review",
        "task_ref": f"PR #{pr_number}",
        "verdict": verdict,
        "evidence": evidence,
        "operator": operator,
        "session_id": session_id,
    }
    if dry_run:
        sys.stdout.write(
            "[dry-run] would-log: "
            + json.dumps(entry, sort_keys=True, ensure_ascii=False)
            + "\n"
        )
        return entry
    cal_module.append_entry(entry, path=ledger_path)
    return entry


# ---------------------------------------------------------------------------
# Per-PR pipeline
# ---------------------------------------------------------------------------

def process_pr(
    number: int,
    *,
    ledger_path: pathlib.Path | None,
    dry_run: bool,
    operator: str,
    session_id: str,
    skip_existing: bool = True,
    pr_data: dict | None = None,
) -> dict:
    """Process one PR. Returns a record describing what was done.

    The record contains::

        {
          "pr": <int>,
          "state": "MERGED" | "CLOSED" | "OPEN",
          "consensus": "AGREED-MERGE-OK" | ... | None,
          "verdicts": {"kimi": "MERGE-OK"|None, "minimax": ...},
          "outcomes": {"kimi": "TRUE"|"FALSE"|"INDETERMINATE", "minimax": ...},
          "logged":   {"kimi": <entry-or-None>, "minimax": <entry-or-None>},
          "skipped":  ["reason", ...],
          "fix_up_after_review": bool,
        }

    ``skip_existing=True`` (default) means: don't re-log a (provider, PR #N)
    pair that already has a row in the ledger. Set False for forced re-grade.
    """
    record: dict[str, Any] = {
        "pr": number,
        "state": None,
        "consensus": None,
        "verdicts": {"kimi": None, "minimax": None},
        "outcomes": {"kimi": "INDETERMINATE", "minimax": "INDETERMINATE"},
        "logged": {"kimi": None, "minimax": None},
        "skipped": [],
        "fix_up_after_review": False,
    }
    cal = _load_calibration_module()

    if pr_data is None:
        try:
            pr_data = fetch_pr(number)
        except Exception as e:
            record["skipped"].append(f"pr-fetch-failed: {e}")
            return record

    state = (pr_data.get("state") or "").upper()
    record["state"] = state

    comments = pr_data.get("comments") or []
    review = find_review_comment(comments)
    if review is None:
        record["skipped"].append("no-review-comment")
        return record

    parsed = parse_review_comment(review.get("body", ""))
    record["consensus"] = parsed.get("consensus")
    record["verdicts"] = {
        "kimi": parsed.get("kimi"),
        "minimax": parsed.get("minimax"),
    }

    fix_up = False
    if parsed.get("consensus") == "DISAGREED" and state == "MERGED":
        fix_up = detect_fix_up(pr_data, review)
    record["fix_up_after_review"] = fix_up

    outcomes = grade_outcome(parsed, state, fix_up_after_review=fix_up)
    record["outcomes"] = outcomes

    # Idempotency: skip writes that would duplicate.
    existing = existing_pr_review_refs(cal, ledger_path) if skip_existing else set()
    task_ref = f"PR #{number}"

    evidence_base = (
        f"merge-hook: state={state} consensus={parsed.get('consensus')} "
        f"fix_up_after_review={fix_up}"
    )

    for prov in ("kimi", "minimax"):
        verdict = outcomes[prov]
        if (prov, task_ref) in existing:
            record["skipped"].append(f"{prov}-already-logged")
            continue
        try:
            entry = append_outcome(
                cal,
                provider=prov,
                pr_number=number,
                verdict=verdict,
                evidence=evidence_base + f" parsed_verdict={parsed.get(prov)}",
                operator=operator,
                session_id=session_id,
                ledger_path=ledger_path,
                dry_run=dry_run,
            )
            record["logged"][prov] = entry
        except ValueError as e:
            record["skipped"].append(f"{prov}-log-rejected: {e}")
    return record


# ---------------------------------------------------------------------------
# Subcommand handlers
# ---------------------------------------------------------------------------

def cmd_process(args: argparse.Namespace) -> int:
    rec = process_pr(
        args.pr,
        ledger_path=args.ledger,
        dry_run=args.dry_run,
        operator=args.operator,
        session_id=args.session_id,
        skip_existing=not args.force,
    )
    sys.stdout.write(_format_record(rec) + "\n")
    return 0


def cmd_process_recent(args: argparse.Namespace) -> int:
    if args.since:
        since_iso = args.since
    else:
        # Default: 7 days ago, UTC midnight.
        cutoff = datetime.now(timezone.utc) - timedelta(days=7)
        since_iso = cutoff.strftime("%Y-%m-%d")
    try:
        prs = list_recent_merged(since_iso, limit=args.limit)
    except Exception as e:
        sys.stderr.write(f"failed-to-list-prs: {e}\n")
        return 2

    if not prs:
        sys.stdout.write(f"no merged PRs since {since_iso}\n")
        return 0

    new_count = 0
    skipped_count = 0
    indeterminate_count = 0
    for p in prs:
        n = p.get("number")
        if n is None:
            continue
        rec = process_pr(
            n,
            ledger_path=args.ledger,
            dry_run=args.dry_run,
            operator=args.operator,
            session_id=args.session_id,
            skip_existing=not args.force,
        )
        sys.stdout.write(_format_record(rec) + "\n")
        for prov in ("kimi", "minimax"):
            if rec["logged"].get(prov):
                new_count += 1
                if rec["outcomes"][prov] == "INDETERMINATE":
                    indeterminate_count += 1
        skipped_count += sum(
            1 for s in rec["skipped"] if s.endswith("already-logged")
        )

    sys.stdout.write(
        f"\n=== merge-hook summary ===\n"
        f"PRs scanned: {len(prs)} since {since_iso}\n"
        f"new outcomes added: {new_count} "
        f"(indeterminate: {indeterminate_count})\n"
        f"already-logged skips: {skipped_count}\n"
    )
    return 0


def _format_record(rec: dict) -> str:
    pr = rec["pr"]
    state = rec["state"]
    cons = rec["consensus"] or "NO-CONSENSUS"
    out = rec["outcomes"]
    logged = sum(1 for v in rec["logged"].values() if v)
    skips = ",".join(rec["skipped"]) if rec["skipped"] else "-"
    return (
        f"PR #{pr} state={state} consensus={cons} "
        f"kimi={rec['verdicts']['kimi']}->{out['kimi']} "
        f"minimax={rec['verdicts']['minimax']}->{out['minimax']} "
        f"logged={logged}/2 skipped=[{skips}]"
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="llm-pr-review-merge-hook.py",
        description=(
            "Auto-grade dual-LLM PR-review comments on merge and append "
            "the per-provider outcome to tools/calibration/"
            "llm_calibration_log.jsonl. Read-only on PR data; write-only "
            "on the ledger."
        ),
    )
    p.add_argument(
        "--ledger",
        type=pathlib.Path,
        default=None,
        help="Override the calibration ledger path (default: tool default).",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Print would-be log lines without writing the ledger.",
    )
    p.add_argument(
        "--operator",
        default="merge-hook",
        help="Value for the entry's `operator` field (default: merge-hook).",
    )
    p.add_argument(
        "--session-id",
        default=datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        help="Value for the entry's `session_id` field (default: today UTC).",
    )
    p.add_argument(
        "--force",
        action="store_true",
        help="Re-log even if a (provider, task_ref) already exists.",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    p_one = sub.add_parser(
        "process", help="Process a single PR by number.",
    )
    p_one.add_argument("pr", type=int, help="PR number to process.")
    p_one.set_defaults(func=cmd_process)

    p_rec = sub.add_parser(
        "process-recent", help="Process every merged PR since DATE.",
    )
    p_rec.add_argument(
        "--since",
        default=None,
        help="YYYY-MM-DD or ISO-8601 cutoff (default: 7 days ago).",
    )
    p_rec.add_argument(
        "--limit", type=int, default=200,
        help="Max PRs to fetch from `gh pr list` (default: 200).",
    )
    p_rec.set_defaults(func=cmd_process_recent)

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
