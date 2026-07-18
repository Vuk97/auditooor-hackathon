#!/usr/bin/env python3
"""codex-peer-poll.py — capability-v3 iter-003 T5.

Symmetric, stdlib-only CLI that polls a PR (default: #104) for peer
activity since a timestamp and emits classified JSON. Both peers
(Opus + Codex) use this same tool; the `--peer-name` flag selects
*which* peer's events to return (i.e. it filters out self-authored
events).

Read-only semantics (fix for PR #104 comment 4312120294)
--------------------------------------------------------
* Does NOT modify remote state. No `git push`, no `gh pr comment`,
  no `gh pr review --approve`. This half of the read-only promise is
  absolute and enforced by the project's hard-negative grep gate.
* Does NOT modify local state by default. The tool no longer runs
  `git fetch --all --prune` unconditionally. That call mutates local
  remote-tracking refs (and prunes stale ones), so it is now gated
  behind the explicit `--fetch` flag. Default behavior is strict
  read-only — the tool reads whatever refs the caller already has.
* Callers that want fresh refs (e.g. the cron peer-poll loop in
  `docs/CAPV3_ITER4_T4_cron_peer_poll.md`) opt in via `--fetch`.
  That is the ONLY path by which this tool mutates anything on disk.

Design notes
------------
* Stdlib-only. Imports: `argparse`, `datetime`, `json`, `pathlib`,
  `re`, `subprocess`, `sys`. (`unittest.mock` only in tests.)
* Classification is keyword heuristic. When confidence is low the
  event is bucketed as `unclassified` rather than guessed.
* Honest-zero is a legitimate output: empty `events` with a reason
  field (e.g. `gh` CLI not found).

Classification types (7)
------------------------
1. `review-feedback`    — PR review with state `CHANGES_REQUESTED`
                          OR a review comment referencing line numbers
                          ("line 12", "L42", "lines 5-10").
2. `suggestion`         — comment body in imperative mood ("change X",
                          "use Y", "consider Z", "replace ... with",
                          "refactor", "rename", "fix").
3. `new-task-proposal`  — comment referencing new scope / next
                          iteration / candidate pool. Phrases:
                          "should", "propose", "next iteration",
                          "iter-v3-", "T-candidate", "roadmap", "candidate".
4. `question`           — comment contains `?` AND an interrogative
                          word ("what", "why", "how", "when", "where",
                          "which", "who", "should", "could", "would",
                          "does", "do").
5. `commit-push`        — a commit on the PR branch since `--since`.
6. `new-pr`             — a PR opened since `--since` by the peer
                          targeting `main` or `claudeboy-capability-v3`.
                          (Heuristic; full new-PR detection lives in
                          the cron loop — we flag in-PR-linked new PRs.)
7. `unclassified`       — anything we can't confidently pin to the
                          above. Mandatory fallback — prefer this over
                          guessing.

Self vs peer heuristic (tightened, fix for PR #104 blocker #8)
--------------------------------------------------------------
Both peers commit under GitHub login `Vuk97` (one physical operator,
two agent CLIs). The previous heuristic used branch name as a strong
signal even for *comments*, which mis-classified Codex comments on a
shared `claudeboy-capv3-*` branch as "opus" (self) and silently
filtered them out. New rule set, priority high → low:

1. **Body markers** (strongest per-event signal — an explicit
   self-identifier in the event body):
   * Opus markers: ``claude opus``, ``opus 4.7``,
     ``co-authored-by: claude``, ``opus (this agent)``,
     ``this agent (opus)``, ``— opus``, ``-- opus``.
   * Codex markers: ``codex here``, ``codex (this agent)``,
     ``this agent (codex)``, ``co-authored-by: codex``, ``— codex``,
     ``-- codex``, ``openai``.
   * If a body contains BOTH kinds of markers we fall through rather
     than guess.
2. **Branch name — asymmetric use**:
   * ``codex/*`` branch → ``codex``. This is a strong signal: only
     the Codex CLI pushes ``codex/*`` branches.
   * ``claudeboy*`` / ``auditooor-capv3-*`` branch → treated as
     *uncertain* for comments/reviews (Opus pushes these branches,
     but Codex ALSO comments and pushes on them). It is still used
     as a tiebreaker for raw git-log commits (no body available).
3. **Author name** (rarely disambiguates — both run as ``Vuk97``):
   substring ``codex`` → ``codex``; ``claude`` or ``opus`` →
   ``opus``.
4. **Unknown** — when none of the above fire with confidence, the
   event is labelled ``unknown``. ``unknown`` events are INCLUDED
   in the output (never filtered as self) so Codex-authored comments
   on shared claudeboy branches cannot be silently dropped.

Output schema (stable)
----------------------
    {
      "ts": "<now ISO8601 UTC>",
      "pr_number": 104,
      "peer_name": "opus",
      "since": "2026-04-23T00:00:00Z",
      "events": [
        {
          "type": "comment|review|commit|pr",
          "author": "<login>",
          "sha_or_url": "<url or commit oid>",
          "classification": "<one of the 7 classes>",
          "body_preview": "<first ~200 chars>",
          "suggested_route": "<short free-form string>",
          "created_at": "<ISO8601>"
        },
        ...
      ],
      "counts": {
        "by_type": {"comment": N, "review": N, "commit": N, "pr": N},
        "by_classification": {"review-feedback": N, ...}
      },
      "reason": "<optional: set when events=[]; e.g. 'gh-missing'>"
    }

Exit codes
----------
* 0 — always (cannot-judge returns 0 with empty events + reason).

Usage
-----
    python3 tools/codex-peer-poll.py \\
        --pr-number 104 \\
        --since 2026-04-23T00:00:00Z \\
        --peer-name opus

    # Append a markdown section to the shared codex log:
    python3 tools/codex-peer-poll.py --pr-number 104 \\
        --since 2026-04-23T00:00:00Z --peer-name codex \\
        --log-append docs/CAPABILITY_V3_CODEX_LOG.md
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

CLASSIFICATIONS = (
    "review-feedback",
    "suggestion",
    "new-task-proposal",
    "question",
    "commit-push",
    "new-pr",
    "unclassified",
)

EVENT_TYPES = ("comment", "review", "commit", "pr")

# Keyword tables (case-insensitive).
_LINE_REF_RE = re.compile(
    r"\b(line\s+\d+|L\d+|lines?\s+\d+\s*[-–]\s*\d+)\b", re.IGNORECASE
)
_IMPERATIVE_KEYWORDS = (
    "change ",
    "use ",
    "consider ",
    "replace ",
    "refactor",
    "rename",
    "fix ",
    "please ",
    "switch to",
    "update the",
    "add a ",
    "remove the ",
    "drop the ",
    "rework",
    "rebase",
)
_TASK_PROPOSAL_KEYWORDS = (
    "should",
    "propose",
    "next iteration",
    "iter-v3-",
    "t-candidate",
    "roadmap",
    "candidate",
    "follow-up",
    "new task",
    "next task",
)
_INTERROGATIVES = (
    "what",
    "why",
    "how",
    "when",
    "where",
    "which",
    "who",
    "should",
    "could",
    "would",
    "does",
    "do you",
    "is this",
    "can you",
    "are we",
)

# Peer-identity heuristic helpers.
_OPUS_BRANCH_RE = re.compile(
    r"^(claudeboy-capability-v3|claudeboy-capv3-|auditooor-capv3-|claudeboy-iter)",
    re.IGNORECASE,
)
_CODEX_BRANCH_RE = re.compile(r"^codex/", re.IGNORECASE)

_OPUS_BODY_MARKERS = (
    "claude opus",
    "opus 4.7",
    "co-authored-by: claude",
    "opus (this agent)",
    "this agent (opus)",
    "— opus",
    "-- opus",
)
_CODEX_BODY_MARKERS = (
    "codex (this agent)",
    "this agent (codex)",
    "co-authored-by: codex",
    "— codex",
    "-- codex",
    "codex here",
    "openai",
)

# ---------------------------------------------------------------------------
# Subprocess helpers (read-only)
# ---------------------------------------------------------------------------

# Retry/outage sentinels.
# `_GH_MISSING` means the `gh` binary isn't on PATH (FileNotFoundError).
# `_GH_RATE_LIMIT_EXHAUSTED` means the retry helper tried the call
# `max_retries` times and every attempt hit a transient-looking failure
# (HTTP 429 / HTTP 5xx / TimeoutExpired / ConnectionError). Callers
# surface these as distinct `reason:` values in the honest-zero JSON
# so the cron log can tell them apart.
_GH_MISSING = "gh-missing-or-unavailable"
_GH_RATE_LIMIT_EXHAUSTED = "gh_api_rate_limit_exhausted"

# Retry trigger matchers. Kept as compiled patterns / substrings so the
# helper stays stdlib-only.
_RATE_LIMIT_SUBSTRINGS = ("rate limit exceeded", "http 429", " 429 ")
_HTTP_5XX_RE = re.compile(r"\b5\d\d\b")


def _is_retryable_stderr(stderr: str) -> bool:
    """True iff stderr text looks like a transient GH API failure.

    Covers HTTP 429 (explicit rate-limit wording or the substring
    `429`) and HTTP 5xx (any 5\\d\\d token). Any other stderr is
    treated as a permanent failure and is NOT retried — we don't
    want to retry authz errors, bad-arg errors, or repo-not-found.
    """
    if not stderr:
        return False
    low = stderr.lower()
    if any(s in low for s in _RATE_LIMIT_SUBSTRINGS):
        return True
    if _HTTP_5XX_RE.search(stderr):
        return True
    return False


def _run_gh_with_retry(
    args: list[str],
    *,
    max_retries: int = 3,
    backoff_base: float = 2.0,
    timeout: float | None = None,
) -> subprocess.CompletedProcess | str:
    """Run `gh <args>` with bounded exponential-backoff retry.

    Wraps ``subprocess.run(["gh", *args], check=False,
    capture_output=True, text=True)``. Retries on transient failures:

      * HTTP 429 (stderr contains ``rate limit exceeded`` /
        ``HTTP 429`` / bare `` 429 `` substring).
      * HTTP 5xx (stderr matches ``\\b5\\d\\d\\b``).
      * ``subprocess.TimeoutExpired``.
      * ``ConnectionError`` / ``socket.timeout`` / ``OSError`` with
        ``EPIPE``-ish semantics (caught as ``ConnectionError``).

    Backoff uses ``time.sleep(min(backoff_base ** attempt, 8.0))``
    between attempts, so with defaults the waits are 2 s, 4 s, 8 s
    (max_retries=3 ⇒ up to 3 extra attempts after the first).

    Return values:

      * ``subprocess.CompletedProcess`` — the call returned **any**
        result (success or a *permanent* non-retryable failure such
        as auth error). The caller inspects ``returncode`` /
        ``stdout`` as usual.
      * ``_GH_MISSING`` (str) — the ``gh`` binary isn't on PATH
        (``FileNotFoundError``). Not retryable — the binary won't
        appear mid-loop.
      * ``_GH_RATE_LIMIT_EXHAUSTED`` (str) — every retry hit a
        transient failure. The caller emits an honest-zero JSON
        with ``reason: "gh_api_rate_limit_exhausted"`` and exit 0.

    Read-only contract: this helper only ever invokes ``gh`` with
    the provided args — it does NOT inject any write verbs. The
    caller is responsible for passing read-only args (the project's
    hard-negative grep gate still enforces absence of remote-write
    tokens in the file; see the module docstring's read-only clause).
    """
    cmd = ["gh", *args]
    # max_retries=3 means: 1 initial attempt + up to 2 retries, OR
    # (more conservatively, matching the spec wording) a ceiling of 3
    # retries after the initial call. We implement the spec literally:
    # one initial attempt plus `max_retries` retries, stopping early
    # on success or a permanent (non-retryable) failure.
    total_attempts = max_retries + 1

    last_stderr = ""
    for attempt in range(total_attempts):
        try:
            proc = subprocess.run(
                cmd,
                check=False,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except FileNotFoundError:
            return _GH_MISSING
        except subprocess.TimeoutExpired:
            # Retryable — behave identically to a 5xx.
            last_stderr = "timeout-expired"
            if attempt >= max_retries:
                break
            time.sleep(min(backoff_base ** (attempt + 1), 8.0))
            continue
        except ConnectionError:
            last_stderr = "connection-error"
            if attempt >= max_retries:
                break
            time.sleep(min(backoff_base ** (attempt + 1), 8.0))
            continue

        # Non-zero rc + retryable stderr → backoff + retry.
        if proc.returncode != 0 and _is_retryable_stderr(proc.stderr or ""):
            last_stderr = proc.stderr or ""
            if attempt >= max_retries:
                # Exhausted — emit a short operator-visible note on
                # stderr so the cron log shows *why* we backed off,
                # then return the exhaustion sentinel.
                try:
                    sys.stderr.write(
                        "gh-retry: exhausted after "
                        f"{total_attempts} attempts "
                        f"(last stderr: {last_stderr.strip()[:120]!r})\n"
                    )
                except Exception:
                    pass
                return _GH_RATE_LIMIT_EXHAUSTED
            time.sleep(min(backoff_base ** (attempt + 1), 8.0))
            continue

        # Either success (rc == 0) or a permanent non-retryable
        # failure — return as-is.
        return proc

    # Loop exited without a definitive return → exhausted on
    # TimeoutExpired / ConnectionError.
    try:
        sys.stderr.write(
            "gh-retry: exhausted after "
            f"{total_attempts} attempts (last stderr: {last_stderr!r})\n"
        )
    except Exception:
        pass
    return _GH_RATE_LIMIT_EXHAUSTED


def _gh_pr_view(pr_number: int) -> dict[str, Any] | None | str:
    """Fetch comments/reviews/commits for a PR.

    Returns the parsed JSON dict on success. On any failure the
    return is a sentinel string (``_GH_MISSING`` or
    ``_GH_RATE_LIMIT_EXHAUSTED``) OR ``None`` for permanent
    non-retryable GH failures (e.g. auth, not-found, JSON parse
    error). Callers key off the value to pick the right
    ``reason:`` for the honest-zero JSON shape.
    """
    args = [
        "pr",
        "view",
        str(pr_number),
        "--json",
        "comments,reviews,commits,headRefName,baseRefName",
    ]
    result = _run_gh_with_retry(args)

    if isinstance(result, str):
        # Sentinel — surface as-is to the caller so it can map to
        # the right `reason:` field.
        return result

    if result.returncode != 0:
        # Permanent non-retryable failure — treat as missing.
        return None

    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return None


def _git_log_since(
    since_iso: str, ref: str, *, do_fetch: bool = False
) -> list[dict[str, str]]:
    """Return a list of {oid, author, subject} since an ISO timestamp
    on a ref. Empty list on any failure (fetch unavailable, ref missing).

    When ``do_fetch`` is True the function runs ``git fetch --all
    --prune`` first. That call mutates local remote-tracking refs
    (and prunes stale ones), so the default is False — the tool is
    then strictly read-only wrt local state. Callers that need fresh
    refs (e.g. the cron peer-poll loop) opt in via the CLI
    ``--fetch`` flag which is threaded down to this helper.
    """
    # Best-effort fetch, gated behind the explicit --fetch flag.
    # Failure (no network, no remote) is tolerated.
    if do_fetch:
        try:
            subprocess.run(
                ["git", "fetch", "--all", "--prune"],
                check=False,
                capture_output=True,
                text=True,
            )
        except FileNotFoundError:
            return []

    fmt = "%H%x09%an%x09%s"
    cmd = ["git", "log", f"--since={since_iso}", f"--format={fmt}", ref]
    try:
        proc = subprocess.run(cmd, check=False, capture_output=True, text=True)
    except FileNotFoundError:
        return []
    if proc.returncode != 0:
        return []

    out: list[dict[str, str]] = []
    for line in proc.stdout.splitlines():
        parts = line.split("\t", 2)
        if len(parts) != 3:
            continue
        oid, author, subject = parts
        out.append({"oid": oid, "author": author, "subject": subject})
    return out


# ---------------------------------------------------------------------------
# Peer identity
# ---------------------------------------------------------------------------


def _guess_peer(
    *,
    body: str = "",
    head_ref: str = "",
    author_name: str = "",
    event_type: str = "",
) -> str:
    """Return 'opus', 'codex', or 'unknown'.

    Priority (high → low):
      1. Body markers — strongest per-event signal. A commit whose
         trailer says "Co-Authored-By: Claude Opus 4.7" is Opus even
         if it landed on a shared branch, and vice versa for
         "Co-Authored-By: codex". Inline comments that explicitly
         self-identify ("Codex here —", "Opus landed X") also win.
      2. Branch name — ASYMMETRIC. `codex/*` → codex (strong signal,
         only the Codex CLI pushes those branches). `claudeboy*` /
         `auditooor-capv3-*` → ``opus`` ONLY for commit-type events
         (where the branch is the best signal we have). For comments
         and reviews we deliberately DO NOT use claudeboy-branch as
         an Opus signal, because Codex also comments/reviews on
         those shared branches — returning "opus" here would
         mis-filter Codex comments as self. See PR #104 blocker #8.
      3. Author name (rarely disambiguates — both run as Vuk97).
      4. Otherwise ``unknown`` (and ``unknown`` is always INCLUDED
         in peer filtering; see `_is_peer_event`).
    """
    body_l = (body or "").lower()
    has_codex_marker = any(m in body_l for m in _CODEX_BODY_MARKERS)
    has_opus_marker = any(m in body_l for m in _OPUS_BODY_MARKERS)

    # When both markers appear (Opus reviewing a Codex commit body, etc.)
    # prefer the branch/author fallback rather than the first win.
    if has_codex_marker and not has_opus_marker:
        return "codex"
    if has_opus_marker and not has_codex_marker:
        return "opus"

    ref = (head_ref or "").strip()
    if ref:
        # `codex/*` is a strong signal regardless of event type —
        # only the Codex CLI pushes these branches.
        if _CODEX_BRANCH_RE.match(ref):
            return "codex"
        # Claudeboy / auditooor-capv3 branches: Opus pushes code
        # there, but Codex ALSO comments and reviews on them. Use
        # the branch as an Opus signal ONLY for `commit` events.
        if event_type == "commit" and _OPUS_BRANCH_RE.match(ref):
            return "opus"

    author_l = (author_name or "").lower()
    if "codex" in author_l:
        return "codex"
    if "claude" in author_l or "opus" in author_l:
        return "opus"

    return "unknown"


def _is_peer_event(
    *, self_peer: str, event_peer: str
) -> bool:
    """True iff the event was authored by the *other* peer.

    `unknown` is kept (included) — the operator can dedup in the log.
    We only drop definite self-authorship.
    """
    if event_peer == "unknown":
        return True
    return event_peer != self_peer


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------


def classify_comment(body: str) -> str:
    """Return one of the 7 classification strings for a comment body.

    Order of checks is important — the first high-confidence match
    wins, then we fall back to `unclassified`.
    """
    if not body:
        return "unclassified"
    text = body.strip()
    low = text.lower()

    # review-feedback-like: explicit line references in the body
    # (reviews proper are handled separately by classify_review).
    if _LINE_REF_RE.search(text):
        return "review-feedback"

    # new-task-proposal: scope / iteration / candidate wording.
    if any(kw in low for kw in _TASK_PROPOSAL_KEYWORDS):
        # Task proposals often use "should"; disambiguate from
        # questions: if the body is clearly a question (? + an
        # interrogative at the START), prefer question.
        if "?" in text and any(
            low.lstrip().startswith(q) for q in _INTERROGATIVES
        ):
            return "question"
        return "new-task-proposal"

    # suggestion: imperative phrasing.
    if any(kw in low for kw in _IMPERATIVE_KEYWORDS):
        return "suggestion"

    # question: must have both `?` and an interrogative token.
    if "?" in text and any(f" {q} " in f" {low} " for q in _INTERROGATIVES):
        return "question"

    return "unclassified"


def classify_review(review: dict[str, Any]) -> str:
    """A PR review event -> classification."""
    state = (review.get("state") or "").upper()
    body = review.get("body") or ""
    if state == "CHANGES_REQUESTED":
        return "review-feedback"
    if _LINE_REF_RE.search(body):
        return "review-feedback"
    # Fall back to body heuristics.
    return classify_comment(body)


# ---------------------------------------------------------------------------
# Filtering by --since
# ---------------------------------------------------------------------------


def _parse_iso(ts: str) -> datetime | None:
    if not ts:
        return None
    # Accept trailing Z.
    norm = ts.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(norm)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _is_after(event_ts: str, since_ts: str) -> bool:
    a = _parse_iso(event_ts)
    b = _parse_iso(since_ts)
    if a is None or b is None:
        return True  # keep rather than drop on bad timestamps.
    return a >= b


# ---------------------------------------------------------------------------
# Core poll logic
# ---------------------------------------------------------------------------


def build_events(
    *,
    pr_data: dict[str, Any] | None,
    git_commits: list[dict[str, str]],
    peer_name: str,
    since: str,
) -> list[dict[str, Any]]:
    """Merge gh + git data into a classified, peer-filtered event list."""
    events: list[dict[str, Any]] = []

    if pr_data is not None:
        head_ref = pr_data.get("headRefName", "") or ""

        for c in pr_data.get("comments", []) or []:
            created = c.get("createdAt", "")
            if not _is_after(created, since):
                continue
            body = c.get("body", "") or ""
            author = (c.get("author") or {}).get("login", "") or ""
            ev_peer = _guess_peer(
                body=body,
                head_ref=head_ref,
                author_name=author,
                event_type="comment",
            )
            if not _is_peer_event(self_peer=peer_name, event_peer=ev_peer):
                continue
            cls = classify_comment(body)
            events.append(
                {
                    "type": "comment",
                    "author": author,
                    "sha_or_url": c.get("url", "") or "",
                    "classification": cls,
                    "body_preview": body[:200],
                    "suggested_route": _route_for(cls),
                    "created_at": created,
                }
            )

        for r in pr_data.get("reviews", []) or []:
            created = r.get("submittedAt", "") or r.get("createdAt", "")
            if not _is_after(created, since):
                continue
            body = r.get("body", "") or ""
            author = (r.get("author") or {}).get("login", "") or ""
            ev_peer = _guess_peer(
                body=body,
                head_ref=head_ref,
                author_name=author,
                event_type="review",
            )
            if not _is_peer_event(self_peer=peer_name, event_peer=ev_peer):
                continue
            cls = classify_review(r)
            events.append(
                {
                    "type": "review",
                    "author": author,
                    "sha_or_url": r.get("url", "") or "",
                    "classification": cls,
                    "body_preview": body[:200],
                    "suggested_route": _route_for(cls),
                    "created_at": created,
                }
            )

        for com in pr_data.get("commits", []) or []:
            committed = com.get("committedDate", "") or com.get("authoredDate", "")
            if not _is_after(committed, since):
                continue
            body = com.get("messageBody", "") or ""
            headline = com.get("messageHeadline", "") or ""
            authors = com.get("authors", []) or []
            author_name = ""
            if authors:
                author_name = authors[0].get("name", "") or authors[0].get("login", "")
            ev_peer = _guess_peer(
                body=body + "\n" + headline,
                head_ref=head_ref,
                author_name=author_name,
                event_type="commit",
            )
            if not _is_peer_event(self_peer=peer_name, event_peer=ev_peer):
                continue
            events.append(
                {
                    "type": "commit",
                    "author": author_name,
                    "sha_or_url": com.get("oid", "") or "",
                    "classification": "commit-push",
                    "body_preview": headline[:200],
                    "suggested_route": _route_for("commit-push"),
                    "created_at": committed,
                }
            )

    # git log on the branch (catches commits not yet in PR view cache).
    seen_oids = {e["sha_or_url"] for e in events if e["type"] == "commit"}
    for g in git_commits:
        oid = g["oid"]
        if oid in seen_oids:
            continue
        ev_peer = _guess_peer(
            body=g["subject"],
            head_ref="",
            author_name=g["author"],
            event_type="commit",
        )
        if not _is_peer_event(self_peer=peer_name, event_peer=ev_peer):
            continue
        events.append(
            {
                "type": "commit",
                "author": g["author"],
                "sha_or_url": oid,
                "classification": "commit-push",
                "body_preview": g["subject"][:200],
                "suggested_route": _route_for("commit-push"),
                "created_at": "",
            }
        )

    return events


def _route_for(classification: str) -> str:
    return {
        "review-feedback": "address-next-tick",
        "suggestion": "file-as-T-candidate",
        "new-task-proposal": "score-against-iter-goal",
        "question": "reply-with-concrete-refs",
        "commit-push": "fetch-and-run-suite",
        "new-pr": "review-against-hard-rules",
        "unclassified": "manual-review",
    }.get(classification, "manual-review")


def build_counts(events: list[dict[str, Any]]) -> dict[str, dict[str, int]]:
    by_type = {t: 0 for t in EVENT_TYPES}
    by_class = {c: 0 for c in CLASSIFICATIONS}
    for e in events:
        t = e.get("type", "")
        if t in by_type:
            by_type[t] += 1
        c = e.get("classification", "")
        if c in by_class:
            by_class[c] += 1
    return {"by_type": by_type, "by_classification": by_class}


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------


def render_markdown(result: dict[str, Any]) -> str:
    """Render a markdown section suitable for appending to the codex log."""
    ts = result.get("ts", "")
    since = result.get("since", "")
    peer = result.get("peer_name", "")
    pr = result.get("pr_number", "")
    events = result.get("events", [])
    reason = result.get("reason", "")

    lines: list[str] = []
    lines.append(f"## {ts} — PR #{pr} peer poll (peer={peer})")
    lines.append("")
    lines.append(f"- since: `{since}`")
    lines.append(f"- events: {len(events)}")
    if reason:
        lines.append(f"- reason: `{reason}`")
    lines.append("")

    if not events:
        lines.append("_No peer events in window._")
        lines.append("")
        return "\n".join(lines)

    lines.append("| type | class | author | route | preview |")
    lines.append("|---|---|---|---|---|")
    for e in events:
        preview = (e.get("body_preview") or "").replace("|", "\\|")
        preview = preview.replace("\n", " ")[:80]
        lines.append(
            "| {typ} | {cls} | {auth} | {route} | {prev} |".format(
                typ=e.get("type", ""),
                cls=e.get("classification", ""),
                auth=e.get("author", ""),
                route=e.get("suggested_route", ""),
                prev=preview,
            )
        )
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def poll(
    *,
    pr_number: int,
    since: str,
    peer_name: str,
    ref: str = "origin/claudeboy-capability-v3",
    do_fetch: bool = False,
) -> dict[str, Any]:
    raw = _gh_pr_view(pr_number)

    reason = ""
    pr_data: dict[str, Any] | None
    if raw is None:
        reason = _GH_MISSING
        pr_data = None
    elif isinstance(raw, str):
        # Sentinel — either `_GH_MISSING` or
        # `_GH_RATE_LIMIT_EXHAUSTED`. Both paths yield an honest-zero
        # JSON shape; the `reason:` field tells them apart.
        reason = raw
        pr_data = None
    else:
        pr_data = raw

    git_commits = _git_log_since(since, ref, do_fetch=do_fetch)

    events = build_events(
        pr_data=pr_data,
        git_commits=git_commits,
        peer_name=peer_name,
        since=since,
    )

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    out: dict[str, Any] = {
        "ts": now,
        "pr_number": pr_number,
        "peer_name": peer_name,
        "since": since,
        "events": events,
        "counts": build_counts(events),
    }
    if reason and not events:
        out["reason"] = reason
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Symmetric peer poller for PR activity. Never posts "
            "comments, reviews, or pushes (no remote writes). Does "
            "not modify local state by default; pass --fetch to opt "
            "into a `git fetch --all --prune` tick. Classifies "
            "events into 7 buckets."
        )
    )
    parser.add_argument(
        "--pr-number",
        type=int,
        required=True,
        help="PR number to poll (e.g. 104).",
    )
    parser.add_argument(
        "--since",
        type=str,
        required=True,
        help="ISO8601 timestamp cutoff (events strictly after are returned).",
    )
    parser.add_argument(
        "--peer-name",
        choices=("codex", "opus"),
        required=True,
        help="Which peer is *running* this tool. The tool returns the "
        "*other* peer's events (self-authored events are filtered).",
    )
    parser.add_argument(
        "--log-append",
        type=Path,
        default=None,
        help=(
            "Optional path to append a markdown section to. File is "
            "created if missing. Typical target: "
            "docs/CAPABILITY_V3_CODEX_LOG.md."
        ),
    )
    parser.add_argument(
        "--format",
        choices=("json", "markdown"),
        default="json",
        help="Stdout format (default: json).",
    )
    parser.add_argument(
        "--ref",
        default="origin/claudeboy-capability-v3",
        help="git ref for the commit-push feed (default: "
        "origin/claudeboy-capability-v3).",
    )
    parser.add_argument(
        "--indent",
        type=int,
        default=2,
        help="JSON indent (default 2). Use 0 for compact.",
    )
    parser.add_argument(
        "--fetch",
        action="store_true",
        default=False,
        help=(
            "Run `git fetch --all --prune` before reading the git log. "
            "Default OFF — the tool is strictly read-only wrt local "
            "state unless this flag is explicitly passed. Opt in when "
            "fresh remote-tracking refs are required (e.g. the cron "
            "peer-poll loop)."
        ),
    )
    args = parser.parse_args(argv)

    # Sanity-check --since.
    if _parse_iso(args.since) is None:
        print(
            f"cannot-poll: invalid --since timestamp: {args.since!r}",
            file=sys.stderr,
        )
        # Emit honest-empty JSON and exit 0 (cannot-judge path).
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        empty = {
            "ts": now,
            "pr_number": args.pr_number,
            "peer_name": args.peer_name,
            "since": args.since,
            "events": [],
            "counts": build_counts([]),
            "reason": "invalid-since",
        }
        _write_output(empty, args)
        return 0

    result = poll(
        pr_number=args.pr_number,
        since=args.since,
        peer_name=args.peer_name,
        ref=args.ref,
        do_fetch=args.fetch,
    )

    reason = result.get("reason", "")
    if reason == _GH_MISSING:
        print("cannot-poll: gh CLI not available", file=sys.stderr)
    elif reason == _GH_RATE_LIMIT_EXHAUSTED:
        # Honest-zero + operator-visible note. Exit 0 — cron tick
        # continuity is more valuable than a single loud failure,
        # and `_run_gh_with_retry` already wrote a detailed stderr
        # line before giving up.
        print(
            "cannot-poll: gh api retries exhausted (rate-limit / 5xx / "
            "timeout / connection)",
            file=sys.stderr,
        )

    _write_output(result, args)
    return 0


def _write_output(result: dict[str, Any], args: argparse.Namespace) -> None:
    if args.format == "markdown":
        sys.stdout.write(render_markdown(result))
        sys.stdout.write("\n")
    else:
        indent = args.indent if args.indent > 0 else None
        json.dump(result, sys.stdout, indent=indent, ensure_ascii=False)
        sys.stdout.write("\n")

    if args.log_append is not None:
        section = render_markdown(result)
        args.log_append.parent.mkdir(parents=True, exist_ok=True)
        with open(args.log_append, "a", encoding="utf-8") as fh:
            fh.write(section)
            fh.write("\n")


if __name__ == "__main__":
    sys.exit(main())
