#!/usr/bin/env python3
"""vault-pr-sync — sync GitHub PRs into obsidian-vault/prs/<N>.md notes.

Lane 1 of MCP harness review (PR #658) commit 3. Closes the 40-PR vault
staleness gap (vault stopped at #618; #619-658+ never landed).

Reads `gh pr list` JSON, writes one markdown note per PR with L0 frontmatter
(per Lane 11 ontology). Idempotent — re-running updates existing notes
in-place without losing manual edits below the AUTO-SYNC marker.

Usage:
    tools/vault-pr-sync.py                          # sync open + last 30 closed
    tools/vault-pr-sync.py --since-pr 619           # backfill from PR 619
    tools/vault-pr-sync.py --all-merged             # full sync of all merged PRs
    tools/vault-pr-sync.py --vault-dir <path>       # override vault location
    tools/vault-pr-sync.py --dry-run                # show what would be written
    tools/vault-pr-sync.py --check                  # exit non-zero if staleness >0

MCP session token (advisory in commit 3, hardened in commit 8):
    Reads $AUDITOOOR_MCP_SESSION_TOKEN env var and logs a warning if missing.
    Future commits will refuse on missing/invalid token.
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import subprocess
import sys
from datetime import datetime, timedelta, timezone

# ---------------------------------------------------------------------------
# LLM-review status column
# ---------------------------------------------------------------------------
STALE_AFTER_DAYS = 7  # configurable threshold

# Accept any of these as a pr-review task_type value
_PR_REVIEW_TASK_TYPES = {"pr_review", "pr-review", "llm-pr-review"}

# Default calibration log path (relative to repo root)
_DEFAULT_CALIB_LOG = pathlib.Path(__file__).resolve().parent / "calibration" / "llm_calibration_log.jsonl"

REPO = pathlib.Path(__file__).resolve().parent.parent


def _llm_review_status_for_pr(
    pr_number: int,
    log_path: "pathlib.Path | None" = None,
    *,
    _now: "datetime | None" = None,
) -> str:
    """Return llm_review_status for *pr_number* by reading the calibration log.

    Status values:
      ``none``  — no llm-pr-review run logged for this PR
      ``pass``  — last logged run verdict was TRUE/pass
      ``fail``  — last logged run verdict was FALSE/fail
      ``stale`` — last logged run is older than STALE_AFTER_DAYS days

    Tolerates missing log file and malformed JSONL rows (skip-and-continue).
    """
    if log_path is None:
        log_path = _DEFAULT_CALIB_LOG

    log_path = pathlib.Path(log_path)
    if not log_path.is_file():
        return "none"

    # Regex to extract a PR number from strings like "PR #167 finding #3"
    _pr_num_re = re.compile(r"PR\s+#(\d+)", re.IGNORECASE)

    now = _now if _now is not None else datetime.now(timezone.utc)
    stale_threshold = timedelta(days=STALE_AFTER_DAYS)

    best: "dict | None" = None  # row with latest timestamp for this PR
    best_ts: "datetime | None" = None

    try:
        with log_path.open("r", encoding="utf-8") as fh:
            for lineno, raw in enumerate(fh, 1):
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    row = json.loads(raw)
                except json.JSONDecodeError:
                    sys.stderr.write(
                        f"[vault-pr-sync] WARN: malformed JSONL at {log_path}:{lineno} — skipping\n"
                    )
                    continue

                # Check task_type
                task_type = row.get("task_type", "")
                if task_type not in _PR_REVIEW_TASK_TYPES:
                    continue

                # Extract PR number: prefer explicit field, fall back to task_ref parse
                row_pr = row.get("pr_number")
                if row_pr is None:
                    task_ref = row.get("task_ref", "")
                    m = _pr_num_re.search(task_ref)
                    if m:
                        try:
                            row_pr = int(m.group(1))
                        except ValueError:
                            continue
                    else:
                        continue

                try:
                    row_pr = int(row_pr)
                except (TypeError, ValueError):
                    continue

                if row_pr != pr_number:
                    continue

                # Parse timestamp
                ts_str = row.get("ts", "")
                try:
                    ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                except (ValueError, AttributeError):
                    continue

                if best_ts is None or ts > best_ts:
                    best = row
                    best_ts = ts
    except OSError as exc:
        sys.stderr.write(f"[vault-pr-sync] WARN: could not read calibration log: {exc}\n")
        return "none"

    if best is None:
        return "none"

    # Check staleness first
    if now - best_ts > stale_threshold:
        return "stale"

    # Map verdict → status
    verdict = str(best.get("verdict", "")).strip().upper()
    if verdict in ("TRUE", "PASS", "PASSED"):
        return "pass"
    if verdict in ("FALSE", "FAIL", "FAILED"):
        return "fail"
    # Unknown verdict — treat as pass if non-empty, else none
    return "pass" if verdict else "none"
DEFAULT_VAULT_DIRS = [
    pathlib.Path("/Users/wolf/Documents/Codex/auditooor/obsidian-vault"),
    REPO / "obsidian-vault",
]
SECTION = "prs"
AUTO_SYNC_MARKER_START = "<!-- AUDITOOOR_PR_AUTO_SYNC_START -->"
AUTO_SYNC_MARKER_END = "<!-- AUDITOOOR_PR_AUTO_SYNC_END -->"


def _resolve_vault_dir(override=None):
    if override:
        p = pathlib.Path(override).expanduser().resolve()
        if not p.is_dir():
            raise SystemExit(f"[vault-pr-sync] vault dir not found: {p}")
        return p
    for cand in DEFAULT_VAULT_DIRS:
        if cand.is_dir():
            return cand
    raise SystemExit("[vault-pr-sync] no vault dir found")


def _check_mcp_token():
    """Advisory check — warn if no MCP session token present (Commit 8 will harden)."""
    tok = os.environ.get("AUDITOOOR_MCP_SESSION_TOKEN", "")
    if not tok:
        sys.stderr.write(
            "[vault-pr-sync] WARN: $AUDITOOOR_MCP_SESSION_TOKEN not set. "
            "Advisory in PR #658 commit 3; will harden in commit 8.\n"
        )
        return None
    # Light-weight verify (don't fail if module not importable)
    try:
        sys.path.insert(0, str(REPO / "tools"))
        from auditooor_mcp_token import verify_token
        valid, err, payload = verify_token(tok, require_scope="write")
        if not valid:
            sys.stderr.write(f"[vault-pr-sync] WARN: token invalid: {err}\n")
            return None
        return payload
    except ImportError:
        return None


def fetch_prs(*, since_pr=None, all_merged=False, limit=100):
    """Fetch PRs via gh CLI. Returns list of dicts."""
    cmd = ["gh", "pr", "list", "--limit", str(limit), "--json",
           "number,state,title,body,createdAt,updatedAt,mergedAt,closedAt,headRefName,labels,author,url"]
    if all_merged:
        cmd.extend(["--state", "all"])
    else:
        cmd.extend(["--state", "all"])  # always all; filter client-side

    proc = subprocess.run(cmd, capture_output=True, text=True, cwd=REPO)
    if proc.returncode != 0:
        raise SystemExit(f"[vault-pr-sync] gh pr list failed: {proc.stderr}")
    prs = json.loads(proc.stdout or "[]")

    if since_pr is not None:
        prs = [pr for pr in prs if pr["number"] >= since_pr]

    return prs


def _frontmatter(pr, last_synced_iso, llm_review_status="none"):
    labels = pr.get("labels", []) or []
    label_names = [l.get("name", "") if isinstance(l, dict) else str(l) for l in labels]
    if not label_names:
        label_names = ["none"]
    state = pr.get("state", "UNKNOWN")
    state_lower = state.lower()
    fm_lines = [
        "---",
        f"layer: L0",  # Lane 11 ontology — PRs are raw L0 artifacts
        f"source_uri: {pr.get('url','')}",
        f"extracted_at: {last_synced_iso}",
        f"verbatim: false",
        f"pr_number: {pr['number']}",
        f"title: {json.dumps(pr.get('title', ''))}",
        f"state: '{state}'",
    ]
    if pr.get("mergedAt"):
        fm_lines.append(f"merged_at: '{pr['mergedAt'][:10]}'")
    if pr.get("closedAt") and not pr.get("mergedAt"):
        fm_lines.append(f"closed_at: '{pr['closedAt'][:10]}'")
    if pr.get("createdAt"):
        fm_lines.append(f"created_at: '{pr['createdAt']}'")
    if pr.get("updatedAt"):
        fm_lines.append(f"updated_at: '{pr['updatedAt']}'")
    fm_lines.append(f"branch: '{pr.get('headRefName','')}'")
    if pr.get("author"):
        author = pr["author"]
        login = author.get("login", "") if isinstance(author, dict) else str(author)
        fm_lines.append(f"author: '{login}'")
    fm_lines.append("labels:")
    for ln in label_names:
        fm_lines.append(f"  - {ln}")
    fm_lines.append(f"last_synced: '{last_synced_iso}'")
    fm_lines.append(f"llm_review_status: '{llm_review_status}'")
    fm_lines.append("tags:")
    fm_lines.append("  - pr/github")
    fm_lines.append(f"  - 'pr/{state_lower}'")
    fm_lines.append("---")
    return "\n".join(fm_lines)


def _body(pr):
    """Compose the PR note body. Auto-sync block goes between markers; manual
    edits BELOW the END marker are preserved on re-sync."""
    state = pr.get("state", "UNKNOWN")
    branch = pr.get("headRefName", "")
    merged = pr.get("mergedAt", "")[:10] if pr.get("mergedAt") else ""
    closed = pr.get("closedAt", "")[:10] if pr.get("closedAt") and not pr.get("mergedAt") else ""
    title = pr.get("title", "")
    pr_body = pr.get("body", "") or ""
    # Truncate body
    body_excerpt = pr_body[:1500]
    if len(pr_body) > 1500:
        body_excerpt += "\n\n*(body truncated for vault — full at GitHub URL above)*"

    lines = [
        f"# PR #{pr['number']}: {title}",
        "",
        AUTO_SYNC_MARKER_START,
        f"**State:** {state}  **Branch:** `{branch}`",
    ]
    if merged:
        lines.append(f"**Merged:** {merged}")
    if closed:
        lines.append(f"**Closed:** {closed}")
    lines.extend([
        "",
        "## Description (auto-synced from GitHub)",
        "",
        body_excerpt or "_(no description)_",
        "",
        AUTO_SYNC_MARKER_END,
        "",
        "## Manual notes",
        "",
        "_(edit below — preserved across re-syncs)_",
        "",
    ])
    return "\n".join(lines)


def _merge_with_existing(existing_text, new_frontmatter, new_body):
    """If existing note has manual notes below the AUTO_SYNC_MARKER_END, preserve them."""
    if AUTO_SYNC_MARKER_END not in existing_text:
        # No prior auto-sync structure; full overwrite
        return new_frontmatter + "\n\n" + new_body

    # Extract manual section from existing
    after_end = existing_text.split(AUTO_SYNC_MARKER_END, 1)[1]
    # Skip the "## Manual notes" header if it's the default; otherwise keep
    # Just preserve everything after the END marker
    return new_frontmatter + "\n\n" + new_body.rsplit(AUTO_SYNC_MARKER_END, 1)[0] + AUTO_SYNC_MARKER_END + after_end


def write_pr_note(vault_dir, pr, *, dry_run=False, log_path=None):
    """Write/update a single PR note. Returns ('created'|'updated'|'unchanged', path)."""
    section_dir = vault_dir / SECTION
    section_dir.mkdir(parents=True, exist_ok=True)
    path = section_dir / f"{pr['number']}.md"
    last_synced_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    llm_status = _llm_review_status_for_pr(pr["number"], log_path)
    new_fm = _frontmatter(pr, last_synced_iso, llm_review_status=llm_status)
    new_body = _body(pr)
    new_text = new_fm + "\n\n" + new_body

    if path.is_file():
        existing = path.read_text(encoding="utf-8")
        merged = _merge_with_existing(existing, new_fm, new_body)
        if existing == merged:
            return "unchanged", path
        if dry_run:
            return "would-update", path
        path.write_text(merged, encoding="utf-8")
        return "updated", path
    else:
        if dry_run:
            return "would-create", path
        path.write_text(new_text, encoding="utf-8")
        return "created", path


def staleness_check(vault_dir):
    """Return (max_synced_pr_number, latest_remote_pr_number) tuple."""
    section_dir = vault_dir / SECTION
    max_local = 0
    if section_dir.is_dir():
        for f in section_dir.glob("*.md"):
            try:
                n = int(f.stem)
                if n > max_local:
                    max_local = n
            except ValueError:
                continue
    # Latest remote PR via gh
    proc = subprocess.run(
        ["gh", "pr", "list", "--limit", "1", "--state", "all", "--json", "number"],
        capture_output=True, text=True, cwd=REPO,
    )
    if proc.returncode != 0:
        return max_local, None
    data = json.loads(proc.stdout or "[]")
    if not data:
        return max_local, None
    return max_local, data[0]["number"]


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--since-pr", type=int, help="backfill from this PR number forward")
    parser.add_argument("--all-merged", action="store_true", help="sync all merged PRs (large operation)")
    parser.add_argument("--limit", type=int, default=100, help="max PRs to fetch (default 100)")
    parser.add_argument("--vault-dir", help="override vault directory")
    parser.add_argument("--dry-run", action="store_true", help="show what would be written")
    parser.add_argument("--check", action="store_true", help="check vault PR staleness; exit non-zero if stale")
    parser.add_argument("--quiet", action="store_true", help="suppress per-PR output")
    args = parser.parse_args()

    vault = _resolve_vault_dir(args.vault_dir)
    _check_mcp_token()

    if args.check:
        local, remote = staleness_check(vault)
        if remote is None:
            print(f"[vault-pr-sync] check: gh unavailable; max local PR = {local}")
            return 0
        gap = max(0, remote - local) if local > 0 else remote
        print(f"[vault-pr-sync] check: vault max PR = {local}, GitHub latest = {remote}, gap = {gap}")
        return 1 if gap > 0 else 0

    prs = fetch_prs(since_pr=args.since_pr, all_merged=args.all_merged, limit=args.limit)
    counts = {"created": 0, "updated": 0, "unchanged": 0, "would-create": 0, "would-update": 0}
    for pr in prs:
        status, path = write_pr_note(vault, pr, dry_run=args.dry_run)
        counts[status] = counts.get(status, 0) + 1
        if not args.quiet:
            sys.stderr.write(f"[vault-pr-sync] {status}: PR #{pr['number']} ({pr.get('state','?')}) -> {path}\n")

    summary = ", ".join(f"{k}={v}" for k, v in counts.items() if v > 0) or "no changes"
    print(f"[vault-pr-sync] {len(prs)} PRs processed; {summary}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
