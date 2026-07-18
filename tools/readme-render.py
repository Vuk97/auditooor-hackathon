#!/usr/bin/env python3
"""readme-render — auto-generate the "Current Status" section of README.

Lane 8 of MCP harness review (PR #658) commit 6. Renders status info from:
  - gh pr list (open PRs)
  - obsidian-vault/.last_sync.json (vault freshness)
  - reference/outcomes.jsonl (recent filings + outcomes)
  - workspace SUBMISSIONS.md files (if found)

Usage:
    tools/readme-render.py                  # render to docs/STATUS.md (default)
    tools/readme-render.py --check          # exit 1 if README desync detected
    tools/readme-render.py --update-readme  # also update <!-- AUDITOOOR_AUTO --> blocks in README.md

Markers used in README.md:
    <!-- AUDITOOOR_AUTO:current-status -->
    ...auto-generated content...
    <!-- /AUDITOOOR_AUTO:current-status -->

Idempotent. Safe to run as cron / GH Action / pre-commit.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import re
import subprocess
import sys
from datetime import datetime, timezone

REPO = pathlib.Path(__file__).resolve().parent.parent
README = REPO / "README.md"
STATUS_DOC = REPO / "docs" / "STATUS.md"
OUTCOMES_LEDGER = REPO / "reference" / "outcomes.jsonl"
DEFAULT_VAULTS = [
    pathlib.Path("/Users/wolf/Documents/Codex/auditooor/obsidian-vault"),
    REPO / "obsidian-vault",
]
MARKER_START = "<!-- AUDITOOOR_AUTO:current-status -->"
MARKER_END = "<!-- /AUDITOOOR_AUTO:current-status -->"


def _gh_pr_count():
    """Returns dict {open: N, merged_last_30d: M} or {error: ...}."""
    try:
        proc = subprocess.run(
            ["gh", "pr", "list", "--state", "open", "--limit", "100", "--json", "number,createdAt,updatedAt"],
            capture_output=True, text=True, cwd=REPO, timeout=10,
        )
        if proc.returncode != 0:
            return {"error": "gh failed", "stderr": proc.stderr[:200]}
        data = json.loads(proc.stdout or "[]")
        # Dormancy: PRs not updated in 7+ days
        now = datetime.now(timezone.utc)
        dormant = 0
        for pr in data:
            updated = pr.get("updatedAt", "")
            if updated:
                try:
                    dt = datetime.fromisoformat(updated.replace("Z", "+00:00"))
                    if (now - dt).days >= 7:
                        dormant += 1
                except ValueError:
                    pass
        return {"open": len(data), "dormant_7d": dormant}
    except Exception as exc:
        return {"error": str(exc)[:120]}


def _vault_freshness():
    for v in DEFAULT_VAULTS:
        sync_file = v / ".last_sync.json"
        if sync_file.is_file():
            try:
                data = json.loads(sync_file.read_text())
                generated = data.get("generated", "?")
                total_notes = data.get("total_notes", 0)
                # Compute staleness
                try:
                    sync_dt = datetime.fromisoformat(generated.replace("Z", "+00:00"))
                    age_min = int((datetime.now(timezone.utc) - sync_dt).total_seconds() / 60)
                except (ValueError, AttributeError):
                    age_min = -1
                return {
                    "vault_dir": str(v),
                    "generated": generated,
                    "total_notes": total_notes,
                    "age_minutes": age_min,
                }
            except Exception:
                continue
    return {"error": "no .last_sync.json found"}


def _outcomes_summary():
    if not OUTCOMES_LEDGER.is_file():
        return {"error": "outcomes.jsonl missing"}
    rows = []
    for line in OUTCOMES_LEDGER.read_text(errors="replace").splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    # Aggregate by status × workspace
    by_workspace = {}
    by_status = {}
    for r in rows:
        ws = r.get("workspace", "?")
        status = r.get("status", "?")
        by_workspace[ws] = by_workspace.get(ws, 0) + 1
        by_status[status] = by_status.get(status, 0) + 1
    # Last 5 filings
    recent = sorted(rows, key=lambda r: r.get("recorded_at", ""), reverse=True)[:5]
    return {
        "total_rows": len(rows),
        "by_workspace": by_workspace,
        "by_status": by_status,
        "recent_5": [{"id": r.get("report_id", "?"), "status": r.get("status", "?"), "workspace": r.get("workspace", "?"), "severity": r.get("severity", "?"), "ts": r.get("recorded_at", "")[:10]} for r in recent],
    }


def render_status_block():
    pr = _gh_pr_count()
    vault = _vault_freshness()
    outcomes = _outcomes_summary()

    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    lines = [
        f"_Auto-rendered by `tools/readme-render.py` at {now_iso}. Edit triggers via `make readme-refresh`._",
        "",
        "### GitHub PRs",
    ]
    if "error" in pr:
        lines.append(f"- Status check failed: {pr['error']}")
    else:
        lines.append(f"- Open: **{pr['open']}**")
        lines.append(f"- Dormant (no update >7d): **{pr.get('dormant_7d', 0)}**")
    lines.extend(["", "### Vault freshness"])
    if "error" in vault:
        lines.append(f"- {vault['error']}")
    else:
        age = vault["age_minutes"]
        age_str = f"{age}m ago" if age < 120 else f"{age//60}h ago" if age < 1440 else f"{age//1440}d ago"
        lines.append(f"- Last sync: **{age_str}** ({vault['generated']})")
        lines.append(f"- Total notes: **{vault['total_notes']:,}**")
    lines.extend(["", "### Filed-finding outcomes"])
    if "error" in outcomes:
        lines.append(f"- {outcomes['error']}")
    else:
        lines.append(f"- Total tracked: **{outcomes['total_rows']}**")
        lines.append(f"- By status: {dict(outcomes['by_status'])}")
        lines.append(f"- By workspace: {dict(outcomes['by_workspace'])}")
        lines.append("")
        lines.append("**Last 5 filings:**")
        for r in outcomes["recent_5"]:
            lines.append(f"  - `{r['id']}` ({r['severity']}/{r['status']}) on `{r['workspace']}` — {r['ts']}")
    lines.extend(["", "### Active discipline rules", "- See `docs/CODIFIED_DISCIPLINE_RULES_2026-05-08.md` (L1-L32)"])
    lines.extend(["", "### Active attacker mental frames",
                  "- 7 frames in `reference/attacker_frames/` (AMF-001 through AMF-007)"])
    return "\n".join(lines)


def write_status_doc(content):
    STATUS_DOC.parent.mkdir(parents=True, exist_ok=True)
    body = "# Auditooor — Current Status (auto-rendered)\n\n" + content + "\n"
    STATUS_DOC.write_text(body)
    return STATUS_DOC


def update_readme(content):
    """Replace content between AUDITOOOR_AUTO markers in README.md.

    If markers don't exist, leave README unchanged and return False.
    """
    if not README.is_file():
        return False
    text = README.read_text()
    if MARKER_START not in text or MARKER_END not in text:
        return False
    pattern = re.compile(
        r"(" + re.escape(MARKER_START) + r")(.*?)(" + re.escape(MARKER_END) + r")",
        re.DOTALL,
    )
    new_text = pattern.sub(MARKER_START + "\n" + content + "\n" + MARKER_END, text)
    if new_text == text:
        return False
    README.write_text(new_text)
    return True


def check_readme_in_sync():
    """Returns True if README's auto block matches what we'd render."""
    if not README.is_file():
        return True  # no README, vacuously in sync
    text = README.read_text()
    if MARKER_START not in text or MARKER_END not in text:
        return True  # no markers, no sync requirement
    fresh = render_status_block()
    pattern = re.compile(
        r"" + re.escape(MARKER_START) + r"(.*?)" + re.escape(MARKER_END),
        re.DOTALL,
    )
    m = pattern.search(text)
    if not m:
        return True
    current = m.group(1).strip()
    return current == fresh.strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--check", action="store_true", help="exit 1 if README desync")
    parser.add_argument("--update-readme", action="store_true", help="also update README.md auto block")
    parser.add_argument("--no-status-doc", action="store_true", help="skip writing docs/STATUS.md")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    content = render_status_block()

    if args.check:
        in_sync = check_readme_in_sync()
        print(f"[readme-render] README in_sync: {in_sync}")
        return 0 if in_sync else 1

    if not args.no_status_doc:
        path = write_status_doc(content)
        if not args.quiet:
            print(f"[readme-render] wrote {path}")

    if args.update_readme:
        updated = update_readme(content)
        if not args.quiet:
            print(f"[readme-render] README updated: {updated}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
