#!/usr/bin/env python3
"""kill-artifact-emitter.py — emit KILL_<id>.md final-disposition artifacts.

Per master mandate § 9.2: every KILL-RECOMMENDED paste-ready row from
paste-ready-triage.py must have a KILL_<id>.md file in
<workspace>/submissions/final_dispositions/. This avoids future agents
re-discovering the same dead lead.

Idempotent: skips rows that already have a KILL artifact at the target path.
Does NOT modify the original paste-ready (filing-freeze respected).

Schema produced (verbatim per § 9.2):
  # <Title>
  **Severity:** <verbatim>
  **Status:** KILL
  **Workspace:** <name>
  **Candidate ID:** <id>
  ## Verbatim rubric line
  ## Reason for kill
  ## Source citations
  ## Lesson learned (detector or fixture artifact)
  ## OOS analysis (if applicable)
  ## Public-fix / known-issue
  ## Final action
  ## Next blocker if revival considered
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import re
import sys
from pathlib import Path
from typing import Optional


WORKLIST_DIR = "/Users/wolf/audits/_worklist"


def latest_triage_json() -> Path:
    cands = sorted(glob.glob(os.path.join(WORKLIST_DIR, "PASTE_READY_TRIAGE_*.json")))
    if not cands:
        sys.exit(f"no PASTE_READY_TRIAGE_*.json under {WORKLIST_DIR}")
    return Path(cands[-1])


def candidate_id(name: str) -> str:
    return re.sub(r"\.md$", "", name)


def extract_section(md_text: str, header_regex: str) -> Optional[str]:
    """Return body of first ## section whose header matches the regex."""
    pat = re.compile(rf"^(#{{1,3}})\s+{header_regex}\s*$", re.MULTILINE | re.IGNORECASE)
    m = pat.search(md_text)
    if not m:
        return None
    start = m.end()
    rest = md_text[start:]
    nxt = re.search(r"^#{1,3}\s+", rest, re.MULTILINE)
    body = rest[: nxt.start()] if nxt else rest
    body = body.strip()
    return body or None


def extract_title(md_text: str) -> Optional[str]:
    m = re.match(r"^#\s+(.+?)\s*$", md_text, re.MULTILINE)
    return m.group(1).strip() if m else None


def extract_citations(md_text: str) -> str:
    """Pull source/affected file references for inheritance."""
    parts: list[str] = []
    for hdr in (
        r"Affected files?",
        r"Source code.*",
        r"Production Path",
        r"Source citations?",
    ):
        body = extract_section(md_text, hdr)
        if body:
            parts.append(f"### {hdr}\n{body}")
    if not parts:
        return "(no source-citation section found in paste-ready; inherit from triage rationale)"
    return "\n\n".join(parts)


def extract_oos(md_text: str) -> str:
    body = extract_section(md_text, r"Out-of-scope.*")
    if body:
        return body
    body = extract_section(md_text, r"OOS analysis")
    return body or "(no explicit OOS section in paste-ready)"


def extract_public_fix(md_text: str) -> str:
    body = extract_section(md_text, r"Public[- ]?fix.*|Known[- ]?issue.*|Status on latest.*")
    return body or "(no public-fix / known-issue note in paste-ready)"


def derive_lesson(row: dict) -> str:
    """One-paragraph lesson on what fix would prevent re-discovery."""
    structural = []
    for line in row.get("kill_justification", []):
        structural.append(line.strip())
    rationale = " ".join(row.get("rationale", []))

    hints: list[str] = []
    rk = "\n".join(structural).lower()
    if "novel class" in rk or "variant/incomplete" in rk:
        hints.append(
            "Add a detector / fixture that flags submissions framing themselves as "
            "variants or incomplete-fixes without a verified novel-class proof "
            "(see PR125 §9b novel-class gate)."
        )
    if "stub-coverage" in rk or "poc-stub-coverage" in rk:
        hints.append(
            "Strengthen poc-stub-coverage gate so paste-readies with stub/placeholder "
            "PoCs are caught at draft time (extend the stub-detector regex set)."
        )
    if "fork_replay" in rationale or "source-only justification" in rationale:
        hints.append(
            "Wire a pre-submit gate that requires either a fork_replay/* artifact or "
            "an explicit source-only-justification block before any High+ draft can "
            "graduate from staging."
        )
    if "oos" in rk or "OOS" in rationale:
        hints.append(
            "Add a per-finding-oos pre-flight detector that auto-runs on first save "
            "of a paste-ready, and marks the file with an OOS sigil so the reviewer "
            "doesn't waste cycles polishing prose."
        )
    if not hints:
        hints.append(
            "Encode the structural failure pattern from this triage rationale as a "
            "fixture in tools/library_fixture_triage.py so the same lead surface is "
            "rejected at intake next time."
        )
    return " ".join(hints)


def derive_next_blocker(row: dict) -> str:
    kj = "\n".join(row.get("kill_justification", []))
    if "novel class" in kj.lower() or "variant" in kj.lower():
        return (
            "Re-prove the underlying claim as a novel class — produce a fork-replay "
            "or source-only artifact that demonstrates the bug is not a known/duplicate "
            "variant. Without this, the submission cannot be revived."
        )
    if "stub-coverage" in kj.lower():
        return (
            "Replace stub PoC sections with a runnable fork_replay/* artifact that "
            "executes the exploit path end-to-end on a real fixture. Stub PoCs cannot "
            "satisfy poc-stub-coverage."
        )
    if "fork_replay" in kj or "source-only" in kj:
        return (
            "Provide a fork_replay/* citation OR an explicit source-only justification "
            "block that satisfies pre-submit-check #22 for High+ drafts."
        )
    if "oos" in kj.lower():
        return (
            "Resolve the per-finding-oos verdict — either rewrite the trigger to land "
            "fully in-scope or document the in-scope root-cause that makes the OOS "
            "prerequisite externally reachable."
        )
    return (
        "Address the structural failure listed in kill_justification before any "
        "revival attempt; until then, the lead remains dead."
    )


def render_artifact(row: dict, triage_md_path: str) -> str:
    name = row["name"]
    cid = candidate_id(name)
    workspace = row["workspace"]
    ws_name = os.path.basename(workspace.rstrip("/"))
    severity = row.get("severity") or "(unknown)"
    paste_path = row["path"]

    md_text = ""
    try:
        md_text = Path(paste_path).read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        md_text = ""

    title = extract_title(md_text) or cid

    rubric_lines = []
    for line in row.get("kill_justification", []) or row.get("gate_lines", []):
        rubric_lines.append(line.strip())
    verbatim_rubric = rubric_lines[0] if rubric_lines else "(no verbatim rubric line captured)"

    reasons = []
    for r in row.get("kill_justification", []):
        reasons.append(f"- {r.strip()}")
    for r in row.get("rationale", []):
        if r.strip():
            reasons.append(f"- {r.strip()}")
    reasons_blk = "\n".join(reasons) if reasons else "- (no rationale captured)"

    citations = extract_citations(md_text)
    oos_blk = extract_oos(md_text)
    public_fix = extract_public_fix(md_text)
    lesson = derive_lesson(row)
    next_blocker = derive_next_blocker(row)

    out = [
        f"# {title}",
        "",
        f"**Severity:** {severity}",
        "**Status:** KILL",
        f"**Workspace:** {ws_name}",
        f"**Candidate ID:** {cid}",
        "",
        "## Verbatim rubric line",
        "",
        f'> "{verbatim_rubric}"',
        "",
        "## Reason for kill",
        "",
        reasons_blk,
        "",
        "## Source citations",
        "",
        citations,
        "",
        "## Lesson learned (detector or fixture artifact)",
        "",
        lesson,
        "",
        "## OOS analysis (if applicable)",
        "",
        oos_blk,
        "",
        "## Public-fix / known-issue",
        "",
        public_fix,
        "",
        "## Final action",
        "",
        f"KILL — no submission. See triage rationale in {triage_md_path}",
        "",
        "## Next blocker if revival considered",
        "",
        next_blocker,
        "",
    ]
    return "\n".join(out)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--triage", default=None, help="path to PASTE_READY_TRIAGE_*.json (default: latest)")
    ap.add_argument("--dry-run", action="store_true", help="do not write files")
    args = ap.parse_args()

    triage_json = Path(args.triage) if args.triage else latest_triage_json()
    triage_md = str(triage_json).replace(".json", ".md")
    print(f"[emitter] triage source: {triage_json}")

    data = json.loads(triage_json.read_text(encoding="utf-8"))
    kills = [r for r in data["rows"] if r["bucket"] == "KILL-RECOMMENDED"]
    print(f"[emitter] KILL-RECOMMENDED rows: {len(kills)}")

    workspaces_touched: set[str] = set()
    emitted: list[str] = []
    skipped: list[str] = []

    for row in kills:
        cid = candidate_id(row["name"])
        ws = row["workspace"]
        fd_dir = Path(ws) / "submissions" / "final_dispositions"
        target = fd_dir / f"KILL_{cid}.md"

        if target.exists():
            print(f"  - skipped (already exists): {target}")
            skipped.append(str(target))
            continue

        body = render_artifact(row, triage_md)

        if args.dry_run:
            print(f"  - DRY: would write {target} ({len(body)} bytes)")
        else:
            fd_dir.mkdir(parents=True, exist_ok=True)
            target.write_text(body, encoding="utf-8")
            print(f"  - wrote: {target}")
        emitted.append(str(target))
        workspaces_touched.add(ws)

    print()
    print(f"[emitter] emitted: {len(emitted)} | skipped: {len(skipped)}")
    print(f"[emitter] workspaces touched: {sorted(workspaces_touched)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
