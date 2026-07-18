#!/usr/bin/env python3
"""Emit a compact rule + dead-end preamble for workflow agent() prompts.

Workflow agent() calls bypass the Agent-tool hook stack (MCP-first, spawn-worker,
universal-rule-enforce), so they get NO mechanical rule floor - only whatever the
script author hand-writes. This tool emits a small preamble that a workflow script
prepends to every agent prompt, giving workflow agents the same baseline as
hook-gated ones: the fileable rubric rows, the do-not-reescalate dead-ends, and the
load-bearing triage gates.

Keep it small (it rides on every agent prompt). Default ~700-1000 tokens.

Usage:
  workflow-rule-preamble.py --workspace <ws-path> [--dead-end-limit N] [--json]
  # in a workflow:  const PRE = <output>;  agent(PRE + "\n\n" + taskPrompt, {...})
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

DEAD_ENDS = Path(__file__).resolve().parent.parent / "reports" / "known_dead_ends.jsonl"

GATES = (
    "Triage gates every candidate MUST pass before you call it CONFIRM:\n"
    "- R76 source-exists: grep the cited code in the worktree; if it is not there verbatim, REFUTE (hallucination).\n"
    "- R52 rubric: the impact must verbatim-map a row in SEVERITY.md (below). No row -> not fileable.\n"
    "- R45 designed-as-intended: if docs/comments document the contested behavior as a design choice, it is not a bug.\n"
    "- R46 trusted-infra: if the exploit needs off-chain relayer/sequencer/fisherman/validator/collator compromise, it is likely OOS.\n"
    "- R24 non-self impact: the victim must be funds/state the attacker does NOT control.\n"
    "- Dupe: check submissions/{filed,paste_ready,staging,_killed} and known_dead_ends before raising.\n"
    "Default to REFUTE when uncertain. Honest empty/zero is correct for a sound target."
)


def _severity_rows(ws: Path) -> list[str]:
    sev = ws / "SEVERITY.md"
    rows = []
    if sev.is_file():
        for ln in sev.read_text(encoding="utf-8", errors="replace").splitlines():
            s = ln.strip()
            # capture rubric impact rows (bullets / table rows with an impact verb)
            if re.search(r"(loss of funds|freezing|theft|unauthorized|manipulation|RPC|crash|"
                         r"reentran|reorder|overflow|underflow|differs from|business description)", s, re.I):
                rows.append(re.sub(r"^[-*|>#\s]+", "", s)[:160])
    # dedup, cap
    seen, out = set(), []
    for r in rows:
        if r and r not in seen:
            seen.add(r); out.append(r)
    return out[:12]


def _dead_ends(ws_name: str, limit: int) -> list[str]:
    out = []
    if DEAD_ENDS.is_file():
        for ln in DEAD_ENDS.read_text(encoding="utf-8", errors="replace").splitlines():
            ln = ln.strip()
            if not ln:
                continue
            try:
                r = json.loads(ln)
            except json.JSONDecodeError:
                continue
            if (r.get("workspace") or "").lower() != ws_name.lower():
                continue
            surf = r.get("surface") or r.get("class") or "?"
            verd = r.get("verdict") or "dead-end"
            out.append(f"- {surf} [{verd}]: {(r.get('reason') or '')[:120]}")
    return out[-limit:] if limit else out


# Task-type -> the MCP callables this lane should run (mirrors the CLAUDE.md Layer-2
# lane-to-callable selectors). A dispatched agent gets told EXACTLY which command to run.
_MCP = "python3 /Users/wolf/auditooor-mcp/tools/vault-mcp-server.py --call"
LANE_SELECTORS = {
    "hunt": ["vault_exploit_context", "vault_hacker_questions", "vault_known_dead_ends"],
    "impact": ["vault_recovery_surface_worklist", "vault_known_dead_ends", "vault_exploit_context"],
    "loss": ["vault_recovery_surface_worklist", "vault_known_dead_ends"],
    "freeze": ["vault_recovery_surface_worklist", "vault_known_dead_ends"],
    "theft": ["vault_recovery_surface_worklist", "vault_known_dead_ends"],
    "dispute": ["vault_kill_rubric_context", "vault_triager_pattern_context", "vault_dupe_rejection_context"],
    "triager-response": ["vault_kill_rubric_context", "vault_triager_pattern_context"],
    "filing": ["vault_finalization_context", "vault_finding_lineage", "vault_engagement_status"],
    "verify": ["vault_known_dead_ends", "vault_lane_cooldown_check"],
    "drill": ["vault_known_dead_ends", "vault_lane_cooldown_check"],
    "depth": ["vault_invariant_library", "vault_anti_pattern_corpus"],
    "harness": ["vault_harness_context", "vault_harness_failure_context"],
    "poc": ["vault_harness_context", "vault_harness_failure_context"],
}


def _mcp_recall_block(ws: Path, lane_type: str | None) -> str:
    ws_name = ws.name
    lines = ["## MCP-FIRST RECALL (run these FIRST; record context_pack_id in your reply)",
             f"{_MCP} vault_resume_context --args '{{\"workspace_path\":\"{ws}\",\"limit\":4}}'",
             f"{_MCP} vault_known_dead_ends --args '{{\"workspace\":\"{ws_name}\",\"limit\":15}}'"]
    sel = LANE_SELECTORS.get((lane_type or "").lower().strip())
    if sel:
        lines.append(f"# lane={lane_type}: also run -")
        for c in sel:
            if c == "vault_recovery_surface_worklist":
                lines.append(f"python3 /Users/wolf/auditooor-mcp/tools/impact-recovery-falsification-check.py "
                             f"--emit-recovery-worklist {ws}   # R82: prove the victim recovers BEFORE building the attack")
            else:
                arg = f'{{\"workspace_path\":\"{ws}\",\"limit\":5}}'
                lines.append(f"{_MCP} {c} --args '{arg}'")
    lines.append("If MCP is unavailable in your context, load it via ToolSearch (query \"vault\") first; "
                 "do NOT proceed blind - the dead-ends below are your floor.")
    return "\n".join(lines)


def build(ws: Path, dead_end_limit: int, lane_type: str | None = None) -> str:
    ws_name = ws.name
    sev = _severity_rows(ws)
    dead = _dead_ends(ws_name, dead_end_limit)
    parts = [_mcp_recall_block(ws, lane_type),
             "## WORKFLOW RULE FLOOR (read before analyzing - you bypass the normal hook gates)"]
    if sev:
        parts.append("Fileable SEVERITY.md rows (impact MUST match one verbatim):\n" +
                     "\n".join(f"- {r}" for r in sev))
    else:
        parts.append("SEVERITY.md not found - confirm the fileable rows from the workspace before raising anything.")
    if dead:
        parts.append("DO-NOT-REESCALATE dead-ends for this workspace (already resolved):\n" + "\n".join(dead))
    parts.append(GATES)
    return "\n\n".join(parts)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--workspace", required=True, type=Path)
    ap.add_argument("--dead-end-limit", type=int, default=20)
    ap.add_argument("--lane-type", default=None,
                    help="hunt|impact|loss|freeze|theft|dispute|filing|verify|depth|harness|poc - "
                         "drives the task-specific MCP-recall selector")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    ws = args.workspace.expanduser().resolve()
    pre = build(ws, args.dead_end_limit, args.lane_type)
    if args.json:
        print(json.dumps({"workspace": str(ws), "preamble": pre,
                          "approx_tokens": len(pre) // 4}, indent=2))
    else:
        print(pre)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
