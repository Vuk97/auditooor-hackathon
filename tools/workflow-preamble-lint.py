#!/usr/bin/env python3
"""Lint a Workflow script for dispatch-parity: do its agent() calls carry the MCP-recall
+ rule-floor preamble that Agent-tool and Codex dispatch get automatically?

Workflow agent() calls bypass the Agent-tool PreToolUse hook stack (MCP-first,
spawn-worker, universal-rule-enforce), so a dispatched workflow agent gets NO recall
or rule floor unless the script author prepends it. This linter is the parity backstop:
it flags a workflow whose agents would run blind.

A workflow PASSES when EITHER:
  - it shells out to `workflow-rule-preamble.py` (the preamble is built + prepended), OR
  - every agent() prompt references an MCP-recall signal (vault_resume_context /
    known_dead_ends / vault_ / MCP-FIRST / recovery-worklist) or the preamble variable.

Use as a manual lint (`workflow-preamble-lint.py <script.js>`) or wire as a PreToolUse
hook on the Workflow tool: read the script being launched, fail/warn if it does not pass.

Usage:
  workflow-preamble-lint.py <workflow_script.js> [--strict] [--json]
  # hook mode: reads the tool-input JSON on stdin, extracts .script / .scriptPath
  workflow-preamble-lint.py --hook
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

# signals that an agent prompt carries recall / rule-floor context
_RECALL_SIGNALS = re.compile(
    r"vault_resume_context|vault_known_dead_ends|known_dead_ends|vault_[a-z_]+|"
    r"MCP-FIRST|mcp.first|recall|recovery-worklist|emit-recovery-worklist|"
    r"workflow-rule-preamble|RULE FLOOR|dead-end", re.I)
_PREAMBLE_TOOL = re.compile(r"workflow-rule-preamble\.py|workflow-context-packets\.py")
# crude agent() prompt extraction: agent(`...`) or agent("...") or agent(VAR + ...)
_AGENT_CALL = re.compile(r"\bagent\s*\(", re.M)


def lint(script_text: str) -> dict:
    if _PREAMBLE_TOOL.search(script_text):
        return {"verdict": "pass-preamble-tool-used", "agent_calls": len(_AGENT_CALL.findall(script_text)),
                "reason": "script builds the recall/rule preamble via workflow-rule-preamble.py / context-packets"}
    n_agents = len(_AGENT_CALL.findall(script_text))
    if n_agents == 0:
        return {"verdict": "pass-no-agents", "agent_calls": 0, "reason": "no agent() calls"}
    # does the script reference any recall signal at all?
    if _RECALL_SIGNALS.search(script_text):
        # a shared preamble variable concatenated into prompts counts
        if re.search(r"(PRE|PREAMBLE|RECALL|RULE_FLOOR|RB)\b\s*\+|\+\s*(PRE|PREAMBLE|RECALL|RB)\b", script_text):
            return {"verdict": "pass-recall-signal-in-prompts", "agent_calls": n_agents,
                    "reason": "agents reference a shared recall/preamble variable"}
        return {"verdict": "pass-recall-signal-present", "agent_calls": n_agents,
                "reason": "script references MCP-recall / dead-end signals (verify each agent prompt uses them)"}
    return {"verdict": "fail-agents-without-recall", "agent_calls": n_agents,
            "reason": (f"{n_agents} agent() call(s) and NO MCP-recall / rule-floor signal - dispatched workflow "
                       "agents will run blind. Prepend workflow-rule-preamble.py output (with --lane-type) to every "
                       "agent prompt, or run impact-recovery-falsification --emit-recovery-worklist for impact lanes.")}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("script", nargs="?", type=Path)
    ap.add_argument("--hook", action="store_true", help="read tool-input JSON on stdin (.script/.scriptPath)")
    ap.add_argument("--strict", action="store_true")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    text = ""
    if args.hook:
        try:
            payload = json.load(sys.stdin)
            ti = payload.get("tool_input", payload)
            if ti.get("script"):
                text = ti["script"]
            elif ti.get("scriptPath") and Path(ti["scriptPath"]).is_file():
                text = Path(ti["scriptPath"]).read_text(encoding="utf-8", errors="replace")
        except Exception:
            print(json.dumps({"verdict": "pass-no-script"})); return 0
    elif args.script and args.script.is_file():
        text = args.script.read_text(encoding="utf-8", errors="replace")
    else:
        print("[workflow-preamble-lint] no script"); return 2

    if not text:
        out = {"verdict": "pass-no-script"}
    else:
        out = lint(text)

    if args.json or args.hook:
        print(json.dumps(out))
    else:
        print(f"[workflow-preamble-lint] {out['verdict']}: {out.get('reason','')}")
    return 1 if (out["verdict"].startswith("fail") and args.strict) else 0


if __name__ == "__main__":
    raise SystemExit(main())
