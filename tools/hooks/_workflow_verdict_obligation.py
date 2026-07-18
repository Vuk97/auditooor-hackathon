#!/usr/bin/env python3
"""Helper for auditooor-workflow-verdict-obligation.sh (PostToolUse on Workflow/Task).
Reads the tool-call JSON payload on STDIN, the obligation-ledger path as argv[1].
Records a verdict-persistence obligation when a Workflow OR Task/Agent dispatch that
touches an audit workspace launches. See the .sh wrapper + hunt-verdict-persistence-gate.py.

# TODO (operator action required): the PostToolUse hook matcher in ~/.claude/settings.json
# currently fires only on tool_name="Workflow". It must ALSO include "Task" so that
# Task-dispatched hunts trigger the .sh wrapper in the first place. Without that change
# this Python helper will never see Task payloads. Add "Task" to the matcher's
# tool_name list (or use a regex that matches both) in the hooks configuration.
"""
from __future__ import annotations

import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

try:
    import fcntl  # POSIX advisory locks; absent on Windows
except Exception:  # pragma: no cover
    fcntl = None


def main() -> int:
    if len(sys.argv) < 2:
        return 0
    ledger = Path(sys.argv[1])
    try:
        payload = json.load(sys.stdin)
    except Exception:
        return 0

    tool_name = payload.get("tool_name") or payload.get("toolName") or ""
    if tool_name not in ("Workflow", "Task"):
        return 0

    ti = payload.get("tool_input") or payload.get("toolInput") or {}
    tr = payload.get("tool_response") or payload.get("toolResponse") or ""
    if isinstance(tr, dict):
        tr = json.dumps(tr)
    tr = str(tr)

    script = ti.get("script") or ""
    if not script:
        sp = ti.get("scriptPath") or ""
        if sp and Path(sp).exists():
            try:
                script = Path(sp).read_text(encoding="utf-8", errors="replace")
            except OSError:
                script = ""
    # For Task dispatches the workspace path lives in ti["prompt"] / ti["description"]
    # rather than ti["script"]; include ALL string values from tool_input in the haystack.
    ti_text = " ".join(str(v) for v in ti.values() if isinstance(v, str))
    haystack = script + "\n" + ti_text + "\n" + tr

    workspaces = re.findall(r"/Users/[^/]+/audits/[A-Za-z0-9_.\-]+", haystack)
    roots = sorted({re.match(r"(/Users/[^/]+/audits/[^/]+)", w).group(1) for w in workspaces})
    if not roots:
        return 0

    m = re.search(r"\b(wf_[a-z0-9\-]{6,})\b", tr) or re.search(r"\b(wf_[a-z0-9\-]{6,})\b", haystack)
    run_id = m.group(1) if m else ""
    if not run_id:
        tm = re.search(r"Task ID:\s*([A-Za-z0-9_\-]+)", tr)
        run_id = tm.group(1) if tm else ""
    if not run_id:
        return 0

    ledger.parent.mkdir(parents=True, exist_ok=True)
    rec = {
        "schema": "auditooor.verdict_obligation.v1",
        "run_id": run_id,
        "workspaces": roots,
        "tool": tool_name,
        "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "status": "open",
    }
    # Read-dedup-append under an EXCLUSIVE lock so two PostToolUse hooks firing
    # concurrently (multiple Workflow launches in one message) cannot race each
    # other's read-then-append and drop an obligation.
    with ledger.open("a+", encoding="utf-8") as fh:
        if fcntl is not None:
            try:
                fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
            except OSError:
                pass
        try:
            fh.seek(0)
            for line in fh.read().splitlines():
                try:
                    if json.loads(line).get("run_id") == run_id:
                        return 0  # already recorded
                except Exception:
                    continue
            fh.write(json.dumps(rec) + "\n")
            fh.flush()
        finally:
            if fcntl is not None:
                try:
                    fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
                except OSError:
                    pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
