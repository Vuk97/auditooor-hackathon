#!/usr/bin/env python3
"""escalation-workflow-required-check.py - Check #128 (companion to #127).

Closes the loophole that escalate-first-required-check.py (#127) cannot: #127 is
a TEXT gate - it accepts a SINGLE agent's *sentence* ("I attempted Critical, the
blocker was X"). Nothing forces that the candidate higher in-scope impacts were
enumerated from the impact library, tested by an INDEPENDENT multi-lane workflow,
and LOGGED to an auditable ledger.

This gate: a finding filed BELOW its max reachable in-scope tier MUST carry a
`resolved` record in <ws>/.auditooor/escalation_attempts.jsonl (produced by
tools/escalation-workflow-planner.py) whose EVERY higher candidate target is
terminally resolved - `escalated` (with a PoC/evidence ref) or
`proof-of-impossibility` (with a code-cited guard/bound/recovery file:line) -
backed by >= MIN_VERIFICATION_LANES independent verification lanes (multi-agent,
not one agent's say-so).

Advisory by default (warn, rc 0). AUDITOOOR_ESCALATION_WORKFLOW_STRICT=1 makes a
missing / incomplete escalation workflow FAIL (rc 1). Rare legitimate exception:
a bounded `<!-- escalation-workflow-rebuttal: <reason up to 200 chars> -->`
marker (e.g. the finding is already at the max in-scope tier via a framing the
parser missed, or the higher tier is platform-OOS).

Verdicts:
  pass-out-of-scope                    severity below Medium (or untiered).
  pass-at-max-tier                     no in-scope rubric tier above the finding.
  pass-escalation-workflow-resolved    a resolved multi-lane record covers it.
  ok-rebuttal                          bounded escalation-workflow-rebuttal marker.
  fail-no-escalation-workflow          sub-max finding, no resolved ledger record.
  fail-escalation-workflow-incomplete  record exists but a candidate is not
                                       terminally resolved (missing lanes / open
                                       verdict / no evidence).

Exit: 0 pass-or-advisory-warn, 1 fail (strict), 2 input error.
Schema: auditooor.escalation_workflow_required.v1
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lib.escalation_ledger import (  # noqa: E402
    finding_id_for,
    higher_in_scope_targets,
    infer_tier,
    latest_record_for,
    max_reachable_tier,
    parse_severity_rows,
    record_is_resolved,
    tier_rank,
)

SCHEMA = "auditooor.escalation_workflow_required.v1"
GATE = "ESCALATION-WORKFLOW-REQUIRED"
STRICT_ENV = "AUDITOOOR_ESCALATION_WORKFLOW_STRICT"
_REBUTTAL_RE = re.compile(r"<!--\s*escalation-workflow-rebuttal:\s*(.+?)\s*-->", re.I | re.S)


def _emit(payload: dict, as_json: bool, human: str) -> None:
    print(json.dumps(payload) if as_json else human)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--draft", required=True, help="finding draft markdown")
    ap.add_argument("--workspace", help="workspace root (inferred from --draft if omitted)")
    ap.add_argument("--severity-md", help="override SEVERITY.md path")
    ap.add_argument("--current-tier", help="override tier (else inferred from draft)")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    strict = os.environ.get(STRICT_ENV) == "1"
    draft = Path(args.draft)

    def _infer_ws(start: Path) -> Path:
        for parent in [start.resolve()] + list(start.resolve().parents):
            if (parent / "SEVERITY.md").is_file():
                return parent
        return start.resolve().parent

    if args.workspace and (Path(args.workspace) / "SEVERITY.md").is_file():
        ws = Path(args.workspace).resolve()
    else:
        ws = _infer_ws(draft.parent if draft.is_file() else draft)
    if not draft.is_file():
        _emit({"schema": SCHEMA, "gate": GATE, "verdict": "input-error",
               "reason": f"draft not found: {draft}"}, args.json,
              f"[{GATE}] input-error: draft not found: {draft}")
        return 2
    draft_text = draft.read_text(encoding="utf-8", errors="replace")

    tier = (args.current_tier or infer_tier(draft_text) or "").lower()
    if not tier or tier_rank(tier) < tier_rank("medium"):
        _emit({"schema": SCHEMA, "gate": GATE, "verdict": "pass-out-of-scope",
               "tier": tier or None}, args.json,
              f"[{GATE}] pass-out-of-scope (tier={tier or 'none'} < medium)")
        return 0

    sev_md = Path(args.severity_md) if args.severity_md else (ws / "SEVERITY.md")
    rows = parse_severity_rows(sev_md)

    # False-pass guard: a Medium+ finding in a workspace whose SEVERITY.md is
    # missing / empty / unparseable must NOT silently pass-at-max-tier - the gate
    # cannot know the escalation ceiling, so it cannot certify nothing-to-escalate.
    if not rows:
        _emit({"schema": SCHEMA, "gate": GATE, "verdict": "fail-no-rubric", "strict": strict,
               "tier": tier, "severity_md": str(sev_md),
               "reason": f"no parseable rubric rows in {sev_md}; cannot verify the escalation "
                         f"ceiling for a {tier} finding"}, args.json,
              f"[{GATE}] fail-no-rubric ({'STRICT' if strict else 'advisory'}): no parseable "
              f"rows in {sev_md}; cannot certify {tier} is the max in-scope tier.")
        return 1 if strict else 0

    targets = higher_in_scope_targets(tier, rows)
    max_tier = max_reachable_tier(rows)

    if not targets:
        _emit({"schema": SCHEMA, "gate": GATE, "verdict": "pass-at-max-tier",
               "tier": tier, "max_reachable_tier": max_tier}, args.json,
              f"[{GATE}] pass-at-max-tier (tier={tier} == max in-scope {max_tier}; nothing higher)")
        return 0

    # rebuttal escape hatch
    reb = _REBUTTAL_RE.search(draft_text)
    if reb:
        _emit({"schema": SCHEMA, "gate": GATE, "verdict": "ok-rebuttal",
               "tier": tier, "rebuttal": reb.group(1).strip()[:200]}, args.json,
              f"[{GATE}] ok-rebuttal: {reb.group(1).strip()[:120]}")
        return 0

    finding_id = finding_id_for(draft, ws)
    record = latest_record_for(ws, finding_id)
    import hashlib
    draft_sha = hashlib.sha256(draft.read_bytes()).hexdigest()  # match planner _draft_sha
    ok, reason, failures = record_is_resolved(
        record, ws=ws, required_targets=targets, draft_sha=draft_sha,
        require_dispatch_log=strict)

    higher_rows = [t["severity_row"] for t in targets]
    if ok:
        _emit({"schema": SCHEMA, "gate": GATE, "verdict": "pass-escalation-workflow-resolved",
               "tier": tier, "finding_id": finding_id, "higher_targets": higher_rows,
               "reason": reason}, args.json,
              f"[{GATE}] pass-escalation-workflow-resolved: {reason} "
              f"({len(higher_rows)} higher target(s) attempted, multi-lane)")
        return 0

    verdict = "fail-escalation-workflow-incomplete" if record else "fail-no-escalation-workflow"
    payload = {"schema": SCHEMA, "gate": GATE, "verdict": verdict, "strict": strict,
               "tier": tier, "max_reachable_tier": max_tier, "finding_id": finding_id,
               "higher_targets": higher_rows, "reason": reason, "candidate_failures": failures,
               "remediation": (
                   f"run: python3 tools/escalation-workflow-planner.py plan --workspace {ws} "
                   f"--draft {draft} ; dispatch each emitted lane as >=2 independent adversarial "
                   f"lanes via spawn-worker; then escalation-workflow-planner.py finalize. "
                   f"OR add <!-- escalation-workflow-rebuttal: <reason> --> if truly at max tier.")}
    human = (f"[{GATE}] {verdict} ({'STRICT' if strict else 'advisory'}): {reason}. "
             f"Finding is {tier} but the rubric supports higher in-scope impact(s): "
             f"{', '.join(r[:50] for r in higher_rows)}. "
             + (f"Candidate gaps: {failures}. " if failures else "")
             + "No `resolved` multi-lane escalation_attempts record. "
             + payload["remediation"])
    _emit(payload, args.json, human)
    return 1 if strict else 0


if __name__ == "__main__":
    raise SystemExit(main())
