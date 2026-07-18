#!/usr/bin/env python3
"""Emit canonical Agent-route triage batches for IGAL incomplete-guard hypotheses.

The incomplete-guard-acknowledgement-scanner surfaces developer-confessed-incompleteness
markers (FIXME/TODO/skip-return co-located with a guard/sink) as ranked hypotheses. This
tool turns the HIGH (and, with --include-med, MED) bucket into per-batch agent prompts -
the canonical "emit-agent-batches" step, mirroring depth-probe-runner. The orchestrator
dispatches each batch via Agent(sonnet) through spawn-worker.sh; the agent reads REAL
source (R76) and emits one combined classification + fileability verdict per item.
``igal-disposition-ingest.py`` then folds the verdicts into the gate's disposition file.

  IN:  <ws>/.auditooor/incomplete_guard_ack_hypotheses.jsonl   (scanner output)
  OUT: <ws>/.auditooor/igal_triage/_agent_plan/batch_NNN.md    (agent prompts)
       <ws>/.auditooor/igal_triage/_agent_plan/manifest.json   (batch index)

The agent must write a JSON array to <ws>/.auditooor/igal_triage/batch_NNN.jsonl with,
per item: {file_line, ack_line, classification(finding-candidate|benign),
fileable(true|false|null), severity, blocking_gate, reason, code_excerpt}.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

HYP_REL = ".auditooor/incomplete_guard_ack_hypotheses.jsonl"
PLAN_DIR_REL = ".auditooor/igal_triage/_agent_plan"
CONTEXT_PACK = "auditooor.vault_context_pack.v1:resume:2efda22b604c944d"

_PROMPT_HEAD = """\
<!-- BEGIN MCP-FIRST RECALL -->
MCP-FIRST RECALL: context_pack_id {pack}.
Workspace {ws} (Immunefi/Cantina audit target). SEVERITY.md + SCOPE.md + scope.json govern.
R76 HARD RULE: open and READ the REAL source at /abs/<file> before deciding; a verdict whose
code_excerpt is absent from real source is rejected.
<!-- END MCP-FIRST RECALL -->

# IGAL TRIAGE - developer-confessed incomplete-guard hypotheses (batch {idx}/{total})

Each item below is a place where in-scope source carries a self-acknowledgement marker
(FIXME/TODO/HACK/unimplemented!/skip-return) CO-LOCATED with a guard/validation/sink. For
EACH, open and READ the real source at the cited file:line and decide, in ONE pass:
  classification = "finding-candidate"  if it is a real security-relevant incompleteness,
                   "benign"             if by-design / covered elsewhere / dev-comment /
                                        unreachable / governance-trusted-only.
  For a finding-candidate ALSO adjudicate fileability (hostile-triager mindset):
    fileable = true   only if reachable via HONEST operation AND exploitable by a
                      NON-trusted external attacker AND it fits a SEVERITY.md row AND is
                      not dev/test-only and not an acknowledged/known issue;
             = false  otherwise (give the single blocking_gate: reachability-trusted |
                      dev-only | dupe | rubric | core-product).
  For benign items set fileable=null.

OUTPUT: a JSON array ONLY (final message) AND write it to
{out_jsonl}
One object per item:
  {{"file_line":"<file>:<ack_line>","ack_line":<n>,"classification":"finding-candidate|benign",
    "fileable":true|false|null,"severity":"Critical|High|Medium|Low|n/a",
    "blocking_gate":"reachability-trusted|dev-only|dupe|rubric|core-product|none",
    "reason":"<=300 chars","code_excerpt":"<verbatim line from real source>"}}
End with: FINDING_CANDIDATES=<n> BENIGN=<n> FILEABLE=<n>.

## ITEMS
"""


def _load_hyps(ws: Path, include_med: bool) -> list[dict]:
    p = ws / HYP_REL
    if not p.is_file():
        return []
    buckets = {"high"} | ({"med"} if include_med else set())
    rows = []
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            r = json.loads(line)
        except ValueError:
            continue
        if str(r.get("rank_bucket")) in buckets:
            rows.append(r)
    return rows


def _item_block(i: int, r: dict) -> str:
    fl = f"{r.get('file')}:{r.get('ack_line')}"
    out = [f"\n### [{i}] {fl}  fn={r.get('function')}  lang={r.get('language')}  bucket={r.get('rank_bucket')}"]
    out.append(f"ack: [{r.get('ack_token')}] {r.get('ack_text')}")
    out.append(f"sink @ {r.get('sink_line')}: {r.get('sink_text')}  (kind={r.get('sink_kind')})")
    if r.get("skipped_call"):
        out.append(f"skipped_call: {r.get('skipped_call')}")
    out.append(f"security_keywords: {r.get('security_keywords')}  rank_score={r.get('rank_score')}")
    return "\n".join(out)


def emit(ws: Path, batch_size: int, include_med: bool) -> dict:
    hyps = _load_hyps(ws, include_med)
    plan = ws / PLAN_DIR_REL
    plan.mkdir(parents=True, exist_ok=True)
    # clear any stale plan so a re-emit is clean
    for old in plan.glob("batch_*.md"):
        old.unlink()
    batches = [hyps[i:i + batch_size] for i in range(0, len(hyps), batch_size)] or []
    total = len(batches)
    manifest = []
    for idx, batch in enumerate(batches):
        out_jsonl = str(ws / ".auditooor" / "igal_triage" / f"batch_{idx:03d}.jsonl")
        body = _PROMPT_HEAD.format(
            pack=CONTEXT_PACK, ws=str(ws), idx=idx + 1, total=total, out_jsonl=out_jsonl)
        body += "".join(_item_block(i + 1, r) for i, r in enumerate(batch))
        path = plan / f"batch_{idx:03d}.md"
        path.write_text(body, encoding="utf-8")
        manifest.append({"batch": idx, "prompt": str(path), "out": out_jsonl, "items": len(batch)})
    (plan / "manifest.json").write_text(
        json.dumps({"schema": "auditooor.igal_triage_plan.v1", "workspace": str(ws),
                    "total_hypotheses": len(hyps), "batches": manifest}, indent=1),
        encoding="utf-8")
    return {"hypotheses": len(hyps), "batches": total, "plan_dir": str(plan),
            "include_med": include_med}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--workspace", "--ws", required=True)
    ap.add_argument("--batch-size", type=int, default=12)
    ap.add_argument("--include-med", action="store_true",
                    help="also emit MED-bucket hypotheses (default: HIGH only)")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    ws = Path(args.workspace).resolve()
    if not ws.is_dir():
        print(f"[igal-triage-emit] ERR workspace not found: {ws}", file=sys.stderr)
        return 2
    res = emit(ws, args.batch_size, args.include_med)
    if args.json:
        print(json.dumps(res))
    else:
        for k, v in res.items():
            print(f"{k}: {v}")
        if res["batches"]:
            print(f"[igal-triage-emit] dispatch each {res['plan_dir']}/batch_*.md via "
                  f"Agent(sonnet) through spawn-worker.sh, then run igal-disposition-ingest.py")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
