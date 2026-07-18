#!/usr/bin/env python3
"""anchor-lead-to-hunt-task.py - the missing downstream consumer of
<ws>/.auditooor/anchor_leads.jsonl (emitted by tools/commit-anchor-lead-emit.py).

WHY THIS EXISTS (72h capability audit, generic / all-language / all-workspace):
commit-anchor-lead-emit.py turns an OUT-OF-SCOPE security-shaped fix-commit into
an anchor lead naming the IN-SCOPE sibling file(s) that may share the same
unfixed pattern - but nothing reads anchor_leads.jsonl. That is the single
highest missed-findings-risk orphan under primacy-of-RULES: it is the only
capability that converts an OOS fix-commit into a directed in-scope anchor hunt.
This tool closes the loop: for every lead with >=1 in-scope sibling, it emits a
scoped hunt task that tells a hunter exactly what to check ("OOS commit <sha>
fixed <hint>; does in-scope <sibling> share the same unfixed pattern?").

SCHEMA CHOICE (documented per the assignment): the per-fn-mimo-batch-gen.py
task schema (auditooor.per_fn_mimo_batch.v1) is a heavily source-derived,
single-function-anchored prompt built from a ranked-questions row (chain
templates, exploit predicates, KDE, guard-negative-space, math-spec, economic
hypotheses, adversarial hypotheses...). An anchor lead is a DIFFERENT shape of
evidence: one OOS commit can implicate an entire in-scope FILE (frequently many
functions), and the actionable unit is "diff the OOS fix against this sibling
file", not "test one ranked hypothesis against one function". Forcing an anchor
lead through the per-fn schema would either drop the multi-function fan-out or
require fabricating a fake ranked-question row upstream of the real ranker.
So this tool emits its OWN standalone schema
(<ws>/.auditooor/anchor_hunt_tasks.jsonl, schema_version
auditooor.anchor_hunt_task.v1) - deliberately COMPATIBLE in spirit with the
per-fn hunt task shape (task_id / task_type / workspace / prompt / function
anchors) so a future wiring pass can fan these into the same dispatcher without
a second reader, but not literally unioned into per_fn_mimo_batch.v1 today.
Per the assignment this lane does NOT wire the emitter into the Makefile /
hunt-scoped driver - it only builds + proves the reader/emitter round-trip.

SIBLING RESOLUTION GAP (documented per the assignment): commit-anchor-lead-emit.py
resolves siblings with a Solidity-only declaration regex (_DECL_RE: `contract /
interface / library ... is ...`) plus a language-agnostic name-stem fallback.
This repo DOES have a generic call-graph-closure primitive
(tools/slither_predicates.py::has_guard_in_closure) but it is a Slither-AST-typed
guard/callee-closure walker - it operates on already-compiled Slither Function
objects, not on raw OOS git-blob text, and it answers "is X guarded" not "does
file A structurally resemble file B" across languages. It is not a drop-in
sibling-resolver for arbitrary Go/Rust/Move source text, so this tool does NOT
attempt to hand-roll a new cross-language symbol-relationship primitive here;
it consumes whatever siblings commit-anchor-lead-emit.py already resolved
(interface-sharing or name-stem, Solidity-first, name-stem fallback for other
languages) and notes the gap rather than half-implementing a riskier one.

USAGE:
  python3 tools/anchor-lead-to-hunt-task.py --workspace <ws>
  python3 tools/anchor-lead-to-hunt-task.py --workspace <ws> --json

Output: <ws>/.auditooor/anchor_hunt_tasks.jsonl - one row per (anchor_sha,
oos_file, in_scope_sibling) with >=1 resolved sibling. Leads with zero
resolved siblings are counted but NOT emitted as tasks (nothing directed to
hunt yet - matches the emitter's own "bare lead" case).
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT / "tools") not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT / "tools"))

import scope_authority as SA  # noqa: E402

SCHEMA = "auditooor.anchor_hunt_task.v1"
MAX_UNITS_PER_SIBLING = 25  # cap the fanned-out function-anchor list per sibling


def _leads_path(ws: Path) -> Path:
    return ws / ".auditooor" / "anchor_leads.jsonl"


def _tasks_path(ws: Path) -> Path:
    return ws / ".auditooor" / "anchor_hunt_tasks.jsonl"


def load_leads(ws: Path) -> list[dict]:
    """Read anchor_leads.jsonl (schema emitted by commit-anchor-lead-emit.py:
    anchor_sha, oos_file, in_scope_siblings[{in_scope_file, match}], hint).
    Malformed lines are skipped (best-effort, matches sibling reader convention
    elsewhere in this repo)."""
    p = _leads_path(ws)
    out: list[dict] = []
    if not p.is_file():
        return out
    for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(r, dict) and r.get("anchor_sha") and r.get("oos_file"):
            out.append(r)
    return out


def _units_for_sibling_basename(ws: Path, basename: str) -> list[dict]:
    """Every in-scope (file, function, file_line) row from inscope_units.jsonl
    whose file basename matches `basename`. A sibling lead only names a
    basename (commit-anchor-lead-emit.py's index is basename-keyed); this
    expands it to concrete function anchors so a hunter has real anchor
    points, not just a bare filename."""
    ins = SA.load_inscope(ws)
    if not ins.present:
        return []
    manifest = ws / ".auditooor" / "inscope_units.jsonl"
    if not manifest.is_file():
        return []
    out: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for line in manifest.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(r, dict):
            continue
        f = str(r.get("file") or "")
        if not f or Path(f).name != basename:
            continue
        fn = str(r.get("function") or "")
        key = (f, fn)
        if key in seen:
            continue
        seen.add(key)
        out.append({"file": f, "function": fn, "file_line": r.get("file_line") or "",
                    "lang": r.get("lang") or ""})
        if len(out) >= MAX_UNITS_PER_SIBLING:
            break
    return out


def _build_prompt(ws_name: str, lead: dict, sib: dict, units: list[dict]) -> str:
    sha = str(lead.get("anchor_sha") or "?")
    oos_file = str(lead.get("oos_file") or "?")
    hint = str(lead.get("hint") or "")[:400]
    sib_file = str(sib.get("in_scope_file") or "?")
    match = str(sib.get("match") or "?")
    nl = chr(10)
    parts = [
        f"You are a security auditor for {ws_name} (anchor-lead hunt).",
        "",
        "TASK: An OUT-OF-SCOPE commit fixed a security-shaped bug. Under primacy-of-RULES "
        "an OOS fix cannot itself be filed, but if the SAME unfixed pattern lives in an "
        "IN-SCOPE sibling, that IS a filable in-scope finding.",
        "",
        f"ANCHOR: OOS commit {sha} touched '{oos_file}' with a security-shaped fix.",
        f"COMMIT HINT: {hint}" if hint else "COMMIT HINT: (none recorded)",
        f"IN-SCOPE SIBLING: '{sib_file}' (matched via {match}).",
        "",
        "QUESTION TO ANSWER: does the in-scope sibling above share the same unfixed "
        "pattern the OOS commit just fixed? Read the OOS commit diff (git show <sha>) "
        "to see exactly what changed, then read the in-scope sibling's current source "
        "and check whether the pre-fix behavior is still present there.",
        "",
    ]
    if units:
        parts.append("CANDIDATE IN-SCOPE ANCHOR POINTS in the sibling file (file:line, function):")
        for u in units:
            parts.append(f"  - {u.get('file_line') or u.get('file')}  {u.get('function') or ''}")
        parts.append("")
    parts.extend([
        "OUTPUT: STRICT JSON only - no prose around it.",
        "REQUIRED JSON KEYS (all required, even if null/'NA'):",
        "  applies_to_target: yes | no | maybe",
        "  confidence: low | medium | high",
        "  candidate_finding: string (one-sentence brief, ANCHOR TO THE IN-SCOPE SIBLING)",
        "  file_line: 'path/to/file.ext:42' (must be a real line in the in-scope sibling)",
        "  code_excerpt: string (verbatim snippet FROM THE IN-SCOPE SIBLING source)",
        "  severity_estimate: LOW | MEDIUM | HIGH | CRITICAL | NA",
        "  rubric_row_cited: string verbatim from SEVERITY.md",
        "  dupe_check: string (cross-ref filed / known_dead_ends / BUG_BOUNTY.md OOS row)",
        "  notes: string",
        "",
        "HARD RULES (R76 hallucination guard): code_excerpt MUST be a verbatim substring of "
        "the in-scope sibling file; do NOT synthesize 'conceptual' code. If you cannot anchor "
        "to a real line in the in-scope sibling, set applies_to_target='no'.",
    ])
    return nl.join(parts)


def build_tasks(ws: Path, leads: list[dict]) -> list[dict]:
    ws_name = ws.name
    tasks: list[dict] = []
    idx = 0
    for lead in leads:
        sibs = lead.get("in_scope_siblings")
        if not isinstance(sibs, list) or not sibs:
            continue  # bare lead, no sibling resolved - nothing to direct a hunt at yet
        for sib in sibs:
            if not isinstance(sib, dict) or not sib.get("in_scope_file"):
                continue
            units = _units_for_sibling_basename(ws, str(sib["in_scope_file"]))
            prompt = _build_prompt(ws_name, lead, sib, units)
            task = {
                "schema_version": SCHEMA,
                "task_id": f"anchorhunt_{ws_name}_{idx:05d}",
                "task_type": "anchor_lead_hunt_v1",
                "workspace": ws_name,
                "workspace_path": str(ws),
                "anchor_sha": lead.get("anchor_sha"),
                "oos_file": lead.get("oos_file"),
                "in_scope_sibling": sib.get("in_scope_file"),
                "sibling_match": sib.get("match"),
                "candidate_anchors": units,
                "hint": lead.get("hint"),
                "prompt": prompt,
                "max_tokens": 1500,
            }
            tasks.append(task)
            idx += 1
    return tasks


def emit(ws: Path) -> dict:
    leads = load_leads(ws)
    tasks = build_tasks(ws, leads)
    out_path = _tasks_path(ws)
    with_sibs = sum(1 for l in leads if isinstance(l.get("in_scope_siblings"), list)
                     and l["in_scope_siblings"])
    bare = len(leads) - with_sibs
    if tasks:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text("\n".join(json.dumps(t) for t in tasks) + "\n", encoding="utf-8")
    return {
        "schema_version": SCHEMA,
        "leads_read": len(leads),
        "leads_with_siblings": with_sibs,
        "leads_bare": bare,
        "tasks_emitted": len(tasks),
        "path": str(out_path) if tasks else "",
        "tasks": tasks,
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--ws", "--workspace", dest="ws", required=True)
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    ws = Path(a.ws).expanduser()
    rep = emit(ws)
    if a.json:
        print(json.dumps({k: v for k, v in rep.items() if k != "tasks"}, indent=2))
    else:
        print(f"[anchor-lead-to-hunt-task] leads_read={rep['leads_read']} "
              f"with_siblings={rep['leads_with_siblings']} bare={rep['leads_bare']} "
              f"tasks_emitted={rep['tasks_emitted']}")
        for t in rep["tasks"][:20]:
            print(f"  {t['task_id']}  {t['oos_file']}  ->  {t['in_scope_sibling']} "
                  f"({len(t['candidate_anchors'])} anchor pts)")
        if rep["tasks_emitted"]:
            print(f"  output: {rep['path']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
