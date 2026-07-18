#!/usr/bin/env python3
"""Big-Loss Template Runner — Phase F (corpus-mining plan 2026-05-08).

Reads reference/big_loss_templates/*.json and evaluates them against a target
workspace. For each matching template (or the single template named via
--template), emits a per-step verdict JSON showing:

  - whether the workspace's scope_path_regex fires
  - per actor_sequence step: applicable, evidence_required, actual_state
  - kill_conditions that are live

CLI shape mirrors big-loss-template-compose.py (--workspace, --template,
--print-json, --out).  Stdlib-only, offline-safe.

Examples
--------
    python3 tools/big-loss-template-runner.py \\
        --workspace ~/audits/base-azul \\
        --template bridge_proof_domain

    python3 tools/big-loss-template-runner.py \\
        --workspace ~/audits/dydx \\
        --print-json

    python3 tools/big-loss-template-runner.py \\
        --workspace ~/audits/base-azul \\
        --template consensus_parser_differential \\
        --out /tmp/runner_out.json
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "auditooor.big_loss_template_runner.v1"

_REPO_ROOT = Path(__file__).resolve().parent.parent
_TEMPLATES_DIR = _REPO_ROOT / "reference" / "big_loss_templates"
_INDEX_PATH = _TEMPLATES_DIR / "INDEX.json"


# ---------------------------------------------------------------------------
# Loaders
# ---------------------------------------------------------------------------

def _load_json(path: Path) -> Any:
    with path.open() as fh:
        return json.load(fh)


def _load_templates() -> dict[str, dict]:
    """Return {template_id: template_dict} from index."""
    index = _load_json(_INDEX_PATH)
    templates: dict[str, dict] = {}
    for entry in index.get("templates", []):
        tid = entry["template_id"]
        tfile = _REPO_ROOT / entry["file"]
        if tfile.exists():
            templates[tid] = _load_json(tfile)
    return templates


def _load_ledger(ws: Path) -> list[dict]:
    ledger_path = ws / ".auditooor" / "invariant_ledger.json"
    if not ledger_path.exists():
        return []
    data = _load_json(ledger_path)
    return data.get("rows", [])


# ---------------------------------------------------------------------------
# Workspace class detection
# ---------------------------------------------------------------------------

def _collect_workspace_paths(ws: Path) -> list[str]:
    """Return all relative file paths under ws (sample up to 5000 for speed)."""
    paths: list[str] = []
    try:
        for p in ws.rglob("*"):
            if p.is_file():
                try:
                    paths.append(str(p.relative_to(ws)))
                except ValueError:
                    pass
            if len(paths) >= 5000:
                break
    except PermissionError:
        pass
    return paths


def _collect_symbol_line_hits(
    ws: Path,
    workspace_paths: list[str],
    *,
    symbol: str,
    max_hits: int = 20,
) -> list[str]:
    """Return refs like `rel/path.rs:line` where symbol appears (best-effort)."""
    hits: list[str] = []
    if not symbol:
        return hits

    for rel in workspace_paths:
        if not rel.endswith(".rs"):
            continue
        path = ws / rel
        try:
            with path.open(errors="replace") as fh:
                for ln, line in enumerate(fh, start=1):
                    if symbol in line:
                        hits.append(f"{rel}:{ln}")
                        if len(hits) >= max_hits:
                            return hits
        except OSError:
            continue
    return hits


def _collect_consensus_predicate_context(ws: Path, workspace_paths: list[str]) -> dict[str, list[str]]:
    """Collect concrete path/symbol hits for consensus_parser_differential worklist predicates."""

    def _path_hits(token: str) -> list[str]:
        token_l = token.lower()
        return [p for p in workspace_paths if token_l in p.lower()]

    return {
        "attributes_path_hits": _path_hits("attributes.rs"),
        "engine_request_processor_path_hits": _path_hits("engine_request_processor"),
        "seal_task_path_hits": _path_hits("seal/task"),
        "stateful_path_hits": _path_hits("stateful"),
        "is_deposits_only_symbol_hits": _collect_symbol_line_hits(
            ws,
            workspace_paths,
            symbol="is_deposits_only",
        ),
    }


def _workspace_scope_text(ws: Path) -> str:
    """Build a single text blob representing the workspace scope for regex matching.

    Combines:
    - All relative file paths (for scope_path_regex)
    - Ledger row production_path and invariant_family fields
    - Any SCOPE.md or engage_report.md text snippets (first 2 KB each)
    """
    parts: list[str] = []

    # File tree
    parts.extend(_collect_workspace_paths(ws))

    # Ledger rows
    for row in _load_ledger(ws):
        for field in ("production_path", "invariant_family", "scope_status"):
            val = row.get(field)
            if val:
                parts.append(str(val))

    # SCOPE.md / engage_report.md snippets
    for fname in ("SCOPE.md", "engage_report.md", "INTAKE_BASELINE.md"):
        fpath = ws / fname
        if fpath.exists():
            try:
                parts.append(fpath.read_text(errors="replace")[:2048])
            except OSError:
                pass

    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Template applicability
# ---------------------------------------------------------------------------

def _template_matches_workspace(template: dict, scope_text: str) -> bool:
    """Return True if scope_path_regex fires anywhere in the workspace scope text."""
    aw = template.get("applicable_when", {})
    pat = aw.get("scope_path_regex", "")
    if not pat:
        return True  # no constraint → always applicable
    try:
        return bool(re.search(pat, scope_text))
    except re.error:
        return False


def _invariant_family_matches(template: dict, row: dict) -> bool:
    """Return True if template's invariant_family_regex matches row.invariant_family."""
    aw = template.get("applicable_when", {})
    pat = aw.get("invariant_family_regex", "")
    family = row.get("invariant_family", "")
    if not pat:
        return True
    try:
        return bool(re.search(pat, family))
    except re.error:
        return False


# ---------------------------------------------------------------------------
# Per-step verdict
# ---------------------------------------------------------------------------

def _evaluate_step(
    step_def: dict,
    ws: Path,
    scope_text: str,
    *,
    template_id: str,
    consensus_predicate_ctx: dict[str, list[str]] | None = None,
) -> dict:
    """Evaluate a single actor_sequence step against workspace artifacts."""
    step_n = step_def.get("step", 0)
    actor = step_def.get("actor", "")
    action = step_def.get("action", "")
    target = step_def.get("target", "")
    prerequisite = step_def.get("prerequisite", "")
    evidence_required = step_def.get("evidence_required", "")

    # Heuristic: check whether the target path/symbol pattern appears in scope
    target_found = False
    if target:
        # Strip angle-bracket placeholders for matching
        cleaned_target = re.sub(r"<[^>]+>", "", target)
        # Try each pipe-separated alternative
        for alt in re.split(r"\s*\|\s*", cleaned_target):
            alt = alt.strip()
            if alt and re.search(re.escape(alt), scope_text, re.IGNORECASE):
                target_found = True
                break
    else:
        target_found = True  # no target specified

    actual_state = (
        "target found in workspace scope" if target_found
        else "target NOT found in workspace scope (step may be N/A for this workspace)"
    )

    worklist_predicates: list[dict[str, Any]] = []
    if template_id == "consensus_parser_differential":
        ctx = consensus_predicate_ctx or {}
        if step_n == 1 and ctx.get("attributes_path_hits"):
            worklist_predicates.append(
                {
                    "predicate_id": "cpd.step1.attributes_path_present",
                    "status": "needs_evidence",
                    "advisory_only": True,
                    "hit_refs": ctx["attributes_path_hits"],
                }
            )
        elif step_n == 2 and ctx.get("is_deposits_only_symbol_hits"):
            worklist_predicates.append(
                {
                    "predicate_id": "cpd.step2.is_deposits_only_symbol_present",
                    "status": "needs_evidence",
                    "advisory_only": True,
                    "hit_refs": ctx["is_deposits_only_symbol_hits"],
                }
            )
        elif step_n == 3:
            if ctx.get("engine_request_processor_path_hits"):
                worklist_predicates.append(
                    {
                        "predicate_id": "cpd.step3.engine_request_processor_path_present",
                        "status": "needs_evidence",
                        "advisory_only": True,
                        "hit_refs": ctx["engine_request_processor_path_hits"],
                    }
                )
            if ctx.get("seal_task_path_hits"):
                worklist_predicates.append(
                    {
                        "predicate_id": "cpd.step3.seal_task_path_present",
                        "status": "needs_evidence",
                        "advisory_only": True,
                        "hit_refs": ctx["seal_task_path_hits"],
                    }
                )
        elif step_n == 4:
            if ctx.get("seal_task_path_hits"):
                worklist_predicates.append(
                    {
                        "predicate_id": "cpd.step4.seal_task_path_present",
                        "status": "needs_evidence",
                        "advisory_only": True,
                        "hit_refs": ctx["seal_task_path_hits"],
                    }
                )
            if ctx.get("stateful_path_hits"):
                worklist_predicates.append(
                    {
                        "predicate_id": "cpd.step4.stateful_path_present",
                        "status": "needs_evidence",
                        "advisory_only": True,
                        "hit_refs": ctx["stateful_path_hits"],
                    }
                )

    return {
        "step": step_n,
        "actor": actor,
        "action": action,
        "target": target,
        "prerequisite": prerequisite,
        "evidence_required": evidence_required,
        "applicable": target_found,
        "actual_state": actual_state,
        "worklist_predicates": worklist_predicates,
    }


# ---------------------------------------------------------------------------
# Template runner
# ---------------------------------------------------------------------------

def run_template(template: dict, ws: Path) -> dict:
    """Run a single template against a workspace; return a verdict dict."""
    tid = template.get("template_id", "unknown")
    title = template.get("title", "")
    scope_text = _workspace_scope_text(ws)
    workspace_paths = _collect_workspace_paths(ws)

    workspace_match = _template_matches_workspace(template, scope_text)

    # Ledger rows that match the invariant_family_regex
    ledger_rows = _load_ledger(ws)
    matching_rows: list[dict] = []
    for row in ledger_rows:
        row_id = row.get("row_id", row.get("id", ""))
        scope_status = row.get("scope_status", "")
        if scope_status == "OOS":
            continue
        severity = row.get("severity", "")
        severity_set = template.get("applicable_when", {}).get("severity_set", [])
        if severity_set and severity not in severity_set:
            continue
        if _invariant_family_matches(template, row):
            matching_rows.append({"row_id": row_id, "production_path": row.get("production_path", ""), "severity": severity})

    # Actor sequence evaluation
    actor_sequence = template.get("actor_sequence", [])
    consensus_predicate_ctx: dict[str, list[str]] | None = None
    if tid == "consensus_parser_differential":
        consensus_predicate_ctx = _collect_consensus_predicate_context(ws, workspace_paths)
    step_verdicts = [
        _evaluate_step(
            s,
            ws,
            scope_text,
            template_id=tid,
            consensus_predicate_ctx=consensus_predicate_ctx,
        )
        for s in actor_sequence
    ]

    applicable_steps = sum(1 for s in step_verdicts if s["applicable"])
    total_steps = len(step_verdicts)

    # Kill conditions (raw — not evaluated, just surfaced)
    kill_conditions = template.get("severity_promotion_rule", {}).get("kill_conditions", [])

    # Compose summary
    summary_applicable = workspace_match and applicable_steps == total_steps

    return {
        "schema_version": SCHEMA_VERSION,
        "template_id": tid,
        "title": title,
        "workspace": str(ws),
        "workspace_scope_match": workspace_match,
        "ledger_matching_rows": matching_rows,
        "ledger_matching_row_count": len(matching_rows),
        "actor_sequence_verdicts": step_verdicts,
        "applicable_steps": applicable_steps,
        "total_steps": total_steps,
        "all_steps_applicable": applicable_steps == total_steps,
        "summary_applicable": summary_applicable,
        "kill_conditions_to_check": kill_conditions,
        "capital_source": template.get("capital_source", ""),
        "engine": template.get("harness_blueprint", {}).get("engine", ""),
        "fixture_kit_required": template.get("harness_blueprint", {}).get("fixture_kit_required", ""),
        "verbatim_severity_md_line": template.get("severity_promotion_rule", {}).get("verbatim_severity_md_line", ""),
        "compose_when_auto_kill_if": template.get("compose_when", {}).get("auto_kill_if", []),
    }


def run(
    workspace: str,
    template_id: str | None = None,
    print_json: bool = False,
    out: str | None = None,
) -> list[dict]:
    """Main entry-point; returns list of verdict dicts (one per template run)."""
    ws = Path(workspace).expanduser().resolve()
    if not ws.exists():
        _die(f"workspace not found: {ws}")

    templates = _load_templates()
    if not templates:
        _die("no templates found in reference/big_loss_templates/")

    if template_id:
        if template_id not in templates:
            _die(f"template '{template_id}' not found. Available: {sorted(templates)}")
        to_run = {template_id: templates[template_id]}
    else:
        # Auto-select by scope_path_regex
        scope_text = _workspace_scope_text(ws)
        to_run = {tid: t for tid, t in templates.items() if _template_matches_workspace(t, scope_text)}
        if not to_run:
            # Fall back: run all
            to_run = templates

    results: list[dict] = []
    for _tid, tmpl in sorted(to_run.items()):
        verdict = run_template(tmpl, ws)
        results.append(verdict)

    _emit(results, print_json=print_json, out=out)
    return results


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

def _emit(results: list[dict], *, print_json: bool, out: str | None) -> None:
    if print_json or out:
        blob = json.dumps(results, indent=2)
        if out:
            Path(out).write_text(blob)
        if print_json or not out:
            print(blob)
    else:
        _print_human(results)


def _print_human(results: list[dict]) -> None:
    print(f"=== big-loss-template-runner ({SCHEMA_VERSION}) ===")
    print(f"templates evaluated: {len(results)}")
    for r in results:
        applicable = r["summary_applicable"]
        flag = "APPLICABLE" if applicable else "no-match"
        print(f"\n[{flag}] {r['template_id']} — {r['title']}")
        print(f"  workspace_scope_match : {r['workspace_scope_match']}")
        print(f"  ledger_matching_rows  : {r['ledger_matching_row_count']}")
        print(f"  steps                 : {r['applicable_steps']}/{r['total_steps']} applicable")
        print(f"  engine                : {r['engine']}")
        print(f"  capital_source        : {r['capital_source']}")
        print(f"  fixture_kit_required  : {r['fixture_kit_required']}")
        print(f"  severity_line         : {r['verbatim_severity_md_line']!r}")
        for sv in r["actor_sequence_verdicts"]:
            marker = "+" if sv["applicable"] else "-"
            print(f"    [{marker}] step {sv['step']:>2} actor={sv['actor']} | {sv['actual_state']}")
            print(f"          evidence_required: {sv['evidence_required'][:100]}...")
        if r["kill_conditions_to_check"]:
            print(f"  kill_conditions_to_check:")
            for kc in r["kill_conditions_to_check"]:
                print(f"    ! {kc}")
    print()


def _die(msg: str) -> None:
    print(f"[big-loss-template-runner] ERROR: {msg}", file=sys.stderr)
    sys.exit(1)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Evaluate big-loss exploit path templates against a workspace.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--workspace", required=True, help="Path to target workspace directory.")
    p.add_argument(
        "--template",
        default=None,
        help="Template ID to run (e.g. bridge_proof_domain). Default: all matching.",
    )
    p.add_argument("--print-json", action="store_true", help="Emit JSON to stdout.")
    p.add_argument("--out", default=None, help="Write JSON output to file path.")
    return p


def main() -> None:
    args = _build_parser().parse_args()
    run(
        workspace=args.workspace,
        template_id=args.template,
        print_json=args.print_json,
        out=args.out,
    )


if __name__ == "__main__":
    main()
