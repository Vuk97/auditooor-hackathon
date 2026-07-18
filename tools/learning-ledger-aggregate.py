#!/usr/bin/env python3
# r36-rebuttal: registered lane learning-closeout-wiring in .auditooor/agent_pathspec.json
"""learning-ledger-aggregate.py — roll per-workspace learning ledgers into a
shared corpus so cross-workspace recall can surface them.

PROBLEM THIS FIXES (the silo):
    ``tools/agent-learning-compiler.py`` writes
    ``<ws>/.auditooor/agent_artifacts/learning_ledger.jsonl`` per workspace.
    ``vault_agent_learning_context`` only reads ONE workspace's ledger (it
    requires ``workspace_path``). There was no cross-workspace roll-up, so the
    ~18k learning rows across all workspaces were written locally and never
    lifted into the shared corpus. brain-prime, the reweighter, and
    ``vault_corpus_search`` could not surface them globally.

WHAT THIS DOES:
    Walks every ``<AUDITS_ROOT>/*/.auditooor/agent_artifacts/learning_ledger.jsonl``
    (plus the repo-local ledger), dedupes on a stable key, and writes a single
    aggregated corpus file at
    ``audit/corpus_tags/derived/agent_learning_ledger_aggregated.jsonl``.
    That derived path is registered in ``obsidian-vault-sync.py``
    ``SECTION_SOURCES["mining"]`` so the next vault sync lifts it and recall can
    surface the rows cross-workspace.

RELATED TOOLS (Rule: tool-duplication preflight):
    - tools/agent-learning-compiler.py — WRITES the per-workspace ledger (this
      tool READS those ledgers). No overlap.
    - tools/agent-learning-metrics.py — computes per-workspace metrics from one
      ledger; does NOT aggregate across workspaces.
    - tools/cross-workspace-state-aggregator.py — aggregates engagement STATE
      (.auditooor-state.yaml), not learning ledgers.
    - tools/memory-rollup-weekly.py — rolls vault EVENTS, not learning ledgers.
    This tool fills the gap: cross-workspace roll-up of the learning ledger
    into the shared derived corpus.

Idempotent: re-running merges new rows into the existing aggregate without
duplicating (stable dedupe key). Skips cleanly when no ledgers exist.

Usage:
    python3 tools/learning-ledger-aggregate.py [--audits-root <dir>]
        [--out <path>] [--workspace <ws>] [--json] [--check]

    --workspace : limit aggregation to a single workspace's ledger (used by the
                  per-workspace learning-closeout stage). Still merges into the
                  shared aggregate (does not clobber other workspaces' rows).
    --check     : do not write; report how many rows WOULD be added.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Sequence

SCRIPT = Path(__file__).resolve()
REPO_ROOT = SCRIPT.parent.parent
AUDITS_ROOT = Path.home() / "audits"
LEDGER_REL = ".auditooor/agent_artifacts/learning_ledger.jsonl"
DEFAULT_OUT = REPO_ROOT / "audit" / "corpus_tags" / "derived" / "agent_learning_ledger_aggregated.jsonl"
AGG_SCHEMA = "auditooor.agent_learning_ledger_aggregated.v1"


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _read_ledger(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not path.is_file():
        return rows
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        raw = raw.strip()
        if not raw:
            continue
        try:
            row = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if isinstance(row, dict):
            rows.append(row)
    return rows


def _row_key(row: dict[str, Any]) -> tuple[str, str, str, str]:
    """Stable dedupe key. Mirrors the compiler's notion of a distinct row but
    also keys on workspace so identical artifact_ids in different workspaces
    are kept distinct."""
    return (
        str(row.get("workspace", "")),
        str(row.get("artifact_id", "")),
        str(row.get("terminal_kind", "")),
        str(row.get("primary_for", "")),
    )


# r36-rebuttal: registered lane learning-closeout-wiring in .auditooor/agent_pathspec.json
def discover_ledgers(
    audits_root: Path,
    workspace: Path | None,
    *,
    include_repo_local: bool = True,
) -> list[Path]:
    """Return every per-workspace ledger path. If workspace is given, only that
    workspace's ledger (the repo-local ledger is NOT auto-included for the
    single-workspace case to keep the closeout lean).

    include_repo_local controls whether REPO_ROOT's own ledger is folded in
    during a full roll-up; tests disable it to isolate a temp audits root.
    """
    ledgers: list[Path] = []
    if workspace is not None:
        cand = workspace / LEDGER_REL
        if cand.is_file():
            ledgers.append(cand)
        return ledgers
    # Repo-local ledger (the auditooor-mcp workspace itself can carry one).
    if include_repo_local:
        repo_ledger = REPO_ROOT / LEDGER_REL
        if repo_ledger.is_file():
            ledgers.append(repo_ledger)
    if audits_root.is_dir():
        for ws in sorted(audits_root.iterdir()):
            if not ws.is_dir():
                continue
            cand = ws / LEDGER_REL
            if cand.is_file():
                ledgers.append(cand)
    return ledgers


# r36-rebuttal: registered lane learning-closeout-wiring in .auditooor/agent_pathspec.json
def aggregate(
    audits_root: Path,
    out_path: Path,
    *,
    workspace: Path | None = None,
    check: bool = False,
    include_repo_local: bool = True,
) -> dict[str, Any]:
    ledgers = discover_ledgers(audits_root, workspace, include_repo_local=include_repo_local)

    # Load existing aggregate so re-runs are idempotent and a single-workspace
    # closeout does not clobber other workspaces' rows.
    existing_rows = _read_ledger(out_path)
    seen: set[tuple[str, str, str, str]] = {_row_key(r) for r in existing_rows}

    added = 0
    new_rows: list[dict[str, Any]] = []
    workspaces_seen: set[str] = set()
    for ledger in ledgers:
        for row in _read_ledger(ledger):
            workspaces_seen.add(str(row.get("workspace", "")))
            key = _row_key(row)
            if key in seen:
                continue
            seen.add(key)
            new_rows.append(row)
            added += 1

    total_after = len(existing_rows) + added

    if not check and added:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        # Append-only merge keeps the file stable for git diffs and recall.
        with out_path.open("a", encoding="utf-8") as fh:
            for row in new_rows:
                fh.write(json.dumps(row, sort_keys=True) + "\n")

    return {
        "schema": AGG_SCHEMA,
        "generated_at_utc": _utc_now(),
        "audits_root": str(audits_root),
        "single_workspace": str(workspace) if workspace else None,
        "ledgers_found": [str(p) for p in ledgers],
        "ledger_count": len(ledgers),
        "workspaces_seen": sorted(w for w in workspaces_seen if w),
        "rows_existing": len(existing_rows),
        "rows_added": added,
        "rows_total": total_after,
        "out_path": str(out_path),
        "check_only": check,
        "source_refs": [
            "tools/agent-learning-compiler.py",
            "tools/learning-ledger-aggregate.py",
        ],
    }


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Aggregate per-workspace learning ledgers into the shared corpus.")
    p.add_argument("--audits-root", default=str(AUDITS_ROOT))
    p.add_argument("--out", default=str(DEFAULT_OUT))
    p.add_argument("--workspace", default="", help="Limit to a single workspace's ledger (still merges into shared aggregate).")
    p.add_argument("--check", action="store_true", help="Do not write; report rows that would be added.")
    p.add_argument("--json", action="store_true")
    return p.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    workspace = Path(args.workspace).expanduser().resolve() if args.workspace else None
    payload = aggregate(
        Path(args.audits_root).expanduser(),
        Path(args.out).expanduser(),
        workspace=workspace,
        check=args.check,
    )
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        verb = "would add" if args.check else "added"
        print(
            f"[learning-ledger-aggregate] {verb} {payload['rows_added']} rows "
            f"from {payload['ledger_count']} ledger(s); total={payload['rows_total']} "
            f"out={payload['out_path']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
