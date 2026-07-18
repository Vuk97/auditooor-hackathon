#!/usr/bin/env python3
"""Batch-scaffold advisory Chimera harnesses from an invariant ledger.

This is the audit-deep bridge for ``tools/chimera-scaffold.py``. It is
intentionally conservative: each row is still scaffolded_unverified, rows that
cannot bind to Solidity are skipped with reasons, and no generated harness is
treated as proof.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any


SCHEMA = "auditooor.chimera_ledger_scaffold.v1"
DEFAULT_ROW_TIMEOUT_SECONDS = 60


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text())
    except FileNotFoundError:
        raise SystemExit(f"missing invariant ledger: {path}") from None
    except json.JSONDecodeError as exc:
        raise SystemExit(f"invalid invariant ledger JSON: {exc}") from exc


def _rows(data: Any) -> list[dict[str, Any]]:
    if isinstance(data, dict) and isinstance(data.get("rows"), list):
        return [row for row in data["rows"] if isinstance(row, dict)]
    if isinstance(data, list):
        return [row for row in data if isinstance(row, dict)]
    return []


def _row_id(row: dict[str, Any]) -> str:
    for key in ("id", "row_id", "invariant_id"):
        value = row.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def _flatten(value: Any) -> list[str]:
    out: list[str] = []
    if isinstance(value, str):
        out.append(value)
    elif isinstance(value, dict):
        for item in value.values():
            out.extend(_flatten(item))
    elif isinstance(value, list):
        for item in value:
            out.extend(_flatten(item))
    return out


def _looks_solidity(row: dict[str, Any]) -> bool:
    return any(".sol" in text.lower() for text in _flatten(row))


def _safe_dir_name(row_id: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", row_id).strip("._-")
    return safe[:120] or "row"


def _run_row(
    tool: Path,
    workspace: Path,
    row_id: str,
    out_dir: Path,
    dry_run: bool,
    require_concrete: bool,
    strict_handlers: bool,
    timeout_seconds: int,
) -> dict[str, Any]:
    row_out_dir = out_dir / _safe_dir_name(row_id)
    cmd = [
        sys.executable,
        str(tool),
        "--workspace",
        str(workspace),
        "--row-id",
        row_id,
        "--out",
        str(row_out_dir),
        "--require-source-binding",
        "--print-json",
    ]
    if dry_run:
        cmd.append("--dry-run")
    if require_concrete:
        cmd.append("--require-concrete-binding")
    if strict_handlers:
        cmd.append("--strict-handlers")

    try:
        proc = subprocess.run(cmd, text=True, capture_output=True, timeout=timeout_seconds)
    except subprocess.TimeoutExpired as exc:
        return {
            "row_id": row_id,
            "safe_dir_name": row_out_dir.name,
            "command": cmd,
            "rc": 124,
            "stdout": (exc.stdout or "").strip()[:4000] if isinstance(exc.stdout, str) else "",
            "stderr": (exc.stderr or "").strip()[:4000] if isinstance(exc.stderr, str) else "",
            "status": "error",
            "reason": f"chimera-scaffold timed out after {timeout_seconds}s",
            "evidence_class": "scaffolded_unverified",
        }
    entry: dict[str, Any] = {
        "row_id": row_id,
        "safe_dir_name": row_out_dir.name,
        "command": cmd,
        "rc": proc.returncode,
        "stdout": proc.stdout.strip()[:4000],
        "stderr": proc.stderr.strip()[:4000],
    }
    if proc.returncode == 0:
        try:
            payload = json.loads(proc.stdout)
        except json.JSONDecodeError:
            payload = {}
        entry.update({
            "status": "planned" if dry_run else "scaffolded",
            "evidence_class": "scaffolded_unverified",
            "out_dir": str(row_out_dir),
            "source_bindings": payload.get("source_bindings", []),
            "concrete_bindings": payload.get("concrete_bindings", []),
            "handler_collisions": payload.get("handler_collisions", {}),
        })
    elif "no source binding" in proc.stderr or "no concrete contract binding" in proc.stderr:
        entry.update({
            "status": "skipped",
            "reason": proc.stderr.strip(),
            "evidence_class": "scaffolded_unverified",
        })
    elif "handler collision" in proc.stderr or "ambiguous" in proc.stderr.lower():
        entry.update({
            "status": "skipped_ambiguous",
            "reason": proc.stderr.strip(),
            "evidence_class": "scaffolded_unverified",
        })
    elif "blocked_missing_impact_contract" in proc.stdout or "blocked_missing_impact_contract" in proc.stderr:
        try:
            payload = json.loads(proc.stdout)
        except json.JSONDecodeError:
            payload = {}
        entry.update({
            "status": "blocked_missing_impact_contract",
            "reason": proc.stderr.strip() or payload.get("blocker_reason") or "blocked_missing_impact_contract",
            "evidence_class": "scaffolded_unverified",
            "out_dir": str(row_out_dir),
            "impact_contract_required": True,
            "impact_contract_id": payload.get("impact_contract_id", ""),
            "selected_impact": payload.get("selected_impact", ""),
            "severity": payload.get("severity", "none"),
            "submit_ready": False,
            "missing_preconditions": payload.get("missing_preconditions", []),
        })
    else:
        entry.update({
            "status": "error",
            "reason": proc.stderr.strip() or "chimera-scaffold failed",
            "evidence_class": "scaffolded_unverified",
        })
    return entry


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--out-dir", type=Path)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--require-concrete-binding", action="store_true")
    parser.add_argument("--strict-handlers", action="store_true")
    parser.add_argument("--max-rows", type=int, default=25)
    parser.add_argument("--row-timeout-seconds", type=int, default=DEFAULT_ROW_TIMEOUT_SECONDS)
    parser.add_argument("--print-json", action="store_true")
    args = parser.parse_args(argv)

    workspace = args.workspace.expanduser().resolve()
    ledger_path = workspace / ".auditooor" / "invariant_ledger.json"
    ledger = _read_json(ledger_path)
    out_dir = (args.out_dir or workspace / "chimera_harnesses").expanduser().resolve()
    manifest_path = (args.manifest or workspace / ".audit_logs" / "chimera_scaffold_manifest.json").expanduser().resolve()
    tool = Path(__file__).resolve().parent / "chimera-scaffold.py"

    for label, path in (("out-dir", out_dir), ("manifest", manifest_path)):
        if not _is_relative_to(path, workspace):
            print(f"{label} must stay inside workspace: {path}", file=sys.stderr)
            return 2

    entries: list[dict[str, Any]] = []
    eligible = [row for row in _rows(ledger) if _row_id(row) and _looks_solidity(row)]
    for row in eligible[: max(args.max_rows, 0)]:
        entries.append(
            _run_row(
                tool=tool,
                workspace=workspace,
                row_id=_row_id(row),
                out_dir=out_dir,
                dry_run=args.dry_run,
                require_concrete=args.require_concrete_binding,
                strict_handlers=args.strict_handlers,
                timeout_seconds=max(args.row_timeout_seconds, 1),
            )
        )

    skipped_non_sol = len(_rows(ledger)) - len(eligible)
    status_counts: dict[str, int] = {}
    for entry in entries:
        status_counts[entry["status"]] = status_counts.get(entry["status"], 0) + 1
    if skipped_non_sol > 0:
        status_counts["skipped_non_solidity"] = skipped_non_sol

    manifest = {
        "schema": SCHEMA,
        "workspace": str(workspace),
        "ledger_path": str(ledger_path),
        "out_dir": str(out_dir),
        "dry_run": args.dry_run,
        "require_concrete_binding": args.require_concrete_binding,
        "strict_handlers": args.strict_handlers,
        "max_rows": args.max_rows,
        "row_timeout_seconds": max(args.row_timeout_seconds, 1),
        "generated_at_unix": int(time.time()),
        "eligible_rows": len(eligible),
        "skipped_non_solidity": skipped_non_sol,
        "status_counts": status_counts,
        "entries": entries,
        "evidence_class": "scaffolded_unverified",
        "proof_boundary": "Generated harnesses are advisory until an execution manifest proves impact.",
    }
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    if args.print_json:
        print(json.dumps(manifest, indent=2, sort_keys=True))
    else:
        print(manifest_path)
    return 1 if status_counts.get("error") else 0


if __name__ == "__main__":
    raise SystemExit(main())
