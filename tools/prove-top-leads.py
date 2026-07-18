#!/usr/bin/env python3
"""Validate prove-top-leads queue handoff semantics.

RELATED TOOLS:
- Makefile prove-top-leads target: runs the existing source mining, judgment,
  harness binding, and harness execution queue commands.
- tools/exploit-conversion-loop.py: owns the shared row eligibility checks used
  here for conversion-loop parity.
- tools/harness-binding-manifest.py and tools/harness-execution-queue.py: build
  runnable or blocked harness queue artifacts; this tool validates the resulting
  proof handoff posture without executing commands.

This fills the Python entrypoint gap for tests and operator diagnostics. It does
not replace the Make target; it reports whether queue rows may enter proof
conversion or must remain advisory.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any


SCHEMA = "auditooor.prove_top_leads_queue_semantics.v1"
REPO_ROOT = Path(__file__).resolve().parents[1]


def _load_conversion_module():
    path = REPO_ROOT / "tools" / "exploit-conversion-loop.py"
    spec = importlib.util.spec_from_file_location("exploit_conversion_loop", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load conversion module at {path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


E = _load_conversion_module()
_TYPED_ENVELOPE_TOOL = REPO_ROOT / "tools" / "zero-day-proof-envelope-verify.py"
_TYPED_ENVELOPE_MOD: Any | None = None


def _load_typed_envelope_tool() -> Any:
    """Load the canonical immutable-envelope verifier once."""
    global _TYPED_ENVELOPE_MOD
    if _TYPED_ENVELOPE_MOD is not None:
        return _TYPED_ENVELOPE_MOD
    spec = importlib.util.spec_from_file_location("prove_top_leads_typed_envelope", _TYPED_ENVELOPE_TOOL)
    if spec is None or spec.loader is None:
        raise RuntimeError("typed_proof_envelope_validator_unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    _TYPED_ENVELOPE_MOD = module
    return module


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8", errors="replace"))


def _load_optional_json(path: Path | None) -> dict[str, Any]:
    if path is None or not path.exists():
        return {}
    try:
        data = _load_json(path)
    except json.JSONDecodeError:
        return {}
    return data if isinstance(data, dict) else {}


def _queue_rows(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [row for row in payload if isinstance(row, dict)]
    if isinstance(payload, dict):
        for key in ("queue", "rows", "candidates"):
            rows = payload.get(key)
            if isinstance(rows, list):
                return [row for row in rows if isinstance(row, dict)]
        if payload:
            return [payload]
    return []


def _row_id(row: dict[str, Any], index: int) -> str:
    for key in ("lead_id", "row_id", "candidate_id", "id", "slug", "title"):
        value = row.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return f"row-{index:04d}"


def _ready_harness_row_ids(payload: dict[str, Any]) -> set[str]:
    ready: set[str] = set()
    for command in payload.get("ready_commands", []):
        if isinstance(command, dict):
            row_id = command.get("row_id")
            if isinstance(row_id, str) and row_id.strip():
                ready.add(row_id.strip())
    for row in payload.get("queue_rows", []):
        if not isinstance(row, dict):
            continue
        row_id = row.get("row_id")
        contract = row.get("execution_contract")
        if (
            isinstance(row_id, str)
            and row_id.strip()
            and isinstance(contract, dict)
            and contract.get("claim") == "runnable_harness"
            and contract.get("runnable") is True
            and contract.get("advisory_only") is not True
        ):
            ready.add(row_id.strip())
    return ready


def _is_evidence_backed_terminal_negative(row: dict[str, Any], typed_entry: dict[str, Any] | None = None) -> bool:
    """Return true only for a row already closed by concrete negative evidence.

    Bare ``killed``/``disqualified`` rows remain live work.  A source-proof path
    or an execution-backed negative is required before a row can be removed from
    the Drive handoff; otherwise the validator would hide unresolved work.
    """
    proof_status = str(
        row.get("proof_status")
        or row.get("source_mined_proof_status")
        or row.get("proof_verdict")
        or ""
    ).strip().lower()
    quality_status = str(row.get("quality_gate_status") or "").strip().lower()
    source_proof = row.get("source_proof_path") or row.get("source_proof")
    truth = row.get("truth_table_summary")
    truth_negative = isinstance(truth, dict) and any(
        str(truth.get(key) or "").strip().lower()
        in {"closed_negative", "source proof killed candidate", "source proof refuted candidate"}
        for key in ("source_state", "clean_control", "next_action")
    )
    terminal_status = {
        "killed", "kill", "drop", "dropped", "disproved", "closed_negative",
        "false_positive", "false-positive", "not_exploitable", "not_candidate",
    }
    terminal_quality = {
        "closed_negative_source_proof", "closed_negative", "false_positive",
        "false-positive", "not_exploitable",
    }
    # A typed zero-day obligation is not a legacy lead. It may only leave the
    # Drive denominator through the exact terminal record bound to the frozen
    # parent pair and immutable envelope. Source-proof paths and status tokens
    # remain useful evidence but cannot close this identity by themselves.
    if typed_entry is not None:
        if proof_status not in terminal_status and quality_status not in terminal_quality:
            return False
        return bool(_load_typed_envelope_tool().terminal_record_matches(typed_entry, row))

    terminal_join = row.get("terminal_join")
    if (
        isinstance(terminal_join, dict)
        and str(terminal_join.get("evidence_ref") or "").strip().lower()
        == "unanchorable-no-target"
        and "auto-terminalized oos"
        in str(terminal_join.get("reason") or "").strip().lower()
    ):
        # This is a generated routing disposition for malformed chain fuel,
        # not a claim that an unanchored hypothesis was source-proved.
        return True
    if proof_status in terminal_status or quality_status in terminal_quality:
        return bool(source_proof or truth_negative)
    return False


def _typed_entries(
    payload: Any, *, workspace: Path | None = None, queue_path: Path | None = None,
) -> dict[str, dict[str, Any]] | None:
    """Return exact typed identities or fail before status-based filtering."""
    if not isinstance(payload, dict) or "zero_day_proof_admission" not in payload:
        return None
    if payload.get("entries") not in (None, []):
        raise ValueError("typed_proof_envelope_legacy_entries_present")
    if workspace is not None or queue_path is not None:
        if workspace is None or queue_path is None:
            raise ValueError("typed_proof_envelope_workspace_required")
        try:
            _load_typed_envelope_tool().verify_persisted(workspace, queue_path)
        except Exception as exc:
            raise ValueError(f"typed_proof_envelope_invalid:{exc}") from exc
    envelope = _load_typed_envelope_tool().build_envelope(payload)
    return {
        entry["lead_id"]: entry
        for entry in envelope["entries"]
        if isinstance(entry, dict) and isinstance(entry.get("lead_id"), str)
    }


def assess_queue(
    *,
    workspace: Path,
    queue_path: Path,
    harness_queue_path: Path | None = None,
    top_n: int = 10,
) -> dict[str, Any]:
    workspace = workspace.expanduser().resolve()
    queue_path = queue_path.expanduser().resolve()
    harness_queue_path = harness_queue_path.expanduser().resolve() if harness_queue_path else None
    # top_n <= 0 means UNBOUNDED (prove EVERY queued lead) - an audit must not
    # silently drop leads beyond an arbitrary top-N. A positive top_n caps to the
    # first N (explicit opt-in prioritisation).
    queue_payload = _load_json(queue_path)
    typed_entries = _typed_entries(
        queue_payload, workspace=workspace, queue_path=queue_path,
    )
    _all_rows = _queue_rows(queue_payload)
    if typed_entries is not None:
        for row in _all_rows:
            lead_id = row.get("lead_id")
            if not isinstance(lead_id, str) or lead_id not in typed_entries:
                raise ValueError("typed_proof_envelope_row_missing")
    terminal_rows_skipped = sum(
        1 for row in _all_rows if _is_evidence_backed_terminal_negative(
            row, typed_entries.get(row["lead_id"]) if typed_entries is not None else None
        )
    )
    live_rows = [
        row for row in _all_rows if not _is_evidence_backed_terminal_negative(
            row, typed_entries.get(row["lead_id"]) if typed_entries is not None else None
        )
    ]
    rows = live_rows if top_n <= 0 else live_rows[:top_n]
    harness_payload = _load_optional_json(harness_queue_path)
    ready_harness_ids = _ready_harness_row_ids(harness_payload)

    assessed: list[dict[str, Any]] = []
    for index, row in enumerate(rows):
        row_id = _row_id(row, index)
        source_status = E._source_ref_status(row, workspace)
        rejection_reasons = list(E._handoff_rejection_reasons(row, workspace))
        has_runnable_harness = E._has_runnable_harness_evidence(row, workspace) or row_id in ready_harness_ids
        if has_runnable_harness and "proof_without_runnable_harness_evidence" in rejection_reasons:
            rejection_reasons.remove("proof_without_runnable_harness_evidence")

        if rejection_reasons:
            decision = "rejected"
        elif has_runnable_harness:
            decision = "proof_ready"
        else:
            decision = "advisory_only"

        assessed.append(
            {
                "row_id": row_id,
                "decision": decision,
                "rejection_reasons": rejection_reasons,
                "has_current_source_refs": bool(source_status["current_refs"]),
                "current_source_refs": source_status["current_refs"],
                "stale_source_refs": source_status["stale_refs"],
                "has_runnable_harness_evidence": has_runnable_harness,
                "advisory_default": decision == "advisory_only",
                "proof_conversion_ready": decision == "proof_ready",
            }
        )

    rejected = [row for row in assessed if row["decision"] == "rejected"]
    advisory = [row for row in assessed if row["decision"] == "advisory_only"]
    proof_ready = [row for row in assessed if row["decision"] == "proof_ready"]
    return {
        "schema": SCHEMA,
        "workspace": str(workspace),
        "queue_path": str(queue_path),
        "harness_queue_path": str(harness_queue_path) if harness_queue_path else "",
        "top_n": top_n,
        "row_count": len(assessed),
        "all_queue_rows": len(_all_rows),
        "typed_proof_queue": typed_entries is not None,
        "terminal_rows_skipped": terminal_rows_skipped,
        "rejected_count": len(rejected),
        "advisory_count": len(advisory),
        "proof_ready_count": len(proof_ready),
        "proof_conversion_posture": (
            "no_live_rows_all_terminal"
            if not assessed and terminal_rows_skipped > 0
            else "proof_ready_rows_present"
            if proof_ready
            else "advisory_default_until_real_harness_and_current_source"
        ),
        "rows": assessed,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate prove-top-leads proof queue handoff semantics.")
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--queue", help="Default <ws>/.auditooor/exploit_queue.source_mined.json")
    parser.add_argument("--harness-queue", help="Default <ws>/.auditooor/harness_execution_queue_from_exploit_queue.json")
    parser.add_argument("--top-n", type=int, default=0,
                        help="how many queued leads to prove; <=0 means ALL (unbounded, default)")
    parser.add_argument("--out")
    parser.add_argument("--strict", action="store_true", help="Exit 1 when rejected rows are present.")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    workspace = Path(args.workspace)
    aud = workspace.expanduser().resolve() / ".auditooor"
    queue_path = Path(args.queue) if args.queue else aud / "exploit_queue.source_mined.json"
    if not queue_path.exists():
        fallback = aud / "exploit_queue.json"
        queue_path = fallback if fallback.exists() else queue_path
    harness_queue = Path(args.harness_queue) if args.harness_queue else aud / "harness_execution_queue_from_exploit_queue.json"
    payload = assess_queue(
        workspace=workspace,
        queue_path=queue_path,
        harness_queue_path=harness_queue if harness_queue.exists() else None,
        top_n=args.top_n,
    )

    out_path = Path(args.out) if args.out else aud / "prove_top_leads_queue_semantics.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=False))
    print(f"[prove-top-leads] wrote {out_path}", file=sys.stderr)
    if args.strict and (payload["rejected_count"] > 0 or payload["advisory_count"] > 0):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
