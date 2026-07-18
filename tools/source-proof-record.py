#!/usr/bin/env python3
"""Record source-only proof evidence for one candidate.

The record is intentionally not a PoC execution manifest. It captures the
reviewer's source citations, exact impact-contract linkage, OOS status, and a
terminal source-review verdict under:

  <workspace>/source_proofs/<candidate>/source_proof.json

Fail-closed defaults:
  * no exact impact contract -> blocked_missing_impact_contract for proof/promote routes
  * killed records are terminal false-positive evidence and do not require an impact contract
  * proved_source_only requires at least one valid source citation
  * proved_source_only is refused when OOS status is not in_scope
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
import evidence_class as _evidence_class  # noqa: E402


SCHEMA_VERSION = "auditooor.source_proof.v1"
FINAL_VERDICTS = {
    "proved_source_only",
    "killed",
    "blocked_missing_impact_contract",
}
OOS_STATUSES = {
    "in_scope",
    "oos",
    "unknown",
    "not_checked",
}


def slug(value: str) -> str:
    safe = re.sub(r"[^a-zA-Z0-9_.-]+", "-", value.strip()).strip("-")
    return safe or "candidate"


def load_json(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def git_head(path: Path) -> str:
    try:
        proc = subprocess.run(
            ["git", "-C", str(path), "rev-parse", "HEAD"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            check=False,
        )
    except OSError:
        return ""
    return proc.stdout.strip() if proc.returncode == 0 else ""


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def parse_citation(workspace: Path, raw: str) -> dict[str, Any]:
    value = raw.strip()
    match = re.match(r"^(?P<path>.+?)(?::(?P<start>[0-9]+)(?:-(?P<end>[0-9]+))?)?$", value)
    rel = match.group("path") if match else value
    start = int(match.group("start")) if match and match.group("start") else None
    end = int(match.group("end")) if match and match.group("end") else start
    path = Path(rel)
    full = path if path.is_absolute() else workspace / path
    exists = full.is_file()
    line_count = 0
    # A citation to a missing file is never a valid source citation.  Keeping
    # valid_lines=True for that case made the record look structurally valid
    # while ``exists`` was false, allowing terminal records to carry
    # nonexistent evidence.
    valid_lines = exists
    if exists:
        try:
            line_count = len(full.read_text(encoding="utf-8", errors="replace").splitlines())
        except OSError:
            line_count = 0
        if start is not None:
            valid_lines = 1 <= start <= max(line_count, 1) and start <= (end or start) <= max(line_count, 1)
    return {
        "raw": value,
        "path": str(path),
        "start_line": start,
        "end_line": end,
        "exists": exists,
        "valid_lines": valid_lines,
    }


def load_impact_contract(
    workspace: Path,
    candidate: str,
    candidate_snapshot: dict[str, Any] | None = None,
) -> tuple[dict[str, Any] | None, str]:
    path = workspace / ".auditooor" / "impact_contracts.json"
    payload = load_json(path)
    if not payload:
        return None, str(path)
    contracts = payload.get("contracts")
    if not isinstance(contracts, list):
        return None, str(path)
    for contract in contracts:
        if isinstance(contract, dict) and str(contract.get("candidate_id") or "") == candidate:
            current_title = str((candidate_snapshot or {}).get("candidate_title") or "").strip()
            contract_title = str(contract.get("title") or "").strip()
            if current_title and contract_title and current_title != contract_title:
                continue
            return contract, str(path)
    return None, str(path)


def load_candidate_snapshot(workspace: Path, candidate: str) -> dict[str, Any]:
    """Bind proof memory to the current queue row, not just a recycled ID."""
    queue_paths = [
        workspace / ".auditooor" / "exploit_queue.source_mined.json",
        workspace / ".auditooor" / "exploit_queue.json",
    ]
    queue_paths.sort(
        key=lambda path: path.stat().st_mtime_ns if path.is_file() else -1,
        reverse=True,
    )
    for queue_path in queue_paths:
        payload = load_json(queue_path)
        if not payload:
            continue
        for field in ("queue", "entries"):
            for row in payload.get(field) or []:
                if not isinstance(row, dict):
                    continue
                row_id = str(row.get("lead_id") or row.get("candidate_id") or row.get("id") or "")
                if row_id != candidate:
                    continue
                title = str(row.get("title") or "").strip()
                refs = [str(ref) for ref in row.get("source_refs") or [] if str(ref).strip()]
                identity = hashlib.sha256(
                    json.dumps([title, refs], sort_keys=True, separators=(",", ":")).encode()
                ).hexdigest()
                return {
                    "candidate_title": title,
                    "candidate_source_refs": refs,
                    "candidate_identity_sha256": identity,
                    "candidate_queue_path": str(queue_path),
                }
    return {}


def _load_impact_preflight_builder() -> Any:
    tool = Path(__file__).resolve().with_name("impact-contract-preflight.py")
    spec = importlib.util.spec_from_file_location("impact_contract_preflight", tool)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load impact preflight helper: {tool}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.build_packet


def build_source_proof_preflight(
    *,
    selected_impact: str,
    has_exact_contract: bool,
    citations: list[dict[str, Any]],
    impact_contract: dict[str, Any] | None,
) -> dict[str, Any]:
    fields: dict[str, Any] = {}
    if has_exact_contract and selected_impact:
        fields["impacted_surface"] = selected_impact
        fields["selected_impact"] = selected_impact
    if impact_contract:
        for source_key, preflight_key in (
            ("severity", "severity_tier"),
            ("severity_tier", "severity_tier"),
            ("listed_impact_proven", "listed_impact_proven"),
            ("evidence_class", "evidence_class"),
            ("oos_traps", "oos_traps"),
            ("stop_condition", "stop_condition"),
        ):
            value = impact_contract.get(source_key)
            if value not in (None, "", [], {}):
                fields.setdefault(preflight_key, value)
    if citations:
        fields["source_proof"] = [
            citation.get("raw") or citation.get("path") or "source-proof-citation"
            for citation in citations
        ]
    payload = {
        "kind": "proof",
        "impact_contract": fields,
    }
    return _load_impact_preflight_builder()(
        payload=payload,
        text="",
        route="source-proof",
    )


def build_record(args: argparse.Namespace) -> tuple[dict[str, Any], Path]:
    workspace = args.workspace.expanduser().resolve()
    if not workspace.is_dir():
        raise SystemExit(f"[source-proof-record] ERR workspace not found: {workspace}")

    candidate = args.candidate.strip()
    if not candidate:
        raise SystemExit("[source-proof-record] ERR --candidate is required")

    out_dir = workspace / "source_proofs" / slug(candidate)
    out_path = args.out_json.expanduser().resolve() if args.out_json else out_dir / "source_proof.json"
    citations = [parse_citation(workspace, raw) for raw in args.citation or []]
    valid_citations = [c for c in citations if c["exists"] and c["valid_lines"]]
    invalid_citations = [c for c in citations if not (c["exists"] and c["valid_lines"])]

    candidate_snapshot = load_candidate_snapshot(workspace, candidate)
    impact_contract, impact_contract_path = load_impact_contract(
        workspace, candidate, candidate_snapshot
    )
    has_exact_contract = bool(
        impact_contract
        and impact_contract.get("exact_impact_row") is True
        and (
            str(impact_contract.get("original_selected_impact") or "").strip()
            or str(impact_contract.get("selected_impact") or "").strip()
        )
    )
    selected_impact = ""
    if impact_contract:
        selected_impact = str(
            impact_contract.get("selected_impact")
            or impact_contract.get("original_selected_impact")
            or ""
        ).strip()
    impact_preflight = build_source_proof_preflight(
        selected_impact=selected_impact,
        has_exact_contract=has_exact_contract,
        citations=citations,
        impact_contract=impact_contract,
    )

    final_verdict = args.verdict
    blockers: list[str] = []
    if invalid_citations:
        details = ", ".join(str(c.get("raw") or c.get("path") or "citation") for c in invalid_citations)
        blockers.append(f"invalid source citation(s): {details}")
    if args.verdict == "proved_source_only" and impact_preflight["decision"]["blocked"]:
        final_verdict = "blocked_missing_impact_contract"
        blockers.append(
            "impact-contract preflight blocked source-proof route: "
            + ", ".join(impact_preflight["impact_contract"]["missing"])
        )
    if args.verdict != "killed" and not has_exact_contract:
        blocker = "missing exact impact_contract row for candidate"
        if blocker not in blockers:
            blockers.append(blocker)
    if args.verdict == "proved_source_only":
        if not valid_citations:
            final_verdict = "killed"
            blockers.append("proved_source_only requires at least one existing source citation with valid line bounds")
        if args.oos_status != "in_scope":
            final_verdict = "killed"
            blockers.append("proved_source_only requires --oos-status in_scope")

    graph = workspace / ".auditooor" / "semantic_graph.json"
    evidence_class = (
        _evidence_class.HUMAN_VERIFIED
        if final_verdict == "proved_source_only"
        else _evidence_class.GENERATED_HYPOTHESIS
    )
    record = {
        "schema_version": SCHEMA_VERSION,
        "candidate_id": candidate,
        **candidate_snapshot,
        "workspace": str(workspace),
        "workspace_commit": git_head(workspace),
        "source_graph_path": str(graph) if graph.is_file() else "",
        "source_graph_sha256": sha256_file(graph) if graph.is_file() else "",
        "impact_contract_path": impact_contract_path,
        "impact_contract": impact_contract or {},
        "impact_contract_linked": has_exact_contract,
        "impact_contract_preflight": impact_preflight,
        "selected_impact": selected_impact,
        "source_citations": citations,
        "source_citation_count": len(citations),
        "valid_source_citation_count": len(valid_citations),
        "oos_status": args.oos_status,
        "oos_note": args.oos_note,
        "final_verdict": final_verdict,
        "requested_verdict": args.verdict,
        "blockers": blockers,
        "notes": args.notes,
        "evidence_class": evidence_class,
        "updated_at_unix": int(time.time()),
    }
    return record, out_path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--citation", action="append", help="Source citation as path[:line[-line]]. Repeatable.")
    parser.add_argument("--oos-status", choices=sorted(OOS_STATUSES), default="not_checked")
    parser.add_argument("--oos-note", default="")
    parser.add_argument("--verdict", choices=sorted(FINAL_VERDICTS), default="blocked_missing_impact_contract")
    parser.add_argument("--notes", default="")
    parser.add_argument("--out-json", type=Path)
    parser.add_argument("--print-json", action="store_true")
    args = parser.parse_args(argv)

    record, out_path = build_record(args)
    if any(str(blocker).startswith("invalid source citation(s):") for blocker in record["blockers"]):
        print(
            "[source-proof-record] ERR refusing to write a terminal record with invalid source citation(s)",
            file=sys.stderr,
        )
        return 1
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if args.print_json:
        print(json.dumps(record, indent=2, sort_keys=True))
    print(
        f"[source-proof-record] OK candidate={record['candidate_id']} "
        f"verdict={record['final_verdict']} json={out_path}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
