#!/usr/bin/env python3
"""
deployment-topology-builder.py — build a deployment/config topology artifact.

Reads CCIA output for a workspace, extracts unique contract targets, runs
deploy-state-lookup.sh in JSON mode for each target, and writes a durable
deployment_topology.json artifact that downstream mining stages can consume.

This is intentionally a low-assumption builder: it does not try to prove
bug-specific live predicates yet. It captures deployment/config evidence,
resolved-vs-ambiguous address state, and whether private RPCs are available for
future live-state follow-up.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

HERE = Path(__file__).resolve().parent
DEPLOY_STATE_LOOKUP = HERE / "deploy-state-lookup.sh"
DEFAULT_MAX_CONTRACTS = 20
DEFAULT_LOOKUP_TIMEOUT_SECONDS = 5


def parse_env_file(path: Path) -> Dict[str, str]:
    values: Dict[str, str] = {}
    try:
        for raw in path.read_text().splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip().strip("'").strip('"')
            if key:
                values[key] = value
    except OSError:
        pass
    return values


def load_workspace_env(workspace: Path) -> Dict[str, str]:
    env: Dict[str, str] = {}
    candidates = [
        workspace / ".env",
        workspace / ".env.local",
        workspace / "env" / ".env",
        workspace / "env" / ".env.local",
    ]
    env_dir = workspace / "env"
    if env_dir.is_dir():
        candidates.extend(sorted(env_dir.glob("*.env")))
    for candidate in candidates:
        if candidate.is_file():
            env.update(parse_env_file(candidate))
    return env


def load_ccia(workspace: Path) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    json_path = workspace / "ccia_report.json"
    if json_path.exists():
        data = json.loads(json_path.read_text())
        if isinstance(data, dict):
            ccia = data.get("ccia", {})
            angles = data.get("attack_angles", [])
            return ccia if isinstance(ccia, dict) else {}, angles if isinstance(angles, list) else []
    md_path = workspace / "ccia_report.md"
    if md_path.exists():
        return {}, parse_angles_from_md(md_path.read_text())
    return {}, []


def parse_angles_from_md(text: str) -> List[Dict[str, Any]]:
    angles: List[Dict[str, Any]] = []
    for line in text.splitlines():
        m = re.match(r"###\s+(A-[A-Z0-9]+)\s+—\s+(\w+)\s+—\s+(.+)", line)
        if m:
            angles.append({
                "id": m.group(1),
                "severity": m.group(2),
                "title": m.group(3),
            })
    return angles


def extract_contracts(angles: Iterable[Dict[str, Any]]) -> List[str]:
    ordered: List[str] = []
    seen: set[str] = set()

    def add(name: str) -> None:
        value = name.strip()
        if not value or value in seen:
            return
        seen.add(value)
        ordered.append(value)

    for angle in angles:
        contracts = angle.get("contracts", [])
        if isinstance(contracts, list):
            for contract in contracts:
                if isinstance(contract, str):
                    add(contract)
        title = str(angle.get("title", ""))
        if not contracts:
            match = re.search(r":\s+([A-Za-z_][A-Za-z0-9_]*)(?:\.(\w+))?\s*$", title)
            if match:
                add(match.group(1))
    return ordered


def run_lookup(workspace: Path, contract: str, timeout_seconds: int = DEFAULT_LOOKUP_TIMEOUT_SECONDS) -> Dict[str, Any]:
    if not DEPLOY_STATE_LOOKUP.exists():
        return {"contract": contract, "error": "deploy-state-lookup.sh missing"}
    cmd = ["bash", str(DEPLOY_STATE_LOOKUP), str(workspace), contract, "--json"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        return {
            "contract": contract,
            "error": f"deploy-state-lookup.sh timed out after {timeout_seconds}s",
        }
    if result.returncode != 0:
        return {
            "contract": contract,
            "error": result.stderr.strip() or result.stdout.strip() or f"lookup failed rc={result.returncode}",
        }
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        return {
            "contract": contract,
            "error": f"invalid JSON from deploy-state-lookup.sh: {exc}",
            "raw_stdout": result.stdout[:2000],
        }
    payload["contract"] = contract
    return payload


def summarize_entry(payload: Dict[str, Any]) -> Dict[str, Any]:
    candidates = payload.get("candidate_addresses", [])
    resolved = payload.get("resolved_address")
    live_request = payload.get("live_request", {})
    error = payload.get("error")
    matches = payload.get("matches", {})
    match_counts = {
        "deploy_and_env": len(matches.get("deploy_and_env", [])),
        "skill_state": len(matches.get("skill_state", [])),
        "workspace_notes": len(matches.get("workspace_notes", [])),
        "source": len(matches.get("source", [])),
    }
    status = "error" if error else "resolved" if resolved else "ambiguous" if candidates else "unresolved"
    return {
        "contract": payload.get("contract"),
        "status": status,
        "resolved_address": resolved,
        "candidate_addresses": candidates,
        "candidate_count": len(candidates),
        "rpc_ready": bool(payload.get("rpc_url_provided") or live_request.get("rpc_url_provided")),
        "match_counts": match_counts,
        "matches": matches,
        "error": error,
    }


def summarize(entries: Iterable[Dict[str, Any]], workspace_env: Dict[str, str]) -> Dict[str, Any]:
    entries = list(entries)
    rpc_keys = sorted(k for k in workspace_env if k.endswith("_RPC_URL"))
    resolved = sum(1 for entry in entries if entry["status"] == "resolved")
    ambiguous = sum(1 for entry in entries if entry["status"] == "ambiguous")
    unresolved = sum(1 for entry in entries if entry["status"] == "unresolved")
    errors = sum(1 for entry in entries if entry["status"] == "error")
    return {
        "contracts_total": len(entries),
        "resolved": resolved,
        "ambiguous": ambiguous,
        "unresolved": unresolved,
        "errors": errors,
        "rpc_ready": bool(rpc_keys),
        "rpc_keys": rpc_keys,
    }


def _evidence_lines(entry: Dict[str, Any], limit: int = 3) -> List[str]:
    matches = entry.get("matches", {})
    lines: List[str] = []
    for label in ("deploy_and_env", "workspace_notes", "skill_state", "source"):
        raw = matches.get(label, [])
        if not isinstance(raw, list):
            continue
        for item in raw:
            text = str(item).strip()
            if not text:
                continue
            lines.append(f"- `{label}`: {text}")
            if len(lines) >= limit:
                return lines
    return lines


def render_markdown(workspace: Path, artifact: Dict[str, Any]) -> str:
    summary = artifact.get("summary", {})
    entries = artifact.get("entries", [])
    lines = [
        "# Deployment Topology",
        "",
        f"- Workspace: `{workspace}`",
        f"- Contracts: {summary.get('contracts_total', 0)}",
        f"- Contracts available: {artifact.get('contracts_available', summary.get('contracts_total', 0))}",
        f"- Truncated: {'yes' if artifact.get('truncated') else 'no'}",
        f"- Resolved: {summary.get('resolved', 0)}",
        f"- Ambiguous: {summary.get('ambiguous', 0)}",
        f"- Unresolved: {summary.get('unresolved', 0)}",
        f"- Errors: {summary.get('errors', 0)}",
        f"- RPC ready: {'yes' if summary.get('rpc_ready') else 'no'}",
    ]
    if artifact.get("truncated"):
        skipped = artifact.get("contracts_skipped", [])
        lines.extend([
            "",
            (
                "Partial artifact: contract lookup was capped to keep the "
                "canonical engage chain bounded and idempotent."
            ),
            f"Skipped contracts: {len(skipped)}",
        ])
    rpc_keys = summary.get("rpc_keys", [])
    if rpc_keys:
        lines.append(f"- RPC keys: {', '.join(f'`{k}`' for k in rpc_keys)}")
    lines.append("")

    if not isinstance(entries, list) or not entries:
        lines.extend(["No deployment topology entries were produced.", ""])
        return "\n".join(lines)

    for entry in entries:
        if not isinstance(entry, dict):
            continue
        contract = entry.get("contract") or "UnknownContract"
        status = entry.get("status") or "unknown"
        lines.extend([f"## {contract}", "", f"- Status: `{status}`"])
        resolved = entry.get("resolved_address")
        if resolved:
            lines.append(f"- Resolved address: `{resolved}`")
        candidates = entry.get("candidate_addresses", [])
        if candidates:
            lines.append("- Candidate addresses:")
            for candidate in candidates[:8]:
                lines.append(f"  - `{candidate}`")
            if len(candidates) > 8:
                lines.append(f"  - _(+{len(candidates) - 8} more)_")
        error = entry.get("error")
        if error:
            lines.append(f"- ERROR: {error}")
        evidence = _evidence_lines(entry)
        if evidence:
            lines.append("- Evidence:")
            lines.extend(f"  {line}" for line in evidence)
        lines.append("")
    return "\n".join(lines)


def build_topology_artifact(
    workspace: Path,
    max_contracts: int = DEFAULT_MAX_CONTRACTS,
    lookup_timeout_seconds: int = DEFAULT_LOOKUP_TIMEOUT_SECONDS,
) -> Dict[str, Any]:
    ccia, angles = load_ccia(workspace)
    if not angles:
        raise ValueError("No CCIA angles found. Run orient/CCIA first.")

    contracts = extract_contracts(angles)
    if max_contracts < 1:
        selected_contracts = contracts
    else:
        selected_contracts = contracts[:max_contracts]
    skipped_contracts = contracts[len(selected_contracts):]

    workspace_env = load_workspace_env(workspace)
    raw_entries = [
        run_lookup(workspace, contract, timeout_seconds=lookup_timeout_seconds)
        for contract in selected_contracts
    ]
    entries = [summarize_entry(payload) for payload in raw_entries]

    artifact = {
        "workspace": str(workspace),
        "contracts": selected_contracts,
        "contracts_available": len(contracts),
        "contracts_skipped": skipped_contracts,
        "truncated": bool(skipped_contracts),
        "max_contracts": max_contracts,
        "lookup_timeout_seconds": lookup_timeout_seconds,
        "summary": summarize(entries, workspace_env),
        "entries": entries,
        "ccia_contract_count": len(set(contract for angle in angles for contract in angle.get("contracts", [])))
        if isinstance(ccia, dict) else 0,
    }
    return artifact


def main() -> None:
    parser = argparse.ArgumentParser(description="Build deployment topology artifact from CCIA targets")
    parser.add_argument("workspace", help="Workspace directory")
    parser.add_argument("--out", help="Output JSON path (default: <workspace>/deployment_topology.json)")
    parser.add_argument(
        "--max-contracts",
        type=int,
        default=DEFAULT_MAX_CONTRACTS,
        help=(
            "Maximum contracts to look up before writing a partial artifact "
            f"(default: {DEFAULT_MAX_CONTRACTS}; use 0 for unbounded)"
        ),
    )
    parser.add_argument(
        "--lookup-timeout",
        type=int,
        default=DEFAULT_LOOKUP_TIMEOUT_SECONDS,
        help=f"Per-contract deploy-state lookup timeout in seconds (default: {DEFAULT_LOOKUP_TIMEOUT_SECONDS})",
    )
    args = parser.parse_args()

    workspace = Path(args.workspace).expanduser().resolve()
    if not workspace.exists():
        print(f"[topology] Workspace not found: {workspace}", file=sys.stderr)
        sys.exit(1)

    try:
        artifact = build_topology_artifact(
            workspace,
            max_contracts=args.max_contracts,
            lookup_timeout_seconds=args.lookup_timeout,
        )
    except ValueError as exc:
        print(f"[topology] {exc}", file=sys.stderr)
        sys.exit(1)

    out_path = Path(args.out).expanduser().resolve() if args.out else workspace / "deployment_topology.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    md_path = out_path.with_suffix(".md")
    artifact["markdown"] = str(md_path)
    out_path.write_text(json.dumps(artifact, indent=2) + "\n")
    md_path.write_text(render_markdown(workspace, artifact) + "\n")

    summary = artifact["summary"]
    truncated = ", truncated=yes" if artifact.get("truncated") else ""
    print(
        "[topology] "
        f"wrote {out_path} "
        f"(contracts={summary['contracts_total']}, resolved={summary['resolved']}, "
        f"ambiguous={summary['ambiguous']}, unresolved={summary['unresolved']}, "
        f"errors={summary['errors']}, "
        f"rpc_ready={'yes' if summary['rpc_ready'] else 'no'}{truncated})"
    )


if __name__ == "__main__":
    main()
