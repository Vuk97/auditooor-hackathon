#!/usr/bin/env python3
"""
temporal-state-provenance.py -- G5 temporal live-state provenance runner.

Schema: auditooor.temporal_state_provenance.v1

Point-in-time config is not enough for upgradeable/live systems. This tool
builds (or checks for) a temporal-state timeline for each in-scope deployed
contract / High-Critical exploit-queue candidate. The timeline records event
rows of these kinds:

  deployment_tx, upgrade, role_grant, role_revoke, param_change, oracle_swap,
  bridge_route_change, pause, unpause, liquidity_change, cap_change,
  historical_exploit_like

OFFLINE-SAFE: the tool never makes a network call.

Modes:
  CHECK (default): for each High/Critical candidate, report whether a temporal
  timeline exists and whether it is cited or a NO_TEMPORAL_STATE_RELEVANCE
  marker with evidence is present. With --strict, exits non-zero when any
  candidate fails the acceptance gate.

  SCAFFOLD (--scaffold): emits a timeline TEMPLATE skeleton for each candidate
  that lacks a filled timeline. Each event kind is present with a PENDING/TODO
  marker and the exact cast/RPC/explorer query an operator would run to fill it.
  The scaffold is clearly marked template_unfilled; it is never real evidence.

Acceptance gate:
  A High/Critical candidate PASSES when it has EITHER:
    (a) a temporal_state_timeline.json sidecar (or timeline row in the
        exploit_queue entry) that is NOT template_unfilled, OR
    (b) a NO_TEMPORAL_STATE_RELEVANCE marker with non-empty evidence text.

Usage:
    temporal-state-provenance.py --workspace <ws>
    temporal-state-provenance.py --workspace <ws> --json
    temporal-state-provenance.py --workspace <ws> --strict
    temporal-state-provenance.py --workspace <ws> --scaffold
    temporal-state-provenance.py --workspace <ws> --scaffold --out <path>
    temporal-state-provenance.py --workspace <ws> --candidate <lead_id>

Artifacts read (do NOT fabricate):
  <ws>/.auditooor/exploit_queue.json       -- High/Critical candidates
  <ws>/.auditooor/temporal_state_provenance.json  -- existing timelines
  <ws>/.auditooor/temporal_timelines/      -- per-candidate timeline files
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

SCHEMA = "auditooor.temporal_state_provenance.v1"
SCHEMA_VERSION = "1"

# ---------------------------------------------------------------------------
# All supported event kinds
# ---------------------------------------------------------------------------

EVENT_KINDS = [
    "deployment_tx",
    "upgrade",
    "role_grant",
    "role_revoke",
    "param_change",
    "oracle_swap",
    "bridge_route_change",
    "pause",
    "unpause",
    "liquidity_change",
    "cap_change",
    "historical_exploit_like",
]

# For each event kind: scaffold template fields + cast/explorer query hint
_EVENT_SCAFFOLD: dict[str, dict[str, Any]] = {
    "deployment_tx": {
        "description": "Initial contract deployment transaction",
        "query_hint": (
            "cast tx <DEPLOY_TX_HASH> --rpc-url <RPC_URL> | grep -E 'blockNumber|contractAddress|from'"
        ),
        "explorer_hint": "etherscan.io/tx/<DEPLOY_TX_HASH>",
        "block": "TODO",
        "tx_hash": "TODO",
        "deployer": "TODO",
        "constructor_args_summary": "TODO",
    },
    "upgrade": {
        "description": "Proxy implementation upgrade",
        "query_hint": (
            "cast logs --from-block <FROM> --to-block latest "
            "'Upgraded(address)' <PROXY_ADDRESS> --rpc-url <RPC_URL>"
        ),
        "explorer_hint": "etherscan.io/address/<PROXY>#events -> filter 'Upgraded'",
        "block": "TODO",
        "tx_hash": "TODO",
        "old_impl": "TODO",
        "new_impl": "TODO",
        "upgrader": "TODO",
    },
    "role_grant": {
        "description": "AccessControl RoleGranted event",
        "query_hint": (
            "cast logs --from-block 0 --to-block latest "
            "'RoleGranted(bytes32,address,address)' <CONTRACT_ADDRESS> --rpc-url <RPC_URL>"
        ),
        "explorer_hint": "etherscan.io/address/<CONTRACT>#events -> filter 'RoleGranted'",
        "block": "TODO",
        "tx_hash": "TODO",
        "role": "TODO",
        "account": "TODO",
        "sender": "TODO",
    },
    "role_revoke": {
        "description": "AccessControl RoleRevoked event",
        "query_hint": (
            "cast logs --from-block 0 --to-block latest "
            "'RoleRevoked(bytes32,address,address)' <CONTRACT_ADDRESS> --rpc-url <RPC_URL>"
        ),
        "explorer_hint": "etherscan.io/address/<CONTRACT>#events -> filter 'RoleRevoked'",
        "block": "TODO",
        "tx_hash": "TODO",
        "role": "TODO",
        "account": "TODO",
        "sender": "TODO",
    },
    "param_change": {
        "description": "Critical parameter change (cap, fee, threshold, limit, rate)",
        "query_hint": (
            "# Identify setter function signature, then:\n"
            "cast logs --from-block 0 --to-block latest "
            "'<SetterEventSignature>' <CONTRACT_ADDRESS> --rpc-url <RPC_URL>"
        ),
        "explorer_hint": "etherscan.io/address/<CONTRACT>#events -> filter '<ParamChangedEvent>'",
        "block": "TODO",
        "tx_hash": "TODO",
        "param_name": "TODO",
        "old_value": "TODO",
        "new_value": "TODO",
        "setter": "TODO",
    },
    "oracle_swap": {
        "description": "Oracle / price-feed address replacement",
        "query_hint": (
            "cast logs --from-block 0 --to-block latest "
            "'<OracleSetEvent>' <CONTRACT_ADDRESS> --rpc-url <RPC_URL>"
        ),
        "explorer_hint": "etherscan.io/address/<CONTRACT>#events -> filter oracle/feed event",
        "block": "TODO",
        "tx_hash": "TODO",
        "old_oracle": "TODO",
        "new_oracle": "TODO",
        "setter": "TODO",
    },
    "bridge_route_change": {
        "description": "Bridge route / registry / router address change",
        "query_hint": (
            "cast logs --from-block 0 --to-block latest "
            "'<RouterSetEvent>' <CONTRACT_ADDRESS> --rpc-url <RPC_URL>"
        ),
        "explorer_hint": "etherscan.io/address/<CONTRACT>#events -> filter router/bridge event",
        "block": "TODO",
        "tx_hash": "TODO",
        "old_route": "TODO",
        "new_route": "TODO",
        "setter": "TODO",
    },
    "pause": {
        "description": "Contract pause event",
        "query_hint": (
            "cast logs --from-block 0 --to-block latest "
            "'Paused(address)' <CONTRACT_ADDRESS> --rpc-url <RPC_URL>"
        ),
        "explorer_hint": "etherscan.io/address/<CONTRACT>#events -> filter 'Paused'",
        "block": "TODO",
        "tx_hash": "TODO",
        "pauser": "TODO",
    },
    "unpause": {
        "description": "Contract unpause event",
        "query_hint": (
            "cast logs --from-block 0 --to-block latest "
            "'Unpaused(address)' <CONTRACT_ADDRESS> --rpc-url <RPC_URL>"
        ),
        "explorer_hint": "etherscan.io/address/<CONTRACT>#events -> filter 'Unpaused'",
        "block": "TODO",
        "tx_hash": "TODO",
        "unpauser": "TODO",
    },
    "liquidity_change": {
        "description": "Significant liquidity / reserve level shift",
        "query_hint": (
            "# Check Deposit/Withdraw/Transfer events over a range:\n"
            "cast logs --from-block <FROM> --to-block <TO> "
            "'<DepositEvent>' <CONTRACT_ADDRESS> --rpc-url <RPC_URL>"
        ),
        "explorer_hint": "etherscan.io/address/<CONTRACT>#events -> filter Deposit/Withdraw",
        "block": "TODO",
        "tx_hash": "TODO",
        "old_liquidity": "TODO",
        "new_liquidity": "TODO",
        "direction": "TODO",
    },
    "cap_change": {
        "description": "Supply cap / borrow cap / limit change",
        "query_hint": (
            "cast logs --from-block 0 --to-block latest "
            "'<CapSetEvent>' <CONTRACT_ADDRESS> --rpc-url <RPC_URL>"
        ),
        "explorer_hint": "etherscan.io/address/<CONTRACT>#events -> filter cap event",
        "block": "TODO",
        "tx_hash": "TODO",
        "param_name": "TODO",
        "old_cap": "TODO",
        "new_cap": "TODO",
        "setter": "TODO",
    },
    "historical_exploit_like": {
        "description": "Historical exploit-like or anomalous event (e.g. flash loan, large liquidation, suspicious governance vote)",
        "query_hint": (
            "# Check Forta alerts, Tenderly simulations, and post-mortem reports.\n"
            "# Also: cast logs for large-value Transfer events:\n"
            "cast logs --from-block <FROM> --to-block <TO> "
            "'Transfer(address,address,uint256)' <CONTRACT_ADDRESS> --rpc-url <RPC_URL> "
            "| awk '/value/{if($NF+0 > 1e22) print}'"
        ),
        "explorer_hint": "forta.network / tenderly.co / rekt.news / etherscan large-tx heuristic",
        "block": "TODO",
        "tx_hash": "TODO",
        "event_type": "TODO",
        "impact_summary": "TODO",
        "resolution": "TODO",
    },
}

# Severity values considered High/Critical for acceptance gate
_HIGH_CRIT_SEVERITIES = {"high", "critical"}


# ---------------------------------------------------------------------------
# Helpers: load exploit queue
# ---------------------------------------------------------------------------

def _load_exploit_queue(workspace: Path) -> list[dict[str, Any]]:
    """Load .auditooor/exploit_queue.json; return the queue list or []."""
    path = workspace / ".auditooor" / "exploit_queue.json"
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return []
    if isinstance(data, list):
        return data
    # Dict wrapper with 'queue' key (real workspace shape)
    if isinstance(data, dict):
        for key in ("queue", "candidates", "items"):
            if key in data and isinstance(data[key], list):
                return data[key]
    return []


def _filter_high_critical(queue: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return only High/Critical candidates."""
    result = []
    for item in queue:
        sev = str(item.get("likely_severity", "")).lower().strip()
        if sev in _HIGH_CRIT_SEVERITIES:
            result.append(item)
    return result


# ---------------------------------------------------------------------------
# Helpers: load existing timelines
# ---------------------------------------------------------------------------

def _load_existing_timelines(workspace: Path) -> dict[str, dict[str, Any]]:
    """
    Load per-candidate timeline files from:
      <ws>/.auditooor/temporal_timelines/<lead_id>.json
    and the monolithic
      <ws>/.auditooor/temporal_state_provenance.json
    Returns {lead_id -> timeline_dict}.
    """
    result: dict[str, dict[str, Any]] = {}

    # Monolithic file
    mono_path = workspace / ".auditooor" / "temporal_state_provenance.json"
    if mono_path.exists():
        try:
            data = json.loads(mono_path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                # May be schema wrapper with "timelines" key or flat {lead_id -> ...}
                timelines = data.get("timelines", data)
                if isinstance(timelines, dict):
                    for lead_id, timeline in timelines.items():
                        if isinstance(timeline, dict):
                            result[lead_id] = timeline
        except (json.JSONDecodeError, OSError):
            pass

    # Per-candidate directory
    timelines_dir = workspace / ".auditooor" / "temporal_timelines"
    if timelines_dir.is_dir():
        for f in sorted(timelines_dir.glob("*.json")):
            lead_id = f.stem
            try:
                data = json.loads(f.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    result[lead_id] = data
            except (json.JSONDecodeError, OSError):
                pass

    return result


# ---------------------------------------------------------------------------
# Helpers: check acceptance gate for a single candidate
# ---------------------------------------------------------------------------

def _check_candidate(
    candidate: dict[str, Any],
    timelines: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """
    Evaluate one High/Critical candidate against the acceptance gate.

    Returns a result dict with:
      lead_id, title, likely_severity, status (pass|fail|no_temporal_state_relevance),
      verdict, evidence_present, no_tsri_evidence
    """
    lead_id = candidate.get("lead_id", "unknown")
    title = candidate.get("title", "untitled")
    severity = candidate.get("likely_severity", "unknown")

    # --- Check 1: does the candidate itself carry a NO_TEMPORAL_STATE_RELEVANCE marker? ---
    ntsr = candidate.get("NO_TEMPORAL_STATE_RELEVANCE", "")
    if not ntsr:
        ntsr = candidate.get("no_temporal_state_relevance", "")
    if ntsr and str(ntsr).strip():
        return {
            "lead_id": lead_id,
            "title": title,
            "likely_severity": severity,
            "status": "no_temporal_state_relevance",
            "verdict": "PASS (NO_TEMPORAL_STATE_RELEVANCE marker present with evidence)",
            "evidence_present": False,
            "no_tsri_evidence": str(ntsr).strip(),
            "timeline_unfilled": False,
        }

    # --- Check 2: does a timeline exist and is it filled? ---
    timeline = timelines.get(lead_id)
    if timeline is not None:
        unfilled = bool(timeline.get("template_unfilled", False))
        if not unfilled:
            events = timeline.get("events", [])
            return {
                "lead_id": lead_id,
                "title": title,
                "likely_severity": severity,
                "status": "pass",
                "verdict": f"PASS (temporal timeline present, {len(events)} event(s))",
                "evidence_present": True,
                "no_tsri_evidence": "",
                "timeline_unfilled": False,
                "event_count": len(events),
            }
        else:
            return {
                "lead_id": lead_id,
                "title": title,
                "likely_severity": severity,
                "status": "fail",
                "verdict": "FAIL (timeline exists but is template_unfilled; fill or add NO_TEMPORAL_STATE_RELEVANCE)",
                "evidence_present": False,
                "no_tsri_evidence": "",
                "timeline_unfilled": True,
            }

    # --- No timeline, no marker -> FAIL ---
    return {
        "lead_id": lead_id,
        "title": title,
        "likely_severity": severity,
        "status": "fail",
        "verdict": (
            "FAIL (no temporal timeline and no NO_TEMPORAL_STATE_RELEVANCE marker); "
            "run with --scaffold to generate a template skeleton"
        ),
        "evidence_present": False,
        "no_tsri_evidence": "",
        "timeline_unfilled": False,
    }


# ---------------------------------------------------------------------------
# CHECK mode: main report builder
# ---------------------------------------------------------------------------

def build_check_report(
    workspace: Path,
    candidate_filter: str | None = None,
) -> dict[str, Any]:
    """
    Build the full CHECK-mode report for a workspace.
    Returns a dict conforming to auditooor.temporal_state_provenance.v1.
    """
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    queue = _load_exploit_queue(workspace)
    has_queue = bool(queue)

    high_crit = _filter_high_critical(queue)

    if candidate_filter:
        high_crit = [c for c in high_crit if c.get("lead_id") == candidate_filter]

    timelines = _load_existing_timelines(workspace)

    candidate_results: list[dict[str, Any]] = []
    for candidate in high_crit:
        candidate_results.append(_check_candidate(candidate, timelines))

    total = len(candidate_results)
    passed = sum(1 for r in candidate_results if r["status"] in ("pass", "no_temporal_state_relevance"))
    failed = sum(1 for r in candidate_results if r["status"] == "fail")

    # Classify missing_artifact situation
    missing_artifacts: list[str] = []
    if not has_queue:
        missing_artifacts.append("exploit_queue.json")

    output: dict[str, Any] = {
        "schema": SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "workspace": str(workspace),
        "generated_at": now,
        "mode": "check",
        "offline_safe": True,
        "queue_loaded": has_queue,
        "total_queue_size": len(queue),
        "high_critical_candidates": total,
        "passed": passed,
        "failed": failed,
        "acceptance_gate": (
            "PASS" if failed == 0 and total > 0 else
            "NO_HIGH_CRITICAL_CANDIDATES" if total == 0 else
            "FAIL"
        ),
        "missing_artifacts": missing_artifacts,
        "candidates": candidate_results,
    }

    if not has_queue:
        output["note"] = (
            "No exploit_queue.json found in .auditooor/. "
            "Run make audit WS=<ws> to generate. "
            "Emitting missing_artifact row; no candidates to check."
        )
    elif total == 0:
        output["note"] = (
            "No High/Critical candidates in exploit_queue.json. "
            "Nothing to check."
        )

    return output


# ---------------------------------------------------------------------------
# SCAFFOLD mode
# ---------------------------------------------------------------------------

def _make_event_row(kind: str, address: str = "TODO") -> dict[str, Any]:
    """Build a single scaffold event row for a given kind."""
    base = _EVENT_SCAFFOLD.get(kind, {}).copy()
    row: dict[str, Any] = {
        "kind": kind,
        "status": "PENDING",
        "address": address,
    }
    row.update(base)
    return row


def build_scaffold(
    workspace: Path,
    candidate_filter: str | None = None,
) -> dict[str, Any]:
    """
    Emit a timeline TEMPLATE skeleton for every High/Critical candidate that
    lacks a filled timeline.  Skeletons are clearly marked template_unfilled.
    Returns dict mapping lead_id -> skeleton.
    """
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    queue = _load_exploit_queue(workspace)
    high_crit = _filter_high_critical(queue)

    if candidate_filter:
        high_crit = [c for c in high_crit if c.get("lead_id") == candidate_filter]

    timelines = _load_existing_timelines(workspace)

    scaffolds: dict[str, Any] = {}
    skipped: list[str] = []

    for candidate in high_crit:
        lead_id = candidate.get("lead_id", "unknown")
        # Skip if already has a filled timeline
        existing = timelines.get(lead_id)
        if existing and not existing.get("template_unfilled", True):
            skipped.append(lead_id)
            continue

        # Build scaffold
        # Try to extract a contract address from the candidate
        address = candidate.get("contract_address", candidate.get("address", "TODO"))

        events = [_make_event_row(kind, address=address) for kind in EVENT_KINDS]

        scaffold: dict[str, Any] = {
            "schema": SCHEMA,
            "schema_version": SCHEMA_VERSION,
            "lead_id": lead_id,
            "title": candidate.get("title", "untitled"),
            "likely_severity": candidate.get("likely_severity", "unknown"),
            "template_unfilled": True,
            "generated_at": now,
            "offline_safe": True,
            "note": (
                "TEMPLATE SKELETON - NOT REAL EVIDENCE. "
                "Fill each event row by running the query_hint command. "
                "Remove event kinds that do not apply to this contract. "
                "Once filled, remove template_unfilled or set it to false. "
                "Alternatively, add NO_TEMPORAL_STATE_RELEVANCE with evidence "
                "to the exploit_queue entry."
            ),
            "no_temporal_state_relevance": "",
            "events": events,
            "acceptance_hint": (
                "After filling: store this file at "
                f"<ws>/.auditooor/temporal_timelines/{lead_id}.json "
                "and rerun temporal-state-provenance.py --workspace <ws> to verify PASS."
            ),
        }
        scaffolds[lead_id] = scaffold

    output: dict[str, Any] = {
        "schema": SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "workspace": str(workspace),
        "generated_at": now,
        "mode": "scaffold",
        "offline_safe": True,
        "scaffolds_emitted": list(scaffolds.keys()),
        "skipped_already_filled": skipped,
        "timelines": scaffolds,
    }

    if not queue:
        output["note"] = (
            "No exploit_queue.json found - no candidates to scaffold. "
            "Run make audit WS=<ws> first."
        )
        output["missing_artifacts"] = ["exploit_queue.json"]

    return output


# ---------------------------------------------------------------------------
# Human-readable summary printer
# ---------------------------------------------------------------------------

def _print_check_human(result: dict[str, Any]) -> None:
    ws = result.get("workspace", "?")
    gate = result.get("acceptance_gate", "?")
    total = result.get("high_critical_candidates", 0)
    passed = result.get("passed", 0)
    failed = result.get("failed", 0)
    missing = result.get("missing_artifacts", [])

    print(f"[temporal-state-provenance] workspace: {ws}")
    print(f"[temporal-state-provenance] mode: check | gate: {gate}")
    print(f"[temporal-state-provenance] high/critical candidates: {total} | passed: {passed} | failed: {failed}")

    if missing:
        for art in missing:
            print(f"[temporal-state-provenance] MISSING_ARTIFACT: {art}")

    if "note" in result:
        print(f"[temporal-state-provenance] note: {result['note']}")

    for cand in result.get("candidates", []):
        status_icon = {"pass": "PASS", "no_temporal_state_relevance": "PASS(NTSR)", "fail": "FAIL"}.get(
            cand["status"], cand["status"].upper()
        )
        print(f"  [{status_icon}] {cand['lead_id']} ({cand['likely_severity']}) - {cand['title'][:60]}")
        if cand["status"] == "fail":
            print(f"         -> {cand['verdict']}")
        if cand.get("no_tsri_evidence"):
            print(f"         -> NTSR: {cand['no_tsri_evidence'][:80]}")


def _print_scaffold_human(result: dict[str, Any]) -> None:
    ws = result.get("workspace", "?")
    emitted = result.get("scaffolds_emitted", [])
    skipped = result.get("skipped_already_filled", [])

    print(f"[temporal-state-provenance] workspace: {ws}")
    print(f"[temporal-state-provenance] mode: scaffold")
    print(f"[temporal-state-provenance] scaffolds emitted: {len(emitted)} | already filled (skipped): {len(skipped)}")

    if "note" in result:
        print(f"[temporal-state-provenance] note: {result['note']}")

    for lead_id in emitted:
        print(f"  [SCAFFOLD] {lead_id}")
    for lead_id in skipped:
        print(f"  [SKIP-filled] {lead_id}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--workspace", required=True, type=Path,
        help="Workspace directory (must exist)",
    )
    parser.add_argument(
        "--scaffold", action="store_true",
        help="Emit a timeline TEMPLATE skeleton for candidates lacking a filled timeline",
    )
    parser.add_argument(
        "--strict", action="store_true",
        help="Exit non-zero when any High/Critical candidate fails the acceptance gate",
    )
    parser.add_argument(
        "--json", action="store_true", dest="json_stdout",
        help="Emit JSON to stdout (also writes file unless --no-file)",
    )
    parser.add_argument(
        "--no-file", action="store_true",
        help="Do not write output file (stdout only)",
    )
    parser.add_argument(
        "--out", type=Path, default=None,
        help="Output path (default: <ws>/.auditooor/temporal_state_provenance.json)",
    )
    parser.add_argument(
        "--candidate", default=None,
        help="Restrict to a single lead_id (for targeted check or scaffold)",
    )
    args = parser.parse_args(argv)

    workspace = args.workspace.expanduser().resolve()
    if not workspace.is_dir():
        print(
            f"[temporal-state-provenance] ERR workspace not found: {workspace}",
            file=sys.stderr,
        )
        return 2

    if args.scaffold:
        result = build_scaffold(workspace, candidate_filter=args.candidate)
    else:
        result = build_check_report(workspace, candidate_filter=args.candidate)

    json_text = json.dumps(result, indent=2)

    if args.json_stdout:
        print(json_text)
    else:
        if args.scaffold:
            _print_scaffold_human(result)
        else:
            _print_check_human(result)

    if not args.no_file:
        out_path = args.out or (workspace / ".auditooor" / "temporal_state_provenance.json")
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json_text, encoding="utf-8")
        if not args.json_stdout:
            print(f"[temporal-state-provenance] written to {out_path}")

    # Strict gate: fail if any candidate fails
    if args.strict and not args.scaffold:
        failed = result.get("failed", 0)
        if failed > 0:
            print(
                f"[temporal-state-provenance] STRICT GATE FAIL: {failed} candidate(s) lack temporal-state citation",
                file=sys.stderr,
            )
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
