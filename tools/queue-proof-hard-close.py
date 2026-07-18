#!/usr/bin/env python3
"""Fail-closed queue-to-proof closeout from local execution evidence.

Reads only local workspace artifacts:

  * <ws>/.auditooor/exploit_queue.json
  * <ws>/.auditooor/high_impact_execution_bridge.json
  * <ws>/source_proofs/**/source_proof.json
  * <ws>/poc_execution/**/execution_manifest.json

The tool never executes shell commands and never calls the network.  It
classifies every queue row as one of:

  * proved           - strict proved-impact execution manifest exists
  * disproved        - executed manifest records final_result=disproved
  * killed           - local source proof records final_verdict=killed
  * blocked          - bridge or execution manifest records a terminal block
  * missing_evidence - no terminal local evidence, or evidence is too weak/stale

This is a closeout ledger, not a submission gate.  It never promotes
exploitability, severity, or submission readiness.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any

TOOLS_DIR = Path(__file__).resolve().parent
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

from execution_manifest_proof import (  # noqa: E402
    bound_source_validation,
    command_evidence_counts,
    command_status_counts,
    is_strict_proved_execution_manifest,
    strict_terminal_blockers,
)


SCHEMA = "auditooor.queue_proof_hard_close.v1"
EXPLOIT_QUEUE_SCHEMA = "auditooor.exploit_queue.v1"
PROOF_TASK_QUEUE_ROLE = "proof_tasks"
CANDIDATE_LEADS_QUEUE_ROLE = "candidate_leads"
_TYPED_ENVELOPE_TOOL = Path(__file__).with_name("zero-day-proof-envelope-verify.py")
_TYPED_ENVELOPE_MOD: Any | None = None
PROOF_BOUNDARY = (
    "Offline queue-to-proof closeout only. Proved rows require a local "
    "poc_execution/**/execution_manifest.json with final_result=proved, "
    "impact_assertion=exploit_impact, evidence_class=executed_with_manifest, "
    "and at least one structured commands_attempted row with a non-empty "
    "command, status=pass, and exit_code=0. Killed rows may close from a "
    "local source_proofs/**/source_proof.json with final_verdict=killed. "
    "This report does not claim exploitability, severity, duplicate status, "
    "or submission readiness."
)
TERMINAL_STATUSES = {"proved", "disproved", "killed", "blocked"}
BLOCKED_FINAL_RESULTS = {"blocked_env", "blocked_path"}
DEFAULT_STALE_DAYS = 7.0
LIVE_WITNESS_SEVERITIES = {"critical", "high"}
COMPLETE_LIVE_WITNESS_STATUSES = {"complete", "pass", "passed", "proved"}
NO_TEMPORAL_STATE_RELEVANCE = "NO_TEMPORAL_STATE_RELEVANCE"
SOURCE_SCOPE_HINTS = (
    "github.com/",
    "github",
    "repository",
    "repo url",
    "repo:",
    "codebase",
    "source code",
    "source-code",
    "commit pin",
    "commit:",
    "audit pin",
)
LIVE_REQUIRED_HINTS = (
    "live state required",
    "live proof required",
    "fork proof required",
    "deployed contracts only",
    "deployed contract only",
    "only deployed",
    "mainnet only",
    "production deployment only",
)


def _load_typed_envelope_tool() -> Any:
    """Load the canonical admitted-proof identity validator once."""
    global _TYPED_ENVELOPE_MOD
    if _TYPED_ENVELOPE_MOD is not None:
        return _TYPED_ENVELOPE_MOD
    spec = importlib.util.spec_from_file_location("queue_proof_hard_close_typed_envelope", _TYPED_ENVELOPE_TOOL)
    if spec is None or spec.loader is None:
        raise RuntimeError("typed_proof_envelope_validator_unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    _TYPED_ENVELOPE_MOD = module
    return module

# HACKERMAN_V3 opposed-trace proof gate (proof-side).
#
# A HIGH+ Direct-loss / freeze / theft row cannot hard-close while its impact
# contract carries an unopposed trace - no enumerated protocol-owned defenses,
# or opposed_trace_required set with coverage not ``covered``, or negative
# controls that lack both a "defender wins" and a "defender absent" variant.
# Empirical anchor: Spark LEAD1 - the chain-watcher bug was real but the proof
# omitted the lower-timelock refund / watchtower defenses, so Direct Loss was
# unproven (attacker-vs-empty-world).
HIGH_PLUS_IMPACT_KEYWORDS = (
    "direct loss",
    "loss of funds",
    "loss of user funds",
    "permanent freeze",
    "permanent freezing",
    "freezing of funds",
    "frozen funds",
    "insolvency",
    "insolvent",
    "undercollateral",
    "bad debt",
    "theft",
    "steal",
    "stolen",
    "drain",
    "drained",
    "unauthorized withdrawal",
    "unauthorized withdraw",
    "unauthorised withdrawal",
    "unauthorized transfer",
)
DEFENDER_WINS_TOKENS = (
    "defender wins",
    "defense wins",
    "defence wins",
    "defender succeeds",
    "defense succeeds",
    "guard wins",
    "defender catches",
    "defense catches",
    "defender neutralizes",
    "defender neutralises",
    "watchtower catches",
    "refund succeeds",
    "challenge succeeds",
    "race won by protocol",
)
DEFENDER_ABSENT_TOKENS = (
    "defender absent",
    "defense absent",
    "defence absent",
    "defender disabled",
    "defense disabled",
    "guard absent",
    "guard disabled",
    "without the defense",
    "without the defender",
    "no defender",
    "defense removed",
    "defender removed",
    "vulnerable precondition removed",
)


def _utc_now_iso(now_unix: float | None = None) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now_unix or time.time()))


def _load_json(path: Path) -> Any | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _contains_any(text: str, needles: tuple[str, ...]) -> bool:
    low = str(text or "").lower()
    return any(needle in low for needle in needles)


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text.rstrip() + "\n", encoding="utf-8")


def _sha256_json(value: Any) -> str:
    data = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def _slug(value: str) -> str:
    out: list[str] = []
    prev_dash = False
    for ch in str(value or "").strip().lower():
        if ch.isalnum() or ch in "._":
            out.append(ch)
            prev_dash = False
        elif not prev_dash:
            out.append("-")
            prev_dash = True
    return "".join(out).strip("-")


def _norm_key(value: Any) -> str:
    return _slug(str(value or "")).replace("-", "_").lower()


def _severity_requires_live_witness(severity: str) -> bool:
    return _norm_key(severity) in LIVE_WITNESS_SEVERITIES


def _workspace_requires_live_witness(workspace: Path) -> bool:
    """Preserve legacy live-witness gating unless source scope says otherwise.

    Many bounties are source-scoped: the listed asset is a GitHub repo/runtime,
    not a specific deployed instance. For those, live-state probes are useful
    materiality witnesses but must not block proof closeout unless the program
    explicitly requires deployed/live proof.
    """

    scope_text = "\n".join(
        _read_text(workspace / name) for name in ("SCOPE.md", "OOS_PASTED.md", "scope.json")
    )
    source_scoped = _contains_any(scope_text, SOURCE_SCOPE_HINTS)
    live_required = _contains_any(scope_text, LIVE_REQUIRED_HINTS)
    policy = _load_json(workspace / ".auditooor" / "scope_live_proof_policy.json")
    if isinstance(policy, dict):
        if "source_scoped" in policy:
            source_scoped = bool(policy["source_scoped"])
        if "requires_live_proof" in policy:
            live_required = bool(policy["requires_live_proof"])
    if source_scoped and not live_required:
        return False
    return True


def _rel(path: Path, workspace: Path) -> str:
    try:
        return path.resolve().relative_to(workspace.resolve()).as_posix()
    except (OSError, ValueError):
        return str(path)


def _path_age_days(path: Path, now_unix: float) -> float | None:
    try:
        return max(0.0, (now_unix - path.stat().st_mtime) / 86400.0)
    except OSError:
        return None


def _manifest_age_days(path: Path, manifest: dict[str, Any], now_unix: float) -> float | None:
    updated = manifest.get("updated_at_unix")
    if isinstance(updated, bool):
        updated = None
    if isinstance(updated, (int, float)):
        return max(0.0, (now_unix - float(updated)) / 86400.0)
    return _path_age_days(path, now_unix)


def _list_dicts(value: Any, key: str) -> list[dict[str, Any]]:
    if isinstance(value, dict) and isinstance(value.get(key), list):
        return [row for row in value[key] if isinstance(row, dict)]
    return []


def _is_advisory_queue_row(raw: dict[str, Any]) -> bool:
    title = str(raw.get("title") or raw.get("root_cause_hypothesis") or "")
    proof_status = _norm_key(raw.get("proof_status"))
    gate = _norm_key(raw.get("quality_gate_status"))
    title_key = _norm_key(title)
    if raw.get("row_is_advisory") is True or proof_status == "not_candidate":
        return True
    if gate in {"advisory_not_candidate", "closed_non_candidate_advisory"}:
        return True
    return bool(title_key.startswith(("q_oos", "q_dupe")) or "_q_oos" in title_key or "_q_dupe" in title_key)


def _queue_rows(workspace: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    typed_admitted_path = workspace / ".auditooor" / "exploit_queue.zero_day_admitted.json"
    source_mined_path = workspace / ".auditooor" / "exploit_queue.source_mined.json"
    canonical_exploit_path = workspace / ".auditooor" / "exploit_queue.json"
    exploit_path = (
        typed_admitted_path if typed_admitted_path.is_file()
        else source_mined_path if source_mined_path.is_file()
        else canonical_exploit_path
    )
    bridge_path = workspace / ".auditooor" / "high_impact_execution_bridge.json"
    exploit = _load_json(exploit_path)
    bridge = _load_json(bridge_path)
    if exploit is None and not exploit_path.exists():
        exploit = {
            "schema": EXPLOIT_QUEUE_SCHEMA,
            "queue_role": CANDIDATE_LEADS_QUEUE_ROLE,
            "queue": [],
        }
    allowed_schemas = {
        EXPLOIT_QUEUE_SCHEMA,
        "auditooor.exploit_queue.source_mined.v1",
    }
    if not isinstance(exploit, dict) or exploit.get("schema") not in allowed_schemas:
        raise ValueError("exploit_queue_schema_invalid")
    expected_role = (
        PROOF_TASK_QUEUE_ROLE
        if exploit_path == typed_admitted_path
        else CANDIDATE_LEADS_QUEUE_ROLE
    )
    # Do not reinterpret an explicitly typed queue. Roleless legacy queues
    # remain readable so historical closeout evidence can be reconciled.
    if exploit.get("queue_role") is not None and exploit.get("queue_role") != expected_role:
        raise ValueError(f"exploit_queue_role_invalid:expected-{expected_role}")
    typed_entries: dict[str, dict[str, Any]] | None = None
    if isinstance(exploit, dict) and "zero_day_proof_admission" in exploit:
        if exploit.get("entries") not in (None, []):
            raise ValueError("typed_proof_envelope_legacy_entries_present")
        envelope_path = workspace / ".auditooor" / "zero_day_proof_envelope.json"
        if not envelope_path.is_file():
            raise ValueError("typed_proof_envelope_missing")
        try:
            _load_typed_envelope_tool().verify(workspace, envelope_path, exploit_path)
            envelope = _load_json(envelope_path)
        except Exception as exc:
            raise ValueError(f"typed_proof_envelope_invalid:{exc}") from exc
        if not isinstance(envelope, dict):
            raise ValueError("typed_proof_envelope_invalid")
        typed_entries = {
            entry["lead_id"]: entry
            for entry in envelope["entries"]
            if isinstance(entry, dict) and isinstance(entry.get("lead_id"), str)
        }

    rows: list[dict[str, Any]] = []
    skipped_advisory = 0
    for row in _list_dicts(exploit, "queue"):
        lead_id = row.get("lead_id")
        if typed_entries is not None and (not isinstance(lead_id, str) or lead_id not in typed_entries):
            raise ValueError("typed_proof_envelope_row_missing")
        if _is_advisory_queue_row(row):
            skipped_advisory += 1
            continue
        row_id = str(lead_id or row.get("id") or row.get("candidate_id") or "").strip()
        rows.append(
            {
                "row_kind": "exploit_queue",
                "row_id": row_id or f"exploit_queue:{len(rows) + 1}",
                "title": str(row.get("title") or row.get("root_cause_hypothesis") or ""),
                "attack_class": str(row.get("attack_class") or ""),
                "severity": str(row.get("likely_severity") or row.get("severity") or ""),
                "source_file": exploit_path,
                "raw": row,
                "typed_proof_envelope": typed_entries.get(lead_id) if typed_entries is not None else None,
            }
        )

    for row in _list_dicts(bridge, "rows"):
        row_id = str(row.get("row_id") or row.get("candidate_id") or "").strip()
        rows.append(
            {
                "row_kind": "high_impact_execution_bridge",
                "row_id": row_id or f"high_impact_execution_bridge:{len(rows) + 1}",
                "title": str(row.get("invariant_family") or row.get("harness_family") or ""),
                "attack_class": str(row.get("invariant_family") or row.get("harness_family") or ""),
                "severity": str(row.get("severity") or ""),
                "source_file": bridge_path,
                "raw": row,
                "typed_proof_envelope": None,
            }
        )

    inputs = {
        "exploit_queue": {
            "path": _rel(exploit_path, workspace),
            "present": exploit_path.is_file(),
            "row_count": len(_list_dicts(exploit, "queue")),
            "advisory_rows_skipped": skipped_advisory,
            "source_mined_selected": exploit_path == source_mined_path,
            "typed_proof_queue_selected": exploit_path == typed_admitted_path,
        },
        "canonical_exploit_queue": {
            "path": _rel(canonical_exploit_path, workspace),
            "present": canonical_exploit_path.is_file(),
            "row_count": len(_list_dicts(_load_json(canonical_exploit_path), "queue")),
        },
        "source_mined_exploit_queue": {
            "path": _rel(source_mined_path, workspace),
            "present": source_mined_path.is_file(),
            "row_count": len(_list_dicts(_load_json(source_mined_path), "queue")),
        },
        "typed_admitted_exploit_queue": {
            "path": _rel(typed_admitted_path, workspace),
            "present": typed_admitted_path.is_file(),
            "row_count": len(_list_dicts(_load_json(typed_admitted_path), "queue")),
        },
        "high_impact_execution_bridge": {
            "path": _rel(bridge_path, workspace),
            "present": bridge_path.is_file(),
            "row_count": len(_list_dicts(bridge, "rows")),
        },
    }
    return rows, inputs


def _candidate_keys_from_manifest(path: Path, manifest: dict[str, Any]) -> set[str]:
    return _manifest_keys(path, manifest)


def _candidate_keys_from_source_proof(path: Path, proof: dict[str, Any]) -> set[str]:
    candidate = str(proof.get("candidate_id") or path.parent.name or "").strip()
    keys = {candidate, _slug(candidate), path.parent.name, _slug(path.parent.name)}
    return {key for key in keys if key}


def _iter_impact_contracts(workspace: Path) -> list[dict[str, Any]]:
    payload = _load_json(workspace / ".auditooor" / "impact_contracts.json")
    if isinstance(payload, dict):
        rows = payload.get("contracts")
        if isinstance(rows, list):
            return [row for row in rows if isinstance(row, dict)]
    return []


def _candidate_match_keys(candidate_id: str) -> set[str]:
    text = str(candidate_id or "").strip()
    return {key for key in (text, _slug(text), _norm_key(text)) if key}


def _impact_contract_matches(contract: dict[str, Any], candidate_id: str) -> bool:
    keys = _candidate_match_keys(candidate_id)
    if not keys:
        return False
    raw_values = [
        contract.get("candidate_id"),
        contract.get("impact_contract_id"),
        contract.get("benchmark_id"),
        contract.get("task_id"),
        contract.get("angle_id"),
    ]
    related = contract.get("related_angle_ids")
    if isinstance(related, list):
        raw_values.extend(related)
    return bool(keys & {key for value in raw_values for key in _candidate_match_keys(str(value or ""))})


def _impact_contract_complete(contract: dict[str, Any]) -> bool:
    required = (
        "selected_impact",
        "severity_tier",
        "evidence_class",
        "oos_traps",
        "stop_condition",
    )
    for key in required:
        value = contract.get(key)
        if isinstance(value, list):
            if not [item for item in value if str(item).strip()]:
                return False
        elif not str(value or "").strip():
            return False
    return (
        contract.get("exact_impact_row") is True
        and contract.get("listed_impact_proven") is True
    )


def _impact_contract_status(workspace: Path, candidate_id: str) -> dict[str, Any]:
    for contract in _iter_impact_contracts(workspace):
        if _impact_contract_matches(contract, candidate_id):
            complete = _impact_contract_complete(contract)
            return {
                "status": "complete" if complete else "incomplete",
                "impact_contract_id": str(contract.get("impact_contract_id") or ""),
                "path": ".auditooor/impact_contracts.json",
                "complete": complete,
                "contract": contract,
            }
    return {
        "status": "missing",
        "impact_contract_id": "",
        "path": ".auditooor/impact_contracts.json",
        "complete": False,
        "contract": None,
    }


def _flatten_text(*values: Any) -> str:
    out: list[str] = []
    for value in values:
        if isinstance(value, (list, tuple, set)):
            out.append(_flatten_text(*value))
        elif isinstance(value, dict):
            out.append(json.dumps(value, sort_keys=True))
        elif value not in (None, ""):
            out.append(str(value))
    return " ".join(out).lower()


def _is_high_plus_impact(severity: str, contract: dict[str, Any] | None) -> bool:
    """True when the row / contract carries a HIGH+ fund-loss-class impact."""
    if _norm_key(severity) in LIVE_WITNESS_SEVERITIES:
        return True
    if not contract:
        return False
    if _norm_key(contract.get("severity")) in LIVE_WITNESS_SEVERITIES:
        return True
    if _norm_key(contract.get("severity_tier")) in LIVE_WITNESS_SEVERITIES:
        return True
    hay = _flatten_text(
        contract.get("selected_impact"),
        contract.get("listed_impact_selected"),
    )
    return any(keyword in hay for keyword in HIGH_PLUS_IMPACT_KEYWORDS)


def _opposed_trace_advisories(contract: dict[str, Any] | None) -> list[str]:
    """Advisory (non-blocking) opposed-trace warnings for a non-HIGH+ contract.

    HACKERMAN_V3 tiered model: the opposed-trace question is asked at every
    severity, but below HIGH+ a missing opposed trace is an ADVISORY, not a
    hard blocker. A non-HIGH+ contract with an unopposed-trace impact emits
    ``advisory_unopposed_trace`` so the operator sees it, while the row still
    hard-closes (never blocked on this advisory).
    """
    if not contract:
        return []
    advisories = contract.get("contract_advisories")
    if isinstance(advisories, list) and any(str(item).strip() for item in advisories):
        return ["advisory_unopposed_trace"]
    coverage = _norm_key(contract.get("opposed_trace_coverage"))
    defenses = contract.get("protocol_defenses_enumerated")
    defenses_present = isinstance(defenses, list) and any(
        str(item).strip() for item in defenses
    )
    if not defenses_present or coverage == "missing":
        return ["advisory_unopposed_trace"]
    return []


def _opposed_trace_blockers(contract: dict[str, Any] | None) -> list[str]:
    """Fail-closed blockers for an unopposed-trace HIGH+ impact contract.

    Emits typed blockers so the operator sees exactly why the row is blocked:

    - ``unopposed_trace_high_plus`` - HIGH+ with no enumerated protocol
      defenses, or ``opposed_trace_required`` set and coverage not ``covered``;
    - ``opposed_trace_missing_defender_wins_control`` /
      ``opposed_trace_missing_defender_absent_control`` - the negative controls
      lack the "defender wins" / "defender absent" variant.
    """
    if not contract:
        return []
    blockers: list[str] = []
    required = contract.get("opposed_trace_required")
    coverage = _norm_key(contract.get("opposed_trace_coverage"))
    defenses = contract.get("protocol_defenses_enumerated")
    defenses_present = isinstance(defenses, list) and any(
        str(item).strip() for item in defenses
    )

    if not defenses_present:
        blockers.append("unopposed_trace_high_plus")
    elif required is True and coverage != "covered":
        blockers.append("unopposed_trace_high_plus")

    if defenses_present:
        control_text = _flatten_text(
            contract.get("negative_control"),
            contract.get("negative_controls"),
            contract.get("kill_conditions"),
            contract.get("stop_condition"),
            contract.get("clean_control"),
            contract.get("defender_wins_control"),
            contract.get("defender_absent_control"),
        )
        if not any(token in control_text for token in DEFENDER_WINS_TOKENS):
            blockers.append("opposed_trace_missing_defender_wins_control")
        if not any(token in control_text for token in DEFENDER_ABSENT_TOKENS):
            blockers.append("opposed_trace_missing_defender_absent_control")

    return list(dict.fromkeys(blockers))


def _list_dict_rows(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [row for row in payload if isinstance(row, dict)]
    if isinstance(payload, dict):
        for key in ("witnesses", "rows", "records", "checks"):
            rows = payload.get(key)
            if isinstance(rows, list):
                return [row for row in rows if isinstance(row, dict)]
        return [payload]
    return []


def _live_witness_candidate_key(witness: dict[str, Any]) -> str:
    for key in (
        "candidate_id",
        "row_id",
        "lead_id",
        "impact_contract_id",
        "finding_id",
        "check_id",
    ):
        text = str(witness.get(key) or "").strip()
        if text:
            return text
    return ""


def _live_witness_complete(witness: dict[str, Any]) -> bool:
    verdict = str(witness.get("verdict") or "").strip()
    if verdict == NO_TEMPORAL_STATE_RELEVANCE or witness.get("no_temporal_state_relevance") is True:
        return True
    status = _norm_key(witness.get("status"))
    if status not in COMPLETE_LIVE_WITNESS_STATUSES:
        return False
    has_block = any(str(witness.get(key) or "").strip() for key in ("pinned_block", "block_number", "block"))
    has_rpc = any(str(witness.get(key) or "").strip() for key in ("rpc_url", "rpc", "chain_rpc"))
    has_state = any(
        bool(witness.get(key))
        for key in (
            "current_state_diff",
            "state_diff",
            "historical_state_transitions",
            "live_state_results",
            "observations",
            "probe_results",
        )
    )
    return has_block and has_rpc and has_state


def _live_witness_candidates(workspace: Path, candidate_id: str) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    paths = [
        workspace / ".auditooor" / "live_state_witnesses.json",
        workspace / ".auditooor" / "live_state_witnesses" / f"{_slug(candidate_id)}.json",
        workspace / "live_state_witnesses" / f"{_slug(candidate_id)}.json",
        workspace / "live_state_witnesses.json",
    ]
    keys = _candidate_match_keys(candidate_id)
    for path in paths:
        payload = _load_json(path)
        for row in _list_dict_rows(payload):
            row_key = _live_witness_candidate_key(row)
            if not row_key or keys & _candidate_match_keys(row_key):
                candidates.append({**row, "_witness_path": _rel(path, workspace)})
    return candidates


def _live_witness_status(workspace: Path, candidate_id: str) -> dict[str, Any]:
    witnesses = _live_witness_candidates(workspace, candidate_id)
    for witness in witnesses:
        if _live_witness_complete(witness):
            return {
                "status": "complete",
                "path": str(witness.get("_witness_path") or ""),
                "complete": True,
            }
    if witnesses:
        return {
            "status": "incomplete",
            "path": str(witnesses[0].get("_witness_path") or ""),
            "complete": False,
        }
    return {"status": "missing", "path": "", "complete": False}


def _proof_grade_gate_status(workspace: Path, candidate_id: str, severity: str) -> dict[str, Any]:
    impact_status = _impact_contract_status(workspace, candidate_id)
    live_status = _live_witness_status(workspace, candidate_id)
    severity_live_candidate = _severity_requires_live_witness(severity)
    live_required = severity_live_candidate and _workspace_requires_live_witness(workspace)
    contract = impact_status.get("contract")
    blockers: list[str] = []
    advisories: list[str] = []
    if severity_live_candidate:
        if not impact_status["complete"]:
            blockers.append("missing_complete_impact_contract")
        if live_required and not live_status["complete"]:
            blockers.append("missing_live_state_witness")
    # HACKERMAN_V3 opposed-trace proof gate (tiered): a HIGH+ Direct-loss /
    # freeze / theft row cannot hard-close from an unopposed
    # (attacker-vs-empty-world) trace - it fails closed on empty enumerated
    # defenses, on opposed_trace_required with coverage != covered, and on
    # missing defender-wins / defender-absent negative-control variants. Below
    # HIGH+ the missing opposed trace is an ADVISORY (non-blocking): the row
    # still hard-closes, but the advisory stays visible to the operator.
    if _is_high_plus_impact(severity, contract):
        blockers.extend(_opposed_trace_blockers(contract))
    else:
        advisories.extend(_opposed_trace_advisories(contract))
    return {
        "impact_contract_status": impact_status["status"],
        "impact_contract_id": impact_status["impact_contract_id"],
        "impact_contract_path": impact_status["path"],
        "live_state_witness_status": live_status["status"],
        "live_state_witness_path": live_status["path"],
        "live_state_witness_required": live_required,
        "proof_grade_gate_blockers": blockers,
        "proof_grade_gate_advisories": advisories,
    }


def _manifest_keys(path: Path, manifest: dict[str, Any]) -> set[str]:
    keys: set[str] = {path.parent.name, _slug(path.parent.name)}
    for field in (
        "candidate_id",
        "bridge_row_id",
        "proof_task_id",
        "detector_slug",
        "detector_obligation",
    ):
        value = str(manifest.get(field) or "").strip()
        if value:
            keys.add(value)
            keys.add(_slug(value))
    return {key for key in keys if key}


def _load_manifests(workspace: Path) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]]]:
    manifests: list[dict[str, Any]] = []
    by_key: dict[str, dict[str, Any]] = {}
    for path in sorted((workspace / "poc_execution").glob("**/execution_manifest.json")):
        payload = _load_json(path)
        if not isinstance(payload, dict):
            continue
        record = {"path": path, "manifest": payload}
        manifests.append(record)
        for key in _manifest_keys(path, payload):
            by_key.setdefault(key, record)
    return manifests, by_key


def _load_source_proofs(workspace: Path) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]]]:
    proofs: list[dict[str, Any]] = []
    by_key: dict[str, dict[str, Any]] = {}
    for path in sorted((workspace / "source_proofs").glob("**/source_proof.json")):
        payload = _load_json(path)
        if not isinstance(payload, dict):
            continue
        record = {"path": path, "proof": payload}
        proofs.append(record)
        candidate = str(payload.get("candidate_id") or path.parent.name or "").strip()
        for key in {candidate, _slug(candidate), path.parent.name, _slug(path.parent.name)}:
            if key:
                by_key.setdefault(key, record)
    return proofs, by_key


def _direct_manifest_for_bridge_row(
    raw: dict[str, Any],
    workspace: Path,
) -> dict[str, Any] | None:
    value = str(raw.get("poc_execution_record_path") or "").strip()
    if not value:
        return None
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = workspace / path
    if not path.is_file():
        return None
    payload = _load_json(path)
    if not isinstance(payload, dict):
        return None
    return {"path": path, "manifest": payload}


def _match_manifest(
    row: dict[str, Any],
    workspace: Path,
    by_key: dict[str, dict[str, Any]],
) -> dict[str, Any] | None:
    raw = row["raw"]
    if row["row_kind"] == "high_impact_execution_bridge":
        direct = _direct_manifest_for_bridge_row(raw, workspace)
        if direct is not None:
            return direct

    candidate_keys: list[str] = []
    for value in (
        row.get("row_id"),
        raw.get("candidate_id"),
        raw.get("lead_id"),
        raw.get("proof_task_id"),
        raw.get("detector_slug"),
        raw.get("detector_obligation"),
        raw.get("bridge_row_id"),
    ):
        text = str(value or "").strip()
        if text:
            candidate_keys.extend([text, _slug(text)])
    for key in candidate_keys:
        if key in by_key:
            return by_key[key]
    return None


def _match_source_proof(
    row: dict[str, Any],
    by_key: dict[str, dict[str, Any]],
) -> dict[str, Any] | None:
    raw = row["raw"]
    candidate_keys: list[str] = []
    for value in (
        row.get("row_id"),
        raw.get("candidate_id"),
        raw.get("lead_id"),
        raw.get("proof_task_id"),
        raw.get("detector_slug"),
        raw.get("detector_obligation"),
        raw.get("bridge_row_id"),
    ):
        text = str(value or "").strip()
        if text:
            candidate_keys.extend([text, _slug(text)])
    for key in candidate_keys:
        if key in by_key:
            return by_key[key]
    return None


def _has_executed_command_evidence(manifest: dict[str, Any]) -> bool:
    counts = command_evidence_counts(manifest)
    return (
        str(manifest.get("evidence_class") or "") == "executed_with_manifest"
        and counts["structured_command_count"] > 0
        and counts["command_with_text_count"] > 0
        and (counts["passing_command_count"] > 0 or counts["missing_exit_code_count"] == 0)
    )


def _manifest_status(
    manifest: dict[str, Any],
    manifest_path: Path,
    workspace: Path,
    now_unix: float,
    stale_days: float,
    *,
    severity: str = "",
) -> dict[str, Any]:
    final_result = str(manifest.get("final_result") or "missing")
    impact_assertion = str(manifest.get("impact_assertion") or "missing")
    evidence_class = str(manifest.get("evidence_class") or "missing")
    candidate_id = str(manifest.get("candidate_id") or manifest_path.parent.name)
    counts = command_evidence_counts(manifest)
    bound_source_blockers = bound_source_validation(manifest, workspace)["errors"]
    proof_blockers = strict_terminal_blockers(manifest) + bound_source_blockers
    proof_grade_gate = _proof_grade_gate_status(
        workspace,
        candidate_id,
        str(manifest.get("severity") or severity or ""),
    )
    proof_blockers = proof_blockers + proof_grade_gate["proof_grade_gate_blockers"]
    age_days = _manifest_age_days(manifest_path, manifest, now_unix)
    stale = age_days is not None and age_days >= stale_days

    base = {
        "evidence_manifest_path": _rel(manifest_path, workspace),
        "evidence_candidate_id": candidate_id,
        "final_result": final_result,
        "impact_assertion": impact_assertion,
        "evidence_class": evidence_class,
        "command_status_counts": command_status_counts(manifest),
        "command_evidence_counts": counts,
        "evidence_age_days": round(age_days, 3) if age_days is not None else None,
        "stale_evidence": stale,
        "proof_blockers": proof_blockers,
        "bound_source_blockers": bound_source_blockers,
        "impact_contract_status": proof_grade_gate["impact_contract_status"],
        "impact_contract_id": proof_grade_gate["impact_contract_id"],
        "impact_contract_path": proof_grade_gate["impact_contract_path"],
        "live_state_witness_status": proof_grade_gate["live_state_witness_status"],
        "live_state_witness_path": proof_grade_gate["live_state_witness_path"],
        "live_state_witness_required": proof_grade_gate["live_state_witness_required"],
        "proof_grade_gate_blockers": proof_grade_gate["proof_grade_gate_blockers"],
        "proof_grade_gate_advisories": proof_grade_gate.get("proof_grade_gate_advisories", []),
    }

    if is_strict_proved_execution_manifest(manifest):
        if proof_grade_gate["proof_grade_gate_blockers"] or bound_source_blockers:
            reasons = ["strict_proved_execution_manifest"]
            if proof_grade_gate["proof_grade_gate_blockers"]:
                reasons.append("proof_grade_gate_blocked")
            if bound_source_blockers:
                reasons.append("bound_source_binding_blocked")
            return {
                **base,
                "closeout_status": "missing_evidence",
                "proof_counted": False,
                "reasons": reasons,
            }
        return {
            **base,
            "closeout_status": "proved",
            "proof_counted": True,
            "reasons": ["strict_proved_impact_execution_manifest"],
        }
    if final_result == "disproved" and _has_executed_command_evidence(manifest):
        return {
            **base,
            "closeout_status": "disproved",
            "proof_counted": False,
            "reasons": ["executed_manifest_records_disproved"],
        }
    if final_result in BLOCKED_FINAL_RESULTS:
        return {
            **base,
            "closeout_status": "blocked",
            "proof_counted": False,
            "reasons": [f"execution_manifest_{final_result}"],
        }

    reasons = ["execution_manifest_not_terminal"]
    if final_result == "proved":
        reasons.append("claimed_proved_but_strict_evidence_missing")
    if stale:
        reasons.append("stale_unresolved_execution_manifest")
    return {
        **base,
        "closeout_status": "missing_evidence",
        "proof_counted": False,
        "reasons": reasons,
    }


def _source_proof_status(
    proof: dict[str, Any],
    proof_path: Path,
    workspace: Path,
    now_unix: float,
    stale_days: float,
) -> dict[str, Any]:
    final_verdict = str(proof.get("final_verdict") or "missing")
    evidence_class = str(proof.get("evidence_class") or "source_proof")
    age_days = _manifest_age_days(proof_path, proof, now_unix)
    stale = age_days is not None and age_days >= stale_days
    blockers = [str(item) for item in proof.get("blockers") or []]
    base = {
        "evidence_manifest_path": _rel(proof_path, workspace),
        "evidence_candidate_id": str(proof.get("candidate_id") or proof_path.parent.name),
        "final_result": final_verdict,
        "impact_assertion": "source_review",
        "evidence_class": evidence_class,
        "command_status_counts": {},
        "command_evidence_counts": {
            "valid_source_citation_count": int(proof.get("valid_source_citation_count") or 0),
            "source_citation_count": int(proof.get("source_citation_count") or 0),
        },
        "evidence_age_days": round(age_days, 3) if age_days is not None else None,
        "stale_evidence": stale,
        "proof_blockers": blockers,
        "impact_contract_status": "unknown",
        "impact_contract_id": "",
        "impact_contract_path": "",
        "live_state_witness_status": "unknown",
        "live_state_witness_path": "",
        "live_state_witness_required": False,
        "proof_grade_gate_blockers": [],
        "proof_grade_gate_advisories": [],
    }
    if final_verdict == "killed":
        reasons = ["source_proof_killed"]
        if stale:
            reasons.append("stale_source_proof")
        return {
            **base,
            "closeout_status": "killed",
            "proof_counted": False,
            "reasons": reasons,
        }
    if final_verdict == "blocked_missing_impact_contract":
        reasons = ["source_proof_blocked_missing_impact_contract"]
        if stale:
            reasons.append("stale_source_proof")
        return {
            **base,
            "closeout_status": "blocked",
            "proof_counted": False,
            "reasons": reasons,
        }
    reasons = [f"source_proof_{final_verdict}_requires_execution_manifest"]
    if stale:
        reasons.append("stale_source_proof")
    return {
        **base,
        "closeout_status": "missing_evidence",
        "proof_counted": False,
        "proof_blockers": blockers + ["missing_poc_execution_manifest"],
        "reasons": reasons,
    }


def _bridge_blocked_reason(raw: dict[str, Any]) -> str:
    if str(raw.get("poc_execution_record_status") or "") == "blocked":
        return str(raw.get("poc_execution_record_blocked_reason") or "poc_execution_record_blocked")
    status = str(raw.get("bridge_status") or "")
    if status.startswith("blocked"):
        return status
    if bool(raw.get("impact_contract_blocked")):
        return "impact_contract_blocked"
    return ""


def _classify_row(
    row: dict[str, Any],
    workspace: Path,
    by_key: dict[str, dict[str, Any]],
    source_proofs_by_key: dict[str, dict[str, Any]],
    *,
    now_unix: float,
    stale_days: float,
) -> dict[str, Any]:
    raw = row["raw"]
    source_proof_record = _match_source_proof(row, source_proofs_by_key)
    if source_proof_record is not None:
        source_status = _source_proof_status(
            source_proof_record["proof"],
            source_proof_record["path"],
            workspace,
            now_unix,
            stale_days,
        )
        if source_status["closeout_status"] in {"killed", "blocked"}:
            status = source_status
        else:
            status = None
    else:
        status = None

    manifest_record = _match_manifest(row, workspace, by_key)
    if status is None and manifest_record is not None:
        status = _manifest_status(
            manifest_record["manifest"],
            manifest_record["path"],
            workspace,
            now_unix,
            stale_days,
            severity=str(raw.get("likely_severity") or raw.get("severity") or row["severity"]),
        )
    elif status is None:
        if source_proof_record is not None:
            status = source_status
        else:
            source_age = _path_age_days(row["source_file"], now_unix)
            stale = source_age is not None and source_age >= stale_days
            bridge_blocked = _bridge_blocked_reason(raw) if row["row_kind"] == "high_impact_execution_bridge" else ""
            if bridge_blocked:
                status = {
                    "closeout_status": "blocked",
                    "proof_counted": False,
                    "evidence_manifest_path": "",
                    "evidence_candidate_id": "",
                    "final_result": "missing",
                    "impact_assertion": "missing",
                    "evidence_class": "missing",
                    "command_status_counts": {},
                    "command_evidence_counts": {},
                    "evidence_age_days": round(source_age, 3) if source_age is not None else None,
                    "stale_evidence": stale,
                    "proof_blockers": ["missing_poc_execution_manifest"],
                    "impact_contract_status": "unknown",
                    "impact_contract_id": "",
                    "impact_contract_path": "",
                    "live_state_witness_status": "unknown",
                    "live_state_witness_path": "",
                    "live_state_witness_required": False,
                    "proof_grade_gate_blockers": [],
                    "proof_grade_gate_advisories": [],
                    "reasons": [bridge_blocked],
                }
            else:
                reasons = ["missing_poc_execution_manifest"]
                if stale:
                    reasons.append("stale_missing_execution_evidence")
                status = {
                    "closeout_status": "missing_evidence",
                    "proof_counted": False,
                    "evidence_manifest_path": "",
                    "evidence_candidate_id": "",
                    "final_result": "missing",
                    "impact_assertion": "missing",
                    "evidence_class": "missing",
                    "command_status_counts": {},
                    "command_evidence_counts": {},
                    "evidence_age_days": round(source_age, 3) if source_age is not None else None,
                    "stale_evidence": stale,
                    "proof_blockers": ["missing_poc_execution_manifest"],
                    "impact_contract_status": "unknown",
                    "impact_contract_id": "",
                    "impact_contract_path": "",
                    "live_state_witness_status": "unknown",
                    "live_state_witness_path": "",
                    "live_state_witness_required": False,
                    "proof_grade_gate_blockers": [],
                    "proof_grade_gate_advisories": [],
                    "reasons": reasons,
                }

    typed_envelope = row.get("typed_proof_envelope")
    if isinstance(typed_envelope, dict) and status["closeout_status"] in {"proved", "disproved", "killed", "blocked"}:
        # Local execution/source evidence is necessary but not enough to close
        # an admitted obligation. The terminal queue record must preserve the
        # frozen parent identity and carry its own source citation.
        if not _load_typed_envelope_tool().terminal_record_matches(typed_envelope, raw):
            status = dict(status)
            status["closeout_status"] = "missing_evidence"
            status["proof_counted"] = False
            status["proof_blockers"] = list(status.get("proof_blockers") or []) + [
                "typed_terminal_record_missing_or_mismatched"
            ]
            status["reasons"] = list(status.get("reasons") or []) + [
                "typed_terminal_record_missing_or_mismatched"
            ]

    blockers = raw.get("blockers")
    if not isinstance(blockers, list):
        blockers = []

    return {
        "row_key": f"{row['row_kind']}:{row['row_id']}",
        "row_kind": row["row_kind"],
        "row_id": row["row_id"],
        "title": row["title"],
        "attack_class": row["attack_class"],
        "severity": row["severity"],
        "source_file": _rel(row["source_file"], workspace),
        "zero_day_proof_envelope": typed_envelope if isinstance(typed_envelope, dict) else None,
        "queue_blockers": [str(item) for item in blockers],
        "bridge_status": str(raw.get("bridge_status") or ""),
        "poc_execution_record_status": str(raw.get("poc_execution_record_status") or ""),
        "closeout_status": status["closeout_status"],
        "proof_counted": status["proof_counted"],
        "evidence_manifest_path": status["evidence_manifest_path"],
        "evidence_candidate_id": status["evidence_candidate_id"],
        "final_result": status["final_result"],
        "impact_assertion": status["impact_assertion"],
        "evidence_class": status["evidence_class"],
        "command_status_counts": status["command_status_counts"],
        "command_evidence_counts": status["command_evidence_counts"],
        "proof_blockers": status["proof_blockers"],
        "impact_contract_status": status.get("impact_contract_status", "unknown"),
        "impact_contract_id": status.get("impact_contract_id", ""),
        "impact_contract_path": status.get("impact_contract_path", ""),
        "live_state_witness_status": status.get("live_state_witness_status", "unknown"),
        "live_state_witness_path": status.get("live_state_witness_path", ""),
        "live_state_witness_required": status.get("live_state_witness_required", False),
        "proof_grade_gate_blockers": status.get("proof_grade_gate_blockers", []),
        "proof_grade_gate_advisories": status.get("proof_grade_gate_advisories", []),
        "reasons": status["reasons"],
        "evidence_age_days": status["evidence_age_days"],
        "stale_evidence": status["stale_evidence"],
        "proof_boundary": PROOF_BOUNDARY,
        "promotion_allowed": False,
        "submission_posture": "NOT_SUBMIT_READY",
    }


def _local_manifest_row(
    record: dict[str, Any],
    workspace: Path,
    *,
    now_unix: float,
    stale_days: float,
) -> dict[str, Any]:
    manifest = record["manifest"]
    path = record["path"]
    candidate_id = str(manifest.get("candidate_id") or path.parent.name or "").strip() or path.parent.name
    status = _manifest_status(manifest, path, workspace, now_unix, stale_days)
    return {
        "row_key": f"local_poc_execution:{candidate_id}",
        "row_kind": "local_poc_execution",
        "row_id": candidate_id,
        "title": str(manifest.get("title") or candidate_id),
        "attack_class": str(manifest.get("attack_class") or ""),
        "severity": str(manifest.get("severity") or ""),
        "source_file": _rel(path, workspace),
        "queue_blockers": [],
        "bridge_status": "",
        "poc_execution_record_status": "present_unmatched_to_queue",
        "closeout_status": status["closeout_status"],
        "proof_counted": status["proof_counted"],
        "evidence_manifest_path": status["evidence_manifest_path"],
        "evidence_candidate_id": status["evidence_candidate_id"],
        "final_result": status["final_result"],
        "impact_assertion": status["impact_assertion"],
        "evidence_class": status["evidence_class"],
        "command_status_counts": status["command_status_counts"],
        "command_evidence_counts": status["command_evidence_counts"],
        "proof_blockers": status["proof_blockers"],
        "impact_contract_status": status.get("impact_contract_status", "unknown"),
        "impact_contract_id": status.get("impact_contract_id", ""),
        "impact_contract_path": status.get("impact_contract_path", ""),
        "live_state_witness_status": status.get("live_state_witness_status", "unknown"),
        "live_state_witness_path": status.get("live_state_witness_path", ""),
        "live_state_witness_required": status.get("live_state_witness_required", False),
        "proof_grade_gate_blockers": status.get("proof_grade_gate_blockers", []),
        "proof_grade_gate_advisories": status.get("proof_grade_gate_advisories", []),
        "reasons": ["unmatched_local_poc_execution"] + status["reasons"],
        "evidence_age_days": status["evidence_age_days"],
        "stale_evidence": status["stale_evidence"],
        "proof_boundary": PROOF_BOUNDARY,
        "promotion_allowed": False,
        "submission_posture": "NOT_SUBMIT_READY",
    }


def _local_source_proof_row(
    record: dict[str, Any],
    workspace: Path,
    *,
    now_unix: float,
    stale_days: float,
) -> dict[str, Any]:
    proof = record["proof"]
    path = record["path"]
    candidate_id = str(proof.get("candidate_id") or path.parent.name or "").strip() or path.parent.name
    status = _source_proof_status(proof, path, workspace, now_unix, stale_days)
    return {
        "row_key": f"local_source_proof:{candidate_id}",
        "row_kind": "local_source_proof",
        "row_id": candidate_id,
        "title": str(proof.get("title") or candidate_id),
        "attack_class": str(proof.get("attack_class") or ""),
        "severity": str(proof.get("severity") or ""),
        "source_file": _rel(path, workspace),
        "queue_blockers": [],
        "bridge_status": "",
        "poc_execution_record_status": "",
        "closeout_status": status["closeout_status"],
        "proof_counted": status["proof_counted"],
        "evidence_manifest_path": status["evidence_manifest_path"],
        "evidence_candidate_id": status["evidence_candidate_id"],
        "final_result": status["final_result"],
        "impact_assertion": status["impact_assertion"],
        "evidence_class": status["evidence_class"],
        "command_status_counts": status["command_status_counts"],
        "command_evidence_counts": status["command_evidence_counts"],
        "proof_blockers": status["proof_blockers"],
        "impact_contract_status": "unknown",
        "impact_contract_id": "",
        "impact_contract_path": "",
        "live_state_witness_status": "unknown",
        "live_state_witness_path": "",
        "live_state_witness_required": False,
        "proof_grade_gate_blockers": [],
        "proof_grade_gate_advisories": [],
        "reasons": ["unmatched_local_source_proof"] + status["reasons"],
        "evidence_age_days": status["evidence_age_days"],
        "stale_evidence": status["stale_evidence"],
        "proof_boundary": PROOF_BOUNDARY,
        "promotion_allowed": False,
        "submission_posture": "NOT_SUBMIT_READY",
    }


def _append_unmatched_local_evidence_rows(
    rows: list[dict[str, Any]],
    *,
    manifests: list[dict[str, Any]],
    source_proofs: list[dict[str, Any]],
    workspace: Path,
    queue_rows: list[dict[str, Any]],
    now_unix: float,
    stale_days: float,
) -> list[dict[str, Any]]:
    matched_keys: set[str] = set()
    for row in queue_rows:
        raw = row["raw"]
        for value in (
            row.get("row_id"),
            raw.get("candidate_id"),
            raw.get("lead_id"),
            raw.get("proof_task_id"),
            raw.get("detector_slug"),
            raw.get("detector_obligation"),
            raw.get("bridge_row_id"),
        ):
            text = str(value or "").strip()
            if text:
                matched_keys.add(text)
                matched_keys.add(_slug(text))

    extended = list(rows)
    # Prefer terminal source review over loose execution manifests for the same
    # candidate. This keeps a killed source proof from being hidden by an older
    # branch-only or setup-only PoC manifest.
    for record in source_proofs:
        keys = _candidate_keys_from_source_proof(record["path"], record["proof"])
        if keys.isdisjoint(matched_keys):
            extended.append(
                _local_source_proof_row(
                    record,
                    workspace,
                    now_unix=now_unix,
                    stale_days=stale_days,
                )
            )
            matched_keys.update(keys)

    for record in manifests:
        keys = _candidate_keys_from_manifest(record["path"], record["manifest"])
        if keys.isdisjoint(matched_keys):
            extended.append(
                _local_manifest_row(
                    record,
                    workspace,
                    now_unix=now_unix,
                    stale_days=stale_days,
                )
            )
            matched_keys.update(keys)

    return extended


def _empty_payload(workspace: Path, *, now_unix: float, reason: str) -> dict[str, Any]:
    payload = {
        "schema": SCHEMA,
        "generated_at_utc": _utc_now_iso(now_unix),
        "workspace": str(workspace),
        "degraded": True,
        "degraded_reason": reason,
        "advisory_only": True,
        "claim_scope": "offline_queue_to_local_execution_evidence_closeout",
        "proof_boundary": PROOF_BOUNDARY,
        "submission_posture": "NOT_SUBMIT_READY",
        "promotion_allowed": False,
        "hard_close_complete": False,
        "inputs": {},
        "summary": {
            "total_rows": 0,
            "by_status": {},
            "proved_count": 0,
            "disproved_count": 0,
            "blocked_count": 0,
            "killed_count": 0,
            "missing_evidence_count": 0,
            "stale_evidence_count": 0,
            "proof_counted": 0,
            "execution_manifests_seen": 0,
            "source_proofs_seen": 0,
        },
        "rows": [],
    }
    digest = _sha256_json(payload["rows"])
    payload["context_pack_hash"] = digest
    payload["context_pack_id"] = f"{SCHEMA}:{digest[:16]}"
    return payload


def build_payload(
    workspace: Path,
    *,
    now_unix: float | None = None,
    stale_days: float = DEFAULT_STALE_DAYS,
) -> dict[str, Any]:
    workspace = workspace.expanduser().resolve()
    now = now_unix if now_unix is not None else time.time()
    if not workspace.is_dir():
        return _empty_payload(workspace, now_unix=now, reason="workspace_missing")

    queue_rows, inputs = _queue_rows(workspace)
    manifests, by_key = _load_manifests(workspace)
    source_proofs, source_proofs_by_key = _load_source_proofs(workspace)
    rows = [
        _classify_row(
            row,
            workspace,
            by_key,
            source_proofs_by_key,
            now_unix=now,
            stale_days=stale_days,
        )
        for row in queue_rows
    ]
    rows = _append_unmatched_local_evidence_rows(
        rows,
        manifests=manifests,
        source_proofs=source_proofs,
        workspace=workspace,
        queue_rows=queue_rows,
        now_unix=now,
        stale_days=stale_days,
    )
    by_status = Counter(row["closeout_status"] for row in rows)
    advisory_skipped = int(inputs.get("exploit_queue", {}).get("advisory_rows_skipped") or 0)
    hard_close_complete = (bool(rows) or advisory_skipped > 0) and by_status.get("missing_evidence", 0) == 0
    payload = {
        "schema": SCHEMA,
        "generated_at_utc": _utc_now_iso(now),
        "workspace": str(workspace),
        "degraded": False,
        "degraded_reason": "",
        "advisory_only": True,
        "claim_scope": "offline_queue_to_local_execution_evidence_closeout",
        "proof_boundary": PROOF_BOUNDARY,
        "submission_posture": "NOT_SUBMIT_READY",
        "promotion_allowed": False,
        "hard_close_complete": hard_close_complete,
        "inputs": {
            **inputs,
            "poc_execution_manifests": {
                "path": "poc_execution/**/execution_manifest.json",
                "present": bool(manifests),
                "row_count": len(manifests),
            },
            "source_proofs": {
                "path": "source_proofs/**/source_proof.json",
                "present": bool(source_proofs),
                "row_count": len(source_proofs),
            },
        },
        "summary": {
            "total_rows": len(rows),
            "by_status": dict(sorted(by_status.items())),
            "proved_count": by_status.get("proved", 0),
            "disproved_count": by_status.get("disproved", 0),
            "killed_count": by_status.get("killed", 0),
            "blocked_count": by_status.get("blocked", 0),
            "missing_evidence_count": by_status.get("missing_evidence", 0),
            "advisory_rows_skipped": advisory_skipped,
            "stale_evidence_count": sum(1 for row in rows if row.get("stale_evidence")),
            "proof_counted": sum(1 for row in rows if row.get("proof_counted")),
            "execution_manifests_seen": len(manifests),
            "source_proofs_seen": len(source_proofs),
        },
        "rows": rows,
    }
    digest = _sha256_json(rows)
    payload["context_pack_hash"] = digest
    payload["context_pack_id"] = f"{SCHEMA}:{digest[:16]}"
    return payload


def render_markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# Queue Proof Hard Close",
        "",
        "Generated by `tools/queue-proof-hard-close.py`.",
        "",
        f"- schema: `{payload['schema']}`",
        f"- rows: {payload['summary']['total_rows']}",
        f"- proved: {payload['summary']['proved_count']}",
        f"- disproved: {payload['summary']['disproved_count']}",
        f"- killed: {payload['summary'].get('killed_count', 0)}",
        f"- blocked: {payload['summary']['blocked_count']}",
        f"- missing_evidence: {payload['summary']['missing_evidence_count']}",
        f"- hard_close_complete: `{str(payload['hard_close_complete']).lower()}`",
        f"- submission_posture: `{payload['submission_posture']}`",
        f"- promotion_allowed: `{str(payload['promotion_allowed']).lower()}`",
        "",
        f"> {payload['proof_boundary']}",
        "",
        "## Rows",
        "",
        "| row | status | evidence | reasons |",
        "|---|---|---|---|",
    ]
    for row in payload.get("rows") or []:
        evidence = row.get("evidence_manifest_path") or "missing"
        reasons = ", ".join(row.get("reasons") or [])
        lines.append(
            f"| `{row['row_key']}` | `{row['closeout_status']}` | `{evidence}` | `{reasons}` |"
        )
    lines.append("")
    return "\n".join(lines)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--out-json", type=Path, default=None)
    parser.add_argument("--out-md", type=Path, default=None, help="Optional Markdown output path.")
    parser.add_argument("--stale-days", type=float, default=DEFAULT_STALE_DAYS)
    parser.add_argument("--print-json", action="store_true")
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit 1 when any row is missing evidence or the workspace is missing.",
    )
    return parser.parse_args(argv)


def run(argv: list[str] | None = None) -> dict[str, Any]:
    args = parse_args(argv)
    workspace = args.workspace.expanduser().resolve()
    payload = build_payload(workspace, stale_days=args.stale_days)

    out_json = args.out_json.expanduser().resolve() if args.out_json else None
    if out_json is None and workspace.is_dir():
        out_json = workspace / ".auditooor" / "queue_proof_hard_close.json"
    if out_json is not None:
        _write_json(out_json, payload)

    if args.out_md is not None:
        _write_text(args.out_md.expanduser().resolve(), render_markdown(payload))

    if args.print_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    elif out_json is not None:
        print(f"[queue-proof-hard-close] wrote {out_json}")
    else:
        print(
            f"[queue-proof-hard-close] degraded={payload['degraded']} "
            f"reason={payload['degraded_reason']}",
            file=sys.stderr,
        )
    return payload


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    workspace = args.workspace.expanduser().resolve()
    payload = build_payload(workspace, stale_days=args.stale_days)

    out_json = args.out_json.expanduser().resolve() if args.out_json else None
    if out_json is None and workspace.is_dir():
        out_json = workspace / ".auditooor" / "queue_proof_hard_close.json"
    if out_json is not None:
        _write_json(out_json, payload)
    if args.out_md is not None:
        _write_text(args.out_md.expanduser().resolve(), render_markdown(payload))

    if args.print_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    elif out_json is not None:
        print(f"[queue-proof-hard-close] wrote {out_json}")
    else:
        print(
            f"[queue-proof-hard-close] degraded={payload['degraded']} "
            f"reason={payload['degraded_reason']}",
            file=sys.stderr,
        )

    if args.strict and (
        payload.get("degraded") or payload.get("summary", {}).get("missing_evidence_count", 0)
    ):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
