#!/usr/bin/env python3
"""Build manual-proof capture templates from unresolved live topology rows.

This is a fail-closed bridge between address-resolution accounting and real
same-block topology proof collection. It does not write ``manual_proofs/`` and
does not mark rows executed; it only materializes exact capture/import commands
and per-row templates that an operator or later live worker can fill with real
addresses, expected values, and a shared block.
"""

from __future__ import annotations

import argparse
import json
import re
import shlex
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA = "auditooor.live_topology_manual_proof_plan.v1"
DEFAULT_INPUT = ".auditooor/live_topology_address_resolution_ew.json"
DEFAULT_OUT = ".auditooor/live_topology_manual_proof_plan_fd.json"
DEFAULT_OUT_MD = ".auditooor/live_topology_manual_proof_plan_fd.md"
DEFAULT_TEMPLATE_DIR = ".auditooor/live_topology_manual_proof_templates_fd"

SOURCE_REF_KEYS = (
    "source_refs",
    "source_ref",
    "workspace_source_refs",
    "current_workspace_source_refs",
    "configured_source_refs",
    "topology_source_refs",
    "source_locations",
    "target_source_refs",
    "target_source_ref",
)
TOPOLOGY_EVIDENCE_KEYS = (
    "configured_topology_evidence",
    "topology_evidence",
    "deployment_topology_evidence",
    "configuration_evidence",
    "topology_config_evidence",
)
PROOF_EVIDENCE_KEYS = (
    "proof_evidence",
    "harness_evidence",
    "proof_artifacts",
    "execution_evidence",
    "proof_transcript",
    "harness_command",
    "test_transcript",
    "capture_artifact",
    "candidate_proof_path",
    "poc_path",
    "pass_evidence_lines",
)
BLOCKER_KEYS = (
    "blockers",
    "promotion_blockers",
    "proof_blockers",
    "terminal_blockers",
    "required_unblockers",
    "execution_blockers",
)
READY_STATUS_KEYS = (
    "status",
    "status_after_ew",
    "proof_plan_status",
    "proof_plan_readiness",
    "manual_proof_plan_status",
)
ADVISORY_TEXT_KEYS = (
    "candidate_artifact_kind",
    "evidence_class",
    "evidence_source",
    "match_method",
    "promotion_review_reason",
    "proof_claim",
    "proof_status",
    "record_kind",
    "source_kind",
    "source_reasons",
    "tags",
)
ADVISORY_MARKER_RE = re.compile(
    r"\b(advisory[-_ ]?only|reference[-_ ]?only|informational[-_ ]?only|"
    r"taxonomy[-_ ]?only|synthetic[-_ ]?taxonomy|precedent[-_ ]?only|"
    r"no[-_ ]?proof|not[-_ ]?proof)\b",
    re.IGNORECASE,
)
PLACEHOLDER_RE = re.compile(
    r"^(?:n/?a|none|null|unknown|todo|tbd|placeholder|conceptual|"
    r"hypothetical|pattern|sample)(?::|$)",
    re.IGNORECASE,
)
SOURCE_FILE_RE = re.compile(
    r"\.(?:sol|vy|rs|go|move|cairo|ts|tsx|js|jsx|py|java|kt|c|cc|cpp|h|hpp)"
    r"(?::\d+)?(?:-\d+)?$",
    re.IGNORECASE,
)
PROOFISH_PATH_RE = re.compile(
    r"(^|/)(?:poc|pocs|poc-tests|proof|proofs|harness|harnesses|test|tests|"
    r"differential_fuzz|verification_runs)(?:/|$)|"
    r"(?:_test\.go|\.t\.sol|run_stdout|transcript|execution|forge|foundry|replay)",
    re.IGNORECASE,
)


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def read_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"[live-topology-manual-proof-plan] cannot read {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise SystemExit(f"[live-topology-manual-proof-plan] expected object JSON: {path}")
    return payload


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def shell_join(parts: list[str]) -> str:
    return " ".join(shlex.quote(str(part)) for part in parts)


def values_from(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    if isinstance(value, set):
        return list(value)
    return [value]


def is_placeholder(value: Any) -> bool:
    raw = str(value or "").strip()
    if not raw:
        return True
    return raw.startswith("<") or raw.endswith(">") or bool(PLACEHOLDER_RE.search(raw))


def is_trueish(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    return str(value or "").strip().lower() in {
        "1",
        "true",
        "yes",
        "y",
        "on",
        "advisory",
        "advisory_only",
        "advisory-only",
    }


def text_values(value: Any) -> list[str]:
    out: list[str] = []

    def add(item: Any) -> None:
        if isinstance(item, str):
            text = item.strip()
            if text:
                out.append(text)
        elif isinstance(item, dict):
            for key in ("path", "file", "source_ref", "source", "ref", "value", "command", "line"):
                raw = item.get(key)
                if isinstance(raw, str) and raw.strip():
                    out.append(raw.strip())
            for raw in item.values():
                if isinstance(raw, (list, tuple, set, dict)):
                    out.extend(text_values(raw))
        elif isinstance(item, (list, tuple, set)):
            for nested in item:
                add(nested)
        elif item is not None:
            text = str(item).strip()
            if text:
                out.append(text)

    add(value)
    return list(dict.fromkeys(out))


def has_concrete_value(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, dict):
        return any(has_concrete_value(item) for item in value.values())
    if isinstance(value, (list, tuple, set)):
        return any(has_concrete_value(item) for item in value)
    return not is_placeholder(value)


def has_any_keyed_evidence(row: dict[str, Any], keys: tuple[str, ...]) -> bool:
    return any(has_concrete_value(row.get(key)) for key in keys)


def nested_source_refs(value: Any) -> list[str]:
    refs: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            if key in SOURCE_REF_KEYS:
                refs.extend(str(ref).strip() for ref in values_from(item) if not is_placeholder(ref))
            else:
                refs.extend(nested_source_refs(item))
    elif isinstance(value, (list, tuple, set)):
        for item in value:
            refs.extend(nested_source_refs(item))
    return refs


def collect_source_refs(row: dict[str, Any]) -> list[str]:
    refs: list[str] = []
    for key in SOURCE_REF_KEYS:
        for item in values_from(row.get(key)):
            if isinstance(item, dict):
                refs.extend(nested_source_refs(item))
                for nested_key in ("path", "file", "source_ref", "source", "ref", "value"):
                    nested = item.get(nested_key)
                    if not is_placeholder(nested):
                        refs.append(str(nested).strip())
            elif not is_placeholder(item):
                refs.append(str(item).strip())
    for key in TOPOLOGY_EVIDENCE_KEYS + PROOF_EVIDENCE_KEYS:
        refs.extend(nested_source_refs(row.get(key)))
    return list(dict.fromkeys(refs))


def parse_source_ref(ref: str) -> tuple[str, int | None]:
    raw = ref.split("#", 1)[0].strip()
    if raw.startswith("file://"):
        raw = raw[len("file://") :]
    for prefix in ("workspace:", "file:", "path:"):
        if raw.lower().startswith(prefix):
            raw = raw[len(prefix) :].strip()
    line: int | None = None
    path_part = raw
    if ":" in raw:
        maybe_path, maybe_line = raw.rsplit(":", 1)
        clean_line = maybe_line.strip().lstrip("Ll")
        range_match = re.match(r"^(\d+)(?:-[Ll]?\d+)?$", clean_line)
        if range_match:
            path_part = maybe_path
            line = int(range_match.group(1))
    return path_part.strip(), line


def source_ref_state(workspace: Path, ref: str) -> tuple[bool, str]:
    path_part, line = parse_source_ref(ref)
    if not path_part or "://" in path_part:
        return False, "not_workspace_source_ref"
    if not SOURCE_FILE_RE.search(path_part):
        return False, "not_protocol_source_ref"
    if PROOFISH_PATH_RE.search(path_part):
        return False, "proof_or_harness_ref_not_source"
    path = Path(path_part).expanduser()
    if not path.is_absolute():
        path = workspace / path
    resolved = path.resolve()
    try:
        resolved.relative_to(workspace)
    except ValueError:
        return False, "outside_workspace"
    if not resolved.is_file():
        return False, "missing_file"
    if line is not None:
        try:
            line_count = len(resolved.read_text(encoding="utf-8", errors="replace").splitlines())
        except OSError:
            return False, "unreadable_file"
        if line < 1 or line > line_count:
            return False, "line_out_of_range"
    return True, "ok"


def current_workspace_source_refs(workspace: Path, row: dict[str, Any]) -> tuple[list[str], list[str]]:
    valid: list[str] = []
    errors: list[str] = []
    for ref in collect_source_refs(row):
        ok, reason = source_ref_state(workspace, ref)
        if ok:
            valid.append(ref)
        else:
            errors.append(f"{ref}:{reason}")
    return list(dict.fromkeys(valid)), list(dict.fromkeys(errors))


def row_blockers(row: dict[str, Any]) -> list[str]:
    blockers: list[str] = []
    for key in BLOCKER_KEYS:
        for item in text_values(row.get(key)):
            if not is_placeholder(item):
                blockers.append(item)
    for key in ("status", "status_after_ew", "address_resolution_status", "proof_status", "promotion_review_status"):
        raw = str(row.get(key) or "").strip()
        lowered = raw.lower()
        if raw and ("blocked" in lowered or lowered.startswith("unresolved")):
            blockers.append(f"{key}:{raw}")
    return list(dict.fromkeys(blockers))


def has_advisory_only_marker(row: dict[str, Any]) -> bool:
    if is_trueish(row.get("advisory_only")):
        return True
    for key in ADVISORY_TEXT_KEYS + PROOF_EVIDENCE_KEYS:
        for text in text_values(row.get(key)):
            if ADVISORY_MARKER_RE.search(text):
                return True
    return False


def marked_proof_plan_ready(row: dict[str, Any]) -> bool:
    if row.get("proof_plan_ready") is True:
        return True
    for key in READY_STATUS_KEYS:
        normalized = str(row.get(key) or "").strip().lower().replace("_", " ").replace("-", " ")
        if "proof plan ready" in normalized:
            return True
        if key in {"proof_plan_status", "proof_plan_readiness", "manual_proof_plan_status"} and normalized == "ready":
            return True
    return False


def row_proof_plan_evaluation(workspace: Path, row: dict[str, Any]) -> dict[str, Any]:
    refs = collect_source_refs(row)
    valid_refs, ref_errors = current_workspace_source_refs(workspace, row)
    topology_present = has_any_keyed_evidence(row, TOPOLOGY_EVIDENCE_KEYS)
    proof_present = has_any_keyed_evidence(row, PROOF_EVIDENCE_KEYS)
    blockers = row_blockers(row)
    advisory_only = has_advisory_only_marker(row)
    marked_ready = marked_proof_plan_ready(row)

    reasons: list[str] = []
    if not valid_refs:
        reasons.append("stale_source_refs" if refs else "missing_source_refs")
    if not topology_present:
        reasons.append("missing_topology_evidence")
    if not proof_present:
        reasons.append("missing_proof_evidence")
    if blockers:
        reasons.append("blocker_present")
    if advisory_only:
        reasons.append("advisory_only")
    if not marked_ready:
        reasons.append("not_marked_proof_plan_ready")

    proof_plan_ready = marked_ready and not reasons
    return {
        "row_id": str(row.get("row_id") or row.get("id") or "").strip(),
        "requirement_id": row.get("requirement_id"),
        "proof_pair_id": str(row.get("proof_pair_id") or row.get("pair_id") or "").strip(),
        "contract": str(row.get("contract") or "UNKNOWN").strip() or "UNKNOWN",
        "network": str(row.get("network") or "mainnet").strip() or "mainnet",
        "marked_proof_plan_ready": marked_ready,
        "proof_plan_ready": proof_plan_ready,
        "readiness_state": "proof_plan_ready" if proof_plan_ready else "proof_plan_not_ready",
        "non_ready_reasons": list(dict.fromkeys(reasons)),
        "source_refs": refs,
        "valid_current_workspace_source_refs": valid_refs,
        "source_ref_errors": ref_errors,
        "topology_evidence_present": topology_present,
        "concrete_proof_or_harness_evidence_present": proof_present,
        "blockers": blockers,
        "advisory_only_marker": advisory_only,
    }


def rpc_env_var(network: str) -> str:
    return {
        "mainnet": "MAINNET_RPC_URL",
        "polygon": "POLYGON_RPC_URL",
        "arbitrum": "ARBITRUM_RPC_URL",
        "optimism": "OPTIMISM_RPC_URL",
        "base": "BASE_RPC_URL",
    }.get(network.lower(), f"{network.upper()}_RPC_URL")


def live_state_command(workspace: Path, row: dict[str, Any], *, block_placeholder: str) -> str:
    row_id = str(row.get("row_id") or row.get("id") or "").strip()
    contract = str(row.get("contract") or "UNKNOWN").strip() or "UNKNOWN"
    network = str(row.get("network") or "mainnet").strip() or "mainnet"
    pair_id = str(row.get("proof_pair_id") or row.get("pair_id") or "").strip()
    call = str(row.get("call") or "owner()").strip() or "owner()"
    expect = str(row.get("expect") or "<expected-value>").strip() or "<expected-value>"
    parts = [
        "python3",
        "tools/live-state-checker.py",
        "--workspace",
        str(workspace),
        "--address",
        f"<resolved-{contract}-address>",
        "--network",
        network,
        "--block",
        block_placeholder,
        "--call",
        call,
        "--expect",
        expect,
        "--save-workspace-proof",
        row_id,
        "--contract-name",
        contract,
        "--title",
        f"{row_id} {row.get('requirement_role') or 'topology-relation'}",
        "--evidence-class",
        "topology-relation",
        "--json",
    ]
    if pair_id:
        parts.extend(["--pair-id", pair_id, "--proof-pair-id", pair_id])
    return shell_join(parts)


def import_command(workspace: Path, row_ids: list[str]) -> str:
    parts = [
        "python3",
        "tools/live-check-runner.py",
        str(workspace),
        "--import-manual-proofs",
    ]
    for row_id in row_ids:
        parts.extend(["--manual-proof-id", row_id])
    parts.extend(
        [
            "--out-json",
            str(workspace / "live_topology_checks.json"),
            "--out-md",
            str(workspace / "LIVE_TOPOLOGY.md"),
        ]
    )
    return shell_join(parts)


def executor_command(workspace: Path) -> str:
    return shell_join(
        [
            "python3",
            "tools/live-topology-proof-executor.py",
            "--workspace",
            str(workspace),
            "--requirements",
            str(workspace / ".auditooor" / "live_topology_proof_requirements.json"),
            "--live-topology",
            str(workspace / "live_topology_checks.json"),
            "--out-json",
            str(workspace / ".auditooor" / "live_topology_proof_executor_fd.json"),
            "--out-md",
            str(workspace / ".auditooor" / "live_topology_proof_executor_fd.md"),
            "--demo-fixture",
        ]
    )


def row_template(workspace: Path, row: dict[str, Any], *, block_placeholder: str) -> dict[str, Any]:
    row_id = str(row.get("row_id") or row.get("id") or "").strip()
    network = str(row.get("network") or "mainnet").strip() or "mainnet"
    contract = str(row.get("contract") or "UNKNOWN").strip() or "UNKNOWN"
    pair_id = str(row.get("proof_pair_id") or row.get("pair_id") or "").strip()
    return {
        "schema": "auditooor.live_topology_manual_proof_template.v1",
        "workspace": str(workspace),
        "row_id": row_id,
        "requirement_id": row.get("requirement_id"),
        "proof_pair_id": pair_id,
        "contract": contract,
        "network": network,
        "rpc_env_var": rpc_env_var(network),
        "required_same_block": block_placeholder,
        "required_address": f"<resolved-{contract}-address>",
        "call": row.get("call") or "owner()",
        "expect": row.get("expect") or "<expected-value>",
        "evidence_class": "topology-relation",
        "submission_posture": "NOT_SUBMIT_READY",
        "promotion_allowed": False,
        "status": "template_not_executed",
        "must_not_count_as_proof_until": [
            "live-state-checker writes a real manual_proofs/<row_id>.json",
            "live-check-runner imports the exact manual proof row ids",
            "live-topology-proof-executor validates the exact same-block proof pair",
        ],
        "capture_command": live_state_command(workspace, row, block_placeholder=block_placeholder),
    }


def build_payload(workspace: Path, source: dict[str, Any], *, template_dir: Path, write_templates: bool) -> dict[str, Any]:
    rows = [row for row in source.get("rows") or [] if isinstance(row, dict)]
    requirements = [row for row in source.get("requirements") or [] if isinstance(row, dict)]
    row_readiness = [row_proof_plan_evaluation(workspace, row) for row in rows]
    readiness_by_row_id = {item["row_id"]: item for item in row_readiness if item["row_id"]}
    ready_row_ids = [item["row_id"] for item in row_readiness if item["proof_plan_ready"]]
    non_ready_rows = [item for item in row_readiness if not item["proof_plan_ready"]]
    by_pair: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        pair_id = str(row.get("proof_pair_id") or row.get("pair_id") or "").strip()
        if pair_id:
            by_pair[pair_id].append(row)

    pair_items: list[dict[str, Any]] = []
    template_paths: list[str] = []
    status_counts = Counter(str(row.get("status_after_ew") or row.get("status") or "unknown") for row in rows)
    address_counts = Counter(str(row.get("address_resolution_status") or "unknown") for row in rows)
    network_counts = Counter(str(row.get("network") or "mainnet") for row in rows)
    terminal_blocker_counts: Counter[str] = Counter()
    non_ready_reason_counts: Counter[str] = Counter(
        reason for item in non_ready_rows for reason in item.get("non_ready_reasons", [])
    )

    for pair_id, pair_rows in sorted(by_pair.items()):
        row_ids = [str(row.get("row_id") or row.get("id") or "").strip() for row in pair_rows]
        row_ids = [row_id for row_id in row_ids if row_id]
        pair_readiness = [readiness_by_row_id.get(row_id) for row_id in row_ids]
        pair_readiness = [item for item in pair_readiness if item is not None]
        pair_proof_plan_ready = bool(pair_readiness) and all(item["proof_plan_ready"] for item in pair_readiness)
        requirement_ids = sorted({str(row.get("requirement_id") or "").strip() for row in pair_rows if row.get("requirement_id")})
        block_placeholder = f"<same-block-for-{requirement_ids[0] if requirement_ids else pair_id}>"
        blockers = []
        for row in pair_rows:
            row_id = str(row.get("row_id") or row.get("id") or "").strip()
            contract = str(row.get("contract") or "UNKNOWN").strip() or "UNKNOWN"
            readiness = readiness_by_row_id.get(row_id, {})
            if str(row.get("address_resolution_status") or "").startswith("unresolved") or str(row.get("status_after_ew") or "") == "blocked_unresolved_address":
                blockers.append(f"address_unresolved:{row_id}:{contract}")
            if not readiness.get("concrete_proof_or_harness_evidence_present"):
                blockers.append(f"manual_proof_missing:{row_id}")
            if not readiness.get("proof_plan_ready"):
                reasons = ",".join(readiness.get("non_ready_reasons") or ["unknown"])
                blockers.append(f"proof_plan_not_ready:{row_id}:{reasons}")
        blockers.append(f"same_block_unpinned:{pair_id}")
        if len(row_ids) < 2:
            blockers.append(f"proof_pair_incomplete:{pair_id}")
        for blocker in blockers:
            terminal_blocker_counts[blocker.split(":", 1)[0]] += 1

        templates = []
        for row in pair_rows:
            template = row_template(workspace, row, block_placeholder=block_placeholder)
            templates.append(template)
            if write_templates:
                path = template_dir / f"{template['row_id']}.json"
                write_json(path, template)
                template_paths.append(str(path))

        pair_items.append(
            {
                "proof_pair_id": pair_id,
                "requirement_ids": requirement_ids,
                "row_ids": row_ids,
                "contracts": sorted({str(row.get("contract") or "UNKNOWN") for row in pair_rows}),
                "networks": sorted({str(row.get("network") or "mainnet") for row in pair_rows}),
                "template_paths": [str(template_dir / f"{template['row_id']}.json") for template in templates],
                "terminal_blockers": sorted(set(blockers)),
                "row_readiness": pair_readiness,
                "proof_plan_ready": pair_proof_plan_ready,
                "capture_commands": [template["capture_command"] for template in templates],
                "import_command_after_capture": import_command(workspace, row_ids),
                "executor_command_after_import": executor_command(workspace),
                "closure_candidate": False,
                "submission_posture": "NOT_SUBMIT_READY",
                "promotion_allowed": False,
            }
        )

    return {
        "schema": SCHEMA,
        "workspace": str(workspace),
        "generated_at": now_iso(),
        "source_artifact": str(workspace / DEFAULT_INPUT),
        "advisory_only": True,
        "promotion_allowed": False,
        "submission_posture": "NOT_SUBMIT_READY",
        "coverage_claim": "manual_proof_capture_plan_only_no_live_execution",
        "before_counts": {
            "source_rows": len(rows),
            "source_requirements": len(requirements),
            "source_proof_pairs": len(by_pair),
            "source_closed_rows": len(source.get("closed_rows") or []),
            "source_closed_requirements": len(source.get("closed_requirements") or []),
        },
        "after_counts": {
            "manual_proof_templates": len(rows),
            "proof_pair_capture_plans": len(pair_items),
            "proof_plan_ready_rows": len(ready_row_ids),
            "proof_plan_non_ready_rows": len(non_ready_rows),
            "proof_plan_ready_pairs": sum(1 for item in pair_items if item["proof_plan_ready"]),
            "closure_candidates": 0,
            "terminal_proof_pairs": len(pair_items),
            "templates_written": len(template_paths),
        },
        "status_counts": dict(sorted(status_counts.items())),
        "address_resolution_counts": dict(sorted(address_counts.items())),
        "network_counts": dict(sorted(network_counts.items())),
        "terminal_blocker_counts": dict(sorted(terminal_blocker_counts.items())),
        "non_ready_reason_counts": dict(sorted(non_ready_reason_counts.items())),
        "row_readiness": row_readiness,
        "proof_plan_ready_row_ids": ready_row_ids,
        "proof_plan_non_ready_rows": non_ready_rows,
        "template_dir": str(template_dir),
        "template_paths": template_paths,
        "proof_pairs": pair_items,
        "next_commands": [
            "Fill resolved addresses and one shared block into each row capture command.",
            f"Run the per-row live-state-checker commands from {template_dir}.",
            "Import each exact proof pair with its import_command_after_capture.",
            executor_command(workspace),
        ],
        "why_no_closure": (
            "FD did not collect live RPC evidence. Rows remain blocked until real resolved "
            "addresses, expected values, manual_proofs JSON, and one shared block are present."
        ),
    }


def render_markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# Live Topology Manual Proof Plan FD",
        "",
        "Operator-ready capture templates for unresolved same-block topology proof pairs.",
        "This is not live proof and is not submission-ready evidence.",
        "",
        f"- source rows: `{payload['before_counts']['source_rows']}`",
        f"- proof-pair plans: `{payload['after_counts']['proof_pair_capture_plans']}`",
        f"- templates written: `{payload['after_counts']['templates_written']}`",
        f"- proof-plan-ready rows: `{payload['after_counts']['proof_plan_ready_rows']}`",
        f"- non-ready rows: `{payload['after_counts']['proof_plan_non_ready_rows']}`",
        f"- closure candidates: `{payload['after_counts']['closure_candidates']}`",
        f"- submission posture: `{payload['submission_posture']}`",
        "",
        "## Counts",
        "",
        f"- status counts: `{json.dumps(payload['status_counts'], sort_keys=True)}`",
        f"- address-resolution counts: `{json.dumps(payload['address_resolution_counts'], sort_keys=True)}`",
        f"- terminal blocker counts: `{json.dumps(payload['terminal_blocker_counts'], sort_keys=True)}`",
        f"- non-ready reason counts: `{json.dumps(payload['non_ready_reason_counts'], sort_keys=True)}`",
        "",
        "## Top Proof Pairs",
        "",
        "| Pair | Rows | Ready | Contracts | Non-ready reasons | First command |",
        "|---|---:|---|---|---|---|",
    ]
    for item in payload["proof_pairs"][:25]:
        first = (item.get("capture_commands") or [""])[0]
        reasons = sorted(
            {
                reason
                for row in item.get("row_readiness") or []
                for reason in row.get("non_ready_reasons", [])
            }
        )
        lines.append(
            f"| `{item['proof_pair_id']}` | {len(item['row_ids'])} | "
            f"`{item.get('proof_plan_ready')}` | `{', '.join(item['contracts'])}` | "
            f"`{', '.join(reasons) if reasons else 'none'}` | `{first}` |"
        )
    lines.extend(["", "## Non-ready Rows", "", "| Row | Reasons |", "|---|---|"])
    for item in payload["proof_plan_non_ready_rows"][:50]:
        reasons = ", ".join(item.get("non_ready_reasons") or ["unknown"])
        lines.append(f"| `{item['row_id']}` | `{reasons}` |")
    lines.extend(["", "## Why No Closure", "", payload["why_no_closure"], ""])
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--input", type=Path)
    parser.add_argument("--out-json", type=Path)
    parser.add_argument("--out-md", type=Path)
    parser.add_argument("--template-dir", type=Path)
    parser.add_argument("--no-write-templates", action="store_true")
    parser.add_argument("--print-json", action="store_true")
    args = parser.parse_args()

    workspace = args.workspace.expanduser().resolve()
    if not workspace.is_dir():
        print(f"[live-topology-manual-proof-plan] workspace not found: {workspace}")
        return 2
    input_path = (args.input or workspace / DEFAULT_INPUT).expanduser().resolve()
    out_json = args.out_json or workspace / DEFAULT_OUT
    out_md = args.out_md or workspace / DEFAULT_OUT_MD
    template_dir = args.template_dir or workspace / DEFAULT_TEMPLATE_DIR

    payload = build_payload(
        workspace,
        read_json(input_path),
        template_dir=template_dir,
        write_templates=not args.no_write_templates,
    )
    write_json(out_json, payload)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_md.write_text(render_markdown(payload), encoding="utf-8")
    if args.print_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    print(
        "[live-topology-manual-proof-plan] OK "
        f"templates={payload['after_counts']['templates_written']} "
        f"pairs={payload['after_counts']['proof_pair_capture_plans']} json={out_json}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
