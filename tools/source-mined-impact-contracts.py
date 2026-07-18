#!/usr/bin/env python3
"""Create fail-closed impact contracts for source-mined exploit-queue rows.

Source mining is useful only if its surviving rows become first-class proof
objects. This tool consumes ``exploit_queue.source_mined.json`` and emits
``impact_contracts.json`` rows that bind each candidate to:

- one exact listed-impact sentence when it can be matched from SEVERITY.md;
- attacker, victim, and asset roles from the queue row;
- OOS traps and a stop/negative-control condition; and
- a stable ``impact_contract_id`` that downstream harness tools can join.

The output is intentionally not submission-ready. It sets
``listed_impact_proven=false`` and ``promotion_allowed=false`` because source
mining and impact-row mapping are not exploit proof.
"""

from __future__ import annotations

import argparse
import datetime as dt
import importlib.util
import json
import re
import sys
from pathlib import Path
from typing import Any

TOOLS_DIR = Path(__file__).resolve().parent
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

from lib.chain_d4 import has_chain_attacker_control_evidence  # noqa: E402

_TYPED_ENVELOPE_PATH = TOOLS_DIR / "zero-day-proof-envelope-verify.py"
_TYPED_ENVELOPE_MOD: Any | None = None


def _load_typed_envelope_tool() -> Any:
    global _TYPED_ENVELOPE_MOD
    if _TYPED_ENVELOPE_MOD is not None:
        return _TYPED_ENVELOPE_MOD
    spec = importlib.util.spec_from_file_location("auditooor_impact_typed_envelope", _TYPED_ENVELOPE_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("typed_proof_envelope_validator_unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    _TYPED_ENVELOPE_MOD = module
    return module


SCHEMA = "auditooor.source_mined_impact_contracts.v1"
IMPACT_CONTRACTS_SCHEMA = "auditooor.pr560.impact_contracts.v1"
PROOF_BOUNDARY = (
    "Source-mined impact contracts bind proof work to a concrete impact row and actors. "
    "They do not prove listed impact, clear OOS/dupe risk, or make a report submission-ready."
)
MISSING_VALUES = {"", "unknown", "n/a", "na", "missing", "todo", "not_assessed", "none", "null"}
TERMINAL_STATES = {
    "killed",
    "disproved",
    "false_positive",
    "not_candidate",
    "not_a_bug",
    "duplicate",
    "oos",
    "out_of_scope",
    "rejected",
    "terminal",
    "terminal_no_submission",
    "negative",
}
SEVERITY_ORDER = ("Critical", "High", "Medium", "Low", "Informational")

# HACKERMAN_V3 opposed-trace proof gate.
#
# Direct loss cannot be claimed from an unopposed trace. When the selected
# impact is a HIGH+ fund-loss / freeze / insolvency / theft class, the contract
# must enumerate every protocol-owned defense that is supposed to race, rescue,
# liquidate, slash, refund, pause, challenge, overwrite, or finalize against the
# attacker path - and prove the attacker beats every one of them. A proof that
# only shows attacker-vs-empty-world (no protocol defenses in the trace) cannot
# carry a Direct Loss claim. Empirical anchor: Spark LEAD1 - the chain watcher
# accepting an unrelated exit_txid was a real bug, but the proof omitted Spark's
# lower-timelock connector refund, post-claim lower-timelock refund, and
# watchtower paths, so the Direct Loss impact was unproven.
#
# HIGH+ impact keyword set keyed off the selected impact sentence + severity
# tier. Reuses the same loss/freeze/insolvency/theft vocabulary the impact
# scorer already groups on (see ``_impact_score``).
HIGH_PLUS_SEVERITIES = {"critical", "high"}
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
# A typed opt-out reason vocabulary. The opt-out is NOT a silent bypass: the
# queue row must carry an explicit ``opposed_trace_opt_out`` object (or string)
# whose reason matches one of these typed categories. Anything else is ignored
# and the gate stays armed.
OPPOSED_TRACE_OPT_OUT_REASONS = {
    "no_protocol_defenses_exist",
    "impact_is_not_fund_loss",
    "defense_is_out_of_scope_dependency",
    "operator_reviewed_no_opposed_path",
}
# Protocol-owned defenses that are supposed to neutralize an attacker path.
# Each verb maps to the canonical defense family name surfaced in the contract.
PROTOCOL_DEFENSE_VERBS = {
    "race": "race-the-attacker defense",
    "rescue": "rescue path",
    "liquidat": "liquidation path",
    "slash": "slashing path",
    "refund": "refund path",
    "pause": "pause / circuit-breaker",
    "challenge": "challenge / fraud-proof window",
    "dispute": "dispute window",
    "overwrite": "state-overwrite defense",
    "finaliz": "finalization guard",
    "timelock": "timelock defense",
    "watchtower": "watchtower path",
    "watch_chain": "chain-watcher path",
    "chain watcher": "chain-watcher path",
    "guardian": "guardian intervention path",
    "cancel": "cancellation path",
    "revert": "revert / rollback guard",
    "freeze guard": "freeze guard",
    "circuit breaker": "circuit-breaker",
    "fraud proof": "fraud-proof path",
    "exit game": "exit-game challenge path",
}
REACHABILITY_FIELD_KEYS = (
    "reachability_trace",
    "production_reachability",
    "dispatch_site",
    "registration_site",
    "entrypoint",
    "entry_point",
    "production_entrypoint",
    "reachable_from",
    "call_site",
    "callsite",
    "reachability_refs",
    "reachability_citations",
)
SOURCE_REF_RE = re.compile(
    r"(?P<path>[A-Za-z0-9_./~@%+,\-]+?\.(?:sol|vy|go|rs|move|cairo|ts|tsx|js|jsx|py|md))"
    r"(?:(?::|#L)(?P<line>\d+))"
)
SOURCE_REF_DICT_PATH_KEYS = ("path", "source_path", "source_file", "file", "target_file")
SOURCE_REF_DICT_LINE_KEYS = ("line", "line_start", "start_line", "lineno")
STATE_IMPACT_LINKAGE_KEYS = (
    "state_impact_linkage",
    "state_impact_trace",
    "impact_linkage",
    "state_transition",
    "state_delta",
    "impact_state_delta",
    "before_after_state",
    "before_after_assertion",
    "balance_delta",
    "asset_delta",
    "victim_delta",
    "invariant_violation",
    "impact_assertion",
    "loss_assertion",
    "funds_flow",
    "exploit_effect",
    "post_state",
    "pre_state",
    "bridge_claims",
    "produces_state",
    "requires_state",
    "unifying_state",
)


def _utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _read_json(path: Path) -> Any | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _norm(value: Any, *, limit: int = 700) -> str:
    if isinstance(value, (list, tuple, set)):
        value = "; ".join(_norm(item, limit=limit) for item in value if _norm(item, limit=limit))
    elif isinstance(value, dict):
        value = json.dumps(value, sort_keys=True)
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    return text[:limit]


def _present(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return True
    if isinstance(value, (list, tuple, set)):
        return any(_present(item) for item in value)
    if isinstance(value, dict):
        return bool(value)
    text = _norm(value).lower()
    return bool(text) and text not in MISSING_VALUES


def _first(row: dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = row.get(key)
        if _present(value):
            return _norm(value)
    return ""


def _slug(value: str) -> str:
    slug = re.sub(r"[^a-z0-9_.-]+", "-", value.strip().lower()).strip("-")
    return slug or "candidate"


def _candidate_id(row: dict[str, Any]) -> str:
    return _first(row, "lead_id", "candidate_id", "row_id", "id", "title") or "candidate"


def _severity(row: dict[str, Any]) -> str:
    raw = _first(row, "likely_severity", "claimed_severity", "severity", "severity_tier").lower()
    for severity in SEVERITY_ORDER:
        if severity.lower() in raw:
            return severity
    return "Unknown"


def _rows_from_queue(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, dict):
        if "zero_day_proof_admission" in payload:
            envelope = _load_typed_envelope_tool().build_envelope(payload)
            if payload.get("entries") not in (None, []):
                raise ValueError("typed_proof_envelope_legacy_entries_present")
            by_lead = {entry["lead_id"]: entry for entry in envelope["entries"]}
            rows = payload.get("queue")
            if not isinstance(rows, list):
                return []
            selected: list[dict[str, Any]] = []
            for row in rows:
                if not isinstance(row, dict):
                    continue
                lead_id = _candidate_id(row)
                if lead_id not in by_lead:
                    raise ValueError("typed_proof_envelope_row_missing")
                typed = dict(row)
                typed["zero_day_proof_envelope"] = by_lead[lead_id]
                selected.append(typed)
            return selected
        for key in ("queue", "rows", "candidates", "leads", "items"):
            rows = payload.get(key)
            if isinstance(rows, list):
                return [row for row in rows if isinstance(row, dict)]
    if isinstance(payload, list):
        return [row for row in payload if isinstance(row, dict)]
    return []


def _is_terminal(row: dict[str, Any]) -> bool:
    if row.get("row_is_advisory") is True or row.get("advisory_only") is True:
        return True
    text = " ".join(
        _first(row, key)
        for key in ("proof_status", "quality_gate_status", "status", "scope_status", "verdict")
    ).lower()
    return any(state in text for state in TERMINAL_STATES)


def _impact_contract_rows(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, dict):
        for key in ("contracts", "rows", "impact_contracts"):
            rows = payload.get(key)
            if isinstance(rows, list):
                return [row for row in rows if isinstance(row, dict)]
    if isinstance(payload, list):
        return [row for row in payload if isinstance(row, dict)]
    return []


def _load_existing_contracts(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    return _impact_contract_rows(_read_json(path))


def _severity_from_heading(line: str, current: str) -> str:
    lowered = line.lower()
    for severity in SEVERITY_ORDER:
        if severity.lower() in lowered:
            return severity
    return current


# Heading keywords that mark an OOS / exclusion / caps block.  When a heading
# matches any of these, ``parse_severity_impacts`` stops collecting bullet
# items (sets ``current = ""``) so that OOS/exclusion sentences are never
# added to any severity's listed-impact pool.
_OOS_HEADING_RE = re.compile(
    r"(?:exclusion|out.of.scope|oos|caps?\s+and|not.eligible|not.covered"
    r"|ineligible|disqualified|explicitly.excluded|scope.exclusion)",
    re.IGNORECASE,
)


def parse_severity_impacts(workspace: Path, severity_path: Path | None = None) -> dict[str, list[str]]:
    path = severity_path or workspace / "SEVERITY.md"
    impacts: dict[str, list[str]] = {severity: [] for severity in SEVERITY_ORDER}
    if not path.is_file():
        return impacts
    current = ""
    for raw_line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("#"):
            # First check if the heading marks an OOS / exclusion block.  If so,
            # clear ``current`` so that bullets inside the block are not added to
            # any severity's impact list.  This prevents exclusion sentences like
            # "Imported-contract vulnerabilities are out of scope." from being
            # returned as candidate ``selected_impact`` values.
            if _OOS_HEADING_RE.search(line):
                current = ""
            else:
                current = _severity_from_heading(line, current)
            continue
        if not current:
            continue
        match = re.match(r"^[-*]\s+(?:\[[ xX]\]\s+)?(.+?)\s*$", line)
        if not match:
            continue
        item = re.sub(r"\s+", " ", match.group(1)).strip().strip("`")
        if len(item) < 4:
            continue
        if item not in impacts[current]:
            impacts[current].append(item)
    return impacts


def _impact_keywords(row: dict[str, Any]) -> str:
    return " ".join(
        _norm(row.get(key))
        for key in (
            "title",
            "impact_path",
            "impact_probe",
            "asset_at_risk",
            "attack_class",
            "root_cause_hypothesis",
            "recommended_next_step",
            "likely_triager_objection",
        )
        if _norm(row.get(key))
    ).lower()


def _impact_score(candidate: str, hay: str) -> int:
    text = candidate.lower()
    score = 0
    groups = (
        (("theft", "steal", "drain", "loss of funds", "user funds", "in-motion", "at-rest"), 40),
        (("freeze", "frozen", "halt", "liveness", "unable to operate", "shutdown", "dos"), 35),
        (("insolvency", "undercollateral", "bad debt"), 35),
        (("governance", "voting", "vote"), 30),
        (("yield", "reward"), 20),
        (("block stuffing", "gas"), 20),
        (("grief", "griefing"), 18),
    )
    for tokens, weight in groups:
        if any(token in hay for token in tokens) and any(token in text for token in tokens):
            score += weight
    for token in re.findall(r"[a-z][a-z0-9-]{3,}", hay):
        if token in text:
            score += 1
    return score


def select_impact(row: dict[str, Any], impacts: dict[str, list[str]]) -> tuple[str, bool, str]:
    severity = _severity(row)
    hay = _impact_keywords(row)
    tiers: list[str] = []
    if severity in impacts:
        tiers.append(severity)
    tiers.extend(tier for tier in SEVERITY_ORDER if tier not in tiers)
    best: tuple[int, str, str] = (0, "", "")
    for tier in tiers:
        for candidate in impacts.get(tier) or []:
            score = _impact_score(candidate, hay)
            if tier == severity and score:
                score += 5
            if score > best[0]:
                best = (score, candidate, tier)
    if best[0] > 0:
        return best[1], True, best[2]
    return _first(row, "impact_path", "impact_probe") or "", False, ""


def _list_values(*values: Any) -> list[str]:
    out: list[str] = []
    for value in values:
        if isinstance(value, list):
            candidates = value
        else:
            candidates = [value]
        for item in candidates:
            text = _norm(item, limit=260)
            if text and text.lower() not in MISSING_VALUES and text not in out:
                out.append(text)
    return out


def _oos_traps(row: dict[str, Any]) -> list[str]:
    traps = _list_values(row.get("oos_traps"), row.get("scope_traps"), row.get("likely_triager_objection"))
    text = _impact_keywords(row)
    if re.search(r"front[- ]?run|sandwich|mev|back[- ]?run", text):
        traps.append("Confirm exploit is not front-run/back-run/sandwich-only under program OOS.")
    if re.search(r"admin|owner|privileged|governance role|guardian", text):
        traps.append("Confirm attacker path is not restricted to pre-existing privileged/admin roles.")
    if re.search(r"imported|dependency|upstream|fork", text):
        traps.append("Confirm vulnerability is in in-scope source or a reachable fork-drift path, not imported-code-only.")
    if not traps:
        traps.append("Confirm scope/OOS text does not exclude this actor, asset, impact, or trigger path.")
    return list(dict.fromkeys(traps))


def _has_oos_trap_signal(row: dict[str, Any]) -> bool:
    # ``scope_status`` is a scope state (e.g. ``in_scope``), not a triager
    # objection / OOS trap. Treating it as a trap signal lets a row promote to
    # ``mapped`` carrying only the generic auto-fallback trap. The OOS-trap gate
    # must see a real row-level trap (``oos_traps`` / ``scope_traps`` /
    # ``likely_triager_objection``) or an impact-keyword that implies one.
    if any(_present(row.get(key)) for key in ("oos_traps", "scope_traps", "likely_triager_objection")):
        return True
    text = _impact_keywords(row)
    return bool(re.search(r"front[- ]?run|sandwich|mev|back[- ]?run|admin|owner|privileged|governance role|guardian|imported|dependency|upstream|fork", text))


def _negative_controls(row: dict[str, Any]) -> list[str]:
    controls = _list_values(
        row.get("negative_control"),
        row.get("negative_controls"),
        row.get("required_control"),
        row.get("falsification_requirements"),
        row.get("kill_conditions"),
    )
    if not controls:
        controls.append("Run the same proof path with the vulnerable precondition removed; expected result must not show impact.")
    return list(dict.fromkeys(controls))


def _has_explicit_negative_control(row: dict[str, Any]) -> bool:
    return any(
        _present(row.get(key))
        for key in (
            "negative_control",
            "negative_controls",
            "required_control",
            "falsification_requirements",
            "kill_conditions",
            "stop_condition",
            "clean_control",
        )
    )


def _source_ref_from_dict(value: dict[str, Any]) -> str:
    path = ""
    line = ""
    for key in SOURCE_REF_DICT_PATH_KEYS:
        candidate = _norm(value.get(key), limit=400)
        if candidate:
            path = candidate
            break
    for key in SOURCE_REF_DICT_LINE_KEYS:
        candidate = _norm(value.get(key), limit=40)
        if candidate:
            line = candidate
            break
    if path and line and not SOURCE_REF_RE.search(path):
        return f"{path}:{line}"
    return path or _norm(value, limit=400)


def _source_refs(row: dict[str, Any]) -> list[str]:
    raw = row.get("source_refs")
    items = raw if isinstance(raw, list) else [raw]
    refs: list[str] = []
    for item in items:
        if isinstance(item, dict):
            text = _source_ref_from_dict(item)
        else:
            text = _norm(item, limit=400)
        if text and text.lower() not in MISSING_VALUES and text not in refs:
            refs.append(text)
    return refs


def _path_inside_workspace(path: Path, workspace: Path) -> bool:
    try:
        resolved = path.expanduser().resolve(strict=False)
        root = workspace.expanduser().resolve(strict=False)
        return resolved == root or root in resolved.parents
    except OSError:
        return False


def _parse_source_ref(ref: str) -> tuple[str, int] | None:
    if str(ref).startswith(("http://", "https://")):
        return None
    match = SOURCE_REF_RE.search(str(ref).strip())
    if not match:
        return None
    return match.group("path"), int(match.group("line"))


def _resolve_source_ref(workspace: Path, ref: str) -> dict[str, Any]:
    parsed = _parse_source_ref(ref)
    if parsed is None:
        return {
            "ref": ref,
            "current": False,
            "reason": "source_refs_not_file_line",
            "path": "",
            "line": None,
        }
    path_text, line = parsed
    path = Path(path_text).expanduser()
    if not path.is_absolute():
        path = workspace / path
    if not _path_inside_workspace(path, workspace):
        return {
            "ref": ref,
            "current": False,
            "reason": "source_ref_outside_workspace",
            "path": str(path),
            "line": line,
        }
    try:
        resolved = path.resolve(strict=False)
        if not resolved.is_file():
            return {
                "ref": ref,
                "current": False,
                "reason": "source_ref_file_missing",
                "path": str(path),
                "line": line,
            }
        line_count = len(resolved.read_text(encoding="utf-8", errors="replace").splitlines())
        if line < 1 or line > line_count:
            return {
                "ref": ref,
                "current": False,
                "reason": "source_ref_line_missing",
                "path": str(resolved),
                "line": line,
            }
    except OSError as exc:
        return {
            "ref": ref,
            "current": False,
            "reason": f"source_ref_error:{exc.__class__.__name__}",
            "path": str(path),
            "line": line,
        }
    return {
        "ref": ref,
        "current": True,
        "reason": "current_workspace_source_ref",
        "path": str(resolved),
        "line": line,
    }


def _source_ref_status(workspace: Path, refs: list[str]) -> dict[str, Any]:
    resolved = [_resolve_source_ref(workspace, ref) for ref in refs]
    current = [item for item in resolved if item.get("current")]
    stale = [item for item in resolved if not item.get("current")]
    return {
        "raw_refs": refs,
        "resolved_refs": resolved,
        "current_refs": current,
        "stale_refs": stale,
    }


def _state_impact_linkages(row: dict[str, Any]) -> list[str]:
    values: list[Any] = []
    for key in STATE_IMPACT_LINKAGE_KEYS:
        values.append(row.get(key))
    state_evidence = row.get("state_evidence")
    if isinstance(state_evidence, dict):
        values.extend(state_evidence.get(key) for key in STATE_IMPACT_LINKAGE_KEYS)
    truth = row.get("truth_table_summary")
    if isinstance(truth, dict):
        values.extend(truth.get(key) for key in STATE_IMPACT_LINKAGE_KEYS)
    return _list_values(*values)


def _proof_relevance_fields(
    workspace: Path, row: dict[str, Any], source_refs: list[str]
) -> tuple[dict[str, Any], list[str]]:
    source_status = _source_ref_status(workspace, source_refs)
    linkages = _state_impact_linkages(row)
    reasons: list[str] = []
    if not source_refs:
        reasons.append("missing_source_refs")
    elif source_status["stale_refs"]:
        reasons.append("stale_workspace_source_refs")
        for stale in source_status["stale_refs"]:
            reason = _norm(stale.get("reason"), limit=120)
            if reason and reason not in reasons:
                reasons.append(reason)
    if not linkages:
        reasons.append("state_impact_linkage_absent")
    proof_relevant = not reasons
    fields = {
        "proof_relevance": proof_relevant,
        "proof_relevance_status": "proof_relevant" if proof_relevant else "skipped_non_proof",
        "proof_relevance_skip_reasons": reasons,
        "current_source_refs": source_status["current_refs"],
        "stale_source_refs": source_status["stale_refs"],
        "source_ref_validation": {
            "raw_refs": source_status["raw_refs"],
            "resolved_refs": source_status["resolved_refs"],
            "current_ref_count": len(source_status["current_refs"]),
            "stale_ref_count": len(source_status["stale_refs"]),
        },
        "state_impact_linkage": linkages,
    }
    return fields, reasons


def _reachability_fields(row: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key in REACHABILITY_FIELD_KEYS:
        value = row.get(key)
        if _present(value):
            out[key] = value
    return out


# A proof command is concrete only if it is a runnable command, not an empty
# string, a missing-evidence placeholder, or a "# address blocker" stub that the
# queue emits for rows whose first command is not yet known.
_PLACEHOLDER_PROOF_COMMAND_RE = re.compile(
    r"^\s*#\s*(address blocker|todo|tbd|fixme|pending)\b",
    re.IGNORECASE,
)


def _has_concrete_proof_command(value: Any) -> bool:
    text = _norm(value).strip()
    if not text or text.lower() in MISSING_VALUES:
        return False
    if _PLACEHOLDER_PROOF_COMMAND_RE.search(text):
        return False
    # A bare comment line carries no runnable command.
    if text.startswith("#"):
        return False
    return True


def _is_high_plus_impact(row: dict[str, Any], selected_impact: str, selected_tier: str) -> bool:
    """True when the contract's selected impact is a HIGH+ fund-loss class.

    Keyed off two independent signals so a row cannot dodge the gate by
    mislabelling one of them:

    - the resolved severity / selected severity tier is Critical or High; OR
    - the selected impact sentence contains a HIGH+ loss / freeze / insolvency
      / theft / unauthorized-withdrawal keyword.
    """
    severity = _severity(row).lower()
    tier = (selected_tier or "").lower()
    if severity in HIGH_PLUS_SEVERITIES or tier in HIGH_PLUS_SEVERITIES:
        return True
    hay = selected_impact.lower()
    return any(keyword in hay for keyword in HIGH_PLUS_IMPACT_KEYWORDS)


def _opposed_trace_opt_out(row: dict[str, Any]) -> tuple[bool, str]:
    """Return (opted_out, typed_reason) for the contract's opposed-trace gate.

    The opt-out is a typed reason, never a silent bypass. The queue row must
    carry ``opposed_trace_opt_out`` as either:

    - a dict with a ``reason`` field, or
    - a bare string,

    whose value matches a member of ``OPPOSED_TRACE_OPT_OUT_REASONS``. Any other
    shape (missing, empty, free-form text, unknown category) is ignored and the
    gate stays armed.
    """
    raw = row.get("opposed_trace_opt_out")
    reason = ""
    if isinstance(raw, dict):
        reason = _norm(raw.get("reason") or raw.get("category"), limit=80).lower()
    elif isinstance(raw, str):
        reason = _norm(raw, limit=80).lower()
    reason = reason.replace("-", "_").replace(" ", "_")
    if reason in OPPOSED_TRACE_OPT_OUT_REASONS:
        return True, reason
    return False, ""


def _protocol_defenses(row: dict[str, Any]) -> list[str]:
    """Enumerate protocol-owned defenses the proof must show the attacker beats.

    Two sources, unioned:

    - explicit row fields a miner / operator can populate
      (``protocol_defenses``, ``opposed_defenses``, ``protocol_owned_defenses``,
      ``defense_paths``); and
    - defense verbs discovered in the row's impact / root-cause / next-step
      keyword text (e.g. a row that mentions a ``refund`` or ``watchtower``
      path implies that defense must be in the opposed trace).
    """
    defenses = _list_values(
        row.get("protocol_defenses"),
        row.get("opposed_defenses"),
        row.get("protocol_owned_defenses"),
        row.get("defense_paths"),
        row.get("racing_defenses"),
    )
    text = _impact_keywords(row)
    for verb, family in PROTOCOL_DEFENSE_VERBS.items():
        if verb in text and family not in defenses:
            defenses.append(family)
    return list(dict.fromkeys(defenses))


def _missing_defenses(row: dict[str, Any], defenses: list[str]) -> list[str]:
    """Defenses named as required but not yet shown covered by the proof.

    A miner / operator can record which defenses are still un-traversed via
    ``missing_defenses`` / ``uncovered_defenses``. If that field is absent the
    coverage is unknown, so every enumerated defense is treated as missing
    until a proof shows otherwise.
    """
    declared = _list_values(row.get("missing_defenses"), row.get("uncovered_defenses"))
    if declared:
        return declared
    covered = _list_values(row.get("covered_defenses"), row.get("opposed_trace_covered"))
    if covered:
        covered_lower = {item.lower() for item in covered}
        return [d for d in defenses if d.lower() not in covered_lower]
    # No coverage signal at all: the opposed trace is unproven, so every
    # enumerated defense is still missing.
    return list(defenses)


def _opposed_trace_fields(
    row: dict[str, Any], selected_impact: str, selected_tier: str
) -> tuple[dict[str, Any], list[str], list[str]]:
    """Build the four opposed-trace contract fields, contract gaps, advisories.

    Returns ``(fields, gaps, advisories)`` where ``fields`` carries
    ``protocol_defenses_enumerated`` / ``opposed_trace_required`` /
    ``opposed_trace_coverage`` / ``missing_defenses`` (plus
    ``opposed_trace_opt_out_reason`` when a typed opt-out is honored).

    Tiered model (HACKERMAN_V3, codified Rule 14):

    - The opposed-trace QUESTION is asked for EVERY contract regardless of
      severity. ``protocol_defenses_enumerated`` and ``opposed_trace_coverage``
      are always computed - "attacker vs empty world" is a proof fallacy at
      any tier.
    - ENFORCEMENT is tiered. A HIGH+ contract with a missing opposed trace
      emits a hard ``gap`` (``opposed_trace_defenses_unenumerated`` /
      ``opposed_trace_coverage_missing``) which keeps the row at
      ``generated_unvalidated`` and blocks promotion to ``mapped``. A
      non-HIGH+ contract with a missing opposed trace emits an ADVISORY (in
      the returned ``advisories`` list, surfaced as ``opposed_trace_advisory``
      / ``contract_advisories``) - it does NOT block promotion, but the
      missing opposed trace stays visible to the reviewer.
    """
    high_plus = _is_high_plus_impact(row, selected_impact, selected_tier)
    opted_out, opt_out_reason = _opposed_trace_opt_out(row)
    # ``required`` records whether HIGH+ HARD enforcement applies. The question
    # itself is asked for every contract; only the enforcement tier differs.
    required = bool(high_plus) and not opted_out
    defenses = _protocol_defenses(row)
    gaps: list[str] = []
    advisories: list[str] = []

    if opted_out:
        # A typed opt-out disarms the gate entirely at every tier.
        coverage = "not_applicable"
        missing: list[str] = []
    else:
        missing = _missing_defenses(row, defenses)
        if not defenses:
            coverage = "missing"
        elif missing:
            coverage = "missing"
        else:
            coverage = "covered"

        if coverage == "missing":
            if required:
                # HIGH+: hard contract gap - keeps the row generated_unvalidated.
                gaps.append(
                    "opposed_trace_defenses_unenumerated"
                    if not defenses
                    else "opposed_trace_coverage_missing"
                )
            else:
                # Medium/Low/below-High: advisory only - the row still promotes
                # but the missing opposed trace is visible to the reviewer.
                advisories.append(
                    "opposed_trace_defenses_unenumerated"
                    if not defenses
                    else "opposed_trace_coverage_missing"
                )

    fields = {
        "protocol_defenses_enumerated": defenses,
        "opposed_trace_required": required,
        "opposed_trace_coverage": coverage,
        "missing_defenses": missing,
    }
    if opted_out:
        fields["opposed_trace_opt_out_reason"] = opt_out_reason
    return fields, gaps, advisories


def build_contract(row: dict[str, Any], impacts: dict[str, list[str]], workspace: Path) -> dict[str, Any]:
    cid = _candidate_id(row)
    selected, exact, selected_tier = select_impact(row, impacts)
    controls = _negative_controls(row)
    traps = _oos_traps(row)
    source_refs = _source_refs(row)
    proof_relevance_fields, proof_relevance_reasons = _proof_relevance_fields(workspace, row, source_refs)
    source_artifact_gaps = row.get("source_artifact_gaps") if isinstance(row.get("source_artifact_gaps"), list) else []
    attacker_actor = _first(row, "attacker_actor", "attacker_role", "attacker_control")
    victim_actor = _first(row, "victim_actor", "victim_role")
    asset_at_risk = _first(row, "asset_at_risk", "asset")
    proof_command = _first(row, "proof_command", "next_command", "harness_command", "gating_test")
    gaps: list[str] = []
    if not exact:
        gaps.append("selected_impact_not_exact_severity_row")
    # A generic D4 placeholder (partial / privileged / needs_review / unknown)
    # is not a confirmed attacker actor. Reuse the centralized chain D4
    # predicate so the contract gate cannot be bypassed by the same generic
    # placeholders the queue/source-miner/judgment gates already reject.
    attacker_actor_confirmed = bool(attacker_actor) and has_chain_attacker_control_evidence(attacker_actor)
    if not attacker_actor_confirmed:
        gaps.append("attacker_actor_inferred")
    if not victim_actor:
        gaps.append("victim_actor_inferred")
    if not asset_at_risk:
        gaps.append("asset_at_risk_inferred")
    if not _has_concrete_proof_command(proof_command):
        gaps.append("proof_command_missing")
    if not row.get("source_artifacts_complete"):
        gaps.append("source_artifacts_incomplete")
    if not source_refs:
        gaps.append("source_refs_missing")
    for reason in proof_relevance_reasons:
        if reason == "missing_source_refs":
            continue
        if reason not in gaps:
            gaps.append(reason)
    for gap in source_artifact_gaps:
        text = _norm(gap, limit=120)
        if text:
            gaps.append(f"source_artifact_gap:{text}")
    if not _has_oos_trap_signal(row):
        gaps.append("oos_traps_missing")
    if not _has_explicit_negative_control(row):
        gaps.append("negative_control_missing")

    # HACKERMAN_V3 opposed-trace proof gate (tiered). The opposed-trace
    # question is asked for EVERY contract regardless of severity. For a HIGH+
    # fund-loss / freeze / theft class the contract must enumerate every
    # protocol-owned defense and the proof must beat each one - an un-enumerated
    # or un-covered opposed trace adds a hard contract gap that keeps the row at
    # generated_unvalidated (never mapped). For a non-HIGH+ contract the missing
    # opposed trace is an ADVISORY (opposed_trace_advisory / contract_advisories)
    # - the row still promotes, but the gap stays visible to the reviewer.
    opposed_trace_fields, opposed_trace_gaps, opposed_trace_advisories = _opposed_trace_fields(
        row, selected, selected_tier
    )
    gaps.extend(opposed_trace_gaps)

    contract_advisories = list(dict.fromkeys(opposed_trace_advisories))
    status = "mapped" if not gaps else "generated_unvalidated"
    severity = _severity(row)
    contract = {
        **opposed_trace_fields,
        **proof_relevance_fields,
        **_reachability_fields(row),
        "contract_advisories": contract_advisories,
        "opposed_trace_advisory": bool(opposed_trace_advisories),
        "schema": "auditooor.source_mined_impact_contract.v1",
        "impact_contract_id": f"impact-contract-{_slug(cid)}",
        "candidate_id": cid,
        "lead_id": cid,
        "row_id": cid,
        "title": _first(row, "title") or cid,
        "attack_class": _first(row, "attack_class"),
        "severity": severity,
        "severity_tier": selected_tier or severity,
        "status": status,
        "impact_contract_status": status,
        "selected_impact": selected,
        "listed_impact_selected": selected,
        "exact_impact_row": bool(exact),
        "listed_impact_proven": False,
        "evidence_class": "source_mined_candidate_unproved",
        # Never surface a rejected D4 generic placeholder (partial / privileged
        # / needs_review / unknown) as the contract's attacker actor. If the
        # value is not confirmed evidence, the field must read the explicit
        # confirm-placeholder so a consumer does not mistake it for a real actor.
        "attacker_actor": attacker_actor if attacker_actor_confirmed else "attacker role must be confirmed",
        "victim_actor": victim_actor or "victim role must be confirmed",
        "asset_at_risk": asset_at_risk or "asset at risk must be confirmed",
        "oos_traps": traps,
        "negative_controls": controls,
        "negative_control": controls[0],
        "stop_condition": controls[0],
        "proof_command": proof_command,
        "proof_artifact": "",
        "source_refs": source_refs,
        "source_artifacts_complete": bool(row.get("source_artifacts_complete")),
        "source_artifact_gaps": source_artifact_gaps,
        "impact_contract_gaps": gaps,
        "submission_posture": "NOT_SUBMIT_READY",
        "promotion_allowed": False,
        "proof_boundary": PROOF_BOUNDARY,
        "required_manual_follow_up": [
            "Prove listed_impact_selected end-to-end before setting listed_impact_proven=true.",
            "Replace inferred actor/asset fields if source review shows a narrower production path.",
            "Keep OOS traps and negative controls in the PoC/test plan.",
        ],
    }
    typed_envelope = row.get("zero_day_proof_envelope")
    if isinstance(typed_envelope, dict):
        contract["zero_day_proof_envelope"] = typed_envelope
    return contract


def _contract_index(rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for row in rows:
        for key in ("impact_contract_id", "candidate_id", "lead_id", "row_id"):
            value = _norm(row.get(key))
            if value and value not in out:
                out[value] = row
    return out


def _protected_existing(row: dict[str, Any]) -> bool:
    status = _norm(row.get("status") or row.get("impact_contract_status")).lower()
    return status in {"locked", "complete", "completed", "proved", "accepted"} or bool(row.get("listed_impact_proven"))


def build_payload(
    workspace: Path,
    *,
    queue_path: Path | None = None,
    severity_path: Path | None = None,
    existing_path: Path | None = None,
    row_id: str | None = None,
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    workspace = workspace.expanduser().resolve()
    queue_path = queue_path or workspace / ".auditooor" / "exploit_queue.source_mined.json"
    existing_path = existing_path or workspace / ".auditooor" / "impact_contracts.json"
    queue_payload = _read_json(queue_path) if queue_path.is_file() else None
    queue_rows = _rows_from_queue(queue_payload)
    impacts = parse_severity_impacts(workspace, severity_path)
    existing_rows = _load_existing_contracts(existing_path)
    existing_index = _contract_index(existing_rows)

    contracts: list[dict[str, Any]] = []
    generated = 0
    preserved = 0
    skipped = 0
    patched_rows = 0

    selected_rows: list[dict[str, Any]] = []
    for row in queue_rows:
        cid = _candidate_id(row)
        if row_id and cid != row_id:
            continue
        if _is_terminal(row):
            skipped += 1
            continue
        selected_rows.append(row)

    for row in selected_rows:
        contract = build_contract(row, impacts, workspace)
        existing = existing_index.get(contract["impact_contract_id"]) or existing_index.get(contract["candidate_id"])
        if existing and _protected_existing(existing):
            contracts.append(existing)
            preserved += 1
            contract = existing
        else:
            contracts.append(contract)
            generated += 1

        if isinstance(queue_payload, dict):
            row["impact_contract_id"] = contract.get("impact_contract_id")
            row["impact_contract_status"] = contract.get("status") or contract.get("impact_contract_status")
            row["impact_contract_gaps"] = contract.get("impact_contract_gaps") or []
            row["oos_traps"] = contract.get("oos_traps") or []
            row["negative_control"] = contract.get("negative_control") or ""
            row["selected_impact"] = contract.get("selected_impact") or ""
            row["listed_impact_selected"] = contract.get("listed_impact_selected") or ""
            row["listed_impact_proven"] = bool(contract.get("listed_impact_proven"))
            if "proof_relevance" in contract:
                row["proof_relevance"] = bool(contract.get("proof_relevance"))
                row["proof_relevance_status"] = contract.get("proof_relevance_status") or ""
                row["proof_relevance_skip_reasons"] = contract.get("proof_relevance_skip_reasons") or []
                row["current_source_refs"] = contract.get("current_source_refs") or []
                row["stale_source_refs"] = contract.get("stale_source_refs") or []
            for key in REACHABILITY_FIELD_KEYS:
                if _present(row.get(key)):
                    continue
                value = contract.get(key)
                if _present(value):
                    row[key] = value
            patched_rows += 1

    selected_ids = {str(c.get("impact_contract_id") or "") for c in contracts}
    for existing in existing_rows:
        impact_contract_id = str(existing.get("impact_contract_id") or "")
        if impact_contract_id and impact_contract_id not in selected_ids:
            contracts.append(existing)

    gap_counts: dict[str, int] = {}
    advisory_counts: dict[str, int] = {}
    for contract in contracts:
        for gap in contract.get("impact_contract_gaps") or []:
            gap_counts[str(gap)] = gap_counts.get(str(gap), 0) + 1
        for advisory in contract.get("contract_advisories") or []:
            advisory_counts[str(advisory)] = advisory_counts.get(str(advisory), 0) + 1

    payload = {
        "schema": IMPACT_CONTRACTS_SCHEMA,
        "source_schema": SCHEMA,
        "generated_at_utc": _utc_now(),
        "workspace": str(workspace),
        "queue_path": str(queue_path),
        "status": "generated_unvalidated",
        "submission_posture": "NOT_SUBMIT_READY",
        "promotion_allowed": False,
        "proof_boundary": PROOF_BOUNDARY,
        "summary": {
            "queue_rows_seen": len(queue_rows),
            "rows_selected": len(selected_rows),
            "generated_contracts": generated,
            "preserved_locked_contracts": preserved,
            "skipped_terminal_rows": skipped,
            "patched_queue_rows": patched_rows,
            "contracts_total": len(contracts),
            "gap_counts": gap_counts,
            "advisory_counts": advisory_counts,
            "contracts_with_opposed_trace_advisory": sum(
                1 for c in contracts if c.get("opposed_trace_advisory")
            ),
            "proof_relevant_contracts": sum(1 for c in contracts if c.get("proof_relevance")),
            "skipped_non_proof_contracts": sum(
                1 for c in contracts if c.get("proof_relevance_status") == "skipped_non_proof"
            ),
        },
        "severity_impacts_by_tier": {tier: len(rows) for tier, rows in impacts.items()},
        "contracts": contracts,
    }
    return payload, queue_payload if isinstance(queue_payload, dict) else None


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--queue", type=Path)
    parser.add_argument("--severity", type=Path)
    parser.add_argument("--out-json", type=Path)
    parser.add_argument("--row")
    parser.add_argument("--update-queue", action="store_true")
    parser.add_argument("--print-json", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    workspace = args.workspace.expanduser().resolve()
    out_json = args.out_json.expanduser().resolve() if args.out_json else workspace / ".auditooor" / "impact_contracts.json"
    queue_path = args.queue.expanduser().resolve() if args.queue else workspace / ".auditooor" / "exploit_queue.source_mined.json"
    payload, patched_queue = build_payload(
        workspace,
        queue_path=queue_path,
        severity_path=args.severity.expanduser().resolve() if args.severity else None,
        existing_path=out_json,
        row_id=args.row,
    )
    _write_json(out_json, payload)
    if args.update_queue and patched_queue is not None:
        _write_json(queue_path, patched_queue)
    if args.print_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(
            "[source-mined-impact-contracts] "
            f"contracts={payload['summary']['contracts_total']} "
            f"generated={payload['summary']['generated_contracts']} "
            f"patched={payload['summary']['patched_queue_rows']} out={out_json}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
