#!/usr/bin/env python3
"""Pre-PoC filing stress test for High/Critical candidates.

HACKERMAN V3 Lane A turns the expensive submission questions into a
before-PoC artifact:

1. What exact permissionless action does the attacker take?
2. Does any step require admin/team action, off-chain compromise, mock state,
   synthetic state, or test-only assets?
3. What exact program rubric row is being claimed?
4. Has prior disclosure / duplicate risk been checked?
5. What evidence class must the PoC satisfy for the claimed severity?
6. (A4) For any value-extraction / yield / MEV / liquidation / oracle / reward
   path: is the attack economically viable (extractable value >= required
   bond/capital/cost), does it avoid an admin-pause / team-action
   prerequisite, and is the claimed victim/asset owner not actually the
   intended actor?

This tool is intentionally conservative. For High/Critical candidates it fails
closed when any of the written answers is missing or contradicted. The
evidence plan is planning output: absence of an already-built PoC does not fail
the gate, but an incompatible planned proof shape does.

A4 routing: an economics-only or scope-only High/Critical failure carries
`verdict_route` of `blocked_by_economics` / `blocked_by_scope` so downstream
consumers send the candidate away from PoC work, not just "fail". `verdict`
itself stays {pass,warn,fail} for backward compatibility.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "auditooor.prefiling_stress_test.v1"
REPO_ROOT = Path(__file__).resolve().parents[1]
OUTCOME_LESSON_GATE = REPO_ROOT / "tools" / "outcome-lesson-gate.py"
LESSON_ENFORCEMENT_INVENTORY = REPO_ROOT / ".auditooor" / "lesson_enforcement_inventory.json"
TYPED_ENVELOPE_TOOL = REPO_ROOT / "tools" / "zero-day-proof-envelope-verify.py"
TYPED_TERMINAL_SCHEMA = "auditooor.zero_day_proof_terminal_verdict.v1"
_TYPED_ENVELOPE_MOD: Any | None = None

# HACKERMAN_V3 Lane J5a: predicates emitted by the shared outcome-lesson
# classifier (tools/outcome-lesson-gate.py) that route a pre-PoC fail. The
# lesson predicate logic itself lives ONLY in the classifier; this map only
# decides which blocker list (economics vs scope) a hard predicate routes to.
OUTCOME_LESSON_ROUTING: dict[str, str] = {
    "economic_viability_missing": "economics",
    "future_reward_eligibility_not_accrued_reward_loss": "economics",
    "intended_actor_mismatch": "scope",
    "ambient_mev_not_protocol_bug": "scope",
    "documented_mechanics_no_stronger_intent": "scope",
    "low_severity_cap_triggered": "scope",
    "admin_or_team_action_prerequisite": "scope",
    "generic_dos_scope_risk": "scope",
}
SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
NEGATORS = ("no ", "not ", "without ", "does not ", "doesn't ", "never ")


PRIVILEGED_PATTERNS: tuple[tuple[str, str], ...] = (
    ("admin", r"\b(admin|administrator|owner|onlyowner|governance|gov|council)\b"),
    ("privileged_role", r"\b(privileged|permissioned|whitelisted|operator|keeper|approver|guardian|boss|authority)\b"),
    ("team_action", r"\b(team|project|protocol operator|maintainer)\b"),
    ("team_inaction", r"\b(team inaction|operator inaction|must not intervene|waits for team|unless the team)\b"),
    ("offchain_compromise", r"\b(private key leak|leaked key|credential|phishing|social engineering|off-chain compromise|offchain compromise)\b"),
    ("mock_component", r"\b(mock|stub|fake|test helper|test-only|dev-only|fixture-only)\b"),
    # NOTE: `FundAccount` (the cosmos-sdk x/bank test-seed helper) is deliberately
    # NOT in this class. It performs a real MintCoins + SendCoinsFromModuleToAccount
    # bank deposit (the standard, production-faithful way every Cosmos keeper test
    # seeds balances - used in 15 of provlabs/vault's own keeper tests), which is
    # categorically different from synthetic/reflection/direct-DB state injection.
    # Flagging it mis-classified a legitimate bank-funded PoC seed as a privileged/
    # mock/synthetic dependency (nuva begin-blocker DoS, 2026-07-04). The genuinely
    # synthetic markers below remain.
    ("synthetic_state", r"\b(synthetic|direct state seed|state seeding|direct db|db key injection|reflection|reflect\.|unsafe\.pointer)\b"),
    ("generic_dos", r"\b(generic dos|unsophisticated dos|rpc pressure|checktx pressure|rate limit|rate-limiting)\b"),
    ("sandwich", r"\b(sandwich|front[- ]?run|frontrun|back[- ]?run|backrun)\b"),
)


NETWORK_PAT = re.compile(
    r"\b(chain halt|halt|liveness|consensus|validator|apphash|finalizeblock|commit|beginblocker|endblocker|network-level)\b",
    re.IGNORECASE,
)
COSMOS_PAT = re.compile(r"\b(cosmos|cometbft|validator|finalizeblock|beginblocker|endblocker|keeper|go test)\b", re.IGNORECASE)
EVM_PAT = re.compile(r"\b(evm|solidity|foundry|forge|erc20|erc4626|vault|router|contract)\b", re.IGNORECASE)
FUND_PAT = re.compile(r"\b(theft|drain|loss of funds|direct loss|freeze|insolvency|principal|user funds)\b", re.IGNORECASE)
YIELD_PAT = re.compile(r"\b(yield|royalt|fees|unclaimed)\b", re.IGNORECASE)
PERMISSIONLESS_PAT = re.compile(
    r"\b(unprivileged|non[- ]privileged|fresh account|normal fee-paying messages?|MsgCreateVault|permissionless|any address|any user|anyone|public entry|publicly callable|external caller|no special role)\b",
    re.IGNORECASE,
)
ECONOMICS_CLAIM_PAT = re.compile(
    r"\b(value extraction|extract(?:s|ed|ion)? (?:value|yield|rewards?|fees?|profit)|"
    r"reward extraction|yield extraction|fee evasion|theft of unclaimed yield|profit|pnl|p&l)\b",
    re.IGNORECASE,
)
# A4: a candidate is economics-relevant when it touches a value-extraction /
# yield / MEV / liquidation / oracle / reward path. This deliberately does NOT
# include generic direct-theft / drain language (a plain withdraw() drain is
# direct theft, not a yield/MEV/oracle path) - that would over-fire on every
# fund-loss finding. ECONOMICS_CLAIM_PAT (extraction verbs) is one input;
# ECONOMICS_RELEVANT_PAT additionally captures the MEV / liquidation / oracle /
# reward / yield classes that A4 names explicitly.
ECONOMICS_RELEVANT_PAT = re.compile(
    r"\b(value[- ]?extraction|extract(?:s|ed|ion)? (?:value|yield|rewards?|fees?|profit)|"
    r"reward[- ]?extraction|yield[- ]?extraction|fee[- ]?evasion|"
    r"unclaimed (?:yield|rewards?|fees?)|"
    r"\bmev\b|sandwich|front[- ]?run|frontrun|back[- ]?run|backrun|arbitrage|"
    r"liquidat(?:e|es|ed|ion|or)|bad debt|"
    r"oracle (?:manipulation|window|stale|price)|price[- ]?manipulation|price feed|"
    r"reward(?:s)? (?:theft|drain|skim|steal|farming|claim)|"
    r"theft of (?:unclaimed )?(?:yield|rewards?|fees?)|"
    r"\bpnl\b|p&l)\b",
    re.IGNORECASE,
)
# A4: explicit admin-pause / team-action prerequisite. When the only path to
# the impact requires a project-side emergency action (pause, freeze, upgrade,
# emergency intervention), the candidate routes to blocked_by_scope, not PoC.
ADMIN_PAUSE_PREREQ_PAT = re.compile(
    r"\b(admin[- ]?pause|emergency[- ]?pause|paused? (?:by (?:the )?(?:admin|team|owner|governance)|state)|"
    r"pause (?:prerequisite|precondition|required|window)|"
    r"requires? (?:an? )?(?:admin|team|owner|governance|emergency) (?:pause|action|intervention|freeze|upgrade)|"
    r"only (?:exists|reachable|possible) after (?:project|team|admin|owner)[- ]side (?:emergency )?action|"
    r"after (?:the )?(?:project|team|admin|owner|governance) (?:pauses?|freezes?|intervenes?|emergency)|"
    r"market is flagged|flag window|flagged state|emergency intervention)\b",
    re.IGNORECASE,
)
# A4: numeric token extraction for the extractable-value-vs-cost comparison.
# Anchored to a currency / unit context so bare integers (line numbers, counts)
# do not pollute the comparison.
_MONEY_RE = re.compile(
    r"(?<![\w.])"
    r"(?:(?P<cur>\$|usd\s*|usdc\s*|dai\s*|eth\s*))?"
    r"(?P<num>\d{1,3}(?:[,_]\d{3})*(?:\.\d+)?|\d+(?:\.\d+)?)"
    r"\s*(?P<suf>k\b|m\b|usd\b|usdc\b|dai\b|dollars?\b)?",
    re.IGNORECASE,
)
EXECUTION_WINDOW_CLAIM_PAT = re.compile(
    r"\b(mev|sandwich|front[- ]?run|frontrun|back[- ]?run|backrun|race condition|race|timestamp|liquidation|oracle[- ]?window|oracle window)\b",
    re.IGNORECASE,
)
EXECUTION_WINDOW_PROOF_PAT = re.compile(
    r"\b(execution[- ]window|same block|same transaction|same tx|block window|within \d+ (?:blocks?|seconds?|minutes?)|mempool|ordering|before/after|oracle update window|liquidation window)\b",
    re.IGNORECASE,
)
OOS_DISTINCTION_PAT = re.compile(
    r"\b(oos|out[- ]of[- ]scope|not (?:a )?(?:mev|sandwich|frontrun|front-run|backrun|back-run)|in[- ]scope distinction|scope distinction|scope boundary|program scope)\b",
    re.IGNORECASE,
)
SELF_CREATED_OR_NON_PRIV_PAT = re.compile(
    r"\b(self[- ]created|attacker[- ]created|attacker creates|created by the attacker|own market|own resource|permissionless(?:ly)? creates|no pre[- ]existing admin|no admin action required|non[- ]privileged path|without admin action)\b",
    re.IGNORECASE,
)
ONE_FIX_RISK_PAT = re.compile(
    r"\b(multiple impacts?|two impacts?|several impacts?|same root cause|single root cause|one root cause|shared root cause|same bug)\b",
    re.IGNORECASE,
)
ONE_FIX_DISCUSSION_PAT = re.compile(
    r"\b(unified report|single report|combined report|one[- ]fix|one fix|same fix|deduplicat|not split|shared root cause discussed)\b",
    re.IGNORECASE,
)
OOS_ASSET_PAT = re.compile(
    r"\b(out[- ]of[- ]scope asset|oos asset|out[- ]of[- ]listed[- ]asset|unlisted asset|unsupported asset|non[- ]listed asset|not listed asset|asset not listed|out of listed asset)\b",
    re.IGNORECASE,
)
PRIMACY_IMPACT_PAT = re.compile(
    r"\b(primacy[- ]of[- ]impact|primary impact|primacy of impact|impact primacy|smart[- ]contract impact|contract impact|in[- ]scope impact category|impact category|impact justification|primary affected component)\b",
    re.IGNORECASE,
)
PROTOCOL_FAULT_DISTINCTION_PAT = re.compile(
    r"\b(protocol[- ]level (?:bug|fault|defect)|protocol (?:bug|fault|defect)|"
    r"contract (?:bug|fault|defect)|invariant (?:break|violation)|"
    r"not (?:merely|just|only) (?:ambient )?(?:mev|sandwich|front[- ]?run|frontrun)|"
    r"independent of (?:ordinary )?(?:mev|sandwich|front[- ]?run|frontrun)|"
    r"underlying (?:protocol|contract) (?:bug|fault|root cause)|"
    r"zero (?:inner )?(?:minamounts|minshares|slippage)|broken internal slippage)\b",
    re.IGNORECASE,
)
PROTOCOL_FAULT_NEGATION_PAT = re.compile(
    r"\b(no|without|lacks?|missing)\b.{0,90}\b(protocol[- ]level (?:bug|fault|defect)|"
    r"protocol (?:bug|fault|defect)|contract (?:bug|fault|defect)|invariant (?:break|violation))\b",
    re.IGNORECASE,
)
NATURAL_NETWORK_ACTIVITY_PAT = re.compile(
    r"\b(natural network activity|ordinary network activity|ordinary market activity|"
    r"public (?:curation|mint|staking|trading|liquidation)|permissionless (?:curation|curator|mint|staking|trading|liquidation)|"
    r"any address (?:is )?(?:entitled|allowed) to call|pre[- ]?(?:curate|curation|position|seed))\b",
    re.IGNORECASE,
)
INTENDED_ACTOR_MISMATCH_PAT = re.compile(
    r"\b(intended actor mismatch|intended creator|only intended creator|protocol[- ]authorized caller|"
    r"authorized actor|designated caller|wrong actor|not the intended actor|creator['’]s reward|creator reward)\b",
    re.IGNORECASE,
)
ECONOMICALLY_NEGATIVE_PAT = re.compile(
    r"\b(unprofitable|negative ev|negative expected value|not economically viable|economically infeasible|"
    r"cost (?:exceeds|outweighs|is greater than) (?:value|reward|profit|gain)|"
    r"(?:bond|gas|fee|capital|cost)[^.\n]{0,120}(?:exceeds|outweighs|more than|greater than)[^.\n]{0,120}(?:reward|value|profit|gain)|"
    r"(?:reward|value|profit|gain)[^.\n]{0,120}(?:less than|below|smaller than)[^.\n]{0,120}(?:bond|gas|fee|capital|cost))\b",
    re.IGNORECASE,
)


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _read_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise SystemExit(f"could not read JSON candidate row {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise SystemExit(f"candidate row must be a JSON object: {path}")
    return data


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except Exception as exc:
        raise SystemExit(f"could not read draft {path}: {exc}") from exc


def _normalize_sev(value: Any) -> str:
    raw = str(value or "").strip().lower()
    for key in ("critical", "high", "medium", "low"):
        if key in raw:
            return key
    return "unknown"


def _is_high_plus(sev: str) -> bool:
    return SEVERITY_RANK.get(sev, 0) >= SEVERITY_RANK["high"]


TERMINAL_QUEUE_PROOF_STATUSES = {
    # NEGATIVE-terminal: the lead was refuted / killed / dropped.
    "killed",
    "kill",
    "drop",
    "dropped",
    "disproved",
    "closed_negative",
    "closed_negative_operator_review",
    "false_positive",
    "false-positive",
    "not_exploitable",
    "not_candidate",
    # POSITIVE-terminal: the lead reached its FINDING outcome - PoC-proven and/or
    # filed/paste-ready. It no longer "needs proving", so it must NOT count as a
    # non-terminal top lead blocking the no-leads manifest (2026-07-07: a
    # proof_status=proven/quality=filed row was assessed as an un-proven top lead,
    # keeping top_n>0 and failing prove-top-leads on an already-filed finding).
    "proven",
    "filed",
    "confirmed",
    "submitted",
    "paste_ready",
    "paste-ready",
}
TERMINAL_QUEUE_QUALITY_STATUSES = {
    "killed",
    "kill",
    "drop",
    "dropped",
    "disqualified",
    "closed_negative",
    "closed_negative_operator_review",
    "false_positive",
    "false-positive",
    "not_exploitable",
    "advisory_not_candidate",
    # POSITIVE-terminal quality outcomes (see above).
    "filed",
    "submitted",
    "paste_ready",
    "paste-ready",
    "accepted",
}


def _load_typed_envelope_tool() -> Any:
    """Load the shared immutable admitted-proof validator once."""
    global _TYPED_ENVELOPE_MOD
    if _TYPED_ENVELOPE_MOD is not None:
        return _TYPED_ENVELOPE_MOD
    spec = importlib.util.spec_from_file_location("auditooor_typed_proof_envelope", TYPED_ENVELOPE_TOOL)
    if spec is None or spec.loader is None:
        raise ValueError("typed_proof_envelope_tool_unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    _TYPED_ENVELOPE_MOD = module
    return module


def _typed_queue_entries(
    payload: dict[str, Any], *, workspace: Path | None = None, queue_path: Path | None = None,
) -> dict[str, dict[str, Any]] | None:
    """Rebuild admitted identities before a closeout reader trusts terminal text."""
    if "zero_day_proof_admission" not in payload:
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
    try:
        envelope = _load_typed_envelope_tool().build_envelope(payload)
    except Exception as exc:
        raise ValueError(f"typed_proof_envelope_invalid:{exc}") from exc
    return {entry["lead_id"]: entry for entry in envelope["entries"]}


def _typed_terminal_record_matches(row: dict[str, Any], entry: dict[str, Any]) -> bool:
    """Require a source-cited exact terminal record for an admitted row."""
    return _load_typed_envelope_tool().terminal_record_matches(entry, row)


def _is_terminal_queue_row(row: dict[str, Any], typed_entry: dict[str, Any] | None = None) -> bool:
    proof_status = str(
        row.get("proof_status")
        or row.get("source_mined_proof_status")
        or row.get("proof_verdict")
        or row.get("status")
        or ""
    ).strip().lower()
    quality_status = str(row.get("quality_gate_status") or "").strip().lower()
    learning_route = str(row.get("learning_route") or row.get("recommended_next_step") or "").strip().lower()
    terminal = (
        proof_status in TERMINAL_QUEUE_PROOF_STATUSES
        or quality_status in TERMINAL_QUEUE_QUALITY_STATUSES
        or quality_status.startswith("closed_negative")
        or learning_route in {"drop", "dropped", "closed-negative", "closed_negative"}
    )
    return terminal and (typed_entry is None or _typed_terminal_record_matches(row, typed_entry))


def _is_non_proof_queue_row(row: dict[str, Any]) -> bool:
    """Keep coverage/reasoning rows out of the pre-PoC candidate lane.

    Rows explicitly marked as non-proof remain useful downstream as coverage
    evidence, but selecting them by queue position makes corpus and unhunted
    rows masquerade as top leads.
    """
    if row.get("row_is_advisory") is True or row.get("advisory_only") is True:
        return True
    if str(row.get("proof_relevance_status") or "").strip().lower() == "skipped_non_proof":
        return True
    return row.get("proof_relevance") is False


def _stringify(value: Any) -> str:
    if isinstance(value, (dict, list, tuple)):
        return json.dumps(value, sort_keys=True)
    return str(value or "")


def _row_text(row: dict[str, Any]) -> str:
    parts: list[str] = []
    for key in (
        "lead_id",
        "title",
        "permissionless_action",
        "attacker_action",
        "trigger",
        "attacker_control",
        "impact_path",
        "selected_impact",
        "rubric_row",
        "proof_path",
        "planned_evidence_class",
        "attacker_actor",
        "victim_actor",
        "capital_lock",
        "capital_cost",
        "attacker_cost",
        "cost_basis",
        "required_capital",
        "profit",
        "loss",
        "profit_loss",
        "pnl",
        "economics",
        "affected_amount",
        "affected_amount_basis",
        "balance_delta",
        "blockers",
        "oos_risks",
        "source_refs",
        "truth_table",
        "proof_status",
        "source_mined_proof_status",
        "quality_gate_status",
        "learning_route",
        "recommended_next_step",
    ):
        if key in row:
            parts.append(f"{key}: {_stringify(row.get(key))}")
    return "\n".join(parts)


def _semantic_stress_text(text: str) -> str:
    """Strip identifiers/boilerplate that should not trigger semantic gates."""
    lines = [
        line for line in text.splitlines()
        if not re.match(
            r"^\s*[-*]?\s*(lead_id|candidate_id|id|oos_traps|not_proven_impacts)\s*:",
            line,
            re.IGNORECASE,
        )
    ]
    cleaned = "\n".join(lines)
    cleaned = re.sub(r"\bother than unclaimed yield\b", "", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r"\bNUVA Critical reward\b.*", "", cleaned, flags=re.IGNORECASE)
    return cleaned


def _extract_first(patterns: list[re.Pattern[str]], text: str) -> str:
    for pat in patterns:
        match = pat.search(text)
        if match:
            return match.group(1).strip()
    return ""


def _draft_to_row(path: Path) -> dict[str, Any]:
    text = _read_text(path)
    title = _extract_first([re.compile(r"(?m)^#\s+(.+)$")], text) or path.stem
    severity = _extract_first([
        re.compile(r"(?im)^\s*[-*]?\s*\**\s*severity\s*\**\s*:\s*(.+)$"),
        re.compile(r"(?im)^\s*[-*]?\s*\**\s*severity[_ -]?tier\s*\**\s*:\s*(.+)$"),
        re.compile(r"(?im)^\s*[-*]?\s*\**\s*status\s*\**\s*:\s*.*?\b((?:critical|high|medium|low)(?:\s*/\s*(?:critical|high|medium|low))?)\b.*$"),
    ], text)
    selected_impact = _extract_first([
        re.compile(r"(?im)^\s*[-*]?\s*\**\s*selected[_ ]impact\s*\**\s*:\s*(.+)$"),
        re.compile(r"(?im)^\s*[-*]?\s*\**\s*impact(?:\(s\))?\s*\**\s*:\s*(.+)$"),
    ], text)
    rubric_row = _extract_first([
        re.compile(r"(?im)^\s*[-*]?\s*\**\s*rubric[_ ]row\s*\**\s*:\s*(.+)$"),
        re.compile(r"(?im)^\s*[-*]?\s*\**\s*severity[_ ]rubric\s*\**\s*:\s*(.+)$"),
        re.compile(r"(?im)^\s*[-*]?\s*\**\s*selected[_ ]impact\s*\**\s*:\s*(.+)$"),
        re.compile(r"(?im)^\s*[-*]?\s*\**\s*impact(?:\(s\))?\s*\**\s*:\s*(.+)$"),
    ], text)
    permissionless = _extract_first([
        re.compile(r"(?im)^\s*[-*]?\s*\**\s*permissionless[_ ]action\s*\**\s*:\s*(.+)$"),
        re.compile(r"(?im)^\s*[-*]?\s*\**\s*attacker[_ ]action\s*\**\s*:\s*(.+)$"),
    ], text)
    if not permissionless:
        permissionless = _extract_first(
            [
                re.compile(
                    r"(?is)(attacker[^.\n]{0,240}?(?:MsgCreateVault|permissionless|fresh account|self-grant|"
                    r"no pre-existing privileged|normal fee-paying messages)[^.\n]{0,240}\.)"
                ),
                re.compile(
                    r"(?is)((?:Any address|Any user|Anyone|A fresh non-privileged account)[^.\n]{0,240}\.)"
                ),
            ],
            text,
        )
    dupe = _extract_first([
        re.compile(r"(?im)^\s*[-*]?\s*\**\s*prior[_ ]disclosure[_ ]status\s*\**\s*:\s*(.+)$"),
        re.compile(r"(?im)^\s*[-*]?\s*\**\s*dupe[_ ]risk\s*\**\s*:\s*(.+)$"),
    ], text)
    if not dupe and re.search(r"(?is)\b(distinct from|distinction from prior|prior .*audits).*?\b(novel|do not flag|different root cause)\b", text):
        dupe = "clean"
    return {
        "lead_id": path.stem,
        "title": title,
        "likely_severity": severity,
        "selected_impact": selected_impact,
        "rubric_row": rubric_row,
        "permissionless_action": permissionless,
        "prior_disclosure_status": dupe,
        "raw_draft_text": text,
        "source_path": str(path),
    }


def _field_answer(row: dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = row.get(key)
        if value is None:
            continue
        if isinstance(value, str) and not value.strip():
            continue
        return _stringify(value).strip()
    return ""


def _line_is_negated(text: str, start: int) -> bool:
    prefix = text[max(0, start - 160):start].lower()
    prefix = re.split(r"[.;:\n]", prefix)[-1]
    return any(neg in prefix for neg in NEGATORS)


def _has_unnegated(pattern: re.Pattern[str], text: str) -> bool:
    return any(not _line_is_negated(text, match.start()) for match in pattern.finditer(text))


def _admin_dependency_excused(text: str) -> bool:
    return bool(SELF_CREATED_OR_NON_PRIV_PAT.search(text))


def _privileged_flags(text: str) -> list[dict[str, str]]:
    flags: list[dict[str, str]] = []
    scan_text = _semantic_stress_text(text)
    for name, pattern in PRIVILEGED_PATTERNS:
        rx = re.compile(pattern, re.IGNORECASE)
        for match in rx.finditer(scan_text):
            if _line_is_negated(scan_text, match.start()):
                continue
            if name == "sandwich" and _has_protocol_fault_distinction(scan_text):
                continue
            if name in {"admin", "privileged_role", "team_action", "team_inaction"} and _admin_dependency_excused(scan_text):
                continue
            snippet = scan_text[max(0, match.start() - 80):match.end() + 80].replace("\n", " ")
            flags.append({"flag": name, "match": match.group(0), "snippet": snippet[:220]})
            break
    return flags


def _prior_status(row: dict[str, Any]) -> tuple[str, list[str]]:
    explicit = str(row.get("prior_disclosure_status") or row.get("originality_status") or "").strip().lower()
    dupe = str(row.get("dupe_risk") or "").strip().lower()
    citations = row.get("prior_disclosure_refs") or row.get("originality_refs") or []
    if isinstance(citations, str):
        citations = [citations]
    if explicit:
        if any(tok in explicit for tok in ("known_dupe", "duplicate", "dupe", "not distinct")):
            return "known_dupe", list(map(str, citations))
        if any(tok in explicit for tok in ("possible", "overlap", "unclear", "needs")):
            return "possible_dupe", list(map(str, citations))
        if any(tok in explicit for tok in ("clean", "novel", "no prior", "none found")):
            return "clean", list(map(str, citations))
        if "not" in explicit and "check" in explicit:
            return "not_checked", list(map(str, citations))
    if dupe:
        if dupe == "low":
            return "clean", list(map(str, citations))
        if dupe == "medium":
            return "possible_dupe", list(map(str, citations))
        if dupe == "high":
            return "known_dupe", list(map(str, citations))
    return "not_checked", list(map(str, citations))


def _permissionless_action_ok(action: str, attacker_control: str) -> bool:
    """Return whether the written action explicitly identifies public control."""
    affirmative = {"known", "yes", "unprivileged", "permissionless", "public", "anyone"}
    if attacker_control in {"missing", "partial", "privileged", "admin", "owner"}:
        return False
    if attacker_control in affirmative:
        return bool(action)
    return bool(action and PERMISSIONLESS_PAT.search(action))


def _rubric_answer(row: dict[str, Any]) -> str:
    truth = row.get("truth_table") if isinstance(row.get("truth_table"), dict) else {}
    return _field_answer(row, "rubric_row", "severity_row", "selected_impact", "impact") or _stringify(truth.get("severity_row")).strip()


def _required_evidence(row: dict[str, Any], text: str, severity: str) -> dict[str, Any]:
    lowered = text.lower()
    requirements: list[str] = []
    evidence_class = "source_review"
    triggers: list[str] = []

    network = bool(NETWORK_PAT.search(text))
    cosmos = bool(COSMOS_PAT.search(text))
    evm = bool(EVM_PAT.search(text))
    fund = bool(FUND_PAT.search(text))
    yield_ = bool(YIELD_PAT.search(text))

    if network and _is_high_plus(severity):
        evidence_class = "production_profile_node_level_multi_validator_restart"
        triggers.append("network_or_chain_liveness_claim")
        requirements.extend([
            "real production entry path: BroadcastTx/RunTx/FinalizeBlock/BeginBlocker/EndBlocker as applicable",
            "production-profile persistent backend when DB/storage is involved (goleveldb/pebbledb/rocksdb; no memdb timing shim)",
            "no reflection, direct private-field mutation, or direct internal DB key injection",
            "multi-validator or equivalent node-level liveness demonstration for network-level claims",
            "restart behavior: whether the failure reoccurs after restart, with exact logs/stack traces",
            "exact commit hash, config, commands, and full transcript",
        ])
    elif cosmos and _is_high_plus(severity):
        evidence_class = "production_entry_go_test_or_binary_harness"
        triggers.append("cosmos_or_go_state_machine_claim")
        requirements.extend([
            "real Msg/ABCI production entry path; keeper-only proof is planning-incomplete",
            "unprivileged actor account and signatures where applicable",
            "persistent state bootstrap through normal messages/genesis, not synthetic state mutation",
            "full go test or binary harness transcript with commit/config",
        ])
    elif evm and (fund or yield_) and _is_high_plus(severity):
        evidence_class = "end_to_end_runtime_poc_with_clean_control"
        triggers.append("evm_funds_or_yield_claim")
        requirements.extend([
            "runnable Foundry/Hardhat/local-fork PoC through public/external entrypoints",
            "unprivileged attacker address distinct from victim/protocol roles",
            "asset balance delta proving the selected rubric row",
            "clean control showing adjacent non-bug condition does not fire",
            "exact commit hash, commands, and full transcript",
        ])
    elif _is_high_plus(severity):
        evidence_class = "high_plus_end_to_end_runtime_poc"
        triggers.append("high_plus_generic_claim")
        requirements.extend([
            "runnable end-to-end PoC through production entrypoints",
            "unprivileged attacker action",
            "measurable impact mapped to the cited rubric row",
            "clean control and full transcript",
        ])
    else:
        evidence_class = "source_or_runtime_evidence_by_rubric"
        requirements.append("evidence sufficient for the selected rubric row; no High/Critical planning gate applied")

    planned = str(row.get("planned_evidence_class") or row.get("proof_path") or "").lower()
    incompatible: list[str] = []
    if _is_high_plus(severity):
        if "keeper" in planned or "internal" in planned:
            incompatible.append("planned_proof_is_keeper_or_internal_only")
        if network and not any(tok in planned for tok in ("multi-validator", "4-validator", "node", "production", "finalizeblock", "beginblocker", "endblocker", "missing", "")):
            incompatible.append("planned_proof_missing_node_level_liveness_shape")
        if any(tok in planned for tok in ("mock", "synthetic", "memdb", "reflection")):
            incompatible.append("planned_proof_contains_synthetic_or_non_production_marker")

    return {
        "required_evidence_class": evidence_class,
        "requirements": requirements,
        "triggers": triggers,
        "planned_evidence_signal": planned or "not_declared",
        "incompatible_planned_evidence": incompatible,
    }


def _field_present(row: dict[str, Any], text: str, keys: tuple[str, ...], text_pattern: re.Pattern[str]) -> bool:
    if any(str(row.get(key) or "").strip() for key in keys):
        return True
    return bool(text_pattern.search(text))


def _source_refs_present(row: dict[str, Any], text: str) -> bool:
    refs = row.get("source_refs") or row.get("source_ref") or row.get("citations") or row.get("references")
    if isinstance(refs, list):
        if any(str(ref).strip() for ref in refs):
            return True
    elif str(refs or "").strip():
        return True
    return bool(
        re.search(
            r"\b(source refs?|source references?|source[-_ ]?proof|refs?|citations?)\s*:\s*\S+",
            text,
            re.IGNORECASE,
        )
    )


def _missing_economics_fields(row: dict[str, Any], text: str) -> list[str]:
    text = _semantic_stress_text(text)
    # A4: economics fields are required for any value-extraction / yield / MEV /
    # liquidation / oracle / reward candidate, not only ones with an explicit
    # extraction verb.
    if not _is_economics_relevant(row, text):
        return []
    checks = {
        "capital_lock_or_cost": _field_present(
            row,
            text,
            ("capital_lock", "capital_cost", "attacker_cost", "cost_basis", "required_capital"),
            re.compile(r"\b(capital lock|capital locked|attacker cost|capital cost|cost basis|required capital)\b", re.IGNORECASE),
        ),
        "profit_or_loss_statement": _field_present(
            row,
            text,
            ("profit", "loss", "profit_loss", "pnl", "loss_statement", "profit_statement"),
            re.compile(r"\b(profit|loss statement|profit/loss|pnl|p&l|net loss|net profit)\b", re.IGNORECASE),
        ),
        "affected_amount_basis": _field_present(
            row,
            text,
            ("affected_amount_basis", "affected_amount", "amount_basis", "balance_delta"),
            re.compile(r"\b(affected amount|amount basis|balance delta|delta basis|valuation basis)\b", re.IGNORECASE),
        ),
        "victim_and_attacker_actor": (
            _field_present(
                row,
                text,
                ("victim_actor", "victim"),
                re.compile(r"\b(victim actor|victim)\b", re.IGNORECASE),
            )
            and _field_present(
                row,
                text,
                ("attacker_actor", "attacker"),
                re.compile(r"\b(attacker actor|attacker)\b", re.IGNORECASE),
            )
        ),
        "source_refs": _source_refs_present(row, text),
    }
    return [name for name, ok in checks.items() if not ok]


def _missing_execution_window_or_oos(text: str) -> bool:
    text = _semantic_stress_text(text)
    return _has_unnegated(EXECUTION_WINDOW_CLAIM_PAT, text) and (
        not EXECUTION_WINDOW_PROOF_PAT.search(text) or not OOS_DISTINCTION_PAT.search(text)
    )


def _missing_one_fix_discussion(text: str) -> bool:
    text = _semantic_stress_text(text)
    return bool(ONE_FIX_RISK_PAT.search(text)) and not ONE_FIX_DISCUSSION_PAT.search(text)


def _missing_oos_asset_primacy(text: str) -> bool:
    text = _semantic_stress_text(text)
    return bool(OOS_ASSET_PAT.search(text)) and not PRIMACY_IMPACT_PAT.search(text)


def _has_protocol_fault_distinction(text: str) -> bool:
    text = _semantic_stress_text(text)
    if not PROTOCOL_FAULT_DISTINCTION_PAT.search(text):
        return False
    negated_fault = PROTOCOL_FAULT_NEGATION_PAT.search(text)
    positive_anchor = re.search(
        r"\b(not (?:merely|just|only) (?:ambient )?(?:mev|sandwich|front[- ]?run|frontrun)|"
        r"independent of (?:ordinary )?(?:mev|sandwich|front[- ]?run|frontrun)|"
        r"underlying (?:protocol|contract) (?:bug|fault|root cause)|"
        r"zero (?:inner )?(?:minamounts|minshares|slippage)|broken internal slippage)\b",
        text,
        re.IGNORECASE,
    )
    return bool(positive_anchor or not negated_fault)


def _ambient_mev_without_protocol_fault(text: str) -> bool:
    text = _semantic_stress_text(text)
    return _has_unnegated(EXECUTION_WINDOW_CLAIM_PAT, text) and not _has_protocol_fault_distinction(text)


def _natural_network_activity_scope_risk(text: str) -> bool:
    text = _semantic_stress_text(text)
    return _has_unnegated(NATURAL_NETWORK_ACTIVITY_PAT, text) and not _has_protocol_fault_distinction(text)


def _intended_actor_mismatch(text: str) -> bool:
    text = _semantic_stress_text(text)
    return _has_unnegated(INTENDED_ACTOR_MISMATCH_PAT, text)


def _economically_negative_claim(text: str) -> bool:
    text = _semantic_stress_text(text)
    return _has_unnegated(ECONOMICALLY_NEGATIVE_PAT, text)


def _is_economics_relevant(row: dict[str, Any], text: str) -> bool:
    """A4: candidate touches a value-extraction / yield / MEV / liquidation /
    oracle / reward path and therefore must carry the economics fields.

    Title/impact/selected_impact prose is checked, plus an explicit
    economics-relevant tag on the row (attack_class / tags / category).
    ECONOMICS_CLAIM_PAT (the pre-A4 extraction-verb trigger) is kept as an
    input so the pre-A4 behaviour is preserved."""
    text = _semantic_stress_text(text)
    if _has_unnegated(ECONOMICS_RELEVANT_PAT, text) or _has_unnegated(ECONOMICS_CLAIM_PAT, text):
        return True
    tag_blob = " ".join(
        _stringify(row.get(key)).lower()
        for key in ("attack_class", "attack_classes", "tags", "category", "bug_class", "lane")
    )
    return bool(ECONOMICS_RELEVANT_PAT.search(tag_blob) or ECONOMICS_CLAIM_PAT.search(tag_blob))


def _money_to_usd(token: str) -> float | None:
    """Best-effort parse of a money token to a USD float. Returns None when the
    token has no currency/unit anchor (bare integers are ignored)."""
    m = _MONEY_RE.fullmatch(token.strip())
    if not m:
        m = _MONEY_RE.search(token.strip())
    if not m:
        return None
    has_anchor = bool(m.group("cur") or m.group("suf"))
    if not has_anchor:
        return None
    raw = m.group("num").replace(",", "").replace("_", "")
    try:
        value = float(raw)
    except ValueError:
        return None
    suf = (m.group("suf") or "").strip().lower()
    if suf == "k":
        value *= 1_000
    elif suf == "m":
        value *= 1_000_000
    return value


def _max_money_in(text: str) -> float | None:
    """Largest currency-anchored amount mentioned in a string (None if none)."""
    best: float | None = None
    for m in _MONEY_RE.finditer(text or ""):
        if not (m.group("cur") or m.group("suf")):
            continue
        val = _money_to_usd(m.group(0))
        if val is None:
            continue
        if best is None or val > best:
            best = val
    return best


def _economics_numbers(row: dict[str, Any], text: str) -> dict[str, Any]:
    """A4: extract extractable-value and required-cost numbers, compare them.

    Prefers explicit typed fields (extractable_value, required_cost / bond /
    capital), falls back to currency-anchored numbers found in the
    cost/value-bearing prose. The verdict is fail-closed only when BOTH a
    value and a cost are recoverable AND value < cost; an unrecoverable side
    yields net_economics='unknown' (no numeric block, prose gate still runs).
    """
    value_fields = (
        "extractable_value", "value_extracted", "value_at_risk",
        "reward_amount", "affected_amount", "extractable_now",
    )
    cost_fields = (
        "required_cost", "required_capital", "required_bond", "bond",
        "attacker_cost", "capital_cost", "capital_lock", "cost_basis",
        "gas_slippage_time_cost",
    )
    value: float | None = None
    value_src = ""
    for key in value_fields:
        if key in row and str(row.get(key) or "").strip():
            value = _max_money_in(_stringify(row.get(key)))
            if value is not None:
                value_src = key
                break
    cost: float | None = None
    cost_src = ""
    for key in cost_fields:
        if key in row and str(row.get(key) or "").strip():
            cost = _max_money_in(_stringify(row.get(key)))
            if cost is not None:
                cost_src = key
                break

    # Fall back to prose: a single line can mention BOTH a value and a cost
    # (e.g. "$4 reward vs $800 bond"), so do not take the max-of-line. Instead,
    # for each currency-anchored amount pick the nearest keyword (value vs
    # cost) within a small window and assign the amount to that side.
    if value is None or cost is None:
        value_kw = re.compile(
            r"\b(reward|yield|extractable|payout|gain|profit|extract(?:s|ed|ion)?)\b",
            re.IGNORECASE,
        )
        cost_kw = re.compile(
            r"\b(bond|capital|gas|fee|cost|stake|deposit|collateral|slippage)\b",
            re.IGNORECASE,
        )
        clean = _semantic_stress_text(text)

        def _closest_kw_side(pos: int) -> str:
            """Pick value/cost by the keyword closest to the amount at `pos`,
            measured by absolute character distance across the whole text."""
            v_best = None
            for hit in value_kw.finditer(clean):
                d = min(abs(hit.start() - pos), abs(hit.end() - pos))
                if v_best is None or d < v_best:
                    v_best = d
            c_best = None
            for hit in cost_kw.finditer(clean):
                d = min(abs(hit.start() - pos), abs(hit.end() - pos))
                if c_best is None or d < c_best:
                    c_best = d
            if v_best is None and c_best is None:
                return ""
            if v_best is None:
                return "cost"
            if c_best is None:
                return "value"
            return "value" if v_best <= c_best else "cost"

        for mm in _MONEY_RE.finditer(clean):
            if not (mm.group("cur") or mm.group("suf")):
                continue
            amt = _money_to_usd(mm.group(0))
            if amt is None:
                continue
            side = _closest_kw_side(mm.start())
            if side == "value" and value is None:
                value, value_src = amt, "prose"
            elif side == "cost" and cost is None:
                cost, cost_src = amt, "prose"

    if value is not None and cost is not None:
        net = "negative" if value < cost else "positive"
    else:
        net = "unknown"
    return {
        "extractable_value_usd": value,
        "extractable_value_source": value_src or None,
        "required_cost_usd": cost,
        "required_cost_source": cost_src or None,
        "net_economics": net,
    }


def _admin_pause_prerequisite(text: str) -> bool:
    """A4: the impact path is only reachable after a project-side emergency
    action (admin pause / team intervention / governance freeze)."""
    text = _semantic_stress_text(text)
    return _has_unnegated(ADMIN_PAUSE_PREREQ_PAT, text)


def _shared_outcome_lesson_predicates(text: str) -> dict[str, Any]:
    """Consume the shared outcome-lesson classifier (HACKERMAN_V3 Lane J5a).

    This does NOT re-encode any lesson logic. It imports and calls
    ``tools/outcome-lesson-gate.py`` and returns its hard-blocker predicates so
    the prefiling stress test routes them as pre-PoC fail conditions. The
    pre-A4 / A4 economics + actor logic in this file is intentionally kept
    (60f56a1dca) as defence-in-depth; the shared classifier is the single
    source of truth for the lesson predicate *definitions*.
    """
    result: dict[str, Any] = {
        "available": False,
        "status": "error",
        "hard_predicates": [],
        "advisory_predicates": [],
        "reason": "",
    }
    if not OUTCOME_LESSON_GATE.is_file():
        result["reason"] = "outcome-lesson-gate.py not found"
        return result
    try:
        spec = importlib.util.spec_from_file_location(
            "auditooor_outcome_lesson_gate_for_prefiling",
            OUTCOME_LESSON_GATE,
        )
        if spec is None or spec.loader is None:
            raise RuntimeError(f"cannot load {OUTCOME_LESSON_GATE}")
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        inventory = LESSON_ENFORCEMENT_INVENTORY if LESSON_ENFORCEMENT_INVENTORY.is_file() else None
        payload = module.build_gate(stdin_text=text, inventory_path=inventory)
    except Exception as exc:  # noqa: BLE001
        result["reason"] = str(exc)
        return result
    result["available"] = True
    result["status"] = payload.get("status")
    result["hard_predicates"] = sorted(
        {
            str(b.get("predicate") or "")
            for b in (payload.get("blockers") or [])
            if str(b.get("predicate") or "")
        }
    )
    result["advisory_predicates"] = sorted(
        {
            str(w.get("predicate") or "")
            for w in (payload.get("warnings") or [])
            if str(w.get("predicate") or "")
        }
    )
    return result


def _harness_blockers(row: dict[str, Any]) -> list[str]:
    harness = (
        row.get("cosmos_harness_exec")
        or row.get("cosmos_production_harness_exec")
        or row.get("production_harness_execution")
        or row.get("harness_execution")
    )
    if not isinstance(harness, dict):
        return []
    blockers: list[str] = []
    preflight = harness.get("preflight") if isinstance(harness.get("preflight"), dict) else {}
    execution = harness.get("execution") if isinstance(harness.get("execution"), dict) else {}
    if preflight.get("execution_allowed") is False or str(preflight.get("phase_a_verdict") or "").lower() in {"needs_work", "blocked"}:
        blockers.append("cosmos_harness_preflight_blocked")
    if execution.get("attempted") is False or harness.get("runtime_proof_claimed") is False:
        blockers.append("production_harness_execution_not_attempted")
    planned = str(row.get("planned_evidence_class") or row.get("proof_path") or "").lower()
    schema_tool = f"{harness.get('schema') or ''} {harness.get('tool') or ''}".lower()
    if "foundry" in planned and ("cosmos" in schema_tool or "go" in schema_tool):
        blockers.append("harness_domain_mismatch")
    return blockers


def _candidate_key(value: Any) -> str:
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "-", str(value or "").strip()).strip("-")
    return safe or "candidate"


def _augment_with_workspace_artifacts(row: dict[str, Any], workspace: Path | None) -> dict[str, Any]:
    if workspace is None:
        return row
    if any(key in row for key in ("cosmos_harness_exec", "cosmos_production_harness_exec", "production_harness_execution")):
        return row
    candidate_id = row.get("lead_id") or row.get("candidate_id") or row.get("id") or row.get("title")
    safe = _candidate_key(candidate_id).lower()
    for path in (
        workspace / "poc_execution" / safe / "cosmos_production_harness_exec.json",
        workspace / "poc_execution" / safe.upper() / "cosmos_production_harness_exec.json",
    ):
        if not path.is_file():
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if isinstance(payload, dict):
            updated = dict(row)
            updated["cosmos_harness_exec"] = payload
            return updated
    return row


def _load_severity_text(workspace: Path | None, severity_file: Path | None) -> str:
    candidates: list[Path] = []
    if severity_file:
        candidates.append(severity_file)
    if workspace:
        candidates.extend([workspace / "SEVERITY.md", workspace / "severity.md"])
    for path in candidates:
        try:
            if path.is_file():
                return path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
    return ""


def _rubric_found_in_severity_file(rubric: str, severity_text: str) -> bool:
    if not severity_text:
        return True
    needle = re.sub(r"\s+", " ", rubric.strip()).lower()
    haystack = re.sub(r"\s+", " ", severity_text).lower()
    if not needle:
        return False
    return needle in haystack


def assess(row: dict[str, Any], source_type: str, severity_text: str = "", workspace: Path | None = None) -> dict[str, Any]:
    row = _augment_with_workspace_artifacts(row, workspace)
    text = _row_text(row)
    if row.get("raw_draft_text"):
        text += "\n" + str(row["raw_draft_text"])
    semantic_text = _semantic_stress_text(text)
    severity = _normalize_sev(_field_answer(row, "claimed_severity", "likely_severity", "severity", "severity_tier"))
    high_plus = _is_high_plus(severity)

    permissionless = _field_answer(row, "permissionless_action", "attacker_action", "trigger")
    attacker_control = str(row.get("attacker_control") or "").strip().lower()
    permissionless_ok = _permissionless_action_ok(permissionless, attacker_control)
    if not permissionless and attacker_control in {"known", "yes", "unprivileged"}:
        permissionless = f"attacker_control={attacker_control}; exact action not written"
        permissionless_ok = False

    flags = _privileged_flags(text)
    rubric = _rubric_answer(row)
    rubric_ok = bool(rubric and rubric.lower() not in {"unknown", "n/a", "na", "none", "todo", "missing"})
    rubric_in_source = _rubric_found_in_severity_file(rubric, severity_text) if rubric_ok else False
    prior, prior_refs = _prior_status(row)
    prior_ok = prior == "clean"
    evidence = _required_evidence(row, text, severity)
    missing_econ = _missing_economics_fields(row, semantic_text)
    missing_window_or_oos = _missing_execution_window_or_oos(semantic_text)
    missing_one_fix = _missing_one_fix_discussion(semantic_text)
    missing_oos_asset_primacy = _missing_oos_asset_primacy(semantic_text)
    ambient_mev_no_fault = _ambient_mev_without_protocol_fault(semantic_text)
    natural_activity_risk = _natural_network_activity_scope_risk(semantic_text)
    intended_actor_mismatch = _intended_actor_mismatch(semantic_text)
    economically_negative = _economically_negative_claim(semantic_text)
    harness_blockers = _harness_blockers(row)

    # A4: economics-viability and actor-model gate.
    economics_relevant = _is_economics_relevant(row, semantic_text)
    econ_numbers = _economics_numbers(row, semantic_text)
    numeric_negative_economics = econ_numbers["net_economics"] == "negative"
    admin_pause_prereq = _admin_pause_prerequisite(semantic_text)

    # HACKERMAN_V3 Lane J5a: consume the shared outcome-lesson classifier. Its
    # hard predicates are pre-PoC fail conditions. The lesson predicate
    # definitions live ONLY in tools/outcome-lesson-gate.py.
    #
    # Negation discipline: the shared classifier's regexes are not
    # negation-aware. For the predicates that DO have a negation-aware A4
    # sibling in this file, the A4 sibling is the applicability filter (the
    # classifier still owns the predicate *definition*; the A4 result only
    # decides whether the text actually asserts the trap vs negates it). For
    # predicates with no A4 sibling, the classifier is the sole authority.
    outcome_lesson = _shared_outcome_lesson_predicates(text)
    _OUTCOME_LESSON_A4_SIBLING_PRESENT = {
        "economic_viability_missing": bool(
            missing_econ or economically_negative or numeric_negative_economics
        ),
        "intended_actor_mismatch": bool(intended_actor_mismatch),
        "ambient_mev_not_protocol_bug": bool(ambient_mev_no_fault),
        "admin_or_team_action_prerequisite": bool(flags or admin_pause_prereq),
    }
    outcome_lesson_hard_predicates = [
        predicate
        for predicate in outcome_lesson.get("hard_predicates", [])
        if _OUTCOME_LESSON_A4_SIBLING_PRESENT.get(predicate, True)
    ]

    blocked: list[str] = []
    warnings: list[str] = []
    # A4: economics/scope-specific blockers are tracked separately so the
    # verdict can route to blocked_by_economics / blocked_by_scope rather than
    # the generic "fail".
    economics_blockers: list[str] = []
    scope_blockers: list[str] = []

    if high_plus:
        if not permissionless_ok:
            blocked.append("missing_or_vague_permissionless_action")
        if flags:
            blocked.append("privileged_mock_oos_or_synthetic_dependency_present")
        if not rubric_ok:
            blocked.append("missing_exact_rubric_row")
        elif severity_text and not rubric_in_source:
            blocked.append("rubric_row_not_found_in_severity_file")
        if prior in {"known_dupe", "possible_dupe", "not_checked"}:
            blocked.append(f"prior_disclosure_{prior}")
        if evidence["incompatible_planned_evidence"]:
            blocked.extend(evidence["incompatible_planned_evidence"])
        if missing_econ:
            economics_blockers.append("missing_economics_proof_for_value_claim")
        if missing_window_or_oos:
            blocked.append("missing_execution_window_or_oos_distinction")
        if missing_one_fix:
            blocked.append("missing_unified_report_or_one_fix_discussion")
        if missing_oos_asset_primacy:
            scope_blockers.append("missing_primacy_of_impact_for_oos_asset_claim")
        if ambient_mev_no_fault:
            scope_blockers.append("ambient_mev_without_protocol_fault_distinction")
        if natural_activity_risk:
            scope_blockers.append("natural_network_activity_scope_risk")
        if intended_actor_mismatch:
            scope_blockers.append("intended_actor_mismatch")
        if economically_negative:
            economics_blockers.append("economically_negative_or_unprofitable_claim")
        if numeric_negative_economics:
            economics_blockers.append("extractable_value_below_required_cost")
        if admin_pause_prereq:
            scope_blockers.append("admin_pause_or_team_action_prerequisite")
        # J5a: route the shared classifier's hard predicates into the same
        # economics/scope blocker lists. Predicate names are prefixed so they
        # are distinct from the A4 in-file blockers (no logic is duplicated -
        # the classifier is the single source of the predicate definition).
        for predicate in outcome_lesson_hard_predicates:
            route = OUTCOME_LESSON_ROUTING.get(predicate, "scope")
            code = f"outcome_lesson_{predicate}"
            if route == "economics":
                economics_blockers.append(code)
            else:
                scope_blockers.append(code)
        blocked.extend(economics_blockers)
        blocked.extend(scope_blockers)
        blocked.extend(harness_blockers)
    else:
        if not permissionless_ok:
            warnings.append("permissionless_action_incomplete")
        if flags:
            warnings.append("privileged_or_oos_dependency_needs_review")
        if not rubric_ok:
            warnings.append("rubric_row_missing")
        if prior != "clean":
            warnings.append(f"prior_disclosure_{prior}")
        if missing_econ:
            warnings.append("missing_economics_proof_for_value_claim")
        if missing_window_or_oos:
            warnings.append("missing_execution_window_or_oos_distinction")
        if missing_one_fix:
            warnings.append("missing_unified_report_or_one_fix_discussion")
        if missing_oos_asset_primacy:
            warnings.append("missing_primacy_of_impact_for_oos_asset_claim")
        if ambient_mev_no_fault:
            warnings.append("ambient_mev_without_protocol_fault_distinction")
        if natural_activity_risk:
            warnings.append("natural_network_activity_scope_risk")
        if intended_actor_mismatch:
            warnings.append("intended_actor_mismatch")
        if economically_negative:
            warnings.append("economically_negative_or_unprofitable_claim")
        if numeric_negative_economics:
            warnings.append("extractable_value_below_required_cost")
        if admin_pause_prereq:
            warnings.append("admin_pause_or_team_action_prerequisite")
        for predicate in outcome_lesson_hard_predicates:
            warnings.append(f"outcome_lesson_{predicate}")
        warnings.extend(harness_blockers)

    verdict = "pass"
    if blocked:
        verdict = "fail"
    elif warnings:
        verdict = "warn"

    # A4: route an economics/scope-only failure to a dedicated verdict_route so
    # downstream consumers send the candidate to blocked_by_economics /
    # blocked_by_scope instead of PoC. verdict stays {pass,warn,fail} for
    # backward compatibility; verdict_route is the A4-specific refinement.
    #
    # privileged_mock_oos_or_synthetic_dependency_present is a scope-class
    # concern (the path is outside the permissionless scope) so it is counted
    # as a scope blocker for routing purposes even though it stays in `blocked`
    # under its original name for backward compatibility.
    SCOPE_CLASS_BLOCKERS = {"privileged_mock_oos_or_synthetic_dependency_present"}
    verdict_route = verdict
    if verdict == "fail":
        effective_scope = list(scope_blockers) + [b for b in blocked if b in SCOPE_CLASS_BLOCKERS]
        non_econ_scope = [
            b for b in blocked
            if b not in economics_blockers
            and b not in scope_blockers
            and b not in SCOPE_CLASS_BLOCKERS
        ]
        if economics_blockers and not non_econ_scope and not effective_scope:
            verdict_route = "blocked_by_economics"
        elif effective_scope and not non_econ_scope and not economics_blockers:
            verdict_route = "blocked_by_scope"
        elif (economics_blockers or effective_scope) and not non_econ_scope:
            # both economics and scope blockers, no other blockers: economics
            # is the harder gate (a net-negative path is never worth PoC).
            verdict_route = "blocked_by_economics" if economics_blockers else "blocked_by_scope"

    candidate_id = str(row.get("lead_id") or row.get("candidate_id") or row.get("id") or row.get("title") or "candidate")
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at_utc": _now(),
        "candidate_id": candidate_id,
        "source_type": source_type,
        "claimed_severity": severity,
        "high_plus_gate_applied": high_plus,
        "verdict": verdict,
        "verdict_route": verdict_route,
        "status": verdict,
        "blocked_reasons": blocked,
        "blockers": blocked,
        "economics_blockers": economics_blockers,
        "scope_blockers": scope_blockers,
        "outcome_lesson_gate": {
            "available": outcome_lesson.get("available", False),
            "status": outcome_lesson.get("status"),
            "hard_predicates_classifier": outcome_lesson.get("hard_predicates", []),
            "hard_predicates_routed": outcome_lesson_hard_predicates,
            "advisory_predicates": outcome_lesson.get("advisory_predicates", []),
            "reason": outcome_lesson.get("reason", ""),
        },
        "warnings": warnings,
        "questions": {
            "permissionless_action": {
                "answer": permissionless or "",
                "status": "pass" if permissionless_ok else "fail" if high_plus else "warn",
                "attacker_control": attacker_control or "not_declared",
            },
            "privileged_or_mock_dependency": {
                "status": "fail" if flags and high_plus else "warn" if flags else "pass",
                "flags": flags,
            },
            "rubric_row": {
                "answer": rubric or "",
                "status": "pass" if rubric_ok and rubric_in_source else "fail" if high_plus else "warn",
                "workspace_severity_file_checked": bool(severity_text),
                "found_in_workspace_severity_file": bool(rubric_in_source),
            },
            "prior_disclosure": {
                "status": prior,
                "gate_status": "pass" if prior_ok else "fail" if high_plus else "warn",
                "citations": prior_refs,
            },
            "economics": {
                "status": "fail" if missing_econ and high_plus else "warn" if missing_econ else "pass",
                "missing_fields": missing_econ,
                "economics_relevant": economics_relevant,
            },
            "economic_viability": {
                "status": (
                    "fail" if (numeric_negative_economics or economically_negative) and high_plus
                    else "warn" if numeric_negative_economics or economically_negative
                    else "pass"
                ),
                "net_economics": econ_numbers["net_economics"],
                "extractable_value_usd": econ_numbers["extractable_value_usd"],
                "extractable_value_source": econ_numbers["extractable_value_source"],
                "required_cost_usd": econ_numbers["required_cost_usd"],
                "required_cost_source": econ_numbers["required_cost_source"],
            },
            "admin_pause_prerequisite": {
                "status": "fail" if admin_pause_prereq and high_plus else "warn" if admin_pause_prereq else "pass",
            },
            "execution_window_oos": {
                "status": "fail" if missing_window_or_oos and high_plus else "warn" if missing_window_or_oos else "pass",
            },
            "one_fix_duplicate_risk": {
                "status": "fail" if missing_one_fix and high_plus else "warn" if missing_one_fix else "pass",
            },
            "oos_asset_primacy": {
                "status": "fail" if missing_oos_asset_primacy and high_plus else "warn" if missing_oos_asset_primacy else "pass",
            },
            "mev_protocol_fault_distinction": {
                "status": "fail" if ambient_mev_no_fault and high_plus else "warn" if ambient_mev_no_fault else "pass",
            },
            "natural_network_activity": {
                "status": "fail" if natural_activity_risk and high_plus else "warn" if natural_activity_risk else "pass",
            },
            "intended_actor": {
                "status": "fail" if intended_actor_mismatch and high_plus else "warn" if intended_actor_mismatch else "pass",
            },
            "negative_economics": {
                "status": "fail" if economically_negative and high_plus else "warn" if economically_negative else "pass",
            },
            "production_harness": {
                "status": "fail" if harness_blockers and high_plus else "warn" if harness_blockers else "pass",
                "blockers": harness_blockers,
            },
        },
        "evidence_plan": evidence,
        "next_action": _next_action(verdict, blocked, warnings, evidence, verdict_route),
    }


def _next_action(
    verdict: str,
    blocked: list[str],
    warnings: list[str],
    evidence: dict[str, Any],
    verdict_route: str = "",
) -> str:
    if verdict == "pass":
        return "Candidate may proceed to PoC planning using evidence_plan.requirements."
    if verdict == "warn" and warnings:
        return "Resolve warnings before spending High/Critical PoC effort, or keep this as lower-severity/advisory work."
    if verdict_route == "blocked_by_economics":
        return ("Route to blocked_by_economics: extractable value does not cover required "
                "bond/capital/cost. Do NOT spend PoC effort unless a sourced positive-EV "
                "profit model is written.")
    if verdict_route == "blocked_by_scope":
        return ("Route to blocked_by_scope: the path is only reachable after project-side "
                "emergency action or relies on ambient activity / wrong actor. Do NOT spend "
                "PoC effort unless an in-scope, permissionless, protocol-fault path is proven.")
    if "extractable_value_below_required_cost" in blocked:
        return ("Route to blocked_by_economics: extractable value is below the required "
                "bond/capital/cost. Write a sourced positive-EV model or kill the candidate.")
    if "admin_pause_or_team_action_prerequisite" in blocked:
        return ("Route to blocked_by_scope: the impact only exists after an admin pause / "
                "team emergency action. Prove a permissionless path or kill the candidate.")
    if "missing_or_vague_permissionless_action" in blocked:
        return "Write the exact unprivileged attacker transaction/action before dispatching PoC work."
    if "privileged_mock_oos_or_synthetic_dependency_present" in blocked:
        return "Kill, reframe, or prove a privilege-bypass/production-state path before PoC work."
    if "ambient_mev_without_protocol_fault_distinction" in blocked:
        return "Prove the protocol fault exists independently of ordinary MEV/sandwich ordering, or kill the candidate."
    if "natural_network_activity_scope_risk" in blocked:
        return "Prove the path breaks a protocol invariant beyond ordinary permissionless network activity, or kill the candidate."
    if "intended_actor_mismatch" in blocked:
        return "Bind the attacker to the protocol-authorized actor/capability, or kill/reframe the candidate."
    if "economically_negative_or_unprofitable_claim" in blocked:
        return "Write a sourced profit/cost model showing positive attacker economics before PoC work."
    if "missing_exact_rubric_row" in blocked:
        return "Map the candidate to a verbatim in-scope rubric row before PoC work."
    if any(b.startswith("prior_disclosure_") for b in blocked):
        return "Run prior disclosure/originality check and write a Q1/Q2 rebuttal before PoC work."
    if evidence.get("incompatible_planned_evidence"):
        return "Change the planned PoC shape to satisfy the required evidence class before coding."
    return "Resolve blocked_reasons before PoC work."


def _artifact_path(workspace: Path, candidate_id: str) -> Path:
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "-", candidate_id).strip("-") or "candidate"
    return workspace / ".auditooor" / "prefiling_stress_tests" / f"{safe}.prefiling_stress_test.json"


def _result_md(result: dict[str, Any]) -> str:
    lines = [
        f"# Prefiling Stress Test: {result['candidate_id']}",
        "",
        f"- Status: {str(result['verdict']).upper()}",
        f"- Route: {result.get('verdict_route', result['verdict'])}",
        f"- Claimed severity: {result['claimed_severity']}",
    ]
    if result.get("blocked_reasons"):
        lines.append("- Blockers:")
        lines.extend(f"  - {reason}" for reason in result["blocked_reasons"])
    if result.get("warnings"):
        lines.append("- Warnings:")
        lines.extend(f"  - {warning}" for warning in result["warnings"])
    lines.extend([
        "",
        "## Next Action",
        result.get("next_action", ""),
    ])
    return "\n".join(lines).rstrip() + "\n"


def _aggregate_md(aggregate: dict[str, Any]) -> str:
    summary = aggregate.get("summary", {})
    lines = [
        "# Prefiling Stress Test",
        "",
        f"- Rows assessed: {aggregate.get('rows_assessed', 0)}",
        f"- Fail: {summary.get('fail', 0)}",
        f"- Warn: {summary.get('warn', 0)}",
        f"- Pass: {summary.get('pass', 0)}",
        "",
        "## Results",
    ]
    for result in aggregate.get("results", []):
        lines.append(f"- {str(result.get('verdict', '')).upper()} {result.get('candidate_id', 'candidate')}")
        for reason in result.get("blocked_reasons", [])[:5]:
            lines.append(f"  - {reason}")
    return "\n".join(lines).rstrip() + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("--candidate-row", type=Path, help="JSON object for one exploit-queue/candidate row")
    src.add_argument("--draft", type=Path, help="Markdown draft to evaluate")
    src.add_argument("--exploit-queue", type=Path, help="exploit_queue.json; assess top queue rows")
    parser.add_argument("--workspace", type=Path, default=None, help="Workspace path for default artifact output")
    parser.add_argument("--severity-file", type=Path, default=None, help="Optional SEVERITY.md to require verbatim rubric row matches")
    parser.add_argument("--out", type=Path, default=None, help="Write JSON artifact to this path")
    parser.add_argument("--top-n", type=int, default=10, help="Rows to assess from --exploit-queue (default: 10)")
    parser.add_argument("--strict", action="store_true", help="Fail on warnings or when no proof-eligible rows remain")
    parser.add_argument("--json", action="store_true", help="Print JSON")
    parser.add_argument("--print-md", action="store_true", help="Print a Markdown summary instead of JSON/default status text")
    args = parser.parse_args(argv)

    workspace_for_severity = args.workspace.expanduser().resolve() if args.workspace else None
    severity_text = _load_severity_text(workspace_for_severity, args.severity_file.expanduser().resolve() if args.severity_file else None)

    if args.exploit_queue:
        q = _read_json(args.exploit_queue)
        rows = q.get("queue") or q.get("rows") or []
        if not isinstance(rows, list):
            raise SystemExit(f"exploit queue has no queue/rows list: {args.exploit_queue}")
        try:
            if workspace_for_severity is None:
                raise SystemExit("typed proof queue rejected: typed_proof_envelope_workspace_required")
            typed_entries = _typed_queue_entries(
                q, workspace=workspace_for_severity,
                queue_path=args.exploit_queue.expanduser().resolve(),
            )
        except ValueError as exc:
            raise SystemExit(f"typed proof queue rejected: {exc}") from exc

        def is_terminal(row: dict[str, Any]) -> bool:
            if typed_entries is None:
                return _is_terminal_queue_row(row)
            lead_id = row.get("lead_id")
            if not isinstance(lead_id, str) or lead_id not in typed_entries:
                raise SystemExit("typed proof queue rejected: typed_proof_envelope_row_missing")
            return _is_terminal_queue_row(row, typed_entries[lead_id])

        skipped_terminal = sum(1 for r in rows if isinstance(r, dict) and is_terminal(r))
        non_proof_rows = [
            r for r in rows
            if isinstance(r, dict) and _is_non_proof_queue_row(r)
        ]
        unresolved_non_proof = [
            r
            for r in non_proof_rows
            if not is_terminal(r)
        ]
        # Explicitly non-proof rows are coverage/telemetry material, not proof
        # obligations. Once this queue also contains at least one corroborated
        # terminal disposition, they cannot create a vacuous strict failure. A
        # queue made only of non-proof rows remains blocked below.
        if skipped_terminal:
            unresolved_non_proof = []
        skipped_non_proof = len(non_proof_rows) - len(unresolved_non_proof)
        proof_eligible_rows = [
            r
            for r in rows
            if isinstance(r, dict)
            and not is_terminal(r)
            and not _is_non_proof_queue_row(r)
        ]
        # TOP_N is a concurrency/triage batch limit, never a completeness
        # boundary.  Zero means assess every proof-eligible row here.
        selected = proof_eligible_rows if args.top_n <= 0 else proof_eligible_rows[: args.top_n]
        results = [assess(r, "exploit_queue_row", severity_text=severity_text, workspace=workspace_for_severity) for r in selected]
        workspace = workspace_for_severity
        if workspace:
            for result in results:
                p = _artifact_path(workspace, result["candidate_id"])
                p.parent.mkdir(parents=True, exist_ok=True)
                result["artifact_path"] = str(p)
                p.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        aggregate = {
            "schema_version": SCHEMA_VERSION,
            "generated_at_utc": _now(),
            "source_type": "exploit_queue",
            "queue_path": str(args.exploit_queue),
            "workspace": str(workspace) if workspace else None,
            "top_n": args.top_n,
            "rows_assessed": len(results),
            "terminal_rows_skipped": skipped_terminal,
            "non_proof_rows_skipped": skipped_non_proof,
            # A non-proof classification is not a terminal verdict by itself.
            # Keep unresolved rows visible so missing source/linkage evidence
            # cannot silently disappear before proof review.
            "unresolved_non_proof_rows": len(unresolved_non_proof),
            "proof_eligible_rows_total": len(proof_eligible_rows),
            "proof_eligible_rows_unassessed": max(0, len(proof_eligible_rows) - len(selected)),
            "summary": {
                "pass": sum(1 for r in results if r["verdict"] == "pass"),
                "warn": sum(1 for r in results if r["verdict"] == "warn"),
                "fail": sum(1 for r in results if r["verdict"] == "fail"),
            },
            "results": results,
        }
        strict_blockers = []
        if args.strict and unresolved_non_proof:
            strict_blockers.append("unresolved_non_proof_rows")
        if args.strict and len(selected) < len(proof_eligible_rows):
            strict_blockers.append("proof_eligible_rows_truncated")
        # A non-empty queue can legitimately contain terminal rows plus
        # explicitly non-proof coverage rows. Once terminal corroboration is
        # present, there is no proof-eligible work left for this stage and the
        # no-leads producer can make the bounded honest disposition. Keep the
        # hard block for a queue with only non-proof, non-terminal rows.
        if args.strict and not selected and skipped_non_proof and not skipped_terminal:
            strict_blockers.append("no_proof_eligible_rows_remaining")
        if args.strict and aggregate["summary"]["warn"]:
            strict_blockers.append("prefiling_warnings_present")
        if strict_blockers:
            aggregate["strict_blockers"] = strict_blockers
        out = args.out
        if out is None and workspace:
            out = workspace / ".auditooor" / "prefiling_stress_test.json"
        if out:
            out = out.expanduser().resolve()
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(json.dumps(aggregate, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            aggregate["artifact_path"] = str(out)
        if args.print_md:
            print(_aggregate_md(aggregate), end="")
        elif args.json or not out:
            print(json.dumps(aggregate, indent=2, sort_keys=True))
        else:
            print(f"{aggregate['summary']['fail']} FAIL / {aggregate['summary']['warn']} WARN / {aggregate['summary']['pass']} PASS -> {out}")
        if strict_blockers:
            if out:
                out.write_text(json.dumps(aggregate, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            return 1
        return 1 if aggregate["summary"]["fail"] else 0

    if args.candidate_row:
        row = _read_json(args.candidate_row)
        source_type = "candidate_row"
    else:
        row = _draft_to_row(args.draft)
        source_type = "draft"

    result = assess(row, source_type, severity_text=severity_text, workspace=workspace_for_severity)
    out = args.out
    if out is None and args.workspace:
        out = _artifact_path(args.workspace.expanduser().resolve(), result["candidate_id"])
    if out:
        out = out.expanduser().resolve()
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        result["artifact_path"] = str(out)

    if args.print_md:
        print(_result_md(result), end="")
    elif args.json or not out:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(f"{result['verdict'].upper()} {result['candidate_id']} -> {out}")

    if result["verdict"] == "fail":
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
