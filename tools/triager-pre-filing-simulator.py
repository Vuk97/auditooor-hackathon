#!/usr/bin/env python3
"""P4 triager precheck and optional provider-backed simulation.

The default path is a deterministic rules MVP over
reference/triager_patterns.json and a small workspace duplicate scan. It does
not call an LLM provider, sets provider-backed capability flags to false, and
does not emit a predicted triager verdict. It can emit local advisory
silent-kill class predictions; those are deterministic hardening hints, not
provider-backed simulation or triager clearance.

The opt-in ``--provider-backed`` path shells through ``tools/llm-dispatch.py``.
That dispatcher enforces live-network consent and provider auth. Provider
output remains advisory and cannot clear pre-submit, scope, originality, or
severity gates by itself.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from lib.triager_precheck_schema import (
    NO_MATCH_WARNING,
    blank_class_votes,
    blank_silent_kill_votes,
    build_packet,
    relpath,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
TRIAGER_PATTERNS_PATH = REPO_ROOT / "reference" / "triager_patterns.json"
TRIAGER_DISPOSITION_CLASSIFIER_PATH = REPO_ROOT / "reference" / "triager_disposition_classifier.json"
MAX_MATCHED_PATTERNS = 8
MAX_DUPLICATE_REFS = 5

CAPABILITY_BOUNDARY = {
    "local_rules_mvp": True,
    "provider_dispatch": False,
    "provider_backed_simulation": False,
    "predicted_triager_verdict": False,
    "triager_verdict_or_clearance": False,
}
PROVIDER_CAPABILITY_BOUNDARY = {
    "local_rules_mvp": True,
    "provider_dispatch": True,
    "provider_backed_simulation": True,
    "predicted_triager_verdict": True,
    "triager_verdict_or_clearance": False,
}
PROVIDER_BLOCKED_CAPABILITY_BOUNDARY = {
    "local_rules_mvp": True,
    "provider_dispatch": False,
    "provider_backed_simulation": False,
    "predicted_triager_verdict": False,
    "triager_verdict_or_clearance": False,
}
PROVIDER_PROMPT_VERSION = "p4-provider-backed-v2"
PROVIDER_ALLOWED_VERDICTS = {
    "likely_accept",
    "likely_reject",
    "likely_duplicate",
    "likely_oos",
    "needs_more_proof",
    "uncertain",
}
CLASS_TO_MIND_CHECK_IDS = {
    "duplicate": ["duplicate_or_acknowledged"],
    "no_fund_impact": ["non_self_value_movement", "event_or_cosmetic_only", "independent_loss_path"],
    "dos": ["production_grade_evidence"],
    "design_intended": ["design_intent_boundary"],
    "event_only": ["event_or_cosmetic_only", "non_self_value_movement"],
    "user_error": ["independent_loss_path", "non_self_value_movement"],
    "reachability": ["realistic_reachability"],
}
MIND_MODEL_CHECKS = [
    {
        "check_id": "non_self_value_movement",
        "linked_classes": ["no_fund_impact", "event_only", "user_error"],
        "question": (
            "Does the finding move, freeze, or burn assets owned by someone other than "
            "the attacker, with a concrete balance/state delta?"
        ),
        "risk_terms": [
            "no fund loss",
            "no user fund loss",
            "no direct loss",
            "no functional impact",
            "informational",
            "self-harm",
            "victim is the attacker",
        ],
        "rebuttal_terms": [
            "non-self victim",
            "attacker can steal",
            "attacker steals",
            "drain funds",
            "drains funds",
            "balance delta",
            "victim balance",
            "user funds are frozen",
            "permanent loss of user funds",
            "value movement",
        ],
        "suggested_strengthening": (
            "Add actor-separated pre/post balances and a non-self victim path before "
            "claiming security impact."
        ),
    },
    {
        "check_id": "event_or_cosmetic_only",
        "linked_classes": ["event_only", "no_fund_impact"],
        "question": (
            "If the visible symptom is an event/log/reporting error, does it drive a "
            "downstream functional failure or value movement?"
        ),
        "risk_terms": [
            "only affects event emission",
            "event emission",
            "incorrect event",
            "wrong event",
            "event topic",
            "logs only",
            "cosmetic",
        ],
        "rebuttal_terms": [
            "downstream functional failure",
            "downstream consumer",
            "downstream accounting",
            "state transition",
            "value movement",
            "attacker can steal",
            "drain funds",
            "liquidation",
        ],
        "suggested_strengthening": (
            "Show the downstream consumer or state transition that makes the event "
            "load-bearing."
        ),
    },
    {
        "check_id": "independent_loss_path",
        "linked_classes": ["user_error", "no_fund_impact"],
        "question": "Would the user lose anyway without the bug, or is the bug the independent loss cause?",
        "risk_terms": [
            "user error",
            "user uses unrelated txid",
            "user is already facing fund loss",
            "receiver must verify",
            "counterparty risk",
            "self-harm",
        ],
        "rebuttal_terms": [
            "victim cannot avoid",
            "ordinary verification cannot prevent",
            "attacker controlled",
            "non-self victim",
            "independent of user error",
        ],
        "suggested_strengthening": (
            "Separate attacker, victim, payer, and preventer, then prove the loss does "
            "not reduce to user/self-error."
        ),
    },
    {
        "check_id": "realistic_reachability",
        "linked_classes": ["reachability"],
        "question": "What real-world setup produces the PoC initial state without mocks or impossible values?",
        "risk_terms": [
            "theoretical",
            "hypothetical",
            "not practically reachable",
            "no realistic scenario",
            "no concrete exploit",
            "genesis-seeded",
            "makeramount > 2^248",
            "2^248",
            "mock verifier",
            "mock oracle",
        ],
        "rebuttal_terms": [
            "fork test",
            "normal entrypoint",
            "permissionless trigger",
            "production path",
            "unmodified production",
            "attacker can create",
            "realistic path",
        ],
        "suggested_strengthening": (
            "Cite the normal entrypoint and production-path setup that creates the bad "
            "state without mocks, genesis seeding, or impossible values."
        ),
    },
    {
        "check_id": "production_grade_evidence",
        "linked_classes": ["dos"],
        "question": "For DoS/liveness claims, is there production-grade impact beyond local pressure?",
        "risk_terms": [
            "generic dos",
            "localized checktx",
            "rpc pressure",
            "rate-limit pressure",
            "timeout is not proof",
            "not only a single-process artifact",
            "synthetic state seeding",
        ],
        "rebuttal_terms": [
            "production entrypoint",
            "block production halt",
            "matching-engine slo",
            "settlement degradation",
            "attacker cost model",
            "comparative run",
            "multi-validator",
        ],
        "suggested_strengthening": (
            "Attach production entrypoint evidence, comparative baseline, and an "
            "attacker-cost-to-impact model."
        ),
    },
    {
        "check_id": "design_intent_boundary",
        "linked_classes": ["design_intended"],
        "question": "Is the contested behavior documented or defended as intentional, and did the draft cross that boundary?",
        "risk_terms": [
            "acknowledged",
            "intended behavior",
            "design choice",
            "expected behavior",
            "by design",
            "architectural",
            "domain-separation-by-design",
        ],
        "rebuttal_terms": [
            "strictly stronger",
            "crosses the intended boundary",
            "non-privileged exploit",
            "value extraction",
            "persistent corruption",
        ],
        "suggested_strengthening": (
            "Quote the design boundary and prove a stronger non-privileged exploit that "
            "the intended design does not cover."
        ),
    },
    {
        "check_id": "duplicate_or_acknowledged",
        "linked_classes": ["duplicate"],
        "question": "Is this the same root cause, one-fix family, or acknowledged/wont-fix issue?",
        "risk_terms": [
            "duplicate",
            "already reported",
            "same issue",
            "same underlying pattern",
            "same bug class",
            "same root cause",
            "acknowledged",
            "wont-fix",
        ],
        "rebuttal_terms": [
            "distinct root cause",
            "one-fix distinction",
            "different vulnerable function",
            "different victim",
            "not same root cause",
        ],
        "suggested_strengthening": (
            "Add a one-fix/root-cause distinction and nearest prior-report comparison."
        ),
    },
]
SILENT_KILL_DEFAULT_CLASSES = [
    {
        "class_key": "duplicate",
        "class_label": "duplicate",
        "pattern_ids": ["R3", "R9", "R10"],
        "evidence_terms": [
            "duplicate",
            "already reported",
            "same issue",
            "same underlying pattern",
            "same bug class",
            "same root cause",
            "multiple finders",
            "workspace title/root-cause overlap",
        ],
        "suggested_strengthening": (
            "Run the duplicate/originality preflight, cite nearest prior reports, "
            "and add a concrete one-fix or root-cause distinction before filing."
        ),
        "confidence_weight": 1.0,
        "rebuttal_terms": [
            "distinct root cause",
            "one-fix distinction",
            "different vulnerable function",
            "different victim",
            "not same root cause",
        ],
        "mind_model_question": MIND_MODEL_CHECKS[6]["question"],
        "rebuttal_mode": "suppress",
    },
    {
        "class_key": "no_fund_impact",
        "class_label": "no-fund-impact",
        "pattern_ids": ["R1", "R6", "R8", "R16"],
        "evidence_terms": [
            "no fund loss demonstrated",
            "no fund loss",
            "no user fund loss",
            "no funds at risk",
            "no direct loss",
            "no functional impact",
            "informational",
            "impact unclear",
            "reconcilable",
            "not rewardable security impact",
        ],
        "suggested_strengthening": (
            "Show a non-self victim, asset owner, concrete balance/state delta, "
            "recoverability analysis, and the exact severity rubric row."
        ),
        "confidence_weight": 0.9,
        "mind_model_question": MIND_MODEL_CHECKS[0]["question"],
    },
    {
        "class_key": "dos",
        "class_label": "DoS",
        "pattern_ids": ["R12", "R13", "R14", "R15"],
        "evidence_terms": [
            "generic dos",
            "denial of service",
            "dos without demonstrated in-scope production impact",
            "localized checktx",
            "rpc pressure",
            "rate-limit pressure",
            "bounded safety-cap exhaustion",
            "no matching-engine or chain-liveness degradation",
            "timeout is not proof",
            "liveness evidence",
            "live halt",
            "deadlock",
            "permanent dos",
        ],
        "suggested_strengthening": (
            "Reframe the impact against the program rubric: prove real production "
            "entrypoint reachability, affected population, duration, restart behavior, "
            "and why this is more than localized or generic DoS."
        ),
        "confidence_weight": 0.86,
        "rebuttal_terms": [
            "production entrypoint",
            "block production halt",
            "matching-engine slo",
            "settlement degradation",
            "attacker cost model",
            "comparative run",
            "multi-validator",
        ],
        "mind_model_question": MIND_MODEL_CHECKS[4]["question"],
        "rebuttal_mode": "suppress",
    },
    {
        "class_key": "design_intended",
        "class_label": "design-intended",
        "pattern_ids": ["R4", "R7"],
        "evidence_terms": [
            "acknowledged",
            "intended behavior",
            "design choice",
            "expected behavior",
            "by design",
            "architectural",
            "domain-separation-by-design",
            "independent",
            "fully collateralized",
        ],
        "suggested_strengthening": (
            "Quote the design or OOS clause, then prove a strictly stronger "
            "non-privileged exploit that crosses the intended boundary with value "
            "extraction or persistent corruption."
        ),
        "confidence_weight": 0.88,
        "rebuttal_terms": [
            "strictly stronger",
            "crosses the intended boundary",
            "non-privileged exploit",
            "value extraction",
            "persistent corruption",
        ],
        "mind_model_question": MIND_MODEL_CHECKS[5]["question"],
        "rebuttal_mode": "suppress",
    },
    {
        "class_key": "event_only",
        "class_label": "event-only",
        "pattern_ids": ["R1"],
        "evidence_terms": [
            "only affects event emission",
            "event emission",
            "incorrect event",
            "wrong event",
            "parameter ordering in logs",
            "event topic",
            "logs only",
            "no functional impact",
        ],
        "suggested_strengthening": (
            "Tie the bad event to a downstream functional failure, state transition, "
            "or value movement; otherwise downgrade or drop the finding."
        ),
        "confidence_weight": 0.95,
        "rebuttal_terms": [
            "downstream functional failure",
            "downstream consumer",
            "downstream accounting",
            "state transition",
            "value movement",
            "attacker can steal",
            "drain funds",
            "liquidation",
        ],
        "mind_model_question": MIND_MODEL_CHECKS[1]["question"],
        "rebuttal_mode": "suppress",
    },
    {
        "class_key": "user_error",
        "class_label": "user-error",
        "pattern_ids": ["R17"],
        "evidence_terms": [
            "user error",
            "user uses unrelated txid",
            "user is already facing fund loss",
            "receiver must verify",
            "counterparty risk",
            "victim is the attacker",
            "self-harm",
        ],
        "required_evidence_terms": [
            "user error",
            "user uses unrelated txid",
            "user is already facing fund loss",
            "receiver must verify",
            "counterparty risk",
            "victim is the attacker",
            "self-harm",
        ],
        "suggested_strengthening": (
            "Add an actor table separating attacker, victim, payer, and preventer; "
            "prove the victim cannot avoid the loss by ordinary verification."
        ),
        "confidence_weight": 0.9,
        "rebuttal_terms": [
            "victim cannot avoid",
            "ordinary verification cannot prevent",
            "attacker controlled",
            "non-self victim",
            "independent of user error",
        ],
        "mind_model_question": MIND_MODEL_CHECKS[2]["question"],
        "rebuttal_mode": "suppress",
    },
    {
        "class_key": "reachability",
        "class_label": "reachability",
        "pattern_ids": ["R2", "R5", "R11", "R14"],
        "evidence_terms": [
            "theoretical",
            "hypothetical",
            "not practically reachable",
            "no realistic scenario",
            "no concrete exploit",
            "please justify this assumption",
            "requires compromised prover/signer",
            "requires compromised",
            "missing root cause",
            "attacker cannot create the prerequisite state",
            "disabled in production",
            "production config",
            "mock verifier",
            "mock oracle",
        ],
        "suggested_strengthening": (
            "Provide a permissionless production-path trigger from normal entrypoint "
            "to bad state, with no mock verifier/oracle, signer compromise, or "
            "project-inaction prerequisite."
        ),
        "confidence_weight": 0.92,
        "rebuttal_terms": [
            "fork test",
            "normal entrypoint",
            "permissionless trigger",
            "production path",
            "unmodified production",
            "attacker can create",
            "realistic path",
        ],
        "mind_model_question": MIND_MODEL_CHECKS[3]["question"],
        "rebuttal_mode": "suppress",
    },
]
CLASSIFIER_DEFAULT = {
    "schema": "auditooor.triager_disposition_classifier.v1",
    "classes": [
        {
            "outcome_class_key": "G_duplicate_or_acknowledged",
            "disposition": "likely_duplicate_or_acknowledged",
            "recommended_action": "add_or_update_originality_and_dupe_distinction_before_filing",
            "confidence_weight": 1.0,
        },
        {
            "outcome_class_key": "E_production_grade_evidence_gap",
            "disposition": "needs_more_production_evidence",
            "recommended_action": "upgrade_production_path_evidence_before_filing",
            "confidence_weight": 0.9,
        },
        {
            "outcome_class_key": "F_no_fund_impact_or_actor_model",
            "disposition": "needs_non_self_impact_or_actor_model",
            "recommended_action": "strengthen_non_self_impact_or_actor_model_before_filing",
            "confidence_weight": 0.85,
        },
        {
            "outcome_class_key": "F_prime_reachability_realism",
            "disposition": "needs_realistic_reachability_proof",
            "recommended_action": "justify_realistic_reachability_before_filing",
            "confidence_weight": 0.8,
        },
        {
            "outcome_class_key": "D_oos_infra_or_deployment",
            "disposition": "likely_scope_gap",
            "recommended_action": "resolve_scope_or_deployment_evidence_before_filing",
            "confidence_weight": 0.75,
        },
        {
            "outcome_class_key": "C_designed_as_intended",
            "disposition": "likely_designed_as_intended_gap",
            "recommended_action": "address_designed_as_intended_counterargument_before_filing",
            "confidence_weight": 0.75,
        },
        {
            "outcome_class_key": "A_rubric_mismatch",
            "disposition": "review_rubric_fit",
            "recommended_action": "review_matched_triager_patterns_before_filing",
            "confidence_weight": 0.65,
        },
    ],
    "silent_kill_classes": SILENT_KILL_DEFAULT_CLASSES,
}

# r36-rebuttal: lane-TRIAGER-MINDSET-WIRE registered via tools/agent-pathspec-register.py
# (.auditooor/agent_pathspec.json includes tools/triager-pre-filing-simulator.py)
OUTCOME_CLASS_BY_PATTERN_ID = {
    "R1": ("F", "F_no_fund_impact_or_actor_model"),
    "R2": ("F-prime", "F_prime_reachability_realism"),
    "R3": ("G", "G_duplicate_or_acknowledged"),
    "R4": ("G", "G_duplicate_or_acknowledged"),
    "R5": ("F-prime", "F_prime_reachability_realism"),
    "R6": ("A", "A_rubric_mismatch"),
    "R7": ("C", "C_designed_as_intended"),
    "R8": ("F", "F_no_fund_impact_or_actor_model"),
    "R9": ("G", "G_duplicate_or_acknowledged"),
    "R10": ("G", "G_duplicate_or_acknowledged"),
    "R11": ("D", "D_oos_infra_or_deployment"),
    "R12": ("E", "E_production_grade_evidence_gap"),
    "R13": ("E", "E_production_grade_evidence_gap"),
    "R14": ("D", "D_oos_infra_or_deployment"),
    "R15": ("E", "E_production_grade_evidence_gap"),
    "R16": ("F", "F_no_fund_impact_or_actor_model"),
    "R17": ("F", "F_no_fund_impact_or_actor_model"),
    # R18-R23 added 2026-05-26 by lane TRIAGER-MINDSET-WIRE (Rule 62 codification).
    # Empirical anchors documented in reference/triager_patterns.json:
    # R18 token-economics-structural-bound -> DRILL-6 (Hyperbridge pallet-relayer u256 truncation)
    # R19 multi-actor-defender-narrative   -> Spark v10 (cooperative-exit FROST signer attribution)
    # R20 in-process-microbench            -> cantina-213 (codec sub-call cap microbench)
    # R21 fault-shim-manufactured          -> cantina-201 (slowBatchDB), cantina-202 (reflection)
    # R22 oos-trusted-infra-or-restricted-population -> Polymarket cantina-84 (POLY_1271)
    # R23 acknowledged-by-design-omission  -> Hyperbridge OP L2Oracle Informative downgrade
    "R18": ("F-prime", "F_prime_reachability_realism"),
    "R19": ("F", "F_no_fund_impact_or_actor_model"),
    "R20": ("E", "E_production_grade_evidence_gap"),
    "R21": ("E", "E_production_grade_evidence_gap"),
    "R22": ("D", "D_oos_infra_or_deployment"),
    "R23": ("C", "C_designed_as_intended"),
}

STOP_TERMS = {
    "issue",
    "proof",
    "state",
    "token",
    "user",
}

WORD_RE = re.compile(r"[a-z0-9][a-z0-9_/-]{2,}", re.IGNORECASE)
HEADING_RE = re.compile(r"(?m)^\s*#\s+(.+?)\s*$")


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _split_terms(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    terms: list[str] = []
    for raw in value:
        term = str(raw).strip().strip("`\"'").lower()
        if len(term) < 4 or term in STOP_TERMS:
            continue
        terms.append(term)
    return terms


def _pattern_terms(row: dict[str, Any]) -> list[str]:
    terms = [
        *_split_terms(row.get("triggers")),
        *_split_terms(row.get("triager_language")),
    ]
    for field in ("name", "description", "pre_submit_guard"):
        text = str(row.get(field) or "").lower()
        for quoted in re.findall(r"`([^`]{4,80})`|\"([^\"]{4,80})\"", text):
            candidate = (quoted[0] or quoted[1]).strip().lower()
            if candidate and candidate not in STOP_TERMS:
                terms.append(candidate)
    seen: set[str] = set()
    out: list[str] = []
    for term in terms:
        if term in seen:
            continue
        seen.add(term)
        out.append(term)
    return out


def load_triager_patterns(path: Path = TRIAGER_PATTERNS_PATH) -> list[dict[str, Any]]:
    payload = json.loads(_read_text(path))
    rows = payload.get("rejections", []) if isinstance(payload, dict) else []
    patterns: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        pattern_id = str(row.get("id") or "").strip()
        if not pattern_id:
            continue
        outcome_class, outcome_class_key = OUTCOME_CLASS_BY_PATTERN_ID.get(
            pattern_id,
            ("unknown", "A_rubric_mismatch"),
        )
        patterns.append({
            "id": pattern_id,
            "name": str(row.get("name") or pattern_id).strip(),
            "severity": str(row.get("severity") or "warn").strip().lower(),
            "description": str(row.get("description") or "").strip(),
            "pre_submit_guard": str(row.get("pre_submit_guard") or "").strip(),
            "terms": _pattern_terms(row),
            "outcome_class": outcome_class,
            "outcome_class_key": outcome_class_key,
        })
    return patterns


def load_disposition_classifier(path: Path = TRIAGER_DISPOSITION_CLASSIFIER_PATH) -> dict[str, Any]:
    if not path.is_file():
        return dict(CLASSIFIER_DEFAULT)
    payload = json.loads(_read_text(path))
    return payload if isinstance(payload, dict) else dict(CLASSIFIER_DEFAULT)


def _confidence_weight(row: dict[str, Any]) -> float:
    try:
        return float(row.get("confidence_weight") or 1.0)
    except (TypeError, ValueError):
        return 1.0


def classify_local_disposition(
    class_votes: dict[str, int],
    matched_patterns: list[dict[str, Any]],
    *,
    classifier_path: Path = TRIAGER_DISPOSITION_CLASSIFIER_PATH,
) -> dict[str, Any]:
    classifier = load_disposition_classifier(classifier_path)
    rows = classifier.get("classes")
    if not isinstance(rows, list):
        rows = CLASSIFIER_DEFAULT["classes"]
    total_votes = sum(max(0, int(v or 0)) for v in class_votes.values())
    if total_votes <= 0:
        return {
            "source": "local_disposition_classifier",
            "provider_backed": False,
            "provider_call_made": False,
            "classifier_schema": classifier.get("schema", CLASSIFIER_DEFAULT["schema"]),
            "classifier_ref": relpath(classifier_path, REPO_ROOT) if classifier_path.is_file() else "embedded_default",
            "predicted_provider_verdict": None,
            "disposition": "no_local_rejection_pattern",
            "confidence": 0.0,
            "confidence_band": "none",
            "supporting_pattern_ids": [],
            "advisory_only": True,
        }
    best_row: dict[str, Any] | None = None
    best_score = -1.0
    for row in rows:
        if not isinstance(row, dict):
            continue
        key = str(row.get("outcome_class_key") or "")
        vote = max(0, int(class_votes.get(key) or 0))
        if vote <= 0:
            continue
        weight = _confidence_weight(row)
        score = vote * max(0.0, weight)
        if score > best_score:
            best_row = row
            best_score = score
    if best_row is None:
        best_row = {"outcome_class_key": "A_rubric_mismatch", "disposition": "review_rubric_fit"}
    key = str(best_row.get("outcome_class_key") or "")
    winning_votes = max(0, int(class_votes.get(key) or 0))
    confidence = max(0.0, min(0.95, (winning_votes / total_votes) * _confidence_weight(best_row)))
    if confidence >= 0.75:
        band = "high"
    elif confidence >= 0.55:
        band = "medium"
    else:
        band = "low"
    supporting_ids = [
        str(row.get("id"))
        for row in matched_patterns
        if isinstance(row, dict) and str(row.get("outcome_class_key") or "") == key
    ]
    return {
        "source": "local_disposition_classifier",
        "provider_backed": False,
        "provider_call_made": False,
        "classifier_schema": classifier.get("schema", CLASSIFIER_DEFAULT["schema"]),
        "classifier_ref": relpath(classifier_path, REPO_ROOT) if classifier_path.is_file() else "embedded_default",
        "predicted_provider_verdict": None,
        "outcome_class_key": key,
        "disposition": str(best_row.get("disposition") or "review_matched_triager_patterns"),
        "recommended_action_hint": str(best_row.get("recommended_action") or ""),
        "confidence": round(confidence, 3),
        "confidence_band": band,
        "supporting_pattern_ids": supporting_ids[:8],
        "advisory_only": True,
    }


def _dedupe_strings(values: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for raw in values:
        value = str(raw).strip()
        if not value:
            continue
        key = value.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(value)
    return out


def _string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item).strip() for item in value if str(item).strip()]


def _silent_kill_rows(classifier: dict[str, Any]) -> list[dict[str, Any]]:
    rows = classifier.get("silent_kill_classes")
    if not isinstance(rows, list):
        rows = SILENT_KILL_DEFAULT_CLASSES
    out: list[dict[str, Any]] = []
    valid_keys = set(blank_silent_kill_votes())
    defaults_by_key = {
        str(row.get("class_key")): row
        for row in SILENT_KILL_DEFAULT_CLASSES
        if isinstance(row, dict) and row.get("class_key")
    }
    for row in rows:
        if not isinstance(row, dict):
            continue
        key = str(row.get("class_key") or "").strip()
        if key not in valid_keys:
            continue
        merged = {**defaults_by_key.get(key, {}), **row}
        merged.setdefault("class_label", key.replace("_", "-"))
        merged.setdefault("pattern_ids", [])
        merged.setdefault("evidence_terms", [])
        merged.setdefault("rebuttal_terms", [])
        merged.setdefault("suggested_strengthening", "")
        merged.setdefault("mind_model_question", "")
        merged.setdefault("rebuttal_mode", "weaken")
        out.append(merged)
    if out:
        return out
    return [dict(row) for row in SILENT_KILL_DEFAULT_CLASSES]


def _phrase_hits(text: str, terms: list[str]) -> list[str]:
    haystack = text.lower()
    hits: list[str] = []
    for term in terms:
        needle = term.strip()
        if len(needle) < 3:
            continue
        if needle.lower() in haystack:
            hits.append(needle)
    return _dedupe_strings(hits)


def _rebuttal_hits(text: str, terms: list[str]) -> list[str]:
    haystack = text.lower()
    hits: list[str] = []
    negating_prefixes = (
        "unless ",
        "without ",
        "needs ",
        "need ",
        "requires ",
        "require ",
        "must ",
        "should ",
        "if we prove ",
        "if the draft proves ",
        "lacks ",
        "lack ",
        "no ",
        "not ",
    )
    for term in terms:
        needle = term.strip()
        if len(needle) < 3:
            continue
        needle_lower = needle.lower()
        for match in re.finditer(re.escape(needle_lower), haystack):
            prefix = haystack[max(0, match.start() - 48):match.start()]
            prefix_tail = prefix[-40:]
            if any(negator in prefix_tail for negator in negating_prefixes):
                continue
            hits.append(needle)
            break
    return _dedupe_strings(hits)


def _confidence_band(confidence: float) -> str:
    if confidence >= 0.75:
        return "high"
    if confidence >= 0.55:
        return "medium"
    if confidence > 0:
        return "low"
    return "none"


def _silent_kill_confidence(pattern_score: int, phrase_count: int, weight: float) -> float:
    if pattern_score <= 0 and phrase_count <= 0:
        return 0.0
    base = 0.58 if pattern_score > 0 else 0.48
    raw = base + min(0.18, pattern_score * 0.03) + min(0.18, phrase_count * 0.045)
    return round(max(0.0, min(0.95, raw * max(0.0, weight))), 3)


def build_mind_model_checks(text: str, matched_patterns: list[dict[str, Any]]) -> list[dict[str, Any]]:
    matched_by_id = {
        str(row.get("id")): row
        for row in matched_patterns
        if isinstance(row, dict) and str(row.get("id") or "")
    }
    checks: list[dict[str, Any]] = []
    for check in MIND_MODEL_CHECKS:
        risk_phrases = _phrase_hits(text, _string_list(check.get("risk_terms")))
        rebuttal_phrases = _rebuttal_hits(text, _string_list(check.get("rebuttal_terms")))
        pattern_ids = _string_list(check.get("pattern_ids"))
        supporting_patterns = [matched_by_id[pid] for pid in pattern_ids if pid in matched_by_id]
        pattern_score = sum(max(0, int(pattern.get("score") or 0)) for pattern in supporting_patterns)
        risk_score = len(risk_phrases) + pattern_score
        rebuttal_score = len(rebuttal_phrases)
        if risk_score > 0 and rebuttal_score > 0:
            status = "risk_rebutted"
        elif risk_score > 0:
            status = "risk"
        elif rebuttal_score > 0:
            status = "rebuttal_present"
        else:
            status = "no_signal"
        checks.append({
            "source": "local_triager_mind_model",
            "provider_backed": False,
            "provider_call_made": False,
            "advisory_only": True,
            "check_id": str(check.get("check_id") or ""),
            "question": str(check.get("question") or ""),
            "linked_classes": _string_list(check.get("linked_classes")),
            "status": status,
            "risk_score": risk_score,
            "rebuttal_score": rebuttal_score,
            "risk_phrases": risk_phrases[:10],
            "rebuttal_phrases": rebuttal_phrases[:10],
            "supporting_pattern_ids": [str(pattern.get("id")) for pattern in supporting_patterns],
            "suggested_strengthening": str(check.get("suggested_strengthening") or ""),
        })
    return checks


def _mind_checks_for_class(class_key: str, checks: list[dict[str, Any]]) -> list[dict[str, Any]]:
    ids = set(CLASS_TO_MIND_CHECK_IDS.get(class_key, []))
    return [check for check in checks if str(check.get("check_id") or "") in ids]


def predict_silent_kills(
    text: str,
    matched_patterns: list[dict[str, Any]],
    *,
    classifier_path: Path = TRIAGER_DISPOSITION_CLASSIFIER_PATH,
    mind_model_checks: list[dict[str, Any]] | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    classifier = load_disposition_classifier(classifier_path)
    rows = _silent_kill_rows(classifier)
    checks = list(mind_model_checks or build_mind_model_checks(text, matched_patterns))
    matched_by_id = {
        str(row.get("id")): row
        for row in matched_patterns
        if isinstance(row, dict) and str(row.get("id") or "")
    }
    votes = blank_silent_kill_votes()
    predictions: list[dict[str, Any]] = []

    for row in rows:
        key = str(row.get("class_key") or "")
        pattern_ids = _string_list(row.get("pattern_ids"))
        supporting_patterns = [matched_by_id[pid] for pid in pattern_ids if pid in matched_by_id]
        pattern_score = sum(max(0, int(pattern.get("score") or 0)) for pattern in supporting_patterns)
        phrase_hits = _phrase_hits(text, _string_list(row.get("evidence_terms")))
        pattern_phrases: list[str] = []
        for pattern in supporting_patterns:
            matched_terms = pattern.get("matched_terms")
            if isinstance(matched_terms, list):
                pattern_phrases.extend(str(term) for term in matched_terms if str(term).strip())
        evidence_phrases = _dedupe_strings([*phrase_hits, *pattern_phrases])[:10]
        required_terms = _string_list(row.get("required_evidence_terms"))
        if required_terms and not _phrase_hits(" ".join([text, *pattern_phrases]), required_terms):
            supporting_patterns = []
            pattern_score = 0
            phrase_hits = []
            evidence_phrases = []
        rebuttal_phrases = _rebuttal_hits(text, _string_list(row.get("rebuttal_terms")))
        raw_score = pattern_score + len(phrase_hits)
        if rebuttal_phrases and str(row.get("rebuttal_mode") or "") == "suppress":
            score = 0
        else:
            score = max(0, raw_score - len(rebuttal_phrases))
        if key in votes:
            votes[key] = score
        related_checks = _mind_checks_for_class(key, checks)
        confidence = _silent_kill_confidence(pattern_score, len(evidence_phrases), _confidence_weight(row))
        if score == 0 and rebuttal_phrases:
            confidence = 0.0
        matched = score > 0
        predictions.append({
            "source": "local_silent_kill_predictor",
            "provider_backed": False,
            "provider_call_made": False,
            "advisory_only": True,
            "class_key": key,
            "class_label": str(row.get("class_label") or key.replace("_", "-")),
            "prediction": "silent_kill_predicted" if matched else "not_predicted",
            "matched": matched,
            "score": score,
            "raw_score": raw_score,
            "confidence": confidence,
            "confidence_band": _confidence_band(confidence),
            "evidence_phrases": evidence_phrases,
            "rebuttal_phrases": rebuttal_phrases[:10],
            "supporting_pattern_ids": [str(pattern.get("id")) for pattern in supporting_patterns],
            "mind_model_question": str(row.get("mind_model_question") or ""),
            "mind_model_check_ids": [str(check.get("check_id")) for check in related_checks],
            "mind_model_status": {
                str(check.get("check_id")): str(check.get("status"))
                for check in related_checks
            },
            "suggested_strengthening": str(row.get("suggested_strengthening") or ""),
        })

    predicted = [row for row in predictions if row["matched"]]
    predicted.sort(key=lambda row: (-float(row["confidence"]), -int(row["score"]), str(row["class_key"])))
    rebutted = [
        str(row["class_key"])
        for row in predictions
        if not row["matched"] and row.get("rebuttal_phrases") and int(row.get("raw_score") or 0) > 0
    ]
    classifier_ref = relpath(classifier_path, REPO_ROOT) if classifier_path.is_file() else "embedded_default"
    summary = {
        "source": "local_silent_kill_predictor",
        "provider_backed": False,
        "provider_call_made": False,
        "advisory_only": True,
        "classifier_schema": classifier.get("schema", CLASSIFIER_DEFAULT["schema"]),
        "classifier_ref": classifier_ref,
        "mind_model_version": "p4-local-mind-model-v1",
        "covered_taste_questions": len(checks),
        "predicted_classes": [str(row["class_key"]) for row in predicted],
        "risk_classes_rebutted": rebutted,
        "top_class": str(predicted[0]["class_key"]) if predicted else None,
        "silent_kill_votes": votes,
        "mind_model_risk_checks": [
            str(check.get("check_id"))
            for check in checks
            if str(check.get("status")) in {"risk", "risk_rebutted"}
        ],
    }
    return predictions, summary


def match_patterns(text: str, patterns: list[dict[str, Any]]) -> list[dict[str, Any]]:
    haystack = text.lower()
    scored: list[dict[str, Any]] = []
    for pattern in patterns:
        hits: list[str] = []
        score = 0
        for term in pattern.get("terms", []):
            if term in haystack:
                hits.append(term)
                score += 2 if " " in term else 1
        if score <= 0:
            continue
        scored.append({
            "id": pattern["id"],
            "name": pattern["name"],
            "severity": pattern["severity"],
            "outcome_class": pattern["outcome_class"],
            "outcome_class_key": pattern["outcome_class_key"],
            "score": score,
            "matched_terms": hits[:8],
            "pre_submit_guard": pattern["pre_submit_guard"],
        })
    scored.sort(key=lambda row: (-int(row["score"]), str(row["id"])))
    return scored[:MAX_MATCHED_PATTERNS]


def warning_for_pattern(pattern: dict[str, Any]) -> dict[str, Any]:
    first_hit = ""
    matched_terms = pattern.get("matched_terms")
    if isinstance(matched_terms, list) and matched_terms:
        first_hit = str(matched_terms[0])
    return {
        "code": "triager_pattern_match",
        "severity": str(pattern.get("severity") or "warn"),
        "pattern_id": pattern.get("id"),
        "pattern_name": pattern.get("name"),
        "outcome_class": pattern.get("outcome_class"),
        "matched_term": first_hit,
        "message": (
            f"Known local triager pattern {pattern.get('id')} ({pattern.get('name')}) "
            f"matched deterministically via {first_hit!r}. This is advisory only; "
            "no simulated triager verdict is implied."
        ),
    }


def _title_for(text: str, path: Path) -> str:
    match = HEADING_RE.search(text)
    if match:
        return match.group(1).strip()
    return path.stem.replace("-", " ").replace("_", " ")


def _tokens(text: str) -> set[str]:
    ignored = {
        "critical",
        "finding",
        "high",
        "impact",
        "issue",
        "medium",
        "protocol",
        "report",
        "the",
        "this",
        "with",
    }
    return {
        token.lower()
        for token in WORD_RE.findall(text)
        if len(token) >= 4 and token.lower() not in ignored
    }


def duplicateish_workspace_refs(draft_path: Path, workspace_path: Path, draft_text: str) -> list[dict[str, Any]]:
    submissions = workspace_path / "submissions"
    if not submissions.is_dir():
        return []
    draft_resolved = draft_path.resolve()
    title_tokens = _tokens(_title_for(draft_text, draft_path))
    if len(title_tokens) < 2:
        title_tokens |= _tokens(draft_path.stem)
    refs: list[dict[str, Any]] = []
    for candidate in sorted(submissions.rglob("*.md")):
        try:
            if candidate.resolve() == draft_resolved:
                continue
        except OSError:
            continue
        candidate_text = _read_text(candidate)[:6000]
        candidate_tokens = _tokens(_title_for(candidate_text, candidate))
        candidate_tokens |= _tokens(candidate.stem)
        overlap = sorted(title_tokens & candidate_tokens)
        if len(overlap) < 3:
            continue
        ratio = len(overlap) / max(1, min(len(title_tokens), len(candidate_tokens)))
        if ratio < 0.5:
            continue
        refs.append({
            "path": relpath(candidate, REPO_ROOT),
            "overlap_terms": overlap[:12],
            "overlap_ratio": round(ratio, 3),
        })
        if len(refs) >= MAX_DUPLICATE_REFS:
            break
    return refs


def add_duplicateish_match(matches: list[dict[str, Any]], refs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not refs:
        return matches
    duplicate_match = {
        "id": "R9",
        "name": "Valid Impact But Obvious Duplicate",
        "severity": "warn",
        "outcome_class": "G",
        "outcome_class_key": "G_duplicate_or_acknowledged",
        "score": 2 + len(refs),
        "matched_terms": ["workspace title/root-cause overlap"],
        "pre_submit_guard": (
            "For live-role/config and full-balance-flush findings, run the submitted-corpus "
            "novelty guard and require a distinction from exact submitted IDs before spending PoC time."
        ),
        "workspace_refs": refs,
    }
    out = [row for row in matches if row.get("id") != "R9"]
    out.append(duplicate_match)
    out.sort(key=lambda row: (-int(row["score"]), str(row["id"])))
    return out[:MAX_MATCHED_PATTERNS]


def mark_rules_only_boundary(packet: dict[str, Any]) -> dict[str, Any]:
    """Annotate the packet so local rules cannot be mistaken for provider P4."""
    local_rules_status = packet.get("local_rules_status")
    if not isinstance(local_rules_status, dict):
        local_rules_status = {}
        packet["local_rules_status"] = local_rules_status
    local_rules_status.setdefault("state", "completed")
    local_rules_status.setdefault("engine", "deterministic_local_rules")
    local_rules_status["provider_backed"] = False
    local_rules_status["provider_call_made"] = False
    local_rules_status["simulation_scope"] = "deterministic_local_rules_only"
    local_rules_status["predicted_verdict_supported"] = False
    local_rules_status["silent_kill_predictions_supported"] = True

    provider_status = packet.get("provider_status")
    if not isinstance(provider_status, dict):
        provider_status = {}
        packet["provider_status"] = provider_status
    provider_status.setdefault("provider", "none")
    provider_status.setdefault("state", "unknown")
    provider_status["provider_backed"] = False
    provider_status["provider_call_made"] = False
    provider_status["simulation_scope"] = "deterministic_local_rules_only"
    provider_status["predicted_verdict_supported"] = False

    packet["predicted_verdict"] = None
    packet["capability_boundary"] = dict(CAPABILITY_BOUNDARY)
    return packet


def build_precheck(draft_path: Path, workspace_path: Path, severity: str | None = None) -> dict[str, Any]:
    draft_text = _read_text(draft_path)
    patterns = load_triager_patterns()
    matched_patterns = match_patterns(draft_text, patterns)
    duplicate_refs = duplicateish_workspace_refs(draft_path, workspace_path, draft_text)
    matched_patterns = add_duplicateish_match(matched_patterns, duplicate_refs)

    warnings = [warning_for_pattern(pattern) for pattern in matched_patterns]
    if duplicate_refs:
        warnings.append({
            "code": "workspace_duplicateish_overlap",
            "severity": "warn",
            "message": (
                "Workspace submissions contain title/root-cause overlap. Add an explicit "
                "novelty and distinction paragraph before filing."
            ),
            "refs": duplicate_refs,
        })
    if not warnings:
        warnings.append(dict(NO_MATCH_WARNING))

    class_votes = blank_class_votes()
    for pattern in matched_patterns:
        key = str(pattern.get("outcome_class_key") or "")
        if key in class_votes:
            class_votes[key] += int(pattern.get("score") or 1)
    disposition_evidence = classify_local_disposition(class_votes, matched_patterns)
    mind_model_checks = build_mind_model_checks(draft_text, matched_patterns)
    silent_kill_predictions, silent_kill_summary = predict_silent_kills(
        draft_text,
        matched_patterns,
        mind_model_checks=mind_model_checks,
    )

    source_refs = [
        "reference/triager_patterns.json",
        relpath(draft_path, REPO_ROOT),
    ]
    classifier_ref = disposition_evidence.get("classifier_ref")
    if isinstance(classifier_ref, str) and classifier_ref != "embedded_default":
        source_refs.append(classifier_ref)
    for ref in duplicate_refs:
        path = ref.get("path")
        if isinstance(path, str):
            source_refs.append(path)

    packet = build_packet(
        draft_path=draft_path,
        workspace_path=workspace_path,
        warnings=warnings,
        matched_patterns=matched_patterns,
        class_votes=class_votes,
        source_refs=sorted(dict.fromkeys(source_refs)),
        repo_root=REPO_ROOT,
        severity=severity,
        disposition_evidence=disposition_evidence,
        mind_model_checks=mind_model_checks,
        silent_kill_predictions=silent_kill_predictions,
        silent_kill_summary=silent_kill_summary,
    )
    return mark_rules_only_boundary(packet)


def build_provider_prompt(draft_text: str, local_packet: dict[str, Any]) -> str:
    """Build the bounded provider prompt for P4 advisory simulation."""
    local_summary = {
        "claimed_severity": local_packet.get("claimed_severity"),
        "recommended_action": local_packet.get("recommended_action"),
        "class_votes": local_packet.get("class_votes"),
        "mind_model_checks": [
            {
                "check_id": row.get("check_id"),
                "status": row.get("status"),
                "risk_phrases": row.get("risk_phrases"),
                "rebuttal_phrases": row.get("rebuttal_phrases"),
            }
            for row in list(local_packet.get("mind_model_checks") or [])
            if isinstance(row, dict) and row.get("status") != "no_signal"
        ][:8],
        "silent_kill_summary": local_packet.get("silent_kill_summary"),
        "silent_kill_predictions": [
            {
                "class_key": row.get("class_key"),
                "prediction": row.get("prediction"),
                "confidence": row.get("confidence"),
                "evidence_phrases": row.get("evidence_phrases"),
                "suggested_strengthening": row.get("suggested_strengthening"),
            }
            for row in list(local_packet.get("silent_kill_predictions") or [])
            if isinstance(row, dict) and row.get("matched")
        ][:8],
        "matched_patterns": [
            {
                "id": row.get("id"),
                "name": row.get("name"),
                "outcome_class": row.get("outcome_class"),
                "matched_terms": row.get("matched_terms"),
            }
            for row in list(local_packet.get("matched_patterns") or [])[:8]
            if isinstance(row, dict)
        ],
    }
    bounded_draft = draft_text[:12000]
    return (
        "You are an advisory security-bounty triage simulator. You do not decide the real outcome.\n"
        "Classify whether this draft is likely to survive triage based only on the text below and known local red flags.\n"
        "Return ONLY compact JSON with keys: predicted_verdict, confidence, killer_phrase, suggested_strengthening, rationale.\n"
        "predicted_verdict must be one of: likely_accept, likely_reject, likely_duplicate, likely_oos, needs_more_proof, uncertain.\n"
        "Do not invent evidence. If proof, scope, configured impact, or duplicate data is missing, say needs_more_proof or uncertain.\n\n"
        f"Local precheck summary:\n{json.dumps(local_summary, sort_keys=True)}\n\n"
        f"Draft text:\n{bounded_draft}\n"
    )


def _parse_provider_json(stdout: str) -> tuple[dict[str, Any] | None, str | None]:
    text = stdout.strip()
    if not text:
        return None, "empty-provider-output"
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", text, re.DOTALL)
        if not match:
            return None, "provider-output-not-json"
        try:
            payload = json.loads(match.group(0))
        except json.JSONDecodeError:
            return None, "provider-output-json-parse-failed"
    if not isinstance(payload, dict):
        return None, "provider-output-not-object"
    return payload, None


def _normalize_provider_prediction(payload: dict[str, Any] | None) -> dict[str, Any] | None:
    if not isinstance(payload, dict):
        return None
    predicted = str(payload.get("predicted_verdict") or "uncertain").strip().lower()
    if predicted not in PROVIDER_ALLOWED_VERDICTS:
        predicted = "uncertain"
    confidence_raw = payload.get("confidence", 0)
    try:
        confidence = float(confidence_raw)
    except (TypeError, ValueError):
        confidence = 0.0
    confidence = max(0.0, min(1.0, confidence))
    return {
        "predicted_verdict": predicted,
        "confidence": confidence,
        "killer_phrase": str(payload.get("killer_phrase") or "")[:400],
        "suggested_strengthening": str(payload.get("suggested_strengthening") or "")[:800],
        "rationale": str(payload.get("rationale") or "")[:1200],
    }


def build_provider_simulation(
    draft_path: Path,
    workspace_path: Path,
    *,
    severity: str | None = None,
    provider: str = "kimi",
    dispatcher: Path | None = None,
    timeout_seconds: int = 180,
) -> dict[str, Any]:
    """Run an explicitly requested provider-backed advisory simulation."""
    local_packet = build_precheck(draft_path, workspace_path, severity=severity)
    draft_text = _read_text(draft_path)
    prompt = build_provider_prompt(draft_text, local_packet)
    dispatcher_path = dispatcher if dispatcher is not None else REPO_ROOT / "tools" / "llm-dispatch.py"
    provider_name = provider.strip().lower() or "kimi"

    with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".txt", delete=False) as tmp:
        tmp.write(prompt)
        prompt_path = Path(tmp.name)

    argv = [
        sys.executable,
        str(dispatcher_path),
        "--provider",
        provider_name,
        "--prompt-file",
        str(prompt_path),
        "--max-tokens",
        "1200",
        "--timeout",
        str(timeout_seconds),
    ]
    try:
        proc = subprocess.run(
            argv,
            cwd=str(REPO_ROOT),
            env=os.environ.copy(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout_seconds + 10,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        proc = subprocess.CompletedProcess(argv, 124, stdout=exc.stdout or "", stderr=exc.stderr or "timeout")
    finally:
        try:
            prompt_path.unlink()
        except OSError:
            pass

    provider_payload, parse_error = _parse_provider_json(str(proc.stdout or ""))
    prediction = _normalize_provider_prediction(provider_payload)
    success = proc.returncode == 0 and prediction is not None
    provider_status = {
        "provider": provider_name,
        "state": "completed" if success else "blocked",
        "provider_backed": success,
        "provider_call_made": True,
        "dispatcher_attempted": True,
        "simulation_scope": "provider_backed_triager_simulation",
        "predicted_verdict_supported": success,
        "dispatcher": relpath(dispatcher_path, REPO_ROOT),
        "dispatcher_rc": proc.returncode,
        "prompt_version": PROVIDER_PROMPT_VERSION,
    }
    if parse_error:
        provider_status["parse_error"] = parse_error
    if proc.returncode != 0:
        provider_status["error"] = str(proc.stderr or proc.stdout or "")[:800]

    out = dict(local_packet)
    out["mode"] = "provider_backed_simulation" if success else "provider_backed_simulation_blocked"
    out["provider_status"] = provider_status
    out["capability_boundary"] = dict(PROVIDER_CAPABILITY_BOUNDARY if success else PROVIDER_BLOCKED_CAPABILITY_BOUNDARY)
    if success:
        out["predicted_verdict"] = prediction
    else:
        out.pop("predicted_verdict", None)
    out["provider_advisory_only"] = True
    out["provider_prompt_version"] = PROVIDER_PROMPT_VERSION
    out["source_refs"] = sorted(
        dict.fromkeys([
            *(out.get("source_refs") or []),
            "tools/triager-pre-filing-simulator.py",
            "tools/llm-dispatch.py",
        ])
    )
    return out


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("draft_arg", nargs="?", help="Path to candidate draft markdown")
    parser.add_argument("workspace_arg", nargs="?", help="Workspace root to scan")
    parser.add_argument("--draft", help="Path to candidate draft markdown")
    parser.add_argument("--workspace", "--ws", help="Workspace root to scan")
    parser.add_argument(
        "--severity",
        # Case-insensitive: pre-submit-check.sh passes an all-uppercase
        # SEVERITY (MEDIUM/HIGH/CRITICAL). Accept any casing here and
        # normalize in main() via .capitalize(); reject unknown values
        # post-parse so we don't argparse-exit rc=2 (which the shell maps
        # to "simulator returned rc=2; skipping (advisory)").
        help="Severity tier (case-insensitive): Critical, High, Medium, or Low.",
    )
    # r36-rebuttal: lane r62-sim-fix declared in .auditooor/agent_pathspec.json
    parser.add_argument(
        "--provider-backed",
        action="store_true",
        help="Opt in to provider-backed advisory simulation via tools/llm-dispatch.py.",
    )
    parser.add_argument(
        "--provider",
        default="kimi",
        choices=["kimi", "minimax", "anthropic"],
        help="Provider for --provider-backed mode.",
    )
    parser.add_argument(
        "--dispatcher",
        help="Override dispatcher path for tests; defaults to tools/llm-dispatch.py.",
    )
    parser.add_argument("--timeout", type=int, default=180, help="Provider-backed dispatch timeout in seconds.")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    draft = args.draft or args.draft_arg
    workspace = args.workspace or args.workspace_arg
    if not draft:
        raise SystemExit("draft path required via --draft or positional argument")
    if not workspace:
        raise SystemExit("workspace path required via --workspace or positional argument")
    draft_path = Path(draft)
    workspace_path = Path(workspace)
    if not draft_path.is_file():
        raise SystemExit(f"draft not found: {draft_path}")
    if not workspace_path.is_dir():
        raise SystemExit(f"workspace not found: {workspace_path}")
    # r36-rebuttal: lane r62-sim-fix declared in .auditooor/agent_pathspec.json
    severity = args.severity.capitalize() if args.severity else None
    if severity is not None and severity not in ("Critical", "High", "Medium", "Low"):
        raise SystemExit(
            f"invalid --severity {args.severity!r}; expected one of "
            "Critical, High, Medium, Low (case-insensitive)"
        )
    if args.provider_backed:
        dispatcher = None
        if args.dispatcher:
            if os.environ.get("AUDITOOOR_MCP_ALLOW_TEST_DISPATCHER") != "1":
                raise SystemExit("--dispatcher override is test-only; set AUDITOOOR_MCP_ALLOW_TEST_DISPATCHER=1")
            dispatcher = Path(args.dispatcher)
        packet = build_provider_simulation(
            draft_path,
            workspace_path,
            severity=severity,
            provider=args.provider,
            dispatcher=dispatcher,
            timeout_seconds=args.timeout,
        )
    else:
        packet = build_precheck(draft_path, workspace_path, severity=severity)
    print(json.dumps(packet, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
