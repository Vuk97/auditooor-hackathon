#!/usr/bin/env python3
"""Draft-level severity calibration preflight.

This gate catches high-confidence overclaim shapes before paste-ready text is
filed. It does not replace program-specific rubric mapping or exact-impact
proof gates; it provides a deterministic triager-tier sanity check over the
draft's actors, asset type, recoverability, and production-path claims.

Exit codes:
  0 - pass, out-of-scope, or advisory only
  1 - hard overclaim contradiction
  2 - input error
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "auditooor.severity_calibration_check.v1"
GATE = "SEVERITY-CALIBRATION"

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
ORDERED = ("low", "medium", "high", "critical")

PRIVILEGED_RE = re.compile(
    r"\b(?:requires?|needs?|depends on|only after|precondition(?:s)? include)\b"
    r"[\s\S]{0,120}\b(?:admin|governance|operator|owner|guardian|approver|"
    r"privileged|trusted role|vault operator|redemption_admin|boss)\b|"
    r"\b(?:admin|governance|operator|owner|guardian|approver|privileged|trusted role)\b"
    r"[\s\S]{0,80}\b(?:must|has to|needs to|required|precondition)\b",
    re.IGNORECASE,
)

UNPRIVILEGED_RE = re.compile(
    r"\b(?:unprivileged|unknown address|unvetted|any user|attacker-controlled|"
    r"permissionless|no privileged account|without privileged)\b",
    re.IGNORECASE,
)

YIELD_RE = re.compile(
    r"\b(?:unclaimed yield|protocol[- ]accumulated yield|protocol yield|"
    r"royalties|fees|residual|slippage residual|surplus)\b",
    re.IGNORECASE,
)

USER_FUNDS_RE = re.compile(
    r"\b(?:user funds|LP funds|customer funds|depositor funds|at-rest funds|"
    r"in-motion funds|subaccount debit|wallet balance)\b",
    re.IGNORECASE,
)

NEGATED_USER_FUNDS_RE = re.compile(
    r"\b(?:not user funds|not LP funds|no user funds|no user subaccount|"
    r"no depositor funds|not .* user[- ]fund|not .* LP[- ]fund)\b",
    re.IGNORECASE,
)

PROTOCOL_INTERNAL_RE = re.compile(
    r"\b(?:protocol[- ]owned|module account|insurance fund|collateral pool|"
    r"internal accounting|accounting drift|no user subaccount is debited|"
    r"TVL is preserved|reconcilable)\b",
    re.IGNORECASE,
)

PERMANENT_RE = re.compile(
    r"\b(?:permanent freezing|permanent loss|unrecoverable|requires hardfork|"
    r"requires governance intervention|persistent AppHash divergence|"
    r"persistent durability divergence)\b",
    re.IGNORECASE,
)

RESTART_HEALS_RE = re.compile(
    r"\b(?:restart clears|restart heals|restart resolves|process restart clears|"
    r"does not persist post-restart|no persistent durability divergence|"
    r"on-disk state is correct|on-disk state is canonical)\b",
    re.IGNORECASE,
)

NETWORK_RE = re.compile(
    r"\b(?:network-level|consensus halt|chain halt|validator halt|"
    r"AppHash divergence|block production halt|multi-validator|liveness failure)\b",
    re.IGNORECASE,
)

MULTI_VALIDATOR_RE = re.compile(
    r"\b(?:multi-validator|4-validator|four-validator|NumValidators\s*[:=]\s*[2-9]|"
    r"\b[2-9]\s+validators?\b|validator set)\b",
    re.IGNORECASE,
)

PRODUCTION_PATH_RE = re.compile(
    r"\b(?:production path|real block execution|FinalizeBlock|Commit|RunTx|"
    r"BroadcastTx|AdvanceToBlock|unmodified runtime|real .*runtime)\b",
    re.IGNORECASE,
)

REBUTTAL_RE = re.compile(r"<!--\s*severity-calibration-rebuttal:\s*(.*?)\s*-->", re.IGNORECASE | re.DOTALL)


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _severity(text: str, path: Path, override: str | None) -> tuple[str | None, str]:
    if override and override.lower() != "auto":
        normalized = override.strip().lower()
        if normalized in SEVERITY_RANK:
            return normalized, "cli"
    for pattern, source in (
        (r"(?im)^\s*\**\s*Severity\s*:\**\s*(Critical|High|Medium|Low)\b", "severity-header"),
        (r"(?im)^\s*severity_implied\s*:\s*(Critical|High|Medium|Low)\b", "program-impact-mapping"),
        (r"(?im)^\s*severity_tier\s*:\s*(Critical|High|Medium|Low)\b", "impact-contract"),
        (r"(?im)^\s*selected_severity\s*:\s*(Critical|High|Medium|Low)\b", "selected-severity"),
    ):
        match = re.search(pattern, text)
        if match:
            return match.group(1).lower(), source
    name = path.name.lower()
    for severity in ("critical", "high", "medium", "low"):
        if re.search(rf"(?:^|[-_]){severity}(?:[-_.]|$)", name):
            return severity, "filename"
    return None, "missing"


def _line_hits(text: str, pattern: re.Pattern[str], limit: int = 8) -> list[dict[str, Any]]:
    hits: list[dict[str, Any]] = []
    for idx, line in enumerate(text.splitlines(), start=1):
        match = pattern.search(line)
        if match:
            hits.append({"line": idx, "token": match.group(0), "text": line.strip()[:240]})
            if len(hits) >= limit:
                break
    return hits


def _cap_tier(current: str, cap: str) -> str:
    return ORDERED[min(SEVERITY_RANK[current], SEVERITY_RANK[cap]) - 1]


def _rebuttal(text: str) -> str | None:
    match = REBUTTAL_RE.search(text)
    if not match:
        return None
    return " ".join(match.group(1).split())


def run(
    draft: Path,
    *,
    severity_override: str | None = None,
    strict: bool = False,
) -> tuple[int, dict[str, Any]]:
    try:
        text = _read_text(draft)
    except Exception as exc:
        return 2, {
            "schema_version": SCHEMA_VERSION,
            "gate": GATE,
            "file": str(draft),
            "verdict": "error",
            "error": f"cannot read draft: {exc}",
        }

    severity, severity_source = _severity(text, draft, severity_override)
    payload: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "gate": GATE,
        "file": str(draft),
        "claimed_severity": severity,
        "severity_source": severity_source,
        "strict": strict,
        "predicted_triager_tier": severity,
        "overclaim_reasons": [],
        "advisory_reasons": [],
        "evidence": {},
        "remediation_options": [
            "Retitle and remap the report to the predicted triager tier.",
            "If claiming Critical, prove unprivileged direct user-fund theft/freezing end-to-end.",
            "If claiming permanent or network-level impact, include restart and multi-validator production-path evidence.",
            "Use <!-- severity-calibration-rebuttal: reason --> only for a bounded, source-backed exception.",
        ],
    }

    if severity is None or SEVERITY_RANK.get(severity, 0) < SEVERITY_RANK["high"]:
        payload["verdict"] = "pass-out-of-scope"
        payload["reason"] = "severity below HIGH or missing"
        return 0, payload

    rebuttal = _rebuttal(text)
    if rebuttal and len(rebuttal) <= 240:
        payload["verdict"] = "ok-rebuttal"
        payload["rebuttal"] = rebuttal
        return 0, payload

    evidence = {
        "privileged_hits": _line_hits(text, PRIVILEGED_RE),
        "unprivileged_hits": _line_hits(text, UNPRIVILEGED_RE),
        "yield_hits": _line_hits(text, YIELD_RE),
        "user_fund_hits": _line_hits(text, USER_FUNDS_RE),
        "negated_user_fund_hits": _line_hits(text, NEGATED_USER_FUNDS_RE),
        "protocol_internal_hits": _line_hits(text, PROTOCOL_INTERNAL_RE),
        "permanent_hits": _line_hits(text, PERMANENT_RE),
        "restart_heals_hits": _line_hits(text, RESTART_HEALS_RE),
        "network_hits": _line_hits(text, NETWORK_RE),
        "multi_validator_hits": _line_hits(text, MULTI_VALIDATOR_RE),
        "production_path_hits": _line_hits(text, PRODUCTION_PATH_RE),
    }
    payload["evidence"] = evidence

    predicted = severity
    hard: list[str] = []
    advisory: list[str] = []

    if severity == "critical":
        negated_user_funds = bool(evidence["negated_user_fund_hits"])
        if evidence["yield_hits"] and (not evidence["user_fund_hits"] or negated_user_funds):
            hard.append("critical_claim_maps_to_unclaimed_yield_not_direct_user_funds")
            predicted = _cap_tier(predicted, "high")
        if evidence["protocol_internal_hits"] and (not evidence["user_fund_hits"] or negated_user_funds):
            hard.append("critical_claim_appears_protocol_internal_or_reconcilable")
            predicted = _cap_tier(predicted, "medium")
        if evidence["privileged_hits"] and not evidence["unprivileged_hits"]:
            hard.append("critical_claim_requires_privileged_or_operator_action")
            predicted = _cap_tier(predicted, "medium")

    if evidence["permanent_hits"] and evidence["restart_heals_hits"]:
        hard.append("permanent_impact_claim_contradicted_by_restart_heals_disclosure")
        predicted = _cap_tier(predicted, "medium")

    if severity in {"critical", "high"} and evidence["network_hits"]:
        if not evidence["multi_validator_hits"]:
            advisory.append("network_liveness_claim_missing_multi_validator_evidence")
        if not evidence["production_path_hits"]:
            advisory.append("network_liveness_claim_missing_production_path_evidence")

    payload["predicted_triager_tier"] = predicted
    payload["overclaim_reasons"] = hard
    payload["advisory_reasons"] = advisory

    if hard:
        payload["verdict"] = "fail-severity-overclaim"
        payload["reason"] = "claimed severity exceeds deterministic triager-calibration cap"
        return 1, payload
    if advisory:
        payload["verdict"] = "pass-with-advisory"
        payload["reason"] = "severity tier is plausible but evidence should be hardened"
        return 0, payload

    payload["verdict"] = "pass-calibrated"
    payload["reason"] = "no deterministic severity overclaim found"
    return 0, payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("draft", type=Path)
    parser.add_argument("--severity", default="auto")
    parser.add_argument("--strict", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    rc, payload = run(args.draft, severity_override=args.severity, strict=args.strict)
    print(json.dumps(payload, indent=2, sort_keys=True))
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
