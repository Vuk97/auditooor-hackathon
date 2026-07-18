#!/usr/bin/env python3
"""High+/Critical draft severity calibration gate.

This companion to ``severity-calibration-check.py`` emits an axis-level report
for draft claims that need triager-grade wording before filing. It is bounded
and deterministic: no network, no model calls, and no workspace mutation unless
``--markdown-report`` is explicitly requested.

Exit codes:
  0 - no blocking overclaim found
  1 - at least one High/Critical draft exceeds the deterministic cap
  2 - input error
"""

from __future__ import annotations

import argparse
import datetime as _dt
import importlib.util
import json
import re
import sys
from pathlib import Path
from typing import Any


SCHEMA = "auditooor.severity_calibration_gate.v1"
GATE = "HIGHPLUS-SEVERITY-CALIBRATION"

REPO_ROOT = Path(__file__).resolve().parents[1]
OUTCOME_LESSON_GATE = REPO_ROOT / "tools" / "outcome-lesson-gate.py"
LESSON_ENFORCEMENT_INVENTORY = REPO_ROOT / ".auditooor" / "lesson_enforcement_inventory.json"
# HACKERMAN_V3 Lane J5a: the shared outcome-lesson classifier's
# low_severity_cap_triggered predicate drives a deterministic medium cap.
LOW_SEVERITY_CAP_PREDICATE = "low_severity_cap_triggered"
LOW_SEVERITY_CAP_TIER = "medium"

SEVERITY_RANK = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
ORDERED = ("none", "low", "medium", "high", "critical")

SEVERITY_RE = (
    re.compile(r"(?im)^\s*\**\s*Severity\s*:\**\s*(Critical|High|Medium|Low)\b"),
    re.compile(r"(?im)^\s*severity_implied\s*:\s*(Critical|High|Medium|Low)\b"),
    re.compile(r"(?im)^\s*severity_tier\s*:\s*(Critical|High|Medium|Low)\b"),
    re.compile(r"(?im)^\s*selected_severity\s*:\s*(Critical|High|Medium|Low)\b"),
)

USER_FUND_THEFT_RE = re.compile(
    r"\b(?:direct theft|steal|drain|sweep|exfiltrat|unauthorized transfer|"
    r"unauthori[sz]ed withdrawal|debit)\b[\s\S]{0,160}"
    r"\b(?:user funds|victim funds|depositor funds|LP funds|customer funds|"
    r"at-rest funds|wallet balance|collateral|principal)\b|"
    r"\b(?:user funds|victim funds|depositor funds|LP funds|customer funds|"
    r"at-rest funds|wallet balance|collateral|principal)\b[\s\S]{0,160}"
    r"\b(?:stolen|drained|swept|transferred|debited|lost)\b",
    re.IGNORECASE,
)

USER_FUNDS_RE = re.compile(
    r"\b(?:user funds|victim funds|depositor funds|LP funds|customer funds|"
    r"at-rest funds|wallet balance|collateral|principal)\b",
    re.IGNORECASE,
)

NEGATED_USER_FUNDS_RE = re.compile(
    r"\b(?:not user funds|not LP funds|no user funds|no victim funds|"
    r"no depositor funds|not .* user[- ]fund|not .* LP[- ]fund)\b",
    re.IGNORECASE,
)

PROTOCOL_YIELD_RE = re.compile(
    r"\b(?:protocol[- ]accumulated yield|protocol yield|unclaimed yield|"
    r"accumulated fees|protocol fees|treasury fees|royalties|residual|"
    r"slippage residual|surplus|skimmed fees)\b",
    re.IGNORECASE,
)

GRIEFING_RE = re.compile(
    r"\b(?:grief|griefing|annoyance|force retry|spam|temporary DoS|temporary denial|"
    r"gas grief|operational cost|delayed execution|delays settlement)\b",
    re.IGNORECASE,
)

TEMP_FREEZE_RE = re.compile(
    r"\b(?:temporary freeze|temporarily frozen|temporary freezing|temporary lock|"
    r"temporary lockup|temporary inability|self[- ]resolves?|resolves after|"
    r"clears after|<\s*24\s*h|less than\s+24\s+hours?|minutes?|hours?)\b",
    re.IGNORECASE,
)

PERM_FREEZE_RE = re.compile(
    r"\b(?:permanent freeze|permanently frozen|permanent freezing|permanent lock|"
    r"permanent lockup|unrecoverable|irrecoverable|forever locked|"
    r"protocol insolvency|requires hardfork|cannot be recovered)\b",
    re.IGNORECASE,
)

PRIVILEGED_RE = re.compile(
    r"\b(?:requires?|needs?|depends on|only after|precondition(?:s)? include|"
    r"must first)\b[\s\S]{0,140}\b(?:admin|governance|operator|owner|guardian|"
    r"approver|privileged|trusted role|vault operator|redemption_admin|multisig)\b|"
    r"\b(?:admin|governance|operator|owner|guardian|approver|privileged|trusted role|"
    r"multisig)\b[\s\S]{0,100}\b(?:must|has to|needs to|required|precondition|sets?)\b",
    re.IGNORECASE,
)

UNPRIVILEGED_RE = re.compile(
    r"\b(?:unprivileged|unknown address|unvetted|any user|anyone|arbitrary caller|"
    r"permissionless|no privileged account|without privileged|without admin|"
    r"attacker-controlled)\b",
    re.IGNORECASE,
)

RECOVERABLE_RE = re.compile(
    r"\b(?:recoverable|can be recovered|admin can recover|governance can recover|"
    r"manual recovery|sweep recovery|restart clears|restart heals|restart resolves|"
    r"process restart clears|self[- ]heals|self[- ]resolves|rollback|replay fixes|"
    r"on-disk state is correct|canonical state is intact)\b",
    re.IGNORECASE,
)

PRODUCTION_PATH_RE = re.compile(
    r"\b(?:production path|real block execution|mainnet path|deployed bytecode|"
    r"unmodified runtime|real .*runtime|FinalizeBlock|Commit|RunTx|BroadcastTx|"
    r"AdvanceToBlock|fork test|local fork|integration test|end[- ]to[- ]end)\b",
    re.IGNORECASE,
)

SYNTHETIC_PROOF_RE = re.compile(
    r"\b(?:synthetic|toy harness|mock|stub|unit test only|contrived|assume|"
    r"manually set|manual state edit|cheatcode only|forge test only|not production|"
    r"simulated only|model-only|component-only|component PoC|poc-only)\b",
    re.IGNORECASE,
)
NEGATED_SYNTHETIC_CONTEXT_RE = re.compile(
    r"\b(?:no|not|without|never)\b.{0,96}\b(?:synthetic|mock|mocked|stub|"
    r"stand[- ]in|placeholder|component|manual state edit|fault[- ]injection)\b",
    re.IGNORECASE,
)
NOT_RELY_SYNTHETIC_CONTEXT_RE = re.compile(
    r"\bdoes\s+not\s+rely\b.{0,240}\b(?:synthetic|mock|mocked|stub|stand[- ]in|"
    r"placeholder|component|manual state edit|fault[- ]injection)\b",
    re.IGNORECASE,
)

END_TO_END_RE = re.compile(
    r"\b(?:end[- ]to[- ]end|e2e|fork test|local fork|integration test|"
    r"production path|real block execution|victim balance decreases|attacker balance increases|"
    r"before and after balances|assertEq|assertLt|assertGt)\b",
    re.IGNORECASE,
)

REBUTTAL_RE = re.compile(
    r"<!--\s*severity-calibration-gate-rebuttal:\s*(.*?)\s*-->",
    re.IGNORECASE | re.DOTALL,
)


def _now_iso() -> str:
    return _dt.datetime.now(_dt.UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _read_text(path: Path) -> tuple[str | None, str | None]:
    try:
        return path.read_text(encoding="utf-8", errors="replace"), None
    except Exception as exc:  # noqa: BLE001
        return None, f"cannot read {path}: {exc}"


def _severity(text: str, path: Path, override: str | None = None) -> tuple[str | None, str]:
    if override and override.lower() != "auto":
        normalized = override.strip().lower()
        if normalized in SEVERITY_RANK:
            return normalized, "cli"
    for pattern in SEVERITY_RE:
        match = pattern.search(text)
        if match:
            return match.group(1).lower(), "draft"
    name = path.name.lower()
    for severity in ("critical", "high", "medium", "low"):
        if re.search(rf"(?:^|[-_]){severity}(?:[-_.]|$)", name):
            return severity, "filename"
    return None, "missing"


def _line_hits(text: str, pattern: re.Pattern[str], limit: int = 6) -> list[dict[str, Any]]:
    hits: list[dict[str, Any]] = []
    for idx, line in enumerate(text.splitlines(), start=1):
        match = pattern.search(line)
        if match:
            hits.append({"line": idx, "token": match.group(0)[:120], "text": line.strip()[:240]})
            if len(hits) >= limit:
                break
    return hits


def _synthetic_line_hits(text: str, limit: int = 6) -> list[dict[str, Any]]:
    """Synthetic-proof hits, excluding lines that explicitly negate the risk."""
    hits: list[dict[str, Any]] = []
    for idx, line in enumerate(text.splitlines(), start=1):
        match = SYNTHETIC_PROOF_RE.search(line)
        if not match:
            continue
        if NEGATED_SYNTHETIC_CONTEXT_RE.search(line) or NOT_RELY_SYNTHETIC_CONTEXT_RE.search(line):
            continue
        hits.append({"line": idx, "token": match.group(0)[:120], "text": line.strip()[:240]})
        if len(hits) >= limit:
            break
    return hits


def _has(evidence: dict[str, list[dict[str, Any]]], key: str) -> bool:
    return bool(evidence.get(key))


def _cap(current: str, cap: str) -> str:
    return ORDERED[min(SEVERITY_RANK[current], SEVERITY_RANK[cap])]


def _rebuttal(text: str) -> str | None:
    match = REBUTTAL_RE.search(text)
    if not match:
        return None
    value = " ".join(match.group(1).split())
    return value if value and len(value) <= 280 else None


def classify_axes(text: str) -> dict[str, Any]:
    evidence = {
        "user_fund_theft": _line_hits(text, USER_FUND_THEFT_RE),
        "user_funds": _line_hits(text, USER_FUNDS_RE),
        "negated_user_funds": _line_hits(text, NEGATED_USER_FUNDS_RE),
        "protocol_yield_theft": _line_hits(text, PROTOCOL_YIELD_RE),
        "griefing": _line_hits(text, GRIEFING_RE),
        "temporary_freeze": _line_hits(text, TEMP_FREEZE_RE),
        "permanent_freeze": _line_hits(text, PERM_FREEZE_RE),
        "privileged_precondition": _line_hits(text, PRIVILEGED_RE),
        "unprivileged_path": _line_hits(text, UNPRIVILEGED_RE),
        "recoverability": _line_hits(text, RECOVERABLE_RE),
        "production_path": _line_hits(text, PRODUCTION_PATH_RE),
        "synthetic_proof": _synthetic_line_hits(text),
        "end_to_end_proof": _line_hits(text, END_TO_END_RE),
    }

    if _has(evidence, "user_fund_theft") and not _has(evidence, "negated_user_funds"):
        impact_kind = "user_fund_theft"
    elif _has(evidence, "permanent_freeze") and _has(evidence, "user_funds"):
        impact_kind = "permanent_freeze"
    elif _has(evidence, "temporary_freeze") and _has(evidence, "user_funds"):
        impact_kind = "temporary_freeze"
    elif _has(evidence, "protocol_yield_theft"):
        impact_kind = "protocol_yield_theft"
    elif _has(evidence, "griefing"):
        impact_kind = "griefing"
    elif _has(evidence, "permanent_freeze"):
        impact_kind = "permanent_freeze"
    elif _has(evidence, "temporary_freeze"):
        impact_kind = "temporary_freeze"
    else:
        impact_kind = "unknown"

    if _has(evidence, "recoverability") or _has(evidence, "temporary_freeze"):
        recoverability = "recoverable_or_temporary"
    elif _has(evidence, "permanent_freeze"):
        recoverability = "unrecoverable_claimed"
    else:
        recoverability = "unknown"

    privileged = "present" if _has(evidence, "privileged_precondition") else "absent"
    attacker_path = "unprivileged" if _has(evidence, "unprivileged_path") else "not_proven_unprivileged"

    proof_risks: list[str] = []
    if _has(evidence, "synthetic_proof"):
        proof_risks.append("synthetic_or_component_only_proof")
    if not _has(evidence, "production_path"):
        proof_risks.append("missing_production_path_evidence")
    if not _has(evidence, "end_to_end_proof"):
        proof_risks.append("missing_end_to_end_evidence")

    return {
        "impact_kind": impact_kind,
        "privileged_precondition": privileged,
        "attacker_path": attacker_path,
        "recoverability": recoverability,
        "proof_risks": proof_risks,
        "evidence": evidence,
    }


def calibrate(severity: str | None, axes: dict[str, Any]) -> tuple[str | None, list[str], list[str]]:
    if severity is None:
        return None, [], ["severity_missing"]

    predicted = severity
    blockers: list[str] = []
    advisory: list[str] = []
    impact = axes["impact_kind"]
    proof_risks = set(axes["proof_risks"])

    if SEVERITY_RANK[severity] < SEVERITY_RANK["high"]:
        return predicted, blockers, advisory

    if impact == "user_fund_theft":
        if severity == "critical" and axes["attacker_path"] != "unprivileged":
            blockers.append("critical_user_fund_theft_missing_unprivileged_attacker_path")
            predicted = _cap(predicted, "high")
    elif impact == "permanent_freeze":
        if axes["recoverability"] == "recoverable_or_temporary":
            blockers.append("permanent_freeze_claim_has_recovery_or_temporary_language")
            predicted = _cap(predicted, "medium")
        else:
            predicted = _cap(predicted, "high")
            if severity == "critical":
                advisory.append("critical_permanent_freeze_needs_program_specific_critical_mapping")
    elif impact == "protocol_yield_theft":
        if severity == "critical":
            blockers.append("critical_claim_maps_to_protocol_yield_theft_not_user_fund_theft")
            predicted = _cap(predicted, "high")
    elif impact == "temporary_freeze":
        if severity == "critical":
            blockers.append("critical_claim_maps_to_temporary_freeze")
            predicted = _cap(predicted, "high")
    elif impact == "griefing":
        if severity in {"critical", "high"}:
            blockers.append("highplus_claim_maps_to_griefing_without_fund_theft_or_permanent_freeze")
            predicted = _cap(predicted, "medium")
    else:
        if severity == "critical":
            blockers.append("critical_claim_missing_concrete_user_fund_theft_or_permanent_freeze_axis")
            predicted = _cap(predicted, "high")
        else:
            advisory.append("high_claim_missing_concrete_impact_axis")

    if axes["privileged_precondition"] == "present" and axes["attacker_path"] != "unprivileged":
        blockers.append("highplus_claim_requires_privileged_precondition")
        predicted = _cap(predicted or severity, "medium")

    if "synthetic_or_component_only_proof" in proof_risks and severity == "critical":
        blockers.append("critical_claim_has_synthetic_or_component_only_proof")
        predicted = _cap(predicted or severity, "high")

    if severity in {"critical", "high"}:
        for risk in sorted(proof_risks):
            if risk not in advisory:
                advisory.append(risk)

    return predicted, sorted(set(blockers)), sorted(set(advisory))


def _outcome_lesson_low_cap(text: str) -> dict[str, Any]:
    """Consume the shared outcome-lesson classifier (HACKERMAN_V3 Lane J5a).

    Returns whether the classifier reports ``low_severity_cap_triggered`` as a
    hard predicate. The predicate definition lives ONLY in
    ``tools/outcome-lesson-gate.py``; this function does not re-encode it.
    """
    result: dict[str, Any] = {"available": False, "low_cap_triggered": False, "reason": "", "predicates": []}
    if not OUTCOME_LESSON_GATE.is_file():
        result["reason"] = "outcome-lesson-gate.py not found"
        return result
    try:
        spec = importlib.util.spec_from_file_location(
            "auditooor_outcome_lesson_gate_for_severity_calibration",
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
    hard = sorted(
        {
            str(b.get("predicate") or "")
            for b in (payload.get("blockers") or [])
            if str(b.get("predicate") or "")
        }
    )
    result["available"] = True
    result["predicates"] = hard
    result["low_cap_triggered"] = LOW_SEVERITY_CAP_PREDICATE in hard
    return result


def analyze_file(path: Path, *, severity_override: str | None = None) -> tuple[int, dict[str, Any]]:
    text, error = _read_text(path)
    if error:
        return 2, {
            "schema": SCHEMA,
            "gate": GATE,
            "file": str(path),
            "verdict": "error",
            "error": error,
        }
    assert text is not None
    severity, source = _severity(text, path, severity_override)
    axes = classify_axes(text)
    predicted, blockers, advisory = calibrate(severity, axes)

    # HACKERMAN_V3 Lane J5a: consume the shared outcome-lesson classifier. When
    # it reports low_severity_cap_triggered, apply a deterministic medium cap.
    # The predicate definition lives ONLY in tools/outcome-lesson-gate.py.
    outcome_lesson = _outcome_lesson_low_cap(text)
    if (
        outcome_lesson.get("low_cap_triggered")
        and severity is not None
        and SEVERITY_RANK.get(severity, 0) > SEVERITY_RANK[LOW_SEVERITY_CAP_TIER]
    ):
        blockers = sorted(set(blockers + ["outcome_lesson_low_severity_cap_triggered"]))
        predicted = _cap(predicted or severity, LOW_SEVERITY_CAP_TIER)

    rebuttal = _rebuttal(text)
    if rebuttal and blockers:
        advisory = sorted(set(advisory + [f"rebutted_blockers: {', '.join(blockers)}"]))
        blockers = []

    if severity is None or SEVERITY_RANK.get(severity, 0) < SEVERITY_RANK["high"]:
        verdict = "pass-out-of-scope"
        reason = "severity below High or missing"
    elif blockers:
        verdict = "fail-severity-overclaim"
        reason = "claimed High+/Critical severity exceeds deterministic axis cap"
    elif advisory:
        verdict = "pass-with-advisory"
        reason = "severity is plausible but proof should be hardened"
    else:
        verdict = "pass-calibrated"
        reason = "no deterministic severity overclaim found"

    payload: dict[str, Any] = {
        "schema": SCHEMA,
        "gate": GATE,
        "file": str(path),
        "verdict": verdict,
        "reason": reason,
        "claimed_severity": severity,
        "severity_source": source,
        "predicted_triager_tier": predicted,
        "impact_kind": axes["impact_kind"],
        "privileged_precondition": axes["privileged_precondition"],
        "attacker_path": axes["attacker_path"],
        "recoverability": axes["recoverability"],
        "proof_risks": axes["proof_risks"],
        "blockers": blockers,
        "advisory": advisory,
        "outcome_lesson_gate": {
            "available": outcome_lesson.get("available", False),
            "low_cap_triggered": outcome_lesson.get("low_cap_triggered", False),
            "hard_predicates": outcome_lesson.get("predicates", []),
            "reason": outcome_lesson.get("reason", ""),
        },
        "evidence": axes["evidence"],
        "remediation_options": [
            "Retitle/remap to the predicted triager tier when a blocker is present.",
            "For Critical, prove unprivileged direct user-fund theft or unrecoverable user-fund freeze end-to-end.",
            "For protocol-yield theft, avoid Critical unless the program explicitly treats that asset as user funds.",
            "For griefing or temporary freeze, state duration and recovery path and avoid permanent-loss wording.",
            "Replace synthetic/component-only proofs with a production-path or fork/integration proof before filing High+.",
        ],
    }
    if rebuttal:
        payload["rebuttal"] = rebuttal

    return (1 if blockers else 0), payload


def build_envelope(
    paths: list[Path],
    *,
    severity_override: str | None = None,
    generated_at: str | None = None,
) -> tuple[int, dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    rc = 0
    for path in paths:
        row_rc, row = analyze_file(path, severity_override=severity_override)
        rows.append(row)
        if row_rc == 2:
            rc = 2
        elif row_rc == 1 and rc == 0:
            rc = 1

    counts: dict[str, int] = {}
    for row in rows:
        verdict = str(row.get("verdict", "unknown"))
        counts[verdict] = counts.get(verdict, 0) + 1

    envelope = {
        "schema": SCHEMA,
        "gate": GATE,
        "generated_at": generated_at or _now_iso(),
        "input_count": len(paths),
        "overall_verdict": "error" if rc == 2 else ("fail" if rc == 1 else "pass"),
        "verdict_counts": dict(sorted(counts.items())),
        "rows": rows,
    }
    return rc, envelope


def render_markdown(envelope: dict[str, Any]) -> str:
    lines = [
        "# Severity Calibration Gate Report",
        "",
        f"- Schema: `{envelope['schema']}`",
        f"- Generated at: `{envelope['generated_at']}`",
        f"- Overall verdict: `{envelope['overall_verdict']}`",
        f"- Drafts analyzed: `{envelope['input_count']}`",
        "",
        "| File | Claimed | Predicted | Impact axis | Privileged | Recoverability | Verdict |",
        "|---|---:|---:|---|---|---|---|",
    ]
    for row in envelope["rows"]:
        lines.append(
            "| {file} | {claimed} | {predicted} | {impact} | {privileged} | {recoverability} | {verdict} |".format(
                file=Path(str(row.get("file", ""))).name,
                claimed=row.get("claimed_severity") or "-",
                predicted=row.get("predicted_triager_tier") or "-",
                impact=row.get("impact_kind") or "-",
                privileged=row.get("privileged_precondition") or "-",
                recoverability=row.get("recoverability") or "-",
                verdict=row.get("verdict") or "-",
            )
        )
    lines.append("")

    for row in envelope["rows"]:
        lines.extend(
            [
                f"## {row.get('file')}",
                "",
                f"- Verdict: `{row.get('verdict')}`",
                f"- Reason: {row.get('reason')}",
                f"- Blockers: {', '.join(row.get('blockers') or []) or 'none'}",
                f"- Advisory: {', '.join(row.get('advisory') or []) or 'none'}",
                "",
            ]
        )
    return "\n".join(lines).rstrip() + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("drafts", nargs="+", type=Path)
    parser.add_argument("--severity", default="auto", help="override severity for every input, or auto")
    parser.add_argument("--json", action="store_true", help="emit JSON envelope")
    parser.add_argument("--markdown-report", type=Path, help="write a bounded Markdown report")
    args = parser.parse_args(argv)

    rc, envelope = build_envelope(args.drafts, severity_override=args.severity)
    if args.markdown_report:
        args.markdown_report.parent.mkdir(parents=True, exist_ok=True)
        args.markdown_report.write_text(render_markdown(envelope), encoding="utf-8")
    if args.json or not args.markdown_report:
        print(json.dumps(envelope, indent=2, sort_keys=True))
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
