#!/usr/bin/env python3
"""Configuration/deployment preconditions plus downstream trace gate (Check #88).

DISTINCT ROLE vs Check #89 (configured-impact-trace-check.py, Rule 42): THIS
gate is the prose-only DOCUMENTATION layer - it confirms the draft body
carries a 'Configuration/Deployment Preconditions' section and a 'Downstream
Consumer Trace' section with source-backed config facts. It is a bounded
documentation check over the draft body only and does NOT inspect workspaces,
source trees, or the PoC corpus. Check #89 is the deeper ENFORCEMENT layer: it
reads the cited PoC corpus and enforces the five required Configured-Impact
Trace fields (scope mode, configuration precondition, downstream consumer,
evidence-class match, triage-follow-up pre-answer) plus the evidence-class
match. Both gates are intentionally kept and both run in pre-submit-check.sh -
#88 catches a missing documentation section, #89 catches an upstream-only PoC
that over-claims downstream fund loss. They compose without conflict.

Medium+ rollup / bridge / oracle / consensus claims are configuration-sensitive:
the vulnerable path must be live in the audited deployment, and the claimed
impact must reach the real downstream consumer that realizes it. This gate is a
bounded documentation check over the draft body. It does not inspect workspaces
or source trees.

Verdicts:
  pass-out-of-scope                 - below Medium or no config-sensitive surface
  pass-config-downstream-traced     - config/deployment and downstream trace found
  pass-not-applicable               - explicit same-component not_applicable proof
  ok-rebuttal                       - bounded HTML rebuttal accepted (<=200 chars)
  fail-config-downstream-trace      - one or more required trace blockers found
  error                             - input/read error

Exit codes:
  0 - pass / out-of-scope / not-applicable / accepted rebuttal
  1 - gate violation
  2 - input error

Schema: auditooor.config_downstream_trace_check.v1
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "auditooor.config_downstream_trace_check.v1"
GATE = "CONFIG-DOWNSTREAM-TRACE"

SEVERITY_RANK = {"info": 0, "informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
FILEABLE_MIN_RANK = SEVERITY_RANK["medium"]
HIGH_MIN_RANK = SEVERITY_RANK["high"]
REBUTTAL_MAX_CHARS = 200

SEVERITY_HEADER_RE = re.compile(
    r"(?im)^\s*(?:[-*]\s*)?\**\s*Severity\s*\**\s*[:\-]?\**\s*"
    r"(Critical|High|Medium|Low)\b"
)
IMPACT_SEVERITY_RE = re.compile(
    r"(?im)^\s*(?:severity_tier|severity_implied)\s*:\s*"
    r"(Critical|High|Medium|Low)\b"
)
FILENAME_SEVERITY_RE = re.compile(
    r"(?:^|[-_])(critical|high|medium|low)(?:[-_.]|$)", re.IGNORECASE
)

SURFACE_RE = re.compile(
    r"\b("
    r"rollup|bridge|bridged|cross[- ]chain|message[- ]passing|inbox|outbox|"
    r"oracle|price feed|feed address|aggregator|sequencer feed|"
    r"consensus|validator set|validator|relayer|sequencer|finality|"
    r"verifier|verification key|domain mapping|domain id|chain[- ]id|"
    r"route|router|registry|registered handler|proxy implementation|"
    r"feature flag|fork rule|chain config|deployment config|watchtower"
    r")\b",
    re.IGNORECASE,
)

DOWNSTREAM_IMPACT_RE = re.compile(
    r"\b("
    r"direct loss|loss of funds|drain|theft|unauthorized withdraw|"
    r"permanent freeze|finality|state corruption|consensus halt|"
    r"oracle drain|bridge drain|downstream|consumer"
    r")\b",
    re.IGNORECASE,
)

CONFIG_SECTION_RE = re.compile(
    r"^#{1,6}\s+Configuration/Deployment Preconditions\s*$|"
    r"^#{1,6}\s+Configuration and Deployment Preconditions\s*$|"
    r"^#{1,6}\s+Config(?:uration)? Preconditions\s*$|"
    r"^\s*config(?:uration)?[_ -]deployment[_ -]preconditions\s*:",
    re.IGNORECASE | re.MULTILINE,
)

DOWNSTREAM_SECTION_RE = re.compile(
    r"^#{1,6}\s+Downstream Consumer Trace\s*$|"
    r"^#{1,6}\s+Downstream Trace\s*$|"
    r"^\s*downstream[_ -](?:consumer[_ -])?trace\s*:",
    re.IGNORECASE | re.MULTILINE,
)

PROVEN_CONFIG_RE = re.compile(
    r"\b(proven|source[- ]cited|deployment artifact|live query|"
    r"reproducible local config|default config|active in production|"
    r"registered (?:route|handler)|proxy implementation|deployed address|"
    r"domain mapping|chain[- ]id mapping|verifier adapter|feed address)\b",
    re.IGNORECASE,
)

DOWNSTREAM_TRACE_RE = re.compile(
    r"\b("
    r"consumer (?:read|reads|accepts|verifies|uses)|"
    r"consumer read site|consumer acceptance site|"
    r"transport boundary|storage boundary|message root|state root|proof|"
    r"fallback result|guard result|challenge result|finalizer result|"
    r"no downstream revalidation|no independent revalidation|"
    r"downstream guard|downstream consumer|final asset impact|"
    r"producer entrypoint"
    r")\b",
    re.IGNORECASE,
)

FILE_LINE_RE = re.compile(r"[A-Za-z0-9_./\\-]+\.[A-Za-z]{1,8}:\d+")
ADDRESS_RE = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
COMMIT_RE = re.compile(r"\b[0-9a-f]{7,40}\b", re.IGNORECASE)

ASSUMED_CONFIG_RE = re.compile(
    r"\b("
    r"assumed|not proven|unproven|unknown deployment|unknown config|"
    r"operator must enable|governance must enable|owner must enable|"
    r"admin must enable|requires governance|requires owner|requires admin|"
    r"requires operator|new privileged action|privileged action required|"
    r"off by default|disabled by default|devnet only|testnet only|local only|"
    r"not active in production|feature flag off|fork not active|not deployed"
    r")\b",
    re.IGNORECASE,
)

OFF_DEFAULT_RE = re.compile(
    r"\b(off by default|disabled by default|devnet only|testnet only|"
    r"local only|feature flag off|fork not active|not active in production|"
    r"not deployed)\b",
    re.IGNORECASE,
)

PRIVILEGED_RE = re.compile(
    r"\b("
    r"owner must|admin must|governance must|operator must|"
    r"requires (?:owner|admin|governance|operator)|"
    r"new privileged action|privileged action required"
    r")\b",
    re.IGNORECASE,
)

DOWNSTREAM_GUARD_UNRESOLVED_RE = re.compile(
    r"\b("
    r"fallback not analyzed|guard not analyzed|challenge not analyzed|"
    r"revalidation not analyzed|consumer guard unresolved|"
    r"downstream guard unresolved|does not analyze fallback|"
    r"does not resolve downstream"
    r")\b",
    re.IGNORECASE,
)

REASONED_ONLY_RE = re.compile(
    r"\b(reasoned[- ]only|source[- ]cited reasoned|no executed poc|"
    r"not executed end[- ]to[- ]end|manual reasoning only)\b",
    re.IGNORECASE,
)

SEVERITY_CAP_RE = re.compile(
    r"(?im)^\s*severity[_ -]cap[_ -]if[_ -]reasoned\s*:\s*(Medium|Low)\b|"
    r"\bseverity capped to (?:Medium|Low)\b",
)

NOT_APPLICABLE_RE = re.compile(
    r"(?im)^\s*config[_ -]downstream[_ -]trace\s*:\s*not[_ -]applicable\b"
)

SAME_COMPONENT_RE = re.compile(
    r"\b(same component|same contract|same module|no downstream consumer|"
    r"impact realized in the same)\b",
    re.IGNORECASE,
)

REBUTTAL_RE = re.compile(
    r"<!--\s*config-downstream-rebuttal:\s*(.*?)\s*-->",
    re.IGNORECASE | re.DOTALL,
)
SECTION_BOUNDARY_RE = re.compile(r"(?m)^(?:#{1,6}\s+|\d+\.\s+)")


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _severity(text: str, path: Path, override: str | None) -> tuple[str | None, str]:
    if override:
        normalized = override.strip().lower()
        if normalized in SEVERITY_RANK:
            return normalized, "cli"
    for pattern, source in (
        (SEVERITY_HEADER_RE, "severity-header"),
        (IMPACT_SEVERITY_RE, "impact-contract"),
    ):
        m = pattern.search(text)
        if m:
            return m.group(1).lower(), source
    m = FILENAME_SEVERITY_RE.search(path.name)
    if m:
        return m.group(1).lower(), "filename"
    return None, "missing"


def _line_hits(text: str, pattern: re.Pattern[str], limit: int = 8) -> list[str]:
    hits = []
    for line in text.splitlines():
        if pattern.search(line):
            hits.append(" ".join(line.strip().split())[:220])
        if len(hits) >= limit:
            break
    return hits


def _matches(text: str, pattern: re.Pattern[str], limit: int = 8) -> list[str]:
    return [m.group(0)[:120] for m in pattern.finditer(text)][:limit]


def _rebuttal(text: str) -> tuple[str | None, bool, int]:
    m = REBUTTAL_RE.search(text)
    if not m:
        return None, False, 0
    reason = " ".join(m.group(1).split())
    if reason and len(reason) <= REBUTTAL_MAX_CHARS:
        return reason, False, len(reason)
    return None, True, len(reason)


def _has_source_backing(text: str) -> bool:
    return bool(FILE_LINE_RE.search(text) or ADDRESS_RE.search(text) or COMMIT_RE.search(text))


def _section_text(text: str, pattern: re.Pattern[str]) -> str:
    match = pattern.search(text)
    if not match:
        return ""
    start = match.end()
    boundary = SECTION_BOUNDARY_RE.search(text, start)
    if boundary:
        return text[start:boundary.start()]
    return text[start:]


def run(
    draft: Path,
    *,
    severity: str | None = None,
    strict: bool = False,
) -> tuple[int, dict[str, Any]]:
    """Run the gate and return (exit_code, JSON-serializable payload)."""
    if not draft.is_file():
        return 2, {
            "schema_version": SCHEMA_VERSION,
            "gate": GATE,
            "file": str(draft),
            "verdict": "error",
            "reason": f"draft not found: {draft}",
            "evidence": {},
        }

    try:
        text = _read(draft)
    except Exception as exc:
        return 2, {
            "schema_version": SCHEMA_VERSION,
            "gate": GATE,
            "file": str(draft),
            "verdict": "error",
            "reason": f"cannot read draft: {exc}",
            "evidence": {},
        }

    sev, sev_src = _severity(text, draft, severity)
    sev_rank = SEVERITY_RANK.get(sev or "", 0)
    surface_hits = _matches(text, SURFACE_RE)
    downstream_impact_hits = _matches(text, DOWNSTREAM_IMPACT_RE)
    in_scope = sev_rank >= FILEABLE_MIN_RANK and bool(surface_hits)

    evidence: dict[str, Any] = {
        "surface_hits": surface_hits,
        "downstream_impact_hits": downstream_impact_hits,
        "config_section_hits": _line_hits(text, CONFIG_SECTION_RE),
        "downstream_section_hits": _line_hits(text, DOWNSTREAM_SECTION_RE),
        "proven_config_hits": _line_hits(text, PROVEN_CONFIG_RE),
        "downstream_trace_hits": _line_hits(text, DOWNSTREAM_TRACE_RE),
        "file_line_citations": FILE_LINE_RE.findall(text)[:10],
        "address_citations": ADDRESS_RE.findall(text)[:6],
        "commit_citations": COMMIT_RE.findall(text)[:6],
    }

    payload: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "gate": GATE,
        "file": str(draft),
        "severity": sev,
        "severity_source": sev_src,
        "strict": strict,
        "in_scope": in_scope,
        "evidence": evidence,
        "remediation_options": [
            "Add '## Configuration/Deployment Preconditions' with proven deployment/config facts and source/deployment/live-query citations.",
            "Add '## Downstream Consumer Trace' from producer entrypoint through the real consumer read/verification site and final impact.",
            "If impact is realized inside the same component, add 'config_downstream_trace: not_applicable' with a source-backed same-component reason.",
            "Use <!-- config-downstream-rebuttal: reason --> only for a bounded source-backed exception (max 200 chars).",
        ],
    }

    if not in_scope:
        payload["verdict"] = "pass-out-of-scope"
        if sev_rank < FILEABLE_MIN_RANK:
            payload["reason"] = "severity below Medium or missing; config/downstream trace not required"
        else:
            payload["reason"] = "no rollup/bridge/oracle/consensus/config-sensitive surface trigger found"
        return 0, payload

    rebuttal, rebuttal_invalid, rebuttal_len = _rebuttal(text)
    if rebuttal and _has_source_backing(rebuttal):
        payload["verdict"] = "ok-rebuttal"
        payload["rebuttal"] = rebuttal
        payload["reason"] = "bounded config-downstream rebuttal accepted"
        return 0, payload
    if rebuttal:
        payload["rebuttal_invalid"] = True
        payload["rebuttal_invalid_reason"] = "rebuttal must include source-backed evidence such as file:line, address, or commit"
        payload["rebuttal_observed_length"] = rebuttal_len
    elif rebuttal_invalid:
        payload["rebuttal_invalid"] = True
        payload["rebuttal_observed_length"] = rebuttal_len

    config_text = _section_text(text, CONFIG_SECTION_RE)
    downstream_text = _section_text(text, DOWNSTREAM_SECTION_RE)
    has_config_source_backing = _has_source_backing(config_text)
    has_downstream_source_backing = _has_source_backing(downstream_text)
    has_any_source_backing = _has_source_backing(text)
    if NOT_APPLICABLE_RE.search(text):
        if SAME_COMPONENT_RE.search(text) and has_any_source_backing:
            payload["verdict"] = "pass-not-applicable"
            payload["reason"] = "config_downstream_trace: not_applicable is source-backed and same-component"
            return 0, payload
        payload["verdict"] = "fail-config-downstream-trace"
        payload["blockers"] = ["invalid_not_applicable"]
        payload["reason"] = "not_applicable requires a source-backed same-component/no-downstream reason"
        return 1, payload

    blockers: list[str] = []

    has_config_section = bool(evidence["config_section_hits"])
    has_downstream_section = bool(evidence["downstream_section_hits"])
    has_proven_config = bool(_line_hits(config_text, PROVEN_CONFIG_RE)) and has_config_source_backing
    has_downstream_trace = bool(_line_hits(downstream_text, DOWNSTREAM_TRACE_RE)) and has_downstream_source_backing

    if not has_config_section:
        blockers.append("missing_config_deployment_preconditions")
    elif not has_proven_config:
        blockers.append("unproven_config_precondition")

    if _line_hits(text, OFF_DEFAULT_RE):
        blockers.append("off_default_or_devnet_only_precondition")
    if _line_hits(text, PRIVILEGED_RE):
        blockers.append("privileged_config_action_required")
    elif _line_hits(text, ASSUMED_CONFIG_RE):
        blockers.append("unproven_config_precondition")

    if not has_downstream_section:
        blockers.append("missing_downstream_consumer_trace")
    elif not has_downstream_trace:
        blockers.append("missing_downstream_consumer_trace")

    if _line_hits(text, DOWNSTREAM_GUARD_UNRESOLVED_RE):
        blockers.append("downstream_guard_not_resolved")

    reasoned_only = bool(_line_hits(text, REASONED_ONLY_RE))
    severity_capped = bool(SEVERITY_CAP_RE.search(text))
    if sev_rank >= HIGH_MIN_RANK and downstream_impact_hits and reasoned_only and not severity_capped:
        blockers.append("reasoned_only_downstream_high_plus")

    blockers = sorted(set(blockers))
    payload["blockers"] = blockers

    if blockers:
        payload["verdict"] = "fail-config-downstream-trace"
        payload["reason"] = "Medium+ config-sensitive claim is missing required deployment/downstream proof"
        return 1, payload

    payload["verdict"] = "pass-config-downstream-traced"
    payload["reason"] = "draft carries proven configuration/deployment preconditions and downstream consumer trace"
    return 0, payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("draft", type=Path, help="Path to the submission draft Markdown")
    parser.add_argument(
        "--severity",
        choices=(
            "Critical", "High", "Medium", "Low", "Info", "Informational",
            "critical", "high", "medium", "low", "info", "informational",
        ),
        help="Override severity detection",
    )
    parser.add_argument("--strict", action="store_true", help="Reserved; failures are hard for in-scope Medium+ drafts")
    parser.add_argument("--json", action="store_true", dest="json_out", help="Emit JSON (default)")
    args = parser.parse_args(argv)

    rc, payload = run(args.draft, severity=args.severity, strict=args.strict)
    print(json.dumps(payload, indent=2, sort_keys=True))
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
