#!/usr/bin/env python3
"""Rule 42 Configured-Impact-Trace preflight (Check #89).

DISTINCT ROLE vs Check #88 (config-downstream-trace-check.py): Check #88 is a
prose-only documentation check that the draft body carries a
'Configuration/Deployment Preconditions' section and a 'Downstream Consumer
Trace' section. THIS gate (Check #89) is the deeper enforcement layer: it
fires on any Medium+ config-dependent claim, reads the cited PoC corpus, and
fails the EXACT triage failure mode - a draft that proves only UPSTREAM
ACCEPTANCE (verifier/consensus accepts a bad root) while claiming downstream
fund loss, leans on an unbacked 'if configured this way' assumption, names a
hypothetical chain/client/consumer, reasons the downstream generically, or
omits the triage-follow-up pre-answer (field 5). Both gates are kept; they
compose without conflict - #88 checks section presence, #89 checks the five
required fields and the evidence-class match.

For any Medium+ claim whose impact depends on a deployed/configured component -
a registered chain, router, oracle, client, adapter, feature flag, role set,
asset pool, bridge reserve, runtime pallet, or downstream consumer - the draft
must include a "Configured-Impact Trace" before promotion to paste_ready/filed.

The trace must prove FIVE things:

  1. Scope mode: source-only / deployed-only / mixed - which environment the
     evidence describes.
  2. Configuration precondition: the vulnerable path is enabled in the
     in-scope environment - cite source config, runtime registration,
     deployment config, registry mapping, contract constructor, admin-set
     value, or live state (for deployed/mixed-scope bounties).
  3. Downstream consumer path: the exact downstream component that consumes
     the bad state/value/root/message and turns it into the claimed impact;
     each hop needs a file:line / source citation or an executed PoC
     assertion.
  4. Evidence-class match: if the PoC executes only the upstream acceptance
     step, the impact must be worded as "accepted forged/unfinalized state"
     or "state-integrity failure" UNLESS the downstream fund/message path is
     either executed or fully source-traced with no missing configurable
     assumptions.
  5. Triage-follow-up pre-answer: the draft must explicitly pre-answer the two
     questions a triager always asks for a config-dependent claim - "what
     deployed/configured-chain assumption is needed?" and "what downstream
     runtime path realizes impact?". Without both answers the gate fails.

Fail-closed for Medium+ drafts if: the affected chain/client/router/oracle/
asset is only hypothetical; the draft says "loss of funds" but only proves
verifier acceptance / a source gap; a required downstream module is reasoned
generically instead of tied to the actual configured consumer; the proof
relies on "if configured this way" without stating whether that configuration
is in-scope / production-plausible / live; the triage-follow-up pre-answer
(field 5) is absent.

Honest narrowing PASSES: e.g. "This proves consensus acceptance of an
unfinalized root; downstream fund-loss is possible only if this client is
configured for a value-bearing state machine." / "Severity capped because
deployment/configuration is unproven." A narrowed claim still has to answer
field 5 - narrowing changes the impact wording, not the triager's two
questions.

Verdict vocabulary:
  pass-out-of-scope, pass-not-config-dependent, pass-configured-impact-traced,
  pass-claim-narrowed, ok-rebuttal, fail-no-configured-impact-trace,
  fail-hypothetical-component, fail-overclaimed-impact-vs-evidence,
  fail-downstream-generic-not-configured, fail-if-configured-without-evidence,
  fail-missing-triage-followup, error.

Exit codes:
  0 - pass, out-of-scope, not-config-dependent, claim-narrowed, or source-backed rebuttal
  1 - Rule 42 violation
  2 - input error

Schema: auditooor.r42_configured_impact_trace.v1
"""

from __future__ import annotations

import argparse
import json
import os
import re
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "auditooor.r42_configured_impact_trace.v1"
GATE = "R42-CONFIGURED-IMPACT-TRACE"

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
REBUTTAL_MAX_CHARS = 200

CODE_SUFFIXES = {
    ".go", ".rs", ".sol", ".ts", ".tsx", ".js", ".mjs", ".py",
    ".move", ".cairo", ".vy", ".log", ".txt",
}

# --- Trigger: the rule fires only on Medium+ claims whose impact depends on a
# deployed/configured component. -------------------------------------------
CONFIG_DEPENDENT_RE = re.compile(
    r"registered (?:chain|client|router|oracle|adapter|state machine|handler|"
    r"consensus client|pallet|module|asset|market)|"
    r"\b(?:router|oracle|adapter|aggregator|sequencer feed|price feed)\b|"
    r"feature[- ]flag|fork rule|fork flag|runtime pallet|"
    r"\bpallet\b|role set|role[- ]gated|admin[- ]set|admin-controlled|"
    r"asset pool|liquidity pool|bridge reserve|asset reserve|token[- ]gateway|"
    r"downstream consumer|downstream component|downstream module|"
    r"deployed contract|deployed address|deployment config|"
    r"registry mapping|registry entry|chain config|chain[- ]id mapping|"
    r"configured (?:router|oracle|client|chain|consumer|adapter)|"
    r"is the active|active router|configured as the|"
    r"registered with [A-Za-z0-9_:]+|"
    r"ConsensusClients|SupportedStateMachines|set_rollup_core_address|"
    r"constructor (?:sets|stores|argument)|constructor-set",
    re.IGNORECASE,
)

# Fund/message impact wording - if the claim leans on this it needs the
# downstream consumer path closed (executed or fully source-traced).
FUND_IMPACT_RE = re.compile(
    r"loss of (?:user )?funds|loss of bridged|theft of funds|direct theft|"
    r"fund drain|drain (?:of |the )|stolen funds|stealing or loss of funds|"
    r"unauthorized (?:asset )?(?:withdraw|transfer|movement)|"
    r"permanent freezing|freezing of funds|insolvency|"
    r"loss of funds for assets|drained|drain trace",
    re.IGNORECASE,
)

# Narrowed / honest-acceptance-only impact wording (the PASS for upstream-only).
NARROWED_IMPACT_RE = re.compile(
    r"accepted (?:a )?(?:forged|unfinalized|unconfirmed|deletable|disputable) "
    r"(?:state|root|output|commitment)|"
    r"consensus[- ]acceptance|acceptance step|acceptance of an unfinalized|"
    r"state[- ]integrity (?:failure|gap)|"
    r"severity (?:is )?capped|capped (?:at|because)|"
    r"downstream (?:fund[- ]loss|drain) (?:is )?possible only if|"
    r"only if (?:this|the) client is configured for a value[- ]bearing|"
    r"value[- ]bearing state machine|"
    r"claim (?:is )?narrow(?:ed)?|narrows? the claim|"
    r"not separately executed|reasoned (?:not|but not) (?:separately )?executed|"
    r"deployment[- /]configuration (?:is )?unproven|"
    r"configuration (?:is )?unproven|honest scope of the PoC|"
    r"capped (?:this )?at medium|filed (?:high|medium) rather than",
    re.IGNORECASE,
)

# --- Configured-Impact Trace section + sub-fields --------------------------
TRACE_SECTION_RE = re.compile(
    r"^\s*#{0,4}\s*Configured-Impact Trace\s*:?\s*$|"
    r"^\s*[-*]?\s*Configured-Impact Trace\s*:",
    re.IGNORECASE | re.MULTILINE,
)

# Sub-field 1: configuration precondition citation.
CONFIG_PRECONDITION_RE = re.compile(
    r"configuration precondition\s*:|"
    r"config(?:uration)?[- ]?precondition|"
    r"runtime registration|deployment config|registry mapping|"
    r"contract constructor|constructor (?:sets|stores|argument)|"
    r"admin[- ]set value|admin-controlled value|"
    r"registered (?:at|in|via)\b|"
    r"is the (?:active|configured)|configured as|"
    r"live (?:on-chain )?state|live state|"
    r"ConsensusClients|SupportedStateMachines|set_rollup_core_address",
    re.IGNORECASE,
)

# Sub-field 2: downstream consumer path.
DOWNSTREAM_CONSUMER_RE = re.compile(
    r"downstream consumer\s*:|"
    r"hop[- ]by[- ]hop|hop-by-hop impact trace|"
    r"downstream component|consumes the (?:bad|forged|stale|unfinalized)|"
    r"is consumed by|consumed by the|reads it back|"
    r"request handler|drain trace|downstream (?:drain|fund|impact) (?:path|trace)|"
    r"downstream consumer (?:path|trace)",
    re.IGNORECASE,
)

# Sub-field 3: scope-mode / executed-in-poc markers.
SCOPE_MODE_RE = re.compile(
    r"scope mode\s*:|executed in poc\??\s*:|"
    r"executed[- ]in[- ]poc|"
    r"if no, narrowed claim|narrowed claim / severity cap",
    re.IGNORECASE,
)

# Field 5 - Triage-follow-up pre-answer. The draft must explicitly pre-answer
# the two questions a triager always asks for a config-dependent claim:
#   (a) what deployed/configured-chain assumption is needed?
#   (b) what downstream runtime path realizes impact?
# Each question has its own marker so the gate can require BOTH answers.
TRIAGE_FOLLOWUP_ASSUMPTION_RE = re.compile(
    r"triage[- ]follow[- ]?up[^:]*:|"
    r"deployed/?configured[- ]chain assumption|"
    r"configured[- ]chain assumption (?:needed|required|is)|"
    r"what (?:deployed|configured)[- ]?(?:chain )?assumption is needed|"
    r"deployment[- ]assumption (?:needed|required)|"
    r"assumption needed\s*:",
    re.IGNORECASE,
)
TRIAGE_FOLLOWUP_RUNTIME_RE = re.compile(
    r"what downstream runtime path realizes impact|"
    r"downstream runtime path (?:that )?realizes (?:the )?impact|"
    r"runtime path realizes impact|"
    r"downstream runtime path\s*:|"
    r"runtime path that realizes the impact",
    re.IGNORECASE,
)

# file:line citation (downstream-hop evidence).
FILE_LINE_RE = re.compile(r"[A-Za-z0-9_./\\-]+\.[A-Za-z]{1,8}:\d+(?:-\d+)?")
ADDRESS_RE = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
COMMIT_RE = re.compile(r"\b[0-9a-f]{7,40}\b", re.IGNORECASE)

# Executed-PoC markers.
EXECUTED_POC_RE = re.compile(
    r"\b(?:assertEq|assertTrue|assertFalse|assert_eq!|assert_ne!|assert!|"
    r"require\.(?:Equal|NotEqual|True|False|NoError)|"
    r"assert\.(?:Equal|NotEqual|True|False|ok)|"
    r"\[PASS\]|Suite result: ok|tests? passed|cargo test|forge test|"
    r"executed (?:V3-grade )?(?:Foundry |Rust )?PoC|executed-exploit)\b",
)

# "if configured this way" smell - a conditional with no config/live evidence.
IF_CONFIGURED_RE = re.compile(
    r"if (?:it is |the |this )?configured|if (?:the )?(?:chain|client|router|"
    r"oracle|deployment) (?:is|were)|"
    r"assuming (?:the |a )?(?:chain|client|router|oracle|deployment|config)|"
    r"when configured|provided (?:the |it is )?configured|"
    r"would (?:be |only )?(?:exploitable|fire|trigger) if",
    re.IGNORECASE,
)

# Hypothetical-component smell - the affected component is only theoretical.
HYPOTHETICAL_RE = re.compile(
    r"hypothetical (?:chain|client|router|oracle|adapter|deployment|consumer)|"
    r"no (?:such )?(?:chain|client|router|oracle) (?:is )?(?:currently )?"
    r"(?:registered|deployed|configured)|"
    r"theoretical (?:chain|client|router|oracle|deployment)|"
    r"if any (?:such )?(?:chain|client) ever (?:exists|is registered)|"
    r"may not be deployed anywhere",
    re.IGNORECASE,
)

# In-scope / production-plausibility statement (rescues a conditional).
SCOPE_STATEMENT_RE = re.compile(
    r"in[- ]scope|production[- ]plausible|production deployment|"
    r"production[- ]reachability|live production|"
    r"normal,? (?:expected |always[- ]present )?(?:on-chain |blockchain )?state|"
    r"default (?:build|config|deployment)|"
    r"stop_condition|stop condition|production code|compiled production",
    re.IGNORECASE,
)

# Generic-downstream smell - downstream reasoned generically not tied to the
# actual configured consumer.
GENERIC_DOWNSTREAM_RE = re.compile(
    r"some downstream (?:module|component|consumer)|"
    r"a downstream (?:module|component|consumer) would|"
    r"generic(?:ally)? (?:downstream|consumer)|"
    r"downstream .{0,40}generic|"
    r"typically .{0,30}downstream|in general,? the downstream",
    re.IGNORECASE,
)

REBUTTAL_RE = re.compile(
    r"<!--\s*r42-rebuttal:\s*(.*?)\s*-->", re.IGNORECASE | re.DOTALL
)
REBUTTAL_LINE_RE = re.compile(
    r"(?im)^\s*(?:[-*]\s*)?r42[-_ ]rebuttal\s*:\s*(.+?)\s*$"
)


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _severity(text: str, path: Path, override: str | None) -> tuple[str | None, str]:
    if override:
        normalized = override.strip().lower()
        if normalized in SEVERITY_RANK:
            return normalized, "cli"
    for pattern, source in (
        (r"(?im)^\s*\**\s*Severity\s*\**\s*:\**\s*(Critical|High|Medium|Low)\b",
         "severity-header"),
        (r"(?im)^\s*severity_tier\s*:\s*(Critical|High|Medium|Low)\b",
         "impact-contract"),
        (r"(?im)^\s*severity_implied\s*:\s*(Critical|High|Medium|Low)\b",
         "program-impact-mapping"),
        (r"(?im)^\s*selected_severity\s*:\s*(Critical|High|Medium|Low)\b",
         "selected-severity"),
    ):
        match = re.search(pattern, text)
        if match:
            return match.group(1).lower(), source
    for severity in ("critical", "high", "medium", "low"):
        if re.search(rf"(?:^|[-_]){severity}(?:[-_.]|$)", path.name.lower()):
            return severity, "filename"
    return None, "missing"


def _workspace_root(draft: Path) -> Path:
    cur = draft.resolve().parent
    for parent in [cur, *cur.parents]:
        if (parent / "poc-tests").is_dir() or (parent / "submissions").is_dir():
            return parent
    return draft.resolve().parent


def _resolve_poc_paths(draft: Path, text: str, explicit: list[str]) -> list[Path]:
    root = _workspace_root(draft)
    refs = list(explicit)
    refs.extend(
        match.group(1)
        for match in re.finditer(r"<!--\s*poc-dir:\s*([^>]+?)\s*-->", text, re.IGNORECASE)
    )
    refs.extend(
        match.group(0)
        for match in re.finditer(r"\b(?:poc-tests|external)/[A-Za-z0-9_.\-/]+", text)
    )
    resolved: list[Path] = []
    for raw in refs:
        ref = raw.strip().strip("`'\"").rstrip(").,;:")
        if not ref or "<" in ref or ">" in ref:
            continue
        path = Path(ref).expanduser()
        candidates = (
            [path]
            if path.is_absolute()
            else [root / path, draft.parent / path, Path.cwd() / path]
        )
        for candidate in candidates:
            if candidate.exists() and candidate not in resolved:
                resolved.append(candidate)
                break
    return resolved


def _source_files(paths: list[Path]) -> list[Path]:
    files: list[Path] = []
    for path in paths:
        if path.is_file() and path.suffix in CODE_SUFFIXES:
            files.append(path)
        elif path.is_dir():
            files.extend(
                sorted(
                    p for p in path.rglob("*")
                    if p.is_file() and p.suffix in CODE_SUFFIXES
                )
            )
    return files


def _combined_text(draft_text: str, poc_paths: list[Path]) -> tuple[str, list[str]]:
    chunks = [draft_text]
    scanned: list[str] = []
    for path in _source_files(poc_paths):
        try:
            chunks.append(_read_text(path))
            scanned.append(str(path))
        except Exception:
            continue
    return "\n".join(chunks), scanned


def _line_hits(text: str, pattern: re.Pattern[str], *, limit: int = 12) -> list[dict[str, Any]]:
    hits: list[dict[str, Any]] = []
    for idx, line in enumerate(text.splitlines(), start=1):
        match = pattern.search(line)
        if match:
            hits.append(
                {"line": idx, "token": match.group(0)[:80], "text": line.strip()[:240]}
            )
            if len(hits) >= limit:
                break
    return hits


def _matches(text: str, pattern: re.Pattern[str]) -> bool:
    """Whole-text match - catches phrases split across wrapped lines.

    `_line_hits` is line-based for citation reporting; a trigger phrase that
    word-wraps across two lines would be missed by a per-line scan. Boolean
    trigger detection uses this whitespace-normalised whole-text search so
    line wrapping does not change the verdict.
    """
    normalized = re.sub(r"\s+", " ", text)
    return pattern.search(normalized) is not None


def _env_extra(name: str) -> re.Pattern[str] | None:
    raw = os.environ.get(name, "")
    if not raw.strip():
        return None
    parts = [p.strip() for p in raw.splitlines() if p.strip()]
    if not parts:
        return None
    return re.compile("|".join(f"(?:{p})" for p in parts), re.IGNORECASE)


def _rebuttal(text: str) -> str | None:
    match = REBUTTAL_LINE_RE.search(text)
    if not match:
        match = REBUTTAL_RE.search(text)
    if not match:
        return None
    return " ".join(match.group(1).split())


def _triage_followup_reason(
    has_assumption: bool, has_runtime: bool, *, narrowed: bool
) -> str:
    """Build the fail-missing-triage-followup reason from which answer is gone.

    Field 5 (Rule 42) requires the draft to pre-answer the two questions a
    triager always asks for a config-dependent claim. A narrowed claim is not
    exempt - narrowing changes the impact wording, not the triager questions.
    """
    prefix = (
        "claim is honestly narrowed but " if narrowed
        else "config-dependent Medium+ claim is missing field 5: "
    )
    missing: list[str] = []
    if not has_assumption:
        missing.append(
            "'what deployed/configured-chain assumption is needed?'"
        )
    if not has_runtime:
        missing.append(
            "'what downstream runtime path realizes impact?'"
        )
    return (
        f"{prefix}the Configured-Impact Trace does not pre-answer the "
        f"triage-follow-up question(s): {' and '.join(missing)} - add an "
        "explicit 'Triage-follow-up pre-answer' block answering both"
    )


def _has_source_backing(text: str) -> bool:
    return bool(FILE_LINE_RE.search(text) or ADDRESS_RE.search(text) or COMMIT_RE.search(text))


def run(
    draft: Path,
    *,
    severity_override: str | None = None,
    poc_dir: list[str] | None = None,
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
        "severity": severity,
        "severity_source": severity_source,
        "strict": strict,
        "evidence": {},
        "remediation_options": [
            "Add a 'Configured-Impact Trace' section with all five fields: "
            "Scope mode, Configuration precondition, Evidence, Downstream "
            "consumer, Hop-by-hop impact trace, Executed in PoC? yes/no, "
            "If no, narrowed claim / severity cap, Triage-follow-up pre-answer.",
            "Field 1 (scope mode): state source-only / deployed-only / mixed.",
            "Field 2 (configuration precondition): cite the source config, "
            "runtime registration, deployment config, registry mapping, contract "
            "constructor, admin-set value, or live state that enables the "
            "vulnerable path in the in-scope environment.",
            "Field 3 (downstream consumer): name the exact configured "
            "downstream component that consumes the bad state/value/root/message; "
            "give a file:line citation or executed PoC assertion per hop.",
            "Field 4 (evidence-class match): if the PoC executes only the "
            "upstream acceptance step, word the impact as 'accepted "
            "forged/unfinalized state' / 'state-integrity failure' unless the "
            "downstream fund/message path is executed or fully source-traced.",
            "Field 5 (triage-follow-up pre-answer): explicitly answer both "
            "'what deployed/configured-chain assumption is needed?' and 'what "
            "downstream runtime path realizes impact?' - a triager asks these "
            "for every config-dependent claim; pre-answer them in the draft.",
            "Honest narrowing PASSES: state 'severity capped because "
            "deployment/configuration is unproven' or 'downstream fund-loss only "
            "if configured for a value-bearing state machine'. A narrowed claim "
            "still has to answer field 5.",
            "Override: visible 'r42-rebuttal: <source-backed reason>' line "
            "(<=200 chars) or <!-- r42-rebuttal: <source-backed reason> -->; "
            "the reason must cite file:line, address, or commit evidence.",
        ],
    }

    # Below Medium: out of scope.
    if severity is None or SEVERITY_RANK.get(severity, 0) < SEVERITY_RANK["medium"]:
        payload["verdict"] = "pass-out-of-scope"
        payload["reason"] = "severity below Medium or missing"
        return 0, payload

    # Source-backed rebuttal short-circuit.
    rebuttal = _rebuttal(text)
    if rebuttal and len(rebuttal) <= REBUTTAL_MAX_CHARS and _has_source_backing(rebuttal):
        payload["verdict"] = "ok-rebuttal"
        payload["rebuttal"] = rebuttal
        return 0, payload
    if rebuttal:
        payload["rebuttal_invalid"] = True
        payload["rebuttal_invalid_reason"] = (
            "r42-rebuttal must be <=200 chars and cite source evidence "
            "such as file:line, address, or commit"
        )
        payload["rebuttal_observed_length"] = len(rebuttal)

    extra_config_re = _env_extra("AUDITOOOR_R42_CONFIG_PATTERNS")
    config_dependent_hits = _line_hits(text, CONFIG_DEPENDENT_RE)
    if extra_config_re is not None:
        config_dependent_hits.extend(_line_hits(text, extra_config_re))
    is_config_dependent = bool(config_dependent_hits) or _matches(
        text, CONFIG_DEPENDENT_RE
    )
    if not is_config_dependent and extra_config_re is not None:
        is_config_dependent = _matches(text, extra_config_re)

    if not is_config_dependent:
        payload["verdict"] = "pass-not-config-dependent"
        payload["reason"] = (
            "draft's impact does not depend on a deployed/configured component "
            "(no registered chain/client/router/oracle/adapter, feature flag, "
            "role set, asset pool, bridge reserve, runtime pallet, or downstream "
            "consumer)"
        )
        payload["evidence"]["config_dependent_hits"] = config_dependent_hits
        return 0, payload

    poc_paths = _resolve_poc_paths(draft, text, poc_dir or [])
    combined, scanned = _combined_text(text, poc_paths)

    trace_section_hits = _line_hits(text, TRACE_SECTION_RE)
    config_precondition_hits = _line_hits(text, CONFIG_PRECONDITION_RE)
    downstream_consumer_hits = _line_hits(text, DOWNSTREAM_CONSUMER_RE)
    scope_mode_hits = _line_hits(text, SCOPE_MODE_RE)
    file_line_hits = _line_hits(text, FILE_LINE_RE)
    executed_poc_hits = _line_hits(combined, EXECUTED_POC_RE)
    fund_impact_hits = _line_hits(text, FUND_IMPACT_RE)
    narrowed_hits = _line_hits(text, NARROWED_IMPACT_RE)
    if_configured_hits = _line_hits(text, IF_CONFIGURED_RE)
    hypothetical_hits = _line_hits(text, HYPOTHETICAL_RE)
    scope_statement_hits = _line_hits(text, SCOPE_STATEMENT_RE)
    generic_downstream_hits = _line_hits(text, GENERIC_DOWNSTREAM_RE)
    triage_assumption_hits = _line_hits(text, TRIAGE_FOLLOWUP_ASSUMPTION_RE)
    triage_runtime_hits = _line_hits(text, TRIAGE_FOLLOWUP_RUNTIME_RE)

    has_trace_section = bool(trace_section_hits) or _matches(text, TRACE_SECTION_RE)
    has_config_precondition = bool(config_precondition_hits) or _matches(
        text, CONFIG_PRECONDITION_RE
    )
    has_downstream_consumer = bool(downstream_consumer_hits) or _matches(
        text, DOWNSTREAM_CONSUMER_RE
    )
    has_downstream_citation = bool(file_line_hits) or bool(executed_poc_hits)
    has_executed_poc = bool(executed_poc_hits) or _matches(combined, EXECUTED_POC_RE)
    claims_fund_impact = bool(fund_impact_hits) or _matches(text, FUND_IMPACT_RE)
    is_narrowed = bool(narrowed_hits) or _matches(text, NARROWED_IMPACT_RE)
    has_if_configured = bool(if_configured_hits) or _matches(text, IF_CONFIGURED_RE)
    has_hypothetical = bool(hypothetical_hits) or _matches(text, HYPOTHETICAL_RE)
    has_scope_statement = bool(scope_statement_hits) or _matches(
        text, SCOPE_STATEMENT_RE
    )
    has_generic_downstream = bool(generic_downstream_hits) or _matches(
        text, GENERIC_DOWNSTREAM_RE
    )
    has_triage_assumption = bool(triage_assumption_hits) or _matches(
        text, TRIAGE_FOLLOWUP_ASSUMPTION_RE
    )
    has_triage_runtime = bool(triage_runtime_hits) or _matches(
        text, TRIAGE_FOLLOWUP_RUNTIME_RE
    )
    has_triage_followup = has_triage_assumption and has_triage_runtime

    payload["poc_paths"] = [str(path) for path in poc_paths]
    payload["evidence"] = {
        "config_dependent_hits": config_dependent_hits,
        "trace_section_hits": trace_section_hits,
        "config_precondition_hits": config_precondition_hits,
        "downstream_consumer_hits": downstream_consumer_hits,
        "scope_mode_hits": scope_mode_hits,
        "file_line_citation_hits": file_line_hits,
        "executed_poc_hits": executed_poc_hits,
        "fund_impact_hits": fund_impact_hits,
        "narrowed_claim_hits": narrowed_hits,
        "if_configured_hits": if_configured_hits,
        "hypothetical_component_hits": hypothetical_hits,
        "scope_statement_hits": scope_statement_hits,
        "generic_downstream_hits": generic_downstream_hits,
        "triage_followup_assumption_hits": triage_assumption_hits,
        "triage_followup_runtime_hits": triage_runtime_hits,
        "scanned_files": scanned,
    }
    payload["trace"] = {
        "config_dependent": True,
        "has_configured_impact_trace_section": has_trace_section,
        "has_configuration_precondition": has_config_precondition,
        "has_downstream_consumer_path": has_downstream_consumer,
        "downstream_has_file_line_or_poc_citation": has_downstream_citation,
        "downstream_executed_in_poc": has_executed_poc,
        "claims_fund_impact": claims_fund_impact,
        "claim_narrowed": is_narrowed,
        "has_triage_followup_assumption_answer": has_triage_assumption,
        "has_triage_followup_runtime_answer": has_triage_runtime,
        "has_triage_followup_preanswer": has_triage_followup,
    }

    # --- Fail 1: hypothetical component, not rescued by a narrowed claim. ---
    if has_hypothetical and not is_narrowed:
        payload["verdict"] = "fail-hypothetical-component"
        payload["reason"] = (
            "the affected chain/client/router/oracle/asset is only hypothetical "
            "(no registered/deployed/configured instance) and the claim is not "
            "honestly narrowed - prove a configured instance or narrow the claim"
        )
        return 1, payload

    # --- Fail 2: "if configured this way" with no config/live/scope evidence
    # and no narrowed claim. -------------------------------------------------
    if (
        has_if_configured
        and not has_config_precondition
        and not has_scope_statement
        and not is_narrowed
    ):
        payload["verdict"] = "fail-if-configured-without-evidence"
        payload["reason"] = (
            "the proof relies on an 'if configured this way' dependency without "
            "stating whether that configuration is in-scope / production-plausible "
            "/ live, and the claim is not narrowed - cite the configuration "
            "precondition or narrow the claim"
        )
        return 1, payload

    # --- Honest narrowing PASSES. The rule explicitly permits a narrowed
    # claim ("accepted forged/unfinalized state", "severity capped because
    # configuration unproven", "downstream fund-loss only if configured for a
    # value-bearing state machine") in place of a closed downstream path. But
    # a narrowed claim still needs a Configured-Impact Trace section so the
    # configuration precondition and the (source-traced) downstream are
    # visible to the triager. -----------------------------------------------
    if is_narrowed:
        if not has_trace_section and not (
            has_config_precondition and has_downstream_consumer
        ):
            payload["verdict"] = "fail-no-configured-impact-trace"
            payload["reason"] = (
                "claim is honestly narrowed but the draft lacks a "
                "'Configured-Impact Trace' section (or the configuration-"
                "precondition + downstream-consumer sub-fields) - add the trace "
                "so the configured precondition and source-traced downstream "
                "are explicit"
            )
            return 1, payload
        if not has_triage_followup:
            payload["verdict"] = "fail-missing-triage-followup"
            payload["reason"] = _triage_followup_reason(
                has_triage_assumption, has_triage_runtime, narrowed=True
            )
            return 1, payload
        payload["verdict"] = "pass-claim-narrowed"
        payload["reason"] = (
            "draft honestly narrows the claim (accepted forged/unfinalized "
            "state, or severity capped because configuration/deployment is "
            "unproven) and carries a Configured-Impact Trace - Rule 42 permits "
            "narrowing in place of a closed downstream fund/message path"
        )
        return 0, payload

    # --- Beyond this point the claim is NOT narrowed: the full trace is
    # required. --------------------------------------------------------------
    if not has_trace_section and not (
        has_config_precondition and has_downstream_consumer
    ):
        payload["verdict"] = "fail-no-configured-impact-trace"
        payload["reason"] = (
            "config-dependent Medium+ claim with no 'Configured-Impact Trace' "
            "section and no configuration-precondition + downstream-consumer "
            "sub-fields - add the trace before promotion"
        )
        return 1, payload

    if not has_config_precondition:
        payload["verdict"] = "fail-no-configured-impact-trace"
        payload["reason"] = (
            "Configured-Impact Trace is missing sub-field 1 (configuration "
            "precondition): cite source config / runtime registration / "
            "deployment config / registry mapping / constructor / admin-set "
            "value / live state proving the vulnerable path is enabled in scope"
        )
        return 1, payload

    if not has_downstream_consumer:
        payload["verdict"] = "fail-no-configured-impact-trace"
        payload["reason"] = (
            "Configured-Impact Trace is missing sub-field 2 (downstream "
            "consumer path): name the exact configured downstream component "
            "that consumes the bad state/value/root/message"
        )
        return 1, payload

    # --- Fail 3: downstream reasoned generically, not tied to the configured
    # consumer. --------------------------------------------------------------
    if has_generic_downstream and not has_downstream_citation:
        payload["verdict"] = "fail-downstream-generic-not-configured"
        payload["reason"] = (
            "the downstream module is reasoned generically instead of tied to "
            "the actual configured consumer with a file:line / PoC citation - "
            "cite the exact configured downstream component per hop"
        )
        return 1, payload

    # --- Fail 4: overclaimed impact vs evidence. The draft claims fund loss
    # but only the upstream acceptance step is proven, with no executed and no
    # fully-source-traced downstream path. -----------------------------------
    if claims_fund_impact and not has_executed_poc and not has_downstream_citation:
        payload["verdict"] = "fail-overclaimed-impact-vs-evidence"
        payload["reason"] = (
            "draft claims loss of funds but proves only verifier acceptance / a "
            "source gap - the downstream fund/message path is neither executed "
            "nor fully source-traced; word the impact as 'accepted "
            "forged/unfinalized state' / 'state-integrity failure' or close the "
            "downstream path"
        )
        return 1, payload

    if strict and not has_downstream_citation:
        payload["verdict"] = "fail-overclaimed-impact-vs-evidence"
        payload["reason"] = (
            "strict mode: the downstream consumer path carries no file:line or "
            "executed-PoC citation per hop"
        )
        return 1, payload

    # --- Fail 5: missing triage-follow-up pre-answer (field 5). The draft must
    # explicitly pre-answer the two questions a triager always asks for a
    # config-dependent claim: "what deployed/configured-chain assumption is
    # needed?" and "what downstream runtime path realizes impact?". -----------
    if not has_triage_followup:
        payload["verdict"] = "fail-missing-triage-followup"
        payload["reason"] = _triage_followup_reason(
            has_triage_assumption, has_triage_runtime, narrowed=False
        )
        return 1, payload

    payload["verdict"] = "pass-configured-impact-traced"
    payload["reason"] = (
        "draft carries a Configured-Impact Trace: configuration precondition "
        "cited, downstream consumer path tied to the configured component with "
        "file:line / PoC citations, and the impact wording matches the "
        "evidence class"
    )
    return 0, payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("draft", type=Path)
    parser.add_argument(
        "--severity",
        choices=["auto", "Critical", "High", "Medium", "Low",
                 "critical", "high", "medium", "low"],
        default="auto",
    )
    parser.add_argument("--poc-dir", action="append", default=[])
    parser.add_argument("--strict", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    override = None if args.severity == "auto" else args.severity
    rc, payload = run(
        args.draft,
        severity_override=override,
        poc_dir=args.poc_dir,
        strict=args.strict,
    )
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        verdict = payload.get("verdict", "error")
        print(f"[{GATE}] {verdict}  severity={payload.get('severity')}  "
              f"file={args.draft}")
        if payload.get("reason"):
            print(f"  reason: {payload['reason']}")
        if payload.get("rebuttal"):
            print(f"  rebuttal: {payload['rebuttal']}")
        if verdict.startswith("fail"):
            for opt in payload.get("remediation_options", []):
                print(f"  fix: {opt}")
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
