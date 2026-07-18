#!/usr/bin/env python3
"""Rule 60 Reachability-Proactive-Embed gate (Check #107).

# Rule 60: this tool emits no corpus record.

TRIGGER: severity Medium+ AND draft body contains reachability-uncertainty
prose ("requires", "extraordinary", "if reachable", "depends on operator",
"production-plausible", "operator-only assessment",
"depends on accumulation", "may not be reachable") in Disposition /
Reachability sections.

When a Medium+ draft surfaces reachability uncertainty in prose, the natural
triager question is "what production path turns this into impact?". If the
draft answers that question only in the cover-letter "Disposition" sentence
without an inline upstream-source proof, the triager closes the finding for
"cannot verify reachability". R60 codifies the "always-escalate-by-default"
rule: the moment uncertainty surfaces in prose, the draft MUST embed an
inline 4-field proof so the triager does not have to guess.

Anchor lesson: DRILL-6 (Medium, hb-pallet-relayer-u256-truncation) was filed
with the Disposition disclosing reachability uncertainty
("operator-only assessment", "extraordinary") without an inline 4-field
Reachability proof in the original body. Operator caught it post-file and
upgraded the body to embed the proof. R60 mechanizes that always-on
upgrade so future Medium+ drafts cannot ship without it.

If a draft triggers R60 it MUST contain a "Reachability" section header
(matching regex r"^##\\s*Reachability" or an inline "Reachability -" / inline
"## Reachability *" form) AND the document body must surface all four of:

  1. Upstream-entry citation:
     - file:line reference, AND
     - an actor-control keyword (one of: user-controlled,
       attacker-controlled, oracle-controlled, operator-controlled,
       governance-controlled, relayer-controlled, validator-controlled,
       proposer-controlled, signer-controlled, anyone-can-call,
       unsigned origin, unprivileged, permissionless, public entrypoint)
  2. Bound-evidence:
     - an explicit grep-count statement ("exhaustive grep ... returned
       ZERO production-code hits"), OR
     - an "no bound check exists" / "no MAX_FEE / max_fee /
       saturating_add" / "no overflow guard" claim
  3. At least one single-shot scenario:
     - "single tx", "one transaction", "single-tx reach", "single-shot",
       "one withdrawal cycle", "single call", "one invocation",
       "even one occurrence", "single hop", "in one block"
  4. At least one real-world prior-art anchor:
     - a citation to a prior audit / CVE / GHSA / Solodit / Cyfrin /
       OpenZeppelin / Trail of Bits / Trail-of-Bits / ToB / SRL /
       Hacken / similar exploit class / Halborn / Spearbit / ConsenSys
       Diligence / Sherlock / Code4rena / Cantina / Immunefi /
       Quantstamp / CertiK / DefiLlama / rekt.news, OR a workspace
       prior_audits/DIGEST anchor (treat as in-workspace prior art).

Honest dispositions PASS:
  pass-out-of-scope                       : severity below Medium
  pass-no-uncertainty-prose               : Medium+ but Disposition is
                                            already escalation-built; no
                                            uncertainty hedges found
  pass-reachability-section-complete      : section present + all 4 fields
                                            detected in the document body
  ok-rebuttal                             : visible bounded r60-rebuttal

Fail-closed verdicts:
  fail-no-reachability-section            : uncertainty prose found AND
                                            no `## Reachability*` section
  fail-missing-upstream-citation          : section present, no file:line +
                                            actor-control combo
  fail-missing-bound-evidence             : section present, no grep-count
                                            or "no bound" claim
  fail-missing-single-shot-scenario       : section present, no single-tx
                                            verb phrase
  fail-missing-prior-art-anchor           : section present, no recognized
                                            external prior-art reference
  error

Exit codes:
  0 - pass / ok-rebuttal / pass-out-of-scope
  1 - any fail-* verdict (always; or with --strict for warn-grade flags)
  2 - input error

Schema: auditooor.r60_reachability_proactive_embed.v1

Override marker:
  visible bounded line "r60-rebuttal: <reason>" (<=200 chars)
    OR
  HTML-comment form "<!-- r60-rebuttal: <reason> -->" (<=200 chars).
  Empty or oversized reasons are ignored; original fail verdict stands.

Env extension hooks:
  AUDITOOOR_R60_UNCERTAINTY_PATTERNS  - newline-separated regex list
                                        appended to DEFAULT_UNCERTAINTY_PATTERNS
  AUDITOOOR_R60_PRIOR_ART_PATTERNS    - newline-separated regex list
                                        appended to DEFAULT_PRIOR_ART_PATTERNS
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "auditooor.r60_reachability_proactive_embed.v1"
GATE = "R60-REACHABILITY-PROACTIVE-EMBED"

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
MIN_SEVERITY_RANK = SEVERITY_RANK["medium"]

# ---------------------------------------------------------------------------
# Trigger: uncertainty prose detectors
# ---------------------------------------------------------------------------

DEFAULT_UNCERTAINTY_PATTERNS = [
    r"\bif\s+reachable\b",
    r"\bif\s+the\s+(?:condition|attack|exploit|path)\s+is\s+reachable\b",
    r"\bmay\s+not\s+be\s+reachable\b",
    r"\bmight\s+not\s+be\s+reachable\b",
    r"\breachability\s+(?:is|remains|stays)\s+(?:the\s+)?(?:calibration|open|uncertain|unclear)\b",
    r"\boperator[- ]only\s+(?:assessment|judgment|judgement|decision|call)\b",
    r"\bdepends\s+on\s+operator\b",
    r"\bdepends\s+on\s+(?:accumulation|deployment|deployment topology|configuration|config|deployed\s+config)\b",
    r"\brequires\s+(?:extraordinary|degenerate|adversarial)\b",
    r"\bextraordinary\b",
    r"\bproduction[- ]plausible\b",
    r"\bproduction[- ]plausibility\b",
    r"\bis\s+this\s+(?:routinely\s+)?reachable\b",
    r"\bwhether\s+(?:this|the\s+condition)\s+is\s+reachable\b",
    r"\bwhether\s+the\s+(?:attack|exploit|condition)\s+(?:can|will)\s+be\s+(?:reached|hit|triggered)\b",
    r"\bcalibration\s+question\b",
    r"\bdegenerate\s+upstream\b",
    r"\bonly\s+if\s+(?:configured|registered|deployed)\b",
    r"\bextraordinarily\s+high\s+threshold\b",
    r"\bunclear\s+whether\b",
    r"\bopen\s+question\b",
]

# ---------------------------------------------------------------------------
# Section header detectors
# ---------------------------------------------------------------------------

REACHABILITY_SECTION_RE = re.compile(
    r"(?im)^##\s*reachability\b",
)
# Inline alternative: a "Reachability -" or "Reachability:" line in a
# bullet/heading that is not a `##` header.
REACHABILITY_INLINE_RE = re.compile(
    r"(?im)^\s*(?:[-*]\s*)?\**\s*reachability\s*[-:]\s+",
)

# ---------------------------------------------------------------------------
# Field detectors
# ---------------------------------------------------------------------------

# (1) Upstream-entry citation:
#     file:line reference (covers .rs / .go / .sol / .py / .ts / .move / .vy /
#     .cairo and other source extensions). .md is excluded - markdown files
#     are documentation, not upstream source; .md:line citations are typically
#     prior_audits/DIGEST anchors (prior-art) not upstream-entry citations.
FILE_LINE_RE = re.compile(
    r"\b[\w./\-]+\.(?:rs|go|sol|py|ts|tsx|js|move|vy|cairo|yul|huff|c|cpp|h|java|kt|swift|rb|php|cs)"
    r":\d+(?:[-:]\d+)?\b",
    re.IGNORECASE,
)

ACTOR_CONTROL_PATTERNS = [
    r"\buser[- ]controlled\b",
    r"\battacker[- ]controlled\b",
    r"\boracle[- ]controlled\b",
    r"\boperator[- ]controlled\b",
    r"\bgovernance[- ]controlled\b",
    r"\brelayer[- ]controlled\b",
    r"\bvalidator[- ]controlled\b",
    r"\bproposer[- ]controlled\b",
    r"\bsigner[- ]controlled\b",
    r"\bsequencer[- ]controlled\b",
    r"\banyone[- ]can[- ]call\b",
    r"\banyone\s+can\s+call\b",
    r"\bcallable\s+by\s+(?:any|anyone)\b",
    r"\bunsigned\s+origin\b",
    r"\bunprivileged\b",
    r"\bpermissionless\b",
    r"\bpublic\s+(?:entry\s*point|entrypoint|function|extrinsic)\b",
    r"\bexternal\s+(?:entry\s*point|entrypoint|function|extrinsic|call)\b",
    r"\bany\s+(?:user|caller|relayer|validator|account)\b",
    r"\bunauthenticated\b",
    r"\bopen\s+to\s+(?:any|all)\b",
]

# (2) Bound-evidence: grep-count statements OR "no bound check" claims.
GREP_COUNT_PATTERNS = [
    r"\bexhaustive\s+grep\b.*\b(?:returned|found|yielded|emitted)\s+(?:ZERO|zero|0|no)\b",
    r"\bgrep\b[^.]{0,80}\b(?:returned|found|yielded|emitted)\s+(?:ZERO|zero|0|no)\b",
    r"\bgrep\b[^.]{0,80}\b(?:zero|0)\s+production[- ]code\s+hits\b",
    r"\b(?:returned|found|yielded)\s+(?:ZERO|zero|0|no)\s+production[- ]code\s+hits\b",
    r"\b(?:returned|found|yielded)\s+(?:ZERO|zero|0|no)\s+hits\b",
    r"\bgrep\s+-rn?\b",  # explicit grep invocation evidence
]

NO_BOUND_PATTERNS = [
    r"\bno\s+(?:overflow|underflow|bound|cap|range|size|length|saturating)\s+(?:check|guard|validation|limit|protection)\b",
    r"\bNO\s+(?:overflow|underflow|bound|cap|range|size|length|saturating)\s+(?:check|guard|validation|limit|protection)\b",
    r"\bno\s+(?:checked_add|checked_sub|checked_mul|saturating_add|saturating_sub|try_into|try_from)\b",
    r"\bno\s+(?:MAX_FEE|max_fee|MAX_AMOUNT|max_amount|MAX_SIZE|max_size|MAX_DEPTH|max_depth|UPPER_BOUND|upper_bound)\b",
    r"\bno\s+(?:upper\s+bound|upper[- ]bound|lower\s+bound|lower[- ]bound|range\s+check|range[- ]check)\b",
    r"\bno\s+(?:bound\s+check|bound[- ]check|cap\s+check|cap[- ]check)\s+(?:exists|present|in\s+place|enforced)?\b",
    r"\bno\s+(?:such\s+)?guard\s+(?:exists|present|in\s+place)\b",
    r"\bNo\s+(?:such\s+)?guard\s+exists\b",
    r"\babsent\s+(?:bound\s+check|cap\s+check|overflow\s+check|guard)\b",
    r"\b(?:bound|cap|overflow)\s+check\s+(?:is\s+)?absent\b",
    r"\bguard\s+(?:is\s+)?absent\b",
    r"\bABSENT\b",
    r"\bno\s+in[- ]tree\s+guard\b",
]

# (3) Single-shot scenario: at least one phrase asserting a one-call/one-tx
#     reach to the impact.
SINGLE_SHOT_PATTERNS = [
    r"\bsingle\s+(?:tx|transaction|call|hop|block|message|invocation|withdrawal|swap|step)\b",
    r"\bone\s+(?:tx|transaction|call|hop|block|message|invocation|withdrawal|swap|step|occurrence)\b",
    r"\bsingle[- ](?:tx|transaction|call|hop|block|shot|step)\s+(?:reach|hit|trigger)\b",
    r"\bsingle[- ]shot\b",
    r"\bone\s+(?:withdrawal|delivery|delivery cycle|withdrawal cycle|operation|action)\s+(?:cycle|step)?\b",
    r"\beven\s+one\s+occurrence\b",
    r"\bone\s+invocation\b",
    r"\bin\s+(?:a\s+)?single\s+(?:tx|transaction|call|block)\b",
    r"\bin\s+one\s+(?:tx|transaction|call|block|hop)\b",
    r"\ba\s+single\s+(?:tx|transaction|call|hop|message|invocation)\b",
    r"\bsingle\s+call\b",
]

# (4) Prior-art anchor: external venue OR in-workspace prior_audits/DIGEST.
DEFAULT_PRIOR_ART_PATTERNS = [
    r"\bCVE-\d{4}-\d{3,7}\b",
    r"\bGHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}\b",
    r"\bSolodit\b",
    r"\bsolodit\.cyfrin\.io\b",
    r"\bCyfrin\b",
    r"\bOpenZeppelin\b",
    r"\bopen[- ]zeppelin\b",
    r"\bTrail\s+of\s+Bits\b",
    r"\bTrail[- ]of[- ]Bits\b",
    r"\bToB\b",
    r"\bHalborn\b",
    r"\bSpearbit\b",
    r"\bConsenSys\s+Diligence\b",
    r"\bConsenSys[- ]Diligence\b",
    r"\bSherlock\b",
    r"\bCode4rena\b",
    r"\bC4\b",
    r"\bCantina\b",
    r"\bImmunefi\b",
    r"\bQuantstamp\b",
    r"\bCertiK\b",
    r"\bCert[- ]?IK\b",
    r"\bHacken\b",
    r"\bHackenProof\b",
    r"\bSRL\b",
    r"\bSRL[- ]\w+",
    r"\bDefiLlama\b",
    r"\brekt\.news\b",
    r"\bsimilar\s+exploit\s+class\b",
    r"\bsimilar\s+exploit\b",
    r"\bprior[- ]art\s+anchor\b",
    r"\bprior\s+exploit\b",
    r"\bpost[- ]mortem\b",
    r"\bpost[- ]mortems?\b",
    r"\bIncident\s+(?:Report|Postmortem)\b",
    # In-workspace prior_audits/DIGEST anchors: documented prior-art in audit
    # workspace counts as a valid prior-art anchor.
    r"\bprior_audits/[\w./\-]+",
    r"\bprior[- ]audits?/[\w./\-]+",
    r"\bDIGEST[_\-A-Z0-9]*\b",
    r"\bDigest\s+(?:of\s+prior\s+audits|entry)\b",
    r"\bresidual\s+hunt\s+area\b",
]

# ---------------------------------------------------------------------------
# Rebuttal markers
# ---------------------------------------------------------------------------

REBUTTAL_HTML_RE = re.compile(
    r"<!--\s*r60-rebuttal:\s*(.*?)\s*-->", re.IGNORECASE | re.DOTALL
)
REBUTTAL_LINE_RE = re.compile(
    r"(?im)^\s*(?:[-*]\s*)?r60[-_ ]rebuttal\s*:\s*(.+?)\s*$"
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _env_patterns(name: str) -> list[str]:
    raw = os.environ.get(name, "")
    if not raw.strip():
        return []
    return [item.strip() for item in raw.splitlines() if item.strip()]


def _compile_union(patterns: list[str]) -> re.Pattern[str]:
    return re.compile("|".join(f"(?:{p})" for p in patterns), re.IGNORECASE)


def _severity(text: str, path: Path, override: str | None) -> tuple[str | None, str]:
    if override:
        normalized = override.strip().lower()
        if normalized in SEVERITY_RANK:
            return normalized, "cli"
    for pattern, source in (
        (r"(?im)^\s*(?:[-*]\s+)?\**\s*Severity\s*:\**\s*(Critical|High|Medium|Low)\b", "severity-header"),
        (r"(?im)^\s*(?:[-*]\s+)?severity_implied\s*:\s*(Critical|High|Medium|Low)\b", "program-impact-mapping"),
        (r"(?im)^\s*(?:[-*]\s+)?severity_tier\s*:\s*(Critical|High|Medium|Low)\b", "impact-contract"),
        (r"(?im)^\s*(?:[-*]\s+)?selected_severity\s*:\s*(Critical|High|Medium|Low)\b", "selected-severity"),
        (r"(?im)^\s*(?:[-*]\s+)?\**\s*Severity\s+selector\s*:\**\s*(Critical|High|Medium|Low)\b", "severity-selector"),
    ):
        m = re.search(pattern, text)
        if m:
            return m.group(1).lower(), source
    for sev in ("critical", "high", "medium", "low"):
        if re.search(rf"(?:^|[-_]){sev}(?:[-_.]|$)", path.name.lower()):
            return sev, "filename"
    return None, "missing"


def _rebuttal(text: str) -> str | None:
    m = REBUTTAL_LINE_RE.search(text)
    if not m:
        m = REBUTTAL_HTML_RE.search(text)
    if not m:
        return None
    return " ".join(m.group(1).split())


def _line_hits(text: str, pattern: re.Pattern[str], limit: int = 8) -> list[dict[str, Any]]:
    hits: list[dict[str, Any]] = []
    for idx, line in enumerate(text.splitlines(), start=1):
        m = pattern.search(line)
        if m:
            hits.append({
                "line": idx,
                "token": m.group(0)[:120],
                "text": line.strip()[:240],
            })
            if len(hits) >= limit:
                break
    return hits


def _has_reachability_section(text: str) -> bool:
    return bool(REACHABILITY_SECTION_RE.search(text)) or bool(REACHABILITY_INLINE_RE.search(text))


def _detect_upstream_citation(text: str) -> dict[str, Any]:
    """A valid upstream citation requires BOTH:
       - at least one file:line token
       - at least one actor-control phrase

    Returns evidence dict + boolean ok.
    """
    file_line_hits = _line_hits(text, FILE_LINE_RE, limit=5)
    actor_re = _compile_union(ACTOR_CONTROL_PATTERNS)
    actor_hits = _line_hits(text, actor_re, limit=5)
    return {
        "file_line_hits": file_line_hits,
        "actor_control_hits": actor_hits,
        "ok": bool(file_line_hits) and bool(actor_hits),
    }


def _detect_bound_evidence(text: str) -> dict[str, Any]:
    """A valid bound-evidence cite is either an explicit grep-count
    statement OR a 'no bound check exists' phrase.
    """
    grep_re = _compile_union(GREP_COUNT_PATTERNS)
    nobound_re = _compile_union(NO_BOUND_PATTERNS)
    grep_hits = _line_hits(text, grep_re, limit=5)
    nobound_hits = _line_hits(text, nobound_re, limit=5)
    return {
        "grep_count_hits": grep_hits,
        "no_bound_hits": nobound_hits,
        "ok": bool(grep_hits) or bool(nobound_hits),
    }


def _detect_single_shot(text: str) -> dict[str, Any]:
    ss_re = _compile_union(SINGLE_SHOT_PATTERNS)
    hits = _line_hits(text, ss_re, limit=5)
    return {"hits": hits, "ok": bool(hits)}


def _detect_prior_art(text: str) -> dict[str, Any]:
    env_extra = _env_patterns("AUDITOOOR_R60_PRIOR_ART_PATTERNS")
    pa_re = _compile_union(DEFAULT_PRIOR_ART_PATTERNS + env_extra)
    hits = _line_hits(text, pa_re, limit=5)
    return {"hits": hits, "ok": bool(hits)}


# ---------------------------------------------------------------------------
# Core logic
# ---------------------------------------------------------------------------

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
        "severity": severity,
        "severity_source": severity_source,
        "strict": strict,
        "evidence": {},
        "remediation_options": [
            "Add a top-level '## Reachability' section embedding (1) upstream-entry "
            "file:line + actor-control keyword, (2) bound-evidence (explicit grep-count "
            "or 'no bound check exists' claim), (3) at least one single-shot "
            "scenario verb phrase ('single tx', 'one call', 'even one occurrence'), "
            "and (4) at least one real-world prior-art anchor "
            "(CVE / GHSA / Solodit / Cyfrin / OpenZeppelin / TOB / SRL / prior_audits/DIGEST).",
            "Override: visible 'r60-rebuttal: <reason>' (<=200 chars) "
            "or '<!-- r60-rebuttal: <reason> -->' for finding-shape that legitimately "
            "carries no reachability question.",
        ],
    }

    # Severity discipline.
    if severity is None or SEVERITY_RANK.get(severity, 0) < MIN_SEVERITY_RANK:
        payload["verdict"] = "pass-out-of-scope"
        payload["reason"] = "severity below MEDIUM; R60 not applicable"
        return 0, payload

    # Rebuttal short-circuit.
    rebuttal = _rebuttal(text)
    if rebuttal and len(rebuttal) <= 200:
        payload["verdict"] = "ok-rebuttal"
        payload["rebuttal"] = rebuttal
        return 0, payload

    # Trigger: uncertainty prose.
    uncertainty_re = _compile_union(
        DEFAULT_UNCERTAINTY_PATTERNS + _env_patterns("AUDITOOOR_R60_UNCERTAINTY_PATTERNS")
    )
    uncertainty_hits = _line_hits(text, uncertainty_re, limit=12)
    payload["evidence"]["uncertainty_hits"] = uncertainty_hits

    if not uncertainty_hits:
        payload["verdict"] = "pass-no-uncertainty-prose"
        payload["reason"] = (
            "no reachability-uncertainty prose detected; escalation pre-built "
            "(Disposition already commits to severity)"
        )
        return 0, payload

    # Section presence is the gate door.
    section_present = _has_reachability_section(text)
    payload["evidence"]["reachability_section_present"] = section_present

    if not section_present:
        payload["verdict"] = "fail-no-reachability-section"
        payload["reason"] = (
            "reachability-uncertainty prose found in body but no '## Reachability' "
            "section embeds an inline 4-field proof; add the section or use r60-rebuttal"
        )
        return 1, payload

    # Section present: now verify the 4 fields.
    upstream = _detect_upstream_citation(text)
    bound = _detect_bound_evidence(text)
    single_shot = _detect_single_shot(text)
    prior_art = _detect_prior_art(text)
    payload["evidence"]["upstream_citation"] = upstream
    payload["evidence"]["bound_evidence"] = bound
    payload["evidence"]["single_shot_scenario"] = single_shot
    payload["evidence"]["prior_art_anchor"] = prior_art

    if not upstream["ok"]:
        payload["verdict"] = "fail-missing-upstream-citation"
        payload["reason"] = (
            "Reachability section present but no upstream-entry citation found "
            "(needs file:line reference AND actor-control keyword such as "
            "'user-controlled' / 'attacker-controlled' / 'unsigned origin' / "
            "'permissionless' / 'anyone can call')"
        )
        return 1, payload

    if not bound["ok"]:
        payload["verdict"] = "fail-missing-bound-evidence"
        payload["reason"] = (
            "Reachability section present but no bound-evidence cited "
            "(needs explicit grep-count statement OR 'no overflow guard / "
            "no MAX_FEE / no bound check exists' claim)"
        )
        return 1, payload

    if not single_shot["ok"]:
        payload["verdict"] = "fail-missing-single-shot-scenario"
        payload["reason"] = (
            "Reachability section present but no single-shot scenario verb phrase "
            "found (needs 'single tx' / 'one call' / 'even one occurrence' / "
            "'single-shot' / 'in one block' to bound the cost-to-reach)"
        )
        return 1, payload

    if not prior_art["ok"]:
        payload["verdict"] = "fail-missing-prior-art-anchor"
        payload["reason"] = (
            "Reachability section present but no real-world prior-art anchor cited "
            "(needs CVE / GHSA / Solodit / Cyfrin / OpenZeppelin / Trail of Bits / "
            "Halborn / Spearbit / SRL / Sherlock / Code4rena / Cantina / Immunefi / "
            "prior_audits/DIGEST citation)"
        )
        return 1, payload

    payload["verdict"] = "pass-reachability-section-complete"
    payload["reason"] = (
        "Reachability section present + all 4 fields detected: upstream-entry "
        "citation + bound-evidence + single-shot scenario + prior-art anchor"
    )
    return 0, payload


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("draft", type=Path, help="Path to draft .md file")
    parser.add_argument(
        "--severity",
        choices=[
            "auto", "Critical", "High", "Medium", "Low",
            "critical", "high", "medium", "low",
        ],
        default="auto",
    )
    parser.add_argument("--strict", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    override = None if args.severity == "auto" else args.severity
    rc, payload = run(
        args.draft,
        severity_override=override,
        strict=args.strict,
    )

    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        verdict = payload.get("verdict", "error")
        reason = payload.get("reason", payload.get("error", ""))
        prefix = "[PASS]" if verdict.startswith("pass") or verdict == "ok-rebuttal" else "[FAIL]"
        print(f"{prefix} {GATE}: {verdict}")
        if reason:
            print(f"  reason: {reason}")
        ev = payload.get("evidence", {})
        if ev.get("uncertainty_hits"):
            print(f"  uncertainty hits: {len(ev['uncertainty_hits'])}")
        if ev.get("reachability_section_present") is not None:
            print(f"  reachability section present: {ev['reachability_section_present']}")
        for fld in ("upstream_citation", "bound_evidence", "single_shot_scenario", "prior_art_anchor"):
            if fld in ev:
                print(f"  {fld}: ok={ev[fld].get('ok')}")
    return rc


if __name__ == "__main__":
    sys.exit(main())
