#!/usr/bin/env python3
"""Rule 43 Load-Bearing Bytes Attribution preflight (Check #91).

# Rule 43: this tool emits no corpus record.

GENERAL RULE - applies to any mediation, dispute, escalation, or
triager-response draft whose argument depends on a defender broadcasting /
spending / signing / submitting a load-bearing artifact (a transaction, a
signature share, a proof, a vote, a commitment, an attestation).

When a draft is at Medium+ severity AND contains defender-narrative phrasing
(e.g. "the SSP broadcasts", "the validator signs", "the sequencer commits"),
it MUST include a "Load-Bearing Bytes Attribution" section before promotion
to paste_ready/ or filed/.

The section must enumerate FIVE things per load-bearing artifact:
  1. Artifact identity (verbatim name)
  2. Production site (file:line or off-chain component + hand-off)
  3. Required signer set (threshold + roles)
  4. Attack-model attacker intersect (yes/no with file:line evidence)
  5. Withholding incentive analysis

Fail-closed for Medium+ drafts that contain defender-narrative phrasing but:
  - have no Load-Bearing Bytes Attribution section at all -> fail-no-attribution-section
  - enumerate no load-bearing bytes -> fail-no-bytes-enumerated
  - name bytes but cite no production site -> fail-no-production-site
  - name production site but omit signer set -> fail-no-signer-set
  - enumerate signers but omit attacker intersect -> fail-no-attacker-intersect
  - assert unreachability without withholding analysis -> fail-no-withholding-analysis

Pass verdicts:
  pass-out-of-scope              - severity below Medium or missing
  pass-no-defender-narrative     - draft contains no defender-narrative phrasing
  pass-attribution-complete-defense-unreachable - full section, verdict=unreachable
  pass-attribution-complete-defense-reachable   - full section, verdict=reachable
  pass-walk-back-justified       - full section, attacker NOT in signer set, walk-back explicit
  ok-rebuttal                    - valid r43-rebuttal marker present

Exit codes:
  0 - pass, out-of-scope, no-narrative, or accepted rebuttal
  1 - Rule 43 violation (with --strict always 1; without --strict still emits fail verdict but rc=0)
  2 - input error

Schema: auditooor.r43_load_bearing_bytes_attribution.v1
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "auditooor.r43_load_bearing_bytes_attribution.v1"
GATE = "R43-LOAD-BEARING-BYTES-ATTRIBUTION"

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
REBUTTAL_MAX_CHARS = 200

# ---------------------------------------------------------------------------
# Defender-narrative trigger patterns
# ---------------------------------------------------------------------------
_ACTOR_RE = r"(?:the\s+)?(?:ssp|sequencer|prover|validator|oracle|watchtower|relayer|attester|co[-]?signer|sender|receiver|committee|operator|bridger|aggregator|node)"

DEFAULT_DEFENDER_NARRATIVE_PATTERNS: list[str] = [
    rf"{_ACTOR_RE}\s+broadcasts",
    rf"{_ACTOR_RE}\s+signs",
    rf"{_ACTOR_RE}\s+spends",
    rf"{_ACTOR_RE}\s+submits",
    rf"{_ACTOR_RE}\s+attests",
    rf"{_ACTOR_RE}\s+finalizes",
    rf"{_ACTOR_RE}\s+commits",
    rf"{_ACTOR_RE}\s+reveals",
    # Additional generic shapes
    r"defender\s+(?:broadcasts|signs|submits|finalizes|commits|reveals)",
    r"honest\s+(?:ssp|validator|sequencer|prover|node)\s+(?:broadcasts|signs|submits)",
]

# ---------------------------------------------------------------------------
# Attribution section header
# ---------------------------------------------------------------------------
ATTRIBUTION_SECTION_RE = re.compile(
    r"(?im)^#+\s*load[-\s]?bearing\s+bytes\s+attribution"
    r"|^load[-\s]?bearing\s+bytes\s+attribution\s*:",
)

# ---------------------------------------------------------------------------
# Field detectors within the attribution section
# ---------------------------------------------------------------------------

# Field 1: load-bearing artifact named
ARTIFACT_NAME_RE = re.compile(
    r"(?im)load[-\s]?bearing\s+artifact\s*(?:\(verbatim[^)]*\))?\s*:",
)

# Field 2: production site
PRODUCTION_SITE_RE = re.compile(
    r"(?im)production\s+site\s*(?:\([^)]*\))?\s*:",
)
# A "real" production site must have either file:line or "off-chain" mention
PRODUCTION_SITE_FILLED_RE = re.compile(
    r"(?:[\w./\\-]+\.(?:go|rs|sol|ts|js|py|move|cairo|vy)\s*:\s*\d+)"  # file:line
    r"|(?:off[-\s]?chain)"
    r"|(?:hand[-\s]?off)"
    r"|(?:\w+\.\w+:\d+)",  # generic file:line
    re.IGNORECASE,
)

# Field 3: required signers
SIGNER_SET_RE = re.compile(
    r"(?im)required\s+signers?\s*(?:\([^)]*\))?\s*:",
)
SIGNER_SET_FILLED_RE = re.compile(
    r"(?:threshold|M-of-N|\d-of-\d|[12]\s*/\s*[23]|FROST|BLS|multisig|"
    r"committee|validator set|single\s+(?:key|signer|operator)|"
    r"\d+\s+(?:validators?|signers?|keys?))",
    re.IGNORECASE,
)

# Field 4: attacker intersect
ATTACKER_INTERSECT_RE = re.compile(
    r"(?im)attack[-\s]?model\s+attacker\s+in\s+signer\s+set\s*\?",
)
ATTACKER_INTERSECT_FILLED_RE = re.compile(
    r"\b(?:yes|no)\b",
    re.IGNORECASE,
)

# Field 5: withholding analysis
WITHHOLDING_RE = re.compile(
    r"(?im)withholding\s+incentive\s+analysis\s*:",
)
WITHHOLDING_FILLED_RE = re.compile(
    r"(?:withhold|incentive|benefit|penalty|rational|motive|reason|payoff|"
    r"cannot withhold|no (?:motive|incentive)|cannot\s+(?:stop|block))",
    re.IGNORECASE,
)

# Verdict line
VERDICT_LINE_RE = re.compile(
    r"(?im)^\s*-\s*verdict\s*:.*?(?:defense[-\s]?unreachable|defense[-\s]?reachable|conditionally[-\s]?reachable)",
)
VERDICT_UNREACHABLE_RE = re.compile(r"defense[-\s]?unreachable", re.IGNORECASE)
VERDICT_REACHABLE_RE = re.compile(r"(?:defense[-\s]?reachable|conditionally[-\s]?reachable)", re.IGNORECASE)

# Walk-back language
WALKBACK_RE = re.compile(
    r"(?im)walk[-\s]?back|walk back|severity.*(?:reduced|lowered|downgraded|drop)|"
    r"downgrade.*severity|lower.*severity|medium.*warranted|walk-back.*justified",
)

# Rebuttal markers
REBUTTAL_HTML_RE = re.compile(r"<!--\s*r43-rebuttal:\s*(.*?)\s*-->", re.IGNORECASE | re.DOTALL)
REBUTTAL_LINE_RE = re.compile(r"(?im)^\s*(?:[-*]\s*)?r43[-_ ]rebuttal\s*:\s*(.+?)\s*$")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _severity(text: str, path: Path, override: str | None) -> tuple[str | None, str]:
    if override:
        normalized = override.strip().lower()
        if normalized in SEVERITY_RANK:
            return normalized, "cli"
    for pattern, source in (
        # Handles plain "Severity: High", bold "**Severity**: High", "**Severity**:" etc.
        (r"(?im)^\s*\**\s*Severity\s*\**\s*:\s*\**\s*(Critical|High|Medium|Low)\b", "severity-header"),
        (r"(?im)^\s*severity_implied\s*:\s*(Critical|High|Medium|Low)\b", "program-impact-mapping"),
        (r"(?im)^\s*severity_tier\s*:\s*(Critical|High|Medium|Low)\b", "impact-contract"),
        (r"(?im)^\s*selected_severity\s*:\s*(Critical|High|Medium|Low)\b", "selected-severity"),
    ):
        match = re.search(pattern, text)
        if match:
            return match.group(1).lower(), source
    for severity in ("critical", "high", "medium", "low"):
        if re.search(rf"(?:^|[-_]){severity}(?:[-_.]|$)", path.name.lower()):
            return severity, "filename"
    return None, "missing"


def _env_patterns(name: str) -> list[str]:
    raw = os.environ.get(name, "")
    if not raw.strip():
        return []
    return [item.strip() for item in raw.splitlines() if item.strip()]


def _compile_union(patterns: list[str]) -> re.Pattern[str]:
    return re.compile("|".join(f"(?:{p})" for p in patterns), re.IGNORECASE)


def _line_hits(text: str, pattern: re.Pattern[str], limit: int = 8) -> list[dict[str, Any]]:
    hits: list[dict[str, Any]] = []
    for idx, line in enumerate(text.splitlines(), start=1):
        m = pattern.search(line)
        if m:
            hits.append({"line": idx, "token": m.group(0)[:80], "text": line.strip()[:240]})
            if len(hits) >= limit:
                break
    return hits


def _rebuttal(text: str) -> str | None:
    m = REBUTTAL_LINE_RE.search(text)
    if not m:
        m = REBUTTAL_HTML_RE.search(text)
    if not m:
        return None
    return " ".join(m.group(1).split())


def _extract_attribution_block(text: str) -> str:
    """Extract the text from the Load-Bearing Bytes Attribution section onwards."""
    m = ATTRIBUTION_SECTION_RE.search(text)
    if not m:
        return ""
    return text[m.start():]


def _check_attribution_fields(block: str) -> dict[str, Any]:
    """Check which of the 5 required fields are present and non-trivially filled."""
    result: dict[str, Any] = {
        "has_artifact_name": bool(ARTIFACT_NAME_RE.search(block)),
        "has_production_site": bool(PRODUCTION_SITE_RE.search(block)),
        "has_production_site_filled": False,
        "has_signer_set": bool(SIGNER_SET_RE.search(block)),
        "has_signer_set_filled": False,
        "has_attacker_intersect": bool(ATTACKER_INTERSECT_RE.search(block)),
        "has_attacker_intersect_filled": False,
        "has_withholding_analysis": bool(WITHHOLDING_RE.search(block)),
        "has_withholding_filled": False,
        "has_verdict_line": bool(VERDICT_LINE_RE.search(block)),
        "verdict_unreachable": bool(VERDICT_UNREACHABLE_RE.search(block)),
        "verdict_reachable": bool(VERDICT_REACHABLE_RE.search(block)),
    }

    if result["has_production_site"]:
        result["has_production_site_filled"] = bool(PRODUCTION_SITE_FILLED_RE.search(block))

    if result["has_signer_set"]:
        result["has_signer_set_filled"] = bool(SIGNER_SET_FILLED_RE.search(block))

    if result["has_attacker_intersect"]:
        result["has_attacker_intersect_filled"] = bool(ATTACKER_INTERSECT_FILLED_RE.search(block))

    if result["has_withholding_analysis"]:
        result["has_withholding_filled"] = bool(WITHHOLDING_FILLED_RE.search(block))

    return result


# ---------------------------------------------------------------------------
# Main run() entry point
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
        "general_rule": "Rule 43 is general - applies to any mediation/dispute/triager-response draft on any target.",
        "evidence": {},
        "remediation_options": [
            "Add a 'Load-Bearing Bytes Attribution' section enumerating: artifact name, production site (file:line), required signer set (threshold + roles), attacker-in-signer-set cross-check (yes/no), and withholding incentive analysis.",
            "If the attacker is NOT in the signer set and has no withholding leverage, state so explicitly and the walk-back is justified.",
            "Override: visible line 'r43-rebuttal: <reason>' (<=200 chars) or <!-- r43-rebuttal: <reason> -->.",
        ],
    }

    # Below Medium: out of scope.
    if severity is None or SEVERITY_RANK.get(severity, 0) < SEVERITY_RANK["medium"]:
        payload["verdict"] = "pass-out-of-scope"
        payload["reason"] = "severity below Medium or missing"
        return 0, payload

    # Rebuttal marker check (before heavy analysis)
    rebuttal = _rebuttal(text)
    if rebuttal and len(rebuttal) <= REBUTTAL_MAX_CHARS:
        payload["verdict"] = "ok-rebuttal"
        payload["rebuttal"] = rebuttal
        return 0, payload

    # Build defender-narrative pattern from defaults + env extension
    all_patterns = DEFAULT_DEFENDER_NARRATIVE_PATTERNS + _env_patterns("AUDITOOOR_R43_DEFENDER_NARRATIVE_PATTERNS")
    narrative_re = _compile_union(all_patterns)

    narrative_hits = _line_hits(text, narrative_re)
    payload["evidence"]["defender_narrative_hits"] = narrative_hits

    if not narrative_hits:
        payload["verdict"] = "pass-no-defender-narrative"
        payload["reason"] = "no defender-narrative phrasing detected in the draft"
        return 0, payload

    # Defender narrative found - check for attribution section
    has_section = bool(ATTRIBUTION_SECTION_RE.search(text))
    payload["evidence"]["has_attribution_section"] = has_section

    if not has_section:
        payload["verdict"] = "fail-no-attribution-section"
        payload["reason"] = (
            "draft contains defender-narrative phrasing but has no "
            "'Load-Bearing Bytes Attribution' section"
        )
        return (1 if strict else 1), payload

    # Extract and analyze the attribution block
    block = _extract_attribution_block(text)
    fields = _check_attribution_fields(block)
    payload["evidence"]["attribution_fields"] = fields

    # Field 1: artifact name (inside the section the header itself counts, but
    # the dedicated "Load-bearing artifact" sub-field is checked separately)
    if not fields["has_artifact_name"]:
        payload["verdict"] = "fail-no-bytes-enumerated"
        payload["reason"] = (
            "attribution section present but the 'Load-bearing artifact' sub-field is missing"
        )
        return 1, payload

    # Field 2: production site
    if not fields["has_production_site"]:
        payload["verdict"] = "fail-no-production-site"
        payload["reason"] = "attribution section missing 'Production site' sub-field"
        return 1, payload

    if not fields["has_production_site_filled"]:
        payload["verdict"] = "fail-no-production-site"
        payload["reason"] = (
            "'Production site' sub-field present but contains no file:line citation "
            "or off-chain component reference"
        )
        return 1, payload

    # Field 3: signer set
    if not fields["has_signer_set"]:
        payload["verdict"] = "fail-no-signer-set"
        payload["reason"] = "attribution section missing 'Required signers' sub-field"
        return 1, payload

    if not fields["has_signer_set_filled"]:
        payload["verdict"] = "fail-no-signer-set"
        payload["reason"] = (
            "'Required signers' sub-field present but contains no threshold/role description"
        )
        return 1, payload

    # Field 4: attacker intersect
    if not fields["has_attacker_intersect"]:
        payload["verdict"] = "fail-no-attacker-intersect"
        payload["reason"] = (
            "attribution section missing 'Attack-model attacker in signer set?' sub-field"
        )
        return 1, payload

    if not fields["has_attacker_intersect_filled"]:
        payload["verdict"] = "fail-no-attacker-intersect"
        payload["reason"] = (
            "'Attack-model attacker in signer set?' sub-field present but contains no yes/no answer"
        )
        return 1, payload

    # Field 5: withholding analysis
    if not fields["has_withholding_analysis"]:
        payload["verdict"] = "fail-no-withholding-analysis"
        payload["reason"] = "attribution section missing 'Withholding incentive analysis' sub-field"
        return 1, payload

    if not fields["has_withholding_filled"]:
        payload["verdict"] = "fail-no-withholding-analysis"
        payload["reason"] = (
            "'Withholding incentive analysis' sub-field present but contains no "
            "incentive/penalty/rational-actor analysis"
        )
        return 1, payload

    # All five fields present and non-trivially filled.
    # Determine final pass verdict.
    is_unreachable = fields["verdict_unreachable"]
    is_reachable = fields["verdict_reachable"]
    has_walkback = bool(WALKBACK_RE.search(text))

    # Check if attacker-in-signer-set line says "no"
    attacker_not_in_set = bool(re.search(
        r"(?im)attack[-\s]?model\s+attacker\s+in\s+signer\s+set\s*\?[^\n]*\bno\b",
        block,
    ))

    if is_unreachable:
        payload["verdict"] = "pass-attribution-complete-defense-unreachable"
        payload["reason"] = (
            "attribution complete; verdict=defense-unreachable; walk-back is unwarranted"
        )
    elif attacker_not_in_set and has_walkback:
        payload["verdict"] = "pass-walk-back-justified"
        payload["reason"] = (
            "attribution complete; attacker not in signer set; walk-back is explicitly justified"
        )
    elif is_reachable:
        payload["verdict"] = "pass-attribution-complete-defense-reachable"
        payload["reason"] = (
            "attribution complete; verdict=defense-reachable; walk-back may be warranted"
        )
    else:
        # Full attribution present but no verdict line - treat as reachable
        payload["verdict"] = "pass-attribution-complete-defense-reachable"
        payload["reason"] = (
            "attribution complete; no explicit verdict line; treating as defense-reachable"
        )

    return 0, payload


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("draft", type=Path)
    parser.add_argument(
        "--severity",
        choices=["auto", "Critical", "High", "Medium", "Low",
                 "critical", "high", "medium", "low"],
        default="auto",
    )
    parser.add_argument("--strict", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    override = None if args.severity == "auto" else args.severity
    rc, payload = run(args.draft, severity_override=override, strict=args.strict)

    print(json.dumps(payload, indent=2, sort_keys=True))
    if not args.json:
        sys.stderr.write(
            f"[{GATE}] {payload.get('verdict')}: "
            f"{payload.get('reason', payload.get('error', ''))}\n"
        )
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
