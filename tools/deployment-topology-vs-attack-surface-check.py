#!/usr/bin/env python3
"""Rule 48 deployment-topology-vs-attack-surface preflight.

Trigger: HIGH+ drafts where the contested vulnerability is gated by a
specific deployment topology (e.g. restricted to certain wallet types,
specific deployments, environment flags, test-only paths). Without the
topology check, drafts get closed as "POLY_1271 restricted to Deposit
Wallets" or "testnet-only" or "OOS test/staging".

Required section: "Deployment Topology Attack Surface" with 4 fields:
  1. Production topology citation: where in the audit-pin tree is the
     deployment configured? (constructor, config file, registry mapping,
     env flag)
  2. Attacker actor existence: in the deployed topology, does the attacker
     actor in the attack model actually exist?
  3. OOS test/staging clause citation: program's SEVERITY.md / SCOPE.md
     verbatim quote for test-only / staging-only OOS clauses
  4. Verdict: not-restricted-by-topology | restricted-but-population-non-empty
     | restricted-and-population-empty (= OOS) | test-only-deployment (= OOS)

Exit codes:
  0 - pass, out-of-scope, or accepted rebuttal
  1 - Rule 48 violation
  2 - input error
"""

from __future__ import annotations

import argparse
import json
import os
import re
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "auditooor.r48_deployment_topology.v1"
GATE = "R48-DEPLOYMENT-TOPOLOGY-VS-ATTACK-SURFACE"
TOPOLOGY_ASSET_SCHEMA = "auditooor.r48_topology_assets.v1"

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}

# --------------------------------------------------------------------------
# Operator-curated topology asset list helpers
# Precedence: asset list > live-check.
# Asset list path: <workspace>/.auditooor/r48_topology/<ws_name>.json
# --------------------------------------------------------------------------

def _load_topology_asset_list(workspace):
    """Load the operator-curated topology asset list for the given workspace.

    Returns the parsed JSON dict if the file is valid, None otherwise
    (callers should fall through to live-check on None).
    """
    if workspace is None:
        return None
    topology_dir = workspace / ".auditooor" / "r48_topology"
    if not topology_dir.is_dir():
        return None
    ws_name = workspace.name  # e.g. "hyperbridge", "dydx", "spark"
    asset_file = topology_dir / f"{ws_name}.json"
    if not asset_file.is_file():
        return None
    try:
        data = json.loads(asset_file.read_text(encoding="utf-8"))
    except Exception:
        import sys as _sys
        print(f"[R48] WARNING: malformed topology asset list at {asset_file}; falling through to live-check", file=_sys.stderr)
        return None
    if not isinstance(data, dict):
        return None
    if data.get("schema_version") != TOPOLOGY_ASSET_SCHEMA:
        return None
    if not isinstance(data.get("deployments"), list):
        return None
    return data


def _attacker_population_from_asset_list(data, contract_name):
    """Return the attacker_population / reason string for a contract, or None.

    None means the contract is not in the list; callers fall through to
    live-check.

    Return value semantics:
      "non-empty"                     -> gate passes (populated)
      "needs-operator-classification" -> unknown; fall through to live-check
      "empty"                         -> OOS (empty population)
      "testnet-only"                  -> OOS (test-only-deployment)
      "interface-only"                -> not a deployed contract; skip
      "library-only"                  -> not a deployed contract; skip
      "deploy-script-only"            -> not a deployed contract; skip
    """
    needle = contract_name.strip().lower()
    for entry in data.get("deployments", []):
        if isinstance(entry, dict) and entry.get("contract_name", "").lower() == needle:
            pop = entry.get("attacker_population")
            return str(pop) if pop else None
    for entry in data.get("unverified_contracts", []):
        if isinstance(entry, dict) and entry.get("contract_name", "").lower() == needle:
            reason = entry.get("reason")
            return str(reason) if reason else None
    return None

# --------------------------------------------------------------------------
# Topology restriction signals: language that suggests the vulnerable path
# is gated by a specific deployment or wallet type.
# --------------------------------------------------------------------------
TOPOLOGY_RESTRICTION_RE = re.compile(
    r"restricted to|only (?:applies?|fires?|affects?|works?) (?:for|when|in|with)|"
    r"requires?.*(?:wallet|account|role|flag|config|mode|env|deployment)|"
    r"only (?:available|enabled|active) (?:for|in|when)|"
    r"deposit wallet|proxy wallet|eoa wallet|smart.?wallet|1271|EIP.?1271|"
    r"erc.?1271|erc1271|abstract account|account abstraction|"
    r"testnet.only|staging.only|test.only|dev.only|sandbox.only|"
    r"test environment|staging environment|mock.*deploy|"
    r"feature flag|env(?:ironment)? flag|env(?:ironment)? var|"
    r"(?:admin|owner|operator) only|role.gated|permissioned path|"
    r"specific (?:deployment|configuration|setup)|"
    r"only (?:deployed|instantiated|configured) (?:on|in|for)",
    re.IGNORECASE,
)

# --------------------------------------------------------------------------
# Section detection: "Deployment Topology Attack Surface" heading
# --------------------------------------------------------------------------
SECTION_RE = re.compile(
    r"(?m)^#{1,4}\s*Deployment Topology(?:\s+Attack\s+Surface)?|"
    r"^Deployment Topology(?:\s+Attack\s+Surface)?\s*:",
    re.IGNORECASE,
)

# --------------------------------------------------------------------------
# The 4 required sub-fields inside the section
# --------------------------------------------------------------------------
FIELD_1_RE = re.compile(
    r"(?:Production topology|topology citation|Deployment (?:configured|citation)|"
    r"(?:constructor|config|registry|env)\s+(?:citation|reference|path|file))\s*:",
    re.IGNORECASE,
)

FIELD_2_RE = re.compile(
    r"(?:Attacker actor(?:\s+existence)?|actor existence|attacker (?:exists?|population)|"
    r"population (?:non.?empty|empty|size)|actor model (?:in )?(?:topology|deployment))\s*:",
    re.IGNORECASE,
)

FIELD_3_RE = re.compile(
    # Match the OOS clause field regardless of whether it says
    # "OOS test/staging clause citation:" or "OOS testnet clause:" etc.
    r"(?:OOS (?:test(?:/staging)?|staging(?:/test)?|env|testnet)\s+(?:(?:clause|citation)\s+)*(?:clause|citation)|"
    r"OOS (?:clause|citation)\s+(?:citation)?|"
    r"test.?only (?:clause|OOS)|staging.?only (?:clause|OOS)|"
    r"program.*(?:SEVERITY|SCOPE).*(?:testnet|staging|test.only)|"
    r"SCOPE\.md (?:quote|citation|verbatim)|SEVERITY\.md (?:testnet|test.only|staging))\s*:",
    re.IGNORECASE,
)

FIELD_4_RE = re.compile(
    r"(?:Verdict|Topology verdict)\s*:\s*"
    r"(?:not.restricted.by.topology|restricted.but.population.non.empty|"
    r"restricted.and.population.empty|test.only.deployment)",
    re.IGNORECASE,
)

# --------------------------------------------------------------------------
# OOS topology signals: look for the verdict field itself (not citations)
# The Verdict field is the authoritative signal, not incidental text.
# --------------------------------------------------------------------------
OOS_EMPTY_POPULATION_RE = re.compile(
    r"Verdict\s*:\s*restricted.and.population.empty",
    re.IGNORECASE,
)

OOS_TESTONLY_RE = re.compile(
    r"Verdict\s*:\s*test.only.deployment",
    re.IGNORECASE,
)

# --------------------------------------------------------------------------
# Non-restricted (positive) signals - also anchored to Verdict field
# --------------------------------------------------------------------------
NON_RESTRICTED_RE = re.compile(
    r"Verdict\s*:\s*not.restricted.by.topology",
    re.IGNORECASE,
)

# --------------------------------------------------------------------------
# Rebuttal patterns
# --------------------------------------------------------------------------
REBUTTAL_RE = re.compile(
    r"r48-rebuttal\s*:\s*(.+?)(?:-->|$)",
    re.IGNORECASE | re.DOTALL,
)
REBUTTAL_COMMENT_RE = re.compile(
    r"<!--\s*r48-rebuttal\s*:\s*(.+?)-->",
    re.IGNORECASE | re.DOTALL,
)

MAX_REBUTTAL_LEN = 200


def _resolve_severity(text: str, severity_arg: str | None) -> str:
    if severity_arg and severity_arg.lower() in SEVERITY_RANK:
        return severity_arg.lower()
    # auto-detect from draft header
    m = re.search(
        r"^[-*]\s*Severity\s*:\s*(critical|high|medium|low)",
        text,
        re.IGNORECASE | re.MULTILINE,
    )
    if m:
        return m.group(1).lower()
    return "medium"


def _check_rebuttal(text: str) -> str | None:
    """Return rebuttal reason if present and valid length, else None."""
    for pat in (REBUTTAL_RE, REBUTTAL_COMMENT_RE):
        m = pat.search(text)
        if m:
            reason = m.group(1).strip().rstrip("-->").strip()
            if 0 < len(reason) <= MAX_REBUTTAL_LEN:
                return reason
    return None


def _find_section(text: str) -> str | None:
    """Return the text content after the topology section heading, or None."""
    m = SECTION_RE.search(text)
    if not m:
        return None
    # Grab everything from the heading until the next ##-level heading
    rest = text[m.end():]
    next_heading = re.search(r"(?m)^#{1,4}\s+\S", rest)
    if next_heading:
        return rest[: next_heading.start()]
    return rest


def check(
    draft_path: Path,
    workspace: Path | None = None,
    severity_arg: str | None = None,
    strict: bool = False,
) -> dict[str, Any]:
    # --- read draft ---
    try:
        text = draft_path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return {
            "schema": SCHEMA_VERSION,
            "gate": GATE,
            "verdict": "error",
            "reason": f"cannot read draft: {exc}",
            "draft": str(draft_path),
        }

    severity = _resolve_severity(text, severity_arg)

    # --- scope check: only HIGH+ ---
    if SEVERITY_RANK.get(severity, 0) < SEVERITY_RANK["high"]:
        return {
            "schema": SCHEMA_VERSION,
            "gate": GATE,
            "verdict": "pass-out-of-scope",
            "reason": f"severity={severity} is below HIGH; R48 only fires on HIGH+",
            "draft": str(draft_path),
            "severity": severity,
        }

    # --- rebuttal ---
    rebuttal = _check_rebuttal(text)
    if rebuttal:
        return {
            "schema": SCHEMA_VERSION,
            "gate": GATE,
            "verdict": "ok-rebuttal",
            "reason": f"r48-rebuttal accepted: {rebuttal}",
            "draft": str(draft_path),
            "severity": severity,
        }

    # --- load operator-curated topology asset list (takes precedence over live-check) ---
    topology_asset_list = _load_topology_asset_list(workspace)
    topology_asset_list_source = (
        str(workspace / ".auditooor" / "r48_topology" / (workspace.name + ".json"))
        if workspace and topology_asset_list is not None
        else None
    )

    # --- check for topology restriction signal ---
    has_restriction = bool(TOPOLOGY_RESTRICTION_RE.search(text))

    if not has_restriction and not strict:
        # No topology restriction language detected; pass without requiring section
        return {
            "schema": SCHEMA_VERSION,
            "gate": GATE,
            "verdict": "pass-no-topology-restriction",
            "reason": "no deployment-topology restriction language detected in draft",
            "draft": str(draft_path),
            "severity": severity,
        }

    # --- section required (restriction detected or strict mode) ---
    section_text = _find_section(text)
    if not section_text:
        return {
            "schema": SCHEMA_VERSION,
            "gate": GATE,
            "verdict": "fail-no-topology-tabulation",
            "reason": (
                'draft contains topology-restriction language but no "Deployment Topology '
                'Attack Surface" section with 4 required fields was found'
            ),
            "draft": str(draft_path),
            "severity": severity,
            "hints": [
                'Add a "## Deployment Topology Attack Surface" section with:',
                "  1. Production topology citation",
                "  2. Attacker actor existence",
                "  3. OOS test/staging clause citation from SEVERITY.md or SCOPE.md",
                "  4. Verdict: not-restricted-by-topology | restricted-but-population-non-empty | restricted-and-population-empty | test-only-deployment",
            ],
        }

    # --- check for 4 fields ---
    missing_fields: list[str] = []
    if not FIELD_1_RE.search(section_text):
        missing_fields.append("field-1: Production topology citation")
    if not FIELD_2_RE.search(section_text):
        missing_fields.append("field-2: Attacker actor existence")
    if not FIELD_3_RE.search(section_text):
        missing_fields.append("field-3: OOS test/staging clause citation")
    if not FIELD_4_RE.search(section_text):
        missing_fields.append("field-4: Verdict (not-restricted-by-topology | restricted-but-population-non-empty | restricted-and-population-empty | test-only-deployment)")

    if missing_fields:
        return {
            "schema": SCHEMA_VERSION,
            "gate": GATE,
            "verdict": "fail-no-topology-tabulation",
            "reason": f"Deployment Topology Attack Surface section missing {len(missing_fields)} field(s)",
            "draft": str(draft_path),
            "severity": severity,
            "missing_fields": missing_fields,
        }

    # --- verdict classification from section content ---
    if OOS_TESTONLY_RE.search(section_text):
        verdict = "fail-test-only-deployment"
        reason = (
            "topology verdict is test-only-deployment: the contested path only "
            "exists in testnet/staging; not fileable without production-topology evidence"
        )
        return {
            "schema": SCHEMA_VERSION,
            "gate": GATE,
            "verdict": verdict,
            "reason": reason,
            "draft": str(draft_path),
            "severity": severity,
            "hints": [
                "Verify the deployment path exists in the production environment",
                "Add production-topology citation from audit-pin constructor / config / registry",
                "Override: r48-rebuttal: <reason up to 200 chars>",
            ],
        }

    if OOS_EMPTY_POPULATION_RE.search(section_text):
        verdict = "fail-restricted-and-empty-population"
        reason = (
            "topology verdict is restricted-and-population-empty: the attacker actor "
            "does not exist in the deployed topology"
        )
        return {
            "schema": SCHEMA_VERSION,
            "gate": GATE,
            "verdict": verdict,
            "reason": reason,
            "draft": str(draft_path),
            "severity": severity,
            "hints": [
                "Verify the attacker actor actually exists in the production deployment",
                "If the actor population is non-empty, change the verdict field accordingly",
                "Override: r48-rebuttal: <reason up to 200 chars>",
            ],
        }

    if NON_RESTRICTED_RE.search(section_text):
        return {
            "schema": SCHEMA_VERSION,
            "gate": GATE,
            "verdict": "pass-no-topology-restriction",
            "reason": "topology verdict is not-restricted: finding applies to all deployments",
            "draft": str(draft_path),
            "severity": severity,
        }

    # --- asset-list attacker-population augmentation ---
    # If the section verdict field is missing (old draft) but the asset list has
    # a definitive population status, use the asset list to augment.
    # This is an advisory enrichment only; it does NOT override a Verdict field
    # already present in the section (those are handled above).
    if topology_asset_list is not None:
        # Extract contract names cited in the section (simple heuristic: quoted names)
        cited_contracts = re.findall(r'`([A-Za-z][A-Za-z0-9_]+)`', section_text)
        for cname in cited_contracts:
            pop = _attacker_population_from_asset_list(topology_asset_list, cname)
            if pop == "testnet-only":
                return {
                    "schema": SCHEMA_VERSION,
                    "gate": GATE,
                    "verdict": "fail-test-only-deployment",
                    "reason": (
                        f"topology asset list ({topology_asset_list_source}) classifies `{cname}` as testnet-only; ",
                    ),
                    "draft": str(draft_path),
                    "severity": severity,
                    "topology_asset_list": topology_asset_list_source,
                    "asset_list_classification": pop,
                }
            if pop == "empty":
                return {
                    "schema": SCHEMA_VERSION,
                    "gate": GATE,
                    "verdict": "fail-restricted-and-empty-population",
                    "reason": (
                        f"topology asset list ({topology_asset_list_source}) classifies `{cname}` as empty population"
                    ),
                    "draft": str(draft_path),
                    "severity": severity,
                    "topology_asset_list": topology_asset_list_source,
                    "asset_list_classification": pop,
                }

    # Section present, all 4 fields present, restricted-but-population-non-empty
    result = {
        "schema": SCHEMA_VERSION,
        "gate": GATE,
        "verdict": "pass-restricted-but-population-non-empty",
        "reason": (
            "Deployment Topology Attack Surface section present with all 4 fields; "
            "restricted deployment but attacker population confirmed non-empty"
        ),
        "draft": str(draft_path),
        "severity": severity,
    }
    if topology_asset_list_source:
        result["topology_asset_list"] = topology_asset_list_source
    return result


def main() -> None:
    env_r48_patterns = os.environ.get("AUDITOOOR_R48_TOPOLOGY_RESTRICTION_PATTERNS", "")

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("draft", type=Path, help="path to the submission draft .md file")
    parser.add_argument("--workspace", "-w", type=Path, default=None)
    parser.add_argument(
        "--severity",
        choices=["auto", "LOW", "MEDIUM", "HIGH", "CRITICAL",
                 "low", "medium", "high", "critical"],
        default="auto",
    )
    parser.add_argument("--strict", action="store_true",
                        help="require topology section even when restriction language absent")
    parser.add_argument("--json", dest="json_out", action="store_true")
    args = parser.parse_args()

    # extend patterns from env
    if env_r48_patterns:
        global TOPOLOGY_RESTRICTION_RE
        extra = "|".join(
            p.strip() for p in env_r48_patterns.strip().splitlines() if p.strip()
        )
        if extra:
            TOPOLOGY_RESTRICTION_RE = re.compile(
                TOPOLOGY_RESTRICTION_RE.pattern + "|" + extra,
                re.IGNORECASE,
            )

    sev = None if args.severity == "auto" else args.severity.lower()
    result = check(args.draft, workspace=args.workspace, severity_arg=sev, strict=args.strict)

    if args.json_out:
        print(json.dumps(result, indent=2))
    else:
        v = result.get("verdict", "error")
        r = result.get("reason", "")
        print(f"{v}: {r}")
        for h in result.get("hints", []):
            print(f"  hint: {h}")
        for f in result.get("missing_fields", []):
            print(f"  missing: {f}")

    verdict = result.get("verdict", "error")
    if verdict.startswith("fail-"):
        raise SystemExit(1)
    if verdict == "error":
        raise SystemExit(2)
    raise SystemExit(0)


if __name__ == "__main__":
    main()
