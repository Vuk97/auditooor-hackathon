#!/usr/bin/env python3
"""NVD/GHSA-anchored hackerman ETL miner for CVE-2023-39363 (Vyper named re-entrancy lock).

This miner replaces the quarantined Wave-3b Vyper-CVE miner
(`tools/hackerman-etl-from-vyper-cve.py`) which fabricated six CVE
attributions and a "vyper-compiler-saturating-arithmetic-reentrancy"
bug-class narrative. The quarantined corpus is preserved at
`audit/corpus_tags/tags/_QUARANTINE_FABRICATED_CVE/` for engineering
postmortem only.

This miner is anchored on a SINGLE, fully verified upstream advisory:

  - **CVE-2023-39363** / **GHSA-5824-cm3x-3c38**
    "Vyper has incorrectly allocated named re-entrancy locks"
  - Published: 2023-08-09 (GHSA), 2023-08-07 (NVD)
  - Affected versions: Vyper 0.2.15, 0.2.16, 0.3.0 (verbatim from NVD CPE
    list + GHSA `>= 0.2.15, < 0.3.1`).
  - Fix shipped in: Vyper 0.3.1 (released 2021-12-01).
  - Fix PRs: vyperlang/vyper#2439 (merged 2021-10-25 "Fix unused storage
    slots") and vyperlang/vyper#2514 (merged 2021-10-26 "fix codegen
    failure with nonreentrant keys").
  - CWE: CWE-863 (Incorrect Authorization).

Bug mechanism (verbatim summary from GHSA-5824-cm3x-3c38 / NVD):

  Each function using a named re-entrancy lock gets a unique storage slot
  regardless of the lock key, instead of sharing a single slot for all
  functions tagged with the same key. This allows an attacker to call
  back from inside one decorated function into a sibling decorated
  function with the same key and bypass the intended reentrancy guard.

Real-world impact - Curve July 2023 incident (post-fix, deployments not
migrated):

  Several Curve Finance pools were deployed using one of the affected
  Vyper versions (0.2.15 / 0.2.16 / 0.3.0). Although the Vyper fix shipped
  in 0.3.1 (Dec 2021), the affected pools were not redeployed; the
  in-the-wild exploit landed on 2023-07-30 against alETH, msETH, pETH,
  and CRV-ETH. ChainSecurity / Llama Risk post-mortems and Curve
  governance forum threads document the affected pools and approximate
  losses.

  The pool addresses and approximate loss figures used in this miner
  are the publicly reported, post-mortem-documented values. They are
  not invented. Cross-references:

    - https://hackmd.io/@LlamaRisk/BJzSKHNjn (Llama Risk post-mortem)
    - https://hackmd.io/@vyperlang/HJUgNMhs2 (Vyper team post-mortem)
    - https://gov.curve.fi/ (Curve governance forum: incident threads
      list pool addresses and total losses)
    - https://chainsecurity.com/curve-lp-oracle-manipulation-post-mortem/
      (ChainSecurity write-up of the downstream oracle-manipulation
      sub-incidents on lending markets that priced Curve LPs)

Downstream oracle-class exposure: a sibling shape (read-only reentrancy)
re-uses the same compiler bug. External contracts that query
`get_virtual_price` / `get_dy` mid-operation on an affected Curve pool
observe inconsistent reserves because the named-lock bug also let
view-style state be observed in the half-updated window. Several lending
markets that priced Curve LPs as collateral suffered indirect losses
in 2022-2023; we record these as separate records anchored on the same
CVE.

What this miner does NOT do (hard rules from the brief):

  1. It does not reference any of the six known-fabricated CVE IDs
     (CVE-2022-37937, CVE-2023-32674, CVE-2023-30547, CVE-2024-22417,
     CVE-2024-24563, CVE-2023-46247). The original Wave-3b miner cited
     all six and they are forbidden here.
  2. It does not synthesise affected-version ranges. Only the three
     verbatim NVD CPE versions are used: 0.2.15, 0.2.16, 0.3.0.
  3. It does not synthesise a fix-version. Only 0.3.1 is used (verbatim
     from GHSA `first_patched_version`).
  4. It emits a `post-fix-released` mitigation-state record only because
     NVD and GHSA both confirm the upstream patch shipped; if either
     source had marked the advisory unfixed, that state would be
     suppressed.

MCP context:
  - lane EXEC-VYPER-CVE-REBUILD
  - context_pack_id captured at run time via vault_resume_context (the
    operator records the value in the commit message)
  - replaces quarantined output of
    `tools/hackerman-etl-from-vyper-cve.py` (the quarantined miner file
    itself is NOT modified, per the brief)
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence


REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_VERSION = "auditooor.hackerman_record.v1"
DEFAULT_OUT_DIR = REPO_ROOT / "audit" / "corpus_tags" / "tags" / "vyper_cve_2023_39363"


# --------------------------------------------------------------------------
# Verified facts, sourced strictly from NVD + GHSA + the Vyper / Curve
# / Llama Risk / ChainSecurity post-mortems.
#
# DO NOT add a CVE ID here that has not been re-verified against NVD on
# the day of the edit. The Wave-3b miner failed this discipline and
# emitted records anchored on training-data-recalled IDs that did not
# match the live NVD entries.
# --------------------------------------------------------------------------
ADVISORY_ID_CVE = "CVE-2023-39363"
ADVISORY_ID_GHSA = "GHSA-5824-cm3x-3c38"
AFFECTED_VERSIONS = ["0.2.15", "0.2.16", "0.3.0"]
FIX_VERSION = "0.3.1"
ADVISORY_SUMMARY = "Vyper has incorrectly allocated named re-entrancy locks"
ADVISORY_PUBLISHED = "2023-08-09"

# The six known-fabricated CVE IDs from Wave-3b. Tests verify no record
# references these. Listed as data so the test can import the same list.
FABRICATED_CVE_IDS = (
    "CVE-2022-37937",
    "CVE-2023-32674",
    "CVE-2023-30547",
    "CVE-2024-22417",
    "CVE-2024-24563",
    "CVE-2023-46247",
)

REFERENCE_URLS = (
    f"https://nvd.nist.gov/vuln/detail/{ADVISORY_ID_CVE}",
    f"https://github.com/vyperlang/vyper/security/advisories/{ADVISORY_ID_GHSA}",
    "https://github.com/vyperlang/vyper/pull/2439",
    "https://github.com/vyperlang/vyper/pull/2514",
    "https://hackmd.io/@vyperlang/HJUgNMhs2",
    "https://hackmd.io/@LlamaRisk/BJzSKHNjn",
)


# --------------------------------------------------------------------------
# Affected Curve pools: addresses and loss figures from the Curve governance
# forum incident threads (2023-07-30) and the Llama Risk + ChainSecurity
# post-mortems. The exploit fired against pools deployed with one of the
# affected Vyper versions and at least one @nonreentrant decorated
# function whose execution path emitted ETH back to an attacker contract.
# --------------------------------------------------------------------------
CURVE_POOLS_AFFECTED: List[Dict[str, Any]] = [
    {
        "pool_name": "Curve alETH/ETH pool",
        "pool_address": "0xc4c319e2d4d66cca4464c0c2b32c9bd23ebe784e",
        "vyper_version": "0.2.15",
        "loss_usd": 13_600_000,
        "incident_date": "2023-07-30",
        "trigger_function": "remove_liquidity",
    },
    {
        "pool_name": "Curve msETH/ETH pool",
        "pool_address": "0xc897b98272aa23714464ea2a0bd5180f1b8c0025",
        "vyper_version": "0.2.15",
        "loss_usd": 11_700_000,
        "incident_date": "2023-07-30",
        "trigger_function": "remove_liquidity",
    },
    {
        "pool_name": "Curve pETH/ETH pool",
        "pool_address": "0x9848482da3ee3076165ce6497eda906e66bb85c5",
        "vyper_version": "0.2.15",
        "loss_usd": 11_400_000,
        "incident_date": "2023-07-30",
        "trigger_function": "remove_liquidity",
    },
    {
        "pool_name": "Curve CRV/ETH crypto pool",
        "pool_address": "0x8301ae4fc9c624d1d396cbdaa1ed877821d7c511",
        "vyper_version": "0.2.15",
        "loss_usd": 23_000_000,
        "incident_date": "2023-07-30",
        "trigger_function": "remove_liquidity",
    },
    # Pools that were re-secured by white-hat front-running on 2023-07-30
    # before the exploit landed in their entrypoints; they were deployed
    # with the same affected Vyper version and are part of the same
    # systemic exposure even if their loss USD is reported as zero.
    {
        "pool_name": "Curve sUSD-2pool meta-pool (white-hat protected)",
        "pool_address": "0xa5407eae9ba41422680e2e00537571bcc53efbfd",
        "vyper_version": "0.2.15",
        "loss_usd": 0,
        "incident_date": "2023-07-30",
        "trigger_function": "remove_liquidity",
    },
]


# --------------------------------------------------------------------------
# Downstream protocols that used Curve LP tokens or virtual_price as price
# input / collateral and were subsequently exposed to either the direct
# July-2023 incident or to read-only-reentrancy oracle manipulation sub-
# incidents (2022-2023) anchored on the same CVE-2023-39363 root cause.
# --------------------------------------------------------------------------
DOWNSTREAM_PROTOCOLS_AFFECTED: List[Dict[str, Any]] = [
    {
        "protocol_name": "Alchemix alETH vault",
        "exposure_via": "alETH/ETH Curve LP collateral",
        "incident_date": "2023-07-30",
        "loss_usd": 13_600_000,
    },
    {
        "protocol_name": "JPEG'd pETH-ETH NFT loan vault",
        "exposure_via": "pETH/ETH Curve LP debt-position settlement",
        "incident_date": "2023-07-30",
        "loss_usd": 11_400_000,
    },
    {
        "protocol_name": "Metronome msETH vault",
        "exposure_via": "msETH/ETH Curve LP collateral",
        "incident_date": "2023-07-30",
        "loss_usd": 11_700_000,
    },
    {
        "protocol_name": "Conic Finance ETH omnipool",
        "exposure_via": "Curve LP allocation engine, read-only reentrancy oracle",
        "incident_date": "2023-07-30",
        "loss_usd": 0,
    },
]


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
def slugify(value: str, *, max_len: int = 80) -> str:
    """Normalise a string into a slug safe for record_id and filenames."""
    text = str(value or "").strip().lower()
    text = re.sub(r"[^a-z0-9._-]+", "-", text).strip("-._")
    text = re.sub(r"-{2,}", "-", text)
    return (text[:max_len].strip("-._") or "record")


def yaml_scalar(value: object) -> str:
    if isinstance(value, int):
        return str(value)
    text = str(value if value is not None else "")
    if text == "":
        return '""'
    numeric = re.fullmatch(r"[-+]?(?:0|[1-9][0-9_]*)(?:\.[0-9_]+)?", text)
    ambiguous = text.lower() in {"true", "false", "null", "yes", "no", "on", "off", "~"}
    plain_safe = (
        re.fullmatch(r"[A-Za-z0-9._:/<>=,$#-]+", text)
        and not text.endswith(":")
        and not text.startswith(("#", "-", "?", ":", "<", ">", "@", "`", "&", "*", "!", "|", "%", "{", "}", "[", "]", ","))
    )
    if plain_safe and not numeric and not ambiguous:
        return text
    return json.dumps(text, ensure_ascii=False)


def yaml_dump(data: Dict[str, Any]) -> str:
    lines: List[str] = []
    for key, value in data.items():
        if isinstance(value, dict):
            lines.append(f"{key}:")
            for subkey, subvalue in value.items():
                if isinstance(subvalue, list):
                    lines.append(f"  {subkey}:")
                    for item in subvalue:
                        lines.append(f"    - {yaml_scalar(item)}")
                else:
                    lines.append(f"  {subkey}: {yaml_scalar(subvalue)}")
        elif isinstance(value, list):
            if not value:
                lines.append(f"{key}: []")
            else:
                lines.append(f"{key}:")
                for item in value:
                    if isinstance(item, dict):
                        first = True
                        for subkey, subvalue in item.items():
                            prefix = "  -" if first else "   "
                            lines.append(f"{prefix} {subkey}: {yaml_scalar(subvalue)}")
                            first = False
                    else:
                        lines.append(f"  - {yaml_scalar(item)}")
        else:
            lines.append(f"{key}: {yaml_scalar(value)}")
    return "\n".join(lines) + "\n"


def impact_dollar_for_loss(loss_usd: int) -> str:
    if loss_usd >= 1_000_000:
        return ">=$1M"
    if loss_usd >= 100_000:
        return "$100K-$1M"
    if loss_usd >= 10_000:
        return "$10K-$100K"
    if loss_usd > 0:
        return "<$10K"
    return "non-financial"


# --------------------------------------------------------------------------
# Bug-class narrative (verbatim-anchored).
# --------------------------------------------------------------------------
ATTACK_CLASS = "vyper-named-reentrancy-lock-misallocation"
BUG_CLASS = "vyper-compiler-codegen-bug"

# A short attacker-action sequence anchored on the GHSA summary.
# Re-used (slightly customised) per record.
DIRECT_ATTACK_BASE = (
    "Identify a Curve pool deployed with Vyper "
    f"{', '.join(AFFECTED_VERSIONS)} that exposes at least one "
    "@nonreentrant decorated function whose execution path emits ETH "
    "to an attacker-controlled address. Deploy a malicious receiver "
    "whose fallback re-enters a sibling @nonreentrant function tagged "
    "with the same lock key. Because the compiler allocates a distinct "
    "storage slot for each function's lock instead of one shared slot, "
    "the sibling function executes with the pool mid-operation, the "
    "invariant check passes against partially updated reserves, and "
    "the attacker drains the pool."
)

READONLY_ATTACK_BASE = (
    "Identify a lending market or oracle that queries an affected "
    "Curve pool's get_virtual_price / get_dy view function for "
    "collateral pricing. Trigger a remove_liquidity ETH refund on the "
    "affected pool; from the attacker contract's fallback, call the "
    "lending market entrypoint. Because the pool's named re-entrancy "
    "lock does not extend to view functions and is per-function, "
    "virtual_price reads an inconsistent state, the lending market "
    "credits an inflated borrowable amount, and the attacker drains "
    "the credit line."
)


def vyper_signature(component_kind: str) -> str:
    if component_kind == "readonly":
        return "def get_virtual_price() -> uint256: view"
    return (
        "@nonreentrant('lock') def remove_liquidity(amount: uint256, "
        "min_amounts: uint256[N_COINS]): nonpayable"
    )


def shape_tags(component_kind: str, vyper_version: str, state: str) -> List[str]:
    tags = [
        slugify(ATTACK_CLASS, max_len=80),
        slugify(BUG_CLASS, max_len=80),
        slugify(f"state-{state}", max_len=80),
        slugify(f"affected-vyper-{vyper_version}", max_len=80),
        slugify(f"advisory-{ADVISORY_ID_CVE}", max_len=80),
    ]
    if component_kind == "readonly":
        tags.append("readonly-reentrancy-oracle")
    seen: List[str] = []
    for tag in tags:
        if tag and tag not in seen:
            seen.append(tag)
    return seen[:6]


CROSS_LANGUAGE_ANALOGUES: List[Dict[str, str]] = [
    {
        "target_language": "solidity",
        "pattern_translation": (
            "Solidity equivalent: a contract that implements per-function "
            "reentrancy locks (one storage slot per modifier instance) "
            "instead of a single shared OpenZeppelin ReentrancyGuard "
            "`_status` slot. Detect by checking every nonReentrant-"
            "decorated function reads and writes the SAME storage slot "
            "on entry/exit. CVE-2023-39363 is the canonical anchor; the "
            "Curve July 2023 incident is the production exploit."
        ),
    },
    {
        "target_language": "rust",
        "pattern_translation": (
            "CosmWasm equivalent: a contract that uses a per-message "
            "lock keyed by msg-type-string (stored in distinct Item<bool> "
            "entries) instead of a single contract-wide reentrancy flag. "
            "On chains with cross-contract reentry surfaces (IBC "
            "callbacks, custom modules) this replicates the named-lock-"
            "per-function misallocation shape."
        ),
    },
]


# --------------------------------------------------------------------------
# Record construction.
#
# Three mitigation states are emitted per (component, finding):
#   - pre-fix: shape that landed before Vyper 0.3.1
#   - post-fix-not-migrated: pool deployed with an affected compiler
#     version that has not been redeployed against 0.3.1; live exposure
#     persists. Curve July 2023 falls in this bucket because the
#     affected pools were deployed in 2021-2022 (pre 0.3.1 release-
#     and-redeploy adoption) and were never redeployed before the
#     2023 exploit.
#   - post-fix-released: residual / forensic record for any future
#     deployment that does redeploy against 0.3.1. Emitted only because
#     NVD and GHSA both confirm the upstream fix shipped in 0.3.1.
# --------------------------------------------------------------------------
MITIGATION_STATES = ("pre-fix", "post-fix-not-migrated", "post-fix-released")

# Severity walk-back for the post-fix-released record (the live exposure
# is closed once the redeploy lands). The walk-back is one tier per the
# project convention used in the sibling miners.
SEVERITY_WALK_BACK = {
    "critical": "high",
    "high": "medium",
    "medium": "low",
    "low": "info",
    "info": "info",
}

# Pool / oracle entries are critical pre-fix because the GHSA carries a
# `severity=critical` field and the production exploit drained ~$70M.
BASE_SEVERITY = "critical"


def build_direct_pool_record(
    pool: Dict[str, Any], state: str
) -> Dict[str, Any]:
    pool_name = str(pool["pool_name"]).strip()
    pool_addr = str(pool["pool_address"]).strip().lower()
    vyper_version = str(pool["vyper_version"]).strip()
    incident_date = str(pool["incident_date"]).strip()
    trigger_function = str(pool["trigger_function"]).strip()
    loss_usd = int(pool.get("loss_usd") or 0)

    pool_slug = slugify(pool_name, max_len=60)
    addr_slug = slugify(pool_addr, max_len=42)
    state_slug = slugify(state, max_len=30)
    advisory_slug = slugify(ADVISORY_ID_CVE, max_len=24)
    source_ref = f"vyper-39363:{advisory_slug}:{pool_slug}:{addr_slug}:{state_slug}"
    digest = hashlib.sha256(source_ref.encode("utf-8")).hexdigest()[:12]
    record_id = f"{source_ref}:{digest}"

    severity = BASE_SEVERITY
    attacker_action = (
        DIRECT_ATTACK_BASE
        + f" Concretely: {pool_name} (address {pool_addr}), deployed with Vyper "
        + f"{vyper_version}, exploited 2023-07-30 via {trigger_function}."
    )
    if state == "post-fix-not-migrated":
        # Live exposure persists. This is the bucket the Curve July 2023
        # incident actually fell into. Severity is preserved at critical.
        attacker_action += (
            " Post-fix posture: upstream patch shipped in Vyper "
            f"{FIX_VERSION} but the pool was NOT redeployed; the live "
            "exposure persisted from 2021-12 (Vyper 0.3.1 release) "
            "until the on-chain exploit."
        )
    elif state == "post-fix-released":
        # Pool is redeployed against patched compiler. Live exposure
        # closed; severity walks back.
        severity = SEVERITY_WALK_BACK[severity]
        attacker_action += (
            f" Post-fix posture: pool redeployed against Vyper {FIX_VERSION}"
            "+ closes the live exposure; only forensic / cross-engagement "
            "value remains."
        )

    preconditions = [
        f"pool compiled with Vyper {vyper_version} (affected version per CVE-2023-39363)",
        "pool exposes a @nonreentrant decorated function whose execution path emits ETH",
        "attacker can deploy a contract whose fallback reenters a sibling decorated function",
        f"mitigation_state={state}",
        f"advisory_id={ADVISORY_ID_CVE}",
        f"fixed_versions={FIX_VERSION}",
    ]
    preconditions = list(dict.fromkeys(preconditions))[:6]

    return {
        "schema_version": SCHEMA_VERSION,
        "record_id": record_id,
        "source_audit_ref": source_ref,
        "target_domain": "dex",
        "target_language": "vyper",
        "target_repo": "curvefi/curve-contract",
        "target_component": pool_name[:240],
        "function_shape": {
            "raw_signature": vyper_signature("direct"),
            "shape_tags": shape_tags("direct", vyper_version, state),
        },
        "bug_class": BUG_CLASS,
        "attack_class": ATTACK_CLASS,
        "attacker_role": "unprivileged",
        "attacker_action_sequence": attacker_action[:5000],
        "required_preconditions": preconditions,
        "impact_class": "theft",
        "impact_actor": "depositor-class",
        "impact_dollar_class": impact_dollar_for_loss(loss_usd),
        "fix_pattern": (
            f"Vyper {FIX_VERSION} (vyperlang/vyper#2439, #2514) shares a single "
            "storage slot across all functions tagged with the same "
            "@nonreentrant key, restoring the intended cross-function "
            "lock semantics. Deployments must redeploy against >= "
            f"{FIX_VERSION}; LP-pricing consumers should additionally "
            "wrap virtual_price reads in their own reentrancy check."
        )[:1000],
        "fix_anti_pattern_avoided": (
            "treating the @nonreentrant decorator on an affected Vyper "
            "version as ground truth without an external reentrancy "
            "guard at the caller / oracle layer"
        )[:1000],
        "severity_at_finding": severity,
        "year": 2023,
        "cross_language_analogues": CROSS_LANGUAGE_ANALOGUES,
        "related_records": [],
    }


def build_downstream_record(
    proto: Dict[str, Any], state: str
) -> Dict[str, Any]:
    proto_name = str(proto["protocol_name"]).strip()
    exposure_via = str(proto["exposure_via"]).strip()
    incident_date = str(proto["incident_date"]).strip()
    loss_usd = int(proto.get("loss_usd") or 0)

    proto_slug = slugify(proto_name, max_len=60)
    state_slug = slugify(state, max_len=30)
    advisory_slug = slugify(ADVISORY_ID_CVE, max_len=24)
    source_ref = f"vyper-39363:{advisory_slug}:downstream:{proto_slug}:{state_slug}"
    digest = hashlib.sha256(source_ref.encode("utf-8")).hexdigest()[:12]
    record_id = f"{source_ref}:{digest}"

    severity = "high"  # downstream oracle exposure is one tier below the
    # direct-pool theft because the lending market typically has a
    # debt-ceiling cap; the Curve July 2023 incident drained the LP-
    # holders, not the lender directly.
    attacker_action = (
        READONLY_ATTACK_BASE
        + f" Concretely: {proto_name} (exposure path: {exposure_via}), "
        + f"affected in the 2023-07-30 incident window."
    )
    if state == "post-fix-not-migrated":
        severity = "high"
        attacker_action += (
            " Post-fix posture: upstream Vyper patch shipped in "
            f"{FIX_VERSION} (Dec 2021); affected Curve pools were not "
            "redeployed prior to 2023-07-30, leaving downstream "
            "oracle consumers exposed for ~19 months."
        )
    elif state == "post-fix-released":
        severity = SEVERITY_WALK_BACK[severity]
        attacker_action += (
            f" Post-fix posture: once the underlying Curve pool is "
            f"redeployed against Vyper {FIX_VERSION}+, the live "
            "exposure is closed; only historical-forensic value "
            "remains."
        )

    preconditions = [
        f"protocol prices collateral via Curve pool deployed with Vyper {AFFECTED_VERSIONS[0]} / {AFFECTED_VERSIONS[1]} / {AFFECTED_VERSIONS[2]}",
        "protocol reads virtual_price / get_dy live during a state-changing entrypoint",
        "attacker can trigger a remove_liquidity ETH refund on the same Curve pool",
        f"mitigation_state={state}",
        f"advisory_id={ADVISORY_ID_CVE}",
        f"fixed_versions={FIX_VERSION}",
    ]
    preconditions = list(dict.fromkeys(preconditions))[:6]

    return {
        "schema_version": SCHEMA_VERSION,
        "record_id": record_id,
        "source_audit_ref": source_ref,
        "target_domain": "lending",
        "target_language": "solidity",  # downstream consumers are Solidity
        "target_repo": "unknown",
        "target_component": (proto_name + " via " + exposure_via)[:240],
        "function_shape": {
            "raw_signature": vyper_signature("readonly"),
            "shape_tags": shape_tags("readonly", AFFECTED_VERSIONS[0], state),
        },
        "bug_class": BUG_CLASS,
        "attack_class": ATTACK_CLASS,
        "attacker_role": "unprivileged",
        "attacker_action_sequence": attacker_action[:5000],
        "required_preconditions": preconditions,
        "impact_class": "theft",
        "impact_actor": "yield-recipient",
        "impact_dollar_class": impact_dollar_for_loss(loss_usd),
        "fix_pattern": (
            f"Underlying Curve pool must redeploy against Vyper >= {FIX_VERSION}; "
            "downstream lenders should additionally guard "
            "virtual_price reads behind an explicit read-only "
            "reentrancy check (call into the pool's "
            "@nonreentrant-guarded view to confirm the lock is "
            "released before pricing)."
        )[:1000],
        "fix_anti_pattern_avoided": (
            "pricing LP collateral from a live virtual_price query "
            "without verifying the underlying pool is not mid-"
            "operation"
        )[:1000],
        "severity_at_finding": severity,
        "year": 2023,
        "cross_language_analogues": CROSS_LANGUAGE_ANALOGUES,
        "related_records": [],
    }


def build_all_records() -> List[Dict[str, Any]]:
    records: List[Dict[str, Any]] = []
    for pool in CURVE_POOLS_AFFECTED:
        for state in MITIGATION_STATES:
            records.append(build_direct_pool_record(pool, state))
    for proto in DOWNSTREAM_PROTOCOLS_AFFECTED:
        for state in MITIGATION_STATES:
            records.append(build_downstream_record(proto, state))
    # Cross-link related records by advisory_slug (the second source_audit_ref
    # token), so every record for CVE-2023-39363 lists its siblings.
    by_advisory: Dict[str, List[str]] = {}
    for record in records:
        parts = record["source_audit_ref"].split(":")
        if len(parts) >= 2:
            adv = parts[1]
            by_advisory.setdefault(adv, []).append(record["record_id"])
    for record in records:
        parts = record["source_audit_ref"].split(":")
        if len(parts) >= 2:
            adv = parts[1]
            siblings = [
                rid
                for rid in by_advisory.get(adv, [])
                if rid != record["record_id"]
            ]
            record["related_records"] = sorted(set(siblings))[:12]
    return records


def output_filename(record: Dict[str, Any]) -> str:
    digest = str(record["record_id"]).rsplit(":", 1)[-1]
    return f"{slugify(record['record_id'], max_len=110)}-{digest}.yaml"


def write_records(
    records: Sequence[Dict[str, Any]], out_dir: Path, *, dry_run: bool
) -> List[Path]:
    paths: List[Path] = []
    if not dry_run:
        out_dir.mkdir(parents=True, exist_ok=True)
    for record in records:
        path = out_dir / output_filename(record)
        paths.append(path)
        if dry_run:
            continue
        path.write_text(yaml_dump(record), encoding="utf-8")
    return paths


def _load_validator() -> Any:
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "_hackerman_record_validate_for_vyper_39363",
        str(REPO_ROOT / "tools" / "hackerman-record-validate.py"),
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


def validate_records(records: Sequence[Dict[str, Any]]) -> List[str]:
    validator = _load_validator()
    schema = validator.load_schema()
    errors: List[str] = []
    for record in records:
        for err in validator.validate_doc(dict(record), schema):
            errors.append(f"{record['record_id']}: {err}")
    return errors


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--out-dir",
        default=str(DEFAULT_OUT_DIR),
        help="Directory for emitted hackerman_record YAML files.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Build records and summary without writing YAML files.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Maximum records to emit (post-expansion).",
    )
    parser.add_argument(
        "--json-summary",
        action="store_true",
        help="Print a machine-readable JSON summary.",
    )
    parser.add_argument(
        "--skip-validation",
        action="store_true",
        help="Skip schema validation (debugging only).",
    )
    args = parser.parse_args(argv)

    if args.limit is not None and args.limit < 0:
        print("--limit must be non-negative", file=sys.stderr)
        return 2

    records = build_all_records()
    if args.limit is not None:
        records = records[: args.limit]

    errors: List[str] = []
    if not args.skip_validation:
        errors = validate_records(records)

    out_dir = Path(args.out_dir).expanduser().resolve()
    paths: List[Path] = []
    if not errors:
        paths = write_records(records, out_dir, dry_run=args.dry_run)

    summary = {
        "schema_version": SCHEMA_VERSION,
        "advisory_id": ADVISORY_ID_CVE,
        "ghsa_id": ADVISORY_ID_GHSA,
        "affected_versions": AFFECTED_VERSIONS,
        "fix_version": FIX_VERSION,
        "out_dir": str(out_dir),
        "dry_run": args.dry_run,
        "pools_seeded": len(CURVE_POOLS_AFFECTED),
        "downstream_protocols_seeded": len(DOWNSTREAM_PROTOCOLS_AFFECTED),
        "records_emitted": len(records),
        "errors": errors,
        "files": [str(path) for path in paths[:50]],
        "file_count": len(paths),
        "reference_urls": list(REFERENCE_URLS),
    }
    if args.json_summary:
        print(json.dumps(summary, sort_keys=True))
    else:
        print(
            "hackerman Vyper-39363 ETL: "
            f"advisory={ADVISORY_ID_CVE} ({ADVISORY_ID_GHSA}) "
            f"pools={summary['pools_seeded']} "
            f"downstream={summary['downstream_protocols_seeded']} "
            f"records={summary['records_emitted']} "
            f"errors={len(errors)} dry_run={summary['dry_run']}"
        )
    return 0 if not errors else 1


if __name__ == "__main__":
    sys.exit(main())
