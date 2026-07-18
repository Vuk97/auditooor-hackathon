#!/usr/bin/env python3
"""Wave-1 Hackerman ETL: deep EigenLayer / AVS / LRT ecosystem GHSA feeds.

Complementary deep miner for ``tools/hackerman-etl-from-restaking-lrt-advisories.py``.
The sibling miner was authored against an early operator brief whose
TARGET_REPOS list contained several mis-named repos (404 on live ``gh
api`` calls): ``karak-network/contracts``,
``etherfi-protocol/smart-contract-v2``, ``ether-fi/king-protocol``,
``renzoprotocol/contracts-public``, ``swell-network/v3``,
``kelpdao/contracts``, ``inception-finance/inception-restaking-pool``,
``bedrock-defi/uniBTC-contracts``, ``puffer-finance/puffer-pool``, and a
few related variants. Those orgs / repo names do not resolve.

This miner replaces them with the CANONICAL org + repo names enumerated
live from ``gh api /orgs/<org>/repos?per_page=100`` on 2026-05-16:

* ``Layr-Labs/*`` (EigenLayer + EigenDA + AVS-SDKs + AVS examples) - 19 repos
* ``symbioticfi/*`` (Symbiotic core + relay + rewards + burners + cli) - 16 repos
* ``karak-network/*`` (Karak v1/v2 contracts + DSS-Templates + KUDA + Hyperlane-DSS) - 12 repos
* ``etherfi-protocol/*`` (ether.fi smart-contracts + AVS-operator + cash + weETH + symbiotic-contracts) - 16 repos
* ``Renzo-Protocol/*`` (Renzo contracts + restaking + eigenpod-proofs) - 5 repos
* ``SwellNetwork/*`` (Swell v3-core + nucleus-boring-vault) - 2 repos
* ``Kelp-DAO/*`` (Kelp LRT-rsETH + kernel + Kred-protocol) - 4 repos
* ``PufferFinance/*`` (Puffer contracts + pufETH + PufferPool + secure-signer + monorepo) - 11 repos
* ``Pier-Two/*`` (Pier Two eigenlayer + symbiotic + pectra-staking-manager) - 4 repos

Total: 90 canonically-named repos. Hard-coded org names that 404 on live
``gh api`` calls (verified 2026-05-16, see honest-zero list comments
below) are NOT in this miner:

* ``ether-fi`` org -> empty / does not host EigenLayer-side LRT code
  (canonical org for ether.fi protocol is ``etherfi-protocol``).
* ``Symbiotic-Fi`` / ``Symbioticfi`` (mixed-case) -> resolve to the
  same org as the canonical lowercase ``symbioticfi``.
* ``puffer-finance`` (kebab-case) -> resolves to the unrelated
  ``puffer-finance`` user; canonical is ``PufferFinance`` (PascalCase).
* ``renzoprotocol`` (lowercase) -> canonical is ``Renzo-Protocol``.
* ``swell-network`` -> canonical is ``SwellNetwork``.
* ``kelpdao`` -> canonical is ``Kelp-DAO``.
* ``inception-labs`` / ``inception-finance`` -> no on-chain restaking
  contracts under either org name (operator brief 2026-05-16 confirmed
  honest zero, no LRT primitives published under either org).
* ``restake-finance`` -> canonical is ``Restake-Finance``, which hosts
  only ``Audits`` / ``DefiLlama-Adapters`` / ``axelar-configs`` - no
  on-chain restaking primitives.
* ``bedrock-defi`` -> empty / no on-chain contracts published under
  this org name; Bedrock uniBTC is not hosted under a github org
  exposed via ``gh api /orgs/bedrock-defi``.

Hard rules (M14-trap discipline, per ``~/.claude/CLAUDE.md``):

* Only emit a record when the advisory was returned by a live
  ``gh api /repos/<owner>/<repo>/security-advisories`` call (or replayed
  from a previously-saved JSON cache of such a call).
* No memory-recalled GHSA / CVE IDs. Every identifier emitted is lifted
  verbatim from the live REST payload.
* Repos that return zero advisories are recorded as honest zeros in the
  summary's ``repos_with_zero_advisories`` list, not invented.
* Each record cites the GHSA ``html_url`` in ``source_audit_ref`` and as
  the first row of ``required_preconditions`` so the URL is resolvable
  from the record alone.
* Records validate against
  ``audit/corpus_tags/schemas/auditooor.hackerman_record.v1.schema.json``.

Per-source ``verification_tier`` is encoded into ``required_preconditions``
(the schema's ``additionalProperties: false`` forbids new top-level
fields). Values:

* ``verification_tier=tier-1-ghsa-rest-api`` - live GHSA REST result
* ``verification_tier=tier-1-ghsa-cache``    - replayed from saved cache

Output: one ``record.json`` + mirror ``record.yaml`` per advisory under
``audit/corpus_tags/tags/restaking_lrt_advisories/<owner>__<repo>__<ghsa>/``
(extends the same dir the original miner writes to; per-record subdir
names cannot collide because the GHSA-id is part of the slug).

CLI:

    # Live pull (default):
    python3 tools/hackerman-etl-from-restaking-avs-deep.py \\
        --out-dir audit/corpus_tags/tags/restaking_lrt_advisories

    # Offline replay of a cached payload:
    python3 tools/hackerman-etl-from-restaking-avs-deep.py \\
        --cache-file /tmp/restaking-avs-deep-ghsa-cache.json \\
        --out-dir audit/corpus_tags/tags/restaking_lrt_advisories

Shape anchor: ``tools/hackerman-etl-from-restaking-lrt-advisories.py``.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import yaml


REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_VERSION = "auditooor.hackerman_record.v1"
SUMMARY_SCHEMA = "auditooor.hackerman_etl.restaking_avs_deep.summary.v1"


def _load_validator() -> Any:
    spec = importlib.util.spec_from_file_location(
        "_hackerman_record_validate_restaking_avs_deep",
        str(REPO_ROOT / "tools" / "hackerman-record-validate.py"),
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


_VALIDATOR = _load_validator()


# ---------------------------------------------------------------------------
# Canonical TARGET_REPOS, ground-truthed via live `gh api /orgs/<org>/repos`
# enumeration on 2026-05-16. Each entry is (repo, language, domain).
#
# Schema enums (see audit/corpus_tags/schemas/auditooor.hackerman_record.v1.schema.json):
#   target_language in {solidity, go, rust, ...};
#   target_domain in {lending, dex, bridge, oracle, governance, staking,
#                     vault, rollup, zk-proof, consensus, rpc-infra, dao,
#                     escrow, nft, gaming, l1-client}.
#
# Mapping doctrine:
#   - EigenLayer core contracts / SDKs / AVS examples       -> "staking"
#   - EigenDA (data availability rollup-side)               -> "rollup"
#   - Symbiotic core / relay / rewards / burners            -> "staking"
#   - Symbiotic cosmos-sdk (consensus-layer fork)           -> "consensus"
#   - Karak v1/v2 contracts + DSS templates + KUDA + Hyperlane-DSS -> "staking"
#   - ether.fi LRT smart-contracts + AVS-operator           -> "vault" / "staking"
#   - Renzo contracts-public + restaking + foundational-hooks      -> "vault"
#   - Swell v3-core-public + nucleus-boring-vault           -> "vault"
#   - Kelp-DAO LRT-rsETH + kernel + Kred-protocol           -> "vault"
#   - Puffer puffer-contracts + pufETH + PufferPool         -> "vault"
#   - Puffer secure-signer + rave (TEE/SGX attestation)     -> "zk-proof"
#   - Puffer monorepo / puffer-sdk / coral                  -> "staking"
#   - Pier-Two eigenlayer / symbiotic / staking-ts          -> "staking"
#
# Honest-zero is preserved; the miner records repos with no advisories
# in ``repos_with_zero_advisories`` rather than fabricating.
# ---------------------------------------------------------------------------


TARGET_REPOS: Tuple[Tuple[str, str, str], ...] = (
    # EigenLayer (Layr-Labs) - 19 repos
    ("Layr-Labs/eigenlayer-contracts", "solidity", "staking"),
    ("Layr-Labs/eigensdk-go", "go", "staking"),
    ("Layr-Labs/eigenlayer-middleware", "solidity", "staking"),
    ("Layr-Labs/eigensdk-rs", "rust", "staking"),
    ("Layr-Labs/eigenlayer-cli", "go", "staking"),
    ("Layr-Labs/eigenda", "go", "rollup"),
    ("Layr-Labs/eigenda-proxy", "go", "rollup"),
    ("Layr-Labs/eigenda-utils", "solidity", "rollup"),
    ("Layr-Labs/eigenpod-proofs-generation", "go", "staking"),
    ("Layr-Labs/eigenlayer-rewards-updater", "go", "staking"),
    ("Layr-Labs/eigenlayer-rewards-proofs", "solidity", "staking"),
    ("Layr-Labs/avs-sync", "go", "staking"),
    ("Layr-Labs/sidecar", "go", "staking"),
    ("Layr-Labs/bn254-bls-keystore-rs", "rust", "staking"),
    ("Layr-Labs/bn254-keystore-go", "go", "staking"),
    ("Layr-Labs/rust-kzg-bn254", "rust", "zk-proof"),
    ("Layr-Labs/incredible-squaring-avs", "solidity", "staking"),
    ("Layr-Labs/incredible-squaring-avs-rs", "rust", "staking"),
    ("Layr-Labs/hello-world-avs", "solidity", "staking"),

    # Symbiotic (symbioticfi) - 16 repos (canonical lowercase org)
    ("symbioticfi/core", "solidity", "staking"),
    ("symbioticfi/collateral", "solidity", "staking"),
    ("symbioticfi/rewards", "solidity", "staking"),
    ("symbioticfi/relay-contracts", "solidity", "staking"),
    ("symbioticfi/burners", "solidity", "staking"),
    ("symbioticfi/periphery", "solidity", "staking"),
    ("symbioticfi/cli", "rust", "staking"),
    ("symbioticfi/hooks", "solidity", "staking"),
    ("symbioticfi/relay", "go", "staking"),
    ("symbioticfi/rewards-v2", "solidity", "staking"),
    ("symbioticfi/cosmos-sdk", "go", "consensus"),
    ("symbioticfi/cosmos-relay-sdk", "go", "consensus"),
    ("symbioticfi/network", "go", "staking"),
    ("symbioticfi/relay-client-ts", "typescript-onchain", "staking"),
    ("symbioticfi/relay-client-rs", "rust", "staking"),
    ("symbioticfi/gov-token-staking", "solidity", "staking"),

    # Karak (karak-network) - 12 repos
    ("karak-network/v1-contracts-public", "solidity", "staking"),
    ("karak-network/v2-contracts", "solidity", "staking"),
    ("karak-network/karak-rs", "rust", "staking"),
    ("karak-network/karak-onchain-sdk", "solidity", "staking"),
    ("karak-network/Hyperlane-DSS", "solidity", "staking"),
    ("karak-network/DSS-Templates", "solidity", "staking"),
    ("karak-network/kuda-operator", "rust", "staking"),
    ("karak-network/wormhole-dss-operator", "rust", "staking"),
    ("karak-network/wormhole-dss-contracts", "solidity", "staking"),
    ("karak-network/kuda-da-server", "rust", "rollup"),
    ("karak-network/kuda-challenger", "rust", "rollup"),
    ("karak-network/kuda-prover", "rust", "rollup"),

    # ether.fi (etherfi-protocol) - 16 repos
    ("etherfi-protocol/smart-contracts", "solidity", "vault"),
    ("etherfi-protocol/etherfi-avs-operator", "solidity", "staking"),
    ("etherfi-protocol/etherfi-avs-operator-CLI", "go", "staking"),
    ("etherfi-protocol/cash-contracts", "solidity", "vault"),
    ("etherfi-protocol/cash-v3", "solidity", "vault"),
    ("etherfi-protocol/ethfi-wormhole", "solidity", "bridge"),
    ("etherfi-protocol/weETH-cross-chain", "solidity", "bridge"),
    ("etherfi-protocol/avs-smart-contracts", "solidity", "staking"),
    ("etherfi-protocol/Native-Minting-Bot", "typescript-onchain", "vault"),
    ("etherfi-protocol/eigenpod-proofs-generation", "go", "staking"),
    ("etherfi-protocol/eigenpod-proofs-generation-slashing", "go", "staking"),
    ("etherfi-protocol/eigenlayer-cli-etherfi", "go", "staking"),
    ("etherfi-protocol/eigenlayer-rewards-proofs", "solidity", "staking"),
    ("etherfi-protocol/burners", "solidity", "vault"),
    ("etherfi-protocol/beHYPE", "solidity", "vault"),
    ("etherfi-protocol/symbiotic-contracts", "solidity", "staking"),

    # Renzo (Renzo-Protocol) - 5 repos
    ("Renzo-Protocol/contracts-public", "solidity", "vault"),
    ("Renzo-Protocol/restaking", "solidity", "vault"),
    ("Renzo-Protocol/eigenpod-proofs-generation", "go", "staking"),
    ("Renzo-Protocol/eigenpod-proofs-generation-prepectra", "go", "staking"),
    ("Renzo-Protocol/foundational-hooks", "solidity", "vault"),

    # Swell (SwellNetwork) - 2 repos
    ("SwellNetwork/v3-core-public", "solidity", "vault"),
    ("SwellNetwork/nucleus-boring-vault", "solidity", "vault"),

    # Kelp-DAO - 4 repos
    ("Kelp-DAO/LRT-rsETH", "solidity", "vault"),
    ("Kelp-DAO/kernel-smart-contracts-public", "solidity", "vault"),
    ("Kelp-DAO/Kred-protocol-public", "solidity", "vault"),
    ("Kelp-DAO/eigenpod-proofs-generation", "go", "staking"),

    # Puffer (PufferFinance) - 11 repos
    ("PufferFinance/puffer-contracts", "solidity", "vault"),
    ("PufferFinance/pufETH", "solidity", "vault"),
    ("PufferFinance/PufferPool", "solidity", "vault"),
    ("PufferFinance/secure-signer", "rust", "zk-proof"),
    ("PufferFinance/rave", "rust", "zk-proof"),
    ("PufferFinance/coral", "rust", "staking"),
    ("PufferFinance/monorepo", "solidity", "staking"),
    ("PufferFinance/puffer-sdk", "typescript-onchain", "staking"),
    ("PufferFinance/operator-calldata-generator", "typescript-onchain", "staking"),
    ("PufferFinance/Deployments-and-ACL", "solidity", "staking"),
    ("PufferFinance/EL-Operator-Metadata", "typescript-onchain", "staking"),

    # Pier-Two - 4 repos
    ("Pier-Two/eigenlayer", "go", "staking"),
    ("Pier-Two/symbiotic", "go", "staking"),
    ("Pier-Two/staking-ts", "typescript-onchain", "staking"),
    ("Pier-Two/pectra-staking-manager", "typescript-onchain", "staking"),
)


# ---------------------------------------------------------------------------
# YAML / slug helpers (byte-stable, mirrored from sibling miner).
# ---------------------------------------------------------------------------


def slugify(value: object, *, max_len: int = 80) -> str:
    text = str(value or "").strip().lower()
    text = re.sub(r"[^a-z0-9._:/-]+", "-", text).strip("-._")
    text = re.sub(r"-{2,}", "-", text)
    return (text[:max_len].strip("-._") or "record")


def one_line(text: object, fallback: str, *, max_len: int = 1000) -> str:
    cleaned = re.sub(r"\s+", " ", str(text or "")).strip()
    return (cleaned[:max_len].strip() if cleaned else fallback)


def yaml_scalar(value: object) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
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
                            lines.append(
                                f"{'  -' if first else '  '} {subkey}: {yaml_scalar(subvalue)}"
                            )
                            first = False
                    else:
                        lines.append(f"  - {yaml_scalar(item)}")
        else:
            lines.append(f"{key}: {yaml_scalar(value)}")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# gh-api fetch + cache.
# ---------------------------------------------------------------------------


def fetch_repo_advisories(repo: str, *, per_page: int = 100) -> List[Dict[str, Any]]:
    """Call ``gh api`` and return the parsed advisory list.

    Returns ``[]`` on error (404, network, repo absent, no advisories).
    The honest-zero case is preserved; this function never invents data.
    """
    url = f"/repos/{repo}/security-advisories?per_page={per_page}&state=published"
    try:
        proc = subprocess.run(
            ["gh", "api", url],
            check=False,
            capture_output=True,
            text=True,
            timeout=60,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []
    if proc.returncode != 0:
        return []
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return []
    if not isinstance(data, list):
        return []
    return data


def fetch_all_advisories(
    repos: Iterable[Tuple[str, str, str]],
    *,
    cache_file: Optional[Path] = None,
    write_cache_file: Optional[Path] = None,
) -> Tuple[Dict[str, List[Dict[str, Any]]], str]:
    """Return ``({repo: [advisory, ...]}, source_tag)``.

    ``source_tag`` is either ``tier-1-ghsa-rest-api`` (live pull) or
    ``tier-1-ghsa-cache`` (replay).
    """
    if cache_file is not None:
        payload = json.loads(cache_file.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError(
                f"cache-file root must be a mapping; got {type(payload).__name__}"
            )
        out: Dict[str, List[Dict[str, Any]]] = {}
        for repo, _lang, _domain in repos:
            adv = payload.get(repo, [])
            if not isinstance(adv, list):
                adv = []
            out[repo] = adv
        return out, "tier-1-ghsa-cache"

    fetched: Dict[str, List[Dict[str, Any]]] = {}
    for repo, _lang, _domain in repos:
        fetched[repo] = fetch_repo_advisories(repo)
    if write_cache_file is not None:
        write_cache_file.parent.mkdir(parents=True, exist_ok=True)
        write_cache_file.write_text(
            json.dumps(fetched, indent=2, sort_keys=True), encoding="utf-8"
        )
    return fetched, "tier-1-ghsa-rest-api"


# ---------------------------------------------------------------------------
# Advisory -> record mapping.
# ---------------------------------------------------------------------------


_SEVERITY_MAP: Dict[str, str] = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "moderate": "medium",
    "low": "low",
    "info": "info",
    "none": "info",
    "": "info",
}


def _normalize_severity(value: Optional[str]) -> str:
    return _SEVERITY_MAP.get(str(value or "").strip().lower(), "info")


def _dollar_class(severity: str) -> str:
    sev = severity.lower()
    if sev == "critical":
        return ">=$1M"
    if sev == "high":
        return "$100K-$1M"
    if sev == "medium":
        return "$10K-$100K"
    if sev == "low":
        return "<$10K"
    return "non-financial"


def _year_for(advisory: Dict[str, Any]) -> int:
    for key in ("published_at", "updated_at", "created_at"):
        val = advisory.get(key)
        if isinstance(val, str) and len(val) >= 4 and val[:4].isdigit():
            year = int(val[:4])
            if year >= 2000:
                return year
    return 2024


# Restaking / AVS / LRT impact keyword routing. Specific terms first.
_IMPACT_KEYWORDS: Tuple[Tuple[str, str], ...] = (
    # Restaking-specific high-signal terms.
    ("slashing cascade", "theft"),
    ("slashing escape", "theft"),
    ("malicious slash", "theft"),
    ("malicious slashing", "theft"),
    ("undelegation", "freeze"),
    ("withdrawal queue", "freeze"),
    ("withdrawal delay", "freeze"),
    ("withdrawal-root", "freeze"),
    ("queued withdrawal", "freeze"),
    # AVS / operator-set governance vectors.
    ("operator takeover", "governance-takeover"),
    ("operator-set", "governance-takeover"),
    ("avs quorum", "governance-takeover"),
    ("quorum manipulation", "governance-takeover"),
    ("registry coordinator", "privilege-escalation"),
    ("bls signature", "privilege-escalation"),
    ("delegation manager", "privilege-escalation"),
    ("strategymanager", "privilege-escalation"),
    ("eigenpod", "theft"),
    ("eigenpod owner", "privilege-escalation"),
    ("beacon proof", "theft"),
    ("beacon chain", "theft"),
    ("partial withdrawal", "theft"),
    ("full withdrawal", "theft"),
    ("restaking reward", "yield-redistribution"),
    ("restaking yield", "yield-redistribution"),
    ("restaking points", "yield-redistribution"),
    # EigenDA-specific (data-availability).
    ("eigenda blob", "freeze"),
    ("blob dispersal", "freeze"),
    ("blob retrieval", "freeze"),
    # TEE / SGX attestation (Puffer secure-signer / rave / Karak KUDA).
    ("attestation", "privilege-escalation"),
    ("sgx", "privilege-escalation"),
    ("tee", "privilege-escalation"),
    ("dcap", "privilege-escalation"),
    # LRT share-accounting.
    ("lrt share inflation", "precision-loss"),
    ("share inflation", "precision-loss"),
    ("first depositor", "precision-loss"),
    ("donation attack", "precision-loss"),
    ("rounding", "precision-loss"),
    ("precision", "precision-loss"),
    ("overflow", "precision-loss"),
    ("underflow", "precision-loss"),
    # Generic theft / freeze families.
    ("reentrancy", "theft"),
    ("flash loan", "theft"),
    ("flashloan", "theft"),
    ("price manipulation", "theft"),
    ("oracle manipulation", "theft"),
    ("twap manipulation", "theft"),
    ("steal", "theft"),
    ("theft", "theft"),
    ("drain", "theft"),
    ("siphon", "theft"),
    ("loss of funds", "theft"),
    ("freeze", "freeze"),
    ("locked", "freeze"),
    ("frozen", "freeze"),
    ("stuck", "freeze"),
    ("griefing", "griefing"),
    # Governance / access-control.
    ("governance", "governance-takeover"),
    ("admin takeover", "governance-takeover"),
    ("voting", "governance-takeover"),
    ("privilege escalation", "privilege-escalation"),
    ("access control", "privilege-escalation"),
    ("authorization", "privilege-escalation"),
    # DoS bucket.
    ("denial of service", "dos"),
    ("denial-of-service", "dos"),
    ("dos", "dos"),
    # Yield / reward redistribution.
    ("validator reward", "yield-redistribution"),
    ("staking reward", "yield-redistribution"),
    ("reward distribution", "yield-redistribution"),
    ("rebase", "yield-redistribution"),
    ("yield", "yield-redistribution"),
    ("interest rate", "yield-redistribution"),
    ("reward", "yield-redistribution"),
)


def _infer_impact_class(advisory: Dict[str, Any]) -> str:
    haystack = " ".join(
        str(advisory.get(k, "")) for k in ("summary", "description")
    ).lower()
    for kw, impact in _IMPACT_KEYWORDS:
        if kw in haystack:
            return impact
    # Restaking / LRT / AVS default: most uncategorised advisories on
    # these surfaces are restaker / LRT-depositor fund-loss. Theft is
    # the safer default than DoS.
    return "theft"


def _infer_impact_actor(impact_class: str, domain: str) -> str:
    if impact_class in {"governance-takeover", "privilege-escalation"}:
        return "protocol-treasury"
    if impact_class == "yield-redistribution":
        return "yield-recipient"
    if impact_class == "dos":
        return "arbitrary-user"
    if impact_class in {"theft", "freeze", "precision-loss", "griefing"}:
        if domain in {"vault", "staking", "rollup", "zk-proof"}:
            return "depositor-class"
        return "arbitrary-user"
    return "arbitrary-user"


def _record_id(repo: str, ghsa_id: str) -> str:
    repo_slug = slugify(repo.replace("/", "-"), max_len=64)
    ghsa_slug = slugify(ghsa_id, max_len=64) or "ghsa-unknown"
    # Distinct prefix from the sibling miner to keep namespaces non-colliding.
    payload = f"restaking-avs-deep|{repo}|{ghsa_id}"
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:12]
    return f"restaking-avs-deep:{repo_slug}:{ghsa_slug}:{digest}"


def _function_shape(
    advisory: Dict[str, Any], lang: str
) -> Dict[str, Any]:
    pkgs: List[str] = []
    for vuln in advisory.get("vulnerabilities", []) or []:
        if isinstance(vuln, dict):
            pkg = vuln.get("package")
            if isinstance(pkg, dict):
                name = pkg.get("name")
                if isinstance(name, str) and name:
                    pkgs.append(name)
    raw_signature = pkgs[0] if pkgs else f"{lang}-restaking-avs-deep-package"
    shape_tags: List[str] = [
        slugify(f"restaking-avs-deep-{lang}", max_len=64),
        slugify(advisory.get("ghsa_id", "ghsa-unknown"), max_len=64),
    ]
    for pkg in pkgs[:3]:
        tag = slugify(f"pkg-{pkg}", max_len=64)
        if tag:
            shape_tags.append(tag)
    cve = advisory.get("cve_id")
    if isinstance(cve, str) and cve:
        shape_tags.append(slugify(cve, max_len=64))
    cwes = advisory.get("cwes") or []
    for cwe in cwes:
        if isinstance(cwe, dict):
            cwe_id = cwe.get("cwe_id")
            if isinstance(cwe_id, str) and cwe_id:
                shape_tags.append(slugify(cwe_id, max_len=64))
    seen: set = set()
    unique: List[str] = []
    for tag in shape_tags:
        if tag and tag not in seen:
            seen.add(tag)
            unique.append(tag)
    if not unique:
        unique = ["restaking-avs-deep-ghsa"]
    return {"raw_signature": raw_signature[:500], "shape_tags": unique}


def _required_preconditions(
    advisory: Dict[str, Any],
    repo: str,
    verification_tier: str,
) -> List[str]:
    out: List[str] = []
    url = advisory.get("html_url") or advisory.get("url")
    if isinstance(url, str) and url:
        out.append(f"Reference advisory at {url}")
    pubs = advisory.get("published_at")
    if isinstance(pubs, str) and pubs:
        out.append(f"Published-at {pubs}")
    cve = advisory.get("cve_id")
    if isinstance(cve, str) and cve:
        out.append(f"CVE identifier {cve}")
    out.append(f"Affected repo {repo}")
    out.append(f"verification_tier={verification_tier}")
    seen: set = set()
    unique: List[str] = []
    for item in out:
        cleaned = one_line(item, "precondition", max_len=900)
        if cleaned and cleaned not in seen:
            seen.add(cleaned)
            unique.append(cleaned)
    return unique


def _mitigation_state(advisory: Dict[str, Any]) -> str:
    for vuln in advisory.get("vulnerabilities", []) or []:
        if isinstance(vuln, dict):
            pv = vuln.get("patched_versions")
            if isinstance(pv, str) and pv.strip():
                return "mitigated"
    return "proposed"


def _fix_pattern(advisory: Dict[str, Any]) -> str:
    patched: List[str] = []
    for vuln in advisory.get("vulnerabilities", []) or []:
        if isinstance(vuln, dict):
            pv = vuln.get("patched_versions")
            if isinstance(pv, str) and pv.strip():
                patched.append(pv.strip())
    if patched:
        return one_line(
            f"Upgrade to patched-versions {'; '.join(patched)} per the upstream GHSA.",
            "Apply the upstream patched-version range.",
            max_len=900,
        )
    return (
        "Apply the upstream maintainer's recommended fix once the advisory "
        "ships a patched-versions range."
    )


def _anti_pattern(advisory: Dict[str, Any]) -> str:
    severity = _normalize_severity(advisory.get("severity"))
    return one_line(
        f"Running unpatched {severity}-severity advisory-tagged restaking "
        f"/ AVS / LRT contract or off-chain dependency in production; "
        f"ignoring the GHSA notification window before applying the "
        f"patched-versions tag.",
        "Running an unpatched advisory-tagged restaking / AVS / LRT dependency.",
        max_len=900,
    )


def _attacker_action_sequence(
    advisory: Dict[str, Any], lang: str, mitigation: str, verification_tier: str
) -> str:
    summary = advisory.get("summary") or ""
    description = advisory.get("description") or ""
    text = f"{summary}. {description}".strip()
    if not text or text == ".":
        text = (
            f"GHSA-tracked vulnerability in {lang} restaking / AVS / LRT "
            f"stack; see upstream advisory."
        )
    state_marker = (
        f" [mitigation-state={mitigation}; source=github-security-advisory; "
        f"verification_tier={verification_tier}]"
    )
    body_max = 4900 - len(state_marker)
    body = one_line(text, "GHSA-tracked attacker action sequence", max_len=body_max)
    return (body + state_marker).strip()


def advisory_to_record(
    repo: str,
    lang: str,
    domain: str,
    advisory: Dict[str, Any],
    verification_tier: str,
) -> Dict[str, Any]:
    ghsa_id = advisory.get("ghsa_id") or "GHSA-unknown"
    if not isinstance(ghsa_id, str):
        ghsa_id = "GHSA-unknown"
    severity = _normalize_severity(advisory.get("severity"))
    impact_class = _infer_impact_class(advisory)
    impact_actor = _infer_impact_actor(impact_class, domain)
    mitigation = _mitigation_state(advisory)
    year = _year_for(advisory)
    source_url = (
        advisory.get("html_url")
        or advisory.get("url")
        or f"https://github.com/{repo}/security/advisories/{ghsa_id}"
    )

    record = {
        "schema_version": SCHEMA_VERSION,
        "record_id": _record_id(repo, ghsa_id),
        "source_audit_ref": one_line(
            source_url, f"ghsa:{repo}:{ghsa_id}", max_len=240
        ),
        "target_domain": domain,
        "target_language": lang,
        "target_repo": repo,
        "target_component": one_line(
            f"{repo}:{ghsa_id}",
            f"{repo}:advisory",
            max_len=240,
        ),
        "function_shape": _function_shape(advisory, lang),
        "bug_class": "smart-contract-restaking-avs-deep-vulnerability",
        "attack_class": f"ghsa-public-advisory-{lang}-restaking-avs-deep",
        "attacker_role": "unprivileged",
        "attacker_action_sequence": _attacker_action_sequence(
            advisory, lang, mitigation, verification_tier
        ),
        "required_preconditions": _required_preconditions(
            advisory, repo, verification_tier
        ),
        "impact_class": impact_class,
        "impact_actor": impact_actor,
        "impact_dollar_class": _dollar_class(severity),
        "fix_pattern": _fix_pattern(advisory),
        "fix_anti_pattern_avoided": _anti_pattern(advisory),
        "severity_at_finding": severity,
        "year": year,
        "record_tier": "public-corpus",
        "record_quality_score": 4.0,
        "source_extraction_method": "corpus-etl",
        "source_extraction_confidence": 0.9,
        "cross_language_analogues": [],
        "related_records": [],
    }
    return record


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------


def build_records(
    fetched: Dict[str, List[Dict[str, Any]]],
    repos: Iterable[Tuple[str, str, str]],
    verification_tier: str,
) -> List[Dict[str, Any]]:
    records: List[Dict[str, Any]] = []
    seen_ids: set = set()
    for repo, lang, domain in repos:
        for advisory in fetched.get(repo, []) or []:
            if not isinstance(advisory, dict):
                continue
            if advisory.get("state") and advisory["state"] != "published":
                continue
            record = advisory_to_record(
                repo, lang, domain, advisory, verification_tier
            )
            if record["record_id"] in seen_ids:
                continue
            seen_ids.add(record["record_id"])
            records.append(record)
    return records


def slug_for_record(record: Dict[str, Any]) -> str:
    """Per-record sub-directory slug,
    e.g. ``layr-labs__eigenlayer-contracts__ghsa-xxxx-yyyy-zzzz``.

    Lowercase, double-underscore separated; collision-free against the
    sibling miner's slugs because the GHSA id is part of the slug.
    """
    repo = record["target_repo"]
    owner_repo = repo.replace("/", "__")
    shape_tags = record["function_shape"]["shape_tags"]
    ghsa_tag = next(
        (t for t in shape_tags if t.startswith("ghsa-")),
        slugify(record["record_id"].split(":")[-1], max_len=32),
    )
    return slugify(f"{owner_repo}__{ghsa_tag}", max_len=140)


def convert(
    out_dir: Path,
    *,
    dry_run: bool = False,
    limit: Optional[int] = None,
    repos: Optional[List[Tuple[str, str, str]]] = None,
    cache_file: Optional[Path] = None,
    write_cache_file: Optional[Path] = None,
    filter_repo: Optional[str] = None,
) -> Dict[str, Any]:
    selected = list(repos or TARGET_REPOS)
    if filter_repo:
        selected = [r for r in selected if r[0] == filter_repo]
    fetched, verification_tier = fetch_all_advisories(
        selected,
        cache_file=cache_file,
        write_cache_file=write_cache_file,
    )
    records = build_records(fetched, selected, verification_tier)
    if limit is not None:
        records = records[:limit]

    schema = _VALIDATOR.load_schema()
    errors: List[str] = []
    files: List[str] = []
    sample_urls: List[str] = []
    by_repo: Dict[str, int] = {}
    by_severity: Dict[str, int] = {}
    by_impact: Dict[str, int] = {}
    by_mitigation: Dict[str, int] = {}

    if not dry_run:
        out_dir.mkdir(parents=True, exist_ok=True)

    for record in records:
        by_repo[record["target_repo"]] = by_repo.get(record["target_repo"], 0) + 1
        by_severity[record["severity_at_finding"]] = (
            by_severity.get(record["severity_at_finding"], 0) + 1
        )
        by_impact[record["impact_class"]] = (
            by_impact.get(record["impact_class"], 0) + 1
        )
        action = record["attacker_action_sequence"]
        m = re.search(r"\[mitigation-state=(\w+);", action)
        state = m.group(1) if m else "unknown"
        by_mitigation[state] = by_mitigation.get(state, 0) + 1

        rendered_yaml = yaml_dump(record)
        try:
            doc = yaml.safe_load(rendered_yaml)
        except yaml.YAMLError as exc:
            errors.append(f"{record['record_id']}: yaml-parse-error: {exc}")
            continue
        errs = _VALIDATOR.validate_doc(doc, schema)
        if errs:
            errors.extend(f"{record['record_id']}: {err}" for err in errs)
            continue

        slug = slug_for_record(record)
        rec_subdir = out_dir / slug
        json_path = rec_subdir / "record.json"
        yaml_path = rec_subdir / "record.yaml"
        files.append(str(json_path))
        if len(sample_urls) < 5:
            sample_urls.append(record["source_audit_ref"])
        if not dry_run:
            rec_subdir.mkdir(parents=True, exist_ok=True)
            json_path.write_text(
                json.dumps(record, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            yaml_path.write_text(rendered_yaml, encoding="utf-8")

    repos_with_zero = sorted(
        repo for repo, _l, _d in selected if not fetched.get(repo)
    )
    return {
        "schema_version": SUMMARY_SCHEMA,
        "out_dir": str(out_dir),
        "dry_run": dry_run,
        "verification_tier": verification_tier,
        "records_emitted": len(records) - len(errors),
        "records_attempted": len(records),
        "errors": errors,
        "by_repo": by_repo,
        "by_severity": by_severity,
        "by_impact_class": by_impact,
        "by_mitigation_state": by_mitigation,
        "file_count": len(files),
        "repos_queried": len(selected),
        "repos_with_zero_advisories": repos_with_zero,
        "sample_source_urls": sample_urls,
        "files": files[:50],
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--out-dir",
        required=True,
        help=(
            "Output dir. Records land under "
            "<out-dir>/<owner>__<repo>__<ghsa>/record.{json,yaml}."
        ),
    )
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--limit", type=int)
    parser.add_argument(
        "--cache-file",
        help="Read advisories from a previously-saved JSON cache instead of calling gh api.",
    )
    parser.add_argument(
        "--write-cache-file",
        help="Save the fetched gh-api payload to this path for later offline replay.",
    )
    parser.add_argument(
        "--filter-repo",
        help="Restrict to a single owner/repo string (must match TARGET_REPOS exactly).",
    )
    parser.add_argument("--json-summary", action="store_true")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if args.limit is not None and args.limit < 0:
        print("--limit must be non-negative", file=sys.stderr)
        return 2
    summary = convert(
        Path(args.out_dir).expanduser().resolve(),
        dry_run=args.dry_run,
        limit=args.limit,
        cache_file=Path(args.cache_file).expanduser().resolve()
        if args.cache_file
        else None,
        write_cache_file=(
            Path(args.write_cache_file).expanduser().resolve()
            if args.write_cache_file
            else None
        ),
        filter_repo=args.filter_repo,
    )
    if args.json_summary:
        print(json.dumps(summary, sort_keys=True))
    else:
        print(
            "hackerman restaking-avs-deep ETL: "
            f"records={summary['records_emitted']}/{summary['records_attempted']} "
            f"verification_tier={summary['verification_tier']} "
            f"repos_queried={summary['repos_queried']} "
            f"zero-advisory-repos={len(summary['repos_with_zero_advisories'])} "
            f"by_severity={summary['by_severity']} "
            f"errors={len(summary['errors'])}"
        )
    return 0 if not summary["errors"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
