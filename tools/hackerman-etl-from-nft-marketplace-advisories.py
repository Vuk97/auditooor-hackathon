#!/usr/bin/env python3
"""Wave-1 Hackerman ETL: NFT / ERC-721 / marketplace ecosystem GHSA feeds.

Pulls REAL security advisories from major NFT / ERC-721 / marketplace
contract suites, indexers, and SDKs (OpenSea / Seaport, Reservoir,
Zora, Foundation, LooksRare, Blur, thirdweb, Manifold, transmissions11,
ERC-6900, ERC721A, Decentraland, Enjin, spcoin) via the GitHub Security
Advisory REST endpoint and emits one ``auditooor.hackerman_record.v1``
per advisory.

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
``audit/corpus_tags/tags/nft_marketplace_advisories/<owner>__<repo>__<ghsa>/``.

CLI:

    # Live pull (default):
    python3 tools/hackerman-etl-from-nft-marketplace-advisories.py \\
        --out-dir audit/corpus_tags/tags/nft_marketplace_advisories

    # Offline replay of a cached payload:
    python3 tools/hackerman-etl-from-nft-marketplace-advisories.py \\
        --cache-file /tmp/nft-marketplace-ghsa-cache.json \\
        --out-dir audit/corpus_tags/tags/nft_marketplace_advisories

Shape anchor: ``tools/hackerman-etl-from-erc4337-advisories.py`` and
``tools/hackerman-etl-from-amm-yield-lst.py``.
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
SUMMARY_SCHEMA = "auditooor.hackerman_etl.nft_marketplace_advisories.summary.v1"


def _load_validator() -> Any:
    spec = importlib.util.spec_from_file_location(
        "_hackerman_record_validate_nft_marketplace",
        str(REPO_ROOT / "tools" / "hackerman-record-validate.py"),
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


_VALIDATOR = _load_validator()


# ---------------------------------------------------------------------------
# Target repos. Each entry is (repo, language, domain).
#
# language + domain are schema-enum values from
# audit/corpus_tags/schemas/auditooor.hackerman_record.v1.schema.json.
#
# Marketplace exchange + NFT contract suites -> Solidity / "nft" domain.
# Indexer/TypeScript SDK off-chain stacks -> "typescript-onchain" /
#   "rpc-infra" (indexer/server surfaces that ingest signed orders).
# In-game pack-contract -> "gaming" domain.
#
# Honest-zero is allowed; the miner records repos with no advisories in
# ``repos_with_zero_advisories`` rather than fabricating.
# ---------------------------------------------------------------------------


TARGET_REPOS: Tuple[Tuple[str, str, str], ...] = (
    # OpenSea / Seaport - canonical NFT marketplace protocol
    ("ProjectOpenSea/opensea-creatures", "solidity", "nft"),
    ("ProjectOpenSea/seaport", "solidity", "nft"),
    ("ProjectOpenSea/seaport-core", "solidity", "nft"),

    # Reservoir - NFT indexer + marketplace UI
    ("reservoirprotocol/indexer", "typescript-onchain", "rpc-infra"),
    ("reservoirprotocol/marketplace-v2", "typescript-onchain", "rpc-infra"),

    # Zora - NFT protocol + v3 marketplace
    ("ourzora/zora-protocol", "solidity", "nft"),
    ("ourzora/v3", "solidity", "nft"),

    # Foundation - fnd-protocol
    ("foundation/fnd-protocol", "solidity", "nft"),

    # LooksRare - exchange v1 + v2
    ("looksrare/contracts-exchange-v1", "solidity", "nft"),
    ("looksrare/contracts-exchange-v2", "solidity", "nft"),

    # Blur - blur-poolswap
    ("blur-io/blur-poolswap", "solidity", "nft"),

    # thirdweb - contracts + typescript-sdk
    ("thirdweb-dev/contracts", "solidity", "nft"),
    ("thirdweb-dev/typescript-sdk", "typescript-onchain", "rpc-infra"),

    # Manifold - creator-core-solidity
    ("manifoldxyz/creator-core-solidity", "solidity", "nft"),

    # transmissions11 - solmate (shared NFT-utility lib)
    ("transmissions11/solmate", "solidity", "nft"),

    # ERC-6900 reference (modular smart accounts; NFT-marketplace adjacent
    # via plug-in NFT execution modules)
    ("erc6900/reference-implementation", "solidity", "nft"),

    # ERC721A - canonical low-gas mint extension
    ("ERC721A/ERC721A", "solidity", "nft"),
    # chiru-labs legacy ERC721A archive (same author, kept per brief)
    ("chiru-labs/ERC721A", "solidity", "nft"),

    # Decentraland - marketplace
    ("Decentraland/marketplace", "solidity", "nft"),

    # Enjin pack-contract (in-game asset packs - gaming domain)
    ("enjin/enjin-platform-pcg-pack-contract", "solidity", "gaming"),

    # spcoin rewards
    ("spcoin-utils/spcoin-rewards", "solidity", "nft"),
)


# ---------------------------------------------------------------------------
# YAML / slug helpers (byte-stable, mirrored from sibling miners).
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
    ``tier-1-ghsa-cache`` (replay). Both reflect tier-1 verification:
    the cache was originally populated by a live REST call.
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


# NFT marketplace impact keyword routing. Ordered: more specific keywords
# first (signature/order replay/forgery first, then theft/drain on NFTs,
# then royalty/fee bypass, then governance, then freeze, then DoS).
_IMPACT_KEYWORDS: Tuple[Tuple[str, str], ...] = (
    # signature / order-validation / replay - the canonical NFT-marketplace
    # exchange bug class (Seaport / LooksRare / Blur exchange order surface).
    ("signature malleability", "privilege-escalation"),
    ("signature forgery", "privilege-escalation"),
    ("signature replay", "privilege-escalation"),
    ("order replay", "privilege-escalation"),
    ("order forgery", "privilege-escalation"),
    ("listing forgery", "privilege-escalation"),
    ("bid replay", "privilege-escalation"),
    ("offer replay", "privilege-escalation"),
    ("permit replay", "privilege-escalation"),
    ("eip-712", "privilege-escalation"),
    ("eip712", "privilege-escalation"),
    ("merkle proof", "privilege-escalation"),
    ("merkle root", "privilege-escalation"),
    ("merkle bypass", "privilege-escalation"),
    ("validation bypass", "privilege-escalation"),
    ("authorization bypass", "privilege-escalation"),
    ("authentication bypass", "privilege-escalation"),
    ("auth bypass", "privilege-escalation"),
    ("access control", "privilege-escalation"),
    ("privilege escalation", "privilege-escalation"),
    ("missing isapproved", "privilege-escalation"),
    ("missing approval check", "privilege-escalation"),
    ("approval", "privilege-escalation"),
    # theft / drain on NFTs, royalty, treasury
    ("nft theft", "theft"),
    ("token theft", "theft"),
    ("steal nft", "theft"),
    ("steal", "theft"),
    ("theft", "theft"),
    ("drain", "theft"),
    ("siphon", "theft"),
    ("loss of funds", "theft"),
    ("fund loss", "theft"),
    ("reentrancy", "theft"),
    ("unsafe transferfrom", "theft"),
    ("safetransferfrom", "theft"),
    ("transferfrom bypass", "theft"),
    # royalty / fee skim - in NFT marketplace contexts a royalty bypass is
    # a yield-redistribution (royalty stream redirected away from creator)
    ("royalty bypass", "yield-redistribution"),
    ("royalty skim", "yield-redistribution"),
    ("royalty manipulation", "yield-redistribution"),
    ("royalty redirect", "yield-redistribution"),
    ("fee skim", "yield-redistribution"),
    ("fee bypass", "yield-redistribution"),
    ("creator fee", "yield-redistribution"),
    # governance / admin
    ("admin takeover", "governance-takeover"),
    ("upgrade hijack", "governance-takeover"),
    ("proxy hijack", "governance-takeover"),
    ("implementation hijack", "governance-takeover"),
    ("governance", "governance-takeover"),
    # precision / rounding
    ("rounding", "precision-loss"),
    ("precision", "precision-loss"),
    ("overflow", "precision-loss"),
    ("underflow", "precision-loss"),
    # freeze / brick the NFT or marketplace contract
    ("brick", "freeze"),
    ("locked", "freeze"),
    ("frozen", "freeze"),
    ("stuck", "freeze"),
    ("freeze", "freeze"),
    ("permanent freeze", "freeze"),
    ("nft locked", "freeze"),
    ("non-transferable", "freeze"),
    # indexer / griefing
    ("indexer poisoning", "griefing"),
    ("griefing", "griefing"),
    ("metadata poisoning", "griefing"),
    # DoS catch-all
    ("denial of service", "dos"),
    ("denial-of-service", "dos"),
    ("dos", "dos"),
)


def _infer_impact_class(advisory: Dict[str, Any]) -> str:
    haystack = " ".join(
        str(advisory.get(k, "")) for k in ("summary", "description")
    ).lower()
    for kw, impact in _IMPACT_KEYWORDS:
        if kw in haystack:
            return impact
    # NFT marketplace default: most uncategorised advisories on these
    # surfaces are order-validation / signature / approval bypass leading
    # to unauthorised transfer of someone else's NFT or listing, so
    # privilege-escalation is the safer default than DoS.
    return "privilege-escalation"


def _infer_impact_actor(impact_class: str, domain: str) -> str:
    if impact_class == "governance-takeover":
        return "protocol-treasury"
    if impact_class == "yield-redistribution":
        # Royalty skim impacts the creator / yield recipient.
        return "yield-recipient"
    if impact_class == "dos":
        return "arbitrary-user"
    # privilege-escalation / theft / freeze / griefing / precision-loss
    # on the nft/gaming/rpc-infra surfaces: typically affects the specific
    # NFT holder whose listing/approval is abused.
    if impact_class in {"privilege-escalation", "theft", "freeze",
                        "precision-loss", "griefing"}:
        if domain in {"nft", "gaming"}:
            return "specific-user"
        if domain == "rpc-infra":
            # Indexer/SDK-side bug typically affects any consumer of the API.
            return "arbitrary-user"
        return "arbitrary-user"
    return "arbitrary-user"


def _record_id(repo: str, ghsa_id: str) -> str:
    repo_slug = slugify(repo.replace("/", "-"), max_len=64)
    ghsa_slug = slugify(ghsa_id, max_len=64) or "ghsa-unknown"
    payload = f"nft-marketplace|{repo}|{ghsa_id}"
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:12]
    return f"nftmkt:{repo_slug}:{ghsa_slug}:{digest}"


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
    raw_signature = pkgs[0] if pkgs else f"{lang}-nft-marketplace-package"
    shape_tags: List[str] = [
        slugify(f"nft-marketplace-{lang}", max_len=64),
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
        unique = ["nft-marketplace-ghsa"]
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
        f"Running unpatched {severity}-severity advisory-tagged NFT / "
        f"ERC-721 / marketplace exchange / indexer / SDK dependency in "
        f"production; ignoring the GHSA notification window before applying "
        f"the patched-versions tag.",
        "Running an unpatched advisory-tagged NFT / marketplace dependency.",
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
            f"GHSA-tracked vulnerability in {lang} NFT / ERC-721 / "
            f"marketplace stack; see upstream advisory."
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
        "bug_class": "smart-contract-nft-marketplace-vulnerability",
        "attack_class": f"ghsa-public-advisory-{lang}-nft-marketplace",
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
    """Per-record sub-directory slug, e.g.
    ``projectopensea__seaport__ghsa-xxxx-yyyy-zzzz``.
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
            "hackerman nft-marketplace ETL: "
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
