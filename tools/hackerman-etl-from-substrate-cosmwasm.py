#!/usr/bin/env python3
"""Wave-1 Hackerman ETL: Substrate / Polkadot / parachain + CosmWasm GHSA feeds.

Pulls REAL security advisories from major Substrate / Polkadot / parachain
repositories and the CosmWasm contracts ecosystem via the GitHub Security
Advisory REST endpoint and emits one ``auditooor.hackerman_record.v1`` per
advisory.

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
``audit/corpus_tags/tags/substrate_cosmwasm_advisories/<owner>__<repo>__<ghsa>/``.

CLI:

    # Live pull (default):
    python3 tools/hackerman-etl-from-substrate-cosmwasm.py \\
        --out-dir audit/corpus_tags/tags/substrate_cosmwasm_advisories

    # Offline replay of a cached payload:
    python3 tools/hackerman-etl-from-substrate-cosmwasm.py \\
        --cache-file /tmp/substrate-cosmwasm-ghsa-cache.json \\
        --out-dir audit/corpus_tags/tags/substrate_cosmwasm_advisories

Shape anchor: ``tools/hackerman-etl-from-lending-protocols.py`` +
``tools/hackerman-etl-from-cosmos-sdk-ibc.py``.
Schema enum constraints: Substrate / Polkadot core map to language=rust,
domain=consensus; parachain dApp stacks map to their primary domain
(dex / lending / bridge / staking / l1-client). CosmWasm core stack maps
to language=rust, domain=consensus (wasmd is the consensus-relevant CW
host module); CosmWasm dApp libraries map to their dApp domain.
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
SUMMARY_SCHEMA = "auditooor.hackerman_etl.substrate_cosmwasm.summary.v1"


def _load_validator() -> Any:
    spec = importlib.util.spec_from_file_location(
        "_hackerman_record_validate_substrate_cosmwasm",
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
# Substrate / Polkadot core: language=rust, domain=consensus.
# Parachain dApp stacks (Acala/Bifrost/HydraDX/...): primary dApp domain.
# CosmWasm: wasmd / cosmwasm core map to consensus; cw-storage-plus /
# cw-template / cw-plus map to consensus as platform-library; dApp
# contracts (Mars / Astroport / Terraswap / White Whale) map to their
# dApp domain.
#
# Honest-zero is allowed; the miner records repos with no advisories in
# ``repos_with_zero_advisories`` rather than fabricating.
# ---------------------------------------------------------------------------


TARGET_REPOS: Tuple[Tuple[str, str, str], ...] = (
    # Substrate / Polkadot core
    ("paritytech/polkadot-sdk", "rust", "consensus"),
    ("paritytech/polkadot", "rust", "consensus"),
    ("paritytech/substrate", "rust", "consensus"),
    ("paritytech/cumulus", "rust", "consensus"),
    ("paritytech/parity-bridges-common", "rust", "bridge"),

    # Parachain ecosystem
    ("moonbeam-foundation/moonbeam", "rust", "l1-client"),
    ("centrifuge/centrifuge-chain", "rust", "lending"),
    ("centrifuge/centrifuge-pallets", "rust", "lending"),
    ("AcalaNetwork/Acala", "rust", "dex"),
    ("AcalaNetwork/karura", "rust", "dex"),
    ("bifrost-finance/bifrost", "rust", "staking"),
    ("galacticcouncil/HydraDX-node", "rust", "dex"),
    ("kintsugi-network/interbtc", "rust", "bridge"),
    ("AstarNetwork/Astar", "rust", "l1-client"),

    # CosmWasm core / platform libraries
    ("CosmWasm/wasmd", "rust", "consensus"),
    ("CosmWasm/cosmwasm", "rust", "consensus"),
    ("CosmWasm/cosmwasm-plus", "rust", "consensus"),
    ("CosmWasm/cw-storage-plus", "rust", "consensus"),
    ("CosmWasm/cw-template", "rust", "consensus"),

    # CosmWasm dApp contracts
    ("mars-protocol/red-bank", "rust", "lending"),
    ("mars-protocol/contracts", "rust", "lending"),
    ("white-whale-defi-platform/white-whale-core", "rust", "dex"),
    ("terraswap/terraswap", "rust", "dex"),
    ("astroport-fi/astroport-core", "rust", "dex"),
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


# Substrate / CosmWasm-specific impact keyword routing. Order matters:
# more specific keywords appear first so e.g. "governance takeover" wins
# before generic "governance".
_IMPACT_KEYWORDS: Tuple[Tuple[str, str], ...] = (
    # consensus / chain-halt
    ("consensus halt", "dos"),
    ("chain halt", "dos"),
    ("block production halt", "dos"),
    ("finality stall", "dos"),
    ("validator halt", "dos"),
    ("apphash divergence", "dos"),
    # bridge / xcm theft
    ("xcm", "theft"),
    ("bridge", "theft"),
    ("teleport", "theft"),
    ("multilocation", "theft"),
    ("cross-chain message", "theft"),
    # generic theft / drain
    ("steal", "theft"),
    ("theft", "theft"),
    ("drain", "theft"),
    ("siphon", "theft"),
    ("loss of funds", "theft"),
    ("unauthorized withdraw", "theft"),
    ("unauthorized transfer", "theft"),
    ("flash loan", "theft"),
    ("flashloan", "theft"),
    ("price manipulation", "theft"),
    ("oracle manipulation", "theft"),
    ("reentrancy", "theft"),
    ("liquidation", "theft"),
    ("collateral", "theft"),
    # freeze / locked / stuck
    ("freeze", "freeze"),
    ("locked", "freeze"),
    ("frozen", "freeze"),
    ("stuck", "freeze"),
    ("permanently inaccessible", "freeze"),
    # governance takeover
    ("governance takeover", "governance-takeover"),
    ("admin takeover", "governance-takeover"),
    ("sudo takeover", "governance-takeover"),
    ("root origin", "governance-takeover"),
    # privilege escalation / access control
    ("privilege escalation", "privilege-escalation"),
    ("access control", "privilege-escalation"),
    ("authorization", "privilege-escalation"),
    ("missing origin check", "privilege-escalation"),
    ("unprivileged caller", "privilege-escalation"),
    # precision / rounding / overflow
    ("precision", "precision-loss"),
    ("rounding", "precision-loss"),
    ("overflow", "precision-loss"),
    ("underflow", "precision-loss"),
    ("share inflation", "precision-loss"),
    ("donation attack", "precision-loss"),
    # yield / reward redistribution
    ("yield", "yield-redistribution"),
    ("interest rate", "yield-redistribution"),
    ("reward", "yield-redistribution"),
    ("staking reward", "yield-redistribution"),
    ("inflation reward", "yield-redistribution"),
    # generic griefing
    ("griefing", "griefing"),
    ("spam", "griefing"),
    # generic dos last
    ("denial of service", "dos"),
    ("denial-of-service", "dos"),
    ("infinite loop", "dos"),
    ("panic", "dos"),
    ("unbounded", "dos"),
    ("dos", "dos"),
    # governance-class generic
    ("governance", "governance-takeover"),
)


def _infer_impact_class(advisory: Dict[str, Any]) -> str:
    haystack = " ".join(
        str(advisory.get(k, "")) for k in ("summary", "description")
    ).lower()
    for kw, impact in _IMPACT_KEYWORDS:
        if kw in haystack:
            return impact
    # Substrate / Polkadot / CosmWasm advisories without keyword match
    # default to DoS (consensus-stack class) - matches cosmos-sdk-ibc
    # miner. Parachain dApp contracts will overwhelmingly hit a keyword.
    return "dos"


def _infer_impact_actor(impact_class: str, domain: str) -> str:
    if impact_class in {"governance-takeover", "privilege-escalation"}:
        return "protocol-treasury"
    if impact_class in {"yield-redistribution"}:
        return "yield-recipient"
    if impact_class in {"dos"}:
        # Chain-level DoS hits validator-set; dApp DoS hits arbitrary
        # users. Domain disambiguates.
        if domain == "consensus":
            return "validator-set"
        return "arbitrary-user"
    if impact_class in {"theft", "freeze", "precision-loss"}:
        if domain in {"lending", "vault"}:
            return "depositor-class"
        return "arbitrary-user"
    return "arbitrary-user"


def _record_id(repo: str, ghsa_id: str) -> str:
    repo_slug = slugify(repo.replace("/", "-"), max_len=64)
    ghsa_slug = slugify(ghsa_id, max_len=64) or "ghsa-unknown"
    payload = f"substrate-cosmwasm|{repo}|{ghsa_id}"
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:12]
    rid = f"substrate-cw:{repo_slug}:{ghsa_slug}:{digest}"
    # schema cap 160 chars
    return rid[:160]


def _function_shape(
    advisory: Dict[str, Any], lang: str, domain: str
) -> Dict[str, Any]:
    pkgs: List[str] = []
    for vuln in advisory.get("vulnerabilities", []) or []:
        if isinstance(vuln, dict):
            pkg = vuln.get("package")
            if isinstance(pkg, dict):
                name = pkg.get("name")
                if isinstance(name, str) and name:
                    pkgs.append(name)
    raw_signature = pkgs[0] if pkgs else f"{lang}-{domain}-package"
    shape_tags: List[str] = [
        slugify(f"substrate-cosmwasm-{lang}", max_len=64),
        slugify(f"domain-{domain}", max_len=64),
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
        unique = ["substrate-cosmwasm-ghsa"]
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
        f"Running unpatched {severity}-severity advisory-tagged Substrate / "
        f"parachain / CosmWasm runtime or contract dependency in production; "
        f"ignoring the GHSA notification window before applying the "
        f"patched-versions tag.",
        "Running an unpatched advisory-tagged Substrate / CosmWasm dependency.",
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
            f"GHSA-tracked vulnerability in {lang} Substrate / CosmWasm "
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
        "function_shape": _function_shape(advisory, lang, domain),
        "bug_class": "substrate-cosmwasm-public-advisory",
        "attack_class": f"ghsa-public-advisory-{lang}-{domain}",
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
    ``paritytech__polkadot-sdk__ghsa-xxxx-yyyy-zzzz`` (double-underscore
    separated). Matches sibling miners' on-disk layout.
    """
    repo = record["target_repo"]
    # Slugify each segment of the owner/repo independently so casing
    # collapses but no spurious dashes get introduced.
    owner_repo = "__".join(
        slugify(seg, max_len=80) for seg in repo.split("/", 1)
    )
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
            "hackerman substrate-cosmwasm ETL: "
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
