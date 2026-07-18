#!/usr/bin/env python3
"""
Wave-1 hackerman corpus miner: Move / Aptos / Sui ecosystem security findings,
REAL SOURCES ONLY.

Hard rules followed (per ~/.claude/CLAUDE.md and the Vyper-CVE quarantine
precedent at `audit/corpus_tags/tags/_QUARANTINE_FABRICATED_CVE/README.md`):

  * Every emitted record cites a resolvable URL that the miner actually
    fetched via `gh api`. No CVE IDs, no GHSA IDs invented from training-data
    memory.
  * If a queried source returns zero results, that is an honest zero; the
    miner emits nothing for that source rather than synthesising rows.
  * The script does NOT mutate `tools/calibration/llm_budget_log.jsonl`.
  * New file only; does not edit sibling miners.

Sources (all live `gh api` reads, all URL-resolvable):

  1. GHSA per-repo databases for the canonical Aptos/Sui/Move repos via
     ``gh api repos/<owner>/<repo>/security-advisories?state=published``.
     Empirically the per-repo GHSA list is sparse for these orgs (most
     advisories are coordinated off-GitHub), but we query for completeness
     and record any real returns.
  2. Global GHSA database filtered by ``affects=<package>&ecosystem=<eco>``
     for known Move / Aptos / Sui crates and npm packages. Returns
     occasional matches (e.g. mysten-metrics malicious-code advisory).
  3. MoveBit `Sampled-Audit-Reports` repo - 29 real Move / Aptos / Sui audit
     report PDFs. Each PDF -> one tier-2 (verified-public-archive) record
     pointing at the live GitHub blob URL.
  4. Sui (`MystenLabs/sui`) and Aptos-core (`aptos-labs/aptos-core`)
     GitHub releases whose body explicitly cites a CVE-XXXX-XXXXX or
     GHSA-XXXX-XXXX-XXXX identifier (a verbatim regex match, not a
     keyword smell). Each matched release -> one tier-2 record pointing
     at the release URL plus the cited advisory ID.

Verification tiers per emitted record:

  * tier-1 (verified-realtime-api) - sourced from a live ``gh api`` GHSA
    advisory object.
  * tier-2 (verified-public-archive) - sourced from a live ``gh api``
    contents/release listing on a public GitHub repo we can resolve.

CLI:

    # Live pull from gh api (default):
    python3 tools/hackerman-etl-from-move-aptos-sui.py \\
        --out-dir audit/corpus_tags/tags/move_aptos_sui

    # Dry-run (no files written) + JSON summary to stdout:
    python3 tools/hackerman-etl-from-move-aptos-sui.py \\
        --out-dir /tmp/etl-mas-out --dry-run --json-summary

    # Offline / from cached payload (deterministic for tests):
    python3 tools/hackerman-etl-from-move-aptos-sui.py \\
        --out-dir audit/corpus_tags/tags/move_aptos_sui \\
        --cache-file /tmp/mas-cache.json

Cross-link policy: this docstring uses relative paths only
(`audit/...`, `tools/...`) per CLAUDE.md rule 3.
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


REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_VERSION = "auditooor.hackerman_record.v1"
DEFAULT_OUT_DIR = REPO_ROOT / "audit" / "corpus_tags" / "tags" / "move_aptos_sui"


# ---------------------------------------------------------------------------
# Validator load (mirrors sibling ETL pattern).
# ---------------------------------------------------------------------------


def _load_validator() -> Any:
    spec = importlib.util.spec_from_file_location(
        "_hackerman_record_validate_for_mas",
        str(REPO_ROOT / "tools" / "hackerman-record-validate.py"),
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


_VALIDATOR = _load_validator()


# ---------------------------------------------------------------------------
# Source catalogues.
# ---------------------------------------------------------------------------


# Repos queried via ``gh api repos/<owner>/<repo>/security-advisories``.
# Empirically all return 0 today (coordinated disclosure is off-GitHub for
# these orgs) but we keep the query so the loop picks up any future
# advisories the maintainers publish on GitHub.
PER_REPO_GHSA: Tuple[Tuple[str, str, str], ...] = (
    # repo, target_language, target_domain
    ("aptos-labs/aptos-core", "rust", "l1-client"),
    ("MystenLabs/sui", "rust", "l1-client"),
    ("move-language/move", "rust", "l1-client"),
    ("aptos-labs/aptos-ts-sdk", "typescript-onchain", "rpc-infra"),
    ("MystenLabs/walrus", "rust", "rpc-infra"),
    ("aptos-labs/aptos-go-sdk", "go", "rpc-infra"),
    ("MystenLabs/sui-rust-sdk", "rust", "rpc-infra"),
    ("MystenLabs/mysten-infra", "rust", "rpc-infra"),
)


# Packages queried via the global ``gh api /advisories?affects=&ecosystem=``
# endpoint. (eco, package, target_language, target_domain).
GLOBAL_PKG_GHSA: Tuple[Tuple[str, str, str, str], ...] = (
    # Rust crates from Mysten and Aptos
    ("rust", "mysten-metrics", "rust", "rpc-infra"),
    ("rust", "move-binary-format", "rust", "l1-client"),
    ("rust", "move-bytecode-verifier", "rust", "l1-client"),
    ("rust", "move-core-types", "rust", "l1-client"),
    ("rust", "move-vm-runtime", "rust", "l1-client"),
    ("rust", "aptos-framework", "rust", "l1-client"),
    ("rust", "aptos-types", "rust", "l1-client"),
    ("rust", "sui-framework", "rust", "l1-client"),
    ("rust", "sui-types", "rust", "l1-client"),
    ("rust", "sui-sdk", "rust", "rpc-infra"),
    # npm packages
    ("npm", "@mysten/sui", "typescript-onchain", "rpc-infra"),
    ("npm", "@mysten/sui.js", "typescript-onchain", "rpc-infra"),
    ("npm", "@aptos-labs/ts-sdk", "typescript-onchain", "rpc-infra"),
    ("npm", "@aptos-labs/aptos-cli", "typescript-onchain", "rpc-infra"),
    ("npm", "@mysten/walrus", "typescript-onchain", "rpc-infra"),
    ("npm", "aptos", "typescript-onchain", "rpc-infra"),
    # pip
    ("pip", "aptos-sdk", "python-onchain", "rpc-infra"),
)


# MoveBit public sampled-audit-reports repo path. Each PDF maps to one
# tier-2 record. We auto-detect the target chain by filename slug.
MOVEBIT_REPO = "movebit/Sampled-Audit-Reports"
MOVEBIT_REPORTS_DIR = "reports"


# Additional public-archive audit-report repos. Each tuple is (repo, subdir,
# publisher_slug). We list the contents and emit one record per Move/Aptos/
# Sui-named PDF. We keep the publisher slug explicit so downstream consumers
# can distinguish report provenance.
EXTRA_PDF_SOURCES: Tuple[Tuple[str, str, str], ...] = (
    # Trail of Bits publishes its public reports here.
    ("trailofbits/publications", "reviews", "trailofbits"),
    ("trailofbits/publications", "reports", "trailofbits"),
    # Zellic publishes its public reports at the top level of this repo.
    ("Zellic/publications", "", "zellic"),
)


# Filename keyword filter for "is this a Move/Aptos/Sui-relevant PDF?".
MAS_NAME_KEYWORDS: Tuple[str, ...] = (
    "aptos", "move", "sui", "mysten", "starcoin", "walrus",
)


# Releases that get parsed for CVE/GHSA identifiers in the body.
RELEASE_REPOS: Tuple[Tuple[str, str, str], ...] = (
    ("MystenLabs/sui", "rust", "l1-client"),
    ("aptos-labs/aptos-core", "rust", "l1-client"),
)


# CVE / GHSA regex (verbatim public identifiers only).
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
GHSA_RE = re.compile(r"GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}", re.IGNORECASE)


# ---------------------------------------------------------------------------
# Helpers (yaml/json scalar utilities mirror sibling ETL for byte-stable
# output rendering, though we emit JSON-pretty for the per-slug record.json
# layout requested by the brief).
# ---------------------------------------------------------------------------


def slugify(value: object, *, max_len: int = 80) -> str:
    text = str(value or "").strip().lower()
    text = re.sub(r"[^a-z0-9._:/-]+", "-", text).strip("-._")
    text = re.sub(r"-{2,}", "-", text)
    return (text[:max_len].strip("-._") or "record")


def one_line(text: object, fallback: str, *, max_len: int = 1000) -> str:
    cleaned = re.sub(r"\s+", " ", str(text or "")).strip()
    return (cleaned[:max_len].strip() if cleaned else fallback)


def short_digest(payload: str) -> str:
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:12]


# ---------------------------------------------------------------------------
# gh api fetch + cache layer.
# ---------------------------------------------------------------------------


def _gh_api(path: str, *, timeout: int = 60) -> Any:
    """Run ``gh api <path>`` and return parsed JSON or ``None`` on any error."""
    try:
        proc = subprocess.run(
            ["gh", "api", path],
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError:
        return None


def fetch_per_repo_ghsa(repo: str) -> List[Dict[str, Any]]:
    data = _gh_api(f"repos/{repo}/security-advisories?per_page=100&state=published")
    if isinstance(data, list):
        return [a for a in data if isinstance(a, dict)]
    return []


def fetch_global_pkg_ghsa(eco: str, pkg: str) -> List[Dict[str, Any]]:
    # GitHub URL-encodes the affects param; pass raw and let gh handle escaping.
    data = _gh_api(f"/advisories?per_page=100&affects={pkg}&ecosystem={eco}")
    if isinstance(data, list):
        return [a for a in data if isinstance(a, dict)]
    return []


def fetch_movebit_pdf_list() -> List[Dict[str, Any]]:
    data = _gh_api(f"repos/{MOVEBIT_REPO}/contents/{MOVEBIT_REPORTS_DIR}")
    if not isinstance(data, list):
        return []
    out: List[Dict[str, Any]] = []
    for entry in data:
        if not isinstance(entry, dict):
            continue
        if entry.get("type") != "file":
            continue
        name = entry.get("name") or ""
        if not isinstance(name, str) or not name.lower().endswith(".pdf"):
            continue
        out.append(entry)
    return out


def fetch_extra_pdf_list(repo: str, subdir: str, publisher: str) -> List[Dict[str, Any]]:
    """List PDFs from a public-archive audit-report repo subdir.

    Filters to Move/Aptos/Sui-relevant filenames via :data:`MAS_NAME_KEYWORDS`.
    Returns an empty list on any error.
    """
    path = f"repos/{repo}/contents/{subdir}" if subdir else f"repos/{repo}/contents/"
    data = _gh_api(path)
    if not isinstance(data, list):
        return []
    out: List[Dict[str, Any]] = []
    for entry in data:
        if not isinstance(entry, dict):
            continue
        if entry.get("type") != "file":
            continue
        name = entry.get("name") or ""
        if not isinstance(name, str) or not name.lower().endswith(".pdf"):
            continue
        lname = name.lower()
        if not any(kw in lname for kw in MAS_NAME_KEYWORDS):
            continue
        # Tag publisher so the record-builder can credit the source.
        merged = dict(entry)
        merged["_publisher"] = publisher
        merged["_repo"] = repo
        out.append(merged)
    return out


def fetch_release_list(repo: str) -> List[Dict[str, Any]]:
    data = _gh_api(f"repos/{repo}/releases?per_page=100")
    if isinstance(data, list):
        return [r for r in data if isinstance(r, dict)]
    return []


def fetch_all(
    *,
    cache_file: Optional[Path] = None,
    write_cache_file: Optional[Path] = None,
) -> Dict[str, Any]:
    """Return a payload dict with all source results. Cache replay supported."""
    if cache_file is not None:
        return json.loads(cache_file.read_text(encoding="utf-8"))

    payload: Dict[str, Any] = {
        "per_repo_ghsa": {},
        "global_pkg_ghsa": {},
        "movebit_pdfs": [],
        "extra_pdfs": [],
        "releases": {},
    }
    for repo, _lang, _domain in PER_REPO_GHSA:
        payload["per_repo_ghsa"][repo] = fetch_per_repo_ghsa(repo)
    for eco, pkg, _lang, _domain in GLOBAL_PKG_GHSA:
        key = f"{eco}::{pkg}"
        payload["global_pkg_ghsa"][key] = fetch_global_pkg_ghsa(eco, pkg)
    payload["movebit_pdfs"] = fetch_movebit_pdf_list()
    for repo, subdir, publisher in EXTRA_PDF_SOURCES:
        payload["extra_pdfs"].extend(fetch_extra_pdf_list(repo, subdir, publisher))
    for repo, _lang, _domain in RELEASE_REPOS:
        payload["releases"][repo] = fetch_release_list(repo)

    if write_cache_file is not None:
        write_cache_file.parent.mkdir(parents=True, exist_ok=True)
        write_cache_file.write_text(
            json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8"
        )
    return payload


# ---------------------------------------------------------------------------
# Severity / impact / language helpers.
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


def normalize_severity(value: Optional[str]) -> str:
    return _SEVERITY_MAP.get(str(value or "").strip().lower(), "info")


def dollar_class(severity: str) -> str:
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


def year_from_iso(value: Optional[str], *, fallback: int = 2024) -> int:
    if isinstance(value, str) and len(value) >= 4 and value[:4].isdigit():
        year = int(value[:4])
        if year >= 2000:
            return year
    return fallback


# Filename-to-target-chain heuristics. The MoveBit report set is consistent
# enough that filename slug -> chain is reliable. We bias to ``move`` (the
# language) on the schema, and capture the chain in the bug_class string.
def detect_chain_from_name(name: str) -> Tuple[str, str]:
    """Return (chain_label, target_language). Default chain=move, lang=move."""
    lname = name.lower()
    if "aptos" in lname or "aries" in lname or "thala" in lname or "mole" in lname:
        return "aptos", "move"
    if "sui" in lname or "scallop" in lname or "kriya" in lname or "navi" in lname or "bucket" in lname or "typus" in lname or "cetus-concentrated-liquidity-protocol-sui" in lname:
        return "sui", "move"
    if "starcoin" in lname or "stc" in lname:
        return "starcoin", "move"
    return "move", "move"


# Filename-to-target-domain heuristics for the MoveBit set.
def detect_domain_from_name(name: str) -> str:
    lname = name.lower()
    pairs = (
        ("amm", "dex"),
        ("swap", "dex"),
        ("dex", "dex"),
        ("liquidity", "dex"),
        ("dexus", "dex"),
        ("mole", "lending"),
        ("aries", "lending"),
        ("navi", "lending"),
        ("scallop", "lending"),
        ("bucket", "lending"),
        ("kriya", "dex"),
        ("typus", "vault"),
        ("vault", "vault"),
        ("nft", "nft"),
        ("kiosk", "nft"),
        ("bridge", "bridge"),
        ("poly", "bridge"),
        ("dao", "dao"),
        ("did", "governance"),
        ("launchpad", "dao"),
        ("pad", "dao"),
        ("game", "gaming"),
        ("arcadia", "gaming"),
        ("miner", "gaming"),
        ("turbo", "gaming"),
        ("legend", "gaming"),
        ("mugen", "gaming"),
        ("oracle", "oracle"),
        ("stak", "staking"),
        ("ido", "dao"),
        ("framework", "l1-client"),
        ("transit", "bridge"),
    )
    for needle, dom in pairs:
        if needle in lname:
            return dom
    return "dex"  # conservative DeFi-domain default


# ---------------------------------------------------------------------------
# Record builders.
# ---------------------------------------------------------------------------


def _impact_class_from_text(text: str) -> str:
    haystack = (text or "").lower()
    pairs = (
        ("denial of service", "dos"),
        ("denial-of-service", "dos"),
        (" dos ", "dos"),
        ("crash", "dos"),
        ("panic", "dos"),
        ("freeze", "freeze"),
        ("lock", "freeze"),
        ("steal", "theft"),
        ("theft", "theft"),
        ("drain", "theft"),
        ("malicious code", "theft"),
        ("backdoor", "theft"),
        ("griefing", "griefing"),
        ("precision", "precision-loss"),
        ("rounding", "precision-loss"),
        ("governance", "governance-takeover"),
        ("privilege escalation", "privilege-escalation"),
        ("unauthorized", "privilege-escalation"),
        ("admin", "privilege-escalation"),
        ("yield", "yield-redistribution"),
        ("reward", "yield-redistribution"),
    )
    for kw, impact in pairs:
        if kw in haystack:
            return impact
    return "dos"


def _impact_actor(impact_class: str) -> str:
    if impact_class in {"governance-takeover", "privilege-escalation"}:
        return "validator-set"
    if impact_class == "yield-redistribution":
        return "yield-recipient"
    return "arbitrary-user"


# ----- GHSA-derived record ---------------------------------------------------


def _ghsa_record(
    advisory: Dict[str, Any],
    *,
    target_repo: str,
    target_language: str,
    target_domain: str,
    source_channel: str,  # "per-repo" or "global-pkg"
    affects_pkg: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    ghsa_id = advisory.get("ghsa_id")
    if not isinstance(ghsa_id, str) or not GHSA_RE.match(ghsa_id):
        return None  # Drop if no real GHSA identifier - never invent.

    severity = normalize_severity(advisory.get("severity"))
    summary = advisory.get("summary") or ""
    description = advisory.get("description") or ""
    url = (
        advisory.get("html_url")
        or advisory.get("url")
        or f"https://github.com/advisories/{ghsa_id}"
    )
    year = year_from_iso(
        advisory.get("published_at")
        or advisory.get("github_reviewed_at")
        or advisory.get("nvd_published_at")
    )

    cve_id = advisory.get("cve_id")
    cve_id = cve_id if isinstance(cve_id, str) and CVE_RE.match(cve_id) else None

    # Build function_shape from package list.
    pkgs: List[str] = []
    for vuln in advisory.get("vulnerabilities", []) or []:
        if isinstance(vuln, dict):
            pkg = vuln.get("package")
            if isinstance(pkg, dict):
                name = pkg.get("name")
                if isinstance(name, str) and name:
                    pkgs.append(name)
    raw_sig = pkgs[0] if pkgs else (affects_pkg or "ghsa-package")
    shape_tags = [
        slugify(f"ghsa-{target_language}", max_len=64),
        slugify(ghsa_id, max_len=64),
        slugify(f"channel-{source_channel}", max_len=64),
    ]
    for pkg in pkgs[:3]:
        tag = slugify(f"pkg-{pkg}", max_len=64)
        if tag:
            shape_tags.append(tag)
    if cve_id:
        shape_tags.append(slugify(cve_id, max_len=64))
    cwes = advisory.get("cwes") or []
    for cwe in cwes:
        if isinstance(cwe, dict):
            cwe_id = cwe.get("cwe_id")
            if isinstance(cwe_id, str) and cwe_id:
                shape_tags.append(slugify(cwe_id, max_len=64))
    seen: set = set()
    unique_tags: List[str] = []
    for t in shape_tags:
        if t and t not in seen:
            seen.add(t)
            unique_tags.append(t)
    if not unique_tags:
        unique_tags = ["ghsa-public"]

    # required_preconditions: at least one URL + advisory ID.
    preconds: List[str] = [
        one_line(f"Reference advisory at {url}", "Reference advisory", max_len=900),
        one_line(f"GHSA identifier {ghsa_id}", "GHSA identifier", max_len=900),
        one_line(f"Affects package {affects_pkg or (pkgs[0] if pkgs else target_repo)}", "Affects package", max_len=900),
    ]
    if cve_id:
        preconds.append(one_line(f"CVE identifier {cve_id}", "CVE identifier", max_len=900))

    impact = _impact_class_from_text(f"{summary} {description}")

    # fix_pattern from patched_versions.
    patched: List[str] = []
    for vuln in advisory.get("vulnerabilities", []) or []:
        if isinstance(vuln, dict):
            pv = vuln.get("patched_versions")
            if isinstance(pv, str) and pv.strip():
                patched.append(pv.strip())
    fix = (
        f"Upgrade affected package to patched-versions {'; '.join(patched)} per GHSA {ghsa_id}."
        if patched
        else f"Apply the upstream maintainer remediation listed under GHSA {ghsa_id}."
    )

    aas_body = f"{summary}. {description}".strip()
    if aas_body == ".":
        aas_body = f"GHSA-tracked vulnerability affecting {target_repo} stack."
    marker = f" [source=github-security-advisory; channel={source_channel}; verification_tier=tier-1-verified-realtime-api]"
    aas = one_line(aas_body, "GHSA action sequence", max_len=4900 - len(marker)) + marker

    record: Dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "record_id": f"ghsa:move-aptos-sui:{slugify(ghsa_id, max_len=64)}:{short_digest(f'ghsa|{target_repo}|{ghsa_id}|{source_channel}')}",
        "source_audit_ref": one_line(url, f"ghsa:{ghsa_id}", max_len=240),
        "target_domain": target_domain,
        "target_language": target_language,
        "target_repo": target_repo if "/" in target_repo else "unknown",
        "target_component": one_line(
            f"{target_repo}:{ghsa_id}", f"{target_repo}:advisory", max_len=240
        ),
        "function_shape": {
            "raw_signature": raw_sig[:500],
            "shape_tags": unique_tags,
        },
        "bug_class": "move-aptos-sui-ghsa-advisory",
        "attack_class": f"ghsa-public-advisory-{target_language}",
        "attacker_role": "unprivileged",
        "attacker_action_sequence": aas,
        "required_preconditions": preconds,
        "impact_class": impact,
        "impact_actor": _impact_actor(impact),
        "impact_dollar_class": dollar_class(severity),
        "fix_pattern": one_line(fix, "Apply upstream patch.", max_len=900),
        "fix_anti_pattern_avoided": one_line(
            f"Running an unpatched {severity}-severity {target_language} dependency known to be tracked by GHSA {ghsa_id}.",
            "Running an unpatched advisory-tagged dependency.",
            max_len=900,
        ),
        "severity_at_finding": severity,
        "year": year,
        "record_tier": "public-corpus",
        "record_quality_score": 4.5,
        "source_extraction_method": "corpus-etl",
        "source_extraction_confidence": 0.9,
        "cross_language_analogues": [],
        "related_records": [],
    }
    return record


# ----- MoveBit-PDF-derived record -------------------------------------------


def _pdf_record(
    entry: Dict[str, Any],
    *,
    publisher: str,
    publisher_repo: str,
) -> Optional[Dict[str, Any]]:
    """Build one tier-2 record per public-archive audit-report PDF.

    Works for any GitHub contents-listing payload that exposes a PDF file
    with ``html_url`` / ``download_url``. We default severity to ``medium``
    (honest "unknown-non-fabricated" anchor) because we do not parse the
    PDF body; per-finding severities are out-of-scope for this miner and
    must be sourced from a follow-on per-finding extraction lane (e.g.
    `tools/hackerman-etl-from-aptos-move.py` already mines the Zellic text
    corpus, so this miner's aggregate record is a non-overlapping pointer
    to the source PDF rather than a per-finding duplicate).
    """
    name = entry.get("name") or ""
    html_url = entry.get("html_url")
    download_url = entry.get("download_url")
    if not isinstance(name, str) or not name.lower().endswith(".pdf"):
        return None
    url = html_url or download_url
    if not isinstance(url, str) or not url:
        return None

    chain, lang = detect_chain_from_name(name)
    domain = detect_domain_from_name(name)
    base = name[:-4]
    severity = "medium"

    publisher_slug = slugify(publisher, max_len=32)
    record_id = (
        f"{publisher_slug}:{slugify(chain, max_len=24)}:{slugify(base, max_len=80)}:"
        f"{short_digest(f'{publisher_slug}|{name}|{url}')}"
    )

    preconds = [
        one_line(f"Reference audit report at {url}", "Reference audit report", max_len=900),
        one_line(f"Source publisher {publisher}", "Source publisher", max_len=900),
        one_line(f"Target chain {chain}", "Target chain", max_len=900),
        one_line(f"Public archive at github.com/{publisher_repo}", "Public archive", max_len=900),
    ]

    aas = one_line(
        f"Public {publisher} audit report for {base.replace('-', ' ')} ({chain}). The PDF enumerates ranked findings against the {chain} Move module set; consult the report URL for per-finding attacker action sequences.",
        f"{publisher} public audit report action sequence",
        max_len=4500,
    ) + f" [source={publisher_slug}-public-audit-archive; verification_tier=tier-2-verified-public-archive]"

    record: Dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "record_id": record_id,
        "source_audit_ref": one_line(url, f"{publisher_slug}:{base}", max_len=240),
        "target_domain": domain,
        "target_language": lang,
        "target_repo": "unknown",
        "target_component": one_line(
            f"{chain}:{base}", f"{chain}:{publisher_slug}-report", max_len=240
        ),
        "function_shape": {
            "raw_signature": f"{chain}-move-module-set",
            "shape_tags": [
                slugify(f"chain-{chain}", max_len=64),
                slugify(f"publisher-{publisher_slug}", max_len=64),
                slugify(f"report-{base}", max_len=64),
            ],
        },
        "bug_class": "move-aptos-sui-audit-report-aggregate",
        "attack_class": f"public-audit-report-{chain}",
        "attacker_role": "unprivileged",
        "attacker_action_sequence": aas,
        "required_preconditions": preconds,
        "impact_class": "dos",
        "impact_actor": "arbitrary-user",
        "impact_dollar_class": dollar_class(severity),
        "fix_pattern": one_line(
            f"Apply the per-finding remediations enumerated in the {publisher} report at {url}.",
            f"Apply per-finding remediations from {publisher} report.",
            max_len=900,
        ),
        "fix_anti_pattern_avoided": one_line(
            f"Deploying the {chain} Move package without auditing against the {publisher}-enumerated findings for the project family.",
            "Deploying without checking the public audit report.",
            max_len=900,
        ),
        "severity_at_finding": severity,
        "year": 2024,
        "record_tier": "public-corpus",
        "record_quality_score": 3.5,
        "source_extraction_method": "corpus-etl",
        "source_extraction_confidence": 0.7,
        "cross_language_analogues": [],
        "related_records": [],
    }
    return record


# ----- Release-with-cited-advisory record -----------------------------------


def _release_record(
    release: Dict[str, Any],
    *,
    target_repo: str,
    target_language: str,
    target_domain: str,
) -> Optional[Dict[str, Any]]:
    body = release.get("body") or ""
    if not isinstance(body, str) or not body.strip():
        return None
    cves = sorted({m.group(0).upper() for m in CVE_RE.finditer(body)})
    ghsas = sorted({m.group(0).upper() for m in GHSA_RE.finditer(body)})
    if not (cves or ghsas):
        return None  # Only emit when an EXPLICIT CVE/GHSA id is cited.

    tag = release.get("tag_name") or release.get("name") or "release"
    url = release.get("html_url") or release.get("url") or f"https://github.com/{target_repo}/releases"
    if not isinstance(url, str):
        return None
    year = year_from_iso(release.get("published_at") or release.get("created_at"))

    preconds = [
        one_line(f"Reference release notes at {url}", "Reference release notes", max_len=900),
        one_line(f"Release tag {tag}", "Release tag", max_len=900),
        one_line(f"Affected repo {target_repo}", "Affected repo", max_len=900),
    ]
    cited_ids: List[str] = []
    for cve in cves:
        preconds.append(one_line(f"Cites CVE {cve}", "Cites CVE", max_len=900))
        cited_ids.append(cve)
    for ghsa in ghsas:
        preconds.append(one_line(f"Cites GHSA {ghsa}", "Cites GHSA", max_len=900))
        cited_ids.append(ghsa)

    impact = _impact_class_from_text(body)
    severity = "high"  # release-cited CVE/GHSA is high by default; downgrade only on explicit signal.
    if "low" in body.lower() and "severity" in body.lower():
        severity = "low"
    elif "medium" in body.lower() and "severity" in body.lower():
        severity = "medium"
    elif "critical" in body.lower() and "severity" in body.lower():
        severity = "critical"

    shape_tags = [
        slugify(f"release-{target_language}", max_len=64),
        slugify(f"repo-{target_repo}", max_len=64),
        slugify(f"tag-{tag}", max_len=64),
    ]
    for cid in cited_ids[:6]:
        shape_tags.append(slugify(cid, max_len=64))

    excerpt = re.sub(r"\s+", " ", body)[:1200]
    marker = " [source=github-release-notes; verification_tier=tier-2-verified-public-archive]"
    aas = one_line(
        f"Release {tag} of {target_repo} cites advisory id(s) {', '.join(cited_ids)}; release notes excerpt: {excerpt}",
        "Release-cited advisory action sequence",
        max_len=4900 - len(marker),
    ) + marker

    record: Dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "record_id": (
            f"release:{slugify(target_repo.replace('/', '-'), max_len=48)}:"
            f"{slugify(tag, max_len=48)}:{short_digest(f'release|{target_repo}|{tag}')}"
        ),
        "source_audit_ref": one_line(url, f"release:{target_repo}:{tag}", max_len=240),
        "target_domain": target_domain,
        "target_language": target_language,
        "target_repo": target_repo,
        "target_component": one_line(
            f"{target_repo}:{tag}", f"{target_repo}:release", max_len=240
        ),
        "function_shape": {
            "raw_signature": f"{target_repo}-{tag}",
            "shape_tags": shape_tags,
        },
        "bug_class": "move-aptos-sui-release-cited-advisory",
        "attack_class": f"release-notes-cited-advisory-{target_language}",
        "attacker_role": "unprivileged",
        "attacker_action_sequence": aas,
        "required_preconditions": preconds,
        "impact_class": impact,
        "impact_actor": _impact_actor(impact),
        "impact_dollar_class": dollar_class(severity),
        "fix_pattern": one_line(
            f"Upgrade {target_repo} to release {tag} or later; cross-reference the cited advisory id(s) {', '.join(cited_ids)} for per-id remediation guidance.",
            "Upgrade to the patched release.",
            max_len=900,
        ),
        "fix_anti_pattern_avoided": one_line(
            f"Running a {target_repo} release earlier than {tag} on production validators after the release explicitly cited advisory id(s) {', '.join(cited_ids)}.",
            "Running an outdated release after a CVE/GHSA citation.",
            max_len=900,
        ),
        "severity_at_finding": severity,
        "year": year,
        "record_tier": "public-corpus",
        "record_quality_score": 4.0,
        "source_extraction_method": "corpus-etl",
        "source_extraction_confidence": 0.85,
        "cross_language_analogues": [],
        "related_records": [],
    }
    return record


# ---------------------------------------------------------------------------
# Pipeline.
# ---------------------------------------------------------------------------


def build_records(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    records: List[Dict[str, Any]] = []
    seen_ids: set = set()

    # 1. per-repo GHSA
    for repo, lang, domain in PER_REPO_GHSA:
        for adv in payload.get("per_repo_ghsa", {}).get(repo, []) or []:
            r = _ghsa_record(
                adv,
                target_repo=repo,
                target_language=lang,
                target_domain=domain,
                source_channel="per-repo",
            )
            if r and r["record_id"] not in seen_ids:
                seen_ids.add(r["record_id"])
                records.append(r)

    # 2. global-pkg GHSA
    for eco, pkg, lang, domain in GLOBAL_PKG_GHSA:
        key = f"{eco}::{pkg}"
        for adv in payload.get("global_pkg_ghsa", {}).get(key, []) or []:
            # Use first vulnerability package's repo if available; else
            # ``unknown``. Most affects-lookups still surface a meaningful
            # source_code_location.
            src_loc = adv.get("source_code_location") or ""
            target_repo = "unknown"
            if isinstance(src_loc, str) and "github.com/" in src_loc:
                m = re.search(r"github\.com/([A-Za-z0-9._-]+/[A-Za-z0-9._-]+)", src_loc)
                if m:
                    target_repo = m.group(1)
            r = _ghsa_record(
                adv,
                target_repo=target_repo,
                target_language=lang,
                target_domain=domain,
                source_channel=f"global-pkg-{eco}",
                affects_pkg=pkg,
            )
            if r and r["record_id"] not in seen_ids:
                seen_ids.add(r["record_id"])
                records.append(r)

    # 3. MoveBit PDF list (tier-2)
    for entry in payload.get("movebit_pdfs", []) or []:
        r = _pdf_record(entry, publisher="MoveBit", publisher_repo=MOVEBIT_REPO)
        if r and r["record_id"] not in seen_ids:
            seen_ids.add(r["record_id"])
            records.append(r)

    # 3b. Other public-archive audit-report PDFs (Trail of Bits, Zellic).
    for entry in payload.get("extra_pdfs", []) or []:
        pub = entry.get("_publisher") or "public-archive"
        prepo = entry.get("_repo") or "unknown"
        r = _pdf_record(entry, publisher=pub, publisher_repo=prepo)
        if r and r["record_id"] not in seen_ids:
            seen_ids.add(r["record_id"])
            records.append(r)

    # 4. Releases with cited CVE/GHSA
    for repo, lang, domain in RELEASE_REPOS:
        for rel in payload.get("releases", {}).get(repo, []) or []:
            r = _release_record(
                rel,
                target_repo=repo,
                target_language=lang,
                target_domain=domain,
            )
            if r and r["record_id"] not in seen_ids:
                seen_ids.add(r["record_id"])
                records.append(r)

    return records


def write_record(out_dir: Path, record: Dict[str, Any]) -> Path:
    rid = str(record["record_id"])
    # Per the brief: audit/corpus_tags/tags/move_aptos_sui/<slug>/record.json
    slug = slugify(rid, max_len=110)
    sub = out_dir / slug
    sub.mkdir(parents=True, exist_ok=True)
    path = sub / "record.json"
    path.write_text(
        json.dumps(record, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return path


def convert(
    out_dir: Path,
    *,
    dry_run: bool = False,
    limit: Optional[int] = None,
    cache_file: Optional[Path] = None,
    write_cache_file: Optional[Path] = None,
) -> Dict[str, Any]:
    payload = fetch_all(cache_file=cache_file, write_cache_file=write_cache_file)
    records = build_records(payload)
    if limit is not None:
        records = records[:limit]

    schema = _VALIDATOR.load_schema()
    errors: List[str] = []
    files: List[str] = []
    by_source: Dict[str, int] = {}
    by_severity: Dict[str, int] = {}
    by_chain: Dict[str, int] = {}
    by_tier: Dict[str, int] = {}
    sample_source_urls: List[str] = []

    if not dry_run:
        out_dir.mkdir(parents=True, exist_ok=True)

    for record in records:
        # Validate in-memory before writing - never write an invalid record.
        errs = _VALIDATOR.validate_doc(record, schema)
        if errs:
            errors.extend(f"{record['record_id']}: {err}" for err in errs)
            continue

        # Source/channel + tier accounting from the marker tag in
        # attacker_action_sequence.
        aas = record["attacker_action_sequence"]
        m = re.search(r"\[source=([^;\]]+)", aas)
        source = m.group(1) if m else "unknown"
        by_source[source] = by_source.get(source, 0) + 1
        m2 = re.search(r"verification_tier=([^;\]\s]+)", aas)
        tier = m2.group(1) if m2 else "unknown"
        by_tier[tier] = by_tier.get(tier, 0) + 1

        # Chain accounting from target_component.
        comp = record["target_component"]
        chain = comp.split(":", 1)[0] if ":" in comp else "unknown"
        by_chain[chain] = by_chain.get(chain, 0) + 1

        by_severity[record["severity_at_finding"]] = (
            by_severity.get(record["severity_at_finding"], 0) + 1
        )

        # Sample source urls.
        if len(sample_source_urls) < 6 and record["source_audit_ref"].startswith("http"):
            sample_source_urls.append(record["source_audit_ref"])

        if not dry_run:
            p = write_record(out_dir, record)
            files.append(str(p))

    return {
        "schema_version": SCHEMA_VERSION,
        "out_dir": str(out_dir),
        "dry_run": dry_run,
        "records_attempted": len(records),
        "records_emitted": len(records) - len(errors),
        "errors": errors,
        "by_source": by_source,
        "by_severity": by_severity,
        "by_chain": by_chain,
        "by_verification_tier": by_tier,
        "sample_source_urls": sample_source_urls,
        "file_count": len(files),
        "files": files[:30],
    }


# ---------------------------------------------------------------------------
# CLI.
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--limit", type=int)
    parser.add_argument(
        "--cache-file",
        help="Read all source payloads from a previously-saved JSON cache.",
    )
    parser.add_argument(
        "--write-cache-file",
        help="Save the live gh-api payload here for later offline replay.",
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
        cache_file=Path(args.cache_file).expanduser().resolve() if args.cache_file else None,
        write_cache_file=(
            Path(args.write_cache_file).expanduser().resolve() if args.write_cache_file else None
        ),
    )
    if args.json_summary:
        print(json.dumps(summary, sort_keys=True, indent=2))
    else:
        print(
            "hackerman Move/Aptos/Sui ETL: "
            f"records={summary['records_emitted']}/{summary['records_attempted']} "
            f"by_source={summary['by_source']} "
            f"by_chain={summary['by_chain']} "
            f"by_tier={summary['by_verification_tier']} "
            f"errors={len(summary['errors'])}"
        )
    return 0 if not summary["errors"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
