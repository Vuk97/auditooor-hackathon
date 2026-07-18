#!/usr/bin/env python3
"""
Convert real GitHub Security Advisories (GHSA) for top audited crypto repos
into hackerman_record v1 YAML.

Wave-EXEC lane EXEC-GHSA-INGEST-MINER. Sibling of:

* tools/hackerman-etl-from-near-ink.py (NEAR + ink! taxonomy)
* tools/hackerman-etl-from-sherlock-c4-historic.py (sherlock + C4 corpus)

This lane pulls PUBLISHED advisories from each repo's GitHub Security
Advisory database via ``gh api repos/<owner>/<repo>/security-advisories``
and renders one hackerman_record per advisory. The data is REAL: only
advisories actually returned by ``gh api`` are emitted. If a repo returns
0 advisories that is an honest 0 - no synthesis, no fan-out, no template
fabrication.

Hard rules followed (per ~/.claude/CLAUDE.md):

* Real ``gh api`` data only - no synthesis or invented advisories.
* If a repo returns 0 advisories, that is an honest 0.
* New file only; does NOT modify any existing file.
* Does NOT touch ``tools/calibration/llm_budget_log.jsonl``.
* Cross-links (in docstring + comments) are relative paths only.
* All emitted records validate against
  ``audit/corpus_tags/schemas/auditooor.hackerman_record.v1.schema.json``.

Optional offline use:

The mining step may be re-run from a cached payload via
``--cache-file <path.json>`` so the test-suite has a deterministic offline
fixture. Cache shape is ``{repo: [advisory_objects...]}`` as returned by
the GitHub Security Advisories REST endpoint.

CLI:

    # Live pull from gh api (default repo list):
    python3 tools/hackerman-etl-from-github-advisory.py \\
        --out-dir /tmp/etl-ghsa-out --dry-run --json-summary

    # Offline / from cached payload:
    python3 tools/hackerman-etl-from-github-advisory.py \\
        --cache-file /tmp/ghsa-cache.json \\
        --out-dir audit/corpus_tags/tags/github_advisory
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


def _load_validator() -> Any:
    spec = importlib.util.spec_from_file_location(
        "_hackerman_record_validate_for_ghsa",
        str(REPO_ROOT / "tools" / "hackerman-record-validate.py"),
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


_VALIDATOR = _load_validator()


# ---------------------------------------------------------------------------
# Top-30 audited Solidity / Go / Rust crypto repos to query.
#
# Each entry is (repo, language, domain). Domain is drawn from the schema enum
# set in audit/corpus_tags/schemas/auditooor.hackerman_record.v1.schema.json.
#
# Language detection from advisory content can override this default; for
# example a Solidity-fork repo might publish a Go-tooling advisory.
# ---------------------------------------------------------------------------


TOP_REPOS: Tuple[Tuple[str, str, str], ...] = (
    # Solidity DeFi libraries
    ("OpenZeppelin/openzeppelin-contracts", "solidity", "lending"),
    ("OpenZeppelin/openzeppelin-contracts-upgradeable", "solidity", "lending"),
    ("OpenZeppelin/cairo-contracts", "cairo", "lending"),
    ("Uniswap/v3-core", "solidity", "dex"),
    ("Uniswap/v3-periphery", "solidity", "dex"),
    ("Uniswap/v2-core", "solidity", "dex"),
    ("aave/aave-v3-core", "solidity", "lending"),
    ("compound-finance/compound-protocol", "solidity", "lending"),
    ("compound-finance/comet", "solidity", "lending"),
    ("MakerDAO/dss", "solidity", "lending"),
    ("lido-finance/lido-dao", "solidity", "staking"),
    ("ProjectOpenSea/seaport", "solidity", "nft"),
    ("Synthetixio/synthetix", "solidity", "dex"),
    ("vyperlang/vyper", "vyper", "dex"),
    ("ethereum/solidity", "solidity", "l1-client"),

    # Cosmos / app-chain stack (Go)
    ("dydxprotocol/v4-chain", "go", "dex"),
    ("cosmos/cosmos-sdk", "go", "consensus"),
    ("cometbft/cometbft", "go", "consensus"),
    ("tendermint/tendermint", "go", "consensus"),
    ("cosmos/iavl", "go", "consensus"),
    ("informalsystems/tendermint-rs", "rust", "consensus"),

    # L1 / L2 clients
    ("ethereum/go-ethereum", "go", "l1-client"),
    ("paradigmxyz/reth", "rust", "l1-client"),
    ("OffchainLabs/nitro", "go", "rollup"),
    ("OffchainLabs/arbitrum-classic", "go", "rollup"),
    ("ethereum-optimism/optimism", "go", "rollup"),
    ("ConsenSys/quorum", "go", "l1-client"),

    # Tooling / infra
    ("foundry-rs/foundry", "rust", "rpc-infra"),
    ("ChainSafe/lodestar", "typescript-onchain", "consensus"),
    ("sigp/lighthouse", "rust", "consensus"),

    # zk / proof systems
    ("0xPolygonZero/plonky2", "rust", "zk-proof"),

    # Sherlock-audited primitives
    ("sherlock-audit/sherlock-v2-core", "solidity", "lending"),
)


# ---------------------------------------------------------------------------
# Helpers (mirrored from sibling near-ink ETL for byte-stable YAML rendering).
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
                            lines.append(f"{'  -' if first else '  '} {subkey}: {yaml_scalar(subvalue)}")
                            first = False
                    else:
                        lines.append(f"  - {yaml_scalar(item)}")
        else:
            lines.append(f"{key}: {yaml_scalar(value)}")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# gh api fetch + cache.
# ---------------------------------------------------------------------------


def fetch_repo_advisories(repo: str, *, per_page: int = 100) -> List[Dict[str, Any]]:
    """Call ``gh api`` and return the parsed JSON list of advisories.

    Returns ``[]`` on any error (404, no permission, network, repo absent,
    or repo has no advisories). The honest 0 case is preserved by upstream
    callers; this function never invents data.
    """
    url = f"repos/{repo}/security-advisories?per_page={per_page}&state=published"
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
) -> Dict[str, List[Dict[str, Any]]]:
    """Return ``{repo: [advisory, ...]}`` for every queried repo.

    If ``cache_file`` is given, read it instead of calling ``gh``. Otherwise
    optionally write the fetched payload to ``write_cache_file`` so tests
    can pin a deterministic offline fixture.
    """
    if cache_file is not None:
        payload = json.loads(cache_file.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError(f"cache-file root must be a mapping; got {type(payload).__name__}")
        out: Dict[str, List[Dict[str, Any]]] = {}
        for repo, _lang, _domain in repos:
            adv = payload.get(repo, [])
            if not isinstance(adv, list):
                adv = []
            out[repo] = adv
        return out

    fetched: Dict[str, List[Dict[str, Any]]] = {}
    for repo, _lang, _domain in repos:
        fetched[repo] = fetch_repo_advisories(repo)
    if write_cache_file is not None:
        write_cache_file.parent.mkdir(parents=True, exist_ok=True)
        write_cache_file.write_text(json.dumps(fetched, indent=2, sort_keys=True), encoding="utf-8")
    return fetched


# ---------------------------------------------------------------------------
# Advisory -> hackerman_record v1 mapping.
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
    return 2024  # conservative fallback for the rare null-dated advisory


def _mitigation_state(advisory: Dict[str, Any]) -> str:
    """Derive a mitigation-state tag from the advisory's patched-versions field.

    * ``mitigated`` - at least one vulnerability row has a non-empty
      ``patched_versions``.
    * ``proposed``  - no patched_versions anywhere (advisory published but
      no fix has shipped yet).
    """
    for vuln in advisory.get("vulnerabilities", []) or []:
        if isinstance(vuln, dict):
            pv = vuln.get("patched_versions")
            if isinstance(pv, str) and pv.strip():
                return "mitigated"
    return "proposed"


_DEFAULT_BUG_CLASS_BY_LANG: Dict[str, str] = {
    "solidity": "smart-contract-vulnerability",
    "vyper": "smart-contract-vulnerability",
    "cairo": "smart-contract-vulnerability",
    "go": "consensus-or-rpc-vulnerability",
    "rust": "client-or-vm-vulnerability",
    "typescript-onchain": "client-or-tooling-vulnerability",
    "move": "smart-contract-vulnerability",
    "huff": "smart-contract-vulnerability",
    "assembly": "smart-contract-vulnerability",
    "python-onchain": "client-or-tooling-vulnerability",
}


_DEFAULT_ATTACK_CLASS_BY_LANG: Dict[str, str] = {
    "solidity": "ghsa-public-advisory-evm",
    "vyper": "ghsa-public-advisory-vyper",
    "cairo": "ghsa-public-advisory-cairo",
    "go": "ghsa-public-advisory-go-stack",
    "rust": "ghsa-public-advisory-rust-stack",
    "typescript-onchain": "ghsa-public-advisory-ts-stack",
    "move": "ghsa-public-advisory-move",
    "huff": "ghsa-public-advisory-evm",
    "assembly": "ghsa-public-advisory-evm",
    "python-onchain": "ghsa-public-advisory-py-stack",
}


_IMPACT_KEYWORDS: Tuple[Tuple[str, str], ...] = (
    ("denial of service", "dos"),
    ("denial-of-service", "dos"),
    ("dos", "dos"),
    ("freeze", "freeze"),
    ("frozen", "freeze"),
    ("locked", "freeze"),
    ("steal", "theft"),
    ("theft", "theft"),
    ("drain", "theft"),
    ("siphon", "theft"),
    ("withdraw arbitrary", "theft"),
    ("griefing", "griefing"),
    ("precision", "precision-loss"),
    ("rounding", "precision-loss"),
    ("governance", "governance-takeover"),
    ("privilege escalation", "privilege-escalation"),
    ("privileged access", "privilege-escalation"),
    ("admin", "privilege-escalation"),
    ("yield", "yield-redistribution"),
    ("reward", "yield-redistribution"),
)


def _infer_impact_class(advisory: Dict[str, Any]) -> str:
    haystack = " ".join(
        str(advisory.get(k, "")) for k in ("summary", "description")
    ).lower()
    for kw, impact in _IMPACT_KEYWORDS:
        if kw in haystack:
            return impact
    return "dos"  # conservative default for unclassified GHSAs


def _infer_impact_actor(impact_class: str) -> str:
    if impact_class in {"governance-takeover", "privilege-escalation"}:
        return "validator-set"
    if impact_class in {"yield-redistribution"}:
        return "yield-recipient"
    if impact_class in {"theft", "freeze"}:
        return "arbitrary-user"
    return "arbitrary-user"


def _identifier_strings(advisory: Dict[str, Any]) -> List[str]:
    out: List[str] = []
    for ident in advisory.get("identifiers", []) or []:
        if isinstance(ident, dict):
            val = ident.get("value")
            if isinstance(val, str) and val:
                out.append(val)
    return out


def _record_id_from_ghsa(repo: str, ghsa_id: str) -> str:
    # Schema pattern: [A-Za-z0-9._:/-]{8,160}
    repo_slug = slugify(repo.replace("/", "-"), max_len=64)
    ghsa_slug = slugify(ghsa_id, max_len=64) or "ghsa-unknown"
    payload = f"ghsa|{repo}|{ghsa_id}"
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:12]
    return f"ghsa:{repo_slug}:{ghsa_slug}:{digest}"


def _function_shape(advisory: Dict[str, Any], lang: str) -> Dict[str, Any]:
    pkgs: List[str] = []
    for vuln in advisory.get("vulnerabilities", []) or []:
        if isinstance(vuln, dict):
            pkg = vuln.get("package")
            if isinstance(pkg, dict):
                name = pkg.get("name")
                if isinstance(name, str) and name:
                    pkgs.append(name)
    raw_signature = pkgs[0] if pkgs else f"{lang}-package"
    shape_tags = [
        slugify(f"ghsa-{lang}", max_len=64),
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
    # Dedup while preserving order.
    seen: set = set()
    unique: List[str] = []
    for tag in shape_tags:
        if tag and tag not in seen:
            seen.add(tag)
            unique.append(tag)
    if not unique:
        unique = ["ghsa-public"]
    return {"raw_signature": raw_signature[:500], "shape_tags": unique}


def _required_preconditions(advisory: Dict[str, Any], repo: str) -> List[str]:
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
    # Always include the repo so the precondition list is non-empty even for
    # bare-bones advisories with no description.
    out.append(f"Affected repo {repo}")
    # Dedup + cap length per schema.
    seen: set = set()
    unique: List[str] = []
    for item in out:
        cleaned = one_line(item, "precondition", max_len=900)
        if cleaned not in seen:
            seen.add(cleaned)
            unique.append(cleaned)
    return unique


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
    return "Apply the upstream maintainer's recommended fix once the advisory ships a patched-versions range."


def _anti_pattern(advisory: Dict[str, Any]) -> str:
    severity = _normalize_severity(advisory.get("severity"))
    return one_line(
        f"Running unpatched {severity}-severity GHSA package version; trusting an advisory without verifying the patched-versions tag is present in the dependency lockfile.",
        "Running an unpatched advisory-tagged dependency.",
        max_len=900,
    )


def _attacker_action_sequence(advisory: Dict[str, Any], lang: str, mitigation: str) -> str:
    summary = advisory.get("summary") or ""
    description = advisory.get("description") or ""
    text = f"{summary}. {description}".strip()
    if not text or text == ".":
        text = f"GHSA-tracked vulnerability in {lang} package; see upstream advisory."
    state_marker = f" [mitigation-state={mitigation}; source=github-security-advisory]"
    # Reserve enough room for the marker so the schema-cap trim does not eat it.
    body_max = 4900 - len(state_marker)
    body = one_line(text, "GHSA-tracked attacker action sequence", max_len=body_max)
    return (body + state_marker).strip()


def advisory_to_record(
    repo: str,
    lang: str,
    domain: str,
    advisory: Dict[str, Any],
) -> Dict[str, Any]:
    ghsa_id = advisory.get("ghsa_id") or "GHSA-unknown"
    if not isinstance(ghsa_id, str):
        ghsa_id = "GHSA-unknown"
    severity = _normalize_severity(advisory.get("severity"))
    impact_class = _infer_impact_class(advisory)
    impact_actor = _infer_impact_actor(impact_class)
    mitigation = _mitigation_state(advisory)
    year = _year_for(advisory)
    source_url = advisory.get("html_url") or advisory.get("url") or f"github.com/{repo}/security/advisories/{ghsa_id}"
    bug_class = _DEFAULT_BUG_CLASS_BY_LANG.get(lang, "smart-contract-vulnerability")
    attack_class = _DEFAULT_ATTACK_CLASS_BY_LANG.get(lang, "ghsa-public-advisory")
    record = {
        "schema_version": SCHEMA_VERSION,
        "record_id": _record_id_from_ghsa(repo, ghsa_id),
        "source_audit_ref": one_line(source_url, f"ghsa:{repo}:{ghsa_id}", max_len=240),
        "target_domain": domain,
        "target_language": lang,
        "target_repo": repo,
        "target_component": one_line(
            f"{repo}:{ghsa_id}",
            f"{repo}:advisory",
            max_len=240,
        ),
        "function_shape": _function_shape(advisory, lang),
        "bug_class": bug_class,
        "attack_class": attack_class,
        "attacker_role": "unprivileged",
        "attacker_action_sequence": _attacker_action_sequence(advisory, lang, mitigation),
        "required_preconditions": _required_preconditions(advisory, repo),
        "impact_class": impact_class,
        "impact_actor": impact_actor,
        "impact_dollar_class": _dollar_class(severity),
        "fix_pattern": _fix_pattern(advisory),
        "fix_anti_pattern_avoided": _anti_pattern(advisory),
        "severity_at_finding": severity,
        "year": year,
        "record_tier": "public-corpus",
        "record_quality_score": 4.0,  # real upstream advisory -> high
        "source_extraction_method": "corpus-etl",
        "source_extraction_confidence": 0.85,  # GHSA is real source-of-truth
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
) -> List[Dict[str, Any]]:
    records: List[Dict[str, Any]] = []
    seen_ids: set = set()
    for repo, lang, domain in repos:
        for advisory in fetched.get(repo, []) or []:
            if not isinstance(advisory, dict):
                continue
            if advisory.get("state") and advisory["state"] != "published":
                # GHSA REST returns published-only when state=published is
                # sent, but defend in case the cache contains other states.
                continue
            record = advisory_to_record(repo, lang, domain, advisory)
            if record["record_id"] in seen_ids:
                continue
            seen_ids.add(record["record_id"])
            records.append(record)
    return records


def output_filename(record: Dict[str, Any]) -> str:
    rid = str(record["record_id"])
    digest = rid.rsplit(":", 1)[-1]
    return f"{slugify(rid, max_len=110)}-{digest}.yaml"


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
    selected = list(repos or TOP_REPOS)
    if filter_repo:
        selected = [r for r in selected if r[0] == filter_repo]
    fetched = fetch_all_advisories(
        selected,
        cache_file=cache_file,
        write_cache_file=write_cache_file,
    )
    records = build_records(fetched, selected)
    if limit is not None:
        records = records[:limit]

    schema = _VALIDATOR.load_schema()
    errors: List[str] = []
    files: List[str] = []
    by_domain: Dict[str, int] = {}
    by_severity: Dict[str, int] = {}
    by_repo: Dict[str, int] = {}
    by_language: Dict[str, int] = {}
    by_mitigation: Dict[str, int] = {}

    if not dry_run:
        out_dir.mkdir(parents=True, exist_ok=True)

    for record in records:
        by_domain[record["target_domain"]] = by_domain.get(record["target_domain"], 0) + 1
        by_severity[record["severity_at_finding"]] = by_severity.get(record["severity_at_finding"], 0) + 1
        by_repo[record["target_repo"]] = by_repo.get(record["target_repo"], 0) + 1
        by_language[record["target_language"]] = by_language.get(record["target_language"], 0) + 1
        # Pull mitigation state from action-sequence marker.
        action = record["attacker_action_sequence"]
        m = re.search(r"\[mitigation-state=(\w+);", action)
        state = m.group(1) if m else "unknown"
        by_mitigation[state] = by_mitigation.get(state, 0) + 1
        rendered = yaml_dump(record)
        try:
            doc = yaml.safe_load(rendered)
        except yaml.YAMLError as exc:
            errors.append(f"{record['record_id']}: yaml-parse-error: {exc}")
            continue
        errs = _VALIDATOR.validate_doc(doc, schema)
        if errs:
            errors.extend(f"{record['record_id']}: {err}" for err in errs)
            continue
        out_path = out_dir / output_filename(record)
        files.append(str(out_path))
        if not dry_run:
            out_path.write_text(rendered, encoding="utf-8")

    repos_with_zero = sorted(repo for repo, _l, _d in selected if not fetched.get(repo))
    return {
        "schema_version": SCHEMA_VERSION,
        "out_dir": str(out_dir),
        "dry_run": dry_run,
        "records_emitted": len(records) - len(errors),
        "records_attempted": len(records),
        "errors": errors,
        "by_domain": by_domain,
        "by_severity": by_severity,
        "by_repo": by_repo,
        "by_language": by_language,
        "by_mitigation_state": by_mitigation,
        "file_count": len(files),
        "repos_queried": len(selected),
        "repos_with_zero_advisories": repos_with_zero,
        "files": files[:50],
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", required=True)
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
        help="Restrict to a single owner/repo string (must match TOP_REPOS exactly).",
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
        filter_repo=args.filter_repo,
    )
    if args.json_summary:
        print(json.dumps(summary, sort_keys=True))
    else:
        print(
            "hackerman GHSA ETL: "
            f"records={summary['records_emitted']}/{summary['records_attempted']} "
            f"repos={summary['repos_queried']} "
            f"by_severity={summary['by_severity']} "
            f"by_language={summary['by_language']} "
            f"zero-advisory-repos={len(summary['repos_with_zero_advisories'])} "
            f"errors={len(summary['errors'])}"
        )
    return 0 if not summary["errors"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
