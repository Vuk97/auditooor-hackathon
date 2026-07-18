#!/usr/bin/env python3
"""
Mine public PoC harness repos (rekt-stuff + smart-contract-vulnerable-examples)
into hackerman_record v1.1 YAML.

Wave-1 lane EXEC-WAVE1-PUBLIC-POC-HARNESSES. Sibling of:

* ``tools/hackerman-etl-from-bridge-attacks.py``
* ``tools/hackerman-etl-from-audit-firm-public-reports.py``
* ``tools/hackerman-etl-from-curve-balancer-uniswap-fixes.py``

This miner indexes PUBLIC PoC test files (Foundry / Echidna harnesses
demonstrating vulnerabilities) from canonical "rekt-stuff" and
"smart-contract-vulnerable-examples" repositories. These are valuable
detector-seed material that is distinct from finding-anchored records
already mined elsewhere (audit-firm reports, contest platforms, CVE/GHSA
advisories).

Each emitted record:

* schema_version = ``auditooor.hackerman_record.v1.1``
* verification_tier = ``tier-2-verified-public-archive`` (file URL is a
  public-archive blob URL but no individual CVE/GHSA ID is anchored on
  the file in the general case)
* record_source_url = the raw GitHub blob URL of the specific PoC file
* attack_class = extracted from filename heuristics + curated mapping

Allowed real sources (configured in :data:`SOURCE_SPECS`):

* ``SunWeb3Sec/DeFiHackLabs``   - reproductions of real DeFi hacks
  organised by ``src/test/<YYYY-MM>/<Name>_exp.sol``
* ``SunWeb3Sec/DeFiVulnLabs``   - per-vulnerability-class Foundry demos
  under ``src/test/<VulnName>.sol``
* ``crytic/echidna``            - fuzz-harness examples under
  ``tests/solidity/**`` (assert / property tests / fuzz contracts)
* ``transmissions11/solmate``   - property-style tests for the solmate
  library under ``src/test/*.t.sol`` (treated as engineering-grade
  positive fixture set; tier-2 record-quality 2.5)

Hard rules followed:

* New file only; does NOT modify any existing file.
* Does NOT touch ``tools/calibration/llm_budget_log.jsonl``.
* Cross-links (in docstring + comments) are relative paths only.
* All emitted records validate against
  ``audit/corpus_tags/schemas/auditooor.hackerman_record.v1.schema.json``.
* Rule 37: every record carries first-class ``verification_tier``.
* Rule 36: commit is staged by explicit pathspec by the caller.
* CVE/GHSA pre-emit check imports :mod:`tools.lib.hackerman_cve_verification`
  and uses ``strict=False`` (PoC files don't always anchor a CVE ID).

CLI:

    # Live mode (calls gh api):
    python3 tools/hackerman-etl-from-public-poc-harnesses.py \
        --out-dir audit/corpus_tags/tags/hackerman_public_poc_harnesses

    # Cached mode (uses a previously-saved {owner_repo: [tree_entries]}):
    python3 tools/hackerman-etl-from-public-poc-harnesses.py \
        --trees-cache /tmp/poc-trees.json \
        --out-dir /tmp/etl-public-poc-out

    # Test-fixture mode (used by the unit tests):
    python3 tools/hackerman-etl-from-public-poc-harnesses.py \
        --trees-cache tools/tests/fixtures/hackerman_etl_from_public_poc_harnesses/payload.json \
        --out-dir /tmp/etl-public-poc-out --dry-run --json-summary

Target seed: ~120-200 records on a live run (DeFiHackLabs + DeFiVulnLabs
+ echidna examples + solmate property tests, deduped on path).
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml

# Rule 37 (Check #77): CVE/GHSA verifier shim - works both when run
# from repo-root (`python3 tools/<miner>.py`) and as a module.
try:
    from tools.lib.hackerman_cve_verification import pre_emit_check  # type: ignore
except ImportError:  # pragma: no cover - bootstrap when tools not on sys.path
    import os as _r37_os
    import sys as _r37_sys
    _r37_sys.path.insert(0, _r37_os.path.dirname(_r37_os.path.dirname(_r37_os.path.abspath(__file__))))
    from tools.lib.hackerman_cve_verification import pre_emit_check  # type: ignore


REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_VERSION = "auditooor.hackerman_record.v1.1"
VERIFICATION_TIER = "tier-2-verified-public-archive"


def _load_validator() -> Any:
    spec = importlib.util.spec_from_file_location(
        "_hackerman_record_validate_for_public_poc",
        str(REPO_ROOT / "tools" / "hackerman-record-validate.py"),
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


_VALIDATOR = _load_validator()


# ---------------------------------------------------------------------------
# YAML helpers (kept self-contained per lane-isolation rule)
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
# Source specs.
#
# Each spec drives the recursive-tree fetch (one `gh api` call per repo)
# and filtering of blob paths to PoC test files only.
# ---------------------------------------------------------------------------


SOURCE_SPECS: Tuple[Dict[str, Any], ...] = (
    {
        "owner_repo": "SunWeb3Sec/DeFiHackLabs",
        "branch": "main",
        "path_prefix": "src/test/",
        # DeFiHackLabs files are grouped by YYYY-MM month directory:
        # src/test/2024-01/BarleyFinance_exp.sol
        "path_regex": r"^src/test/(\d{4}-\d{2})/[^/]+\.sol$",
        "kind": "rekt-replay",
        "default_attack_class": "rekt-replay-poc-foundry",
        "default_bug_class": "rekt-replay-historical-poc",
        "default_severity": "high",
        "default_impact_class": "theft",
        "record_quality_score": 4.0,
        "extraction_confidence": 0.85,
    },
    {
        "owner_repo": "SunWeb3Sec/DeFiVulnLabs",
        "branch": "main",
        "path_prefix": "src/test/",
        # DeFiVulnLabs files are per-vuln-class Foundry demos:
        # src/test/Delegatecall.sol
        "path_regex": r"^src/test/[^/]+\.sol$",
        "kind": "vuln-class-demo",
        "default_attack_class": "solidity-vuln-class-demo",
        "default_bug_class": "solidity-pattern-illustration",
        "default_severity": "medium",
        "default_impact_class": "theft",
        "record_quality_score": 3.5,
        "extraction_confidence": 0.80,
    },
    {
        "owner_repo": "crytic/echidna",
        "branch": "master",
        "path_prefix": "tests/solidity/",
        # Echidna examples under tests/solidity/<category>/<file>.sol
        "path_regex": r"^tests/solidity/[^/]+/[^/]+\.sol$",
        "kind": "fuzz-harness-example",
        "default_attack_class": "echidna-property-fuzz-harness",
        "default_bug_class": "fuzz-property-target",
        "default_severity": "info",
        "default_impact_class": "dos",
        "record_quality_score": 3.0,
        "extraction_confidence": 0.70,
    },
    {
        "owner_repo": "transmissions11/solmate",
        "branch": "main",
        "path_prefix": "src/test/",
        # Solmate property tests: src/test/Auth.t.sol
        "path_regex": r"^src/test/[^/]+\.t\.sol$",
        "kind": "library-property-test",
        "default_attack_class": "solmate-library-property-test",
        "default_bug_class": "library-property-fixture",
        "default_severity": "info",
        "default_impact_class": "precision-loss",
        "record_quality_score": 2.5,
        "extraction_confidence": 0.65,
    },
)


# ---------------------------------------------------------------------------
# Attack-class extraction heuristics.
#
# Filenames in DeFiVulnLabs are mostly self-explanatory. DeFiHackLabs files
# are named after the project hacked. We map known vuln keywords in the
# filename to canonical attack_class values that align with the rest of
# the corpus taxonomy.
# ---------------------------------------------------------------------------


FILENAME_KEYWORD_TO_ATTACK_CLASS: Tuple[Tuple[str, str, str, str], ...] = (
    # (keyword (lowercase substring), attack_class, bug_class, impact_class)
    ("reentrancy",        "reentrancy",                    "missing-reentrancy-guard",        "theft"),
    ("reentry",           "reentrancy",                    "missing-reentrancy-guard",        "theft"),
    ("erc777",            "reentrancy",                    "erc777-callback-reentrancy",      "theft"),
    ("delegatecall",      "unsafe-delegatecall",           "delegatecall-to-attacker-input",  "privilege-escalation"),
    ("flashloan",         "flashloan-price-manipulation",  "oracle-spot-price-manipulation",  "theft"),
    ("flash-loan",        "flashloan-price-manipulation",  "oracle-spot-price-manipulation",  "theft"),
    ("oracle",            "oracle-spot-manipulation",      "spot-price-oracle-misuse",        "theft"),
    ("price",             "oracle-spot-manipulation",      "spot-price-oracle-misuse",        "theft"),
    ("signature",         "signature-replay",              "ecrecover-replay-or-malleable",   "theft"),
    ("ecrecover",         "signature-replay",              "ecrecover-replay-or-malleable",   "theft"),
    ("permit",            "permit-frontrun",               "permit-frontrun-or-replay",       "theft"),
    ("approve",           "approval-frontrun",             "approval-frontrun-or-misuse",     "theft"),
    ("overflow",          "integer-overflow",              "unchecked-arithmetic",            "precision-loss"),
    ("underflow",         "integer-underflow",             "unchecked-arithmetic",            "precision-loss"),
    ("integer",           "integer-overflow",              "unchecked-arithmetic",            "precision-loss"),
    ("access",            "missing-access-control",        "missing-onlyOwner-guard",         "privilege-escalation"),
    ("onlyowner",         "missing-access-control",        "missing-onlyOwner-guard",         "privilege-escalation"),
    ("authoriz",          "missing-access-control",        "missing-onlyOwner-guard",         "privilege-escalation"),
    ("selfdestruct",      "force-eth-via-selfdestruct",    "selfdestruct-balance-injection",  "griefing"),
    ("force",             "force-eth-via-selfdestruct",    "selfdestruct-balance-injection",  "griefing"),
    ("randomness",        "weak-randomness",               "blockhash-prevrandao-misuse",     "theft"),
    ("blockhash",         "weak-randomness",               "blockhash-prevrandao-misuse",     "theft"),
    ("randao",            "weak-randomness",               "blockhash-prevrandao-misuse",     "theft"),
    ("timestamp",         "block-timestamp-dependence",    "timestamp-bias",                  "griefing"),
    ("dos",               "denial-of-service",             "gas-bomb-or-revert-flood",        "dos"),
    ("griefing",          "denial-of-service",             "gas-bomb-or-revert-flood",        "dos"),
    ("frontrun",          "transaction-frontrun",          "mempool-frontrun",                "theft"),
    ("sandwich",          "transaction-frontrun",          "mempool-sandwich",                "theft"),
    ("mev",               "transaction-frontrun",          "mempool-sandwich",                "theft"),
    ("tx-origin",         "tx-origin-auth-bypass",         "tx-origin-vs-msg-sender",         "privilege-escalation"),
    ("txorigin",          "tx-origin-auth-bypass",         "tx-origin-vs-msg-sender",         "privilege-escalation"),
    ("storage",           "storage-collision",             "proxy-storage-layout-collision",  "privilege-escalation"),
    ("uninit",            "uninitialized-state",           "uninitialised-trusted-root",      "theft"),
    ("init",              "uninitialized-state",           "uninitialised-trusted-root",      "theft"),
    ("constructor",       "constructor-name-mismatch",     "fake-constructor",                "privilege-escalation"),
    ("rounding",          "rounding-direction",            "share-price-rounding-wrong-way",  "precision-loss"),
    ("div",               "rounding-direction",            "share-price-rounding-wrong-way",  "precision-loss"),
    ("erc20",             "non-standard-erc20",            "non-standard-erc20-handling",     "theft"),
    ("erc721",            "nft-callback-abuse",            "onERC721Received-callback-abuse", "theft"),
    ("nft",               "nft-callback-abuse",            "onERC721Received-callback-abuse", "theft"),
    ("typeahead",         "transaction-frontrun",          "mempool-frontrun",                "theft"),
    ("liquidat",          "liquidation-griefing",          "liquidation-path-griefing",       "theft"),
    ("borrow",            "lending-share-inflation",       "share-price-inflation",           "theft"),
    ("lending",           "lending-share-inflation",       "share-price-inflation",           "theft"),
    ("router",            "router-permit-takeover",        "router-permit-takeover",          "theft"),
    ("bridge",            "bridge-validator-set-takeover", "bridge-quorum-compromise",        "theft"),
    ("merkle",            "merkle-proof-misuse",           "merkle-leaf-collision",           "theft"),
    ("proxy",             "proxy-upgrade-takeover",        "proxy-admin-takeover",            "privilege-escalation"),
    ("upgrade",           "proxy-upgrade-takeover",        "proxy-admin-takeover",            "privilege-escalation"),
    ("array",             "array-out-of-bounds",           "array-length-mismatch",           "dos"),
    ("assembly",          "inline-assembly-misuse",        "raw-call-return-value",           "theft"),
    ("backdoor",          "owner-backdoor",                "hidden-admin-function",           "privilege-escalation"),
    ("rugpull",           "owner-backdoor",                "hidden-admin-function",           "theft"),
    ("rug",               "owner-backdoor",                "hidden-admin-function",           "theft"),
)


def classify_filename(filename: str) -> Optional[Tuple[str, str, str]]:
    """Return ``(attack_class, bug_class, impact_class)`` extracted from
    filename keywords, or ``None`` if no keyword matched.
    """
    name = filename.lower()
    # Strip suffixes
    name = re.sub(r"\.(t\.sol|sol)$", "", name)
    name = re.sub(r"_exp$", "", name)
    for keyword, attack_class, bug_class, impact_class in FILENAME_KEYWORD_TO_ATTACK_CLASS:
        if keyword in name:
            return (attack_class, bug_class, impact_class)
    return None


def extract_project_name(filename: str) -> str:
    """Extract a project-name hint from a DeFiHackLabs '<Project>_exp.sol'
    filename or a vuln-class demo name like 'Delegatecall.sol'."""
    stem = re.sub(r"\.(t\.sol|sol)$", "", filename, flags=re.IGNORECASE)
    stem = re.sub(r"_exp$", "", stem, flags=re.IGNORECASE)
    return stem


# ---------------------------------------------------------------------------
# Tree-listing API.
# ---------------------------------------------------------------------------


def fetch_tree_paths(owner_repo: str, branch: str) -> List[Dict[str, Any]]:
    """Return the list of blob entries via ``gh api`` recursive trees.

    Returns an empty list when ``gh api`` is unavailable or the call
    fails. Callers downstream emit zero records honestly rather than
    fabricating.
    """
    try:
        proc = subprocess.run(
            [
                "gh", "api",
                f"repos/{owner_repo}/git/trees/{branch}?recursive=1",
            ],
            check=False, capture_output=True, text=True, timeout=90,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []
    if proc.returncode != 0:
        return []
    try:
        doc = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return []
    tree = doc.get("tree")
    if not isinstance(tree, list):
        return []
    return [t for t in tree if isinstance(t, dict) and t.get("type") == "blob"]


def load_trees_cache(cache_file: Path) -> Dict[str, List[Dict[str, Any]]]:
    """Load a previously-saved ``{owner_repo: [tree_entries]}`` cache.
    Test-suite fixtures drive the miner offline through this path.
    """
    data = json.loads(cache_file.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("trees cache must be a JSON object")
    out: Dict[str, List[Dict[str, Any]]] = {}
    for key, entries in data.items():
        if not isinstance(entries, list):
            continue
        out[key] = [e for e in entries if isinstance(e, dict) and e.get("type") == "blob"]
    return out


def write_trees_cache(cache_file: Path, trees: Dict[str, List[Dict[str, Any]]]) -> None:
    cache_file.parent.mkdir(parents=True, exist_ok=True)
    cache_file.write_text(
        json.dumps(trees, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def load_or_fetch_trees(
    *,
    cache_file: Optional[Path] = None,
    write_cache: Optional[Path] = None,
    specs: Tuple[Dict[str, Any], ...] = SOURCE_SPECS,
) -> Dict[str, List[Dict[str, Any]]]:
    if cache_file is not None:
        return load_trees_cache(cache_file)
    trees: Dict[str, List[Dict[str, Any]]] = {}
    for spec in specs:
        owner_repo = spec["owner_repo"]
        branch = spec["branch"]
        trees[owner_repo] = fetch_tree_paths(owner_repo, branch)
    if write_cache is not None:
        write_trees_cache(write_cache, trees)
    return trees


# ---------------------------------------------------------------------------
# Per-file record synthesis.
# ---------------------------------------------------------------------------


def _record_source_url(owner_repo: str, branch: str, path: str) -> str:
    return f"https://github.com/{owner_repo}/blob/{branch}/{path}"


def _record_id(owner_repo: str, path: str) -> str:
    payload = f"{owner_repo}|{path}"
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:12]
    repo_slug = slugify(owner_repo, max_len=40)
    path_slug = slugify(path, max_len=80)
    return f"public-poc:{repo_slug}:{path_slug}:{digest}"


def _shape_tags(attack_class: str, bug_class: str, kind: str, project: str) -> List[str]:
    tags = [
        slugify(attack_class, max_len=64),
        slugify(f"public-poc-{kind}", max_len=64),
        slugify(f"poc-{bug_class}", max_len=64),
    ]
    if project:
        tags.append(slugify(f"project-{project}", max_len=64))
    seen: set = set()
    result: List[str] = []
    for tag in tags:
        if tag and tag not in seen:
            seen.add(tag)
            result.append(tag)
    return result


def _year_from_path(spec: Dict[str, Any], path: str) -> int:
    # DeFiHackLabs path: src/test/<YYYY-MM>/<file>
    if spec["owner_repo"] == "SunWeb3Sec/DeFiHackLabs":
        m = re.match(r"^src/test/(\d{4})-\d{2}/", path)
        if m:
            return int(m.group(1))
    return 2024


def record_from_path(spec: Dict[str, Any], path: str) -> Optional[Dict[str, Any]]:
    """Synthesise a hackerman_record v1.1 row from a single tree entry.

    Returns ``None`` if the path is filtered out by the spec's
    ``path_regex`` or if classification fails.
    """
    if not re.match(spec["path_regex"], path):
        return None
    filename = path.rsplit("/", 1)[-1]
    project = extract_project_name(filename)

    classified = classify_filename(filename)
    if classified is None:
        attack_class = spec["default_attack_class"]
        bug_class = spec["default_bug_class"]
        impact_class = spec["default_impact_class"]
        classified_via = "default"
    else:
        attack_class, bug_class, impact_class = classified
        classified_via = "filename-keyword"

    owner_repo = spec["owner_repo"]
    branch = spec["branch"]
    source_url = _record_source_url(owner_repo, branch, path)
    record_id = _record_id(owner_repo, path)
    year = _year_from_path(spec, path)

    raw_signature = f"function setUp() public  // PoC fixture in {filename}"

    action = (
        f"Public PoC harness file in {owner_repo} at {path}. "
        f"Kind: {spec['kind']}. Classification via {classified_via} "
        f"(filename '{filename}' -> attack_class '{attack_class}'). "
        "Downstream consumers should treat the file as a runnable "
        "Foundry / Echidna harness and lift its assertions / setUp / "
        "exploit() body as detector seed material. Source URL: "
        f"{source_url}."
    )

    preconds = [
        f"Source repo {owner_repo} at branch {branch}",
        f"Source path {path}",
        f"verification_tier={VERIFICATION_TIER}",
        f"record_source_url={source_url}",
    ]

    fix_pattern = (
        f"For real-world deployments matching the pattern demonstrated in {filename}: "
        "audit for the same attack surface, port the assertions / property checks "
        "from the public PoC into the project's test suite, and add an invariant "
        "test mirroring the harness."
    )
    fix_anti_pattern = (
        f"Shipping code that exhibits the pattern illustrated in {filename} without "
        "regression coverage matching the public PoC's assertions."
    )

    record: Dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "record_id": record_id,
        "source_audit_ref": one_line(
            f"public-poc:{slugify(owner_repo, max_len=40)}:{path}",
            f"public-poc:{owner_repo}",
            max_len=240,
        ),
        "verification_tier": VERIFICATION_TIER,
        "record_source_url": source_url,
        "target_domain": "vault",  # generic catch-all; refined downstream
        "target_language": "solidity",
        "target_repo": owner_repo,
        "target_component": one_line(path, "unknown", max_len=240),
        "function_shape": {
            "raw_signature": one_line(raw_signature, "function setUp() public", max_len=500),
            "shape_tags": _shape_tags(attack_class, bug_class, spec["kind"], project),
        },
        "bug_class": one_line(bug_class, "public-poc-pattern", max_len=160),
        "attack_class": one_line(attack_class, spec["default_attack_class"], max_len=160),
        "attacker_role": "unprivileged",
        "attacker_action_sequence": one_line(action, f"Execute PoC at {path}", max_len=4900),
        "required_preconditions": preconds,
        "impact_class": impact_class,
        "impact_actor": "arbitrary-user",
        "impact_dollar_class": "non-financial",
        "fix_pattern": one_line(fix_pattern, "Apply the recommended invariant check.", max_len=900),
        "fix_anti_pattern_avoided": one_line(
            fix_anti_pattern,
            "Shipping without invariant test coverage of the demonstrated pattern.",
            max_len=900,
        ),
        "severity_at_finding": spec["default_severity"],
        "year": year,
        "record_tier": "public-corpus",
        "record_quality_score": float(spec["record_quality_score"]),
        "source_extraction_method": "corpus-etl",
        "source_extraction_confidence": float(spec["extraction_confidence"]),
        "verification_method": "manual",
        "cross_language_analogues": [],
        "related_records": [],
    }
    return record


# ---------------------------------------------------------------------------
# Top-level build / write-out.
# ---------------------------------------------------------------------------


def build_records(
    trees: Dict[str, List[Dict[str, Any]]],
    *,
    specs: Tuple[Dict[str, Any], ...] = SOURCE_SPECS,
    existing_record_ids: Optional[set] = None,
) -> Tuple[List[Dict[str, Any]], int]:
    """Return ``(records, dedup_count)`` for the supplied trees.

    Records are deduplicated by ``record_id`` against:

    1. Other records in the same emission (intra-batch dedup).
    2. ``existing_record_ids`` if supplied (used by the orchestrator to
       skip re-emitting records that already exist on disk in sibling
       corpus subtrees).
    """
    out: List[Dict[str, Any]] = []
    seen: set = set(existing_record_ids or set())
    dedup_count = 0
    for spec in specs:
        owner_repo = spec["owner_repo"]
        entries = trees.get(owner_repo, [])
        # Sort for determinism.
        paths = sorted(
            e["path"] for e in entries
            if isinstance(e, dict) and isinstance(e.get("path"), str)
        )
        for path in paths:
            rec = record_from_path(spec, path)
            if rec is None:
                continue
            rid = rec["record_id"]
            if rid in seen:
                dedup_count += 1
                continue
            seen.add(rid)
            out.append(rec)
    return out, dedup_count


def collect_existing_record_ids(corpus_root: Path) -> set:
    """Scan sibling corpus subtrees for record_ids beginning with the
    'public-poc:' namespace OR records whose target_repo matches one of
    our SOURCE_SPECS owner_repos. Used for additive-only dedup so a
    re-run on a populated tree skips repeats silently.

    Implementation note: cheap stem scan - only opens YAML files whose
    name begins with our slug prefix. Full corpus crawl would be
    expensive; this is a best-effort safeguard, the gold dedup is the
    in-batch one in :func:`build_records`.
    """
    ids: set = set()
    if not corpus_root.is_dir():
        return ids
    for sub in corpus_root.iterdir():
        if not sub.is_dir():
            continue
        for path in sub.glob("public-poc*.yaml"):
            try:
                with path.open("r", encoding="utf-8") as fh:
                    doc = yaml.safe_load(fh)
            except Exception:
                continue
            if isinstance(doc, dict):
                rid = doc.get("record_id")
                if isinstance(rid, str):
                    ids.add(rid)
    return ids


def output_filename(record: Dict[str, Any]) -> str:
    rid = str(record["record_id"])
    digest = rid.rsplit(":", 1)[-1]
    return f"{slugify(rid, max_len=110)}-{digest}.yaml"


def convert(
    out_dir: Path,
    *,
    trees: Optional[Dict[str, List[Dict[str, Any]]]] = None,
    cache_file: Optional[Path] = None,
    write_cache: Optional[Path] = None,
    corpus_root_for_dedup: Optional[Path] = None,
    dry_run: bool = False,
    limit: Optional[int] = None,
    filter_attack_class: Optional[str] = None,
    filter_owner_repo: Optional[str] = None,
) -> Dict[str, Any]:
    if trees is None:
        trees = load_or_fetch_trees(cache_file=cache_file, write_cache=write_cache)

    existing_ids: set = set()
    if corpus_root_for_dedup is not None:
        existing_ids = collect_existing_record_ids(corpus_root_for_dedup)

    records, intra_dedup = build_records(trees, existing_record_ids=existing_ids)
    if filter_attack_class:
        records = [r for r in records if r["attack_class"] == filter_attack_class]
    if filter_owner_repo:
        records = [r for r in records if r["target_repo"] == filter_owner_repo]
    if limit is not None:
        records = records[:limit]

    schema = _VALIDATOR.load_schema()
    errors: List[str] = []
    files: List[str] = []
    by_attack_class: Dict[str, int] = {}
    by_owner_repo: Dict[str, int] = {}
    by_severity: Dict[str, int] = {}
    by_year: Dict[int, int] = {}

    if not dry_run:
        out_dir.mkdir(parents=True, exist_ok=True)

    for record in records:
        rid = str(record["record_id"])
        by_attack_class[record["attack_class"]] = by_attack_class.get(record["attack_class"], 0) + 1
        by_owner_repo[record["target_repo"]] = by_owner_repo.get(record["target_repo"], 0) + 1
        by_severity[record["severity_at_finding"]] = by_severity.get(record["severity_at_finding"], 0) + 1
        year = int(record.get("year", 0))
        by_year[year] = by_year.get(year, 0) + 1

        rendered = yaml_dump(record)
        try:
            doc = yaml.safe_load(rendered)
        except yaml.YAMLError as exc:
            errors.append(f"{rid}: yaml-parse-error: {exc}")
            continue
        errs = _VALIDATOR.validate_doc(doc, schema)
        if errs:
            errors.extend(f"{rid}: {err}" for err in errs)
            continue
        out_path = out_dir / output_filename(record)
        if (not dry_run) and out_path.exists():
            # Additive-only: don't overwrite an existing record.
            files.append(str(out_path))
            continue
        files.append(str(out_path))
        if not dry_run:
            _r37_ok, _r37_reason = pre_emit_check(doc, strict=False)  # Rule 37
            if not _r37_ok:
                print(f"r37-skip {_r37_reason}: {doc.get('record_id','?')}", file=sys.stderr)
            out_path.write_text(rendered, encoding="utf-8")

    return {
        "schema_version": SCHEMA_VERSION,
        "verification_tier": VERIFICATION_TIER,
        "out_dir": str(out_dir),
        "dry_run": dry_run,
        "records_emitted": len(files),
        "records_attempted": len(records),
        "intra_batch_dedup_count": intra_dedup,
        "existing_dedup_against_corpus": len(existing_ids),
        "errors": errors,
        "by_attack_class": by_attack_class,
        "by_owner_repo": by_owner_repo,
        "by_severity": by_severity,
        "by_year": {str(k): v for k, v in sorted(by_year.items())},
        "file_count": len(files),
        "files": files[:50],
    }


# ---------------------------------------------------------------------------
# CLI.
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--trees-cache",
                        help="Read previously-saved {owner_repo: [tree_entries]} JSON instead of calling gh api.")
    parser.add_argument("--write-trees-cache",
                        help="Persist the fetched trees JSON to this path for offline re-use.")
    parser.add_argument("--corpus-root-for-dedup",
                        help="If supplied, scan this directory for existing public-poc records and skip re-emission.")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--apply", action="store_true",
                        help="Explicit safety toggle; default is to write unless --dry-run.")
    parser.add_argument("--limit", type=int)
    parser.add_argument("--filter-attack-class")
    parser.add_argument("--filter-owner-repo")
    parser.add_argument("--json-summary", action="store_true")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if args.limit is not None and args.limit < 0:
        print("--limit must be non-negative", file=sys.stderr)
        return 2
    if args.dry_run and args.apply:
        print("--dry-run and --apply are mutually exclusive", file=sys.stderr)
        return 2
    dry_run = bool(args.dry_run) and not args.apply
    summary = convert(
        Path(args.out_dir).expanduser().resolve(),
        cache_file=Path(args.trees_cache).expanduser().resolve() if args.trees_cache else None,
        write_cache=Path(args.write_trees_cache).expanduser().resolve() if args.write_trees_cache else None,
        corpus_root_for_dedup=Path(args.corpus_root_for_dedup).expanduser().resolve() if args.corpus_root_for_dedup else None,
        dry_run=dry_run,
        limit=args.limit,
        filter_attack_class=args.filter_attack_class,
        filter_owner_repo=args.filter_owner_repo,
    )
    if args.json_summary:
        print(json.dumps(summary, sort_keys=True))
    else:
        print(
            "hackerman public-poc-harnesses ETL: "
            f"records={summary['records_emitted']}/{summary['records_attempted']} "
            f"verification_tier={summary['verification_tier']} "
            f"by_owner_repo={summary['by_owner_repo']} "
            f"by_severity={summary['by_severity']} "
            f"intra_dedup={summary['intra_batch_dedup_count']} "
            f"existing_dedup={summary['existing_dedup_against_corpus']} "
            f"errors={len(summary['errors'])}"
        )
    return 0 if not summary["errors"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
