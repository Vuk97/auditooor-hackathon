#!/usr/bin/env python3
"""I3a - Primary-source downgrade rules (Check I3a).

Every external-mined corpus record must classify a ``source_type`` into one
of 7 categories.  Blog-only and provider-summary rows can become
``hunt_context`` or ``detector_seed``, but NOT ``proof_grade``, unless the
record carries an explicit binding to a primary tx, source, audit, contest,
or proof evidence.  ``unknown`` is capped at ``hunt_context``.

In ``--strict`` mode the tool exits non-zero when any record that currently
carries ``proof_grade``-equivalent signals is backed only by a secondary
source (blog / provider-summary / unknown) without a primary binding.

Schema id: ``auditooor.primary_source_downgrade.v1``

Exit codes:
  0  - pass (no violations, or all violations have primary bindings)
  1  - fail (strict mode: at least one secondary-only proof_grade record)
  2  - error (I/O failure, bad args)
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Iterator

# ---------------------------------------------------------------------------
# Schema / versioning
# ---------------------------------------------------------------------------

SCHEMA_ID = "auditooor.primary_source_downgrade.v1"
TOOL_VERSION = "1.0.0"
GATE_NAME = "I3A-PRIMARY-SOURCE-DOWNGRADE"

# ---------------------------------------------------------------------------
# Source-type classification constants
# ---------------------------------------------------------------------------

# The 7 canonical source types per I3a spec.
SOURCE_TYPE_OFFICIAL_POSTMORTEM = "official_postmortem"
SOURCE_TYPE_TX_CONTRACT_TRACE = "tx_contract_trace"
SOURCE_TYPE_AUDIT_REPORT = "audit_report"
SOURCE_TYPE_CONTEST_JUDGMENT = "contest_judgment"
SOURCE_TYPE_BLOG_ANALYSIS = "blog_analysis"
SOURCE_TYPE_PROVIDER_SUMMARY = "provider_summary"
SOURCE_TYPE_UNKNOWN = "unknown"

# Primary types are allowed up to proof_grade.
PRIMARY_SOURCE_TYPES = frozenset([
    SOURCE_TYPE_OFFICIAL_POSTMORTEM,
    SOURCE_TYPE_TX_CONTRACT_TRACE,
    SOURCE_TYPE_AUDIT_REPORT,
    SOURCE_TYPE_CONTEST_JUDGMENT,
])

# Secondary types are capped unless a primary binding is present.
SECONDARY_SOURCE_TYPES = frozenset([
    SOURCE_TYPE_BLOG_ANALYSIS,
    SOURCE_TYPE_PROVIDER_SUMMARY,
    SOURCE_TYPE_UNKNOWN,
])

# Evidence grade levels (ordered low -> high).
EVIDENCE_GRADE_DETECTOR_SEED = "detector_seed"
EVIDENCE_GRADE_HUNT_CONTEXT = "hunt_context"
EVIDENCE_GRADE_PROOF_GRADE = "proof_grade"

GRADE_RANK = {
    EVIDENCE_GRADE_DETECTOR_SEED: 0,
    EVIDENCE_GRADE_HUNT_CONTEXT: 1,
    EVIDENCE_GRADE_PROOF_GRADE: 2,
}

# Permitted max_evidence_grade per source_type (without primary binding).
MAX_GRADE_BY_SOURCE_TYPE: dict[str, str] = {
    SOURCE_TYPE_OFFICIAL_POSTMORTEM: EVIDENCE_GRADE_PROOF_GRADE,
    SOURCE_TYPE_TX_CONTRACT_TRACE: EVIDENCE_GRADE_PROOF_GRADE,
    SOURCE_TYPE_AUDIT_REPORT: EVIDENCE_GRADE_PROOF_GRADE,
    SOURCE_TYPE_CONTEST_JUDGMENT: EVIDENCE_GRADE_PROOF_GRADE,
    SOURCE_TYPE_BLOG_ANALYSIS: EVIDENCE_GRADE_HUNT_CONTEXT,
    SOURCE_TYPE_PROVIDER_SUMMARY: EVIDENCE_GRADE_DETECTOR_SEED,
    SOURCE_TYPE_UNKNOWN: EVIDENCE_GRADE_HUNT_CONTEXT,
}

# ---------------------------------------------------------------------------
# URL / field patterns for source-type classification
# ---------------------------------------------------------------------------

# Patterns map (regex, source_type).  Evaluated in order; first match wins.
_URL_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # Official post-mortems: team/project authored post-mortem pages.
    (re.compile(r"(?i)post[-_]?mortem|postmortem|incident[-_]report|security[-_]advisory"), SOURCE_TYPE_OFFICIAL_POSTMORTEM),
    # TX / contract trace: Etherscan, Tenderly, Phalcon, eigenphi, tx hashes.
    (re.compile(r"(?i)etherscan\.io/tx/|tenderly\.co|phalcon\.xyz|eigenphi\.io|0x[0-9a-f]{64}"), SOURCE_TYPE_TX_CONTRACT_TRACE),
    # Audit reports: known firm domains, PDF audit reports, GitHub spearbit/portfolio, pashov.
    (re.compile(r"(?i)spearbit\.com|pashov\.net|trail[-_]?of[-_]?bits|consensys\.net/diligence|openzeppelin\.com|certik\.com/projects|halborn\.com|quantstamp\.com|audit[-_]?report|/pdfs/|\.pdf$"), SOURCE_TYPE_AUDIT_REPORT),
    # GitHub raw PDFs from known audit firm repos.
    (re.compile(r"(?i)raw\.githubusercontent\.com/.*/(portfolio|audit|security[-_]review|audits)/"), SOURCE_TYPE_AUDIT_REPORT),
    # Contest judgments: code4rena, sherlock, cantina, immunefi (past-audit-competitions).
    (re.compile(r"(?i)code4rena\.com|github\.com/code[-_]?423n4/|sherlock[-_]?xyz|cantina\.xyz|github\.com/immunefi[-_]team/past[-_]audit"), SOURCE_TYPE_CONTEST_JUDGMENT),
    # Blog analysis: rekt.news, defimon, darknavy, medium, mirror, substack, blog.
    (re.compile(r"(?i)rekt\.news|defimon\.xyz|darknavy\.org|medium\.com|mirror\.xyz|substack\.com|blog\.|/blog/"), SOURCE_TYPE_BLOG_ANALYSIS),
    # Provider summary: defillama hacks, slowmist, beosin, peckshield, blocksec.
    (re.compile(r"(?i)defillama\.com|slowmist\.com|beosin\.com|peckshield\.com|blocksec\.com|certik\.com(?!/projects)|github\.com/slowmist"), SOURCE_TYPE_PROVIDER_SUMMARY),
]

# Schema / record_id prefix patterns -> source_type override.
_RECORD_ID_PREFIXES: list[tuple[str, str]] = [
    ("code4rena:", SOURCE_TYPE_CONTEST_JUDGMENT),
    ("sherlock:", SOURCE_TYPE_CONTEST_JUDGMENT),
    ("cantina:", SOURCE_TYPE_CONTEST_JUDGMENT),
    ("immunefi-public:", SOURCE_TYPE_CONTEST_JUDGMENT),
    ("audit-firm:", SOURCE_TYPE_AUDIT_REPORT),
    ("post-mortem-rekt:", SOURCE_TYPE_BLOG_ANALYSIS),
    ("darknavy-web3:", SOURCE_TYPE_BLOG_ANALYSIS),
    ("defimon-blog:", SOURCE_TYPE_BLOG_ANALYSIS),
    ("bridge-incident:", SOURCE_TYPE_BLOG_ANALYSIS),
    ("defillama:", SOURCE_TYPE_PROVIDER_SUMMARY),
    ("cve-", SOURCE_TYPE_OFFICIAL_POSTMORTEM),
    ("ghsa-", SOURCE_TYPE_OFFICIAL_POSTMORTEM),
]

# source_extraction_method -> hint.
_EXTRACTION_METHOD_MAP: dict[str, str] = {
    "web-scrape-rekt": SOURCE_TYPE_BLOG_ANALYSIS,
    "web-scrape-defimon": SOURCE_TYPE_BLOG_ANALYSIS,
    "web-scrape-darknavy": SOURCE_TYPE_BLOG_ANALYSIS,
    "corpus-etl": SOURCE_TYPE_CONTEST_JUDGMENT,  # typically immunefi/c4 ETL
    "human-curated": None,  # ambiguous; fall back to URL
    "corpus-etl-audit-firm": SOURCE_TYPE_AUDIT_REPORT,
    "defillama-hacks-api": SOURCE_TYPE_PROVIDER_SUMMARY,
    "cve-api": SOURCE_TYPE_OFFICIAL_POSTMORTEM,
    "ghsa-api": SOURCE_TYPE_OFFICIAL_POSTMORTEM,
}

# schema field names that signal a primary binding (tx hash, audit ref, etc.).
_PRIMARY_BINDING_FIELDS = (
    "exploit_tx_hash",
    "exploit_tx",
    "tx_hash",
    "primary_tx_hash",
    "primary_binding",
    "cve_id",
    "ghsa_id",
)

# Patterns inside field values that signal a primary tx/audit binding.
_TX_HASH_RE = re.compile(r"0x[0-9a-fA-F]{64}")
_CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)
_GHSA_RE = re.compile(r"GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}", re.IGNORECASE)
_AUDIT_REF_RE = re.compile(r"(?i)(audit|review|contest|code4rena|code[-_]423n4|sherlock|cantina|immunefi)[:\-/]")

# Proof-grade signal fields: if a record has these at non-empty value, it
# carries proof_grade signals.
_PROOF_GRADE_SIGNAL_FIELDS = (
    "exploit_preconditions",
    "attacker_action_sequence",
    "required_preconditions",
)

_PROOF_GRADE_TIERS = frozenset([
    "tier-1-verified-realtime-api",
    "tier-1-officially-disclosed",
    "tier-2-verified-public-archive",
])

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_TAGS_DIR = REPO_ROOT / "audit" / "corpus_tags" / "tags"

# Subtrees known to be external-mined / external-intelligence subtrees.
EXTERNAL_SUBTREES = [
    "bridge_incidents",
    "bridge_attacks",
    "rekt_news_incidents",
    "defimon_blog_incidents",
    "darknavy_web3_incidents",
    "defillama_hacks_delta",
    "mev_exploits",
    "mev_flashloan",
    "immunefi",
    "contest_platform_findings",
    "contest_platforms",
    "audit_firm_public_reports",
    "audit_firm_findings_pashov",
    "audit_firm_findings_sb_security",
    "evm_client_advisories",
    "evm_tooling_advisories",
    "erc4337_smart_wallet_advisories",
    "oracle_advisories",
    "orderbook_rfq_advisories",
    "restaking_lrt_advisories",
    "stablecoin_cdp_advisories",
    "lending_protocols",
    "github_advisory",
    "cve_db",
    "corpus_mined",
    "solodit_freshness_backfill_2026-05-16",
    "cosmos_sdk_ibc",
    "ethereum_client_rust",
    "l2_rollup_advisories",
    "l2_zkrollup",
    "zk_circuit_bugs",
    "zk_miners",
    "near_ink",
    "substrate_cosmwasm_advisories",
    "substrate_cosmwasm_frost",
    "substrate_fix_history",
    "solana_svm",
    "vyper_cve",
    "vyper_cve_real_source",
    "vyper_cve_2023_39363",
    "vyper_compiler_fix_history",
    "solc_compiler_bugs",
    "move_cve_advisory",
    "aptos_move",
    "move_aptos_sui",
    "sui_move",
    "evm_proxy_upgrade",
    "privacy_mixer_advisories",
    "sig_extracts",
    "amm_yield_lst_protocols",
    "major_defi_fix_history",
    "defi_fine_grain",
    "dex_fix_history",
    "nft_marketplace_advisories",
    "starknet_cairo_real",
    "solidity_fork_patterns",
]


def _as_text(v: Any) -> str:
    if v is None:
        return ""
    if isinstance(v, list):
        return " ".join(str(x) for x in v)
    return str(v).strip()


def _load_record(path: Path) -> dict[str, Any] | None:
    """Load a JSON or YAML record from *path*.  Returns None on parse failure."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    if path.suffix in (".yaml", ".yml"):
        try:
            import yaml  # type: ignore
            return yaml.safe_load(text)
        except Exception:
            return None
    else:
        try:
            return json.loads(text)
        except Exception:
            return None


def _skip_path(path: Path) -> bool:
    parts = str(path)
    return "_QUARANTINE_" in parts or "_deprecated" in parts


def _iter_records(
    tags_dir: Path,
    subtrees: list[str] | None,
    all_subtrees: bool,
) -> Iterator[tuple[Path, dict[str, Any]]]:
    """Yield (path, record_dict) for candidate files under *tags_dir*."""
    if not tags_dir.exists():
        return
    if all_subtrees:
        candidates = sorted(tags_dir.iterdir())
    elif subtrees:
        candidates = [tags_dir / s for s in subtrees]
    else:
        candidates = [tags_dir / s for s in EXTERNAL_SUBTREES]

    for sub in candidates:
        if not sub.is_dir():
            continue
        for path in sorted(sub.rglob("*.json")):
            if _skip_path(path):
                continue
            rec = _load_record(path)
            if isinstance(rec, dict):
                yield path, rec
        for path in sorted(sub.rglob("*.yaml")):
            if _skip_path(path):
                continue
            rec = _load_record(path)
            if isinstance(rec, dict):
                yield path, rec


# ---------------------------------------------------------------------------
# Source-type classification
# ---------------------------------------------------------------------------

def _classify_source_type(record: dict[str, Any]) -> tuple[str, str]:
    """Return (source_type, reason) for a record.

    Classification order:
    1. Explicit ``source_type`` field on the record (pass-through).
    2. ``record_id`` prefix lookup.
    3. ``schema`` field (darknavy, defimon custom schemas).
    4. ``source_extraction_method`` hint.
    5. URL pattern match on ``record_source_url`` / ``source_audit_ref``.
    6. Fallback to ``unknown``.
    """
    # 1. Explicit field.
    explicit = _as_text(record.get("source_type"))
    if explicit in (
        SOURCE_TYPE_OFFICIAL_POSTMORTEM,
        SOURCE_TYPE_TX_CONTRACT_TRACE,
        SOURCE_TYPE_AUDIT_REPORT,
        SOURCE_TYPE_CONTEST_JUDGMENT,
        SOURCE_TYPE_BLOG_ANALYSIS,
        SOURCE_TYPE_PROVIDER_SUMMARY,
        SOURCE_TYPE_UNKNOWN,
    ):
        return explicit, "explicit source_type field"

    # 2. record_id prefix.
    record_id = _as_text(record.get("record_id")).lower()
    for prefix, stype in _RECORD_ID_PREFIXES:
        if record_id.startswith(prefix.lower()):
            return stype, f"record_id prefix '{prefix}'"

    # 3. schema field.
    schema = _as_text(record.get("schema")).lower()
    if "darknavy" in schema:
        return SOURCE_TYPE_BLOG_ANALYSIS, "darknavy schema"
    if "defimon" in schema:
        return SOURCE_TYPE_BLOG_ANALYSIS, "defimon schema"
    if "audit_firm" in schema or "audit-firm" in schema:
        return SOURCE_TYPE_AUDIT_REPORT, "audit_firm schema"
    if "contest" in schema or "code4rena" in schema or "immunefi" in schema:
        return SOURCE_TYPE_CONTEST_JUDGMENT, "contest schema"

    # 3b. schema_version field (covers hackerman_record.v1.1 with id prefix classified above).
    schema_ver = _as_text(record.get("schema_version")).lower()
    if "audit_firm" in schema_ver:
        return SOURCE_TYPE_AUDIT_REPORT, "audit_firm schema_version"

    # 4. source_extraction_method.
    method = _as_text(record.get("source_extraction_method")).lower()
    if method in _EXTRACTION_METHOD_MAP and _EXTRACTION_METHOD_MAP[method]:
        return _EXTRACTION_METHOD_MAP[method], f"source_extraction_method='{method}'"

    # 5. URL pattern match.
    urls = []
    source_url = record.get("record_source_url")
    source_audit = record.get("source_audit_ref")
    if isinstance(source_audit, dict):
        source_audit = source_audit.get("url", "")
    for u in (source_url, source_audit):
        if u:
            urls.append(_as_text(u))

    for url in urls:
        for pat, stype in _URL_PATTERNS:
            if pat.search(url):
                return stype, f"URL pattern match on '{url[:80]}'"

    # 6. CVE/GHSA in record body fields.
    body = " ".join([
        _as_text(record.get("record_id")),
        _as_text(record.get("notes")),
        _as_text(record.get("attacker_action_sequence")),
    ])
    if _CVE_RE.search(body):
        return SOURCE_TYPE_OFFICIAL_POSTMORTEM, "CVE reference found in record body"
    if _GHSA_RE.search(body):
        return SOURCE_TYPE_OFFICIAL_POSTMORTEM, "GHSA reference found in record body"

    return SOURCE_TYPE_UNKNOWN, "no matching classification signal"


# ---------------------------------------------------------------------------
# Primary binding detection
# ---------------------------------------------------------------------------

def _has_primary_binding(record: dict[str, Any]) -> tuple[bool, str]:
    """Return (has_binding, evidence) for the record.

    A primary binding exists when the record carries ANY of:
    - An explicit tx hash (0x + 64 hex) in a known field or required_preconditions.
    - A CVE/GHSA id.
    - A source_audit_ref / record_source_url pointing to an audit, contest, or
      code4rena/sherlock/cantina/immunefi-team URL.
    - An explicit ``primary_binding`` or ``exploit_tx_hash`` field.
    """
    # Check dedicated binding fields.
    for field in _PRIMARY_BINDING_FIELDS:
        val = _as_text(record.get(field))
        if val:
            return True, f"field '{field}'='{val[:60]}'"

    # Check required_preconditions for tx hash or CVE/GHSA.
    preconditions = _as_text(record.get("required_preconditions"))
    if _TX_HASH_RE.search(preconditions):
        match = _TX_HASH_RE.search(preconditions)
        return True, f"tx hash in required_preconditions: {match.group()[:20]}..."
    if _CVE_RE.search(preconditions):
        return True, "CVE id in required_preconditions"
    if _GHSA_RE.search(preconditions):
        return True, "GHSA id in required_preconditions"

    # Check attacker_action_sequence for tx hash.
    aas = _as_text(record.get("attacker_action_sequence"))
    if _TX_HASH_RE.search(aas):
        return True, "tx hash in attacker_action_sequence"

    # Check source_audit_ref for audit/contest URL.
    source_audit = record.get("source_audit_ref")
    if isinstance(source_audit, dict):
        source_audit = source_audit.get("url", "")
    source_audit_str = _as_text(source_audit)
    if _AUDIT_REF_RE.search(source_audit_str) and "://" in source_audit_str:
        return True, f"source_audit_ref points to primary source: '{source_audit_str[:60]}'"

    # Check record_source_url for audit/contest URL.
    rsu = _as_text(record.get("record_source_url"))
    if _AUDIT_REF_RE.search(rsu) and "://" in rsu:
        return True, f"record_source_url points to primary source: '{rsu[:60]}'"

    return False, "no primary binding signal found"


# ---------------------------------------------------------------------------
# Evidence grade detection (current state)
# ---------------------------------------------------------------------------

def _current_evidence_grade(record: dict[str, Any]) -> str:
    """Infer the current evidence grade of the record.

    A record is treated as proof_grade when:
    - ``verification_tier`` is tier-1 or tier-2 AND the record has proof-shape
      fields (required_preconditions, attacker_action_sequence with content).
    - ``record_quality_score`` >= 4.0.
    - ``source_extraction_confidence`` >= 0.9.

    Otherwise it is ``hunt_context`` or ``detector_seed``.
    """
    vt = _as_text(record.get("verification_tier"))
    quality = record.get("record_quality_score")
    conf = record.get("source_extraction_confidence")

    # Explicit evidence_grade field.
    explicit = _as_text(record.get("evidence_grade"))
    if explicit in GRADE_RANK:
        return explicit

    # Tier-1/2 + proof shape = proof_grade.
    if vt in _PROOF_GRADE_TIERS:
        for field in _PROOF_GRADE_SIGNAL_FIELDS:
            val = _as_text(record.get(field))
            if val and len(val) > 20:
                return EVIDENCE_GRADE_PROOF_GRADE

    # High quality score.
    try:
        if float(quality) >= 4.0:
            return EVIDENCE_GRADE_PROOF_GRADE
    except (TypeError, ValueError):
        pass

    # High confidence.
    try:
        if float(conf) >= 0.9:
            return EVIDENCE_GRADE_PROOF_GRADE
    except (TypeError, ValueError):
        pass

    # Tier-3/4 or low quality -> detector_seed at best.
    if vt in ("tier-3-synthetic-taxonomy-anchored", "tier-4-bundled-fixture"):
        return EVIDENCE_GRADE_DETECTOR_SEED

    # Default to hunt_context.
    return EVIDENCE_GRADE_HUNT_CONTEXT


# ---------------------------------------------------------------------------
# Per-record analysis
# ---------------------------------------------------------------------------

def _analyze_record(path: Path, record: dict[str, Any], tags_dir: Path) -> dict[str, Any]:
    """Return a per-record analysis row."""
    rel = str(path.relative_to(tags_dir)) if path.is_relative_to(tags_dir) else str(path)

    source_type, st_reason = _classify_source_type(record)
    current_grade = _current_evidence_grade(record)

    # Determine permitted grade.
    if source_type in PRIMARY_SOURCE_TYPES:
        permitted_grade = EVIDENCE_GRADE_PROOF_GRADE
        binding_note = "primary source type - no binding required"
        has_binding = True
    else:
        # Secondary type: check for primary binding upgrade.
        has_binding, binding_note = _has_primary_binding(record)
        if has_binding:
            # Binding present - allow proof_grade even for blog/provider.
            permitted_grade = EVIDENCE_GRADE_PROOF_GRADE
        else:
            permitted_grade = MAX_GRADE_BY_SOURCE_TYPE[source_type]

    # Determine if this is a violation.
    current_rank = GRADE_RANK.get(current_grade, 1)
    permitted_rank = GRADE_RANK.get(permitted_grade, 1)
    violation = current_rank > permitted_rank

    reason_parts = [f"source_type={source_type} ({st_reason})"]
    if not has_binding and source_type in SECONDARY_SOURCE_TYPES:
        reason_parts.append(f"no primary binding ({binding_note})")
    elif has_binding and source_type in SECONDARY_SOURCE_TYPES:
        reason_parts.append(f"primary binding present: {binding_note}")

    return {
        "record_path": rel,
        "record_id": _as_text(record.get("record_id")) or "(no record_id)",
        "detected_source_type": source_type,
        "source_type_reason": st_reason,
        "current_grade": current_grade,
        "permitted_grade": permitted_grade,
        "has_primary_binding": has_binding,
        "primary_binding_note": binding_note,
        "violation": violation,
        "reason": "; ".join(reason_parts),
    }


# ---------------------------------------------------------------------------
# Main scan logic
# ---------------------------------------------------------------------------

def _scan(
    tags_dir: Path,
    subtrees: list[str] | None,
    all_subtrees: bool,
) -> dict[str, Any]:
    """Scan records and return a report dict."""
    scanned_dirs: list[str] = []
    missing_dirs: list[str] = []

    if all_subtrees:
        scan_list = sorted(d.name for d in tags_dir.iterdir() if d.is_dir()) if tags_dir.exists() else []
    elif subtrees:
        scan_list = subtrees
    else:
        scan_list = EXTERNAL_SUBTREES

    for s in scan_list:
        d = tags_dir / s
        if d.is_dir():
            scanned_dirs.append(s)
        else:
            missing_dirs.append(s)

    records_scanned = 0
    violations: list[dict[str, Any]] = []
    source_type_counts: dict[str, int] = {}
    parse_errors = 0

    for path, record in _iter_records(tags_dir, subtrees, all_subtrees):
        records_scanned += 1
        row = _analyze_record(path, record, tags_dir)
        st = row["detected_source_type"]
        source_type_counts[st] = source_type_counts.get(st, 0) + 1
        if row["violation"]:
            violations.append(row)

    return {
        "schema_id": SCHEMA_ID,
        "gate": GATE_NAME,
        "tags_dir": str(tags_dir),
        "scanned_dirs": scanned_dirs,
        "missing_dirs": missing_dirs,
        "records_scanned": records_scanned,
        "parse_errors": parse_errors,
        "violations_count": len(violations),
        "source_type_counts": source_type_counts,
        "violations": violations,
    }


# ---------------------------------------------------------------------------
# Output formatters
# ---------------------------------------------------------------------------

def _human_report(report: dict[str, Any], verbose: bool) -> str:
    lines: list[str] = []
    lines.append(f"=== {GATE_NAME} (schema={SCHEMA_ID}) ===")
    lines.append(f"Tags dir   : {report['tags_dir']}")
    lines.append(f"Scanned    : {report['records_scanned']} records across {len(report['scanned_dirs'])} subtrees")
    if report["missing_dirs"]:
        lines.append(f"Missing    : {', '.join(report['missing_dirs'][:10])}" + (
            f" (+{len(report['missing_dirs'])-10} more)" if len(report["missing_dirs"]) > 10 else ""
        ))
    lines.append(f"Violations : {report['violations_count']}")
    lines.append("")

    st_counts = report["source_type_counts"]
    lines.append("Source type distribution:")
    for st in [
        SOURCE_TYPE_OFFICIAL_POSTMORTEM,
        SOURCE_TYPE_TX_CONTRACT_TRACE,
        SOURCE_TYPE_AUDIT_REPORT,
        SOURCE_TYPE_CONTEST_JUDGMENT,
        SOURCE_TYPE_BLOG_ANALYSIS,
        SOURCE_TYPE_PROVIDER_SUMMARY,
        SOURCE_TYPE_UNKNOWN,
    ]:
        n = st_counts.get(st, 0)
        if n or verbose:
            lines.append(f"  {st:<28}: {n}")
    lines.append("")

    if report["violations"]:
        lines.append(f"VIOLATIONS ({report['violations_count']}):")
        for v in report["violations"]:
            lines.append(f"  - {v['record_path']}")
            lines.append(f"      record_id     : {v['record_id']}")
            lines.append(f"      source_type   : {v['detected_source_type']} ({v['source_type_reason']})")
            lines.append(f"      current_grade : {v['current_grade']}")
            lines.append(f"      permitted_grade: {v['permitted_grade']}")
            lines.append(f"      reason        : {v['reason']}")
    else:
        lines.append("No violations found.")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "--tags-dir",
        default=str(DEFAULT_TAGS_DIR),
        help="Root of corpus tags directory (default: audit/corpus_tags/tags/)",
    )
    p.add_argument(
        "--subtrees",
        nargs="*",
        default=None,
        help="Specific subtree names to scan (default: known external subtrees). "
             "Pass no value to scan default set.",
    )
    p.add_argument(
        "--all-subtrees",
        action="store_true",
        default=False,
        help="Scan ALL subtrees under tags-dir (overrides --subtrees).",
    )
    p.add_argument(
        "--strict",
        action="store_true",
        default=False,
        help="Exit 1 when any secondary-only proof_grade record is found.",
    )
    p.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        default=False,
        help="Emit machine-readable JSON report.",
    )
    p.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        default=False,
        help="Show all source_type counts even when zero.",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    tags_dir = Path(args.tags_dir)
    subtrees: list[str] | None = args.subtrees  # None = use default EXTERNAL_SUBTREES

    try:
        report = _scan(tags_dir, subtrees, args.all_subtrees)
    except Exception as exc:
        if args.json_output:
            print(json.dumps({"schema_id": SCHEMA_ID, "error": str(exc)}, indent=2))
        else:
            print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    if args.json_output:
        print(json.dumps(report, indent=2, default=str))
    else:
        print(_human_report(report, args.verbose))

    # Strict mode: exit 1 if violations exist.
    if args.strict and report["violations_count"] > 0:
        if not args.json_output:
            print(
                f"\nSTRICT MODE: {report['violations_count']} secondary-only proof_grade "
                "record(s) found. Exit 1.",
                file=sys.stderr,
            )
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
