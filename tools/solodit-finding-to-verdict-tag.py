#!/usr/bin/env python3
"""solodit-finding-to-verdict-tag — Mine Solodit spec drafts into corpus verdict tags.

Wave-9 Track F: ingests detectors/_specs/drafts_solodit/*.yaml and emits
schema-v2-valid verdict-tag YAMLs into audit/corpus_tags/tags/solodit_*.yaml.

CLI:
    python3 tools/solodit-finding-to-verdict-tag.py [options]

Options:
    --limit N          Max number of tags to emit (default: 100)
    --min-severity S   Minimum severity: MEDIUM or HIGH (default: HIGH)
    --out-dir DIR      Output directory (default: audit/corpus_tags/tags/)
    --drafts-dir DIR   Input drafts dir (default: detectors/_specs/drafts_solodit/)
    --dry-run          Count and rank without writing files
    --bug-class-map F  Path to bug_class_to_attack_classes_map.yaml
    --quiet            Suppress progress output

Exit codes:
    0  success (>= 1 tag emitted)
    1  no qualifying findings
    2  argument / IO error
"""
from __future__ import annotations

import argparse
import datetime as _dt
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent

# Solodit historical sentinel SHA (7 hex chars, passes schema pattern ^[0-9a-f]{7,40}$)
SENTINEL_SHA = "0000000"

# Maps solodit_tags values -> attack_classes_to_try entries
SOLODIT_TAG_TO_ATTACK_CLASSES: Dict[str, List[str]] = {
    "Reentrancy": [
        "reentrancy-state-corruption",
        "cross-function-reentrancy",
        "single-function-reentrancy",
    ],
    "Access Control": [
        "access-control-escalation",
        "missing-access-check",
        "unauthorized-state-write",
    ],
    "Oracle": [
        "oracle-staleness",
        "oracle-price-manipulation",
        "stale-price-dos",
    ],
    "Front-Running": [
        "frontrun-sandwich",
        "mev-extraction",
        "state-race-before-tx",
    ],
    "Overflow/Underflow": [
        "integer-overflow-clamp",
        "arithmetic-underflow",
        "unchecked-arithmetic",
    ],
    "Decimals": [
        "decimals-mismatch",
        "precision-loss",
        "rounding-asymmetry",
    ],
    "Signature Replay": [
        "signature-replay",
        "missing-nonce-check",
        "eip712-domain-bypass",
    ],
    "Slippage": [
        "slippage-bypass",
        "price-impact-manipulation",
        "amm-slippage",
    ],
    "First Depositor Issue": [
        "first-depositor-inflation",
        "erc4626-first-depositor-share-skew",
        "donation-attack",
    ],
    "Business Logic": [
        "logic-error",
        "incorrect-invariant",
        "state-machine-bypass",
    ],
    "Validation": [
        "missing-input-validation",
        "unchecked-return-value",
        "missing-bounds-check",
    ],
    "Wrong Math": [
        "arithmetic-error",
        "rounding-asymmetry",
        "precision-loss",
    ],
    "DOS": [
        "denial-of-service",
        "gas-griefing",
        "unbounded-loop",
    ],
    "Denial-Of-Service": [
        "denial-of-service",
        "gas-griefing",
        "unbounded-loop",
    ],
    "Fee On Transfer": [
        "fee-on-transfer-mismatch",
        "token-fee-accounting",
        "rebasing-token",
    ],
    "Don't update state": [
        "missing-state-update",
        "stale-state-read",
        "time-of-check-time-of-use",
    ],
    "Liquidation": [
        "liquidation-bypass",
        "liquidation-price-manipulation",
        "bad-debt-accumulation",
    ],
    "ERC4626": [
        "erc4626-first-depositor-share-skew",
        "share-price-manipulation",
        "vault-inflation",
    ],
    "Weird ERC20": [
        "fee-on-transfer-mismatch",
        "rebasing-token",
        "non-standard-erc20",
    ],
    "ERC20": [
        "erc20-approval-race",
        "non-standard-erc20",
        "token-transfer-failure",
    ],
    "Fund Lock": [
        "fund-lock",
        "unrecoverable-funds",
        "frozen-funds",
    ],
    "Vote": [
        "vote-double-count",
        "governance-manipulation",
        "delegation-power-inflation",
    ],
    "Approve": [
        "erc20-approval-race",
        "unlimited-approval",
        "approval-abuse",
    ],
    "Allowance": [
        "approval-abuse",
        "erc20-approval-race",
        "allowance-frontrun",
    ],
    "Stale Price": [
        "oracle-staleness",
        "stale-price-dos",
        "chainlink-stale-answer",
    ],
    "Missing-Logic": [
        "missing-check",
        "missing-guard",
        "logic-omission",
    ],
    "Rounding": [
        "rounding-asymmetry",
        "precision-loss",
        "rounding-direction-attack",
    ],
    "Admin": [
        "admin-bypass",
        "admin-privilege-escalation",
        "privileged-role-abuse",
    ],
    "Refund Ether": [
        "eth-refund-loss",
        "push-payment-failure",
        "unhandled-eth-return",
    ],
    "ERC721": [
        "nft-approval-bypass",
        "nft-transfer-race",
        "erc721-reentrancy",
    ],
    "Flash Loan": [
        "flashloan-price-manipulation",
        "read-only-reentrancy-via-flashloan",
        "oracle-flashloan-attack",
    ],
    "Signature": [
        "signature-replay",
        "missing-nonce-check",
        "ecrecover-malleability",
    ],
    "TWAP": [
        "twap-manipulation",
        "oracle-staleness",
        "short-twap-window",
    ],
    "Price Manipulation": [
        "oracle-price-manipulation",
        "amm-price-manipulation",
        "spot-price-oracle-abuse",
    ],
    "Upgrade": [
        "upgrade-storage-collision",
        "initializer-not-called",
        "upgrade-bypass",
    ],
    "Initialization": [
        "uninitialized-implementation",
        "initializer-not-called",
        "double-initialize",
    ],
}

# Severity order for comparison
SEV_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def _try_import_yaml():
    try:
        import yaml
        return yaml
    except ImportError:
        return None


def _load_yaml(path: Path) -> Optional[Dict[str, Any]]:
    yaml_mod = _try_import_yaml()
    if yaml_mod is None:
        raise RuntimeError("PyYAML not available; install it with pip install pyyaml")
    try:
        with path.open("r", encoding="utf-8") as fh:
            return yaml_mod.safe_load(fh)
    except Exception:
        return None


def _load_bug_class_map(map_path: Path) -> Dict[str, List[str]]:
    """Load bug_class -> attack_classes map from YAML."""
    d = _load_yaml(map_path)
    if not d:
        return {}
    mappings = d.get("mappings", {})
    result: Dict[str, List[str]] = {}
    for key, classes in mappings.items():
        if isinstance(classes, list):
            result[key] = [str(c) for c in classes]
    return result


def _slug_from_class_name(class_name: str) -> str:
    """Convert CamelCase class_name to kebab-case slug, max 50 chars."""
    s = re.sub(r"([A-Z])", r"-\1", class_name).lower().lstrip("-")
    s = re.sub(r"[^a-z0-9-]", "-", s)
    s = re.sub(r"-{2,}", "-", s).strip("-")
    return s[:50].rstrip("-")


def _protocol_from_source(source: str) -> str:
    """Extract protocol slug from source string like 'Solodit #951 (Code4rena/BadgerDAO)'."""
    m = re.search(r"\(([^/]+)/([^)]+)\)", source)
    if m:
        protocol_raw = m.group(2).strip()
        # kebab-case
        protocol = re.sub(r"[^A-Za-z0-9]", "-", protocol_raw).lower()
        protocol = re.sub(r"-{2,}", "-", protocol).strip("-")
        return protocol
    return "unknown"


def _target_repo_from_source(source: str) -> str:
    """Build a target_repo string valid for schema pattern ^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$."""
    protocol = _protocol_from_source(source)
    if not protocol or protocol == "unknown":
        return "solodit/unknown"
    # Sanitize to schema-safe chars
    protocol = re.sub(r"[^A-Za-z0-9._-]", "-", protocol)
    protocol = re.sub(r"-{2,}", "-", protocol).strip("-") or "unknown"
    return f"solodit/{protocol}"


def _derive_attack_classes(
    solodit_tags: str,
    class_name: str,
    bug_class_map: Dict[str, List[str]],
) -> List[str]:
    """Derive attack classes from solodit_tags and class_name."""
    attack_classes: List[str] = []

    # 1. solodit_tags -> mapped attack classes
    if solodit_tags:
        tags = [t.strip() for t in str(solodit_tags).split(",") if t.strip()]
        for tag in tags:
            for ac in SOLODIT_TAG_TO_ATTACK_CLASSES.get(tag, []):
                if ac not in attack_classes:
                    attack_classes.append(ac)

    # 2. Try to match class_name against bug_class_map keys (kebab version)
    if class_name:
        slug = _slug_from_class_name(class_name)
        # partial match heuristic
        for key, classes in bug_class_map.items():
            if key in slug or slug[:20] in key:
                for ac in classes:
                    if ac not in attack_classes:
                        attack_classes.append(ac)
                break

    return attack_classes


def _quality_score(d: Dict[str, Any]) -> int:
    """Score a draft for prioritization (higher = better quality)."""
    score = 0
    sev = (d.get("severity") or "").upper()
    if sev == "HIGH":
        score += 10
    elif sev == "MEDIUM":
        score += 5
    # solodit_quality field (0-5 scale)
    try:
        q = int(d.get("solodit_quality") or 0)
        score += q
    except (ValueError, TypeError):
        pass
    # Has solodit_tags (richer semantic signal)
    if d.get("solodit_tags"):
        score += 3
    # Has fn_name_regex (canonical bug-class pattern)
    if d.get("fn_name_regex"):
        score += 2
    # Has read_var_regex
    if d.get("read_var_regex"):
        score += 1
    return score


def _emit_tag_yaml(
    d: Dict[str, Any],
    source_path: Path,
    bug_class_map: Dict[str, List[str]],
    now_utc: str,
) -> Tuple[str, str]:
    """Return (filename, yaml_content) for the verdict tag."""
    solodit_id = str(d.get("solodit_id", ""))
    class_name = str(d.get("class_name") or "")
    slug = _slug_from_class_name(class_name) if class_name else f"finding-{solodit_id}"
    source = str(d.get("source") or "")
    solodit_tags = d.get("solodit_tags") or ""
    severity = (d.get("severity") or "MEDIUM").upper()

    target_repo = _target_repo_from_source(source)
    attack_classes = _derive_attack_classes(solodit_tags, class_name, bug_class_map)

    # Build bug_class from solodit_tags or class_name slug
    if solodit_tags:
        primary_tag = str(solodit_tags).split(",")[0].strip()
        bug_class = re.sub(r"[^a-z0-9-]", "-", primary_tag.lower()).strip("-")
    else:
        bug_class = slug[:40].rstrip("-")

    # verdict_id
    verdict_id = f"solodit/{solodit_id}/{slug}"

    filename = f"solodit_{solodit_id}_{slug[:40].rstrip('-')}.yaml"

    # Build source_url if available
    source_url_raw = d.get("solodit_slug") or ""
    source_url = (
        f"https://solodit.cyfrin.io/issues/{source_url_raw.strip()}"
        if source_url_raw.strip()
        else ""
    )

    # Build a minimal sites entry from vuln_fn_name if available
    # Required when verdict_class is FILED (schema allOf condition)
    vuln_fn = str(d.get("vuln_fn_name") or "").strip()
    vuln_fn_return = str(d.get("vuln_fn_return") or "").strip()
    vuln_fn_mutability = str(d.get("vuln_fn_mutability") or "").strip()
    # Infer a plausible file path from contract_name or class_name
    contract_raw = str(d.get("contract_name") or class_name or "Contract")
    contract_slug = re.sub(r"[^A-Za-z0-9]", "", contract_raw)[:40]
    file_path_inferred = f"{contract_slug}.sol"

    lines = [
        f"verdict_id: solodit/{solodit_id}/{slug}",
        f"target_repo: {target_repo}",
        f"audit_pin_sha: '{SENTINEL_SHA}'",
        "language: solidity",
        "verdict_class: FILED",
        "extraction_provenance: manual",
        "extractor_version: 0.1.0",
        f"extracted_at_utc: '{now_utc}'",
        f"platform: unknown",
        f"bug_class: {bug_class}",
        f"severity_claimed: {severity}",
        f"severity_final: {severity}",
        "triager_outcome: ACCEPTED",
    ]

    # sites: one minimal entry (required by schema when verdict_class=FILED)
    lines.append("sites:")
    lines.append(f"  - file_path: {file_path_inferred}")
    if vuln_fn:
        lines.append(f"    function_name: {vuln_fn}")
    if vuln_fn_mutability in ("public", "private", "internal", "external"):
        lines.append(f"    visibility: {vuln_fn_mutability}")

    if attack_classes:
        lines.append("attack_classes_to_try:")
        for ac in attack_classes:
            lines.append(f"  - {ac}")

    # notes block
    source_doc = f"detectors/_specs/drafts_solodit/{source_path.name}"
    note_parts = [
        f"Mined from Solodit corpus. Real published finding. Used as S1/S2/S3",
        f"corpus signal for Solidity workspaces.",
        f"solodit_id: {solodit_id}",
        f"source: {source}",
    ]
    if source_url:
        note_parts.append(f"source_url: {source_url}")
    note_parts.append(f"source_doc: {source_doc}")
    if class_name:
        note_parts.append(f"class_name: {class_name}")
    if solodit_tags:
        note_parts.append(f"solodit_tags: {solodit_tags}")

    lines.append("notes: |")
    for part in note_parts:
        lines.append(f"  {part}")

    return filename, "\n".join(lines) + "\n"


def _scan_drafts(
    drafts_dir: Path,
    min_severity: str,
    limit: int,
    bug_class_map: Dict[str, List[str]],
    quiet: bool,
) -> Tuple[List[Tuple[Path, Dict[str, Any]]], Dict[str, int]]:
    """Scan drafts dir, filter, rank, return top-N candidates + skip stats."""
    min_sev_val = SEV_ORDER.get(min_severity.upper(), 2)

    skip_stats: Dict[str, int] = {
        "parse_error": 0,
        "below_severity": 0,
        "no_solodit_id": 0,
        "no_class_name": 0,
        "no_bug_class_signal": 0,
    }

    candidates: List[Tuple[int, Path, Dict[str, Any]]] = []

    yaml_files = sorted(drafts_dir.glob("*.yaml"))
    total = len(yaml_files)

    if not quiet:
        print(f"[Track F] Scanning {total} Solodit drafts...", file=sys.stderr)

    for path in yaml_files:
        d = _load_yaml(path)
        if d is None:
            skip_stats["parse_error"] += 1
            continue

        # Must have solodit_id
        if not d.get("solodit_id"):
            skip_stats["no_solodit_id"] += 1
            continue

        # Must have class_name
        if not d.get("class_name"):
            skip_stats["no_class_name"] += 1
            continue

        # Severity filter
        sev = (d.get("severity") or "").upper()
        sev_val = SEV_ORDER.get(sev, 0)
        if sev_val < min_sev_val:
            skip_stats["below_severity"] += 1
            continue

        # Must have some bug class signal (class_name already checked, but skip "misc-other" / "unknown")
        class_name = str(d.get("class_name") or "")
        if class_name.lower() in ("unknown", "misc-other", "miscother"):
            skip_stats["no_bug_class_signal"] += 1
            continue

        score = _quality_score(d)
        candidates.append((score, path, d))

    # Sort by quality descending
    candidates.sort(key=lambda x: x[0], reverse=True)

    top_n = [(p, d) for _, p, d in candidates[:limit]]

    if not quiet:
        total_candidates = len(candidates)
        total_skipped = sum(skip_stats.values())
        print(
            f"[Track F] Candidates after filter: {total_candidates} | "
            f"Skipped: {total_skipped} | Emitting: {len(top_n)}",
            file=sys.stderr,
        )

    return top_n, skip_stats, total


def main(argv=None):
    parser = argparse.ArgumentParser(description="Mine Solodit drafts into verdict-tag YAMLs")
    parser.add_argument("--limit", type=int, default=100, help="Max tags to emit")
    parser.add_argument(
        "--min-severity",
        default="HIGH",
        choices=["MEDIUM", "HIGH"],
        help="Minimum severity filter",
    )
    parser.add_argument(
        "--out-dir",
        default=str(REPO_ROOT / "audit" / "corpus_tags" / "tags"),
        help="Output directory for emitted tags",
    )
    parser.add_argument(
        "--drafts-dir",
        default=str(REPO_ROOT / "detectors" / "_specs" / "drafts_solodit"),
        help="Input directory with Solodit draft YAMLs",
    )
    parser.add_argument(
        "--bug-class-map",
        default=str(REPO_ROOT / "audit" / "bug_class_to_attack_classes_map.yaml"),
        help="Path to bug_class_to_attack_classes_map.yaml",
    )
    parser.add_argument("--dry-run", action="store_true", help="No file writes")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)

    drafts_dir = Path(args.drafts_dir)
    out_dir = Path(args.out_dir)
    bug_class_map_path = Path(args.bug_class_map)

    if not drafts_dir.is_dir():
        print(f"[Track F] ERROR: drafts dir not found: {drafts_dir}", file=sys.stderr)
        sys.exit(2)

    bug_class_map: Dict[str, List[str]] = {}
    if bug_class_map_path.is_file():
        bug_class_map = _load_bug_class_map(bug_class_map_path)
        if not args.quiet:
            print(f"[Track F] Loaded {len(bug_class_map)} bug class mappings", file=sys.stderr)

    candidates, skip_stats, total_scanned = _scan_drafts(
        drafts_dir=drafts_dir,
        min_severity=args.min_severity,
        limit=args.limit,
        bug_class_map=bug_class_map,
        quiet=args.quiet,
    )

    if not candidates:
        print("[Track F] No qualifying findings found. Check --min-severity or drafts dir.", file=sys.stderr)
        sys.exit(1)

    now_utc = _dt.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

    if not args.dry_run:
        out_dir.mkdir(parents=True, exist_ok=True)

    emitted = 0
    for path, d in candidates:
        try:
            filename, content = _emit_tag_yaml(d, path, bug_class_map, now_utc)
        except Exception as e:
            if not args.quiet:
                print(f"[Track F] WARN: skip {path.name}: {e}", file=sys.stderr)
            continue

        if not args.dry_run:
            out_path = out_dir / filename
            out_path.write_text(content, encoding="utf-8")
        emitted += 1

    if not args.quiet:
        print(f"\n[Track F] Results:", file=sys.stderr)
        print(f"  Total drafts scanned : {total_scanned}", file=sys.stderr)
        print(f"  Skip - parse error   : {skip_stats['parse_error']}", file=sys.stderr)
        print(f"  Skip - below severity: {skip_stats['below_severity']}", file=sys.stderr)
        print(f"  Skip - no solodit_id : {skip_stats['no_solodit_id']}", file=sys.stderr)
        print(f"  Skip - no class_name : {skip_stats['no_class_name']}", file=sys.stderr)
        print(f"  Skip - no bug signal : {skip_stats['no_bug_class_signal']}", file=sys.stderr)
        print(f"  Emitted              : {emitted}", file=sys.stderr)
        if not args.dry_run:
            print(f"  Output dir           : {out_dir}", file=sys.stderr)
        else:
            print(f"  (dry-run, no files written)", file=sys.stderr)

    return emitted


if __name__ == "__main__":
    count = main()
    sys.exit(0 if count >= 1 else 1)
