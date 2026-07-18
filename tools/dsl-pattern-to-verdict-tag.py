#!/usr/bin/env python3
"""dsl-pattern-to-verdict-tag — Wave-9 Track D corpus diversifier.

Converts canonical DSL patterns in ``reference/patterns.dsl/*.yaml`` into
verdict-tag stubs (schema v2, ``verdict_class: CANDIDATE``) written to
``audit/corpus_tags/tags/dsl_pattern_<slug>.yaml``.

The synthesized tags give the ranker Solidity corpus signal at parity with the
90%+ Go corpus that comes from dydx/spark engagement verdict tags.

Algorithm
---------
1. Walk ``reference/patterns.dsl/*.yaml`` (NOT subdirectories such as
   ``_held``, ``_quarantine``, ``r78_reth_chain``, ``r99_pdf_mined``).
2. Skip patterns marked:
   - ``status`` in {``not-submit-ready``, ``NOT_SUBMIT_READY``,
     ``documentation-only``, ``handwritten-detector``,
     ``blocked_semantic_detector``}
   - ``submission_posture: NOT_SUBMIT_READY``
   - ``wiring_status: documentation_only_text_pattern_no_executable_detector``
   - No ``match`` block (nothing to synthesize a site from)
3. Derive ``bug_class`` from pattern slug keywords + source provenance.
4. Look up ``attack_classes_to_try`` from
   ``audit/bug_class_to_attack_classes_map.yaml`` (best-effort; leave empty
   with log on miss).
5. Synthesize a shape_hash from the visibility predicate (if present) and
   default flags for Solidity.
6. Emit a v2-schema-valid YAML to ``audit/corpus_tags/tags/dsl_pattern_<slug>.yaml``.
7. Re-run is idempotent: overwrites existing ``dsl_pattern_*.yaml`` but never
   touches non-DSL tags.

CLI
---
    python3 tools/dsl-pattern-to-verdict-tag.py [--dry-run] [--limit N]
        [--out-dir <tags_dir>] [--report <path>]

Exit codes: 0 = success, 1 = fatal error.

Constraints (Wave-9 Track D)
-----------------------------
- Never modifies ``reference/patterns.dsl/*.yaml`` (read-only).
- Never modifies non-DSL tags (names must start with ``dsl_pattern_``).
- Does NOT touch ``tools/calibration/llm_budget_log.jsonl``.
- All emitted tags validate against schema v2.
"""
from __future__ import annotations

import argparse
import collections
import datetime
import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    import yaml  # type: ignore
    _HAS_YAML = True
except ImportError:
    _HAS_YAML = False

REPO_ROOT = Path(__file__).resolve().parent.parent
DSL_DIR = REPO_ROOT / "reference" / "patterns.dsl"
TAGS_DIR = REPO_ROOT / "audit" / "corpus_tags" / "tags"
BUG_CLASS_MAP_PATH = REPO_ROOT / "audit" / "bug_class_to_attack_classes_map.yaml"
SCHEMA_V2_PATH = REPO_ROOT / "audit" / "corpus_tags" / "auditooor.verdict_tag.v2.schema.json"

EMITTER_VERSION = "0.1.0"
# Synthetic audit pin SHA for DSL-pattern-derived tags (7 hex zeros = valid hex >= 7 chars)
DSL_SYNTHETIC_SHA = "0000000"
DSL_TARGET_REPO = "unknown/dsl-synthetic"

# Subdirectory names to skip inside DSL_DIR
SKIP_SUBDIRS: Set[str] = {"_held", "_quarantine", "r78_reth_chain", "r99_pdf_mined"}

# Status values that trigger a skip
SKIP_STATUSES: Set[str] = {
    "not-submit-ready",
    "NOT_SUBMIT_READY",
    "documentation-only",
    "handwritten-detector",
    "blocked_semantic_detector",
}

# ─────────────────────────────────────────────────────────────────────────────
# Bug-class derivation from pattern slug keywords
# ─────────────────────────────────────────────────────────────────────────────

# Ordered list of (keyword_set, bug_class) pairs. First match wins.
# Keywords are checked as substring matches against the lowercased slug.
SLUG_TO_BUG_CLASS: List[Tuple[List[str], str]] = [
    (["reentrancy", "reentrant", "reenter"], "reentrancy"),
    (["flash-loan", "flashloan", "flash_loan"], "flash-loan-attack"),
    (["oracle", "price-manip", "price_manip", "twap", "chainlink", "stale-price",
      "latestanswer", "latestrounddata"], "oracle-price-manipulation"),
    (["overflow", "underflow", "arithmetic", "integer-overflow", "int-overflow",
      "uint-overflow"], "integer-overflow-underflow"),
    (["toctou", "time-of-check", "timestamp", "block.timestamp",
      "time-manip", "block-manip"], "time-of-check-time-of-use"),
    (["access-control", "access_control", "authorization", "privilege",
      "onlyowner", "only-owner", "role", "acl", "admin-bypass",
      "admin_bypass"], "access-control"),
    (["denial-of-service", "dos", "griefing", "block-user",
      "obstruct"], "denial-of-service"),
    (["signature", "sig-replay", "replay", "ecrecover", "permit",
      "eip712", "eip-712", "malleability"], "signature-replay"),
    (["precision", "rounding", "division", "truncat"], "precision-loss"),
    (["frontrun", "front-run", "sandwich", "mev", "slippage"], "frontrunning"),
    (["cross-chain", "bridge", "relay", "teleport", "ibc",
      "message-replay", "dispatch"], "cross-chain-bridge"),
    (["delegate", "delegat", "proxy", "upgradeable",
      "upgrade", "implementation"], "proxy-upgrade"),
    (["storage", "slot", "collision"], "storage-collision"),
    (["donation", "inflation", "share-price", "share_price",
      "first-deposit"], "token-share-inflation"),
    (["freeze", "lock", "stuck", "frozen"], "funds-freeze"),
    (["callback", "hook", "post-hook", "aftertoken"], "callback-hook-bypass"),
    (["withdrawal", "withdraw", "claim", "redeem", "unlock"], "withdrawal-logic"),
    (["liquidation", "liquidate", "collateral"], "liquidation-logic"),
    (["fee", "rebate", "reward", "emission", "distribute"], "fee-accounting"),
    (["invariant", "accounting", "balance", "totalSupply", "total-supply",
      "totalassets", "total-assets"], "accounting-invariant"),
    (["allowance", "approve", "transferfrom", "transfer-from"], "erc20-allowance"),
    (["kill", "gauge", "terminated", "deprecated"], "killed-gauge"),
    (["auction", "bid", "reserve-price"], "auction-logic"),
    (["governance", "proposal", "voting", "quorum", "guardian",
      "cancel", "timelock"], "governance"),
    (["randomness", "rng", "entropy", "vrf"], "randomness-manipulation"),
    (["nft", "token-id", "tokenid", "erc721", "erc-721"], "nft-logic"),
    (["gas", "out-of-gas", "oog"], "gas-griefing"),
    (["seaport", "marketplace", "listing"], "marketplace-logic"),
    (["migration", "upgrade-handler", "genesis"], "migration-upgrade"),
    (["erc4626", "vault", "asset", "share"], "erc4626-vault"),
    (["buyback", "revenue", "sweep"], "revenue-accounting"),
    (["escrow", "custody"], "custody-logic"),
    (["airdrop", "merkle", "drop"], "merkle-airdrop"),
]


def derive_bug_class(slug: str, source: str, help_text: str) -> str:
    """Derive a hyphen-cased bug_class from the pattern slug + source + help text.

    Uses the SLUG_TO_BUG_CLASS table for deterministic, keyword-driven matching.
    Falls back to 'unknown-bug-class' when no keyword fires.
    """
    combined = (slug + " " + (source or "") + " " + (help_text or "")).lower()
    for keywords, bug_class in SLUG_TO_BUG_CLASS:
        for kw in keywords:
            if kw in combined:
                return bug_class
    return "unknown-bug-class"


# ─────────────────────────────────────────────────────────────────────────────
# Attack-class map loader
# ─────────────────────────────────────────────────────────────────────────────

def load_bug_class_map(path: Path) -> Dict[str, List[str]]:
    """Load audit/bug_class_to_attack_classes_map.yaml -> {bug_class: [attack_classes]}."""
    if not path.exists():
        return {}
    try:
        if _HAS_YAML:
            with path.open("r", encoding="utf-8") as fh:
                d = yaml.safe_load(fh)
        else:
            d = _minimal_yaml_load(path)
        return d.get("mappings", {}) if isinstance(d, dict) else {}
    except Exception:
        return {}


# ─────────────────────────────────────────────────────────────────────────────
# Shape-hash synthesis (Solidity default)
# ─────────────────────────────────────────────────────────────────────────────

def synthesize_shape_hash(visibility: str, has_reentrancy_guard: bool = False) -> str:
    """Compute a synthetic shape_hash for a DSL pattern site.

    Uses the same 6-field canonical string as tools/shape-hash.py but with
    Solidity defaults for fields we cannot extract from a DSL pattern alone:
    - params/returns: empty (DSL predicates name regex patterns, not types)
    - receiver_type: 'misc-family' (default)
    - flags: visibility=exported when public/external; guards from predicate
    """
    exported = 1 if visibility in ("public", "external", "exported") else 0
    reentrancy = 1 if has_reentrancy_guard else 0
    flag_str = f"{exported}0{reentrancy}000"  # exported,authority,pause,reentrancy,blocked,mutates
    canonical = "|".join([
        "lang=solidity",
        "params=",
        "returns=",
        f"flags={flag_str}",
        "family=misc-family",
        "fine=0",
    ])
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]


# ─────────────────────────────────────────────────────────────────────────────
# Visibility extractor
# ─────────────────────────────────────────────────────────────────────────────

def extract_visibility(match_predicates: List[Dict]) -> str:
    """Extract visibility from DSL match predicates if present, else 'external'."""
    for m in match_predicates:
        if not isinstance(m, dict):
            continue
        vis = m.get("function.visibility")
        if vis and isinstance(vis, str):
            vis_lc = vis.lower().strip()
            if vis_lc in ("public", "external", "internal", "private"):
                return vis_lc
    return "external"  # Solidity default


def extract_guard_hints(match_predicates: List[Dict]) -> bool:
    """Return True if any predicate suggests a reentrancy guard is present."""
    for m in match_predicates:
        if not isinstance(m, dict):
            continue
        for k, v in m.items():
            if "reentrancy" in k.lower():
                return True
            if isinstance(v, str) and "nonReentrant" in v:
                return True
    return False


def extract_name_regex(match_predicates: List[Dict]) -> str:
    """Extract the function.name_matches regex from predicates."""
    for m in match_predicates:
        if not isinstance(m, dict):
            continue
        for k in ("function.name_matches", "function.name_matches_regex"):
            if k in m and isinstance(m[k], str):
                return m[k]
    return "(synthetic)"


# ─────────────────────────────────────────────────────────────────────────────
# Slug normalizer
# ─────────────────────────────────────────────────────────────────────────────

def slugify(pattern_name: str) -> str:
    """Produce a filesystem-safe slug from a pattern name.

    Strips non-alnum characters, lowercases, collapses hyphens.
    """
    s = re.sub(r"[^A-Za-z0-9-]", "-", pattern_name)
    s = re.sub(r"-+", "-", s).strip("-").lower()
    return s[:120]  # cap length


# ─────────────────────────────────────────────────────────────────────────────
# Minimal YAML loader (stdlib fallback)
# ─────────────────────────────────────────────────────────────────────────────

def _minimal_yaml_load(path: Path) -> Any:
    """Very limited YAML loader for flat DSL patterns (fallback when PyYAML missing)."""
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    root: Dict[str, Any] = {}
    i = 0
    while i < len(lines):
        ln = lines[i].rstrip()
        if not ln or ln.lstrip().startswith("#"):
            i += 1
            continue
        if ":" in ln and not ln.startswith(" "):
            key, _, rest = ln.partition(":")
            key = key.strip()
            rest = rest.strip()
            if rest == "":
                # might be a block
                block_items: List[Any] = []
                i += 1
                while i < len(lines) and (lines[i].startswith("  ") or lines[i].startswith("\t")):
                    sub = lines[i].strip()
                    if sub.startswith("- "):
                        item = sub[2:]
                        if ":" in item:
                            ikey, _, ival = item.partition(":")
                            obj: Dict[str, Any] = {}
                            obj[ikey.strip()] = ival.strip()
                            block_items.append(obj)
                        else:
                            block_items.append(item)
                    i += 1
                root[key] = block_items if block_items else None
                continue
            else:
                # strip quotes
                v = rest
                if (v.startswith('"') and v.endswith('"')) or (v.startswith("'") and v.endswith("'")):
                    v = v[1:-1]
                root[key] = v
        i += 1
    return root


def load_dsl_pattern(path: Path) -> Optional[Dict[str, Any]]:
    """Load a DSL pattern YAML. Returns None on parse failure."""
    try:
        if _HAS_YAML:
            with path.open("r", encoding="utf-8", errors="replace") as fh:
                d = yaml.safe_load(fh)
        else:
            d = _minimal_yaml_load(path)
        if not isinstance(d, dict):
            return None
        return d
    except Exception:
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Skip logic
# ─────────────────────────────────────────────────────────────────────────────

def should_skip(d: Dict[str, Any]) -> Tuple[bool, str]:
    """Return (skip, reason) for a loaded DSL pattern dict."""
    status = d.get("status", "")
    if status in SKIP_STATUSES:
        return True, f"status={status}"
    posture = d.get("submission_posture", "")
    if posture == "NOT_SUBMIT_READY":
        return True, f"submission_posture={posture}"
    wiring = d.get("wiring_status", "")
    if wiring == "documentation_only_text_pattern_no_executable_detector":
        return True, f"wiring_status={wiring}"
    if not d.get("match"):
        return True, "no_match_block"
    return False, ""


# ─────────────────────────────────────────────────────────────────────────────
# Verdict-tag YAML emitter
# ─────────────────────────────────────────────────────────────────────────────

_SEVERITY_MAP = {
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
    "INFORMATIONAL": "INFORMATIONAL",
    "INFO": "INFORMATIONAL",
    "N/A": "N/A",
}


def map_severity(raw: str) -> str:
    """Map DSL severity to schema enum value."""
    return _SEVERITY_MAP.get((raw or "").upper().strip(), "MEDIUM")


def build_tag(
    dsl_path: Path,
    d: Dict[str, Any],
    bug_class_map: Dict[str, List[str]],
    ts: str,
) -> Dict[str, Any]:
    """Build a verdict-tag v2 dict from a loaded DSL pattern dict."""
    pattern_name = d.get("pattern", dsl_path.stem)
    slug = slugify(pattern_name)
    source = str(d.get("source", ""))
    help_text = str(d.get("help", ""))

    # DSL relative path from repo root
    try:
        dsl_rel = str(dsl_path.relative_to(REPO_ROOT))
    except ValueError:
        dsl_rel = str(dsl_path)

    match_predicates: List[Dict] = d.get("match") or []

    # Derive bug_class
    bug_class = derive_bug_class(slug, source, help_text)

    # Look up attack_classes
    attack_classes = list(bug_class_map.get(bug_class, []))

    # Visibility and guard hints
    visibility = extract_visibility(match_predicates)
    has_reentrancy = extract_guard_hints(match_predicates)
    name_regex = extract_name_regex(match_predicates)

    # Shape hash
    shape_hash = synthesize_shape_hash(visibility, has_reentrancy)

    # Severity
    raw_sev = str(d.get("severity", "MEDIUM"))
    severity = map_severity(raw_sev)

    # Build the tag
    tag: Dict[str, Any] = {
        "verdict_id": f"dsl_pattern/{slug}",
        "target_repo": DSL_TARGET_REPO,
        "audit_pin_sha": DSL_SYNTHETIC_SHA,
        "language": "solidity",
        "verdict_class": "CANDIDATE",
        "extraction_provenance": "dsl_pattern_synthesis",
        "extractor_version": EMITTER_VERSION,
        "extracted_at_utc": ts,
        "platform": "unknown",
        "bug_class": bug_class,
        "severity_claimed": severity,
        "severity_final": "N/A",
        "sites": [
            {
                "file_path": dsl_rel,
                "line_start": 1,
                "line_end": 1,
                "function_signature": name_regex,
                "function_name": "(synthetic from regex)",
                "visibility": visibility,
                "shape_hash": shape_hash,
                "shape_hash_fine": shape_hash,
            }
        ],
        "notes": (
            f"Synthesized from {dsl_rel}.\n"
            f"Pattern-derived prior; not a filed finding. Used as S1/S2/S3 corpus signal\n"
            f"for Solidity workspaces where verdict-tag corpus is thin.\n"
            f"source: {source}"
        ),
    }

    if attack_classes:
        tag["attack_classes_to_try"] = attack_classes

    return tag


# ─────────────────────────────────────────────────────────────────────────────
# YAML emitter (stdlib — no PyYAML dependency for output)
# ─────────────────────────────────────────────────────────────────────────────

def _yaml_str(v: str) -> str:
    """Emit a YAML scalar string. Use double-quote if it contains special chars."""
    if not v:
        return "''"
    if any(c in v for c in (':', '#', '{', '}', '[', ']', '*', '&', '?', '|', '-', '<', '>', '=', '!', '%', '@', '`', '\n', '\\')):
        escaped = v.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n')
        return f'"{escaped}"'
    if v[0] in ('"', "'") or v.strip() != v:
        return f'"{v}"'
    return v


def tag_to_yaml(tag: Dict[str, Any]) -> str:
    """Serialize a verdict-tag dict to a YAML string."""
    lines: List[str] = []

    def emit_str(k: str, v: str) -> None:
        lines.append(f"{k}: {_yaml_str(v)}")

    def emit_list(k: str, items: List[str]) -> None:
        if not items:
            lines.append(f"{k}: []")
            return
        lines.append(f"{k}:")
        for item in items:
            lines.append(f"- {_yaml_str(item)}")

    # Required fields first (schema order)
    emit_str("verdict_id", tag["verdict_id"])
    emit_str("target_repo", tag["target_repo"])
    # audit_pin_sha must be quoted to prevent YAML from parsing "0000000" as int
    lines.append(f"audit_pin_sha: \"{tag['audit_pin_sha']}\"")

    emit_str("language", tag["language"])
    emit_str("verdict_class", tag["verdict_class"])
    emit_str("extraction_provenance", tag["extraction_provenance"])
    emit_str("extractor_version", tag["extractor_version"])
    emit_str("extracted_at_utc", tag["extracted_at_utc"])

    # Optional fields
    if "platform" in tag:
        emit_str("platform", tag["platform"])
    if "bug_class" in tag:
        emit_str("bug_class", tag["bug_class"])
    if "severity_claimed" in tag:
        emit_str("severity_claimed", tag["severity_claimed"])
    if "severity_final" in tag:
        emit_str("severity_final", tag["severity_final"])

    if "attack_classes_to_try" in tag:
        emit_list("attack_classes_to_try", tag["attack_classes_to_try"])

    # Sites block
    if "sites" in tag:
        lines.append("sites:")
        for site in tag["sites"]:
            lines.append(f"- file_path: {_yaml_str(site['file_path'])}")
            if "line_start" in site:
                lines.append(f"  line_start: {site['line_start']}")
            if "line_end" in site:
                lines.append(f"  line_end: {site['line_end']}")
            if "function_signature" in site:
                lines.append(f"  function_signature: {_yaml_str(site['function_signature'])}")
            if "function_name" in site:
                lines.append(f"  function_name: {_yaml_str(site['function_name'])}")
            if "visibility" in site:
                lines.append(f"  visibility: {_yaml_str(site['visibility'])}")
            if "shape_hash" in site:
                lines.append(f"  shape_hash: {site['shape_hash']}")
            if "shape_hash_fine" in site:
                lines.append(f"  shape_hash_fine: {site['shape_hash_fine']}")

    if "notes" in tag:
        emit_str("notes", tag["notes"])

    return "\n".join(lines) + "\n"


# ─────────────────────────────────────────────────────────────────────────────
# Main walk
# ─────────────────────────────────────────────────────────────────────────────

def run(
    dsl_dir: Path = DSL_DIR,
    out_dir: Path = TAGS_DIR,
    dry_run: bool = False,
    limit: Optional[int] = None,
    report_path: Optional[Path] = None,
    verbose: bool = False,
) -> Dict[str, Any]:
    """Walk DSL patterns and emit verdict-tag stubs.

    Returns a stats dict with keys:
      total_scanned, emitted, skipped, skip_reasons, bug_class_miss, bug_class_unknown
    """
    ts = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    bug_class_map = load_bug_class_map(BUG_CLASS_MAP_PATH)

    # Collect DSL pattern files (top-level only, no skipped subdirs)
    all_files: List[Path] = []
    for entry in sorted(dsl_dir.iterdir()):
        if entry.is_dir() and entry.name in SKIP_SUBDIRS:
            continue
        if entry.is_file() and entry.suffix == ".yaml":
            all_files.append(entry)

    if limit:
        all_files = all_files[:limit]

    stats: Dict[str, Any] = {
        "total_scanned": 0,
        "emitted": 0,
        "skipped": 0,
        "parse_errors": 0,
        "skip_reasons": collections.Counter(),
        "bug_class_unknown": 0,
        "bug_class_map_miss": 0,
        "ts": ts,
    }

    out_dir.mkdir(parents=True, exist_ok=True)

    for fpath in all_files:
        stats["total_scanned"] += 1
        d = load_dsl_pattern(fpath)
        if d is None:
            stats["parse_errors"] += 1
            stats["skipped"] += 1
            stats["skip_reasons"]["parse_error"] += 1
            if verbose:
                print(f"  SKIP parse_error: {fpath.name}", file=sys.stderr)
            continue

        skip, reason = should_skip(d)
        if skip:
            stats["skipped"] += 1
            stats["skip_reasons"][reason] += 1
            if verbose:
                print(f"  SKIP {reason}: {fpath.name}", file=sys.stderr)
            continue

        tag = build_tag(fpath, d, bug_class_map, ts)

        # Track unknown bug_class
        if tag.get("bug_class") == "unknown-bug-class":
            stats["bug_class_unknown"] += 1
        # Track map miss (bug_class known but not in attack_classes map)
        if tag.get("bug_class") != "unknown-bug-class" and "attack_classes_to_try" not in tag:
            stats["bug_class_map_miss"] += 1

        slug = slugify(d.get("pattern", fpath.stem))
        out_path = out_dir / f"dsl_pattern_{slug}.yaml"

        if not dry_run:
            out_path.write_text(tag_to_yaml(tag), encoding="utf-8")
        stats["emitted"] += 1

        if verbose:
            print(f"  EMIT {out_path.name}", file=sys.stderr)

    # Emit coverage report
    if report_path and not dry_run:
        report_path.parent.mkdir(parents=True, exist_ok=True)
        _write_report(report_path, stats, bug_class_map)

    return stats


# ─────────────────────────────────────────────────────────────────────────────
# Coverage report
# ─────────────────────────────────────────────────────────────────────────────

def _write_report(report_path: Path, stats: Dict[str, Any], bug_class_map: Dict) -> None:
    lines: List[str] = [
        "# Wave-9 Track D: DSL Pattern Synthesis Coverage Report",
        f"generated_at: {stats['ts']}",
        "",
        "## Counts",
        f"- total_scanned: {stats['total_scanned']}",
        f"- emitted: {stats['emitted']}",
        f"- skipped: {stats['skipped']}",
        f"- parse_errors: {stats['parse_errors']}",
        f"- bug_class_unknown (fallback): {stats['bug_class_unknown']}",
        f"- bug_class_map_miss (no attack_classes): {stats['bug_class_map_miss']}",
        "",
        "## Skip reasons",
    ]
    for reason, count in sorted(stats["skip_reasons"].items(), key=lambda x: -x[1]):
        lines.append(f"- {reason}: {count}")
    lines += [
        "",
        "## Attack-class map coverage",
        f"- bug_class keys in map: {len(bug_class_map)}",
    ]
    report_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--dry-run", action="store_true",
                   help="Walk and build tags but do not write files.")
    p.add_argument("--limit", type=int, default=None,
                   help="Process only the first N DSL patterns (for testing).")
    p.add_argument("--out-dir", type=Path, default=TAGS_DIR,
                   help="Directory to write dsl_pattern_*.yaml files to.")
    p.add_argument("--report", type=Path,
                   default=REPO_ROOT / "audit" / "corpus_tags" / "reports" /
                            "wave9_dsl_synthesis_coverage.md",
                   help="Path to emit a coverage report.")
    p.add_argument("--verbose", action="store_true")
    args = p.parse_args(argv)

    stats = run(
        dsl_dir=DSL_DIR,
        out_dir=args.out_dir,
        dry_run=args.dry_run,
        limit=args.limit,
        report_path=args.report,
        verbose=args.verbose,
    )

    mode = "DRY-RUN" if args.dry_run else "EMIT"
    print(f"[{mode}] total={stats['total_scanned']} emitted={stats['emitted']} "
          f"skipped={stats['skipped']} bug_class_unknown={stats['bug_class_unknown']} "
          f"map_miss={stats['bug_class_map_miss']}")
    print(f"Skip breakdown: {dict(stats['skip_reasons'])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
