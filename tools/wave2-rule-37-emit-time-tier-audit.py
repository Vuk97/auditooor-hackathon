#!/usr/bin/env python3
"""wave2-rule-37-emit-time-tier-audit.

Wave-2 PR-A Rule 37 emit-time tier audit.

Rule 37 (auditooor doctrine): "Every record emit MUST declare
verification_tier at emit time." This tool is a stricter, deeper drill on
top of ``tools/wave2-w21-post-migration-validator.py``. Where W21 reports an
aggregate verification_tier count and a sample of failures, this audit:

  1. Walks every record YAML under ``audit/corpus_tags/tags/`` excluding
     ``_QUARANTINE_*`` and ``_deprecated`` subtrees.
  2. Per record, decides whether ``verification_tier`` is present as a
     top-level field AND whether its value is in the accepted taxonomy.
  3. Aggregates results per "prefix" - the dirname under ``tags/`` (or the
     YAML filename slug for tag files living directly in ``tags/``). The
     per-prefix breakdown lets a follow-up batch isolate which corpus
     section regressed Rule 37 compliance.
  4. Emits a JSON status pack of schema
     ``auditooor.wave2_rule_37_emit_time_tier_audit.v1``.

Accepted taxonomy
-----------------

The brief that ordered this tool listed a "brief variant" taxonomy:

  - tier-1-officially-disclosed
  - tier-2-verified-public-archive
  - tier-3-public-archive
  - tier-4-protocol-disclosure
  - tier-5-third-party-mined
  - no_tier

The live corpus (post-Phase-3, commit 5ac7108d01) actually populates the
canonical Wave-2 W21 taxonomy:

  - tier-1-verified-realtime-api
  - tier-2-verified-public-archive
  - tier-3-synthetic-taxonomy-anchored
  - tier-4-bundled-fixture
  - tier-5-quarantine
  - no_tier

To avoid a paper failure caused by a brief-vs-reality drift, this tool
accepts BOTH variants as compliant values. Any tier value outside the
union is flagged as ``rule-37-violation`` with detail ``invalid_value``.
The verdict payload records which taxonomy each populated record used so
a downstream gate can re-canonicalise if the operator chooses.

R37 exemption registry
----------------------

Wave-3 W3.2 lane extension: the audit tool reads
``audit/corpus_tags/schemas/r37_exemption_registry.yaml`` and tallies
records matching an exempt prefix (e.g. ``dsl_pattern``) under
``exempt_count`` rather than ``violation_count``. Pass
``--ignore-exemption-registry`` to reproduce the pre-W3.2 baseline.

Exit codes
----------

  0  PASS (overall_status=PASS) or non-strict mode
  1  WARNING/FAIL under ``--strict``
  2  ERROR (corpus dir missing, etc.)
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

SCHEMA = "auditooor.wave2_rule_37_emit_time_tier_audit.v1"

REPO_ROOT_GUESS = Path(__file__).resolve().parent.parent
DEFAULT_WORKSPACE = REPO_ROOT_GUESS

QUARANTINE_PATH_MARKERS = (
    "_QUARANTINE_FABRICATED_CVE",
    "_QUARANTINE_FABRICATED",
    "_QUARANTINE_",
)
DEPRECATED_PATH_MARKERS = ("_deprecated",)

# Wave-3 W3.2 lane: Rule 37 exemption registry. Maintained at
# audit/corpus_tags/schemas/r37_exemption_registry.yaml. Prefix families
# whose schema has no verification axis (e.g. dsl_pattern_* synthesized
# pattern fixtures) are not within Rule 37's intended scope. The audit
# tool reads the registry, tallies matching records under exempt_count
# instead of violation_count, and rolls up overall_status accordingly.
DEFAULT_EXEMPTION_REGISTRY_REL_PATH = (
    "audit/corpus_tags/schemas/r37_exemption_registry.yaml"
)

# Canonical Wave-2 W21 taxonomy (matches the live corpus post-Phase-3).
CANONICAL_TIERS = (
    "tier-1-verified-realtime-api",
    "tier-2-verified-public-archive",
    "tier-3-synthetic-taxonomy-anchored",
    "tier-4-bundled-fixture",
    "tier-5-quarantine",
)

# Brief variant taxonomy (kept accepted for forward-compat).
BRIEF_VARIANT_TIERS = (
    "tier-1-officially-disclosed",
    "tier-2-verified-public-archive",
    "tier-3-public-archive",
    "tier-4-protocol-disclosure",
    "tier-5-third-party-mined",
)

NO_TIER_SENTINEL = "no_tier"
ACCEPTABLE_TIER_VALUES = (
    frozenset(CANONICAL_TIERS)
    | frozenset(BRIEF_VARIANT_TIERS)
    | {NO_TIER_SENTINEL}
)

VIOLATION_SAMPLE_CAP = 50

_TOP_LEVEL_TIER_RE = re.compile(r"^verification_tier:\s*(.*)$")


def _strip_yaml_quotes(value: str) -> str:
    v = value.strip()
    if len(v) >= 2 and (
        (v[0] == '"' and v[-1] == '"') or (v[0] == "'" and v[-1] == "'")
    ):
        return v[1:-1]
    return v


def _path_under_marker(path: Path, tags_dir: Path, markers: Iterable[str]) -> bool:
    try:
        rel = path.resolve().relative_to(tags_dir.resolve())
    except ValueError:
        rel = path
    upper_markers = tuple(m.upper() for m in markers)
    for part in rel.parts:
        upart = part.upper()
        for marker in upper_markers:
            if marker in upart:
                return True
    return False


def is_under_quarantine(path: Path, tags_dir: Path) -> bool:
    return _path_under_marker(path, tags_dir, QUARANTINE_PATH_MARKERS)


def is_under_deprecated(path: Path, tags_dir: Path) -> bool:
    return _path_under_marker(path, tags_dir, DEPRECATED_PATH_MARKERS)


def iter_record_files(tags_dir: Path) -> Iterable[Path]:
    """Yield candidate record YAML files under tags_dir.

    Mirrors the W21 validator iteration so the two audits agree on the
    "record" universe. JSON record files are accepted but the corpus does
    not currently ship any.
    """
    if not tags_dir.exists():
        return
    for path in sorted(tags_dir.rglob("*")):
        if not path.is_file():
            continue
        name = path.name.lower()
        if name == "readme.md":
            continue
        if name in {"record.yaml", "record.json"}:
            yield path
            continue
        if path.suffix.lower() == ".yaml":
            yield path


def classify_prefix(path: Path, tags_dir: Path) -> str:
    """Derive a "prefix" bucket for the per-prefix breakdown.

    For files directly under ``tags_dir`` we use the first colon-separated
    slug of the filename (e.g. ``solodit-spec`` for
    ``solodit-spec:drafts_rust_soroban:....yaml``). For files nested under
    a subdirectory we use the first directory component
    (e.g. ``lending_protocols``).
    """
    try:
        rel = path.relative_to(tags_dir)
    except ValueError:
        return "_unknown"
    parts = rel.parts
    if len(parts) <= 1:
        # File lives directly under tags_dir; bucket on filename slug.
        stem = parts[0]
        if ":" in stem:
            return stem.split(":", 1)[0]
        if "-" in stem:
            return stem.split("-", 1)[0]
        return stem
    return parts[0]


def _extract_top_level_tier(text: str) -> Optional[str]:
    """Return the top-level ``verification_tier`` value, or None."""
    for raw in text.splitlines():
        if not raw:
            continue
        # Top-level keys have no leading whitespace.
        if raw.startswith(" ") or raw.startswith("\t"):
            continue
        m = _TOP_LEVEL_TIER_RE.match(raw)
        if m:
            return _strip_yaml_quotes(m.group(1)) or None
    return None


def load_exemption_registry(
    workspace: Path,
    *,
    registry_rel_path: str = DEFAULT_EXEMPTION_REGISTRY_REL_PATH,
) -> Dict[str, Any]:
    """Load the R37 exemption registry from disk.

    Returns a dict with keys ``exempt_prefixes`` (mapping prefix -> entry)
    and ``exemption_gates`` (mapping prefix -> gate-spec). Missing /
    malformed registry returns an empty registry (no exemptions); this
    keeps the tool conservative when the file is absent.
    """
    empty: Dict[str, Any] = {
        "exempt_prefixes": {},
        "exemption_gates": {},
        "registry_path": None,
        "registry_loaded": False,
        "registry_error": None,
    }
    registry_path = workspace / registry_rel_path
    if not registry_path.exists():
        return empty
    try:
        import yaml  # local import - yaml is a soft dep
    except ImportError as exc:
        empty["registry_path"] = str(registry_path)
        empty["registry_error"] = f"PyYAML missing: {exc}"
        return empty
    try:
        text = registry_path.read_text(encoding="utf-8")
        payload = yaml.safe_load(text)
    except (OSError, yaml.YAMLError) as exc:
        empty["registry_path"] = str(registry_path)
        empty["registry_error"] = f"load error: {exc}"
        return empty

    if not isinstance(payload, dict):
        empty["registry_path"] = str(registry_path)
        empty["registry_error"] = "registry root is not a mapping"
        return empty

    exempt_prefixes: Dict[str, Dict[str, Any]] = {}
    for entry in payload.get("exempt_prefixes", []) or []:
        if not isinstance(entry, dict):
            continue
        prefix = entry.get("prefix")
        if not isinstance(prefix, str) or not prefix:
            continue
        exempt_prefixes[prefix] = entry

    exemption_gates_raw = payload.get("exemption_gates", {}) or {}
    exemption_gates: Dict[str, Dict[str, Any]] = {}
    if isinstance(exemption_gates_raw, dict):
        for prefix, gate in exemption_gates_raw.items():
            if isinstance(prefix, str) and isinstance(gate, dict):
                exemption_gates[prefix] = gate

    return {
        "exempt_prefixes": exempt_prefixes,
        "exemption_gates": exemption_gates,
        "registry_path": str(registry_path),
        "registry_loaded": True,
        "registry_error": None,
    }


def _record_has_field(text: str, field: str) -> bool:
    """True iff ``text`` contains a top-level YAML key named ``field``.

    Top-level = no leading whitespace. Used to apply the registry's
    exemption_gate filters without parsing full YAML (cheap, robust to
    the corpus's mixed-shape records).
    """
    pat = re.compile(rf"^{re.escape(field)}:", re.MULTILINE)
    return bool(pat.search(text))


def _match_registry_prefix(
    record_prefix: str,
    exempt_prefixes: Dict[str, Any],
) -> Optional[str]:
    """Return the registry key that matches ``record_prefix``, or None.

    Supports two match modes:
      - exact equality: ``"dsl_pattern" == "dsl_pattern"``
      - trailing-wildcard: ``"dsl_pattern_*"`` matches any record prefix
        that startswith ``"dsl_pattern_"``.

    Exact-match wins over wildcard if both are present.
    """
    if record_prefix in exempt_prefixes:
        return record_prefix
    for key in exempt_prefixes:
        if isinstance(key, str) and key.endswith("*"):
            stem = key[:-1]
            if stem and record_prefix.startswith(stem):
                return key
    return None


def is_record_exempt(
    *,
    prefix: str,
    record_text: str,
    record_payload: Optional[Dict[str, Any]],
    audit_result: Dict[str, Any],
    registry: Dict[str, Any],
) -> Tuple[bool, Optional[str]]:
    """Decide if a record matches the R37 exemption registry.

    Returns (is_exempt, reason). ``reason`` is a short tag used in the
    payload's `exempt_breakdown`.

    A record is exempt iff:
      (a) its prefix matches an entry in ``registry['exempt_prefixes']``
          (exact or trailing-wildcard match), AND
      (b) the registry's exemption_gate for that key (if any) matches
          the record's top-level fields.

    Compliant records (already carry a valid verification_tier) are
    NEVER exempt - the registry is a "this record family is outside
    Rule 37 scope" gate, not a "ignore compliant records" gate.
    """
    exempt_prefixes = registry.get("exempt_prefixes", {}) or {}
    matched_key = _match_registry_prefix(prefix, exempt_prefixes)
    if matched_key is None:
        return False, None

    # A record that already has a valid verification_tier should still
    # be counted as compliant, not exempt. The registry only changes the
    # treatment of records that would otherwise be violations.
    if audit_result.get("status") == "compliant":
        return False, None

    gates = registry.get("exemption_gates", {}) or {}
    gate = gates.get(matched_key)
    if gate is None:
        return True, "prefix-match-no-gate"

    require_present = gate.get("require_field_present", []) or []
    require_absent = gate.get("require_field_absent", []) or []

    # JSON record path: use payload keys directly when available.
    if record_payload is not None and isinstance(record_payload, dict):
        for field in require_present:
            if not isinstance(field, str):
                continue
            if field not in record_payload:
                return False, None
        for field in require_absent:
            if not isinstance(field, str):
                continue
            if field in record_payload:
                return False, None
        return True, "prefix-match-gate-ok"

    # YAML record path: scan top-level keys via regex on raw text.
    for field in require_present:
        if not isinstance(field, str):
            continue
        if not _record_has_field(record_text, field):
            return False, None
    for field in require_absent:
        if not isinstance(field, str):
            continue
        if _record_has_field(record_text, field):
            return False, None
    return True, "prefix-match-gate-ok"


def audit_record(path: Path) -> Dict[str, Any]:
    """Parse one record file. Returns a dict with keys:

      - status: "compliant" | "missing-field" | "invalid-value" | "parse-error"
      - tier_value: the value of ``verification_tier`` (if present)
      - taxonomy_variant: "canonical" | "brief-variant" | "no-tier" | None
    """
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return {
            "status": "parse-error",
            "tier_value": None,
            "taxonomy_variant": None,
            "detail": f"unreadable: {exc}",
            "_text": "",
            "_json_payload": None,
        }

    json_payload: Optional[Dict[str, Any]] = None
    if path.suffix.lower() == ".json":
        try:
            payload = json.loads(text)
        except json.JSONDecodeError as exc:
            return {
                "status": "parse-error",
                "tier_value": None,
                "taxonomy_variant": None,
                "detail": f"json decode: {exc}",
                "_text": text,
                "_json_payload": None,
            }
        if isinstance(payload, dict):
            json_payload = payload
        tier_value = (
            payload.get("verification_tier") if isinstance(payload, dict) else None
        )
    else:
        tier_value = _extract_top_level_tier(text)

    if tier_value is None or tier_value == "":
        return {
            "status": "missing-field",
            "tier_value": None,
            "taxonomy_variant": None,
            "detail": "top-level verification_tier field missing or empty",
            "_text": text,
            "_json_payload": json_payload,
        }

    tier_str = str(tier_value).strip()
    if tier_str in ACCEPTABLE_TIER_VALUES:
        if tier_str == NO_TIER_SENTINEL:
            variant = "no-tier"
        elif tier_str in CANONICAL_TIERS:
            variant = "canonical"
        else:
            variant = "brief-variant"
        return {
            "status": "compliant",
            "tier_value": tier_str,
            "taxonomy_variant": variant,
            "detail": None,
            "_text": text,
            "_json_payload": json_payload,
        }
    return {
        "status": "invalid-value",
        "tier_value": tier_str,
        "taxonomy_variant": None,
        "detail": f"verification_tier={tier_str!r} not in accepted taxonomy",
        "_text": text,
        "_json_payload": json_payload,
    }


def audit(
    workspace: Path,
    *,
    limit: Optional[int] = None,
    exemption_registry: Optional[Dict[str, Any]] = None,
    ignore_exemption_registry: bool = False,
) -> Tuple[int, Dict[str, Any]]:
    tags_dir = workspace / "audit" / "corpus_tags" / "tags"

    if exemption_registry is None and not ignore_exemption_registry:
        exemption_registry = load_exemption_registry(workspace)
    if exemption_registry is None:
        exemption_registry = {
            "exempt_prefixes": {},
            "exemption_gates": {},
            "registry_path": None,
            "registry_loaded": False,
            "registry_error": None,
        }

    payload: Dict[str, Any] = {
        "schema": SCHEMA,
        "workspace": str(workspace),
        "tags_dir": str(tags_dir),
        "total_records_scanned": 0,
        "compliant_count": 0,
        "violation_count": 0,
        "exempt_count": 0,
        "skipped_quarantine": 0,
        "skipped_deprecated": 0,
        "parse_error_count": 0,
        "missing_field_count": 0,
        "invalid_value_count": 0,
        "tier_distribution": {},
        "taxonomy_variant_distribution": {},
        "prefix_breakdown": {},
        "exempt_breakdown": {},
        "violations": [],
        "exemption_registry": {
            "path": exemption_registry.get("registry_path"),
            "loaded": exemption_registry.get("registry_loaded", False),
            "error": exemption_registry.get("registry_error"),
            "exempt_prefixes": sorted(
                list((exemption_registry.get("exempt_prefixes") or {}).keys())
            ),
        },
        "overall_status": "PASS",
        "notes": [],
    }

    if not tags_dir.exists():
        payload["overall_status"] = "ERROR"
        payload["notes"].append(f"tags dir missing: {tags_dir}")
        return 2, payload

    tier_distribution: Counter = Counter()
    variant_distribution: Counter = Counter()
    prefix_compliant: Counter = Counter()
    prefix_violations: Counter = Counter()
    prefix_exempt: Counter = Counter()
    violations: List[Dict[str, Any]] = []
    exempt_reason_counts: Counter = Counter()

    scanned = 0
    for path in iter_record_files(tags_dir):
        if limit is not None and scanned >= limit:
            break

        if is_under_quarantine(path, tags_dir):
            payload["skipped_quarantine"] += 1
            continue
        if is_under_deprecated(path, tags_dir):
            payload["skipped_deprecated"] += 1
            continue

        scanned += 1
        prefix = classify_prefix(path, tags_dir)
        result = audit_record(path)
        status = result["status"]

        if status == "compliant":
            payload["compliant_count"] += 1
            prefix_compliant[prefix] += 1
            tier_distribution[result["tier_value"]] += 1
            variant_distribution[result["taxonomy_variant"]] += 1
            continue

        # Apply R37 exemption registry before counting as a violation.
        exempt, reason = is_record_exempt(
            prefix=prefix,
            record_text=result.get("_text", "") or "",
            record_payload=result.get("_json_payload"),
            audit_result=result,
            registry=exemption_registry,
        )
        if exempt:
            payload["exempt_count"] += 1
            prefix_exempt[prefix] += 1
            if reason:
                exempt_reason_counts[reason] += 1
            continue

        payload["violation_count"] += 1
        prefix_violations[prefix] += 1

        if status == "missing-field":
            payload["missing_field_count"] += 1
            kind = "missing_field"
        elif status == "invalid-value":
            payload["invalid_value_count"] += 1
            kind = "invalid_value"
        else:
            payload["parse_error_count"] += 1
            kind = "parse_error"

        if len(violations) < VIOLATION_SAMPLE_CAP:
            try:
                rel_path = str(path.relative_to(workspace))
            except ValueError:
                rel_path = str(path)
            violations.append(
                {
                    "record_path": rel_path,
                    "prefix": prefix,
                    "kind": kind,
                    "tier_value": result.get("tier_value"),
                    "detail": result.get("detail"),
                }
            )

    payload["total_records_scanned"] = scanned
    payload["tier_distribution"] = dict(tier_distribution)
    payload["taxonomy_variant_distribution"] = dict(variant_distribution)
    payload["violations"] = violations
    payload["exempt_reason_counts"] = dict(exempt_reason_counts)

    prefix_breakdown: Dict[str, Dict[str, int]] = {}
    for prefix in sorted(
        set(prefix_compliant) | set(prefix_violations) | set(prefix_exempt)
    ):
        prefix_breakdown[prefix] = {
            "compliant": prefix_compliant.get(prefix, 0),
            "violations": prefix_violations.get(prefix, 0),
            "exempt": prefix_exempt.get(prefix, 0),
        }
    payload["prefix_breakdown"] = prefix_breakdown
    payload["exempt_breakdown"] = {
        prefix: prefix_exempt.get(prefix, 0)
        for prefix in sorted(prefix_exempt)
    }

    violations_n = payload["violation_count"]
    if violations_n == 0:
        payload["overall_status"] = "PASS"
        rc = 0
    elif violations_n <= 100:
        payload["overall_status"] = "WARNING"
        rc = 1
    else:
        payload["overall_status"] = "FAIL"
        rc = 1

    if variant_distribution.get("brief-variant", 0) > 0:
        payload["notes"].append(
            "brief-variant taxonomy values detected (forward-compat accepted; "
            "consider re-canonicalising to W21 taxonomy)"
        )
    if variant_distribution.get("no-tier", 0) > 0:
        payload["notes"].append(
            f"{variant_distribution['no-tier']} record(s) declared sentinel no_tier"
        )
    if payload["exempt_count"] > 0:
        payload["notes"].append(
            f"{payload['exempt_count']} record(s) covered by R37 exemption "
            f"registry ({DEFAULT_EXEMPTION_REGISTRY_REL_PATH})"
        )
    if exemption_registry.get("registry_error"):
        payload["notes"].append(
            f"exemption registry error: {exemption_registry['registry_error']}"
        )

    return rc, payload


def _print_human(payload: Dict[str, Any]) -> None:
    print("# wave2-rule-37-emit-time-tier-audit")
    print(f"workspace: {payload['workspace']}")
    print(f"tags_dir:  {payload['tags_dir']}")
    print(f"total_records_scanned: {payload['total_records_scanned']}")
    print(f"  compliant_count:     {payload['compliant_count']}")
    print(f"  exempt_count:        {payload.get('exempt_count', 0)}")
    print(f"  violation_count:     {payload['violation_count']}")
    print(f"    missing_field:     {payload['missing_field_count']}")
    print(f"    invalid_value:     {payload['invalid_value_count']}")
    print(f"    parse_error:       {payload['parse_error_count']}")
    print(f"skipped_quarantine:    {payload['skipped_quarantine']}")
    print(f"skipped_deprecated:    {payload['skipped_deprecated']}")
    reg = payload.get("exemption_registry") or {}
    if reg:
        print(
            "exemption_registry:    "
            f"loaded={reg.get('loaded')} prefixes={reg.get('exempt_prefixes')}"
        )
        if reg.get("error"):
            print(f"  error: {reg.get('error')}")
    if payload["tier_distribution"]:
        print("tier_distribution:")
        for tier, n in sorted(payload["tier_distribution"].items()):
            print(f"  {tier:<40} {n:>7}")
    if payload["taxonomy_variant_distribution"]:
        print("taxonomy_variant_distribution:")
        for variant, n in sorted(payload["taxonomy_variant_distribution"].items()):
            print(f"  {variant:<20} {n:>7}")
    if payload["prefix_breakdown"]:
        print("prefix_breakdown (top 20 by violations, then top 20 by compliant):")
        rows = sorted(
            payload["prefix_breakdown"].items(),
            key=lambda kv: (-kv[1]["violations"], -kv[1]["compliant"]),
        )
        for prefix, info in rows[:20]:
            print(
                f"  {prefix:<40} compliant={info['compliant']:>6}  "
                f"violations={info['violations']:>6}"
            )
    print(f"overall_status: {payload['overall_status']}")
    if payload["violations"]:
        print(f"sample_violations (capped at {VIOLATION_SAMPLE_CAP}):")
        for v in payload["violations"][:10]:
            print(
                f"  [{v['kind']}] {v['record_path']} "
                f"tier_value={v['tier_value']!r}"
            )
    if payload["notes"]:
        print("notes:")
        for n in payload["notes"]:
            print(f"  - {n}")


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument(
        "--workspace",
        type=Path,
        default=DEFAULT_WORKSPACE,
        help="Repo root containing audit/corpus_tags/tags/.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit JSON status pack on stdout (suppresses the human report).",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit non-zero when overall_status != PASS.",
    )
    parser.add_argument(
        "--limit-records",
        dest="limit_records",
        type=int,
        default=None,
        help="Cap audited record count (for smoke / CI sanity).",
    )
    parser.add_argument(
        "--ignore-exemption-registry",
        dest="ignore_exemption_registry",
        action="store_true",
        help=(
            "Ignore audit/corpus_tags/schemas/r37_exemption_registry.yaml. "
            "Use to reproduce the pre-W3.2 baseline output."
        ),
    )
    args = parser.parse_args(argv)

    rc, payload = audit(
        args.workspace.expanduser(),
        limit=args.limit_records,
        ignore_exemption_registry=args.ignore_exemption_registry,
    )

    if args.json:
        json.dump(payload, sys.stdout, sort_keys=True, indent=2)
        sys.stdout.write("\n")
    else:
        _print_human(payload)

    if payload["overall_status"] == "ERROR":
        return 2
    if not args.strict:
        return 0
    return rc


if __name__ == "__main__":
    sys.exit(main())
