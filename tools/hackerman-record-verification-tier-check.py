#!/usr/bin/env python3
"""hackerman-record-verification-tier-check.

Pre-submit gate that audits the Hackerman corpus for `verification_tier`
provenance discipline. Two enforcement axes:

  1. Every record must carry a `verification_tier`. Schema v1.1 records
     (Wave-2 Phase-3 migration, Rule 37) declare it as a first-class
     top-level field `verification_tier: tier-N-*`; that field is the
     canonical source and is preferred when present. Legacy v1 records
     that lack the first-class field fall back to a single
     `verification_tier:tier-N-*` tag inside `function_shape.shape_tags`.
     A record with neither a valid first-class tier nor a shape_tags tier
     fails the gate. Smuggling the tier into `shape_tags` is the documented
     v1 anti-pattern, accepted only for backward compatibility.

  2. Records living under a `_QUARANTINE_*` subtree of the tags directory
     must NEVER be treated as fileable / pattern-source / production.
     The gate reports those records as `quarantine` verdicts and refuses
     to PASS a draft submission that cites such a record as a corpus
     anchor (i.e. references a quarantined record_id or YAML path in the
     submission body).

Two record shapes are supported:

  - v1 hackerman flat YAML: `audit/corpus_tags/tags/<slug>.yaml` whose
    first line declares `schema_version: auditooor.hackerman_record.v1`.
  - v2 per-dir bundles: `audit/corpus_tags/tags/<bucket>/<slug>/record.yaml`
    plus an optional `record.json` mirror. Either file form is sufficient.

Tier taxonomy (mirrors `tools/hackerman-stratify-verification-tier.py`):

    tier-1-verified-realtime-api
    tier-1-officially-disclosed
    tier-2-verified-public-archive
    tier-3-synthetic-taxonomy-anchored
    tier-4-bundled-fixture
    tier-5-quarantine

Usage:

    # Audit the corpus tree only (no draft involved)
    python3 tools/hackerman-record-verification-tier-check.py --json

    # Pre-submit gate path: also verify a submission file does not promote
    # tier-5 quarantine records.
    python3 tools/hackerman-record-verification-tier-check.py \
        --submission submissions/paste_ready/foo.md --json

Exit codes:

    0  - pass (all records carry verification_tier; no tier-5 cited)
    1  - fail (missing tiers OR tier-5 record cited as fileable)
    2  - error (corpus dir missing, unreadable, etc.)
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

SCHEMA = "auditooor.hackerman_record_verification_tier_check.v1"
HACKERMAN_V1_SCHEMA = "auditooor.hackerman_record.v1"

REPO_ROOT_GUESS = Path(__file__).resolve().parent.parent
DEFAULT_TAGS_DIR = REPO_ROOT_GUESS / "audit" / "corpus_tags" / "tags"

VERIFICATION_TIERS = (
    "tier-1-verified-realtime-api",
    "tier-1-officially-disclosed",
    "tier-2-verified-public-archive",
    "tier-3-synthetic-taxonomy-anchored",
    "tier-4-bundled-fixture",
    "tier-5-quarantine",
)

QUARANTINE_PATH_MARKERS = (
    "_QUARANTINE_FABRICATED_CVE",
    "_QUARANTINE_FABRICATED",
    "_QUARANTINE_",
)

VERIFICATION_TIER_PREFIX = "verification_tier:"
VERIFICATION_TIER_VALUE_RE = re.compile(
    r"^verification_tier:(tier-[1-5]-[a-z0-9][a-z0-9-]*)$"
)
# Loose form: any `verification_tier:<anything>` tag. Used to detect drafts
# of the tag that don't pass the strict tier-[1-5]-* taxonomy check, so the
# gate can surface them as `malformed-tier` rather than `missing-tier`.
VERIFICATION_TIER_VALUE_LOOSE_RE = re.compile(
    r"^verification_tier:.+$"
)


# --------------------------------------------------------------------------- #
# Record loading
# --------------------------------------------------------------------------- #


def _is_under_quarantine(path: Path, tags_dir: Path) -> bool:
    """True iff any path component between tags_dir and `path` matches a
    quarantine marker."""
    try:
        rel = path.resolve().relative_to(tags_dir.resolve())
    except ValueError:
        rel = path
    for part in rel.parts:
        upart = part.upper()
        for marker in QUARANTINE_PATH_MARKERS:
            if marker.upper() in upart:
                return True
    return False


def _iter_record_files(tags_dir: Path) -> Iterable[Path]:
    """Yield every candidate record file under `tags_dir` (recursively).

    Emits in deterministic sorted order. Both flat `*.yaml` and per-dir
    `record.{json,yaml}` shapes are returned. README.md and other top-level
    markdown files are ignored.
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
        if path.suffix.lower() == ".yaml" and path.parent == tags_dir:
            yield path
            continue
        # Also surface flat .yaml records inside known top-level buckets
        # (e.g. `audit/corpus_tags/tags/_QUARANTINE_FABRICATED_CVE/vyper_cve_fabricated/*.yaml`)
        if path.suffix.lower() == ".yaml" and path.parent != tags_dir:
            # Only include if there is NO sibling `record.yaml` (avoid
            # double-counting when both a record.yaml and a sidecar are
            # present in the same directory).
            sibling_record = path.parent / "record.yaml"
            if sibling_record.exists() and sibling_record != path:
                continue
            yield path


def _extract_shape_tags(
    text: str, fmt: str
) -> Tuple[List[str], Optional[str], Optional[str]]:
    """Return (shape_tags, schema_version, verification_tier) parsed from text.

    The JSON path uses json.loads; the YAML path is a minimal hand parser
    that finds the `function_shape:` block and reads its `shape_tags` list
    items. PyYAML is intentionally avoided so the gate stays import-free.

    `verification_tier` is the first-class top-level field introduced by the
    Wave-2 Phase-3 schema v1.1 migration (Rule 37). It is the canonical
    location for the tier; the older v1 anti-pattern smuggled the tier into
    `function_shape.shape_tags` instead. The gate prefers the first-class
    field and falls back to the shape_tags scan only for legacy v1 records
    that lack it.
    """
    if fmt == "json":
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            return [], None, None
        schema_version = payload.get("schema_version")
        shape = payload.get("function_shape") or {}
        tags = shape.get("shape_tags") or []
        first_class_tier = payload.get("verification_tier")
        first_class_tier = (
            str(first_class_tier).strip()
            if isinstance(first_class_tier, str) and first_class_tier.strip()
            else None
        )
        if not isinstance(tags, list):
            return [], (schema_version if isinstance(schema_version, str) else None), first_class_tier
        return (
            [str(t) for t in tags],
            schema_version if isinstance(schema_version, str) else None,
            first_class_tier,
        )

    # YAML — minimal scan
    schema_version: Optional[str] = None
    first_class_tier: Optional[str] = None
    lines = text.splitlines()
    in_fs = False
    in_tags = False
    tags_indent: Optional[int] = None
    tags: List[str] = []
    for raw in lines:
        if not raw.strip():
            continue
        stripped = raw.strip()
        # Top-level scalar capture for schema_version
        if not raw.startswith(" ") and not raw.startswith("\t"):
            if stripped.startswith("schema_version:"):
                _, _, rhs = stripped.partition(":")
                schema_version = _strip_yaml_quotes(rhs.strip())
            # Top-level first-class verification_tier (schema v1.1, Rule 37).
            if stripped.startswith("verification_tier:"):
                _, _, rhs = stripped.partition(":")
                rhs = _strip_yaml_quotes(rhs.strip())
                first_class_tier = rhs or None
            # New top-level key resets nested state
            if in_fs and stripped.endswith(":") and not raw.startswith(" "):
                in_fs = False
                in_tags = False
            elif in_fs and ":" in stripped and not raw.startswith(" "):
                in_fs = False
                in_tags = False
            if stripped.startswith("function_shape:"):
                in_fs = True
                in_tags = False
                continue
            continue
        if not in_fs:
            continue
        # Inside function_shape block
        indent = len(raw) - len(raw.lstrip(" "))
        if stripped.startswith("shape_tags:"):
            in_tags = True
            tags_indent = indent
            continue
        if in_tags:
            if stripped.startswith("- "):
                # List item — accept if its indent is deeper than (or equal to)
                # the shape_tags key indent.
                if tags_indent is not None and indent >= tags_indent:
                    val = stripped[2:].strip()
                    tags.append(_strip_yaml_quotes(val))
                    continue
                else:
                    in_tags = False
            else:
                # Non-list line at same or shallower indent ends the block.
                if tags_indent is not None and indent <= tags_indent:
                    in_tags = False
        # Detect if function_shape block ends (a sibling key at the same
        # indent as `function_shape:` itself — handled by the top-level
        # branch above).
    return tags, schema_version, first_class_tier


def _strip_yaml_quotes(value: str) -> str:
    v = value.strip()
    if len(v) >= 2 and ((v[0] == '"' and v[-1] == '"') or (v[0] == "'" and v[-1] == "'")):
        return v[1:-1]
    return v


def _extract_record_id(text: str, fmt: str) -> Optional[str]:
    if fmt == "json":
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            return None
        rid = payload.get("record_id")
        return rid if isinstance(rid, str) else None
    for raw in text.splitlines():
        if not raw or raw.startswith(" ") or raw.startswith("\t"):
            continue
        if raw.startswith("record_id:"):
            _, _, rhs = raw.partition(":")
            return _strip_yaml_quotes(rhs.strip())
    return None


# --------------------------------------------------------------------------- #
# Per-record audit
# --------------------------------------------------------------------------- #


def audit_record(path: Path, tags_dir: Path) -> Dict[str, Any]:
    fmt = "json" if path.suffix.lower() == ".json" else "yaml"
    quarantine = _is_under_quarantine(path, tags_dir)
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return {
            "file": str(path),
            "record_id": None,
            "schema_version": None,
            "format": fmt,
            "quarantine": quarantine,
            "verification_tier": None,
            "verification_tier_count": 0,
            "verdict": "error",
            "reason": f"unreadable: {exc}",
        }

    shape_tags, schema_version, first_class_tier = _extract_shape_tags(text, fmt)
    record_id = _extract_record_id(text, fmt)

    # Only audit records that declare the canonical hackerman v1.x schema.
    # Wave-2 Phase-3 introduced v1.1 (corpus migration); use prefix-match so
    # v1 + v1.1 (+ future v1.x minor bumps) all stay in-gate. Sibling
    # verdict_tag.v2 YAMLs share the directory and must be ignored.
    if not str(schema_version or "").startswith(HACKERMAN_V1_SCHEMA):
        return {
            "file": str(path),
            "record_id": record_id,
            "schema_version": schema_version,
            "format": fmt,
            "quarantine": quarantine,
            "verification_tier": None,
            "verification_tier_count": 0,
            "verdict": "skipped-non-hackerman-v1",
            "reason": f"schema_version={schema_version!r}; out of gate scope",
        }

    # Find verification_tier:tier-N-* tags (strict-form, value-only). Loose
    # form is also recorded so we can report a "malformed" verdict for tags
    # that almost-but-don't match (helpful for migration triage).
    strict_hits = [t for t in shape_tags if VERIFICATION_TIER_VALUE_RE.match(t.strip())]
    loose_hits = [
        t
        for t in shape_tags
        if VERIFICATION_TIER_VALUE_LOOSE_RE.search(t.strip())
        and not VERIFICATION_TIER_VALUE_RE.match(t.strip())
    ]
    tier_value: Optional[str] = None
    if strict_hits:
        m = VERIFICATION_TIER_VALUE_RE.match(strict_hits[0].strip())
        tier_value = m.group(1) if m else None

    # Rule 37: schema v1.1 records carry `verification_tier` as a first-class
    # top-level field. Smuggling the tier into `function_shape.shape_tags` is
    # the documented v1 anti-pattern. When a record exposes a valid first-class
    # tier, that is the canonical source - prefer it and ONLY fall back to the
    # shape_tags scan for legacy v1 records that lack the field. A first-class
    # value that is non-empty but NOT a valid `tier-[1-5]-*` taxonomy value is
    # surfaced as `malformed-tier` rather than silently ignored.
    first_class_valid = bool(
        first_class_tier and first_class_tier in VERIFICATION_TIERS
    )
    tier_source = "shape_tags"
    if first_class_tier:
        tier_source = "first-class-field"
        if first_class_valid:
            tier_value = first_class_tier

    base: Dict[str, Any] = {
        "file": str(path),
        "record_id": record_id,
        "schema_version": schema_version,
        "format": fmt,
        "quarantine": quarantine,
        "verification_tier": tier_value,
        "verification_tier_count": len(strict_hits),
        "verification_tier_loose_count": len(loose_hits),
        "verification_tier_source": tier_source,
        "first_class_verification_tier": first_class_tier,
    }

    if quarantine:
        # Quarantined records get a dedicated verdict regardless of tag
        # presence (they MUST be tier-5 if tagged at all, but absent tag
        # still flags as missing). A first-class tier counts as a present
        # tier here too - reconcile it the same way as a shape_tags hit.
        has_any_tier = bool(strict_hits) or first_class_valid
        if not has_any_tier:
            base["verdict"] = "quarantine-missing-tier"
            base["reason"] = "record sits under a _QUARANTINE_* subtree but has no verification_tier:tier-5-* tag"
            return base
        if tier_value and not tier_value.startswith("tier-5"):
            base["verdict"] = "quarantine-tier-mismatch"
            base["reason"] = f"record is in _QUARANTINE_* subtree but tagged as {tier_value} (expected tier-5-*)"
            return base
        base["verdict"] = "quarantine"
        base["reason"] = "record is correctly quarantined and not fileable"
        return base

    # First-class field path: a valid v1.1 first-class tier is sufficient on
    # its own - the shape_tags array is NOT consulted for these records.
    if first_class_valid:
        base["verdict"] = "pass"
        base["reason"] = f"carries first-class verification_tier {tier_value}"
        return base

    # First-class field present but malformed (non-taxonomy value): fail the
    # gate with a malformed-tier verdict so migration triage sees the offender.
    if first_class_tier and not first_class_valid:
        base["verdict"] = "malformed-tier"
        base["reason"] = (
            f"first-class verification_tier value {first_class_tier!r} not in taxonomy"
        )
        return base

    # Legacy v1 fallback: no first-class field, scan function_shape.shape_tags.
    if not shape_tags:
        base["verdict"] = "missing-shape-tags"
        base["reason"] = "function_shape.shape_tags is empty or unparseable"
        return base

    if not strict_hits and not loose_hits:
        base["verdict"] = "missing-tier"
        base["reason"] = (
            "no first-class verification_tier field and no "
            "verification_tier:tier-N-* entry in function_shape.shape_tags"
        )
        return base

    if not strict_hits and loose_hits:
        base["verdict"] = "malformed-tier"
        base["reason"] = f"verification_tier tag present but malformed: {loose_hits[0]!r}"
        return base

    if len(strict_hits) > 1:
        base["verdict"] = "duplicate-tier"
        base["reason"] = f"multiple verification_tier tags present ({len(strict_hits)})"
        return base

    if tier_value and not any(tier_value == t for t in VERIFICATION_TIERS):
        base["verdict"] = "unknown-tier"
        base["reason"] = f"verification_tier value {tier_value!r} not in taxonomy"
        return base

    base["verdict"] = "pass"
    base["reason"] = f"carries {tier_value}"
    return base


# --------------------------------------------------------------------------- #
# Submission cross-reference
# --------------------------------------------------------------------------- #


def find_submission_quarantine_refs(
    submission_text: str,
    record_audits: List[Dict[str, Any]],
    tags_dir: Path,
) -> List[Dict[str, Any]]:
    """Return any quarantined records cited by the submission text.

    A citation is matched by either (a) the record_id appearing verbatim in
    the submission body or (b) the record's repo-relative file path
    appearing as a substring.
    """
    hits: List[Dict[str, Any]] = []
    body = submission_text or ""
    for audit in record_audits:
        if not audit.get("quarantine"):
            continue
        rid = audit.get("record_id")
        file_field = audit.get("file") or ""
        try:
            rel = Path(file_field).resolve().relative_to(tags_dir.parent.parent.resolve())
            rel_str = str(rel)
        except (ValueError, OSError):
            rel_str = file_field
        matched_via: List[str] = []
        if rid and rid in body:
            matched_via.append("record_id")
        if rel_str and rel_str in body:
            matched_via.append("file-path")
        # Also accept just the bare filename match (covers paste-ready refs
        # that strip the workspace prefix).
        if file_field:
            base = Path(file_field).name
            if base and base in body and base.endswith((".yaml", ".json")):
                if "filename" not in matched_via:
                    matched_via.append("filename")
        if matched_via:
            hits.append(
                {
                    "record_id": rid,
                    "file": file_field,
                    "rel_path": rel_str,
                    "matched_via": matched_via,
                }
            )
    return hits


# --------------------------------------------------------------------------- #
# Driver
# --------------------------------------------------------------------------- #

PASS_VERDICTS = {"pass", "quarantine", "skipped-non-hackerman-v1"}
FAIL_VERDICTS = {
    "missing-tier",
    "malformed-tier",
    "duplicate-tier",
    "missing-shape-tags",
    "unknown-tier",
    "quarantine-missing-tier",
    "quarantine-tier-mismatch",
}


def run(
    tags_dir: Path,
    submission_path: Optional[Path] = None,
    *,
    limit: Optional[int] = None,
    fail_on_missing_dir: bool = True,
) -> Tuple[int, Dict[str, Any]]:
    payload: Dict[str, Any] = {
        "schema": SCHEMA,
        "tags_dir": str(tags_dir),
        "submission": str(submission_path) if submission_path else None,
        "scanned": 0,
        "audited_hackerman_v1": 0,
        "skipped_non_hackerman_v1": 0,
        "verdict_counts": {},
        "tier_counts": {},
        "failed_records": [],
        "submission_quarantine_refs": [],
        "verdict": "pass",
        "reason": "",
    }

    if not tags_dir.exists():
        payload["verdict"] = "error"
        payload["reason"] = f"tags dir does not exist: {tags_dir}"
        return (2 if fail_on_missing_dir else 0), payload

    scanned = 0
    audits: List[Dict[str, Any]] = []
    verdict_counter: Counter[str] = Counter()
    tier_counter: Counter[str] = Counter()
    failed: List[Dict[str, Any]] = []

    for record_path in _iter_record_files(tags_dir):
        scanned += 1
        if limit is not None and scanned > limit:
            scanned -= 1
            break
        audit = audit_record(record_path, tags_dir)
        audits.append(audit)
        verdict_counter[audit["verdict"]] += 1
        if audit.get("verification_tier"):
            tier_counter[audit["verification_tier"]] += 1
        if audit["verdict"] in FAIL_VERDICTS:
            failed.append(audit)

    payload["scanned"] = scanned
    payload["skipped_non_hackerman_v1"] = verdict_counter.get("skipped-non-hackerman-v1", 0)
    payload["audited_hackerman_v1"] = scanned - payload["skipped_non_hackerman_v1"]
    payload["verdict_counts"] = dict(verdict_counter)
    payload["tier_counts"] = dict(tier_counter)
    payload["failed_records"] = failed[:200]  # cap for output size

    submission_text = ""
    if submission_path is not None:
        try:
            submission_text = submission_path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            payload["verdict"] = "error"
            payload["reason"] = f"submission unreadable: {exc}"
            return 2, payload

    quarantine_refs: List[Dict[str, Any]] = []
    if submission_text:
        quarantine_refs = find_submission_quarantine_refs(submission_text, audits, tags_dir)
    payload["submission_quarantine_refs"] = quarantine_refs

    # Verdict resolution: any failed records OR any cited quarantine record
    # in the submission fails the gate.
    failed_count = len(failed)
    if failed_count == 0 and not quarantine_refs:
        payload["verdict"] = "pass"
        payload["reason"] = (
            f"audited={payload['audited_hackerman_v1']} (skipped={payload['skipped_non_hackerman_v1']}); "
            "all hackerman-v1 records carry verification_tier; "
            "submission cites zero tier-5 quarantine records"
        )
        return 0, payload

    reasons: List[str] = []
    if failed_count:
        reasons.append(f"{failed_count} record(s) failed verification_tier audit")
    if quarantine_refs:
        reasons.append(
            f"{len(quarantine_refs)} tier-5 quarantine record(s) cited by submission"
        )
    payload["verdict"] = "fail"
    payload["reason"] = "; ".join(reasons)
    return 1, payload


def _print_human(payload: Dict[str, Any]) -> None:
    print("# hackerman-record-verification-tier-check")
    print(f"tags_dir:  {payload['tags_dir']}")
    if payload.get("submission"):
        print(f"submission: {payload['submission']}")
    print(f"scanned:   {payload['scanned']}")
    print(f"audited:   {payload.get('audited_hackerman_v1', 0)} (hackerman v1)")
    print(f"skipped:   {payload.get('skipped_non_hackerman_v1', 0)} (non-hackerman-v1)")
    print()
    print("# verdict_counts")
    for verdict, count in sorted(payload["verdict_counts"].items()):
        print(f"  {verdict:<28} {count:>7}")
    if payload.get("tier_counts"):
        print()
        print("# tier_counts")
        for tier in VERIFICATION_TIERS:
            count = payload["tier_counts"].get(tier, 0)
            print(f"  {tier:<40} {count:>7}")
    failed = payload.get("failed_records") or []
    if failed:
        print()
        print("# failed_records (first 10)")
        for entry in failed[:10]:
            print(f"  - {entry['verdict']:<22} {entry.get('record_id') or '?':<60} {entry['file']}")
            print(f"      reason: {entry.get('reason') or ''}")
    refs = payload.get("submission_quarantine_refs") or []
    if refs:
        print()
        print("# submission cites tier-5 quarantine records")
        for ref in refs:
            print(f"  - {ref.get('record_id') or '?':<60} via={','.join(ref.get('matched_via') or [])}")
            print(f"      {ref.get('rel_path') or ref.get('file')}")
    print()
    print(f"verdict: {payload['verdict']}")
    if payload.get("reason"):
        print(f"reason:  {payload['reason']}")


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument(
        "--tags-dir",
        type=Path,
        default=DEFAULT_TAGS_DIR,
        help="Directory of hackerman corpus tag records.",
    )
    parser.add_argument(
        "--submission",
        type=Path,
        default=None,
        help="Optional submission file; the gate fails if it cites a tier-5 quarantine record.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Cap scanned files (for smoke / CI sanity).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit the full JSON payload on stdout (silences the human report).",
    )
    parser.add_argument(
        "--allow-missing-tags-dir",
        action="store_true",
        help="When the corpus dir is missing, exit 0 with a warning instead of error.",
    )
    args = parser.parse_args(argv)

    rc, payload = run(
        args.tags_dir.expanduser(),
        args.submission.expanduser() if args.submission else None,
        limit=args.limit,
        fail_on_missing_dir=not args.allow_missing_tags_dir,
    )

    if args.json:
        json.dump(payload, sys.stdout, sort_keys=True, indent=2)
        sys.stdout.write("\n")
    else:
        _print_human(payload)

    return rc


if __name__ == "__main__":
    sys.exit(main())
