#!/usr/bin/env python3
"""Migrator: hackerman_record v1 -> v1.1 (Wave-2 schema additions).

Lifts smuggled fields into first-class properties:

  * verification_tier: extracted from function_shape.shape_tags entries that
    match the prefix `verification_tier:tier-<N>-*`. The shape_tag is left in
    place during the one-wave double-write window so v1-only consumers keep
    working (Wave-3 strips the legacy shape_tag once parity-check passes).

  * record_source_url: extracted from required_preconditions entries that
    match an http(s) URL pattern. The first URL-bearing entry is hoisted and
    dropped from the required_preconditions array (subject to the v1 minItems
    constraint: if removing it would empty the array, the entry is preserved
    in-place so the result remains schema-valid; an operator-side cleanup pass
    can re-derive a real precondition later).

  * cve_id: regex-extracted from source_audit_ref, record_id, target_component,
    attacker_action_sequence, fix_pattern, required_preconditions joined.
    First match wins.

  * ghsa_id: same set of fields, first match wins.

Idempotent: re-running on a v1.1 record (with verification_tier/cve_id/ghsa_id
already populated) is a no-op for those fields; the migrator only writes a
field if it is not already set. Schema_version is bumped to
`auditooor.hackerman_record.v1.1`.

NOTE: This migrator DOES NOT auto-run over the corpus. It is a library +
single-file CLI that operators can wire into a backfill pass under explicit
scope.

Usage (single-file):
  python3 tools/hackerman-schema-v1-to-v1.1-migrator.py \
      --in path/to/record.json --out path/to/record.v11.json

Usage (library):
  from tools import hackerman_schema_v1_to_v1_1_migrator as M
  v11 = M.migrate_record(v1_record)
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from typing import Any, Dict, Iterable, List, Optional, Tuple

# Public regex contracts: keep aligned with the v1.1 schema property patterns.
VERIFICATION_TIER_VALUES = (
    "tier-1-verified-realtime-api",
    "tier-2-verified-public-archive",
    "tier-3-synthetic-taxonomy-anchored",
    "tier-4-bundled-fixture",
    "tier-5-quarantine",
)
_VERIFICATION_TIER_SET = frozenset(VERIFICATION_TIER_VALUES)
_SHAPE_TAG_PREFIX = "verification_tier:"

_URL_RE = re.compile(r"https?://[^\s\"'`<>\[\]{}|\\^]+")
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b")
_GHSA_RE = re.compile(r"\bGHSA-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}\b")

# Field scan order for cve_id / ghsa_id extraction. First match wins.
_SCAN_FIELDS = (
    "source_audit_ref",
    "record_id",
    "target_component",
    "attacker_action_sequence",
    "fix_pattern",
    "fix_anti_pattern_avoided",
    "bug_class",
    "attack_class",
)


def _extract_verification_tier(record: Dict[str, Any]) -> Optional[str]:
    fn_shape = record.get("function_shape")
    if not isinstance(fn_shape, dict):
        return None
    shape_tags = fn_shape.get("shape_tags")
    if not isinstance(shape_tags, list):
        return None
    for tag in shape_tags:
        if not isinstance(tag, str):
            continue
        if not tag.startswith(_SHAPE_TAG_PREFIX):
            continue
        candidate = tag[len(_SHAPE_TAG_PREFIX):]
        if candidate in _VERIFICATION_TIER_SET:
            return candidate
    return None


def _extract_url_from_preconditions(
    record: Dict[str, Any],
) -> Tuple[Optional[str], Optional[List[str]]]:
    """Returns (hoisted_url, mutated_preconditions_list_or_None).

    If a URL-bearing entry is found AND removing it leaves >= 1 entry, the
    mutated list is returned with that entry removed. Otherwise the mutated
    list is None (caller leaves preconditions in place to preserve the v1
    minItems:1 constraint).
    """
    preconds = record.get("required_preconditions")
    if not isinstance(preconds, list):
        return None, None
    for idx, entry in enumerate(preconds):
        if not isinstance(entry, str):
            continue
        m = _URL_RE.search(entry)
        if not m:
            continue
        url = m.group(0)
        # Drop the entry only if removal leaves the array non-empty.
        if len(preconds) > 1:
            mutated = list(preconds[:idx]) + list(preconds[idx + 1:])
            return url, mutated
        return url, None
    return None, None


def _scan_for(regex: re.Pattern[str], record: Dict[str, Any]) -> Optional[str]:
    for field in _SCAN_FIELDS:
        value = record.get(field)
        if isinstance(value, str):
            m = regex.search(value)
            if m:
                return m.group(0)
    # Also scan record_source_url (which may have been hoisted earlier in
    # the same migration pass and which commonly embeds CVE/GHSA tokens in
    # GitHub advisory URLs).
    rsu = record.get("record_source_url")
    if isinstance(rsu, str):
        m = regex.search(rsu)
        if m:
            return m.group(0)
    preconds = record.get("required_preconditions")
    if isinstance(preconds, list):
        for entry in preconds:
            if isinstance(entry, str):
                m = regex.search(entry)
                if m:
                    return m.group(0)
    related = record.get("related_records")
    if isinstance(related, list):
        for entry in related:
            if isinstance(entry, str):
                m = regex.search(entry)
                if m:
                    return m.group(0)
    return None


def _normalize_ghsa(ghsa: str) -> str:
    # The schema pattern accepts mixed case; the GitHub canonical form is
    # lowercase. We preserve the case of the source match so the migrator is
    # purely lossless / non-canonicalizing.
    return ghsa


def migrate_record(record: Dict[str, Any]) -> Dict[str, Any]:
    """Return a new dict with v1.1 additive fields populated where derivable.

    Idempotent: existing values are preserved. The original record is not
    mutated. The original `required_preconditions` URL entry is preserved
    in place when removing it would violate v1 minItems:1.
    """
    if not isinstance(record, dict):
        raise TypeError("migrate_record expects a dict")
    out: Dict[str, Any] = dict(record)

    # 1. verification_tier
    if "verification_tier" not in out or not out.get("verification_tier"):
        tier = _extract_verification_tier(out)
        if tier:
            out["verification_tier"] = tier

    # 2. record_source_url + mutated preconditions
    if "record_source_url" not in out or not out.get("record_source_url"):
        url, mutated = _extract_url_from_preconditions(out)
        if url:
            out["record_source_url"] = url
            if mutated is not None:
                out["required_preconditions"] = mutated

    # 3. cve_id
    if "cve_id" not in out or not out.get("cve_id"):
        cve = _scan_for(_CVE_RE, out)
        if cve:
            out["cve_id"] = cve

    # 4. ghsa_id
    if "ghsa_id" not in out or not out.get("ghsa_id"):
        ghsa = _scan_for(_GHSA_RE, out)
        if ghsa:
            out["ghsa_id"] = _normalize_ghsa(ghsa)

    # 5. schema_version bump.
    sv = out.get("schema_version")
    if sv == "auditooor.hackerman_record.v1":
        out["schema_version"] = "auditooor.hackerman_record.v1.1"

    return out


def _main(argv: Iterable[str]) -> int:
    ap = argparse.ArgumentParser(
        description=(
            "Migrate a single hackerman_record JSON file from v1 to v1.1. "
            "Does NOT auto-run over the corpus; operators wire this into a "
            "backfill pass."
        ),
    )
    ap.add_argument("--in", dest="inp", required=True, help="Input JSON path.")
    ap.add_argument("--out", dest="out", required=True, help="Output JSON path.")
    ap.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the migrated record to stdout instead of writing --out.",
    )
    args = ap.parse_args(list(argv))

    with open(args.inp, "r", encoding="utf-8") as fh:
        record = json.load(fh)
    migrated = migrate_record(record)
    if args.dry_run:
        json.dump(migrated, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
        return 0
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(migrated, fh, indent=2, sort_keys=True)
        fh.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv[1:]))
