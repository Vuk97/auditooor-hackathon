#!/usr/bin/env python3
"""r37-real-violation-tier-backfill.

Wave-3 W3.2-CORRECTED lane. Backfills a first-class ``verification_tier``
field onto the ~255 *real* Rule 37 violations that remain after the
``dsl_pattern_*`` family was formally exempted by the Option-B exemption
registry (``audit/corpus_tags/schemas/r37_exemption_registry.yaml``,
commit ``cfaa3501cd``).

Scope
-----
The remaining violations are NOT the synthesized ``dsl_pattern_*``
synthetic-pattern records (those are correctly verification-axis-free
and exempt - tagging them would be a documented category error per
``docs/WAVE3_FOLLOWUPS_FROM_WAVE2_2026-05-16.md`` section 7). The
violations this tool addresses are:

  * the ``verdict_id``-style records under ``audit/corpus_tags/tags/``
    that carry no ``schema_version`` and no ``verification_tier`` field:
    worker verdicts, FN-IMMUNEFI submission records, dydx / spark /
    reserve hunt-candidate verdicts, and publicly-mined ``sibling_*`` /
    ``solodit_*`` records (255 records);

  * the ``dsl_pattern_universal_fp_*`` records: these share the
    ``dsl_pattern_`` filename prefix but are NOT the synthetic-pattern
    family - they are real ``auditooor.hackerman_record.v1``
    cross-protocol fingerprint records (``human-curated``, with a
    ``source_audit_ref``). The exemption registry's ``exemption_gate``
    deliberately does NOT exempt them ("someone moved a real
    hackerman_record file into the dsl_pattern prefix and that file
    should still carry verification_tier"). They carry the tier
    smuggled into ``function_shape.shape_tags`` - this tool lifts it to
    a first-class field (6 records).

The exemption check below is gate-aware: it mirrors the registry's
``exemption_gate`` (a ``dsl_pattern_*`` file is exempt only when it
carries BOTH ``verdict_id`` AND ``extraction_provenance``), so the 6
``universal_fp`` records are correctly treated as violations.

Evidence-based tier assignment
------------------------------
The correct tier is decided from each record's ``extraction_provenance``,
which is a faithful proxy for the record's verification axis:

  * ``extraction_provenance: manual``  -> ``tier-2-verified-public-archive``
        These records were manually mined from a public audit archive
        (the Solodit corpus at solodit.cyfrin.io, or named-firm audit
        catalogs - Zellic / Hexens / DeFiHackLabs). Each carries a
        ``source_url`` / ``source_doc`` plus >=3 shape fields
        (``bug_class``, ``sites``, ``severity_*``, ``triager_outcome``).
        That is exactly the tier-2 definition: parsed-from-public-archive
        with >=3 mandatory shape fields.

  * ``extraction_provenance: hybrid`` / ``regex`` -> ``tier-4-bundled-fixture``
        These records were auto-extracted from the auditooor repo's own
        in-tree audit-loop work-product markdown files (verdict.md,
        CANDIDATES.md, *-IMMUNEFI-SUBMISSION.md). They are in-tree
        fixtures that seed detectors; they are not externally verified,
        not live-API-resolved CVEs, and not synthetic taxonomy seeds.
        That is the tier-4 definition: in-tree test/work-product fixture.

No record in this population qualifies for ``tier-1`` (none carries a
resolvable live-API external ID nor an NVD/GHSA officially-disclosed
anchor) or ``tier-3-synthetic-taxonomy-anchored`` (none is a synthesized
taxonomy seed - the synthetic family is the already-exempt
``dsl_pattern_*`` set).

M14-trap
--------
If a record's ``extraction_provenance`` is missing or is an
unrecognised value, the tool does NOT guess. It assigns
``tier-pending-operator-classify`` and emits an ``r37-rebuttal`` note so
the record is honestly flagged for operator re-classification rather
than mis-tiered.

Schema-version bump for v1 records
----------------------------------
The 6 ``dsl_pattern_universal_fp_*`` records carry
``schema_version: auditooor.hackerman_record.v1``, whose JSON schema
declares ``additionalProperties: false`` and so rejects a first-class
``verification_tier`` field. The ``v1.1`` schema is a strict superset of
``v1`` (identical ``required`` list, adds ``verification_tier`` and 4
other optional properties) - so when a record on the ``v1`` schema
needs the first-class field, this tool also rewrites its
``schema_version`` line to ``auditooor.hackerman_record.v1.1``. This is
the documented Wave-2 W21 migration pattern (41,094 records were flipped
to v1.1 with a first-class verification_tier field). The bump is
non-destructive: every ``v1`` record already satisfies every ``v1.1``
required field.

Idempotency
-----------
A record that already carries a first-class ``verification_tier`` line
is left byte-for-byte unchanged. Re-running ``--apply`` is a no-op once
the backfill has landed. The write is additive (plus, for v1-schema
records, a one-line in-place ``schema_version`` rewrite); no other
existing bytes are rewritten.

Usage
-----
    python3 tools/r37-real-violation-tier-backfill.py --check
    python3 tools/r37-real-violation-tier-backfill.py --apply
"""
from __future__ import annotations

import argparse
import sys
from collections import Counter
from pathlib import Path
from typing import Dict, List, Optional, Tuple

try:
    import yaml
except ImportError:  # pragma: no cover
    print("PyYAML is required: pip install pyyaml", file=sys.stderr)
    sys.exit(2)

REPO_ROOT_GUESS = Path(__file__).resolve().parent.parent
DEFAULT_TAGS_DIR = REPO_ROOT_GUESS / "audit" / "corpus_tags" / "tags"

# Prefix families formally exempted from Rule 37 (verification-axis-free
# synthesized fixtures). The exemption registry is the source of truth;
# this constant mirrors it so the tool never touches an exempt record.
EXEMPT_PREFIXES: Tuple[str, ...] = ("dsl_pattern_",)

TIER_PUBLIC_ARCHIVE = "tier-2-verified-public-archive"
TIER_BUNDLED_FIXTURE = "tier-4-bundled-fixture"
TIER_PENDING = "tier-pending-operator-classify"

# extraction_provenance -> verification_tier mapping (evidence-based).
PROVENANCE_TO_TIER: Dict[str, str] = {
    "manual": TIER_PUBLIC_ARCHIVE,
    "hybrid": TIER_BUNDLED_FIXTURE,
    "regex": TIER_BUNDLED_FIXTURE,
}

R37_REBUTTAL_REASON = (
    "extraction_provenance missing/unrecognised - operator must classify "
    "verification axis (Rule 37 M14-trap, W3.2-CORRECTED)"
)

# Schema versions that declare additionalProperties:false and therefore
# need a bump to v1.1 (strict superset) before a first-class
# verification_tier field can be added.
SCHEMA_V1 = "auditooor.hackerman_record.v1"
SCHEMA_V11 = "auditooor.hackerman_record.v1.1"


# Valid Wave-2 W21 tier values that may legitimately appear smuggled
# into function_shape.shape_tags and be lifted to a first-class field.
ACCEPTED_LIFT_TIERS = frozenset(
    {
        "tier-1-verified-realtime-api",
        "tier-1-officially-disclosed",
        "tier-2-verified-public-archive",
        "tier-3-synthetic-taxonomy-anchored",
        "tier-3-public-archive",
        "tier-4-bundled-fixture",
        "tier-4-protocol-disclosure",
        "tier-5-quarantine",
        "tier-5-third-party-mined",
    }
)


def is_exempt(filename: str, payload: Optional[dict] = None) -> bool:
    """True when the record is covered by the Rule 37 exemption registry.

    Gate-aware: a ``dsl_pattern_*`` file is exempt only when it satisfies
    the registry's ``exemption_gate`` - it must carry BOTH ``verdict_id``
    and ``extraction_provenance`` (the synthetic-pattern schema family).
    A ``dsl_pattern_universal_fp_*`` record is a real
    ``hackerman_record.v1`` file that lacks those fields, so it is NOT
    exempt and must still carry a verification_tier.
    """
    if not any(filename.startswith(p) for p in EXEMPT_PREFIXES):
        return False
    if payload is None or not isinstance(payload, dict):
        # Conservative: without the payload we cannot confirm the gate,
        # so treat as non-exempt (a violation we should look at).
        return False
    return "verdict_id" in payload and "extraction_provenance" in payload


def extract_smuggled_tier(payload: dict) -> Optional[str]:
    """Return a verification_tier value smuggled into shape_tags, if any.

    The documented Rule 37 anti-pattern: the tier is carried as a
    ``verification_tier:<value>`` string inside
    ``function_shape.shape_tags`` instead of a first-class field.
    """
    fs = payload.get("function_shape")
    if not isinstance(fs, dict):
        return None
    tags = fs.get("shape_tags")
    if not isinstance(tags, list):
        return None
    for tag in tags:
        if isinstance(tag, str) and tag.startswith("verification_tier:"):
            value = tag.split(":", 1)[1].strip()
            if value in ACCEPTED_LIFT_TIERS:
                return value
    return None


def classify_tier(payload: dict) -> Tuple[str, bool]:
    """Return (verification_tier, is_pending) for a violation record.

    is_pending is True when the tier could not be decided from evidence
    and the record must be flagged for operator re-classification.

    Resolution order:
      1. A valid tier smuggled into function_shape.shape_tags is lifted
         verbatim to the first-class field (anti-pattern fix).
      2. Otherwise the tier is derived from extraction_provenance.
      3. If neither is available -> pending (M14-trap).
    """
    smuggled = extract_smuggled_tier(payload)
    if smuggled is not None:
        return smuggled, False
    prov = payload.get("extraction_provenance")
    if isinstance(prov, str):
        prov = prov.strip().lower()
    tier = PROVENANCE_TO_TIER.get(prov)
    if tier is None:
        return TIER_PENDING, True
    return tier, False


def find_violations(tags_dir: Path) -> List[Path]:
    """Return record files that are real Rule 37 violations.

    A real violation is a non-exempt record file under tags_dir that
    parses to a mapping and has no first-class ``verification_tier``.
    """
    violations: List[Path] = []
    for path in sorted(tags_dir.glob("*.yaml")):
        try:
            payload = yaml.safe_load(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if not isinstance(payload, dict):
            continue
        if is_exempt(path.name, payload):
            continue
        vt = payload.get("verification_tier")
        if vt in (None, ""):
            violations.append(path)
    return violations


def _bump_schema_version_line(text: str) -> str:
    """Rewrite a top-level ``schema_version: <v1>`` line to v1.1.

    Only the exact v1 value is bumped; any other value (already v1.1,
    or a non-hackerman schema) is left untouched. Operates line-wise so
    no other bytes are disturbed.
    """
    out_lines = []
    for line in text.splitlines(keepends=True):
        stripped = line.rstrip("\n")
        if stripped.replace(" ", "") == f"schema_version:{SCHEMA_V1}":
            indent = line[: len(line) - len(line.lstrip())]
            newline = "\n" if line.endswith("\n") else ""
            out_lines.append(f"{indent}schema_version: {SCHEMA_V11}{newline}")
        else:
            out_lines.append(line)
    return "".join(out_lines)


def append_tier_line(path: Path, tier: str, is_pending: bool) -> bool:
    """Append a first-class verification_tier line. Idempotent.

    Returns True when the file was modified, False when it already
    carried a verification_tier line (no-op).

    For records on the v1 schema (additionalProperties:false), the
    top-level ``schema_version`` line is bumped to v1.1 (strict
    superset) so the first-class field validates.
    """
    text = path.read_text(encoding="utf-8")
    payload = yaml.safe_load(text)
    if isinstance(payload, dict) and payload.get("verification_tier") not in (
        None,
        "",
    ):
        return False
    if isinstance(payload, dict) and payload.get("schema_version") == SCHEMA_V1:
        text = _bump_schema_version_line(text)
    if not text.endswith("\n"):
        text += "\n"
    text += f"verification_tier: {tier}\n"
    if is_pending:
        # r37-rebuttal marker so the gate tags the record
        # tier-pending-operator-classify rather than hard-failing.
        text += f"r37_rebuttal: '{R37_REBUTTAL_REASON}'\n"
    path.write_text(text, encoding="utf-8")
    return True


def run(tags_dir: Path, apply: bool) -> int:
    violations = find_violations(tags_dir)
    tier_counts: Counter = Counter()
    pending: List[str] = []
    would_write: List[Tuple[Path, str, bool]] = []

    for path in violations:
        payload = yaml.safe_load(path.read_text(encoding="utf-8"))
        tier, is_pending = classify_tier(payload)
        tier_counts[tier] += 1
        if is_pending:
            pending.append(path.name)
        would_write.append((path, tier, is_pending))

    mode = "APPLY" if apply else "CHECK"
    print(f"# r37-real-violation-tier-backfill ({mode})")
    print(f"tags_dir:         {tags_dir}")
    print(f"violations_found: {len(violations)}")
    print("tier_breakdown:")
    for tier in (TIER_PUBLIC_ARCHIVE, TIER_BUNDLED_FIXTURE, TIER_PENDING):
        print(f"  {tier:34s} {tier_counts.get(tier, 0)}")
    if pending:
        print(f"pending_operator_classify ({len(pending)}):")
        for name in pending:
            print(f"  - {name}")

    if not apply:
        if violations:
            print("\nrun with --apply to backfill the verification_tier field")
        return 1 if violations else 0

    modified = 0
    for path, tier, is_pending in would_write:
        if append_tier_line(path, tier, is_pending):
            modified += 1
    print(f"\nfiles_modified:   {modified}")
    print(f"already_compliant: {len(violations) - modified}")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Backfill first-class verification_tier on real "
        "Rule 37 violations (W3.2-CORRECTED).",
    )
    parser.add_argument(
        "--tags-dir",
        type=Path,
        default=DEFAULT_TAGS_DIR,
        help="Directory of corpus record YAML files.",
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--check",
        action="store_true",
        help="Report what would change; exit non-zero if violations remain.",
    )
    mode.add_argument(
        "--apply",
        action="store_true",
        help="Append the first-class verification_tier field in place.",
    )
    args = parser.parse_args(argv)
    return run(args.tags_dir, apply=args.apply)


if __name__ == "__main__":
    raise SystemExit(main())
