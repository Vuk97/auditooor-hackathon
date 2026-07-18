#!/usr/bin/env python3
"""hackerman-corpus-subdir-acceptance-check.

Acceptance-test gate for Hackerman corpus subtrees. Verifies that every NEW
corpus subtree under ``audit/corpus_tags/tags/`` has tier-1 or tier-2
coverage on at least ``--min-coverage-pct`` (default 80) of its records.

Each record's verification tier is read from its
``function_shape.shape_tags`` array. The strict-form tag is
``verification_tier:tier-N-<slug>`` where N is 1..5 (mirrors
``tools/hackerman-stratify-verification-tier.py`` and
``tools/hackerman-record-verification-tier-check.py``).

Records without a strict ``verification_tier:`` shape_tag are counted as
``unlabeled`` and DO contribute toward the >20% threshold. Records under a
``_QUARANTINE_*`` subtree are excluded from the gate (they are expected to
be tier-5 by construction).

This tool is REPORT-ONLY. It never edits records and never auto-fails an
existing corpus directory at the orchestration level (it emits per-dir
``fail`` or ``pass`` verdicts but the exit code stays 0 by default so the
gate is runnable / introspectable as a standalone command). Pass
``--strict`` to make it exit 1 when any directory fails the threshold; the
pre-submit-check wire-in is a separate lane.

Usage:

    # Scan every subdir under audit/corpus_tags/tags/ (excluding _QUARANTINE_*)
    python3 tools/hackerman-corpus-subdir-acceptance-check.py --all

    # Scan a single subdir
    python3 tools/hackerman-corpus-subdir-acceptance-check.py \\
        --corpus-dir audit/corpus_tags/tags/dex_fix_history

    # Emit JSON for downstream tooling
    python3 tools/hackerman-corpus-subdir-acceptance-check.py --all --json

Exit codes:

    0  - report emitted (default)
    1  - --strict and at least one directory fails the threshold
    2  - input error (missing dir, invalid args)
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


SCHEMA = "auditooor.hackerman_corpus_subdir_acceptance_check.v1"
HACKERMAN_V1_SCHEMA = "auditooor.hackerman_record.v1"

REPO_ROOT_GUESS = Path(__file__).resolve().parent.parent
DEFAULT_TAGS_DIR = REPO_ROOT_GUESS / "audit" / "corpus_tags" / "tags"
DEFAULT_EXEMPTIONS_PATH = (
    REPO_ROOT_GUESS / "audit" / "corpus_tags" / "acceptance_exemptions.yaml"
)
EXEMPTIONS_SCHEMA = "auditooor.hackerman_corpus_acceptance_exemptions.v1"

VERIFICATION_TIERS = (
    "tier-1-verified-realtime-api",
    "tier-1-officially-disclosed",
    "tier-2-verified-public-archive",
    "tier-3-synthetic-taxonomy-anchored",
    "tier-4-bundled-fixture",
    "tier-5-quarantine",
)

# ACCEPTED_TIER_PREFIXES uses plain "tier-1" / "tier-2" prefix-match, which
# already covers `tier-1-officially-disclosed` (Wave-2 PR-A follow-up to
# ad3cc4bda7; closes the Vyper-CVE rebuilder verification_label workaround).
ACCEPTED_TIER_PREFIXES = ("tier-1", "tier-2")

QUARANTINE_PATH_MARKERS = (
    "_QUARANTINE_FABRICATED_CVE",
    "_QUARANTINE_FABRICATED",
    "_QUARANTINE_",
)

VERIFICATION_TIER_VALUE_RE = re.compile(
    r"^verification_tier:(tier-[1-5]-[a-z0-9][a-z0-9-]*)$"
)


# --------------------------------------------------------------------------- #
# Record loading (YAML / JSON minimal parsers; mirrors sibling tools)
# --------------------------------------------------------------------------- #


def _strip_yaml_quotes(value: str) -> str:
    v = value.strip()
    if len(v) >= 2 and ((v[0] == '"' and v[-1] == '"') or (v[0] == "'" and v[-1] == "'")):
        return v[1:-1]
    return v


def _extract_shape_tags_and_schema(text: str, fmt: str) -> Tuple[List[str], Optional[str]]:
    if fmt == "json":
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            return [], None
        schema_version = payload.get("schema_version")
        shape = payload.get("function_shape") or {}
        tags = shape.get("shape_tags") or []
        if not isinstance(tags, list):
            tags = []
        return (
            [str(t) for t in tags],
            schema_version if isinstance(schema_version, str) else None,
        )

    schema_version: Optional[str] = None
    lines = text.splitlines()
    in_fs = False
    in_tags = False
    tags_indent: Optional[int] = None
    tags: List[str] = []
    for raw in lines:
        if not raw.strip():
            continue
        stripped = raw.strip()
        if not raw.startswith(" ") and not raw.startswith("\t"):
            if stripped.startswith("schema_version:"):
                _, _, rhs = stripped.partition(":")
                schema_version = _strip_yaml_quotes(rhs.strip())
            if stripped.startswith("function_shape:"):
                in_fs = True
                in_tags = False
                continue
            # Any other top-level key ends function_shape block.
            in_fs = False
            in_tags = False
            continue
        if not in_fs:
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        if stripped.startswith("shape_tags:"):
            in_tags = True
            tags_indent = indent
            continue
        if in_tags:
            if stripped.startswith("- "):
                if tags_indent is not None and indent >= tags_indent:
                    tags.append(_strip_yaml_quotes(stripped[2:].strip()))
                    continue
                in_tags = False
            else:
                if tags_indent is not None and indent <= tags_indent:
                    in_tags = False
    return tags, schema_version


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
# Exemptions registry
# --------------------------------------------------------------------------- #


def _parse_exemptions_yaml(text: str) -> Dict[str, Dict[str, Any]]:
    """Minimal YAML parser for the acceptance_exemptions.yaml registry shape.

    The shape we accept is intentionally narrow (the file is hand-authored;
    we avoid taking a PyYAML dep):

        schema: auditooor.hackerman_corpus_acceptance_exemptions.v1
        generated_at: 2026-05-16
        documented_in: docs/...
        exemptions:
          - corpus_dir: <name>
            category: A
            reason: ...
            expected_tier_distribution:
              tier-1: 0.2
              tier-3: 0.8
            review_at: 2026-06-15
            documented_in: docs/...

    Returns a mapping ``corpus_dir -> entry-dict`` for fast lookup. Unknown /
    malformed entries are skipped silently (the gate is report-only and we
    do not want a registry typo to block the gate). A best-effort policy is
    fine because the human table still shows the exempted rows.
    """
    if not text.strip():
        return {}
    out: Dict[str, Dict[str, Any]] = {}
    lines = text.splitlines()
    i = 0
    in_exemptions = False
    current: Optional[Dict[str, Any]] = None
    current_etd: Optional[Dict[str, float]] = None
    in_etd = False

    def _flush(entry: Optional[Dict[str, Any]]) -> None:
        if not entry:
            return
        cd = entry.get("corpus_dir")
        if isinstance(cd, str) and cd:
            out[cd] = entry

    while i < len(lines):
        raw = lines[i]
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            i += 1
            continue
        indent = len(raw) - len(raw.lstrip(" "))

        # Top-level keys (indent 0)
        if indent == 0:
            if stripped.startswith("exemptions:"):
                in_exemptions = True
                _flush(current)
                current = None
                current_etd = None
                in_etd = False
                i += 1
                continue
            # Other top-level scalars (schema:, generated_at:, etc.) we ignore.
            in_exemptions = False
            _flush(current)
            current = None
            current_etd = None
            in_etd = False
            i += 1
            continue

        if not in_exemptions:
            i += 1
            continue

        # List item start: "  - corpus_dir: <name>" or "  - key: value"
        if stripped.startswith("- "):
            _flush(current)
            current = {}
            current_etd = None
            in_etd = False
            inline = stripped[2:].strip()
            # Inline first key (typical YAML list-of-map shape)
            if ":" in inline:
                key, _, rhs = inline.partition(":")
                key = key.strip()
                val = _strip_yaml_quotes(rhs.strip())
                current[key] = val
            i += 1
            continue

        # Continuation of current entry
        if current is None:
            i += 1
            continue
        if ":" in stripped:
            key, _, rhs = stripped.partition(":")
            key = key.strip()
            val = _strip_yaml_quotes(rhs.strip())
            if key == "expected_tier_distribution" and val == "":
                # Nested map follows; collect indented children.
                current_etd = {}
                in_etd = True
                current[key] = current_etd
                i += 1
                continue
            if in_etd and key.startswith("tier-") and val:
                try:
                    current_etd[key] = float(val)  # type: ignore[union-attr]
                except (TypeError, ValueError):
                    pass
                i += 1
                continue
            # Any non-tier key under the entry terminates the etd nested map.
            in_etd = False
            current_etd = None
            current[key] = val
        i += 1

    _flush(current)
    return out


def load_exemptions(
    path: Optional[Path] = None,
) -> Dict[str, Dict[str, Any]]:
    """Load the acceptance-exemptions registry.

    Returns an empty dict if the file is missing (registry is optional).
    Malformed entries are skipped silently.
    """
    target = path if path is not None else DEFAULT_EXEMPTIONS_PATH
    if not target.exists():
        return {}
    try:
        text = target.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return {}
    return _parse_exemptions_yaml(text)


# --------------------------------------------------------------------------- #
# Per-record + per-directory audit
# --------------------------------------------------------------------------- #


def _is_quarantine_dir(corpus_dir: Path) -> bool:
    name_upper = corpus_dir.name.upper()
    for marker in QUARANTINE_PATH_MARKERS:
        if marker.upper() in name_upper:
            return True
    return False


def _iter_record_files(corpus_dir: Path) -> Iterable[Path]:
    """Yield candidate record files inside corpus_dir.

    Supports two shapes:
      - per-dir bundle: ``corpus_dir/<slug>/record.yaml`` (preferred when
        present; sibling ``record.json`` is then ignored to avoid double
        counting the same record).
      - flat ``.yaml`` files directly under corpus_dir.
    """
    if not corpus_dir.exists() or not corpus_dir.is_dir():
        return
    for path in sorted(corpus_dir.rglob("*")):
        if not path.is_file():
            continue
        name = path.name.lower()
        if name == "readme.md":
            continue
        if name == "record.yaml":
            yield path
            continue
        if name == "record.json":
            # Prefer the YAML sibling if present, otherwise emit the JSON.
            if (path.parent / "record.yaml").exists():
                continue
            yield path
            continue
        if path.suffix.lower() == ".yaml":
            # Skip flat YAMLs in a directory that also has a sibling
            # record.yaml (e.g. a backup or sidecar). Otherwise treat as a
            # flat record.
            sibling = path.parent / "record.yaml"
            if sibling.exists() and sibling != path:
                continue
            yield path


def classify_record(shape_tags: List[str]) -> Tuple[str, Optional[str]]:
    """Return (bucket, raw_tier_value).

    Bucket is one of: ``tier-1``, ``tier-2``, ``tier-3``, ``tier-4``,
    ``tier-5``, ``unlabeled``. Records with multiple strict
    ``verification_tier:`` tags are reported with the FIRST one; the
    multi-tier shape is otherwise out of this tool's scope (the sibling
    ``hackerman-record-verification-tier-check`` flags it separately).
    """
    for tag in shape_tags:
        m = VERIFICATION_TIER_VALUE_RE.match(tag.strip())
        if m:
            value = m.group(1)
            for tier in VERIFICATION_TIERS:
                if value == tier:
                    return tier.split("-")[0] + "-" + tier.split("-")[1], value
            # Strict-form but unknown slug; treat as unlabeled.
            return "unlabeled", value
    return "unlabeled", None


def audit_record(path: Path) -> Dict[str, Any]:
    fmt = "json" if path.suffix.lower() == ".json" else "yaml"
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return {
            "file": str(path),
            "record_id": None,
            "schema_version": None,
            "format": fmt,
            "bucket": "error",
            "verification_tier": None,
            "reason": f"unreadable: {exc}",
        }
    shape_tags, schema_version = _extract_shape_tags_and_schema(text, fmt)
    record_id = _extract_record_id(text, fmt)
    # Accept both v1 and v1.1 (Wave-2 Phase-3 schema migration). Use
    # prefix-match so future v1.x minor bumps remain in-gate without a
    # tool-side rev. Sibling verdict_tag.v2 YAMLs still fail this check.
    if not str(schema_version or "").startswith(HACKERMAN_V1_SCHEMA):
        return {
            "file": str(path),
            "record_id": record_id,
            "schema_version": schema_version,
            "format": fmt,
            "bucket": "skipped-non-hackerman-v1",
            "verification_tier": None,
            "reason": f"schema_version={schema_version!r}; out of gate scope",
        }
    bucket, tier_value = classify_record(shape_tags)
    return {
        "file": str(path),
        "record_id": record_id,
        "schema_version": schema_version,
        "format": fmt,
        "bucket": bucket,
        "verification_tier": tier_value,
        "reason": "ok",
    }


def audit_corpus_dir(
    corpus_dir: Path,
    *,
    min_coverage_pct: float = 80.0,
    tags_dir: Optional[Path] = None,
) -> Dict[str, Any]:
    """Audit a single corpus subdirectory; return a verdict dict.

    Verdicts:
      - ``skip-quarantine``   directory matches a _QUARANTINE_ marker
      - ``skip-empty``        no hackerman v1 records found
      - ``pass``              tier-1 + tier-2 coverage >= min_coverage_pct
      - ``fail``              coverage below threshold (>20% non-tier-1/2)
    """
    quarantine = _is_quarantine_dir(corpus_dir)
    if quarantine:
        return {
            "corpus_dir": str(corpus_dir),
            "verdict": "skip-quarantine",
            "reason": "quarantine subtree excluded by design",
            "record_count": 0,
            "hackerman_record_count": 0,
            "skipped_non_hackerman_v1": 0,
            "bucket_counts": {},
            "tier1_tier2_count": 0,
            "tier1_tier2_pct": 0.0,
            "min_coverage_pct": min_coverage_pct,
        }

    bucket_counts: Counter[str] = Counter()
    skipped = 0
    record_count = 0
    record_details: List[Dict[str, Any]] = []
    for path in _iter_record_files(corpus_dir):
        record_count += 1
        result = audit_record(path)
        bucket = result["bucket"]
        if bucket == "skipped-non-hackerman-v1":
            skipped += 1
            continue
        if bucket == "error":
            bucket_counts["error"] += 1
            record_details.append(result)
            continue
        bucket_counts[bucket] += 1
        record_details.append(result)

    hackerman_count = sum(
        c for b, c in bucket_counts.items() if b != "error"
    )
    tier1_2 = bucket_counts.get("tier-1", 0) + bucket_counts.get("tier-2", 0)
    if hackerman_count == 0:
        return {
            "corpus_dir": str(corpus_dir),
            "verdict": "skip-empty",
            "reason": "no hackerman v1 records found",
            "record_count": record_count,
            "hackerman_record_count": 0,
            "skipped_non_hackerman_v1": skipped,
            "bucket_counts": dict(bucket_counts),
            "tier1_tier2_count": 0,
            "tier1_tier2_pct": 0.0,
            "min_coverage_pct": min_coverage_pct,
        }
    pct = 100.0 * tier1_2 / hackerman_count
    verdict = "pass" if pct >= min_coverage_pct else "fail"
    return {
        "corpus_dir": str(corpus_dir),
        "verdict": verdict,
        "reason": (
            f"tier-1+tier-2 coverage {pct:.2f}% "
            f"({'>=' if verdict == 'pass' else '<'} {min_coverage_pct:.2f}%)"
        ),
        "record_count": record_count,
        "hackerman_record_count": hackerman_count,
        "skipped_non_hackerman_v1": skipped,
        "bucket_counts": dict(bucket_counts),
        "tier1_tier2_count": tier1_2,
        "tier1_tier2_pct": pct,
        "min_coverage_pct": min_coverage_pct,
    }


# --------------------------------------------------------------------------- #
# Driver
# --------------------------------------------------------------------------- #


def _select_subdirs(tags_dir: Path) -> List[Path]:
    if not tags_dir.exists() or not tags_dir.is_dir():
        return []
    out: List[Path] = []
    for p in sorted(tags_dir.iterdir()):
        if not p.is_dir():
            continue
        if _is_quarantine_dir(p):
            continue
        out.append(p)
    return out


def _format_summary_table(reports: List[Dict[str, Any]]) -> str:
    headers = [
        "corpus_dir",
        "records",
        "hkv1",
        "t1",
        "t2",
        "t3",
        "t4",
        "t5",
        "unlabeled",
        "t1+t2 pct",
        "verdict",
    ]
    rows: List[List[str]] = []
    for rep in reports:
        bc = rep.get("bucket_counts", {}) or {}
        rows.append(
            [
                Path(rep["corpus_dir"]).name,
                str(rep.get("record_count", 0)),
                str(rep.get("hackerman_record_count", 0)),
                str(bc.get("tier-1", 0)),
                str(bc.get("tier-2", 0)),
                str(bc.get("tier-3", 0)),
                str(bc.get("tier-4", 0)),
                str(bc.get("tier-5", 0)),
                str(bc.get("unlabeled", 0)),
                f"{rep.get('tier1_tier2_pct', 0.0):.2f}",
                rep.get("verdict", "?"),
            ]
        )
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))

    def _fmt_row(cells: List[str]) -> str:
        return "  ".join(c.ljust(widths[i]) for i, c in enumerate(cells))

    lines = [_fmt_row(headers), _fmt_row(["-" * w for w in widths])]
    for row in rows:
        lines.append(_fmt_row(row))
    return "\n".join(lines)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument(
        "--corpus-dir",
        type=Path,
        help="Single corpus subdirectory to audit "
        "(e.g. audit/corpus_tags/tags/dex_fix_history/).",
    )
    src.add_argument(
        "--all",
        action="store_true",
        help="Audit every subdir under --tags-dir (excluding _QUARANTINE_*).",
    )
    parser.add_argument(
        "--tags-dir",
        type=Path,
        default=DEFAULT_TAGS_DIR,
        help="Root tags directory used when --all is passed.",
    )
    parser.add_argument(
        "--min-coverage-pct",
        type=float,
        default=80.0,
        help="Minimum tier-1+tier-2 coverage percentage for PASS (default 80).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON instead of the human report.",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Return exit code 1 when any directory has verdict=fail.",
    )
    parser.add_argument(
        "--exemptions-file",
        type=Path,
        default=None,
        help=(
            "Path to the acceptance-exemptions registry "
            "(default: audit/corpus_tags/acceptance_exemptions.yaml)."
        ),
    )
    parser.add_argument(
        "--no-exempt",
        action="store_true",
        help=(
            "Bypass the exemptions registry. Fail-exempt subtrees are "
            "reported as plain `fail` and count toward --strict exit-1."
        ),
    )
    args = parser.parse_args(argv)

    if args.all:
        targets = _select_subdirs(args.tags_dir)
        if not targets:
            print(
                f"error: no non-quarantine subdirs found under {args.tags_dir}",
                file=sys.stderr,
            )
            return 2
    else:
        if not args.corpus_dir.exists() or not args.corpus_dir.is_dir():
            print(
                f"error: corpus dir does not exist or is not a directory: "
                f"{args.corpus_dir}",
                file=sys.stderr,
            )
            return 2
        targets = [args.corpus_dir]

    reports: List[Dict[str, Any]] = []
    for d in targets:
        reports.append(
            audit_corpus_dir(d, min_coverage_pct=args.min_coverage_pct)
        )

    # Load exemptions registry (no-op when --no-exempt).
    if args.no_exempt:
        exemptions: Dict[str, Dict[str, Any]] = {}
    else:
        exemptions = load_exemptions(args.exemptions_file)

    # Annotate exempt fails. Strict exit-1 ignores them; the human/JSON
    # report still surfaces the row with verdict=fail-exempt so the operator
    # can see what is being skipped and revisit when a deep-mine lane
    # upgrades the subtree.
    for r in reports:
        if r.get("verdict") != "fail":
            continue
        name = Path(r["corpus_dir"]).name
        ex = exemptions.get(name)
        if not ex:
            continue
        r["verdict"] = "fail-exempt"
        r["exemption"] = {
            "category": ex.get("category"),
            "reason": ex.get("reason"),
            "review_at": ex.get("review_at"),
            "expected_tier_distribution": ex.get("expected_tier_distribution"),
            "documented_in": ex.get("documented_in"),
        }

    any_real_fail = any(r.get("verdict") == "fail" for r in reports)

    if args.json:
        payload = {
            "schema": SCHEMA,
            "min_coverage_pct": args.min_coverage_pct,
            "directory_count": len(reports),
            "fail_count": sum(1 for r in reports if r.get("verdict") == "fail"),
            "fail_exempt_count": sum(
                1 for r in reports if r.get("verdict") == "fail-exempt"
            ),
            "pass_count": sum(1 for r in reports if r.get("verdict") == "pass"),
            "skip_count": sum(
                1
                for r in reports
                if r.get("verdict") in {"skip-quarantine", "skip-empty"}
            ),
            "exemptions_loaded": len(exemptions),
            "no_exempt": bool(args.no_exempt),
            "reports": reports,
        }
        print(json.dumps(payload, sort_keys=True, indent=2))
    else:
        print("# hackerman corpus-subdir acceptance check")
        print(f"min_coverage_pct: {args.min_coverage_pct:.2f}%")
        print(f"directories scanned: {len(reports)}")
        if exemptions and not args.no_exempt:
            print(f"exemptions loaded: {len(exemptions)}")
        if args.no_exempt:
            print("exemptions bypassed (--no-exempt)")
        print()
        print(_format_summary_table(reports))
        print()
        fail_dirs = [r for r in reports if r.get("verdict") == "fail"]
        exempt_dirs = [r for r in reports if r.get("verdict") == "fail-exempt"]
        if fail_dirs:
            print(f"# {len(fail_dirs)} dir(s) below threshold (non-exempt):")
            for r in fail_dirs:
                bc = r.get("bucket_counts", {}) or {}
                non_accepted = (
                    bc.get("tier-3", 0)
                    + bc.get("tier-4", 0)
                    + bc.get("tier-5", 0)
                    + bc.get("unlabeled", 0)
                )
                total = r.get("hackerman_record_count", 0) or 0
                pct_bad = (100.0 * non_accepted / total) if total else 0.0
                print(
                    f"  - {Path(r['corpus_dir']).name}: "
                    f"{r.get('tier1_tier2_pct', 0.0):.2f}% tier-1/2, "
                    f"{pct_bad:.2f}% tier-3/4/5/unlabeled"
                )
        else:
            print("# no non-exempt directories below threshold.")
        if exempt_dirs:
            print()
            print(
                f"# {len(exempt_dirs)} dir(s) below threshold but exempt "
                "(not counted toward --strict):"
            )
            for r in exempt_dirs:
                ex = r.get("exemption", {}) or {}
                cat = ex.get("category") or "?"
                reason = ex.get("reason") or ""
                review = ex.get("review_at") or "indefinite"
                print(
                    f"  - {Path(r['corpus_dir']).name} "
                    f"[cat-{cat}, review_at={review}]: "
                    f"{r.get('tier1_tier2_pct', 0.0):.2f}% tier-1/2 - {reason}"
                )

    if args.strict and any_real_fail:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
