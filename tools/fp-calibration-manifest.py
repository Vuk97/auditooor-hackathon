#!/usr/bin/env python3
"""fp-calibration-manifest.py — read/write the FP-calibration manifest.

P1-4 burn-down (KNOWN_LIMITATIONS.md). The clean-codebase FP calibration loop
(``tools/fp-calibration.sh``, ``docs/archive/FP_CALIBRATION.md``) already
runs against OpenZeppelin / Solady / Solmate at pinned tags and emits
``docs/archive/FP_CALIBRATION_REPORT.md`` for human inspection. That report is
prose; auditooor close-out cannot say "this Tier-A pattern was last calibrated
on N clean codebases on date D, precision X%" without a machine-readable
sidecar.

This tool is that sidecar. It reads, writes, validates, and lints a small
JSON manifest with one row per detector pattern. The manifest is checked
into the repo at ``reference/fp_calibration_manifest.json`` so it travels
with the patterns themselves (cross-engagement) — not with a particular
audit workspace.

Schema (one row per pattern; manifest is ``patterns: { <name>: <row> }``)
-------------------------------------------------------------------------

Each row carries:

- ``pattern`` (str) — detector / DSL pattern name. Echoed in the row body
  so the manifest is greppable when the file is read line by line.
- ``tier`` (str) — last-known tier from ``detectors/_tier_registry.yaml``
  at the time of calibration ("S", "A", "B", ...). Stored so the freshness
  rule can be applied without re-reading the registry.
- ``last_calibrated_iso`` (str, ISO 8601 UTC) — when the calibration row
  was last written, e.g. ``2026-04-29T12:34:56Z``.
- ``clean_codebases_count`` (int) — how many distinct clean reference
  codebases were scanned for this row.
- ``clean_corpus_hash`` (str) — short content-addressed hash of the
  corpus list + pinned versions (e.g. ``oz@v5.1.0+solady@v0.0.287+...``,
  SHA-256, first 16 hex chars). Used to detect "the corpus changed but
  the manifest didn't".
- ``precision_pct`` (float, 0..100) — measured precision for this pattern
  on the corpus run that produced this row. Conventionally 100.0 means
  the pattern fired zero times on the clean corpus (no FP).
- ``notes`` (str, optional) — free-text caveat. Not parsed.

Modes
-----

::

    python3 tools/fp-calibration-manifest.py --read
    python3 tools/fp-calibration-manifest.py --update <pattern> \\
        --tier <S|A|B|C|D|E> \\
        --precision <pct> \\
        --corpus <hash> \\
        --clean-codebases <count> \\
        [--notes "..."]
    python3 tools/fp-calibration-manifest.py --validate
    python3 tools/fp-calibration-manifest.py --required-for-tier-sa
    python3 tools/fp-calibration-manifest.py --required-for-tier-sa --json

Discipline
----------

- Stdlib only. No ``yaml``, no ``jsonschema``.
- Atomic writes (tempfile + ``os.replace``).
- Deterministic key ordering on write.
- Workspace-rooted: the manifest lives at
  ``<repo>/reference/fp_calibration_manifest.json``.
- ``--required-for-tier-sa`` exits 1 (fail closed) when any Tier-S/A
  pattern has no row, or has a row older than ``--max-age-days`` (default
  90). Used by the close-out check and CI lints.
- The manifest is intentionally small (Tier-S/A is a few dozen patterns
  at most). We do not stream / shard.

Exit codes
----------
0  read/update succeeded; validate/required-for-tier-sa passed
1  validate or required-for-tier-sa identified missing/stale rows
2  argument or I/O error
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import re
import sys
import tempfile
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH_DEFAULT = REPO_ROOT / "reference" / "fp_calibration_manifest.json"
TIER_REGISTRY_DEFAULT = REPO_ROOT / "detectors" / "_tier_registry.yaml"

SCHEMA_VERSION = "auditooor.fp_calibration_manifest.v1"

REQUIRED_FIELDS = (
    "pattern",
    "tier",
    "last_calibrated_iso",
    "clean_codebases_count",
    "clean_corpus_hash",
    "precision_pct",
)

TIER_VALUES = {"S", "A", "B", "C", "D", "E"}

DEFAULT_MAX_AGE_DAYS = 90


# ---- helpers --------------------------------------------------------------


def _utcnow_iso() -> str:
    """Return the current UTC time as an ISO 8601 string with seconds."""
    now = datetime.datetime.now(datetime.timezone.utc)
    return now.strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_iso(value: str) -> datetime.datetime | None:
    """Parse the manifest's ISO 8601 UTC timestamp.

    Accept ``Z`` suffix and offsets. Return None on parse error.
    """
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    return dt


def corpus_hash_for(libs: list[tuple[str, str]]) -> str:
    """Return the canonical short hash used in ``clean_corpus_hash``.

    ``libs`` is a list of ``(slug, pinned_version)`` pairs. The hash is
    SHA-256 of the canonical string ``slug@version|slug@version|...``
    (sorted by slug), truncated to 16 hex chars.
    """
    items = sorted((slug, ver) for slug, ver in libs)
    canonical = "|".join(f"{slug}@{ver}" for slug, ver in items)
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return digest[:16]


def _empty_manifest() -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "patterns": {},
    }


def load_manifest(path: Path) -> dict:
    """Load the manifest, returning an empty doc if the file is absent."""
    if not path.exists():
        return _empty_manifest()
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise SystemExit(
            f"[fp-calibration-manifest] cannot read {path}: {exc}"
        ) from exc
    if not text.strip():
        return _empty_manifest()
    try:
        data = json.loads(text)
    except ValueError as exc:
        raise SystemExit(
            f"[fp-calibration-manifest] {path} is not valid JSON: {exc}"
        ) from exc
    if not isinstance(data, dict):
        raise SystemExit(
            f"[fp-calibration-manifest] {path} top-level must be an object"
        )
    data.setdefault("schema_version", SCHEMA_VERSION)
    patterns = data.get("patterns")
    if not isinstance(patterns, dict):
        data["patterns"] = {}
    return data


def _atomic_write(path: Path, payload: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        dir=str(path.parent),
        delete=False,
        prefix=path.name + ".",
        suffix=".tmp",
    )
    try:
        tmp.write(payload)
        tmp.flush()
        os.fsync(tmp.fileno())
    finally:
        tmp.close()
    os.replace(tmp.name, path)


def save_manifest(path: Path, manifest: dict) -> None:
    """Write the manifest deterministically (sorted keys, trailing newline)."""
    patterns = manifest.get("patterns", {})
    out = {
        "schema_version": manifest.get("schema_version", SCHEMA_VERSION),
        "patterns": {k: patterns[k] for k in sorted(patterns)},
    }
    text = json.dumps(out, indent=2, sort_keys=True) + "\n"
    _atomic_write(path, text)


def _row_errors(name: str, row: object) -> list[str]:
    errors: list[str] = []
    if not isinstance(row, dict):
        return [f"{name}: row is not a JSON object"]
    for field in REQUIRED_FIELDS:
        if field not in row:
            errors.append(f"{name}: missing required field '{field}'")
    if isinstance(row.get("pattern"), str) and row["pattern"] != name:
        errors.append(
            f"{name}: row['pattern']={row['pattern']!r} does not match key"
        )
    tier = row.get("tier")
    if isinstance(tier, str) and tier not in TIER_VALUES:
        errors.append(
            f"{name}: tier={tier!r} not in {sorted(TIER_VALUES)}"
        )
    iso = row.get("last_calibrated_iso")
    if isinstance(iso, str) and _parse_iso(iso) is None:
        errors.append(
            f"{name}: last_calibrated_iso={iso!r} is not parseable ISO 8601"
        )
    count = row.get("clean_codebases_count")
    if count is None:
        pass
    elif isinstance(count, bool) or not isinstance(count, int):
        errors.append(
            f"{name}: clean_codebases_count must be int (got "
            f"{type(count).__name__})"
        )
    elif count < 0:
        errors.append(
            f"{name}: clean_codebases_count must be >= 0 (got {count})"
        )
    pct = row.get("precision_pct")
    if pct is None:
        pass
    elif isinstance(pct, bool) or not isinstance(pct, (int, float)):
        errors.append(
            f"{name}: precision_pct must be number (got {type(pct).__name__})"
        )
    elif pct < 0 or pct > 100:
        errors.append(
            f"{name}: precision_pct={pct} outside [0, 100]"
        )
    corpus = row.get("clean_corpus_hash")
    if isinstance(corpus, str) and not re.fullmatch(r"[0-9a-fA-F]{6,64}", corpus):
        errors.append(
            f"{name}: clean_corpus_hash={corpus!r} not a hex string of length 6..64"
        )
    return errors


def validate_manifest(manifest: dict) -> list[str]:
    """Return a list of human-readable error strings (empty on PASS)."""
    errors: list[str] = []
    schema = manifest.get("schema_version")
    if schema != SCHEMA_VERSION:
        errors.append(
            f"schema_version={schema!r} (expected {SCHEMA_VERSION!r})"
        )
    patterns = manifest.get("patterns")
    if not isinstance(patterns, dict):
        errors.append("patterns: missing or not an object")
        return errors
    for name in sorted(patterns):
        errors.extend(_row_errors(name, patterns[name]))
    return errors


# ---- tier-registry parsing (stdlib only) ----------------------------------


_TIER_KEY_RE = re.compile(r"^  ([A-Za-z0-9_\-./]+):\s*$")
_TIER_FIELD_RE = re.compile(r"^    tier:\s*([A-Za-z]+)\s*$")


def parse_tier_registry(path: Path) -> dict[str, str]:
    """Parse ``detectors/_tier_registry.yaml`` to ``{name: tier}`` without
    PyYAML — the file follows a stable two-space block style.

    The shape is::

        tiers:
          some-pattern:
            tier: S
            reason: ...
          other-pattern:
            tier: D
            ...
    """
    if not path.exists():
        return {}
    out: dict[str, str] = {}
    current: str | None = None
    in_tiers = False
    for raw in path.read_text(encoding="utf-8").splitlines():
        if raw == "tiers:":
            in_tiers = True
            continue
        if not in_tiers:
            continue
        # End of the tiers block: a top-level key like "version:".
        if raw and not raw.startswith(" "):
            in_tiers = False
            current = None
            continue
        m = _TIER_KEY_RE.match(raw)
        if m:
            current = m.group(1)
            continue
        if current is None:
            continue
        m2 = _TIER_FIELD_RE.match(raw)
        if m2:
            out[current] = m2.group(1).upper()
            current = None
    return out


def required_for_tier_sa(
    manifest: dict,
    tier_registry: dict[str, str],
    *,
    max_age_days: int = DEFAULT_MAX_AGE_DAYS,
    now: datetime.datetime | None = None,
) -> dict:
    """Return a structured report for the required-for-tier-sa lint mode.

    Output shape::

        {
          "ok": bool,
          "max_age_days": int,
          "tier_sa_patterns": [...],
          "missing": [...],
          "stale": [{"pattern": ..., "age_days": ...}, ...],
          "fresh": [...],
        }
    """
    now = now or datetime.datetime.now(datetime.timezone.utc)
    cutoff = now - datetime.timedelta(days=max_age_days)
    patterns_block = manifest.get("patterns", {})
    tier_sa = sorted(
        name for name, tier in tier_registry.items() if tier in {"S", "A"}
    )
    missing: list[str] = []
    stale: list[dict] = []
    fresh: list[str] = []
    for name in tier_sa:
        row = patterns_block.get(name)
        if not isinstance(row, dict):
            missing.append(name)
            continue
        iso = row.get("last_calibrated_iso")
        ts = _parse_iso(iso) if isinstance(iso, str) else None
        if ts is None:
            missing.append(name)
            continue
        if ts < cutoff:
            age = max(0, (now - ts).days)
            stale.append({"pattern": name, "age_days": age})
        else:
            fresh.append(name)
    return {
        "ok": not missing and not stale,
        "max_age_days": max_age_days,
        "tier_sa_patterns": tier_sa,
        "missing": missing,
        "stale": stale,
        "fresh": fresh,
    }


# ---- subcommand handlers --------------------------------------------------


def cmd_read(args: argparse.Namespace) -> int:
    manifest = load_manifest(args.manifest)
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


def cmd_update(args: argparse.Namespace) -> int:
    if not args.update:
        print(
            "[fp-calibration-manifest] --update requires a pattern name",
            file=sys.stderr,
        )
        return 2
    manifest = load_manifest(args.manifest)
    patterns = manifest.setdefault("patterns", {})
    name = args.update
    tier = (args.tier or "").upper()
    if not tier:
        # Fall back to the registry's current tier if available.
        registry = parse_tier_registry(args.tier_registry)
        tier = registry.get(name, "")
    if tier and tier not in TIER_VALUES:
        print(
            f"[fp-calibration-manifest] tier={tier!r} not in "
            f"{sorted(TIER_VALUES)}",
            file=sys.stderr,
        )
        return 2
    iso = args.iso or _utcnow_iso()
    if _parse_iso(iso) is None:
        print(
            f"[fp-calibration-manifest] --iso {iso!r} is not parseable",
            file=sys.stderr,
        )
        return 2
    row = {
        "pattern": name,
        "tier": tier or "D",
        "last_calibrated_iso": iso,
        "clean_codebases_count": int(args.clean_codebases),
        "clean_corpus_hash": args.corpus,
        "precision_pct": float(args.precision),
    }
    if args.notes:
        row["notes"] = args.notes
    errors = _row_errors(name, row)
    if errors:
        print(
            "[fp-calibration-manifest] update would produce invalid row:",
            file=sys.stderr,
        )
        for e in errors:
            print("  - " + e, file=sys.stderr)
        return 2
    patterns[name] = row
    save_manifest(args.manifest, manifest)
    print(
        f"[fp-calibration-manifest] updated {name} "
        f"(tier={row['tier']}, precision_pct={row['precision_pct']:.2f}, "
        f"corpus={row['clean_corpus_hash']})"
    )
    return 0


def cmd_validate(args: argparse.Namespace) -> int:
    manifest = load_manifest(args.manifest)
    errors = validate_manifest(manifest)
    if not errors:
        n = len(manifest.get("patterns", {}))
        print(
            f"[fp-calibration-manifest] OK ({n} pattern row(s), "
            f"schema={manifest.get('schema_version', SCHEMA_VERSION)})"
        )
        return 0
    print("[fp-calibration-manifest] FAIL: validation errors", file=sys.stderr)
    for e in errors:
        print("  - " + e, file=sys.stderr)
    return 1


def cmd_required_for_tier_sa(args: argparse.Namespace) -> int:
    manifest = load_manifest(args.manifest)
    registry = parse_tier_registry(args.tier_registry)
    report = required_for_tier_sa(
        manifest, registry, max_age_days=args.max_age_days
    )
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        n_sa = len(report["tier_sa_patterns"])
        n_missing = len(report["missing"])
        n_stale = len(report["stale"])
        n_fresh = len(report["fresh"])
        verdict = "OK" if report["ok"] else "FAIL"
        print(
            f"[fp-calibration-manifest] required-for-tier-sa: {verdict} "
            f"(tier-S/A patterns={n_sa}, fresh={n_fresh}, "
            f"stale={n_stale}, missing={n_missing}, "
            f"max_age_days={report['max_age_days']})"
        )
        if report["missing"]:
            print("  missing:")
            for name in report["missing"]:
                print(f"    - {name}")
        if report["stale"]:
            print("  stale:")
            for entry in report["stale"]:
                print(f"    - {entry['pattern']} ({entry['age_days']}d old)")
    return 0 if report["ok"] else 1


# ---- main -----------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description=(
            "Read/write the FP calibration manifest "
            "(reference/fp_calibration_manifest.json)."
        ),
    )
    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--read",
        action="store_true",
        help="Print the manifest as pretty JSON.",
    )
    mode.add_argument(
        "--update",
        metavar="PATTERN",
        help=(
            "Insert/replace one row keyed by PATTERN. Requires "
            "--precision and --corpus; --tier defaults to the registry's "
            "current tier; --clean-codebases defaults to 1; "
            "--iso defaults to now UTC."
        ),
    )
    mode.add_argument(
        "--validate",
        action="store_true",
        help="Validate the manifest schema; non-zero exit on errors.",
    )
    mode.add_argument(
        "--required-for-tier-sa",
        action="store_true",
        help=(
            "Lint mode: every Tier-S/A pattern must have a row newer than "
            "--max-age-days. Fail-closed (exit 1) on missing or stale rows."
        ),
    )
    p.add_argument(
        "--manifest",
        type=Path,
        default=MANIFEST_PATH_DEFAULT,
        help=(
            "Path to the manifest file "
            f"(default: {MANIFEST_PATH_DEFAULT.relative_to(REPO_ROOT)})."
        ),
    )
    p.add_argument(
        "--tier-registry",
        type=Path,
        default=TIER_REGISTRY_DEFAULT,
        help=(
            "Path to detectors/_tier_registry.yaml "
            "(used by --update to resolve tier and by "
            "--required-for-tier-sa to enumerate Tier-S/A patterns)."
        ),
    )
    p.add_argument(
        "--tier",
        default="",
        help="Tier override (S/A/B/C/D/E). Used by --update.",
    )
    p.add_argument(
        "--precision",
        type=float,
        default=None,
        help="Precision percentage (0..100). Used by --update.",
    )
    p.add_argument(
        "--corpus",
        default="",
        help="Clean corpus hash. Used by --update.",
    )
    p.add_argument(
        "--clean-codebases",
        type=int,
        default=1,
        help="Number of clean reference codebases scanned. Used by --update.",
    )
    p.add_argument(
        "--iso",
        default="",
        help="ISO 8601 UTC timestamp override. Used by --update.",
    )
    p.add_argument(
        "--notes",
        default="",
        help="Optional free-text notes. Used by --update.",
    )
    p.add_argument(
        "--max-age-days",
        type=int,
        default=DEFAULT_MAX_AGE_DAYS,
        help=(
            "Freshness threshold for --required-for-tier-sa "
            f"(default: {DEFAULT_MAX_AGE_DAYS} days)."
        ),
    )
    p.add_argument(
        "--json",
        action="store_true",
        help="Emit JSON for --required-for-tier-sa.",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.read:
        return cmd_read(args)
    if args.update is not None:
        if args.precision is None or not args.corpus:
            parser.error("--update requires --precision and --corpus")
        return cmd_update(args)
    if args.validate:
        return cmd_validate(args)
    if args.required_for_tier_sa:
        return cmd_required_for_tier_sa(args)
    parser.error("no mode selected")
    return 2  # unreachable


if __name__ == "__main__":
    sys.exit(main())
