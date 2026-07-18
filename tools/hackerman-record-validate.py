#!/usr/bin/env python3
"""Validate hackerman_record YAML files against v1, v1.1, or v1.2 schema.

The validator auto-detects the schema version per-record via the
``schema_version`` field:

* ``auditooor.hackerman_record.v1``   -> v1 schema (legacy / default).
* ``auditooor.hackerman_record.v1.1`` -> v1.1 schema (Wave-2 additive:
  verification_tier / record_source_url / cve_id / ghsa_id / record_extensions).
  Canonical default for PER-FINDING hackerman miners (cantina, immunefi,
  contest-platform, audit-PDF, CVE-DB, and similar audit-finding sources).
* ``auditooor.hackerman_record.v1.2`` -> v1.2 schema (permissive wide-shape:
  additionalProperties=true; required={schema_version, record_id,
  verification_tier}). Canonical default for INCIDENT-MINING and ENRICHMENT
  lanes whose records carry structured_extraction / tok_a_enrichment /
  source_url / incident_date / amount_usd blocks (bridge-incidents,
  bridge-attacks, mev-exploits, mev-flashloan, onchain-traces,
  major-defi-fix-history, defimon-telegram-archive-miner). (lane227)

All three versions validate. v1 and v1.1 records continue to validate
unchanged (backward-compat). v1.2 records pick up the v1.2 schema
automatically.

By default this validator is corpus-compatible: legacy verdict-tag YAML
files are skipped unless they declare one of the recognised hackerman
``schema_version`` strings. Pass ``--strict-all`` to validate every YAML
file supplied, including legacy files that do not declare the hackerman
schema.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


REPO_ROOT = Path(__file__).resolve().parent.parent
# <!-- r36-rebuttal: schema-v1.2-validator-patch-2026-05-26 (add v1.2 permissive wide-shape schema for incident-mining + corpus-enrichment lanes; lane declared in agent_pathspec.json with 2h TTL) -->
SCHEMA_VERSION_V1 = "auditooor.hackerman_record.v1"
SCHEMA_VERSION_V1_1 = "auditooor.hackerman_record.v1.1"
SCHEMA_VERSION_V1_2 = "auditooor.hackerman_record.v1.2"
RECOGNISED_SCHEMA_VERSIONS = (
    SCHEMA_VERSION_V1,
    SCHEMA_VERSION_V1_1,
    SCHEMA_VERSION_V1_2,
)
# Legacy alias kept for callers importing SCHEMA_VERSION (defaults to v1).
SCHEMA_VERSION = SCHEMA_VERSION_V1

DEFAULT_SCHEMA_PATH_V1 = (
    REPO_ROOT / "audit" / "corpus_tags" / "schemas" / "auditooor.hackerman_record.v1.schema.json"
)
DEFAULT_SCHEMA_PATH_V1_1 = (
    REPO_ROOT / "audit" / "corpus_tags" / "schemas" / "auditooor.hackerman_record.v1.1.schema.json"
)
DEFAULT_SCHEMA_PATH_V1_2 = (
    REPO_ROOT / "audit" / "corpus_tags" / "schemas" / "auditooor.hackerman_record.v1.2.schema.json"
)
# Backward-compat: callers that import DEFAULT_SCHEMA_PATH expect the v1 path.
DEFAULT_SCHEMA_PATH = DEFAULT_SCHEMA_PATH_V1

DEFAULT_TAG_DIR = REPO_ROOT / "audit" / "corpus_tags" / "tags"


def _load_verdict_schema_tool() -> Any:
    spec = importlib.util.spec_from_file_location(
        "_verdict_tag_schema", str(REPO_ROOT / "tools" / "verdict-tag-schema.py")
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


_VTS = _load_verdict_schema_tool()


def load_yaml(path: Path) -> Any:
    return _VTS._load_yaml(path)  # type: ignore[attr-defined]


def load_schema(path: Path = DEFAULT_SCHEMA_PATH_V1) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def is_hackerman_record(doc: Any) -> bool:
    return (
        isinstance(doc, dict)
        and doc.get("schema_version") in RECOGNISED_SCHEMA_VERSIONS
    )


def resolve_schema_path(doc: Dict[str, Any]) -> Path:
    """Pick the schema file matching the doc's declared schema_version.

    Falls back to the v1 schema path if the doc does not declare a
    recognised hackerman schema_version (callers normally gate this via
    ``is_hackerman_record`` first).
    """
    # <!-- r36-rebuttal: schema-v1.2-validator-patch-2026-05-26 -->
    version = doc.get("schema_version") if isinstance(doc, dict) else None
    if version == SCHEMA_VERSION_V1_2:
        return DEFAULT_SCHEMA_PATH_V1_2
    if version == SCHEMA_VERSION_V1_1:
        return DEFAULT_SCHEMA_PATH_V1_1
    return DEFAULT_SCHEMA_PATH_V1


def load_schema_for_doc(doc: Dict[str, Any]) -> Dict[str, Any]:
    return load_schema(resolve_schema_path(doc))


def validate_doc(doc: Dict[str, Any], schema: Optional[Dict[str, Any]] = None) -> List[str]:
    """Validate a hackerman_record doc.

    If ``schema`` is None the schema is auto-selected per the doc's
    declared ``schema_version`` (v1 vs v1.1). Passing an explicit
    ``schema`` preserves the legacy single-schema call shape used by
    older callers and tests.
    """
    if schema is None:
        schema = load_schema_for_doc(doc)
    return list(_VTS.validate(doc, schema))  # type: ignore[attr-defined]


def validate_file(
    path: Path,
    schema: Optional[Dict[str, Any]] = None,
    *,
    strict_all: bool = False,
) -> Tuple[str, List[str]]:
    """Return (status, errors), where status is valid, invalid, or skipped.

    When ``schema`` is None the schema is selected per the record's
    declared ``schema_version`` (v1 or v1.1). When ``schema`` is
    provided, it is used as-is (preserves legacy call shape).
    """
    try:
        doc = load_yaml(path)
    except Exception as exc:
        return "invalid", [f"{path}: YAML parse error: {exc}"]
    if not isinstance(doc, dict):
        return "invalid", [f"{path}: top-level YAML must be a mapping, got {type(doc).__name__}"]
    if not strict_all and not is_hackerman_record(doc):
        return "skipped", []
    effective_schema = schema if schema is not None else load_schema_for_doc(doc)
    errs = validate_doc(doc, effective_schema)
    return ("valid" if not errs else "invalid"), errs


def discover_files(validate: Iterable[str], validate_dir: Iterable[str]) -> Tuple[List[Path], List[str]]:
    files = [Path(f) for f in validate]
    errors: List[str] = []
    for d in validate_dir:
        dp = Path(d)
        if not dp.is_dir():
            errors.append(f"not a directory: {dp}")
            continue
        files.extend(sorted(dp.glob("*.yaml")))
        files.extend(sorted(dp.glob("*.yml")))
    return files, errors


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--validate", action="append", default=[], help="YAML file to validate; repeatable.")
    parser.add_argument(
        "--validate-dir",
        action="append",
        default=[],
        help=f"Directory of YAML files to validate. Default: {DEFAULT_TAG_DIR}",
    )
    parser.add_argument(
        "--schema-path",
        default=None,
        help=(
            "Override schema path. When omitted, the schema is auto-selected "
            "per-record by schema_version (v1 vs v1.1). Provide an explicit "
            "path to force a single schema for every record."
        ),
    )
    parser.add_argument(
        "--strict-all",
        action="store_true",
        help="Validate every YAML file instead of skipping non-hackerman records.",
    )
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)

    forced_schema: Optional[Dict[str, Any]] = None
    if args.schema_path:
        schema_path = Path(args.schema_path)
        if not schema_path.exists():
            print(f"schema not found: {schema_path}", file=sys.stderr)
            return 2
        forced_schema = load_schema(schema_path)

    validate_dirs = args.validate_dir or ([] if args.validate else [str(DEFAULT_TAG_DIR)])
    files, discover_errors = discover_files(args.validate, validate_dirs)
    if discover_errors:
        for err in discover_errors:
            print(err, file=sys.stderr)
        return 2
    if not files:
        print("no files provided", file=sys.stderr)
        return 2

    counts = {"valid": 0, "invalid": 0, "skipped": 0}
    for path in sorted(files):
        status, errs = validate_file(path, forced_schema, strict_all=args.strict_all)
        counts[status] += 1
        if status == "valid":
            if not args.quiet:
                print(f"OK      {path}")
        elif status == "skipped":
            if not args.quiet:
                print(f"SKIP    {path}")
        else:
            print(f"FAIL    {path}")
            for err in errs:
                print(f"        - {err}")

    if not args.quiet:
        print(
            f"\nresult: valid={counts['valid']} invalid={counts['invalid']} "
            f"skipped={counts['skipped']}"
        )
    return 0 if counts["invalid"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
