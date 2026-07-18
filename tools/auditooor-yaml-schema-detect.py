#!/usr/bin/env python3
"""auditooor-yaml-schema-detect.

Wave-2 PR-A (PR #728) capability-gap #3 helper. The post-migration validator
and other corpus tooling walks specific tags-dirs only. Operators frequently
need a "what schema is this YAML?" probe over arbitrary paths (e.g. a YAML
dropped into ``/tmp/foo.yaml`` or an unfamiliar workspace state file).

This tool is a READ-ONLY probe. It walks one file or a directory recursively,
parses each ``*.yaml`` / ``*.yml`` file, and detects which auditooor schema
family the record belongs to. Detection prefers the explicit top-level
``schema_version`` field; when that is absent it falls back to a small set of
heuristics keyed on per-schema signature fields:

  - ``verdict_id`` + ``extraction_provenance``  -> dsl_pattern_* (synthetic)
  - ``record_id`` + ``record_tier`` + ``attack_class`` (no schema_version)
    -> auditooor.hackerman_record.v1 (legacy, no explicit version field)
  - ``engagement_id`` + ``state_yaml``  -> auditooor.skill_state.v1
  - workspace skill-state files (``version`` + ``workspace`` + ``last_scan``)
    -> auditooor.skill_state.v1 (heuristic)
  - dependency-manifest fields (``packages`` + ``lockfileVersion``,
    ``importers``, ``dependencies`` + ``devDependencies``)
    -> non_auditooor.dependency_manifest (e.g. pnpm-lock.yaml)
  - CI workflow shape (``name`` + ``on`` + ``jobs``)
    -> non_auditooor.ci_workflow (GitHub Actions / similar)
  - otherwise -> ``unknown``

The tool emits a JSON status pack of schema
``auditooor.yaml_schema_detect.v1`` with the per-schema distribution, an
``unknown_files`` list (capped at 50 entries), and a ``dual_form_pairs`` list
enumerating records that exist as both ``.yaml`` and a sibling ``.json``
form. When run with ``--strict``, exits non-zero if any unknown schema was
detected.

CLI::

    python3 tools/auditooor-yaml-schema-detect.py --file /tmp/foo.yaml --json
    python3 tools/auditooor-yaml-schema-detect.py --dir /path/to/dir --json
    python3 tools/auditooor-yaml-schema-detect.py --dir /tmp/x --strict

This file is checked-in. ``synthetic_fixture: true`` is reserved for unit
tests under ``tools/tests/test_auditooor_yaml_schema_detect.py``.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Dict, List, Optional, Tuple

try:
    import yaml  # type: ignore
except ImportError:  # pragma: no cover - PyYAML is part of the project's base env
    yaml = None  # type: ignore


SCHEMA_VERSION_TAG = "auditooor.yaml_schema_detect.v1"

# Cap unknown_files in JSON output to keep status packs bounded.
UNKNOWN_FILES_CAP = 50

# Canonical known schema families. The detector returns one of these strings
# (or a verbatim schema_version when explicit).
KNOWN_HACKERMAN_V1 = "auditooor.hackerman_record.v1"
KNOWN_HACKERMAN_V1_1 = "auditooor.hackerman_record.v1.1"
KNOWN_SKILL_STATE_V1 = "auditooor.skill_state.v1"
KNOWN_DSL_PATTERN = "auditooor.dsl_pattern.synthetic"
NON_AUDITOOOR_DEP_MANIFEST = "non_auditooor.dependency_manifest"
NON_AUDITOOOR_CI_WORKFLOW = "non_auditooor.ci_workflow"
PARSE_ERROR = "parse_error"
EMPTY_DOCUMENT = "empty_document"
UNKNOWN = "unknown"


def _is_mapping(doc: Any) -> bool:
    return isinstance(doc, dict)


def detect_schema_from_doc(doc: Any) -> Tuple[str, str]:
    """Return ``(schema_family, evidence)``.

    ``evidence`` is a short human-readable string explaining WHY the family
    was selected (``schema_version=...``, ``heuristic: verdict_id+...``, etc.).
    """
    if doc is None:
        return EMPTY_DOCUMENT, "document parsed as None"
    if not _is_mapping(doc):
        # YAML can be a list or scalar at the top level; we treat that as
        # unknown for our auditooor-schema lens.
        return UNKNOWN, f"top-level type={type(doc).__name__} (expected mapping)"

    # 1. Explicit schema_version wins.
    schema_version = doc.get("schema_version")
    if isinstance(schema_version, str) and schema_version.strip():
        return schema_version.strip(), f"schema_version={schema_version.strip()}"

    # 2. dsl_pattern heuristic: synthetic patterns lack schema_version but
    #    always carry verdict_id + extraction_provenance.
    if "verdict_id" in doc and "extraction_provenance" in doc:
        return KNOWN_DSL_PATTERN, "heuristic: verdict_id + extraction_provenance"

    # 3. Legacy hackerman_record.v1 without explicit schema_version field.
    if "record_id" in doc and "record_tier" in doc and "attack_class" in doc:
        return KNOWN_HACKERMAN_V1, "heuristic: record_id + record_tier + attack_class"

    # 4. Explicit engagement-flavored skill_state (older shape).
    if "engagement_id" in doc and "state_yaml" in doc:
        return KNOWN_SKILL_STATE_V1, "heuristic: engagement_id + state_yaml"

    # 5. Workspace skill-state file shape (the live ``.skill_state.yaml`` shape
    #    used by audits/thegraph/.skill_state.yaml).
    if (
        "workspace" in doc
        and "last_scan" in doc
        and "adversarial_reads" in doc
    ):
        return KNOWN_SKILL_STATE_V1, "heuristic: workspace + last_scan + adversarial_reads"

    # 6. Dependency manifest shapes (pnpm-lock.yaml etc).
    dep_signals = ("lockfileVersion", "importers", "packages")
    if isinstance(doc.get("lockfileVersion"), (str, int, float)) and any(
        k in doc for k in dep_signals
    ):
        return NON_AUDITOOOR_DEP_MANIFEST, "heuristic: lockfileVersion + importers/packages"

    # 7. GitHub Actions / CI workflow shape: ``name`` + ``on`` + ``jobs``.
    #    PyYAML helpfully turns the bare key ``on:`` into Python ``True``,
    #    so we accept either spelling.
    has_on_key = ("on" in doc) or (True in doc)
    if "jobs" in doc and isinstance(doc.get("jobs"), dict) and has_on_key:
        return NON_AUDITOOOR_CI_WORKFLOW, "heuristic: jobs + on + (name)"

    return UNKNOWN, "no schema_version and no heuristic match"


def _iter_yaml_files(root: str) -> List[str]:
    """Walk a directory tree and yield ``*.yaml`` / ``*.yml`` file paths."""
    out: List[str] = []
    for dirpath, _dirnames, filenames in os.walk(root):
        for fname in filenames:
            if fname.endswith((".yaml", ".yml")):
                out.append(os.path.join(dirpath, fname))
    out.sort()
    return out


def _safe_load(path: str) -> Tuple[Optional[Any], Optional[str]]:
    """Read+parse a YAML file. Returns ``(doc, error_string)``."""
    if yaml is None:
        return None, "PyYAML not available"
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            doc = yaml.safe_load(fh)
        return doc, None
    except yaml.YAMLError as exc:
        return None, f"yaml.YAMLError: {exc.__class__.__name__}"
    except OSError as exc:
        return None, f"OSError: {exc}"
    except Exception as exc:  # pragma: no cover - defensive
        return None, f"{exc.__class__.__name__}: {exc}"


def _check_dual_form(yaml_path: str) -> bool:
    """Return True if the sibling ``.json`` form exists next to ``yaml_path``.

    A "dual-form pair" is the same record name with both ``.yaml`` and
    ``.json`` siblings (e.g. ``record.yaml`` + ``record.json``).
    """
    base, _ext = os.path.splitext(yaml_path)
    return os.path.isfile(base + ".json")


def scan_paths(
    files: List[str],
) -> Dict[str, Any]:
    """Scan one or more file paths and return the JSON status pack body."""
    distribution: Dict[str, int] = {}
    unknown_files: List[str] = []
    parse_errors: List[Dict[str, str]] = []
    dual_form_pairs: List[str] = []

    for path in files:
        doc, err = _safe_load(path)
        if err is not None:
            distribution[PARSE_ERROR] = distribution.get(PARSE_ERROR, 0) + 1
            parse_errors.append({"path": path, "error": err})
            continue
        family, _evidence = detect_schema_from_doc(doc)
        distribution[family] = distribution.get(family, 0) + 1
        if family == UNKNOWN and len(unknown_files) < UNKNOWN_FILES_CAP:
            unknown_files.append(path)
        if _check_dual_form(path):
            dual_form_pairs.append(path)

    return {
        "schema_version": SCHEMA_VERSION_TAG,
        "files_scanned": len(files),
        "schema_distribution": distribution,
        "unknown_files": unknown_files,
        "unknown_files_truncated": max(
            0,
            distribution.get(UNKNOWN, 0) - len(unknown_files),
        ),
        "dual_form_pairs": dual_form_pairs,
        "parse_errors": parse_errors,
    }


def _detect_one_file(path: str) -> Dict[str, Any]:
    """Single-file pretty result used for ``--file`` mode."""
    doc, err = _safe_load(path)
    if err is not None:
        return {
            "schema_version": SCHEMA_VERSION_TAG,
            "file": path,
            "detected_schema": PARSE_ERROR,
            "evidence": err,
            "dual_form_sibling": _check_dual_form(path),
        }
    family, evidence = detect_schema_from_doc(doc)
    return {
        "schema_version": SCHEMA_VERSION_TAG,
        "file": path,
        "detected_schema": family,
        "evidence": evidence,
        "dual_form_sibling": _check_dual_form(path),
    }


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="auditooor-yaml-schema-detect",
        description="Probe a YAML file (or directory) and report its auditooor schema family.",
    )
    parser.add_argument(
        "--file",
        dest="file_path",
        default=None,
        help="Single YAML file to probe.",
    )
    parser.add_argument(
        "--dir",
        dest="dir_path",
        default=None,
        help="Directory to walk recursively for *.yaml / *.yml files.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit a JSON status pack instead of human-readable lines.",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit non-zero if any unknown schema is detected.",
    )
    args = parser.parse_args(argv)

    if not args.file_path and not args.dir_path:
        parser.error("must supply --file or --dir")
    if args.file_path and args.dir_path:
        parser.error("--file and --dir are mutually exclusive")

    if args.file_path:
        if not os.path.isfile(args.file_path):
            sys.stderr.write(f"error: not a file: {args.file_path}\n")
            return 2
        result = _detect_one_file(args.file_path)
        if args.json:
            sys.stdout.write(json.dumps(result, indent=2, sort_keys=True) + "\n")
        else:
            sys.stdout.write(
                f"{result['file']}\t{result['detected_schema']}\t{result['evidence']}\n"
            )
        if args.strict and result["detected_schema"] == UNKNOWN:
            return 1
        if args.strict and result["detected_schema"] == PARSE_ERROR:
            return 1
        return 0

    # Directory mode.
    if not os.path.isdir(args.dir_path):
        sys.stderr.write(f"error: not a directory: {args.dir_path}\n")
        return 2
    files = _iter_yaml_files(args.dir_path)
    pack = scan_paths(files)
    if args.json:
        sys.stdout.write(json.dumps(pack, indent=2, sort_keys=True) + "\n")
    else:
        sys.stdout.write(f"files_scanned: {pack['files_scanned']}\n")
        sys.stdout.write("schema_distribution:\n")
        for k, v in sorted(pack["schema_distribution"].items(), key=lambda kv: -kv[1]):
            sys.stdout.write(f"  {k}: {v}\n")
        if pack["unknown_files"]:
            sys.stdout.write(f"unknown_files (showing {len(pack['unknown_files'])}):\n")
            for p in pack["unknown_files"]:
                sys.stdout.write(f"  {p}\n")
        if pack["dual_form_pairs"]:
            sys.stdout.write(f"dual_form_pairs: {len(pack['dual_form_pairs'])}\n")
        if pack["parse_errors"]:
            sys.stdout.write(f"parse_errors: {len(pack['parse_errors'])}\n")
    if args.strict and pack["schema_distribution"].get(UNKNOWN, 0) > 0:
        return 1
    if args.strict and pack["schema_distribution"].get(PARSE_ERROR, 0) > 0:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
