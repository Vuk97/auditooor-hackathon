#!/usr/bin/env python3
"""Backfill weak Solodit function-shape signatures without rewriting records.

Some Solodit-derived records previously rendered detector-guessed names as
precise Solidity signatures such as ``function pool0() internal returns
(bool)``. This tool narrows those to explicit ``function-name-hint`` records
and annotates the shape tags while preserving all other enriched corpus fields.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import re
import sys
from pathlib import Path
from typing import Any

import yaml


REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_TAG_DIR = REPO_ROOT / "audit" / "corpus_tags" / "tags"
DEFAULT_INDEX_DIR = REPO_ROOT / "audit" / "corpus_tags" / "index"
OLD_SYNTHETIC_SIGNATURE_RE = re.compile(r"^function\s+([A-Za-z_][A-Za-z0-9_]*)\(\)\s+internal\s+returns\s+\(bool\)$")


def _load_tool(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


_ETL = _load_tool(
    REPO_ROOT / "tools" / "hackerman-etl-from-solodit-specs.py",
    "_hackerman_etl_from_solodit_specs_for_shape_backfill",
)
_VALIDATOR = _load_tool(
    REPO_ROOT / "tools" / "hackerman-record-validate.py",
    "_hackerman_record_validate_for_shape_backfill",
)


def _source_spec_path(source_audit_ref: object) -> Path | None:
    text = str(source_audit_ref or "")
    if not text.startswith("solodit-spec:"):
        return None
    body = text.removeprefix("solodit-spec:")
    if ":" not in body:
        return None
    path_text, _source_id = body.rsplit(":", 1)
    if not path_text:
        return None
    path = Path(path_text)
    if not path.is_absolute():
        path = REPO_ROOT / path
    return path


def _replace_raw_signature_line(text: str, signature: str) -> tuple[str, bool]:
    lines = text.splitlines()
    for idx, line in enumerate(lines):
        if line.startswith("  raw_signature:"):
            lines[idx] = f"  raw_signature: {_ETL.yaml_scalar(signature)}"
            return "\n".join(lines) + "\n", True
    return text, False


def _replace_shape_tags_block(text: str, tags: list[str]) -> tuple[str, bool]:
    lines = text.splitlines()
    for idx, line in enumerate(lines):
        if line == "  shape_tags:":
            end = idx + 1
            while end < len(lines) and lines[end].startswith("    - "):
                end += 1
            block = ["  shape_tags:"] + [f"    - {_ETL.yaml_scalar(tag)}" for tag in tags]
            return "\n".join(lines[:idx] + block + lines[end:]) + "\n", True
    return text, False


def _merged_shape_tags(record: dict[str, Any], spec_data: dict[str, Any]) -> list[str]:
    shape = record.get("function_shape") if isinstance(record.get("function_shape"), dict) else {}
    raw_tags = shape.get("shape_tags") if isinstance(shape, dict) else []
    tags = [str(item) for item in raw_tags if str(item).strip()]
    for candidate in (spec_data.get("skeleton"), _ETL.SYNTHETIC_FUNCTION_HINT_TAG):
        tag = _ETL.slugify(candidate, max_len=48)
        if tag and tag not in tags:
            tags.append(tag)
    return tags


def _updated_record_text(tag_path: Path, record: dict[str, Any], spec_path: Path, spec_data: dict[str, Any]) -> tuple[str | None, str | None]:
    shape = record.get("function_shape") if isinstance(record.get("function_shape"), dict) else {}
    old_signature = str(shape.get("raw_signature") or "")
    if not OLD_SYNTHETIC_SIGNATURE_RE.fullmatch(old_signature):
        return None, None
    language = str(record.get("target_language") or spec_data.get("language") or "solidity").lower()
    title = str(spec_data.get("wiki_title") or spec_data.get("title") or spec_data.get("help") or spec_data.get("name") or spec_path.stem)
    if not _ETL.is_weak_generated_function_hint(spec_data, language):
        return None, None
    new_signature = _ETL.raw_signature(spec_data, language, title)
    if new_signature == old_signature:
        return None, None
    text = tag_path.read_text(encoding="utf-8")
    text, replaced_sig = _replace_raw_signature_line(text, new_signature)
    text, replaced_tags = _replace_shape_tags_block(text, _merged_shape_tags(record, spec_data))
    if not replaced_sig or not replaced_tags:
        return None, f"{tag_path}: expected raw_signature and shape_tags lines"
    return text, None


def backfill_shapes(tag_dir: Path, *, dry_run: bool = False) -> dict[str, Any]:
    schema = _VALIDATOR.load_schema()
    scanned = 0
    candidates = 0
    updated = 0
    skipped = 0
    missing_source = 0
    errors: list[str] = []
    examples: list[dict[str, object]] = []

    for tag_path in sorted(tag_dir.glob("*.yaml")):
        scanned += 1
        try:
            record = _VALIDATOR.load_yaml(tag_path)
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{tag_path}: YAML parse error: {exc}")
            continue
        if not _VALIDATOR.is_hackerman_record(record):
            skipped += 1
            continue
        if not str(record.get("source_audit_ref") or "").startswith("solodit-spec:"):
            skipped += 1
            continue
        spec_path = _source_spec_path(record.get("source_audit_ref"))
        if not spec_path or not spec_path.exists():
            missing_source += 1
            continue
        shape = record.get("function_shape") if isinstance(record.get("function_shape"), dict) else {}
        if not OLD_SYNTHETIC_SIGNATURE_RE.fullmatch(str(shape.get("raw_signature") or "")):
            skipped += 1
            continue
        candidates += 1
        spec_data = _ETL.load_yaml(spec_path)
        if not isinstance(spec_data, dict):
            errors.append(f"{tag_path}: source spec is not a mapping: {spec_path}")
            continue
        updated_text, error = _updated_record_text(tag_path, record, spec_path, spec_data)
        if error:
            errors.append(error)
            continue
        if updated_text is None:
            skipped += 1
            continue
        updated_doc = yaml.safe_load(updated_text)
        errs = _VALIDATOR.validate_doc(updated_doc, schema) if isinstance(updated_doc, dict) else ["updated YAML is not a mapping"]
        if errs:
            errors.extend(f"{tag_path}: {err}" for err in errs)
            continue
        if not dry_run:
            tag_path.write_text(updated_text, encoding="utf-8")
        updated += 1
        if len(examples) < 8:
            examples.append(
                {
                    "tag_file": tag_path.name,
                    "old_signature": shape.get("raw_signature"),
                    "new_signature": updated_doc["function_shape"]["raw_signature"],
                    "source_spec": str(spec_path.relative_to(REPO_ROOT)) if spec_path.is_relative_to(REPO_ROOT) else str(spec_path),
                }
            )

    return {
        "schema": "auditooor.hackerman_backfill_solodit_function_shapes.v1",
        "tag_dir": str(tag_dir),
        "dry_run": dry_run,
        "scanned_files": scanned,
        "skipped": skipped,
        "missing_source": missing_source,
        "candidate_synthetic_signatures": candidates,
        "updated": updated,
        "examples": examples,
        "errors": errors,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag-dir", default=str(DEFAULT_TAG_DIR))
    parser.add_argument("--index-dir", default=str(DEFAULT_INDEX_DIR))
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--rebuild-index", action="store_true")
    parser.add_argument("--json-summary", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    tag_dir = Path(args.tag_dir).expanduser().resolve()
    summary = backfill_shapes(tag_dir, dry_run=args.dry_run)
    if summary["errors"]:
        for error in summary["errors"]:
            print(error, file=sys.stderr)
    if args.rebuild_index and not args.dry_run and not summary["errors"]:
        index_tool = _load_tool(
            REPO_ROOT / "tools" / "hackerman-index-build.py",
            "_hackerman_index_build_for_shape_backfill",
        )
        summary["index_counts"] = index_tool.build_indices(
            tag_dir,
            Path(args.index_dir).expanduser().resolve(),
            preserve_existing=True,
        )
    if args.json_summary:
        print(json.dumps(summary, sort_keys=True))
    else:
        print(
            "hackerman Solodit function-shape backfill: "
            f"candidates={summary['candidate_synthetic_signatures']} "
            f"updated={summary['updated']} missing_source={summary['missing_source']} "
            f"errors={len(summary['errors'])}"
        )
    return 0 if not summary["errors"] else 1


if __name__ == "__main__":
    sys.exit(main())
