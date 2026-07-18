#!/usr/bin/env python3
"""verdict-tag-schema — Validate YAML verdict-tag files against
``auditooor.verdict_tag.v1.schema.json``.

Standalone validator with no external deps beyond ``PyYAML`` if available.
A pure-stdlib JSON-Schema (draft 2020-12) subset is implemented inline so the
script runs on a vanilla Python 3.9+ install (no `jsonschema`).

CLI:
    python3 tools/verdict-tag-schema.py --validate <file.yaml>
    python3 tools/verdict-tag-schema.py --validate-dir audit/corpus_tags/tags
    python3 tools/verdict-tag-schema.py --schema-path audit/corpus_tags/auditooor.verdict_tag.v1.schema.json --validate ...

Exit codes:
    0 — every input file validates clean
    1 — at least one file failed validation
    2 — argv / IO error
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SCHEMA_PATH = (
    REPO_ROOT / "audit" / "corpus_tags" / "auditooor.verdict_tag.v1.schema.json"
)
SCHEMA_V2_PATH = (
    REPO_ROOT / "audit" / "corpus_tags" / "auditooor.verdict_tag.v2.schema.json"
)


# ----------------------------- YAML loader ---------------------------------


def _load_yaml(path: Path) -> Any:
    """Load a YAML document; prefer PyYAML, fall back to a tiny stdlib parser
    sufficient for our flat-key tag files."""
    try:
        import yaml  # type: ignore

        with path.open("r", encoding="utf-8") as fh:
            return yaml.safe_load(fh)
    except ImportError:
        return _load_yaml_minimal(path)


def _load_yaml_minimal(path: Path) -> Any:
    """A YAML *subset* loader for verdict-tag files. Handles:
      - top-level scalar key: value
      - lists via ``- item`` (block style) and ``[a, b]`` (flow style)
      - dict items in lists via ``- key: value`` blocks
    Not a general YAML implementation; covers what the extractor emits.
    """
    text = path.read_text(encoding="utf-8")
    return _parse_yaml_minimal(text)


def _parse_yaml_minimal(text: str) -> Any:
    lines = [ln.rstrip() for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]
    root: Dict[str, Any] = {}

    def coerce(val: str) -> Any:
        v = val.strip()
        if v == "" or v.lower() in ("null", "~"):
            return None
        if v.lower() == "true":
            return True
        if v.lower() == "false":
            return False
        if v.startswith("[") and v.endswith("]"):
            inner = v[1:-1].strip()
            if not inner:
                return []
            return [coerce(x) for x in _split_flow_list(inner)]
        # quoted string
        if (v.startswith('"') and v.endswith('"')) or (v.startswith("'") and v.endswith("'")):
            return v[1:-1]
        # int
        try:
            return int(v)
        except ValueError:
            pass
        try:
            return float(v)
        except ValueError:
            pass
        return v

    i = 0
    n = len(lines)
    while i < n:
        ln = lines[i]
        if not ln.startswith(" "):
            if ":" not in ln:
                i += 1
                continue
            key, _, rest = ln.partition(":")
            key = key.strip()
            rest = rest.strip()
            if rest == "":
                # block — either list of items or nested map
                items: List[Any] = []
                nested: Dict[str, Any] = {}
                j = i + 1
                while j < n and lines[j].startswith(" "):
                    sub = lines[j]
                    if sub.lstrip().startswith("- "):
                        # list item
                        item = sub.lstrip()[2:]
                        if ":" in item and not (item.startswith('"') or item.startswith("'")):
                            ikey, _, ival = item.partition(":")
                            obj: Dict[str, Any] = {ikey.strip(): coerce(ival)}
                            # consume continuation lines indented deeper than the dash item
                            base_indent = len(sub) - len(sub.lstrip())
                            k = j + 1
                            while k < n and lines[k].startswith(" "):
                                indent = len(lines[k]) - len(lines[k].lstrip())
                                if indent <= base_indent:
                                    break
                                if ":" in lines[k]:
                                    sk, _, sv = lines[k].partition(":")
                                    obj[sk.strip()] = coerce(sv)
                                k += 1
                            items.append(obj)
                            j = k
                        else:
                            items.append(coerce(item))
                            j += 1
                    elif ":" in sub:
                        sk, _, sv = sub.partition(":")
                        nested[sk.strip()] = coerce(sv)
                        j += 1
                    else:
                        j += 1
                if items:
                    root[key] = items
                elif nested:
                    root[key] = nested
                else:
                    root[key] = None
                i = j
                continue
            root[key] = coerce(rest)
        i += 1
    return root


def _split_flow_list(inner: str) -> List[str]:
    # split on commas not inside brackets/quotes
    parts: List[str] = []
    depth = 0
    quote: Optional[str] = None
    buf = []
    for ch in inner:
        if quote:
            buf.append(ch)
            if ch == quote:
                quote = None
            continue
        if ch in ("'", '"'):
            quote = ch
            buf.append(ch)
            continue
        if ch in "[{(":
            depth += 1
            buf.append(ch)
            continue
        if ch in "]})":
            depth -= 1
            buf.append(ch)
            continue
        if ch == "," and depth == 0:
            parts.append("".join(buf))
            buf = []
            continue
        buf.append(ch)
    if buf:
        parts.append("".join(buf))
    return [p.strip() for p in parts]


# --------------------- JSON-Schema subset validator -----------------------


class ValidationError(Exception):
    pass


def validate(instance: Any, schema: Dict[str, Any]) -> List[str]:
    """Return list of validation error strings. Empty list = valid."""
    errors: List[str] = []
    _check(instance, schema, "<root>", errors, schema)
    return errors


def _check(inst: Any, schema: Dict[str, Any], path: str, errors: List[str], root: Dict[str, Any]) -> None:
    if "$ref" in schema:
        # not used in our schema
        return
    if "type" in schema:
        if not _check_type(inst, schema["type"]):
            errors.append(f"{path}: expected type {schema['type']}, got {type(inst).__name__}")
            return
    if "enum" in schema:
        if inst not in schema["enum"]:
            errors.append(f"{path}: value {inst!r} not in enum {schema['enum']}")
    if "pattern" in schema and isinstance(inst, str):
        if not re.search(schema["pattern"], inst):
            errors.append(f"{path}: value {inst!r} does not match pattern {schema['pattern']}")
    if "format" in schema and isinstance(inst, str):
        if schema["format"] == "date-time" and not _is_iso8601(inst):
            errors.append(f"{path}: value {inst!r} not an ISO-8601 date-time")
    if "minLength" in schema and isinstance(inst, str):
        if len(inst) < schema["minLength"]:
            errors.append(f"{path}: string length {len(inst)} < minLength {schema['minLength']}")
    if "maxLength" in schema and isinstance(inst, str):
        if len(inst) > schema["maxLength"]:
            errors.append(f"{path}: string length {len(inst)} > maxLength {schema['maxLength']}")
    if "minimum" in schema and isinstance(inst, (int, float)):
        if inst < schema["minimum"]:
            errors.append(f"{path}: value {inst} < minimum {schema['minimum']}")
    if "minItems" in schema and isinstance(inst, list):
        if len(inst) < schema["minItems"]:
            errors.append(f"{path}: list length {len(inst)} < minItems {schema['minItems']}")
    if "uniqueItems" in schema and schema["uniqueItems"] and isinstance(inst, list):
        seen = set()
        for it in inst:
            key = json.dumps(it, sort_keys=True) if isinstance(it, (dict, list)) else it
            if key in seen:
                errors.append(f"{path}: duplicate item {it!r}")
                break
            seen.add(key)
    if isinstance(inst, dict):
        if "required" in schema:
            for r in schema["required"]:
                if r not in inst:
                    errors.append(f"{path}: missing required field '{r}'")
        if "additionalProperties" in schema and schema["additionalProperties"] is False:
            allowed = set((schema.get("properties") or {}).keys())
            for k in inst.keys():
                if k not in allowed:
                    errors.append(f"{path}: additional property '{k}' not allowed")
        for k, sub in (schema.get("properties") or {}).items():
            if k in inst:
                _check(inst[k], sub, f"{path}.{k}", errors, root)
    if isinstance(inst, list) and "items" in schema:
        for idx, it in enumerate(inst):
            _check(it, schema["items"], f"{path}[{idx}]", errors, root)
    if "allOf" in schema:
        for sub in schema["allOf"]:
            if "if" in sub:
                if _matches(inst, sub["if"]):
                    if "then" in sub:
                        _check(inst, sub["then"], path, errors, root)
                else:
                    if "else" in sub:
                        _check(inst, sub["else"], path, errors, root)
            else:
                _check(inst, sub, path, errors, root)


def _matches(inst: Any, cond: Dict[str, Any]) -> bool:
    if "properties" in cond and isinstance(inst, dict):
        for k, sub in cond["properties"].items():
            if k not in inst:
                return False
            if "enum" in sub and inst[k] not in sub["enum"]:
                return False
            if "const" in sub and inst[k] != sub["const"]:
                return False
        return True
    return False


def _check_type(inst: Any, ty: str) -> bool:
    if ty == "object":
        return isinstance(inst, dict)
    if ty == "array":
        return isinstance(inst, list)
    if ty == "string":
        return isinstance(inst, str)
    if ty == "integer":
        return isinstance(inst, int) and not isinstance(inst, bool)
    if ty == "number":
        return isinstance(inst, (int, float)) and not isinstance(inst, bool)
    if ty == "boolean":
        return isinstance(inst, bool)
    if ty == "null":
        return inst is None
    return True


def _is_iso8601(s: str) -> bool:
    try:
        # accept Z and +HH:MM
        s2 = s.replace("Z", "+00:00")
        _dt.datetime.fromisoformat(s2)
        return True
    except ValueError:
        return False


# ------------------------------ CLI ---------------------------------------


def load_schema(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def auto_select_schema(doc: Dict[str, Any], v1_schema_path: Path, v2_schema_path: Path) -> Dict[str, Any]:
    """Auto-detect whether to use v1 or v2 schema based on doc content.
    v2 documents may have 'predicted_attack_classes' or 'realized_attack_class'.
    Falls back to v1 for backward compatibility.
    """
    if "predicted_attack_classes" in doc or "realized_attack_class" in doc:
        if v2_schema_path.exists():
            return load_schema(v2_schema_path)
    # Default to v1
    return load_schema(v1_schema_path)


def validate_file(path: Path, schema: Dict[str, Any],
                  v1_schema_path: Optional[Path] = None,
                  v2_schema_path: Optional[Path] = None) -> Tuple[bool, List[str]]:
    try:
        doc = _load_yaml(path)
    except Exception as e:
        return False, [f"{path}: YAML parse error: {e}"]
    if not isinstance(doc, dict):
        return False, [f"{path}: top-level YAML must be a mapping, got {type(doc).__name__}"]

    # If no explicit schema provided, auto-select based on doc content
    if schema is None and v1_schema_path and v2_schema_path:
        schema = auto_select_schema(doc, v1_schema_path, v2_schema_path)

    errs = validate(doc, schema)
    return (not errs), errs


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(description="Validate verdict-tag YAML files against v1 or v2 schema (auto-detected).")
    p.add_argument("--validate", action="append", default=[], help="YAML file to validate (repeatable).")
    p.add_argument("--validate-dir", action="append", default=[], help="Directory of YAMLs to validate (repeatable).")
    p.add_argument("--schema-path", default=str(DEFAULT_SCHEMA_PATH),
                  help="Explicit schema path (overrides auto-detection). Default: v1")
    p.add_argument("--auto-schema", action="store_true", default=True,
                  help="Auto-detect v1 vs v2 schema based on doc content (default).")
    p.add_argument("--quiet", action="store_true")
    args = p.parse_args(argv)

    schema_path = Path(args.schema_path)
    if not schema_path.exists():
        print(f"schema not found: {schema_path}", file=sys.stderr)
        return 2

    # If auto-schema is enabled and explicit path not changed from default, set up both
    schema = None
    v1_schema_path = DEFAULT_SCHEMA_PATH if args.auto_schema else schema_path
    v2_schema_path = SCHEMA_V2_PATH if args.auto_schema else None

    # If explicit schema path was provided, use it
    if args.schema_path != str(DEFAULT_SCHEMA_PATH):
        schema = load_schema(schema_path)
        v1_schema_path = None
        v2_schema_path = None

    files: List[Path] = [Path(f) for f in args.validate]
    for d in args.validate_dir:
        dp = Path(d)
        if not dp.is_dir():
            print(f"not a directory: {dp}", file=sys.stderr)
            return 2
        files.extend(sorted(dp.glob("*.yaml")))

    if not files:
        print("no files provided", file=sys.stderr)
        return 2

    fail = 0
    for f in files:
        ok, errs = validate_file(f, schema, v1_schema_path, v2_schema_path)
        if ok:
            if not args.quiet:
                print(f"OK  {f}")
        else:
            fail += 1
            print(f"FAIL {f}")
            for e in errs:
                print(f"     - {e}")
    if not args.quiet:
        print(f"\nresult: {len(files) - fail}/{len(files)} valid")
    return 0 if fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
