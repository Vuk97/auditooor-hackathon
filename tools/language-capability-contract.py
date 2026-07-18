#!/usr/bin/env python3
"""Validate and query the canonical language capability contract.

Schema: auditooor.language_capability.v1

Examples:
  python3 tools/language-capability-contract.py validate
  python3 tools/language-capability-contract.py query --inventory inventory.json --phase dataflow

The query command is a planning/reporting operation. It never runs an engine.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import re
import sys
from pathlib import Path
from typing import Any

SCHEMA = "auditooor.language_capability.v1"
ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONTRACT = ROOT / "reference" / "language_capabilities.json"
DEFAULT_SOURCE_EXTENSIONS = ROOT / "tools" / "lib" / "source_extensions.py"
TIERS = {
    "semantic/compiler-backed",
    "AST-backed",
    "lexical/shape-only",
    "enumerator-only",
    "unsupported",
    "unsupported_applicable",
}
CAPABILITY_FIELDS = (
    "parser_extractor",
    "dataflow_substrate",
    "semantic_graph_tier",
    "reasoner_ids",
    "engine_substrate_route",
    "depth_route",
    "harness_fuzz_route",
    "evidence_tier",
)
PHASES = {
    "source": ("parser_extractor", "evidence_tier"),
    "ast": ("parser_extractor",),
    "dataflow": ("dataflow_substrate",),
    "semantic-graph": ("semantic_graph_tier",),
    "reasoner": ("reasoner_ids",),
    "engine": ("engine_substrate_route",),
    "depth": ("depth_route",),
    "harness": ("harness_fuzz_route",),
    "fuzz": ("harness_fuzz_route",),
    "all": CAPABILITY_FIELDS,
}
DEFAULT_PHASE_MINIMUM_TIERS = {
    "source": "lexical/shape-only",
    "ast": "AST-backed",
    "dataflow": "semantic/compiler-backed",
    "semantic-graph": "semantic/compiler-backed",
    "reasoner": "semantic/compiler-backed",
    "engine": "semantic/compiler-backed",
    "depth": "semantic/compiler-backed",
    "harness": "AST-backed",
    "fuzz": "semantic/compiler-backed",
}
TIER_RANK = {
    "unsupported": 0,
    "unsupported_applicable": 0,
    "lexical/shape-only": 1,
    "enumerator-only": 1,
    "AST-backed": 2,
    "semantic/compiler-backed": 3,
}
FIELD_PHASE = {
    field: phase
    for phase, fields in PHASES.items()
    if phase != "all"
    for field in fields
}
REQUIRED_FIELDS = {
    "canonical", "display_name", "aliases", "extensions",
    "authoritative_inventory_token", *CAPABILITY_FIELDS,
}


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read JSON {path}: {exc}") from exc


def load_contract(path: Path = DEFAULT_CONTRACT) -> dict[str, Any]:
    payload = _load_json(path)
    if not isinstance(payload, dict):
        raise ValueError("contract must be a JSON object")
    return payload


def authoritative_languages(path: Path = DEFAULT_SOURCE_EXTENSIONS) -> set[str]:
    """Read canonical language values from source_extensions.py or an inventory.

    JSON inventories may be a list, {"languages": [...]}, {"files": [...]}, or
    JSONL rows carrying language/lang/file/path fields. This keeps query useful
    with the same small inventories used by audit stages without treating an
    arbitrary language string as supported.
    """
    if path.suffix == ".py":
        return set(authoritative_extension_map(path).values())

    try:
        payload = _load_json(path)
        rows = payload.get("languages", payload) if isinstance(payload, dict) else payload
    except ValueError:
        rows = []
        try:
            for line in path.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    rows.append(json.loads(line))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"cannot read inventory {path}: {exc}") from exc

    if isinstance(rows, dict):
        rows = rows.get("languages", rows.get("files", []))
    if not isinstance(rows, list):
        raise ValueError("inventory must contain a language/file list")
    extension_map = authoritative_extension_map()
    out: set[str] = set()
    for row in rows:
        if isinstance(row, str):
            value = row.strip().lower()
            out.add(extension_map.get(Path(value).suffix, value))
        elif isinstance(row, dict):
            value = row.get("language", row.get("lang", row.get("canonical")))
            if value is None:
                value = row.get("file", row.get("path", ""))
            if value:
                text = str(value).strip().lower()
                out.add(extension_map.get(Path(text).suffix, text))
    return out


def authoritative_extension_map(path: Path = DEFAULT_SOURCE_EXTENSIONS) -> dict[str, str]:
    """Return the extension map when the authoritative source is Python."""
    if path.suffix != ".py":
        return {}
    spec = importlib.util.spec_from_file_location("language_source_extensions_map", path)
    if spec is None or spec.loader is None:
        raise ValueError(f"cannot import authoritative inventory {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    values = getattr(module, "EXT_TO_LANG", None)
    if not isinstance(values, dict):
        raise ValueError(f"{path} has no EXT_TO_LANG mapping")
    return {str(key).lower(): str(value).strip().lower() for key, value in values.items()}


def _evidence_rows(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, dict):
        for key in ("receipts", "evidence", "records", "rows", "backend_receipts"):
            if isinstance(payload.get(key), list):
                return [row for row in payload[key] if isinstance(row, dict)]
        return [payload]
    if isinstance(payload, list):
        return [row for row in payload if isinstance(row, dict)]
    return []


def load_evidence(paths: list[Path] | None = None) -> list[dict[str, Any]]:
    """Load machine evidence rows from JSON or JSONL receipt inputs."""
    rows: list[dict[str, Any]] = []
    for path in paths or []:
        try:
            rows.extend(_evidence_rows(_load_json(path)))
            continue
        except ValueError:
            pass
        try:
            for line in path.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    rows.extend(_evidence_rows(json.loads(line)))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"cannot read evidence {path}: {exc}") from exc
    return rows


def _make_targets(makefile: Path) -> set[str]:
    if not makefile.is_file():
        return set()
    text = makefile.read_text(encoding="utf-8", errors="replace")
    targets = set(re.findall(r"(?m)^([A-Za-z0-9_.-]+)\s*:", text))
    for line in text.splitlines():
        if line.lstrip().startswith(".PHONY:"):
            targets.update(line.split(":", 1)[1].split())
    return targets


def _iter_tool_refs(value: Any) -> list[str]:
    if not isinstance(value, dict):
        return []
    refs = value.get("tool_refs", [])
    return [str(ref) for ref in refs] if isinstance(refs, list) else []


def _tier_of(value: Any) -> str | None:
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        tier = value.get("tier")
        return str(tier) if tier is not None else None
    return None


def _phase_minimums(contract: dict[str, Any]) -> dict[str, str]:
    declared = contract.get("phase_minimum_tiers")
    if not isinstance(declared, dict):
        return dict(DEFAULT_PHASE_MINIMUM_TIERS)
    return {str(key): str(value) for key, value in declared.items()}


def _tier_satisfies(actual: str | None, minimum: str | None) -> bool:
    if actual not in TIER_RANK or minimum not in TIER_RANK:
        return False
    return TIER_RANK[actual] >= TIER_RANK[minimum]


def _validate_route(name: str, value: Any, errors: list[str], language: str) -> None:
    if name == "reasoner_ids":
        if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
            errors.append(f"{language}.{name} must be a list of strings")
        return
    if name == "evidence_tier":
        if value not in TIERS:
            errors.append(f"{language}.{name} has invalid tier {value!r}")
        return
    if not isinstance(value, dict):
        errors.append(f"{language}.{name} must be an object")
        return
    tier = _tier_of(value)
    if tier not in TIERS:
        errors.append(f"{language}.{name} has invalid tier {tier!r}")
    if "language_filter" not in value or value.get("language_filter") is None:
        errors.append(f"{language}.{name} must declare a non-null language_filter")
    elif not isinstance(value.get("language_filter"), list) or language not in value["language_filter"]:
        errors.append(f"{language}.{name} language_filter must include {language!r}")
    if not isinstance(value.get("tool_refs", []), list):
        errors.append(f"{language}.{name}.tool_refs must be a list")
    if not isinstance(value.get("make_targets", []), list):
        errors.append(f"{language}.{name}.make_targets must be a list")


def validate_contract(contract: dict[str, Any], *, repo_root: Path = ROOT,
                      source_extensions: Path = DEFAULT_SOURCE_EXTENSIONS) -> list[str]:
    errors: list[str] = []
    if contract.get("schema") != SCHEMA:
        errors.append(f"schema must be {SCHEMA}")
    declared_phase_minimums = contract.get("phase_minimum_tiers")
    phase_minimums = declared_phase_minimums if isinstance(declared_phase_minimums, dict) else {}
    if not isinstance(declared_phase_minimums, dict):
        errors.append("phase_minimum_tiers must be an object")
    for phase, minimum in phase_minimums.items():
        if phase not in PHASES or phase == "all":
            errors.append(f"phase_minimum_tiers has unknown phase {phase!r}")
        if minimum not in TIERS:
            errors.append(f"phase_minimum_tiers.{phase} has invalid tier {minimum!r}")
    for phase in DEFAULT_PHASE_MINIMUM_TIERS:
        if phase not in phase_minimums:
            errors.append(f"phase_minimum_tiers missing {phase}")
    authority = contract.get("authoritative_inventory")
    if not isinstance(authority, dict):
        errors.append("authoritative_inventory must be an object")
    else:
        module_ref = authority.get("module")
        if not isinstance(module_ref, str) or not (repo_root / module_ref).is_file():
            errors.append(f"authoritative_inventory references missing file {module_ref!r}")
    rows = contract.get("languages")
    if not isinstance(rows, list):
        return errors + ["languages must be a list"]
    try:
        authoritative = authoritative_languages(source_extensions)
        extension_map = authoritative_extension_map(source_extensions)
    except ValueError as exc:
        return errors + [str(exc)]

    seen_canonical: set[str] = set()
    seen_aliases: dict[str, str] = {}
    seen_extensions: dict[str, str] = {}
    make_targets = _make_targets(repo_root / "Makefile")
    for index, row in enumerate(rows):
        prefix = f"languages[{index}]"
        if not isinstance(row, dict):
            errors.append(f"{prefix} must be an object")
            continue
        missing = REQUIRED_FIELDS - set(row)
        errors.extend(f"{prefix} missing {field}" for field in sorted(missing))
        canonical = str(row.get("canonical", "")).strip().lower()
        if not canonical:
            continue
        if canonical in seen_canonical:
            errors.append(f"duplicate canonical language {canonical}")
        seen_canonical.add(canonical)
        token = str(row.get("authoritative_inventory_token", "")).strip().lower()
        if token != canonical:
            errors.append(f"{canonical} authoritative_inventory_token must be {canonical!r}")
        if canonical not in authoritative:
            errors.append(f"{canonical} is not in authoritative source_extensions inventory")

        receipt = row.get("semantic_backend_receipt")
        semantic_fields = [
            field for field in CAPABILITY_FIELDS
            if _tier_of(row.get(field)) == "semantic/compiler-backed"
        ]
        if semantic_fields or row.get("reasoner_ids"):
            if not isinstance(receipt, dict):
                errors.append(f"{canonical} semantic capabilities require semantic_backend_receipt")
            else:
                for key in ("required_for_phases", "receipt_schema", "backend", "confidence"):
                    if not receipt.get(key):
                        errors.append(f"{canonical}.semantic_backend_receipt missing {key}")
                if receipt.get("receipt_schema") != "auditooor.language_backend_receipt.v1":
                    errors.append(f"{canonical}.semantic_backend_receipt has invalid schema")
                required_phases = receipt.get("required_for_phases", [])
                if isinstance(required_phases, list):
                    for phase in required_phases:
                        if phase not in phase_minimums:
                            errors.append(f"{canonical}.semantic_backend_receipt has unknown phase {phase!r}")
                        elif not _tier_satisfies("semantic/compiler-backed", phase_minimums[phase]):
                            errors.append(f"{canonical}.semantic_backend_receipt phase {phase!r} is below semantic minimum")

        aliases = row.get("aliases", [])
        extensions = row.get("extensions", [])
        if not isinstance(aliases, list) or any(not isinstance(item, str) for item in aliases):
            errors.append(f"{canonical}.aliases must be a list of strings")
            aliases = []
        if not isinstance(extensions, list) or any(not isinstance(item, str) for item in extensions):
            errors.append(f"{canonical}.extensions must be a list of strings")
            extensions = []
        for alias in aliases:
            key = alias.strip().lower()
            if key in seen_aliases:
                errors.append(f"duplicate alias {alias!r} ({seen_aliases[key]} and {canonical})")
            seen_aliases[key] = canonical
        for extension in extensions:
            key = extension.strip().lower()
            if key in seen_extensions:
                errors.append(f"duplicate extension {extension!r} ({seen_extensions[key]} and {canonical})")
            seen_extensions[key] = canonical
            if extension_map and extension_map.get(key) != canonical:
                errors.append(f"{canonical} extension {extension!r} is not registered for {canonical}")

        for field in CAPABILITY_FIELDS:
            _validate_route(field, row.get(field), errors, canonical)
        evidence = row.get("evidence_tier")
        for field in CAPABILITY_FIELDS:
            value = row.get(field)
            tier = _tier_of(value)
            if tier == "semantic/compiler-backed" and evidence in {"lexical/shape-only", "enumerator-only", "unsupported", "unsupported_applicable"}:
                errors.append(f"{canonical}.{field} makes a semantic claim with {evidence} evidence")
            for ref in _iter_tool_refs(value):
                ref_path = repo_root / ref
                if not ref.startswith("tools/") or not ref_path.is_file():
                    errors.append(f"{canonical}.{field} references missing tool {ref}")
            if isinstance(value, dict):
                for target in value.get("make_targets", []):
                    if str(target) not in make_targets:
                        errors.append(f"{canonical}.{field} references missing Make target {target}")
            if field == "reasoner_ids" and isinstance(value, list):
                for reasoner in value:
                    if not (repo_root / "tools" / reasoner).is_file():
                        errors.append(f"{canonical}.reasoner_ids references missing tool {reasoner}")

    missing_languages = authoritative - seen_canonical
    errors.extend(f"authoritative language {language} has no contract row" for language in sorted(missing_languages))
    return errors


def _row_alias_map(contract: dict[str, Any]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for row in contract.get("languages", []):
        if not isinstance(row, dict):
            continue
        canonical = str(row.get("canonical", "")).lower()
        for key in [canonical, *row.get("aliases", []), *row.get("extensions", [])]:
            out[str(key).lower()] = row
    return out


def _present_rows(contract: dict[str, Any], inventory: set[str]) -> tuple[list[dict[str, Any]], list[str]]:
    by_key = _row_alias_map(contract)
    rows: dict[str, dict[str, Any]] = {}
    unknown: list[str] = []
    for item in sorted(inventory):
        row = by_key.get(item)
        if row is None:
            unknown.append(item)
        else:
            rows[str(row["canonical"])] = row
    return [rows[key] for key in sorted(rows)], unknown


def _receipt_matches(row: dict[str, Any], receipts: list[dict[str, Any]],
                     aliases: dict[str, dict[str, Any]]) -> bool:
    requirement = row.get("semantic_backend_receipt")
    if not isinstance(requirement, dict):
        return False
    canonical = str(row.get("canonical", "")).lower()
    backend = str(requirement.get("backend", "")).lower()
    confidence = str(requirement.get("confidence", "")).lower()
    for receipt in receipts:
        language = str(receipt.get("language", receipt.get("lang", ""))).lower()
        mapped = aliases.get(language)
        if not mapped or str(mapped.get("canonical", "")).lower() != canonical:
            continue
        actual_backend = str(receipt.get("backend", receipt.get("engine", ""))).lower()
        actual_confidence = str(receipt.get("confidence", receipt.get("evidence_tier", ""))).lower()
        backend_tokens = {
            "go-ssa": ("go-ssa", "go/ssa", "go.ssa", "ssa"),
            "mir": ("mir",),
            "slither": ("slither",),
        }.get(backend, (backend,))
        if not any(token in actual_backend for token in backend_tokens):
            continue
        if actual_confidence != confidence:
            continue
        if bool(receipt.get("degraded", False)):
            continue
        if str(receipt.get("status", "pass")).lower() not in {"pass", "passed", "ok", "available", "complete"}:
            continue
        return True
    return False


def _requirements(contract: dict[str, Any], required: tuple[str, ...]) -> tuple[list[str], dict[str, str]]:
    phase_minimums = _phase_minimums(contract)
    expanded: list[str] = []
    field_phases: dict[str, str] = {}
    for item in required:
        if item == "all":
            fields = PHASES[item]
            phase = ""
        elif item in PHASES:
            fields = PHASES[item]
            phase = item
        else:
            fields = (item,)
            phase = FIELD_PHASE.get(item, "source")
        for field in fields:
            if field not in expanded:
                expanded.append(field)
                field_phases[field] = phase or FIELD_PHASE.get(field, "source")
    return expanded, field_phases


def _missing_fields(row: dict[str, Any], fields: list[str], field_phases: dict[str, str],
                    contract: dict[str, Any], receipts: list[dict[str, Any]],
                    aliases: dict[str, dict[str, Any]]) -> list[str]:
    phase_minimums = _phase_minimums(contract)
    missing: list[str] = []
    for field in fields:
        phase = field_phases[field]
        minimum = phase_minimums.get(phase, "unsupported_applicable")
        value = row.get(field)
        if field == "reasoner_ids":
            if not value:
                missing.append(field)
            elif _tier_satisfies("semantic/compiler-backed", minimum):
                receipt = row.get("semantic_backend_receipt")
                if isinstance(receipt, dict) and phase in receipt.get("required_for_phases", []):
                    if not _receipt_matches(row, receipts, aliases):
                        missing.append("semantic_backend_receipt")
            continue
        actual = _tier_of(value)
        if not _tier_satisfies(actual, minimum):
            missing.append(field)
            continue
        receipt = row.get("semantic_backend_receipt")
        if _tier_satisfies(minimum, "semantic/compiler-backed") and isinstance(receipt, dict):
            if phase in receipt.get("required_for_phases", []) and not _receipt_matches(row, receipts, aliases):
                missing.append("semantic_backend_receipt")
    return list(dict.fromkeys(missing))


def query_contract(contract: dict[str, Any], inventory: set[str], required: tuple[str, ...],
                   receipts: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    fields, field_phases = _requirements(contract, required)
    rows, unknown = _present_rows(contract, inventory)
    aliases = _row_alias_map(contract)
    receipts = receipts or []
    phase_minimums = _phase_minimums(contract)
    reported_phases = list(phase_minimums) if "all" in required else [phase for phase in required if phase in phase_minimums]
    report: dict[str, Any] = {
        "schema": "auditooor.language_capability_query.v1",
        "present_languages": [str(row["canonical"]) for row in rows],
        "unknown_inventory_languages": unknown,
        "required_capabilities": fields,
        "requested_phases": list(required),
        "phase_minimum_tiers": {phase: phase_minimums[phase] for phase in reported_phases},
        "evidence_inputs": len(receipts),
        "languages": [],
    }
    for row in rows:
        missing = _missing_fields(row, fields, field_phases, contract, receipts, aliases)
        report["languages"].append({
            "language": row["canonical"],
            "required": list(required),
            "missing": missing,
            "status": "blocked" if missing else "available",
        })
    report["blocked_languages"] = [item["language"] for item in report["languages"] if item["missing"]]
    report["ok"] = not unknown and not report["blocked_languages"]
    return report


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command")
    validate = sub.add_parser("validate", help="validate the canonical contract")
    validate.add_argument("--contract", type=Path, default=DEFAULT_CONTRACT)
    validate.add_argument("--source-extensions", type=Path, default=DEFAULT_SOURCE_EXTENSIONS)
    query = sub.add_parser("query", help="report capabilities for present inventory languages")
    query.add_argument("--contract", type=Path, default=DEFAULT_CONTRACT)
    query.add_argument("--source-extensions", type=Path, default=DEFAULT_SOURCE_EXTENSIONS)
    query.add_argument("--inventory", type=Path, required=True)
    query.add_argument("--phase", choices=sorted(PHASES), default="all")
    query.add_argument("--require", action="append", choices=CAPABILITY_FIELDS)
    query.add_argument("--evidence", "--receipt", dest="evidence", type=Path, action="append", default=[],
                       help="machine backend receipt JSON/JSONL; repeatable")
    query.add_argument("--out", type=Path, help="write the canonical query report to this JSON file")
    query.add_argument("--json", action="store_true", help="emit JSON")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "validate":
        try:
            errors = validate_contract(load_contract(args.contract), source_extensions=args.source_extensions)
        except ValueError as exc:
            print(f"FAIL: {exc}", file=sys.stderr)
            return 2
        if errors:
            for error in errors:
                print(f"FAIL: {error}")
            return 1
        print("PASS: language capability contract")
        return 0
    if args.command == "query":
        try:
            contract = load_contract(args.contract)
            validation_errors = validate_contract(contract, source_extensions=args.source_extensions)
            if validation_errors:
                for error in validation_errors:
                    print(f"FAIL: {error}", file=sys.stderr)
                return 2
            inventory = authoritative_languages(args.inventory)
            required = tuple(args.require) if args.require else (args.phase,)
            report = query_contract(contract, inventory, required, load_evidence(args.evidence))
        except ValueError as exc:
            print(f"FAIL: {exc}", file=sys.stderr)
            return 2
        rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
        if args.out:
            args.out.parent.mkdir(parents=True, exist_ok=True)
            args.out.write_text(rendered, encoding="utf-8")
        print(rendered, end="")
        return 0 if report["ok"] else 1
    _parser().print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
