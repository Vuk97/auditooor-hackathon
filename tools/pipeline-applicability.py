#!/usr/bin/env python3
"""Deterministic applicability authority for Pipeline V2 manifests."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

try:
    from tools.lib.source_extensions import EXT_TO_LANG
except ModuleNotFoundError:
    from lib.source_extensions import EXT_TO_LANG


def _load_stable_hash() -> Any:
    path = Path(__file__).resolve().parent / "pipeline-receipt.py"
    spec = importlib.util.spec_from_file_location("_pipeline_applicability_receipt", path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.stable_hash


stable_hash = _load_stable_hash()
INVENTORY_RELATIVE_PATH = Path(".auditooor") / "inscope_units.jsonl"

_LANGUAGE_ALIASES = {
    "sol": "solidity",
    "solidity": "solidity",
    "evm": "solidity",
    "ethereum": "solidity",
    "go": "go",
    "golang": "go",
    "rust": "rust",
    "rs": "rust",
    "javascript": "javascript",
    "js": "javascript",
    "node": "javascript",
    "nodejs": "javascript",
    "typescript": "typescript",
    "ts": "typescript",
    "oscript": "oscript",
    "aa": "oscript",
    "obyte": "oscript",
    "autonomousagent": "oscript",
    "autonomousagents": "oscript",
    "vyper": "vyper",
    "move": "move",
    "cairo": "cairo",
    "circom": "circom",
    "clarity": "clarity",
    "clar": "clarity",
    "noir": "noir",
    "python": "python",
    "py": "python",
    "c": "c",
    "c99": "c",
    "c11": "c",
    "c17": "c",
    "cpp": "cpp",
    "cxx": "cpp",
    "cc": "cpp",
    "cplusplus": "cpp",
    "java": "java",
    "zokrates": "zokrates",
    "zok": "zokrates",
}
_CANONICAL_SOURCE_LANGUAGES = frozenset(EXT_TO_LANG.values())


@dataclass(frozen=True)
class ProbeDiagnostic:
    code: str
    path: str
    message: str


class ApplicabilityError(ValueError):
    """Raised when a declared applicability probe cannot be evaluated."""

    def __init__(self, *diagnostics: str):
        self.diagnostics = tuple(sorted(set(diagnostics)))
        super().__init__(", ".join(self.diagnostics))


def _canonical(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _canonical(value[key]) for key in sorted(value, key=lambda item: str(item))}
    if isinstance(value, (list, tuple)):
        return [_canonical(item) for item in value]
    return value


def normalize_language(value: Any) -> str:
    """Return a stable canonical language token without dropping unknown values."""

    if not isinstance(value, str):
        return ""
    token = value.strip()
    if not token:
        return ""
    normalized_key = re.sub(r"[^a-z0-9+]", "", token.lower())
    if normalized_key in {"c++", "cplus", "cc++", "oscriptaa", "solidityevm"}:
        if normalized_key == "oscriptaa":
            return "oscript"
        if normalized_key == "solidityevm":
            return "solidity"
        normalized_key = "cplusplus"
    normalized = _LANGUAGE_ALIASES.get(normalized_key, token.lower())
    if normalized in _CANONICAL_SOURCE_LANGUAGES:
        return normalized
    return normalized


def _probe_diagnostic(diagnostics: list[ProbeDiagnostic], code: str, path: str, message: str) -> None:
    diagnostics.append(ProbeDiagnostic(code, path, message))


def _validate_aliases(
    value: Any,
    path: str,
    diagnostics: list[ProbeDiagnostic],
    seen_aliases: set[str],
    probe_id: str,
) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list):
        _probe_diagnostic(diagnostics, "MALFORMED_APPLICABILITY_ALIASES", path, "aliases must be a list of non-empty strings")
        return []
    aliases: list[str] = []
    local: set[str] = set()
    for index, raw in enumerate(value):
        alias_path = f"{path}[{index}]"
        if not isinstance(raw, str) or not raw.strip():
            _probe_diagnostic(diagnostics, "MALFORMED_APPLICABILITY_ALIAS", alias_path, "alias must be a non-empty string")
            continue
        alias = raw.strip()
        if alias == probe_id or alias in local or alias in seen_aliases:
            _probe_diagnostic(diagnostics, "DUPLICATE_APPLICABILITY_ALIAS", alias_path, f"duplicate applicability alias '{alias}'")
            continue
        local.add(alias)
        seen_aliases.add(alias)
        aliases.append(alias)
    if aliases != sorted(aliases):
        _probe_diagnostic(diagnostics, "UNSORTED_APPLICABILITY_ALIASES", path, "aliases must be sorted")
    return aliases


def parse_probe_registry(manifest: Any) -> tuple[dict[str, dict[str, Any]], list[ProbeDiagnostic]]:
    """Validate and normalize explicit applicability probe definitions."""

    diagnostics: list[ProbeDiagnostic] = []
    if not isinstance(manifest, dict):
        return {}, [ProbeDiagnostic("MALFORMED_APPLICABILITY_REGISTRY", "$.applicability_probes", "manifest must be an object")]
    raw = manifest.get("applicability_probes")
    if not isinstance(raw, list) or not raw:
        return {}, [ProbeDiagnostic("MALFORMED_APPLICABILITY_REGISTRY", "$.applicability_probes", "applicability_probes must be a non-empty list of objects")]
    probes: dict[str, dict[str, Any]] = {}
    seen_aliases: set[str] = set()
    for index, item in enumerate(raw):
        path = f"$.applicability_probes[{index}]"
        if not isinstance(item, dict):
            _probe_diagnostic(diagnostics, "MALFORMED_APPLICABILITY_PROBE", path, "applicability probe entries must be objects")
            continue
        probe_id = item.get("id")
        kind = item.get("kind")
        if not isinstance(probe_id, str) or not probe_id.strip():
            _probe_diagnostic(diagnostics, "MALFORMED_APPLICABILITY_PROBE", f"{path}.id", "probe id must be a non-empty string")
            continue
        probe_id = probe_id.strip()
        if probe_id in probes or probe_id in seen_aliases:
            _probe_diagnostic(diagnostics, "DUPLICATE_APPLICABILITY_PROBE", f"{path}.id", f"duplicate probe id '{probe_id}'")
            continue
        allowed_fields = {"id", "kind", "aliases"}
        if isinstance(kind, str) and kind == "language_any":
            allowed_fields.add("languages")
        for key in sorted(item):
            if key not in allowed_fields:
                _probe_diagnostic(diagnostics, "MALFORMED_APPLICABILITY_PROBE", f"{path}.{key}", f"unsupported probe field '{key}'")
        if not isinstance(kind, str) or kind not in {"always", "language_any"}:
            _probe_diagnostic(diagnostics, "UNKNOWN_APPLICABILITY_PROBE_KIND", f"{path}.kind", "probe kind must be 'always' or 'language_any'")
            continue
        raw_aliases = item.get("aliases")
        if isinstance(raw_aliases, list):
            for alias_index, raw_alias in enumerate(raw_aliases):
                if isinstance(raw_alias, str) and raw_alias.strip() in probes:
                    _probe_diagnostic(
                        diagnostics,
                        "DUPLICATE_APPLICABILITY_ALIAS",
                        f"{path}.aliases[{alias_index}]",
                        f"applicability alias '{raw_alias.strip()}' conflicts with a probe id",
                    )
        aliases = _validate_aliases(item.get("aliases"), f"{path}.aliases", diagnostics, seen_aliases, probe_id)
        definition: dict[str, Any] = {"id": probe_id, "kind": kind}
        if aliases:
            definition["aliases"] = aliases
        if kind == "always":
            if "languages" in item:
                _probe_diagnostic(diagnostics, "MALFORMED_APPLICABILITY_PROBE", f"{path}.languages", "always probes must not define languages")
            probes[probe_id] = definition
            continue
        languages = item.get("languages")
        if not isinstance(languages, list) or not languages:
            _probe_diagnostic(diagnostics, "MALFORMED_APPLICABILITY_LANGUAGES", f"{path}.languages", "language_any probes require a non-empty languages list")
            continue
        normalized: list[str] = []
        for language_index, raw_language in enumerate(languages):
            language = normalize_language(raw_language)
            if not language:
                _probe_diagnostic(diagnostics, "MALFORMED_APPLICABILITY_LANGUAGE", f"{path}.languages[{language_index}]", "language must be a non-empty string")
                continue
            normalized.append(language)
        if len(normalized) != len(set(normalized)):
            _probe_diagnostic(diagnostics, "DUPLICATE_APPLICABILITY_LANGUAGE", f"{path}.languages", "languages must not contain duplicate canonical aliases")
        if normalized != sorted(normalized):
            _probe_diagnostic(diagnostics, "UNSORTED_APPLICABILITY_LANGUAGES", f"{path}.languages", "languages must be sorted by canonical language")
        definition["languages"] = normalized
        probes[probe_id] = definition
    return probes, diagnostics


def _inventory_metadata(path: Path, raw: bytes, row_count: int) -> dict[str, Any]:
    return {
        "path": INVENTORY_RELATIVE_PATH.as_posix(),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "size": len(raw),
        "row_count": row_count,
    }


def _load_inventory(workspace: Path) -> tuple[dict[str, Any], list[str]]:
    path = workspace / INVENTORY_RELATIVE_PATH
    try:
        raw = path.read_bytes()
    except FileNotFoundError as exc:
        raise ApplicabilityError("applicability_inventory_missing") from exc
    except OSError as exc:
        raise ApplicabilityError("applicability_inventory_unreadable") from exc
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ApplicabilityError("applicability_inventory_invalid_utf8") from exc
    rows = [line.strip() for line in text.splitlines() if line.strip()]
    if not rows:
        raise ApplicabilityError("applicability_inventory_empty")
    languages: set[str] = set()
    paths_to_languages: dict[Path, str] = {}
    for index, line in enumerate(rows, start=1):
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ApplicabilityError(f"applicability_inventory_malformed_row:{index}") from exc
        if not isinstance(row, dict):
            raise ApplicabilityError(f"applicability_inventory_non_object_row:{index}")
        file_value = row.get("file")
        language_value = row.get("lang")
        if not isinstance(file_value, str) or not file_value.strip():
            raise ApplicabilityError(f"applicability_inventory_missing_file:{index}")
        language = normalize_language(language_value)
        if not language:
            raise ApplicabilityError(f"applicability_inventory_missing_lang:{index}")
        source = Path(file_value.strip())
        resolved = source.resolve() if source.is_absolute() else (workspace / source).resolve()
        try:
            resolved.relative_to(workspace.resolve())
        except ValueError as exc:
            raise ApplicabilityError(f"applicability_inventory_source_outside_workspace:{index}") from exc
        if not resolved.is_file():
            raise ApplicabilityError(f"applicability_inventory_source_missing:{index}")
        prior = paths_to_languages.get(resolved)
        if prior is not None and prior != language:
            raise ApplicabilityError(f"applicability_inventory_contradictory_row:{index}")
        paths_to_languages[resolved] = language
        languages.add(language)
    return _inventory_metadata(path, raw, len(rows)), sorted(languages)


def _always_inputs(definition: dict[str, Any], workspace: Path) -> dict[str, Any]:
    path = workspace / INVENTORY_RELATIVE_PATH
    if not path.is_file():
        inventory = {"path": INVENTORY_RELATIVE_PATH.as_posix(), "sha256": None, "size": 0, "row_count": 0}
    else:
        try:
            raw = path.read_bytes()
        except OSError as exc:
            raise ApplicabilityError("applicability_inventory_unreadable") from exc
        try:
            row_count = len([line for line in raw.decode("utf-8").splitlines() if line.strip()])
        except UnicodeDecodeError as exc:
            raise ApplicabilityError("applicability_inventory_invalid_utf8") from exc
        inventory = _inventory_metadata(path, raw, row_count)
    return {
        "probe_definition": _canonical(definition),
        "workspace_root": str(workspace),
        "inventory": inventory,
        "normalized_languages": [],
        "requested_languages": [],
    }


def evaluate_probe(manifest: Any, probe_id: Any, workspace: str | Path) -> dict[str, Any]:
    """Evaluate one registered probe and return receipt-compatible evidence."""

    probes, diagnostics = parse_probe_registry(manifest)
    if diagnostics:
        raise ApplicabilityError(*(item.code for item in diagnostics))
    if not isinstance(probe_id, str) or probe_id not in probes:
        raise ApplicabilityError("applicability_probe_unregistered")
    root = Path(workspace).expanduser().resolve()
    if not root.is_dir():
        raise ApplicabilityError("applicability_workspace_missing")
    definition = probes[probe_id]
    if definition["kind"] == "always":
        inputs = _always_inputs(definition, root)
        result = True
    else:
        inventory, normalized_languages = _load_inventory(root)
        requested_languages = definition["languages"]
        inputs = {
            "probe_definition": _canonical(definition),
            "workspace_root": str(root),
            "inventory": inventory,
            "normalized_languages": normalized_languages,
            "requested_languages": requested_languages,
        }
        result = bool(set(normalized_languages) & set(requested_languages))
    body = {"probe_id": probe_id, "canonical_inputs": _canonical(inputs), "result": result}
    return {**body, "hash": stable_hash(body)}


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--probe-id", required=True)
    args = parser.parse_args(argv)
    try:
        print(json.dumps(evaluate_probe(_load_json(args.manifest), args.probe_id, args.workspace), indent=2, sort_keys=True))
        return 0
    except (ApplicabilityError, OSError, json.JSONDecodeError) as exc:
        diagnostics = list(exc.diagnostics) if isinstance(exc, ApplicabilityError) else [str(exc)]
        print(json.dumps({"valid": False, "diagnostics": diagnostics}, sort_keys=True), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
