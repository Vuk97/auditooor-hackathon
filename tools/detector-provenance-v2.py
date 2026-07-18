#!/usr/bin/env python3
"""Bounded detector provenance resolver v2."""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
from pathlib import Path
from typing import Any


SCHEMA_SOLIDITY = "auditooor.detector_provenance_v2.solidity.v1"
SCHEMA_RUST = "auditooor.detector_provenance_v2.rust.v1"
MAX_REFS = 16
ADVISORY_BOUNDARY = "advisory_only_local_metadata_no_impact_claim"


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _load_ast(path: Path) -> ast.Module | None:
    text = _read(path)
    if not text:
        return None
    try:
        return ast.parse(text)
    except SyntaxError:
        return None


def _safe_rel(repo_root: Path, raw: str | Path) -> str:
    if not raw:
        return ""
    text = str(raw).strip()
    if re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://", text):
        return text
    path = Path(text)
    root = repo_root.resolve()
    candidates = [path] if path.is_absolute() else [root / path]
    for candidate in candidates:
        try:
            return candidate.resolve(strict=False).relative_to(root).as_posix()
        except (OSError, ValueError):
            continue
    if not path.is_absolute() and path.parts and path.parts[0] != "..":
        return path.as_posix()
    return path.name


def _extract_argument(text: str) -> str:
    m = re.search(r"\bARGUMENT\s*=\s*['\"]([^'\"]+)['\"]", text)
    return (m.group(1).strip() if m else "")


def _extract_wiki(text: str) -> str:
    m = re.search(r"\bWIKI\s*=\s*['\"]([^'\"]+)['\"]", text)
    return (m.group(1).strip() if m else "")


def _extract_generated_from(text: str) -> str:
    patterns = [
        r"generated from\s+([^\n`]+?\.ya?ml)",
        r"Spec:\s*([^\n]+?\.ya?ml)",
    ]
    for pat in patterns:
        m = re.search(pat, text, flags=re.IGNORECASE)
        if m:
            return m.group(1).strip().strip("`")
    return ""


def _find_detector_by_id(repo_root: Path, detector_id: str) -> Path | None:
    detectors_root = repo_root / "detectors"
    if not detectors_root.is_dir():
        return None
    by_name = sorted(detectors_root.rglob(f"{detector_id}.py"))
    if by_name:
        return by_name[0]
    for path in sorted(detectors_root.rglob("*.py")):
        text = _read(path)
        if _extract_argument(text) == detector_id:
            return path
    return None


def _is_solidity_detector(path: Path, text: str) -> bool:
    if "go_wave" in path.parts or "rust_wave" in path.parts:
        return False
    if "slither.detectors.abstract_detector" in text:
        return True
    return bool(re.search(r"\.sol\b|solidity", text, flags=re.IGNORECASE))


def _discover_manifests(repo_root: Path, argument: str) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    fixtures_root = repo_root / "detectors" / "fixtures"
    if not fixtures_root.is_dir() or not argument:
        return out
    for manifest in sorted(fixtures_root.rglob("*manifest*.json")):
        payload_text = _read(manifest)
        if not payload_text:
            continue
        try:
            payload = json.loads(payload_text)
        except json.JSONDecodeError:
            continue
        if not isinstance(payload, dict):
            continue
        source_pattern_path = str(payload.get("source_pattern_path") or "")
        if argument not in payload_text and argument not in source_pattern_path:
            continue
        smoke_path = str(payload.get("smoke_record_path") or "")
        row = {
            "manifest_path": _safe_rel(repo_root, manifest),
            "smoke_record_path": _safe_rel(repo_root, smoke_path),
        }
        for key in ("detector_path", "legacy_detector_path"):
            value = _safe_rel(repo_root, payload.get(key) or "")
            if value:
                row[key] = value
        out.append(row)
        if len(out) >= MAX_REFS:
            break
    return out


def _focused_test_refs(repo_root: Path, argument: str, detector_id: str) -> list[str]:
    refs: list[str] = []
    tests_root = repo_root / "tools" / "tests"
    if not tests_root.is_dir():
        return refs
    needles = [needle for needle in (argument, detector_id) if needle]
    for path in sorted(tests_root.rglob("test_*.py")):
        if path.name in {
            "test_detector_provenance_v2.py",
            "test_vault_mcp_server_detector_provenance.py",
        }:
            continue
        text = _read(path)
        if not text:
            continue
        lines: list[int] = []
        for needle in needles:
            for m in re.finditer(re.escape(needle), text):
                line = text[: m.start()].count("\n") + 1
                lines.append(line)
                if len(lines) >= 2:
                    break
            if len(lines) >= 2:
                break
        if not lines:
            continue
        for line in sorted(set(lines)):
            refs.append(f"{_safe_rel(repo_root, path)}:{line}")
            if len(refs) >= MAX_REFS:
                return refs
    return refs


def _source_refs(repo_root: Path, generated_from: str, wiki: str) -> list[str]:
    refs: list[str] = []
    if generated_from:
        refs.append(_safe_rel(repo_root, generated_from))
    if wiki:
        refs.append(wiki)
    return refs[:MAX_REFS]


def _merge_refs(*groups: list[str]) -> list[str]:
    out: list[str] = []
    for group in groups:
        for ref in group:
            if ref not in out:
                out.append(ref)
                if len(out) >= MAX_REFS:
                    return out
    return out


def _literal_str(node: ast.AST | None) -> str:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return ""


def _python_func_meta(tree: ast.Module | None, name: str) -> tuple[int, str]:
    if tree is None:
        return 0, ""
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return int(getattr(node, "lineno", 0) or 0), ast.get_docstring(node) or ""
    return 0, ""


def _module_str_dict(
    tree: ast.Module | None, assign_name: str
) -> dict[str, tuple[str, int]]:
    out: dict[str, tuple[str, int]] = {}
    if tree is None:
        return out
    for node in tree.body:
        value_node: ast.AST | None = None
        if isinstance(node, ast.Assign):
            if not any(isinstance(target, ast.Name) and target.id == assign_name for target in node.targets):
                continue
            value_node = node.value
        elif isinstance(node, ast.AnnAssign):
            if not isinstance(node.target, ast.Name) or node.target.id != assign_name:
                continue
            value_node = node.value
        else:
            continue
        if not isinstance(value_node, ast.Dict):
            continue
        for key_node, item_value_node in zip(value_node.keys, value_node.values):
            key = _literal_str(key_node)
            value = _literal_str(item_value_node)
            if key and value:
                out[key] = (value, int(getattr(key_node, "lineno", node.lineno) or 0))
        break
    return out


def _rust_runner_native_dispatch(tree: ast.Module | None) -> dict[str, tuple[str, int]]:
    out: dict[str, tuple[str, int]] = {}
    if tree is None:
        return out
    for node in tree.body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) or node.name != "scan_workspace":
            continue
        for stmt in node.body:
            value_node: ast.AST | None = None
            if isinstance(stmt, ast.Assign):
                if not any(isinstance(target, ast.Name) and target.id == "pattern_results" for target in stmt.targets):
                    continue
                value_node = stmt.value
            elif isinstance(stmt, ast.AnnAssign):
                if not isinstance(stmt.target, ast.Name) or stmt.target.id != "pattern_results":
                    continue
                value_node = stmt.value
            else:
                continue
            if not isinstance(value_node, ast.Dict):
                continue
            for key_node, item_value_node in zip(value_node.keys, value_node.values):
                key = _literal_str(key_node)
                if not key or not isinstance(item_value_node, ast.Call):
                    continue
                callee = ""
                if isinstance(item_value_node.func, ast.Name):
                    callee = item_value_node.func.id
                elif isinstance(item_value_node.func, ast.Attribute):
                    callee = item_value_node.func.attr
                if callee:
                    out[key] = (callee, int(getattr(key_node, "lineno", stmt.lineno) or 0))
            break
        break
    return out


def _module_constant(tree: ast.Module | None, name: str) -> str:
    if tree is None:
        return ""
    for node in tree.body:
        value_node: ast.AST | None = None
        if isinstance(node, ast.Assign):
            if not any(isinstance(target, ast.Name) and target.id == name for target in node.targets):
                continue
            value_node = node.value
        elif isinstance(node, ast.AnnAssign):
            if not isinstance(node.target, ast.Name) or node.target.id != name:
                continue
            value_node = node.value
        else:
            continue
        value = _literal_str(value_node)
        if value:
            return value
    return ""


def _rust_wave2_index(
    repo_root: Path,
) -> dict[str, dict[str, str | int]]:
    wave2_root = repo_root / "detectors" / "rust_wave2"
    out: dict[str, dict[str, str | int]] = {}
    if not wave2_root.is_dir():
        return out
    for path in sorted(wave2_root.glob("*.py")):
        tree = _load_ast(path)
        if tree is None:
            continue
        raw_id = _module_constant(tree, "DETECTOR_ID")
        def_line, _ = _python_func_meta(tree, "scan")
        out[path.stem] = {
            "module_name": path.stem,
            "raw_detector_id": raw_id,
            "detector_path": _safe_rel(repo_root, path),
            "def_line": def_line,
            "docstring": ast.get_docstring(tree) or "",
        }
    return out


def _hash_payload(payload: dict[str, Any]) -> dict[str, Any]:
    digest = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()[:16]
    payload["context_pack_hash"] = f"sha256:{digest}"
    return payload


def _build_rust_payload(
    repo_root: Path,
    detector_id: str,
    canonical_detector_id: str,
    resolution_kind: str,
    detector_path: str,
    runner_path: str,
    callee: str,
    dispatch_line: int,
    def_line: int,
    docstring: str,
    standalone_detector_id: str,
    focused_needles: list[str],
) -> dict[str, Any]:
    source_refs = _merge_refs(
        [ref for ref in (detector_path, runner_path) if ref],
    )
    focused_tests = _merge_refs(
        _focused_test_refs(repo_root, "", canonical_detector_id),
        *[
            _focused_test_refs(repo_root, needle, standalone_detector_id)
            for needle in focused_needles
            if needle
        ],
    )
    payload: dict[str, Any] = {
        "schema": SCHEMA_RUST,
        "kind": "detector_provenance_v2",
        "backend": "rust",
        "detector_id": detector_id,
        "canonical_detector_id": canonical_detector_id,
        "resolution_kind": resolution_kind,
        "detector_path": detector_path,
        "runner_path": runner_path,
        "callee": callee,
        "dispatch_line": dispatch_line,
        "def_line": def_line,
        "docstring": docstring,
        "standalone_detector_id": standalone_detector_id,
        "focused_test_refs": focused_tests[:MAX_REFS],
        "advisory_boundary": ADVISORY_BOUNDARY,
        "source_refs": source_refs[:MAX_REFS],
    }
    return _hash_payload(payload)


def _resolve_rust(repo_root: Path, detector_id: str) -> dict[str, Any] | None:
    runner_path = repo_root / "tools" / "rust-detector-runner.py"
    runner_rel = _safe_rel(repo_root, runner_path)
    runner_tree = _load_ast(runner_path)
    native_dispatch = _rust_runner_native_dispatch(runner_tree)
    wave2_dispatch = _module_str_dict(runner_tree, "_WAVE2_DETECTORS")
    wave2_index = _rust_wave2_index(repo_root)

    if detector_id in native_dispatch:
        callee, dispatch_line = native_dispatch[detector_id]
        def_line, docstring = _python_func_meta(runner_tree, callee)
        return _build_rust_payload(
            repo_root=repo_root,
            detector_id=detector_id,
            canonical_detector_id=detector_id,
            resolution_kind="runner_native",
            detector_path=runner_rel,
            runner_path=runner_rel,
            callee=callee,
            dispatch_line=dispatch_line,
            def_line=def_line,
            docstring=docstring,
            standalone_detector_id="",
            focused_needles=[detector_id, callee],
        )

    module_name = ""
    canonical_detector_id = ""
    dispatch_line = 0
    if detector_id in wave2_dispatch:
        module_name, dispatch_line = wave2_dispatch[detector_id]
        canonical_detector_id = detector_id
    else:
        for canonical_id, (candidate_module, candidate_line) in sorted(wave2_dispatch.items()):
            entry = wave2_index.get(candidate_module, {})
            raw_id = str(entry.get("raw_detector_id") or "")
            if detector_id in {candidate_module, raw_id}:
                module_name = candidate_module
                canonical_detector_id = canonical_id
                dispatch_line = candidate_line
                break
    if not module_name:
        return None

    entry = wave2_index.get(module_name)
    if not entry:
        return None
    raw_detector_id = str(entry.get("raw_detector_id") or "")
    return _build_rust_payload(
        repo_root=repo_root,
        detector_id=detector_id,
        canonical_detector_id=canonical_detector_id or detector_id,
        resolution_kind="wave2_standalone",
        detector_path=str(entry.get("detector_path") or ""),
        runner_path=runner_rel,
        callee="scan",
        dispatch_line=dispatch_line,
        def_line=int(entry.get("def_line") or 0),
        docstring=str(entry.get("docstring") or ""),
        standalone_detector_id=raw_detector_id,
        focused_needles=[
            canonical_detector_id or detector_id,
            raw_detector_id or module_name,
        ],
    )


def resolve(repo_root: Path, detector_id: str) -> dict[str, Any]:
    rust_out = _resolve_rust(repo_root, detector_id)
    if rust_out is not None:
        return rust_out
    detector_path = _find_detector_by_id(repo_root, detector_id)
    if detector_path is None:
        return {
            "schema": SCHEMA_SOLIDITY,
            "error": "not_found",
            "detector_id": detector_id,
        }
    text = _read(detector_path)
    argument = _extract_argument(text)
    generated_from = _extract_generated_from(text)
    wiki = _extract_wiki(text)
    if not _is_solidity_detector(detector_path, text):
        return {
            "schema": SCHEMA_SOLIDITY,
            "error": "unsupported_backend",
            "detector_id": detector_id,
            "backend": "non_solidity",
        }
    manifests = _discover_manifests(repo_root, argument or detector_id)
    focused_tests = _focused_test_refs(repo_root, argument, detector_id)
    source_refs = _source_refs(repo_root, generated_from, wiki)
    payload: dict[str, Any] = {
        "schema": SCHEMA_SOLIDITY,
        "kind": "detector_provenance_v2",
        "backend": "solidity",
        "detector_id": detector_id,
        "detector_path": _safe_rel(repo_root, detector_path),
        "argument": argument,
        "generated_from_dsl_path": _safe_rel(repo_root, generated_from),
        "wiki": wiki,
        "fixture_manifests": manifests,
        "focused_test_refs": focused_tests,
        "advisory_boundary": ADVISORY_BOUNDARY,
        "source_refs": source_refs,
    }
    return _hash_payload(payload)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", default=".", help="Repository root path")
    parser.add_argument("--detector-id", required=True, help="Detector id or ARGUMENT")
    args = parser.parse_args()
    repo_root = Path(args.repo_root).resolve()
    out = resolve(repo_root, args.detector_id.strip())
    print(json.dumps(out, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
