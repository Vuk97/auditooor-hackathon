"""Helpers for resolving declared project source roots.

Workspace-local ``.auditooor/project_source_roots.json`` is operator intent;
``.auditooor/project_source_root_readiness.json`` is the validated form. These
helpers prefer readiness when present and fall back to historical scan roots
only when no declared Rust/DLT root exists.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Iterable


def _load_json(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def _rel_to_workspace(workspace: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(workspace.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def _looks_like_rust_root(path: Path, meta: dict | None = None) -> bool:
    meta = meta or {}
    language_presence = meta.get("language_presence")
    if isinstance(language_presence, dict) and int(language_presence.get("rust") or 0) > 0:
        return True
    if int(meta.get("rust_files") or 0) > 0:
        return True
    return (path / "Cargo.toml").exists() or (path / "crates").is_dir()


def _slugify(value: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", value.strip()).strip(".-_").lower()
    return slug or "rust-root"


def _artifact_slug(path: Path, row: dict) -> str:
    """Return a stable artifact suffix for a declared Rust root.

    Prefer the concrete source checkout basename because labels can be broad
    ("base-rc28") while the path often carries the exact cleanliness/pin hint
    ("base-rc28-clean").  For Base checkouts, strip the redundant leading
    "base-" so artifacts read as `*.rc28-clean.json`.
    """
    raw = path.name or str(row.get("label") or row.get("declared_path") or row.get("path") or "")
    slug = _slugify(raw)
    if slug.startswith("base-") and len(slug) > len("base-"):
        slug = slug[len("base-") :]
    return slug


def declared_rust_project_root_specs(workspace: Path) -> list[dict[str, str]]:
    """Return validated Rust/DLT root specs, readiness first.

    Each row contains workspace-relative ``path``, absolute ``resolved_path``,
    source-root ``label`` when present, and ``artifact_slug`` for named graph
    outputs.  The old ``declared_rust_project_roots`` API remains as a thin
    compatibility wrapper over this richer form.
    """
    workspace = workspace.expanduser().resolve()
    out: list[dict[str, str]] = []
    seen: set[str] = set()

    readiness = _load_json(workspace / ".auditooor" / "project_source_root_readiness.json")
    roots = readiness.get("roots") if isinstance(readiness.get("roots"), list) else []
    for row in roots:
        if not isinstance(row, dict):
            continue
        if row.get("rejection_reasons"):
            continue
        raw = row.get("resolved_path") or row.get("declared_path")
        if not raw:
            continue
        path = Path(str(raw))
        if not path.is_absolute():
            path = workspace / path
        if not path.exists() or not _looks_like_rust_root(path, row):
            continue
        rel = _rel_to_workspace(workspace, path)
        if rel not in seen:
            seen.add(rel)
            out.append({
                "path": rel,
                "resolved_path": str(path.resolve()),
                "label": str(row.get("label") or ""),
                "artifact_slug": _artifact_slug(path, row),
            })

    if out:
        return out

    manifest = _load_json(workspace / ".auditooor" / "project_source_roots.json")
    roots = manifest.get("roots") if isinstance(manifest.get("roots"), list) else []
    for row in roots:
        if not isinstance(row, dict):
            continue
        raw = row.get("path")
        if not raw:
            continue
        path = workspace / str(raw)
        if not path.exists() or not _looks_like_rust_root(path, row):
            continue
        rel = _rel_to_workspace(workspace, path)
        if rel not in seen:
            seen.add(rel)
            out.append({
                "path": rel,
                "resolved_path": str(path.resolve()),
                "label": str(row.get("label") or ""),
                "artifact_slug": _artifact_slug(path, row),
            })
    return out


def declared_rust_project_roots(workspace: Path) -> list[str]:
    """Return workspace-relative declared Rust/DLT roots, readiness first."""
    return [row["path"] for row in declared_rust_project_root_specs(workspace)]


def rust_crate_scan_roots(workspace: Path, fallback: Iterable[str]) -> list[str]:
    """Return declared crate roots, falling back to historical defaults."""
    roots: list[str] = []
    seen: set[str] = set()
    for rel in declared_rust_project_roots(workspace):
        base = workspace / rel
        crate_rel = f"{rel}/crates" if (base / "crates").is_dir() else rel
        if crate_rel not in seen:
            seen.add(crate_rel)
            roots.append(crate_rel)
    if roots:
        return roots
    return list(fallback)


def rust_subdir_scan_roots(
    workspace: Path,
    subdirs: Iterable[str],
    fallback: Iterable[str],
) -> list[str]:
    """Return declared Rust roots plus existing subdirs, or fallback defaults."""
    roots: list[str] = []
    seen: set[str] = set()
    for rel in declared_rust_project_roots(workspace):
        for subdir in subdirs:
            candidate = f"{rel}/{subdir}".rstrip("/")
            if (workspace / candidate).is_dir() and candidate not in seen:
                seen.add(candidate)
                roots.append(candidate)
    if roots:
        return roots
    return list(fallback)
