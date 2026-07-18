#!/usr/bin/env python3
"""cargo-crate-resolver.py — Walk a file path upward to resolve its Cargo crate name.

Part of Wave O-A Gap #1/#6 fix: replaces path-substring regex heuristics in
upstream-equivalent-gate.py Step 3 with a principled Cargo-crate-name resolver.

Public API
----------
resolve_crate_name(file_path, workspace_root=None) -> Optional[str]
    Walk upward from file_path until a Cargo.toml with a [package] block is found.
    Return the ``name`` field, or None.

find_workspace_root_and_crate(file_path) -> tuple[Path, str] | None
    Walk upward finding both the nearest [package] Cargo.toml (gives crate name)
    and the highest-level [workspace] Cargo.toml (gives workspace root).
    Return (workspace_root, crate_name), or None if not found.

stdlib-only. Uses tomllib (Python 3.11+) with a tiny regex fallback.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# TOML parsing — stdlib tomllib (Python 3.11+) with regex fallback
# ---------------------------------------------------------------------------

def _parse_package_name(toml_text: str) -> Optional[str]:
    """Extract [package] name = "..." from TOML text.

    Uses tomllib when available; falls back to regex for Python < 3.11.
    The regex fallback only needs to handle the ``name`` field under
    ``[package]``, which is always a simple quoted string in real Cargo.toml.
    """
    if sys.version_info >= (3, 11):
        import tomllib  # type: ignore[import]
        try:
            data = tomllib.loads(toml_text)
        except Exception:
            return None
        pkg = data.get("package")
        if isinstance(pkg, dict):
            name = pkg.get("name")
            if isinstance(name, str):
                return name
        return None
    else:
        # Regex fallback: find [package] section then name = "..."
        # Match [package] (possibly with trailing spaces), then scan for name =
        pkg_match = re.search(r"^\[package\]\s*$", toml_text, re.MULTILINE)
        if not pkg_match:
            return None
        after = toml_text[pkg_match.end():]
        # Stop at next section header
        next_section = re.search(r"^\[", after, re.MULTILINE)
        section_text = after[: next_section.start()] if next_section else after
        name_match = re.search(
            r"""^name\s*=\s*["']([^"']+)["']""", section_text, re.MULTILINE
        )
        return name_match.group(1) if name_match else None


def _has_workspace(toml_text: str) -> bool:
    """Return True if this Cargo.toml contains a [workspace] table."""
    if sys.version_info >= (3, 11):
        import tomllib  # type: ignore[import]
        try:
            data = tomllib.loads(toml_text)
        except Exception:
            return False
        return "workspace" in data
    else:
        return bool(re.search(r"^\[workspace\]", toml_text, re.MULTILINE))


# ---------------------------------------------------------------------------
# Core resolver
# ---------------------------------------------------------------------------

def resolve_crate_name(
    file_path: Path,
    workspace_root: Optional[Path] = None,
) -> Optional[str]:
    """Walk upward from ``file_path`` to find the nearest Cargo.toml [package].

    Parameters
    ----------
    file_path:
        Absolute (or relative) path to the source file. May or may not exist on disk —
        we walk the directory tree upward regardless.
    workspace_root:
        Optional upper boundary.  The walk stops here (inclusive).  If None, walk
        until the filesystem root.

    Returns
    -------
    The ``name`` field from ``[package]``, or ``None`` if not found.
    """
    file_path = Path(file_path).resolve()
    # Start from the directory containing the file (or the path itself if dir)
    if file_path.is_file():
        current = file_path.parent
    else:
        current = file_path

    stop_at = Path(workspace_root).resolve() if workspace_root else None

    while True:
        cargo_toml = current / "Cargo.toml"
        if cargo_toml.is_file():
            try:
                text = cargo_toml.read_text(encoding="utf-8", errors="replace")
            except OSError:
                text = ""
            name = _parse_package_name(text)
            if name is not None:
                return name
        # Boundary check
        if stop_at and current == stop_at:
            break
        parent = current.parent
        if parent == current:
            break  # filesystem root
        current = parent

    return None


def find_workspace_root_and_crate(
    file_path: Path,
) -> Optional[tuple[Path, str]]:
    """Find (workspace_root, crate_name) for a file.

    The crate_name comes from the nearest [package] Cargo.toml upward.
    The workspace_root comes from the nearest [workspace] Cargo.toml upward
    from that package manifest (or the package manifest itself if it contains
    [workspace]).

    Returns None if no [package] block is found at all.
    """
    file_path = Path(file_path).resolve()
    if file_path.is_file():
        current = file_path.parent
    else:
        current = file_path

    # Phase 1: find nearest [package] Cargo.toml
    package_dir: Optional[Path] = None
    crate_name: Optional[str] = None

    probe = current
    while True:
        cargo_toml = probe / "Cargo.toml"
        if cargo_toml.is_file():
            try:
                text = cargo_toml.read_text(encoding="utf-8", errors="replace")
            except OSError:
                text = ""
            name = _parse_package_name(text)
            if name is not None:
                package_dir = probe
                crate_name = name
                break
        parent = probe.parent
        if parent == probe:
            break
        probe = parent

    if package_dir is None or crate_name is None:
        return None

    # Phase 2: walk upward from package_dir looking for [workspace]
    workspace_root: Path = package_dir  # fallback: package dir is the workspace root
    probe = package_dir
    while True:
        cargo_toml = probe / "Cargo.toml"
        if cargo_toml.is_file():
            try:
                text = cargo_toml.read_text(encoding="utf-8", errors="replace")
            except OSError:
                text = ""
            if _has_workspace(text):
                workspace_root = probe
                break
        parent = probe.parent
        if parent == probe:
            break
        probe = parent

    return workspace_root, crate_name


# ---------------------------------------------------------------------------
# CLI (diagnostic)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("usage: cargo-crate-resolver.py <file_path> [workspace_root]", file=sys.stderr)
        sys.exit(1)

    path = Path(sys.argv[1])
    ws = Path(sys.argv[2]) if len(sys.argv) > 2 else None
    name = resolve_crate_name(path, ws)
    if name:
        print(name)
    else:
        print("(none)", file=sys.stderr)
        sys.exit(1)
