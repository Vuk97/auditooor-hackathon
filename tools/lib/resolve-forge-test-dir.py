#!/usr/bin/env python3
"""Resolve the Foundry test directory for a workspace.

Reads <workspace>/foundry.toml (or the shallowest non-lib foundry.toml under
src/ if none at root) and returns the active profile's `test` value.
Defaults to `test` when the file is missing or the key is absent.

Stdout: the test directory name (no trailing slash).
"""
from __future__ import annotations

import os
import re
import sys
from pathlib import Path


def _find_foundry_toml(ws: Path) -> Path | None:
    root = ws / "foundry.toml"
    if root.is_file():
        return root
    src = ws / "src"
    if src.is_dir():
        for cand in sorted(src.rglob("foundry.toml")):
            if cand.is_file() and cand.parent.name != "lib":
                return cand
    return None


def _parse_with_tomllib(path: Path) -> str | None:
    try:
        import tomllib
    except Exception:
        return None
    try:
        with path.open("rb") as f:
            data = tomllib.load(f)
    except Exception:
        return None

    active = os.environ.get("FOUNDRY_PROFILE", "default")

    # Profile-scoped key
    profiles = data.get("profile", {})
    if isinstance(profiles, dict):
        profile_data = profiles.get(active, {})
        if isinstance(profile_data, dict) and "test" in profile_data:
            return str(profile_data["test"])
        # Fall back to any profile that has the key
        for _, pdat in profiles.items():
            if isinstance(pdat, dict) and "test" in pdat:
                return str(pdat["test"])

    # Top-level key
    if "test" in data:
        return str(data["test"])

    return None


def _parse_with_regex(path: Path) -> str | None:
    try:
        text = path.read_text()
    except Exception:
        return None

    # Look for test = "value" anywhere in the file.
    # This is intentionally permissive because Foundry TOML is small.
    m = re.search(r'^\s*test\s*=\s*"([^"]+)"', text, re.MULTILINE)
    if m:
        return m.group(1)
    return None


def resolve(ws: str) -> str:
    ws_path = Path(ws)
    foundry = _find_foundry_toml(ws_path)
    if not foundry:
        return "test"

    val = _parse_with_tomllib(foundry)
    if val is None:
        val = _parse_with_regex(foundry)
    if val is None:
        return "test"
    return val.strip().rstrip("/")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("test")
        sys.exit(0)
    print(resolve(sys.argv[1]))
