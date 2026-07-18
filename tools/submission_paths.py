#!/usr/bin/env python3
"""Helpers for resolving workspace submission ledgers."""

from __future__ import annotations

from pathlib import Path


def nested_submission_file(ws: Path) -> Path:
    return ws / "submissions" / "SUBMISSIONS.md"


def root_submission_file(ws: Path) -> Path:
    return ws / "SUBMISSIONS.md"


def find_submission_file(ws: Path) -> Path | None:
    """Return the active workspace submission ledger path if one exists."""
    nested = nested_submission_file(ws)
    if nested.exists():
        return nested
    root = root_submission_file(ws)
    if root.exists():
        return root
    return None


def submission_file_location(ws: Path) -> str:
    """Describe the current tracker layout for user-facing logs."""
    found = find_submission_file(ws)
    if found is None:
        return "missing"
    if found == nested_submission_file(ws):
        return "nested"
    return "root"
