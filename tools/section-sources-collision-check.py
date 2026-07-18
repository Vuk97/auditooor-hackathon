#!/usr/bin/env python3
"""section-sources-collision-check.py — Guard that detects SECTION_SOURCES collisions.

Reads tools/obsidian-vault-sync.py SECTION_SOURCES (via AST parse, no import side-effects)
and compares against the canonical layer registrations in docs/section_sources_known_layers.json
(established by PRs #622-625 / #629 / #631 for §M_ARCH L1-L4 memory layers).

Two collision rules:
  1. Slug collision: SECTION_SOURCES has slug X → path-set P1, known_layers has slug X →
     path-set P2, and P1 != P2.  Indicates a SECTION_SOURCES edit changed a registered layer.
  2. Path duplication: a NEW slug X (not in known_layers) maps to paths that overlap with
     paths already registered under a different known slug.  Indicates path sharing across
     slugs which causes double-refresh for the same source.

Exit codes:
  0 — clean (no collisions)
  1 — one or more collisions detected (details on stderr)
  2 — tool/parse error (source file missing, malformed AST)

Usage:
    python3 tools/section-sources-collision-check.py
    python3 tools/section-sources-collision-check.py --known-layers docs/section_sources_known_layers.json
    python3 tools/section-sources-collision-check.py --vault-sync tools/obsidian-vault-sync.py
    python3 tools/section-sources-collision-check.py --json        # machine-readable output on stdout
"""
from __future__ import annotations

import ast
import argparse
import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_VAULT_SYNC = REPO_ROOT / "tools" / "obsidian-vault-sync.py"
DEFAULT_KNOWN_LAYERS = REPO_ROOT / "docs" / "section_sources_known_layers.json"

# Placeholder token used in the known_layers JSON to represent AUDITS_ROOT
# (which is a runtime Path that includes the user's home dir).
_AUDITS_ROOT_TOKEN = "AUDITS_ROOT"


def _extract_section_sources(vault_sync_path: Path) -> dict[str, list[str]]:
    """Parse SECTION_SOURCES from vault_sync_path via Python AST.

    Returns a dict mapping slug → list-of-path-strings.
    Raises ValueError on parse failure or if SECTION_SOURCES is not found.
    """
    try:
        source = vault_sync_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"cannot read {vault_sync_path}: {exc}") from exc

    try:
        tree = ast.parse(source, filename=str(vault_sync_path))
    except SyntaxError as exc:
        raise ValueError(f"syntax error in {vault_sync_path}: {exc}") from exc

    # Walk module-level assignments to find: SECTION_SOURCES = { ... }
    # Handles both plain `ast.Assign` and annotated `ast.AnnAssign` forms.
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "SECTION_SOURCES":
                    return _ast_dict_to_py(node.value, source)
        elif isinstance(node, ast.AnnAssign):
            if (
                isinstance(node.target, ast.Name)
                and node.target.id == "SECTION_SOURCES"
                and node.value is not None
            ):
                return _ast_dict_to_py(node.value, source)

    raise ValueError(
        f"SECTION_SOURCES dict assignment not found in {vault_sync_path}"
    )


def _ast_dict_to_py(node: ast.expr, source: str) -> dict[str, list[str]]:
    """Recursively evaluate an ast.Dict node to a plain Python dict."""
    if not isinstance(node, ast.Dict):
        raise ValueError(
            f"SECTION_SOURCES must be a dict literal, got {type(node).__name__}"
        )
    result: dict[str, list[str]] = {}
    for key_node, val_node in zip(node.keys, node.values):
        if key_node is None:
            raise ValueError("SECTION_SOURCES dict cannot use ** unpacking")
        key = ast.literal_eval(key_node)
        if not isinstance(key, str):
            raise ValueError(f"SECTION_SOURCES key must be a str, got {type(key)}")
        # Values are lists of strings, possibly with f-string / Call expressions.
        # We only need the string constant portions for collision detection.
        val = _eval_list(val_node)
        result[key] = val
    return result


def _eval_list(node: ast.expr) -> list[str]:
    """Evaluate a list node to a list of strings; non-literal elements → token."""
    if not isinstance(node, ast.List):
        raise ValueError(f"expected list literal for SECTION_SOURCES value, got {type(node).__name__}")
    items: list[str] = []
    for elt in node.elts:
        try:
            val = ast.literal_eval(elt)
            if isinstance(val, str):
                items.append(val)
            else:
                items.append(repr(val))
        except (ValueError, TypeError):
            # Non-literal (e.g. str(AUDITS_ROOT / "...")) — extract the string literal portion.
            items.append(_extract_string_from_call(elt))
    return items


def _extract_string_from_call(node: ast.expr) -> str:
    """Best-effort: extract a representative string token from complex AST nodes.

    For str(AUDITS_ROOT / "subpath") we want "AUDITS_ROOT/subpath" as a stable token.
    For other patterns we return a generic "<non-literal>" token.
    """
    # Pattern: str(Name / Const) or str(Name / Const / Const ...)
    if isinstance(node, ast.Call) and len(node.args) == 1:
        arg = node.args[0]
        parts = _flatten_div(arg)
        if parts:
            return "/".join(parts)
    # BinOp (rare at top level) — e.g. AUDITS_ROOT / "x" without str() wrapper
    parts = _flatten_div(node)
    if parts:
        return "/".join(parts)
    return "<non-literal>"


def _flatten_div(node: ast.expr) -> list[str] | None:
    """Flatten a chain of BinOp(/, ...) nodes to a list of string tokens."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        # Strip leading/trailing separators
        return [node.value.strip("/")]
    if isinstance(node, ast.Name):
        return [node.id]
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
        left = _flatten_div(node.left)
        right = _flatten_div(node.right)
        if left is not None and right is not None:
            return left + right
    return None


def _normalise_paths(paths: list[str]) -> list[str]:
    """Replace home-dir expansions with stable tokens for comparison.

    The known_layers JSON uses "AUDITS_ROOT" as a token where obsidian-vault-sync.py
    uses `str(AUDITS_ROOT / "...")` which the AST extractor resolves to e.g.
    "AUDITS_ROOT/*/submissions/**/*.md".
    """
    normalised = []
    for p in paths:
        # Our AST extractor already produces "AUDITS_ROOT/..." for str(AUDITS_ROOT / ...)
        # but in case absolute paths from the runtime crept in, normalise them too.
        p2 = re.sub(
            r"^/[^/]+/[^/]+/audits/",
            f"{_AUDITS_ROOT_TOKEN}/",
            p,
        )
        normalised.append(p2)
    return normalised


def _load_known_layers(known_layers_path: Path) -> dict[str, list[str]]:
    """Load and validate the known-layers JSON."""
    try:
        data = json.loads(known_layers_path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValueError(f"cannot read {known_layers_path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"malformed JSON in {known_layers_path}: {exc}") from exc

    if "known_layers" not in data:
        raise ValueError(f"missing 'known_layers' key in {known_layers_path}")
    known: dict[str, list[str]] = {}
    for slug, paths in data["known_layers"].items():
        if not isinstance(paths, list):
            raise ValueError(
                f"known_layers[{slug!r}] must be a list, got {type(paths).__name__}"
            )
        known[slug] = [str(p) for p in paths]
    return known


def check_collisions(
    section_sources: dict[str, list[str]],
    known_layers: dict[str, list[str]],
) -> list[dict]:
    """Return a list of collision records; empty list = clean."""
    collisions: list[dict] = []

    # Normalise all paths for comparison.
    live: dict[str, list[str]] = {
        slug: _normalise_paths(paths)
        for slug, paths in section_sources.items()
    }
    known: dict[str, list[str]] = {
        slug: _normalise_paths(paths)
        for slug, paths in known_layers.items()
    }

    # Rule 1: slug exists in both but path-sets differ.
    for slug in known:
        if slug not in live:
            # Slug was removed — not a collision per spec but worth noting.
            # We keep it as an info; not an error (guard is about NEW edits, not deletions).
            continue
        live_set = set(live[slug])
        known_set = set(known[slug])
        if live_set != known_set:
            added = live_set - known_set
            removed = known_set - live_set
            collisions.append({
                "rule": "slug_path_mismatch",
                "slug": slug,
                "live_paths": sorted(live[slug]),
                "known_paths": sorted(known[slug]),
                "added_paths": sorted(added),
                "removed_paths": sorted(removed),
            })

    # Rule 2: new slug (not in known) whose paths overlap with any known slug's paths.
    all_known_paths: set[str] = set()
    for paths in known.values():
        all_known_paths.update(paths)

    for slug, paths in live.items():
        if slug in known:
            continue  # already checked by Rule 1
        overlap = set(paths) & all_known_paths
        if overlap:
            # Find which known slug owns the overlapping path(s).
            for dup_path in sorted(overlap):
                owning_slugs = [
                    s for s, ps in known.items() if dup_path in set(ps)
                ]
                collisions.append({
                    "rule": "path_duplication",
                    "new_slug": slug,
                    "duplicate_path": dup_path,
                    "also_in_slugs": owning_slugs,
                })

    return collisions


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Check SECTION_SOURCES in obsidian-vault-sync.py for collisions with known §M_ARCH layer registrations."
    )
    parser.add_argument(
        "--vault-sync",
        type=Path,
        default=DEFAULT_VAULT_SYNC,
        help="Path to tools/obsidian-vault-sync.py (default: auto-detected)",
    )
    parser.add_argument(
        "--known-layers",
        type=Path,
        default=DEFAULT_KNOWN_LAYERS,
        help="Path to docs/section_sources_known_layers.json (default: auto-detected)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_out",
        help="Emit machine-readable JSON on stdout",
    )
    args = parser.parse_args(argv)

    # --- Parse SECTION_SOURCES ---
    try:
        section_sources = _extract_section_sources(args.vault_sync)
    except ValueError as exc:
        print(f"[section-sources-collision-check] ERROR: {exc}", file=sys.stderr)
        return 2

    # --- Load known layers ---
    try:
        known_layers = _load_known_layers(args.known_layers)
    except ValueError as exc:
        print(f"[section-sources-collision-check] ERROR: {exc}", file=sys.stderr)
        return 2

    # --- Check ---
    collisions = check_collisions(section_sources, known_layers)

    if args.json_out:
        result = {
            "status": "clean" if not collisions else "collision",
            "section_sources_slugs": sorted(section_sources.keys()),
            "known_layers_slugs": sorted(known_layers.keys()),
            "collisions": collisions,
        }
        print(json.dumps(result, indent=2))

    if not collisions:
        if not args.json_out:
            print("[section-sources-collision-check] OK — no collisions detected")
        return 0

    # Report collisions.
    print(
        f"[section-sources-collision-check] FAIL — {len(collisions)} collision(s) detected:",
        file=sys.stderr,
    )
    for c in collisions:
        if c["rule"] == "slug_path_mismatch":
            print(
                f"  SLUG_MISMATCH  slug={c['slug']!r}"
                f"  added={c['added_paths']}  removed={c['removed_paths']}",
                file=sys.stderr,
            )
        elif c["rule"] == "path_duplication":
            print(
                f"  PATH_DUPE  new_slug={c['new_slug']!r}"
                f"  path={c['duplicate_path']!r}"
                f"  already_in={c['also_in_slugs']}",
                file=sys.stderr,
            )
        else:
            print(f"  UNKNOWN  {c}", file=sys.stderr)
    print(
        "\nFix: update docs/section_sources_known_layers.json to reflect intentional changes,\n"
        "or revert the unintended SECTION_SOURCES edit in tools/obsidian-vault-sync.py.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
