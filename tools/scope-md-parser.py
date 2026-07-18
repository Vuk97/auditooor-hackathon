#!/usr/bin/env python3
"""scope-md-parser.py — Structured SCOPE.md section parser.

Part of Wave O-A Gap #6 fix: replaces unstructured substring-grep of SCOPE.md
with a section-aware parser that understands ## In scope / ## Out of scope blocks
and extracts "Base modifications to <X> are in-scope (core <X> is OOS)" rules.

Public API
----------
parse_scope_md(scope_md_path) -> ScopeManifest
    Parse a SCOPE.md file into structured form.

is_path_in_scope(rel_path, manifest, crate_name=None) -> tuple[bool, str]
    Decide whether a path is in-scope.  Returns (in_scope, reason).

stdlib-only.
"""
from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclass
class ModRule:
    """A 'Base modifications to <upstream> are in-scope' clause.

    E.g.: upstream_crate = "op-succinct", fork_prefix = "base-"
    A crate named ``base-succinct-*`` (starts with fork_prefix and contains
    a stem of upstream_crate) is in-scope via this rule.
    """
    upstream_crate: str   # e.g. "op-succinct"
    fork_prefix: str      # e.g. "base-"

    def matches_crate_name(self, crate_name: str) -> bool:
        """Return True if crate_name looks like a Base-fork of upstream_crate."""
        name = crate_name.lower()
        # Must start with the fork_prefix
        if not name.startswith(self.fork_prefix.lower()):
            return False
        # Must contain a meaningful stem from the upstream crate name.
        # We extract alphabetic tokens from upstream_crate and require at least
        # one to appear in the remainder.
        remainder = name[len(self.fork_prefix):]
        upstream_tokens = re.findall(r"[a-z0-9]+", self.upstream_crate.lower())
        # The fork crate name should contain at least one non-trivial token from
        # the upstream crate (excluding generic words like "core", "lib", "utils")
        skip = {"core", "lib", "the", "and", "of"}
        for tok in upstream_tokens:
            if tok in skip or len(tok) < 3:
                continue
            if tok in remainder:
                return True
        return False


@dataclass
class ScopeManifest:
    """Structured representation of SCOPE.md scope declarations."""
    in_scope_paths: list[str] = field(default_factory=list)
    oos_paths: list[str] = field(default_factory=list)
    oos_clauses: list[str] = field(default_factory=list)     # raw OOS bullet text
    modification_rules: list[ModRule] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

# Headers we recognise as "In scope" sections.
_IN_SCOPE_HEADER_RE = re.compile(
    r"in.?scope|in scope",
    re.IGNORECASE,
)
# Headers we recognise as "Out of scope" sections.
_OOS_HEADER_RE = re.compile(
    r"out.of.scope|oos|excluded|not.in.scope",
    re.IGNORECASE,
)

# Modification rule patterns, e.g.:
#   "Base modifications to Op-Succinct are in-scope"
#   "Base modifications to **Op-Succinct** are in-scope (core Op-Succinct is OOS)"
_MOD_RULE_RE = re.compile(
    r"base\s+modifications?\s+to\s+\*{0,2}([A-Za-z0-9_\-]+)\*{0,2}\s+are\s+in.scope",
    re.IGNORECASE,
)

# Path-like token: backtick-wrapped or looks like crates/ or github/ etc.
_BACKTICK_PATH_RE = re.compile(r"`([^`]+)`")
# Bullets: dash/star AND numbered lists (1. 2) etc.) - an enumerated in-scope
# target list ("1. tranches/Tranche.sol") is a common Immunefi SCOPE.md shape and
# was previously dropped (Strata 2026-06-30: 13 numbered in-scope targets parsed to
# zero in_scope_paths -> whole-repo bleed).
_BULLET_RE = re.compile(r"^\s*(?:[-*]|\d+[.)])\s+")


def _extract_path_tokens(line: str) -> list[str]:
    """Extract path-like strings from a bullet line."""
    tokens = []
    # Backtick-wrapped paths
    for m in _BACKTICK_PATH_RE.finditer(line):
        tokens.append(m.group(1))
    # Bare path-like tokens (contain / or -)
    for tok in re.findall(r"[a-zA-Z0-9][a-zA-Z0-9_\-/]+", line):
        if ("/" in tok or "-" in tok) and len(tok) >= 5:
            tokens.append(tok)
    return tokens


def parse_scope_md(scope_md_path: Path) -> ScopeManifest:
    """Parse SCOPE.md into a ScopeManifest.

    Handles:
    - ``## In scope`` / ``## In-scope`` / ``## In Scope`` headers (case-insensitive)
    - ``## Out of scope`` / ``## Out-of-scope`` / ``## OOS`` headers
    - Bullet lists under each header
    - "Base modifications to <X> are in-scope" clauses anywhere in the file
    """
    manifest = ScopeManifest()
    if not scope_md_path.is_file():
        return manifest

    text = scope_md_path.read_text(encoding="utf-8", errors="replace")

    # First pass: extract modification rules from the entire document.
    for m in _MOD_RULE_RE.finditer(text):
        upstream = m.group(1).lower()
        # Normalise: "Op-Succinct" → "op-succinct"
        manifest.modification_rules.append(
            ModRule(upstream_crate=upstream, fork_prefix="base-")
        )

    # Second pass: section-aware parsing.
    # We track which section we're in and collect bullet lines.
    section: Optional[str] = None  # "in_scope" | "oos" | None

    for line in text.splitlines():
        stripped = line.strip()

        # Check for a markdown header.
        # Only ## (and # ) level headers change the active section;
        # deeper sub-headings (###, ####, …) are treated as sub-sections
        # that stay within the current section.
        hdr = re.match(r"^(#{1,6})\s+(.+)$", stripped)
        if hdr:
            level = len(hdr.group(1))
            title = hdr.group(2)
            if level <= 2:
                # Top-level section change
                if _IN_SCOPE_HEADER_RE.search(title) and not _OOS_HEADER_RE.search(title):
                    section = "in_scope"
                elif _OOS_HEADER_RE.search(title):
                    section = "oos"
                else:
                    section = None
            # Sub-headings (level >= 3) do not reset section
            continue

        # Blank line — stay in section (sub-headers and blank lines in lists
        # shouldn't reset the active section)
        if not stripped:
            continue

        if section == "in_scope" and _BULLET_RE.match(stripped):
            for tok in _extract_path_tokens(stripped):
                if tok not in manifest.in_scope_paths:
                    manifest.in_scope_paths.append(tok)

        elif section == "oos":
            if _BULLET_RE.match(stripped):
                manifest.oos_clauses.append(stripped)
                for tok in _extract_path_tokens(stripped):
                    if tok not in manifest.oos_paths:
                        manifest.oos_paths.append(tok)

    return manifest


# ---------------------------------------------------------------------------
# Decision function
# ---------------------------------------------------------------------------

def is_path_in_scope(
    rel_path: str,
    manifest: ScopeManifest,
    crate_name: Optional[str] = None,
) -> tuple[bool, str]:
    """Decide whether ``rel_path`` is in-scope.

    Decision tree (in priority order):
    1. If ``crate_name`` is provided AND matches a modification_rule
       (fork_prefix + upstream_crate shape) → IN_SCOPE via modifications clause.
    2. Else if rel_path matches any OOS path token (path-prefix or substring) → OOS.
    3. Else if rel_path matches any in-scope path token → IN_SCOPE.
    4. Else → IN_SCOPE_DEFAULT (advisory; no explicit clause).

    Returns
    -------
    (in_scope: bool, reason: str)
    """
    pp_lower = rel_path.lower()

    # Step 1: modification rules (highest priority — explicitly in-scope forks)
    if crate_name:
        for rule in manifest.modification_rules:
            if rule.matches_crate_name(crate_name):
                return (
                    True,
                    f"in_scope_via_modification_rule: crate '{crate_name}' is "
                    f"a Base fork of upstream '{rule.upstream_crate}' "
                    f"(SCOPE.md 'Base modifications to {rule.upstream_crate} are in-scope')",
                )

    # Step 2: OOS check — any OOS token present as a path-prefix, substring, or
    # (when the token contains a glob wildcard) a glob match.
    for oos_tok in manifest.oos_paths:
        tok = oos_tok.lower().rstrip("/")
        if not tok or len(tok) < 4:
            continue
        if "*" in tok:
            if fnmatch.fnmatch(pp_lower, tok):
                return False, f"oos_via_scope_md_oos_token: '{oos_tok}' glob-matches path"
            continue
        # Match as path-prefix or path segment
        if tok in pp_lower:
            return False, f"oos_via_scope_md_oos_token: '{oos_tok}' found in path"

    # Step 3: in-scope token check. A token containing a glob wildcard (``*``,
    # e.g. ``src/**/*.sol``) is matched with fnmatch instead of a literal
    # substring test - a literal substring test can never match a glob shape
    # (the ``*`` characters never appear verbatim in a real path), which would
    # silently empty the entire in-scope allowlist for any SCOPE.md that uses
    # glob-shaped in-scope tokens.
    for in_tok in manifest.in_scope_paths:
        tok = in_tok.lower().rstrip("/")
        if not tok or len(tok) < 4:
            continue
        if "*" in tok:
            if fnmatch.fnmatch(pp_lower, tok):
                return True, f"in_scope_via_scope_md_in_scope_token: '{in_tok}' glob-matches path"
            continue
        if tok in pp_lower:
            return True, f"in_scope_via_scope_md_in_scope_token: '{in_tok}' matches path"

    # Step 4: default. When SCOPE.md declared an EXPLICIT in-scope allowlist
    # (in_scope_paths non-empty), a path matching NONE of those tokens is OUT of
    # scope: an enumerated Immunefi scope ("exactly these N targets, nothing else")
    # means anything not enumerated is OOS. Strata 2026-06-30: a 13-target allowlist
    # leaked 46 OOS files (Strategy=149 units, DiscreteAccounting, lens/, swap/) into
    # the worklist because the default was in-scope. If NO allowlist was declared
    # (in_scope_paths empty = "whole repo in scope" doc), keep the advisory in-scope
    # default so existing whole-repo workspaces are unchanged.
    if manifest.in_scope_paths:
        return (
            False,
            "oos_via_allowlist: path matches no SCOPE.md enumerated in-scope token "
            "(enumerated-allowlist scope: only listed targets are in scope)",
        )
    return True, "in_scope_default: no explicit clause matched (advisory)"


# ---------------------------------------------------------------------------
# CLI (diagnostic)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 3:
        print(
            "usage: scope-md-parser.py <SCOPE.md> <rel_path> [crate_name]",
            file=sys.stderr,
        )
        sys.exit(1)

    scope_path = Path(sys.argv[1])
    rel_path = sys.argv[2]
    crate = sys.argv[3] if len(sys.argv) > 3 else None

    mf = parse_scope_md(scope_path)
    in_scope, reason = is_path_in_scope(rel_path, mf, crate)
    print(f"in_scope={in_scope}  reason={reason}")
    print(f"  modification_rules: {mf.modification_rules}")
    print(f"  in_scope_paths[:10]: {mf.in_scope_paths[:10]}")
    print(f"  oos_paths[:10]: {mf.oos_paths[:10]}")
