#!/usr/bin/env python3
"""platform-export.py - emit a platform-correct export from a paste_ready .md draft.

RELATED TOOLS:
  tools/hackenproof-plain-export.py  - CANONICAL HackenProof exporter + validator.
      Exports via: --draft <md> --platform hackenproof [--out <txt>] [--json] [--strict]
      Validates via: --validate <txt> [--json] [--strict]
      Owns all HackenProof-specific logic: 4-section structure, markdown stripping,
      PoC-to-zip summarization, internal-label scrub, ASCII normalization, leak checks.
      The 6 operator-filed .hackenproof-plain.txt artifacts all validated ok=true
      through this canonical tool; do NOT introduce a second strip implementation.

  tools/hackenproof-poc-not-inline-check.py  - gate that verifies the produced .txt
      does not re-inline the PoC harness source.

  platform-export.py (THIS FILE) - multi-platform ROUTER.
      Distinct gap vs the tools above: workspace->platform resolution
      (reference/platform_submission_requirements.json + heuristics) and dispatch
      to the right exporter. For HackenProof it DELEGATES entirely to
      hackenproof-plain-export.py rather than reimplementing stripping.
      For markdown-allowed platforms (cantina, immunefi, github-ghsa, generic) it
      performs pass-through validation of required_sections.

Usage:
    python3 tools/platform-export.py <draft.md> [--platform <id>] [--workspace <path>] [--out <path>]

Platform resolution order:
  1. --platform flag (explicit override)
  2. --workspace flag -> resolve_workspace_platform() heuristic
  3. auto-detect from draft path (walk up to find SCOPE.md / SEVERITY.md)
  4. fallback: generic

Behaviours per platform:
  hackenproof  -> DELEGATES to tools/hackenproof-plain-export.py which emits
                  <slug>.hackenproof-plain.txt (4-section ASCII plain text) and
                  <slug>.hackenproof-plain.json sidecar. All markdown stripping,
                  PoC-to-zip summarization, and leak validation is owned there.
  cantina      -> pass-through markdown; validate required_sections present.
  immunefi     -> pass-through markdown; validate required_sections present.
  github-ghsa  -> pass-through markdown; validate required_sections present.
  generic      -> pass-through markdown; validate required_sections present.

Idempotent: re-running on the same draft overwrites the output with the same result.
Dependency-free: stdlib only (no requests, no third-party libs).
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import pathlib
import re
import subprocess
import sys
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# repo layout
# ---------------------------------------------------------------------------

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
REGISTRY_PATH = REPO_ROOT / "reference" / "platform_submission_requirements.json"
DISPATCH_TOOL = REPO_ROOT / "tools" / "dispatch-agent-with-prebriefing.py"
HP_EXPORT_TOOL = REPO_ROOT / "tools" / "hackenproof-plain-export.py"

# ---------------------------------------------------------------------------
# lazy-import resolve_workspace_platform from dispatch tool
# ---------------------------------------------------------------------------

_dispatch_mod: Any = None


def _get_dispatch_mod() -> Any:
    global _dispatch_mod
    if _dispatch_mod is not None:
        return _dispatch_mod
    spec = importlib.util.spec_from_file_location("_dispatch_tool", DISPATCH_TOOL)
    if spec is None or spec.loader is None:
        return None
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)  # type: ignore[attr-defined]
    except Exception:
        return None
    _dispatch_mod = mod
    return mod


def resolve_platform(
    platform_flag: Optional[str],
    workspace_path: Optional[pathlib.Path],
    draft_path: Optional[pathlib.Path],
) -> str:
    """Resolve platform id via the three-step priority chain."""
    if platform_flag:
        return platform_flag.lower().strip()
    # try workspace path
    candidate_ws = workspace_path
    if candidate_ws is None and draft_path is not None:
        # walk up from draft until we find SCOPE.md or SEVERITY.md
        for parent in draft_path.parents:
            if (parent / "SCOPE.md").exists() or (parent / "SEVERITY.md").exists():
                candidate_ws = parent
                break
    if candidate_ws is not None:
        mod = _get_dispatch_mod()
        if mod is not None:
            try:
                return mod.resolve_workspace_platform(candidate_ws)
            except Exception:
                pass
    return "generic"


def load_registry() -> Dict[str, Any]:
    """Load reference/platform_submission_requirements.json; return platforms map."""
    try:
        data = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
        return data.get("platforms") or {}
    except (OSError, ValueError):
        return {}


# ---------------------------------------------------------------------------
# required-section validation (markdown-allowed platforms)
# ---------------------------------------------------------------------------

def validate_required_sections(
    text: str,
    required_sections: List[str],
    platform_id: str,
) -> Tuple[bool, List[str]]:
    """Check that each required section string appears somewhere in text.

    Returns (ok, missing_sections).  Section matches are case-insensitive
    substring checks against the section name (the part before any parenthetical).
    """
    missing: List[str] = []
    for section in required_sections:
        # Extract the base label (before any parenthetical qualifier)
        base = re.split(r"[\(\[]", section)[0].strip()
        # Use just the first meaningful word sequence (up to ~40 chars)
        base = base[:40].strip()
        if not base:
            continue
        if base.lower() not in text.lower():
            missing.append(section)
    return len(missing) == 0, missing


# ---------------------------------------------------------------------------
# HackenProof delegation helpers
# ---------------------------------------------------------------------------

def _delegate_to_hackenproof_exporter(
    draft_path: pathlib.Path,
    out_path: Optional[pathlib.Path],
) -> pathlib.Path:
    """Delegate HackenProof export to the canonical tools/hackenproof-plain-export.py.

    Invokes the canonical tool via subprocess (or module import) and returns
    the path of the produced .hackenproof-plain.txt.  All markdown stripping,
    PoC-to-zip handling, ASCII normalization, and leak validation is owned by
    the canonical tool; this function is a thin router shim.
    """
    cmd = [sys.executable, str(HP_EXPORT_TOOL), "--draft", str(draft_path),
           "--platform", "hackenproof", "--json"]
    if out_path is not None:
        cmd += ["--out", str(out_path)]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
        )
        # Print canonical tool stdout/stderr so the caller can see progress
        if result.stdout:
            print(result.stdout, end="")
        if result.stderr:
            print(result.stderr, end="", file=sys.stderr)
        if result.returncode not in (0, 1):
            # rc=1 from canonical tool means validation failures (ok=false) - that
            # is not a fatal error for the router; we still surface the output.
            print(
                f"[platform-export] WARNING: hackenproof-plain-export.py exited "
                f"with rc={result.returncode}",
                file=sys.stderr,
            )
    except Exception as exc:
        print(
            f"[platform-export] ERROR invoking hackenproof-plain-export.py: {exc}",
            file=sys.stderr,
        )
        raise

    # Determine where the canonical tool wrote its output
    if out_path is not None:
        resolved_out = out_path
    else:
        base = draft_path.stem
        resolved_out = draft_path.parent / f"{base}.hackenproof-plain.txt"

    return resolved_out


# ---------------------------------------------------------------------------
# main export logic
# ---------------------------------------------------------------------------

def export_draft(
    draft_path: pathlib.Path,
    platform_id: str,
    out_path: Optional[pathlib.Path],
    registry: Dict[str, Any],
) -> pathlib.Path:
    """Export draft_path to the platform-correct format.

    Returns the path of the written output file.

    For HackenProof: delegates entirely to tools/hackenproof-plain-export.py
    (the canonical exporter). No duplicate stripping logic lives here.

    For markdown-allowed platforms: pass-through with required-section validation.
    """
    entry = registry.get(platform_id) or registry.get("generic") or {}
    markdown_allowed = bool(entry.get("markdown_allowed", True))
    required_sections: List[str] = list(entry.get("required_sections") or [])

    slug = draft_path.stem
    source_text = draft_path.read_text(encoding="utf-8", errors="replace")

    if not markdown_allowed:
        # HackenProof: DELEGATE to the canonical tool - do NOT strip markdown here.
        print(f"[platform-export] hackenproof -> delegating to {HP_EXPORT_TOOL.name}")
        resolved_out = _delegate_to_hackenproof_exporter(draft_path, out_path)
        return resolved_out
    else:
        # Markdown-allowed platforms: pass-through with section validation
        if out_path is None:
            out_path = draft_path.parent / f"{slug}.{platform_id}-export.md"

        # For same-format pass-through, just copy
        out_path.write_text(source_text, encoding="utf-8")

        ok, missing = validate_required_sections(source_text, required_sections, platform_id)
        if missing:
            print(
                f"[platform-export] WARNING: {len(missing)} required section(s) "
                f"not found in draft for platform `{platform_id}`:",
                file=sys.stderr,
            )
            for s in missing:
                print(f"  - {s}", file=sys.stderr)
        else:
            print(
                f"[platform-export] {platform_id} markdown: all {len(required_sections)} "
                f"required sections present."
            )
        print(f"[platform-export] output: {out_path}")

    return out_path


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Emit a platform-correct export from a paste_ready draft.md",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("draft", help="Path to the source draft.md file")
    parser.add_argument(
        "--platform",
        default=None,
        help="Platform id override: cantina | immunefi | github-ghsa | hackenproof | generic",
    )
    parser.add_argument(
        "--workspace",
        default=None,
        help="Workspace root path (used for platform auto-detection when --platform is not set)",
    )
    parser.add_argument(
        "--out",
        default=None,
        help="Output file path (default: sibling of draft with platform-specific suffix)",
    )
    args = parser.parse_args(argv)

    draft_path = pathlib.Path(args.draft).resolve()
    if not draft_path.is_file():
        print(f"ERROR: draft not found: {draft_path}", file=sys.stderr)
        return 1

    workspace_path = pathlib.Path(args.workspace).resolve() if args.workspace else None
    out_path = pathlib.Path(args.out).resolve() if args.out else None

    platform_id = resolve_platform(args.platform, workspace_path, draft_path)
    registry = load_registry()

    print(f"[platform-export] draft={draft_path.name} platform={platform_id}")

    export_draft(draft_path, platform_id, out_path, registry)
    return 0


if __name__ == "__main__":
    sys.exit(main())
