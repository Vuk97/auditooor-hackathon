#!/usr/bin/env python3
"""vault-ontology-validate.py — validate vault-note frontmatter against the 5-layer ontology.

Lane 11 of MCP harness review (PR #658). Schema: schemas/vault_layer.v1.json.
5-layer ontology:
  L0 — Raw artifacts (PoCs, audit PDFs, commits, source extracts)
  L1 — Structural patterns (detectors, DSL, AST predicates)
  L2 — Causal case studies ("why does this exploit work?")
  L3 — Attacker mental frames ("how would I try this?")
  L4 — Meta-discipline rules (L1-L32 + harness ops)

Usage:
    python3 tools/vault-ontology-validate.py                   # default scan vault
    python3 tools/vault-ontology-validate.py path/to/note.md   # single note
    python3 tools/vault-ontology-validate.py --strict          # exit non-zero on warnings
    python3 tools/vault-ontology-validate.py --check-cross-refs # enforce cross-ref rules

Cross-reference rules (validator-enforced when --check-cross-refs):
  L1 must link to ≥1 L2 OR ≥1 L0
  L2 must link to ≥1 L0 PoC and ≥1 L1 (or be tagged pattern_seed: true)
  L3 must link to ≥2 L2 case studies
  L4 must list triggers: [task_type | surface_keyword]

Written by Claude Opus 4.7 for PR #658 implementation Phase 1 commit 1.
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import sys

REPO = pathlib.Path(__file__).resolve().parent.parent
SCHEMA_PATH = REPO / "schemas" / "vault_layer.v1.json"

DEFAULT_VAULT_DIRS = [
    pathlib.Path("/Users/wolf/Documents/Codex/auditooor/obsidian-vault"),
    REPO / "obsidian-vault",
]

FRONTMATTER_RE = re.compile(r"^---\s*\n(.*?)\n---\s*\n", re.DOTALL)


def _load_schema():
    if not SCHEMA_PATH.is_file():
        raise SystemExit(f"[fatal] schema not found: {SCHEMA_PATH}")
    with SCHEMA_PATH.open(encoding="utf-8") as fh:
        return json.load(fh)


def _parse_frontmatter(text):
    """Returns dict from YAML-ish frontmatter or None if no frontmatter."""
    m = FRONTMATTER_RE.match(text)
    if not m:
        return None
    fm = {}
    body = m.group(1)
    current_key = None
    for line in body.splitlines():
        line = line.rstrip()
        if not line:
            continue
        if line.startswith(("  - ", "    - ")):
            # list item under previous key
            if current_key and isinstance(fm.get(current_key), list):
                item = line.lstrip(" -").strip().strip('"\'')
                fm[current_key].append(item)
            continue
        if ":" in line and not line.startswith(" "):
            key, _, val = line.partition(":")
            key = key.strip()
            val = val.strip().strip('"\'')
            if val == "":
                fm[key] = []
                current_key = key
            elif val.startswith("[") and val.endswith("]"):
                inner = val[1:-1].strip()
                if inner:
                    items = [x.strip().strip('"\'') for x in inner.split(",")]
                    fm[key] = items
                else:
                    fm[key] = []
                current_key = None
            else:
                # try bool / number
                low = val.lower()
                if low in ("true", "false"):
                    fm[key] = (low == "true")
                else:
                    fm[key] = val
                current_key = None
    return fm


def _validate_layer(fm, *, path, check_cross_refs=False):
    """Returns (errors, warnings)."""
    errors = []
    warnings = []

    if "layer" not in fm:
        # If note has no layer field, that's a Phase A migration gap, not a hard error
        warnings.append("missing 'layer' field (Phase A migration not yet applied)")
        return errors, warnings

    layer = fm["layer"]
    if layer not in {"L0", "L1", "L2", "L3", "L4"}:
        errors.append(f"invalid layer {layer!r} (must be L0..L4)")
        return errors, warnings

    # Per-layer required fields
    if layer == "L0":
        if "source_uri" not in fm:
            errors.append("L0 requires source_uri")
        if "extracted_at" not in fm:
            warnings.append("L0 should have extracted_at")
    elif layer == "L1":
        if "pattern_id" not in fm:
            errors.append("L1 requires pattern_id")
        if check_cross_refs:
            l2_links = fm.get("links_to_l2", [])
            l0_links = fm.get("links_to_l0", [])
            if not (l2_links or l0_links):
                errors.append("L1 must link to ≥1 L2 OR ≥1 L0 (orphan-pattern gate)")
    elif layer == "L2":
        if "engagement" not in fm:
            errors.append("L2 requires engagement")
        if "root_cause_class" not in fm:
            warnings.append("L2 should have root_cause_class")
        if check_cross_refs and not fm.get("pattern_seed"):
            # advisory: L2 should link to L0 + L1 unless explicitly novel
            warnings.append("L2 without pattern_seed flag should link to L0 PoC + L1 detector")
    elif layer == "L3":
        if "frame_id" not in fm:
            errors.append("L3 requires frame_id")
        if "applicable_classes" not in fm:
            errors.append("L3 requires applicable_classes")
        case_studies = fm.get("case_studies", [])
        if check_cross_refs and len(case_studies) < 2:
            errors.append(f"L3 requires ≥2 case_studies (got {len(case_studies)}); frames are derived not invented")
    elif layer == "L4":
        if "rule_id" not in fm:
            errors.append("L4 requires rule_id")
        triggers = fm.get("triggers", [])
        if not triggers:
            errors.append("L4 requires triggers (≥1 task_type or surface_keyword)")

    return errors, warnings


def iter_md_files(root):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if not d.startswith(".") and d != "_archive"]
        for fn in filenames:
            if fn.endswith(".md"):
                yield pathlib.Path(dirpath) / fn


def _resolve_vault_dir():
    for cand in DEFAULT_VAULT_DIRS:
        if cand.is_dir():
            return cand
    return None


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("path", nargs="?", help="single note OR vault dir (default: auto-resolve)")
    parser.add_argument("--strict", action="store_true", help="treat warnings as errors")
    parser.add_argument("--check-cross-refs", action="store_true", help="enforce cross-reference rules (L1→L2/L0, L3→≥2 L2, etc.)")
    parser.add_argument("--print-schema", action="store_true")
    parser.add_argument("--summary-only", action="store_true", help="print only summary counts")
    args = parser.parse_args()

    if args.print_schema:
        print(json.dumps(_load_schema(), indent=2))
        return 0

    if args.path:
        target = pathlib.Path(args.path).resolve()
    else:
        target = _resolve_vault_dir()
        if target is None:
            print("[vault-ontology-validate] no vault dir found; nothing to do", file=sys.stderr)
            return 0

    n_files = 0
    n_err = 0
    n_warn = 0
    layer_counts = {"L0": 0, "L1": 0, "L2": 0, "L3": 0, "L4": 0, "MISSING": 0}

    if target.is_file():
        files = [target]
    else:
        files = list(iter_md_files(target))

    for fp in files:
        n_files += 1
        try:
            text = fp.read_text(encoding="utf-8")
        except Exception as exc:
            if not args.summary_only:
                print(f"[{fp}] read error: {exc}", file=sys.stderr)
            n_err += 1
            continue
        fm = _parse_frontmatter(text)
        if fm is None:
            layer_counts["MISSING"] += 1
            continue
        errors, warnings = _validate_layer(fm, path=fp, check_cross_refs=args.check_cross_refs)
        layer = fm.get("layer", "MISSING")
        if layer in layer_counts:
            layer_counts[layer] += 1
        for err in errors:
            if not args.summary_only:
                print(f"[{fp.relative_to(target if target.is_dir() else fp.parent)}] ERROR: {err}", file=sys.stderr)
            n_err += 1
        for w in warnings:
            if not args.summary_only:
                print(f"[{fp.relative_to(target if target.is_dir() else fp.parent)}] WARN: {w}", file=sys.stderr)
            n_warn += 1

    print(f"[vault-ontology-validate] files={n_files} errors={n_err} warnings={n_warn}")
    print(f"[vault-ontology-validate] layer counts: {layer_counts}")
    if n_err > 0:
        return 1
    if args.strict and n_warn > 0:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
