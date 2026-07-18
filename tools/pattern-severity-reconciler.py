#!/usr/bin/env python3
"""pattern-severity-reconciler.py — cross-check DSL severities vs BUG_CLASSES.

Each `reference/patterns.dsl/*.yaml` carries explicit `severity` + `confidence`
fields (and sometimes a `tier`). The canonical class registry in
`tools/parity-report.py::BUG_CLASSES` also occasionally carries `tier`,
`severity`, and `confidence` hints.

When these two diverge — e.g. the DSL pattern says `severity: HIGH` but the
BUG_CLASSES entry registers `tier: D` (quarantine) — one of the two is stale.
This tool surfaces those mismatches so a human can reconcile them.

Scope:
  * Read-only on every source file.
  * Advisory — always exits 0.
  * Tolerant of missing fields (prints SKIPPED, not FAIL).

Output: `docs/archive/SEVERITY_RECONCILE_REPORT.md`.

Run with `make severity-reconcile`. Part of Phase 24 of the consolidation
megaplan (PR #84).
"""
from __future__ import annotations

import ast
import re
import sys
from collections import defaultdict
from pathlib import Path

try:
    import yaml
except ImportError:
    print("[error] PyYAML required. pip3 install pyyaml", file=sys.stderr)
    sys.exit(0)  # advisory — do not fail CI on missing dep

REPO = Path(__file__).resolve().parent.parent
PATTERN_DSL = REPO / "reference" / "patterns.dsl"
PARITY = REPO / "tools" / "parity-report.py"
REPORT = REPO / "docs" / "SEVERITY_RECONCILE_REPORT.md"

HIGH_SEVERITIES = {"HIGH", "CRITICAL"}
LOW_SEVERITIES = {"INFO", "LOW"}
LOW_TIERS = {"C", "D"}
HIGH_TIERS = {"S", "A"}


def load_bug_classes() -> dict:
    """Extract BUG_CLASSES literal from parity-report.py via regex + ast.literal_eval.

    Same trick as tools/finding-clusterer.py::load_bug_classes. Keeps the
    reconciler from importing the parity module (which does heavy I/O at
    import time).
    """
    if not PARITY.exists():
        return {}
    src = PARITY.read_text()
    m = re.search(r"BUG_CLASSES\s*=\s*\{", src)
    if not m:
        return {}
    start = m.end() - 1
    depth, i = 0, start
    while i < len(src):
        c = src[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                end = i + 1
                break
        i += 1
    else:
        return {}
    try:
        return ast.literal_eval(src[start:end])
    except Exception as exc:
        print(f"[warn] BUG_CLASSES parse failed: {exc}", file=sys.stderr)
        return {}


def load_dsl_patterns() -> dict:
    """Return {slug: {severity, confidence, tier, path}} for every DSL yaml."""
    out: dict = {}
    if not PATTERN_DSL.is_dir():
        return out
    for p in sorted(PATTERN_DSL.glob("*.yaml")):
        slug = p.stem
        try:
            data = yaml.safe_load(p.read_text()) or {}
        except Exception as exc:
            out[slug] = {"error": str(exc), "path": p}
            continue
        out[slug] = {
            "severity": (data.get("severity") or "").strip().upper() or None,
            "confidence": (data.get("confidence") or "").strip().upper() or None,
            "tier": (data.get("tier") or "").strip().upper() or None,
            "path": p,
        }
    return out


def match_bug_class(slug: str, bug_classes: dict) -> str | None:
    """Match a DSL pattern slug to a BUG_CLASSES entry.

    Match strategies, in order:
      1. Direct key match (BUG_CLASSES has some long-form slugs too).
      2. Keyword containment — slug contains a BUG_CLASSES keyword.
      3. Slug contains the class name (e.g. "oracle-stale-..." → "oracle-cascade").
    """
    if slug in bug_classes:
        return slug
    slug_l = slug.lower()
    # Try keyword hits — pick the class with the longest keyword that matches.
    best: tuple[int, str | None] = (0, None)
    for name, meta in bug_classes.items():
        for kw in meta.get("keywords", []) or []:
            if kw and kw.lower() in slug_l and len(kw) > best[0]:
                best = (len(kw), name)
    if best[1]:
        return best[1]
    # Last resort: slug contains the class-name root.
    for name in bug_classes.keys():
        root = name.split("-")[0]
        if len(root) >= 6 and root in slug_l:
            return name
    return None


def classify_mismatch(dsl_meta: dict, bc_name: str | None, bc_meta: dict | None) -> tuple[str, str] | None:
    """Return (category, recommendation) if there's a mismatch, else None."""
    sev = dsl_meta.get("severity")
    conf = dsl_meta.get("confidence")
    if bc_name is None:
        if sev:
            return ("dsl_only",
                    f"No BUG_CLASSES entry matches slug. Consider adding a class "
                    f"or linking to an existing one (DSL severity={sev}, confidence={conf}).")
        return None
    if bc_meta is None:
        return None
    bc_tier = (bc_meta.get("tier") or "").strip().upper() or None
    bc_sev = (bc_meta.get("severity") or "").strip().upper() or None
    # Prefer tier, fall back to severity for classification.
    if bc_tier:
        if sev in HIGH_SEVERITIES and bc_tier in LOW_TIERS:
            return ("dsl_high_bc_low_tier",
                    f"DSL={sev} but BUG_CLASSES[{bc_name}].tier={bc_tier} (quarantine). "
                    f"Either promote tier to A/S or downgrade DSL severity.")
        if sev in LOW_SEVERITIES and bc_tier in HIGH_TIERS:
            return ("dsl_low_bc_high_tier",
                    f"DSL={sev} but BUG_CLASSES[{bc_name}].tier={bc_tier}. "
                    f"Severity should be MEDIUM+ to match tier.")
    if bc_sev:
        if sev and bc_sev and sev != bc_sev:
            return ("severity_disagreement",
                    f"DSL severity={sev}, BUG_CLASSES[{bc_name}].severity={bc_sev}. "
                    f"Pick one source of truth.")
    return None


def main() -> int:
    dsl_patterns = load_dsl_patterns()
    bug_classes = load_bug_classes()
    print(f"[reconciler] DSL patterns: {len(dsl_patterns)}", file=sys.stderr)
    print(f"[reconciler] BUG_CLASSES entries: {len(bug_classes)}", file=sys.stderr)

    # ── 1. Scan DSL → mismatches (dsl_only, dsl_high_bc_low_tier, dsl_low_bc_high_tier, severity_disagreement)
    by_kind: dict[str, list] = defaultdict(list)
    skipped: list[tuple[str, str]] = []
    matched_bc_names: set[str] = set()

    for slug, meta in sorted(dsl_patterns.items()):
        if "error" in meta:
            skipped.append((slug, f"yaml parse error: {meta['error']}"))
            continue
        if not meta.get("severity"):
            skipped.append((slug, "missing severity field"))
            continue
        bc_name = match_bug_class(slug, bug_classes)
        if bc_name:
            matched_bc_names.add(bc_name)
        bc_meta = bug_classes.get(bc_name) if bc_name else None
        result = classify_mismatch(meta, bc_name, bc_meta)
        if result:
            kind, rec = result
            by_kind[kind].append({
                "slug": slug,
                "dsl_severity": meta.get("severity"),
                "dsl_confidence": meta.get("confidence"),
                "bc_name": bc_name,
                "bc_tier": (bc_meta or {}).get("tier"),
                "bc_severity": (bc_meta or {}).get("severity"),
                "recommendation": rec,
            })

    # ── 2. BUG_CLASSES with no DSL pattern matched (bc_only)
    for name, meta in sorted(bug_classes.items()):
        if name in matched_bc_names:
            continue
        if meta.get("applies_to") not in (None, "both", "solidity_only"):
            # rust_only entries won't have Solidity DSL patterns by design
            continue
        by_kind["bc_only"].append({
            "slug": None,
            "bc_name": name,
            "bc_tier": meta.get("tier"),
            "bc_severity": meta.get("severity"),
            "applies_to": meta.get("applies_to", "both"),
            "recommendation": (
                f"BUG_CLASSES entry '{name}' has no DSL pattern. Either author "
                f"a pattern under reference/patterns.dsl/ or retire the entry."),
        })

    # ── 3. Emit report
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    lines: list[str] = []
    lines.append("# Severity reconciliation report")
    lines.append("")
    lines.append(f"- DSL patterns scanned: **{len(dsl_patterns)}**")
    lines.append(f"- BUG_CLASSES entries: **{len(bug_classes)}**")
    lines.append(f"- Patterns skipped (missing fields / parse error): **{len(skipped)}**")
    lines.append("")
    lines.append("## Mismatch counts by category")
    lines.append("")
    lines.append("| Category | Count | Meaning |")
    lines.append("|---|---|---|")
    meanings = {
        "dsl_high_bc_low_tier": "DSL HIGH/CRITICAL but BUG_CLASSES tier C/D (quarantine). Suspicious — promote tier or downgrade severity.",
        "dsl_low_bc_high_tier": "DSL INFO/LOW but BUG_CLASSES tier S/A. Severity likely too low.",
        "severity_disagreement": "Both have severity and they differ.",
        "dsl_only": "DSL pattern present but no matching BUG_CLASSES entry.",
        "bc_only": "BUG_CLASSES entry present but no matching DSL pattern.",
    }
    for kind in ("dsl_high_bc_low_tier", "dsl_low_bc_high_tier",
                 "severity_disagreement", "dsl_only", "bc_only"):
        lines.append(f"| `{kind}` | {len(by_kind.get(kind, []))} | {meanings[kind]} |")
    lines.append("")

    for kind in ("dsl_high_bc_low_tier", "dsl_low_bc_high_tier",
                 "severity_disagreement", "dsl_only", "bc_only"):
        rows = by_kind.get(kind, [])
        if not rows:
            continue
        lines.append(f"## {kind} ({len(rows)})")
        lines.append("")
        lines.append(f"_{meanings[kind]}_")
        lines.append("")
        # cap long lists to keep report reviewable
        limit = 200
        for row in rows[:limit]:
            if kind == "bc_only":
                lines.append(f"- **BUG_CLASSES: `{row['bc_name']}`** "
                             f"(tier={row.get('bc_tier') or '—'}, sev={row.get('bc_severity') or '—'}, "
                             f"applies_to={row.get('applies_to')})")
                lines.append(f"  - reco: {row['recommendation']}")
            else:
                lines.append(f"- **`{row['slug']}`** — DSL sev=`{row.get('dsl_severity')}`, "
                             f"conf=`{row.get('dsl_confidence')}`; "
                             f"BC=`{row.get('bc_name') or '—'}` "
                             f"(tier=`{row.get('bc_tier') or '—'}`, sev=`{row.get('bc_severity') or '—'}`)")
                lines.append(f"  - reco: {row['recommendation']}")
        if len(rows) > limit:
            lines.append(f"- … +{len(rows) - limit} more (truncated)")
        lines.append("")

    if skipped:
        lines.append(f"## Skipped patterns ({len(skipped)})")
        lines.append("")
        for slug, reason in skipped[:50]:
            lines.append(f"- `{slug}` — {reason}")
        if len(skipped) > 50:
            lines.append(f"- … +{len(skipped) - 50} more (truncated)")
        lines.append("")

    lines.append("---")
    lines.append("_Generated by `tools/pattern-severity-reconciler.py` "
                 "(`make severity-reconcile`). Advisory — always exits 0._")
    REPORT.write_text("\n".join(lines) + "\n")

    # Stderr summary
    for kind in ("dsl_high_bc_low_tier", "dsl_low_bc_high_tier",
                 "severity_disagreement", "dsl_only", "bc_only"):
        print(f"[reconciler] {kind}: {len(by_kind.get(kind, []))}", file=sys.stderr)
    print(f"[reconciler] skipped: {len(skipped)}", file=sys.stderr)
    print(f"[reconciler] wrote {REPORT.relative_to(REPO)}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
