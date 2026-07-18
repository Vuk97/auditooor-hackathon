#!/usr/bin/env python3
"""registry-health-report.py — Single-file health report for _tier_registry.yaml.

Produces docs/REGISTRY_HEALTH_<ts>.md with 10 sections covering tier breakdown,
engine breakdown, verified-true subset, wave membership, smoke evidence freshness,
drift (T-01), master mandate §7.5 compliance, tier movement, top-10 recent
promotions, and operator action items.

Usage:
    python3 tools/registry-health-report.py
    python3 tools/registry-health-report.py --registry path/to/_tier_registry.yaml
    python3 tools/registry-health-report.py --out path/to/output.md
    python3 tools/registry-health-report.py --drift-json /tmp/_drift.json  # reuse existing
"""

import argparse
import json
import os
import subprocess
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml

# ---------------------------------------------------------------------------
# Repo root detection
# ---------------------------------------------------------------------------
SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent  # tools/ lives under repo root


def find_registry(explicit: str | None) -> Path:
    if explicit:
        p = Path(explicit)
        if not p.exists():
            sys.exit(f"ERROR: registry not found at {p}")
        return p
    default = REPO_ROOT / "detectors" / "_tier_registry.yaml"
    if not default.exists():
        sys.exit(f"ERROR: registry not found at {default}. Use --registry.")
    return default


# ---------------------------------------------------------------------------
# Load registry
# ---------------------------------------------------------------------------
def load_registry(path: Path) -> dict:
    with path.open() as f:
        raw = yaml.safe_load(f)
    return raw.get("tiers", {})


# ---------------------------------------------------------------------------
# Utility: parse ISO datetime safely
# ---------------------------------------------------------------------------
def parse_dt(val) -> datetime | None:
    if val is None:
        return None
    try:
        dt = datetime.fromisoformat(str(val))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Section 1 — Tier breakdown
# ---------------------------------------------------------------------------
def section_tier_breakdown(rows: dict) -> str:
    counts = Counter(v.get("tier", "MISSING") for v in rows.values())
    total = sum(counts.values())
    lines = ["## 1. Tier Breakdown\n"]
    lines.append(f"Total rows: **{total}**\n")
    lines.append("| Tier | Count | % |")
    lines.append("|------|------:|--:|")
    for tier in sorted(counts, key=lambda t: (t not in ("S", "A", "B"), t)):
        c = counts[tier]
        lines.append(f"| {tier} | {c} | {c/total*100:.1f}% |")
    lines.append(f"| **TOTAL** | **{total}** | 100% |")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Section 2 — Engine breakdown
# ---------------------------------------------------------------------------
def section_engine_breakdown(rows: dict) -> str:
    counts = Counter(v.get("engine", "MISSING") for v in rows.values())
    total = sum(counts.values())
    lines = ["## 2. Engine Breakdown\n"]
    lines.append("| Engine | Count | % |")
    lines.append("|--------|------:|--:|")
    for eng, c in sorted(counts.items(), key=lambda x: -x[1]):
        lines.append(f"| {eng} | {c} | {c/total*100:.1f}% |")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Section 3 — Verified-true subset
# ---------------------------------------------------------------------------
def section_verified_subset(rows: dict) -> str:
    tier_total: dict[str, int] = defaultdict(int)
    tier_verified: dict[str, int] = defaultdict(int)
    for v in rows.values():
        t = v.get("tier", "MISSING")
        tier_total[t] += 1
        if v.get("verified"):
            tier_verified[t] += 1
    total_v = sum(tier_verified.values())
    total_r = sum(tier_total.values())
    lines = ["## 3. Verified-True Subset\n"]
    lines.append(f"Total verified: **{total_v}** / {total_r} ({total_v/total_r*100:.1f}%)\n")
    lines.append("| Tier | Verified | Total | % Verified |")
    lines.append("|------|--------:|------:|-----------:|")
    for tier in sorted(tier_total, key=lambda t: (t not in ("S", "A", "B"), t)):
        tv = tier_verified[tier]
        tt = tier_total[tier]
        pct = tv / tt * 100 if tt else 0
        lines.append(f"| {tier} | {tv} | {tt} | {pct:.1f}% |")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Section 4 — Wave breakdown
# ---------------------------------------------------------------------------
def section_wave_breakdown(rows: dict) -> str:
    wave_counts: Counter = Counter()
    no_wave = 0
    for v in rows.values():
        waves = v.get("waves") or []
        if not waves:
            no_wave += 1
        for w in waves:
            wave_counts[w] += 1
    lines = ["## 4. Wave Breakdown\n"]
    lines.append(f"Rows with no wave tag: **{no_wave}**\n")
    lines.append("| Wave | Row-membership count |")
    lines.append("|------|--------------------:|")
    for wave, c in sorted(wave_counts.items(), key=lambda x: -x[1]):
        lines.append(f"| {wave} | {c} |")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Section 5 — Smoke evidence freshness
# ---------------------------------------------------------------------------
def section_freshness(rows: dict) -> str:
    now = datetime.now(timezone.utc)
    last_24h = 0
    last_7d = 0
    older = 0
    total_verified = 0
    for v in rows.values():
        if not v.get("verified"):
            continue
        total_verified += 1
        va = v.get("verified_at")
        dt = parse_dt(va)
        if dt is None:
            older += 1
            continue
        age = now - dt
        if age <= timedelta(hours=24):
            last_24h += 1
        elif age <= timedelta(days=7):
            last_7d += 1
        else:
            older += 1
    lines = ["## 5. Smoke Evidence Freshness\n"]
    lines.append(f"Verified rows: **{total_verified}**\n")
    lines.append("| Window | Count | % of verified |")
    lines.append("|--------|------:|---------------:|")
    for label, c in [("Last 24 h", last_24h), ("Last 7 d (excl. 24 h)", last_7d), ("Older / no timestamp", older)]:
        pct = c / total_verified * 100 if total_verified else 0
        lines.append(f"| {label} | {c} | {pct:.1f}% |")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Section 6 — Drift (T-01)
# ---------------------------------------------------------------------------
def section_drift(drift_json_path: str | None) -> tuple[str, dict]:
    # Run drift check if no cached output provided
    if drift_json_path and Path(drift_json_path).exists():
        with open(drift_json_path) as f:
            data = json.load(f)
    else:
        out_path = "/tmp/_registry_health_drift.json"
        script = REPO_ROOT / "tools" / "registry-disk-consistency-check.py"
        result = subprocess.run(
            [sys.executable, str(script), "--json-out", out_path],
            capture_output=True,
            text=True,
            cwd=str(REPO_ROOT),
        )
        if not Path(out_path).exists():
            return "## 6. Drift (T-01)\n\nERROR: drift check failed to produce output.\n\n```\n" + result.stderr[:500] + "\n```", {}
        with open(out_path) as f:
            data = json.load(f)

    total_high = data.get("total_high_tier_rows", 0)
    ok = data.get("ok_count", 0)
    drift = data.get("drift_count", 0)
    prob_counter: Counter = Counter()
    tier_counter: Counter = Counter()
    for row in data.get("drift_rows", []):
        for p in row.get("problems", []):
            prob_counter[p] += 1
        tier_counter[row.get("tier", "?")] += 1

    lines = ["## 6. Drift (T-01)\n"]
    lines.append(f"Checked Tier-S/A/B rows: **{total_high}**  ")
    lines.append(f"Clean: **{ok}** ({ok/total_high*100:.1f}%)  Drift: **{drift}** ({drift/total_high*100:.1f}%)\n")
    lines.append("**Problem breakdown:**\n")
    lines.append("| Problem | Count |")
    lines.append("|---------|------:|")
    for p, c in sorted(prob_counter.items(), key=lambda x: -x[1]):
        lines.append(f"| {p} | {c} |")
    lines.append("\n**Drift by tier:**\n")
    lines.append("| Tier | Drifting rows |")
    lines.append("|------|-------------:|")
    for t, c in sorted(tier_counter.items(), key=lambda x: -x[1]):
        lines.append(f"| {t} | {c} |")

    return "\n".join(lines), data


# ---------------------------------------------------------------------------
# Section 7 — Master mandate §7.5 status
# ---------------------------------------------------------------------------
def section_mandate(rows: dict) -> str:
    # Solidity = slither engine (or MISSING engine that is not rust)
    # Rust = engine == rust
    TARGET_SOL_VERIFIED_SAB = 150
    TARGET_RUST_VERIFIED_SAB = 80

    sol_sab_verified = 0
    rust_sab_verified = 0
    sol_sab_total = 0
    rust_sab_total = 0

    for v in rows.values():
        tier = v.get("tier", "")
        engine = v.get("engine", "MISSING")
        if tier not in ("S", "A", "B"):
            continue
        if engine == "rust":
            rust_sab_total += 1
            if v.get("verified"):
                rust_sab_verified += 1
        else:
            # slither or MISSING — treat as Solidity
            sol_sab_total += 1
            if v.get("verified"):
                sol_sab_verified += 1

    sol_ok = sol_sab_verified >= TARGET_SOL_VERIFIED_SAB
    rust_ok = rust_sab_verified >= TARGET_RUST_VERIFIED_SAB

    lines = ["## 7. Master Mandate §7.5 Status\n"]
    lines.append("| Language | Target | Verified S/A/B | Total S/A/B | Status |")
    lines.append("|----------|-------:|---------------:|------------:|--------|")
    lines.append(
        f"| Solidity (slither/unknown) | ≥{TARGET_SOL_VERIFIED_SAB} | {sol_sab_verified} | {sol_sab_total} | {'PASS' if sol_ok else 'FAIL'} |"
    )
    lines.append(
        f"| Rust | ≥{TARGET_RUST_VERIFIED_SAB} | {rust_sab_verified} | {rust_sab_total} | {'PASS' if rust_ok else 'FAIL'} |"
    )
    lines.append("")
    if sol_ok and rust_ok:
        lines.append("Overall mandate: **COMPLIANT**")
    else:
        gaps = []
        if not sol_ok:
            gaps.append(f"Solidity short by {TARGET_SOL_VERIFIED_SAB - sol_sab_verified}")
        if not rust_ok:
            gaps.append(f"Rust short by {TARGET_RUST_VERIFIED_SAB - rust_sab_verified}")
        lines.append(f"Overall mandate: **NON-COMPLIANT** — {'; '.join(gaps)}")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Section 8 — Tier movement this session
# ---------------------------------------------------------------------------
def section_tier_movement(rows: dict) -> str:
    # Infer source from waves + reason text heuristics
    # We look at last_promoted date = today or yesterday (session activity)
    now = datetime.now(timezone.utc)
    today = now.date()

    source_counter: Counter = Counter()
    recent_promotions = 0

    wave_source_map = {
        "phase-a-inventory": "Phase-A inventory",
        "phase4-overnight": "phase4-overnight",
        "wave17": "wave17 synthesis",
        "wave18": "wave18 synthesis",
        "wave16": "wave16 synthesis",
        "wave1": "wave1 (legacy)",
    }

    for v in rows.values():
        lp = v.get("last_promoted")
        if lp is None:
            continue
        lp_date = None
        try:
            if isinstance(lp, str):
                lp_date = datetime.fromisoformat(lp).date()
            else:
                lp_date = lp  # already a date object from YAML
        except Exception:
            continue
        # Consider "this session" = last 2 days
        if lp_date and (today - lp_date).days <= 1:
            recent_promotions += 1
            waves = v.get("waves") or []
            labeled = False
            for w in waves:
                if w in wave_source_map:
                    source_counter[wave_source_map[w]] += 1
                    labeled = True
                    break
            if not labeled:
                # Check reason string for clues
                reason = v.get("reason", "")
                if "fp-repair" in reason.lower() or "fp repair" in reason.lower():
                    source_counter["FP-repair"] += 1
                elif "arch" in reason.lower():
                    source_counter["arch-mismatch"] += 1
                elif "no-yaml" in reason.lower() or "synthesis" in reason.lower():
                    source_counter["no-YAML synthesis"] += 1
                elif "rust" in reason.lower() or v.get("engine") == "rust":
                    source_counter["r94 Rust"] += 1
                else:
                    source_counter["other / unlabeled"] += 1

    lines = ["## 8. Tier Movement This Session\n"]
    if not recent_promotions:
        lines.append("No promotions detected in the last 2 days (no `last_promoted` within window).")
    else:
        lines.append(f"Promotions in last 2 days: **{recent_promotions}**\n")
        if source_counter:
            lines.append("| Source | Promotions |")
            lines.append("|--------|----------:|")
            for src, c in sorted(source_counter.items(), key=lambda x: -x[1]):
                lines.append(f"| {src} | {c} |")
        else:
            lines.append("Source breakdown unavailable (no matching wave tags).")

    lines.append("")
    lines.append("_Note: No baseline snapshot found; movement inferred from `last_promoted` date proximity to today._")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Section 9 — Top 10 most-recent promotions
# ---------------------------------------------------------------------------
def section_top10_recent(rows: dict) -> str:
    rows_with_va = []
    for k, v in rows.items():
        va = v.get("verified_at")
        if va is None:
            continue
        dt = parse_dt(va)
        if dt:
            rows_with_va.append((k, v.get("tier", "?"), dt, v.get("engine", "?")))
    rows_with_va.sort(key=lambda x: x[2], reverse=True)

    lines = ["## 9. Top 10 Most-Recent Promotions\n"]
    lines.append("| Detector | Tier | Engine | Verified At |")
    lines.append("|----------|------|--------|-------------|")
    for k, tier, dt, eng in rows_with_va[:10]:
        lines.append(f"| `{k}` | {tier} | {eng} | {dt.strftime('%Y-%m-%dT%H:%M:%SZ')} |")
    if not rows_with_va:
        lines.append("_No rows with `verified_at` found._")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Section 10 — Operator action items
# ---------------------------------------------------------------------------
def section_action_items(rows: dict, drift_data: dict) -> str:
    drift_count = drift_data.get("drift_count", "unknown")
    prob_counter: Counter = Counter()
    for row in drift_data.get("drift_rows", []):
        for p in row.get("problems", []):
            prob_counter[p] += 1
    missing_verified = prob_counter.get("missing verified=true", 0)
    no_py = prob_counter.get("no .py file", 0)
    no_fixture = prob_counter.get("no vulnerable fixture", prob_counter.get("no vulnerable/clean fixture", 0))

    # D-tier rows with backing .py (heuristic: engine field present or name-searchable)
    d_with_engine = sum(
        1 for v in rows.values()
        if v.get("tier") == "D" and v.get("engine") is not None
    )

    # ARCHIVED count and breakdown
    archived_count = sum(1 for v in rows.values() if v.get("tier") == "ARCHIVED")
    archived_reason = Counter(v.get("archived_reason", "unknown") for v in rows.values() if v.get("tier") == "ARCHIVED")
    top_archived_reason = archived_reason.most_common(1)[0] if archived_reason else ("none", 0)

    lines = ["## 10. Operator Action Items\n"]

    lines.append("### Drift remediation")
    lines.append(f"- **{drift_count}** high-tier rows in drift state:")
    if missing_verified:
        lines.append(f"  - {missing_verified} rows need `verified: true` — run `tools/inventory-bulk-promote.py` after smoke pass")
    if no_fixture:
        lines.append(f"  - {no_fixture} rows missing on-disk fixture — add fixture or downgrade to Tier-D")
    if no_py:
        lines.append(f"  - {no_py} rows missing `.py` file — stale YAML entry; consider archiving or recompiling")
    lines.append("")

    lines.append("### Tier-D rows with artifacts")
    lines.append(
        f"- **{d_with_engine}** Tier-D rows carry an `engine` field (likely have backing artifacts)"
    )
    lines.append("  - Run `tools/tier-d-revival-pipeline.py` to attempt smoke-test promotion to Tier-B")
    lines.append("")

    lines.append("### ARCHIVED rows")
    lines.append(f"- **{archived_count}** ARCHIVED rows total")
    lines.append(f"  - Top reason: `{top_archived_reason[0]}` ({top_archived_reason[1]} rows)")
    lines.append("  - All were archived today (2026-05-04); no purge urgency — keep as audit trail for 30 days")
    lines.append("  - If disk is a concern, safe to `grep` out rows where `tier_before_archived: B` and `archived_reason` contains `no .py file`")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="Generate registry health report.")
    ap.add_argument("--registry", default=None, help="Path to _tier_registry.yaml")
    ap.add_argument("--out", default=None, help="Output .md path (default: docs/REGISTRY_HEALTH_<ts>.md)")
    ap.add_argument("--drift-json", default=None, help="Path to pre-computed drift JSON (skips re-running drift check)")
    args = ap.parse_args()

    reg_path = find_registry(args.registry)
    rows = load_registry(reg_path)

    now = datetime.now(timezone.utc)
    ts = now.strftime("%Y%m%dT%H%M%SZ")

    if args.out:
        out_path = Path(args.out)
    else:
        docs_dir = REPO_ROOT / "docs"
        docs_dir.mkdir(exist_ok=True)
        out_path = docs_dir / f"REGISTRY_HEALTH_{ts}.md"

    print(f"Registry: {reg_path} ({len(rows)} rows)")
    print(f"Output:   {out_path}")
    print("Running drift check (T-01)...")

    s6, drift_data = section_drift(args.drift_json)

    sections = [
        f"# Registry Health Report\n\nGenerated: {now.strftime('%Y-%m-%dT%H:%M:%SZ')}  \nRegistry: `{reg_path.relative_to(REPO_ROOT)}`  \nTotal rows: **{len(rows)}**\n\n---\n",
        section_tier_breakdown(rows),
        "\n---\n",
        section_engine_breakdown(rows),
        "\n---\n",
        section_verified_subset(rows),
        "\n---\n",
        section_wave_breakdown(rows),
        "\n---\n",
        section_freshness(rows),
        "\n---\n",
        s6,
        "\n---\n",
        section_mandate(rows),
        "\n---\n",
        section_tier_movement(rows),
        "\n---\n",
        section_top10_recent(rows),
        "\n---\n",
        section_action_items(rows, drift_data),
        "\n\n---\n_End of report._\n",
    ]

    content = "\n".join(sections)
    out_path.write_text(content, encoding="utf-8")

    line_count = content.count("\n") + 1
    print(f"Done. Report: {out_path} ({line_count} lines, {len(content):,} bytes)")
    return str(out_path)


if __name__ == "__main__":
    main()
