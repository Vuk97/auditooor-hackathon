#!/usr/bin/env python3
"""detector-coverage-matrix.py — bug-class × detector-count matrix.

Finer-grained companion to tools/parity-report.py: instead of raw detector
names, rolls counts up to the 17 bug-class topics defined in
tools/finding-clusterer.py::BUCKETS, so we can see topic-level coverage
across rust_wave1/ (Rust) and wave17/ (Solidity) and track recent PR #84
additions.

Writes docs/DETECTOR_COVERAGE_MATRIX.md.

Usage:
    python3 tools/detector-coverage-matrix.py
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
from collections import defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
RUST_DIR = REPO / "detectors" / "rust_wave1"
SOL_DIR = REPO / "detectors" / "wave17"
OUT = REPO / "docs" / "DETECTOR_COVERAGE_MATRIX.md"


def _extract_literal(src: str, name: str) -> str | None:
    m = re.search(rf"^{name}\s*=\s*(\[|\{{)", src, re.MULTILINE)
    if not m:
        return None
    start = m.end() - 1
    open_c, close_c = src[start], "]" if src[start] == "[" else "}"
    depth, i = 0, start
    while i < len(src):
        c = src[i]
        if c == open_c:
            depth += 1
        elif c == close_c:
            depth -= 1
            if depth == 0:
                return src[start : i + 1]
        i += 1
    return None


def _load(path: str, name: str, default):
    src = (REPO / path).read_text()
    lit = _extract_literal(src, name)
    if not lit:
        return default
    try:
        return eval(lit, {"__builtins__": {}}, {})  # noqa: S307 — trusted src
    except Exception:
        return default


def _read_docstring_and_head(path: Path) -> str:
    try:
        text = path.read_text(errors="ignore")
    except Exception:
        return ""
    # First 2000 chars cover docstring + imports + any DESCRIPTION/message.
    return text[:2000].lower()


def classify(path: Path, buckets: list[tuple[str, list[str]]]) -> str:
    name = path.stem.lower()
    haystack = name + " " + _read_docstring_and_head(path)
    for label, keys in buckets:
        for k in keys:
            if k.lower() in haystack:
                return label
    return "unclassified"


def scan_dir(d: Path, buckets) -> dict[str, int]:
    counts: dict[str, int] = defaultdict(int)
    if not d.exists():
        return counts
    for p in sorted(d.glob("*.py")):
        if p.name.startswith("_") or p.name == "_util.py":
            continue
        counts[classify(p, buckets)] += 1
    return counts


def parity_status(rust: int, sol: int, applies_to: str) -> str:
    if applies_to == "rust_only":
        return "rust-only (expected)" if rust > 0 else "MISSING"
    if applies_to == "solidity_only":
        return "sol-only (expected)" if sol > 0 else "MISSING"
    if rust == 0 and sol == 0:
        return "UNCOVERED_BOTH"
    if rust == 0:
        return "rust gap"
    if sol == 0:
        return "sol gap"
    return "both covered"


def recent_additions_by_topic(buckets) -> dict[str, list[str]]:
    """Scan git log for PR #84 phase/mine/loop commits, group by bucket."""
    try:
        log = subprocess.check_output(
            ["git", "log", "--oneline", "-n", "200"],
            cwd=str(REPO), text=True,
        )
    except Exception:
        return {}
    pat = re.compile(r"(phase\s*\d+|mine|loop|cycle)", re.IGNORECASE)
    out: dict[str, list[str]] = defaultdict(list)
    for line in log.splitlines():
        if not pat.search(line):
            continue
        lower = line.lower()
        for label, keys in buckets:
            for k in keys:
                if k.lower() in lower:
                    out[label].append(line.strip())
                    break
    return out


def load_detectorization_gate_summary(workspace: Path | None) -> dict[str, Any]:
    if workspace is None:
        return {}
    inventory = workspace / ".auditooor" / "corpus_detectorization_inventory.json"
    advisories = workspace / "scanner_promotion_advisories.json"
    rows: list[dict[str, Any]] = []
    advisory_rows: list[dict[str, Any]] = []
    if inventory.is_file():
        try:
            payload = json.loads(inventory.read_text(encoding="utf-8"))
            if isinstance(payload, dict) and isinstance(payload.get("rows"), list):
                rows = [row for row in payload["rows"] if isinstance(row, dict)]
        except Exception:
            rows = []
    if advisories.is_file():
        try:
            payload = json.loads(advisories.read_text(encoding="utf-8"))
            if isinstance(payload, dict) and isinstance(payload.get("advisories"), list):
                advisory_rows = [row for row in payload["advisories"] if isinstance(row, dict)]
        except Exception:
            advisory_rows = []
    by_lane: dict[str, dict[str, int]] = {}
    for row in rows:
        contract = row.get("impact_contract_summary")
        if not isinstance(contract, dict) or not contract.get("required"):
            continue
        lane = str(row.get("detector_or_lane") or "").strip()
        if not lane:
            continue
        bucket = by_lane.setdefault(lane, {"reportable_rows": 0, "mapped_rows": 0, "blocked_rows": 0})
        bucket["reportable_rows"] += 1
        if contract.get("status") == "mapped" and str(contract.get("selected_impact") or "").strip():
            bucket["mapped_rows"] += 1
        else:
            bucket["blocked_rows"] += 1
    advisory_counts = {
        "count": len(advisory_rows),
        "reportable_required": 0,
        "reportable_blocked": 0,
    }
    for row in advisory_rows:
        contract = row.get("impact_contract_summary")
        if not isinstance(contract, dict) or not contract.get("required"):
            continue
        advisory_counts["reportable_required"] += 1
        if contract.get("status") != "mapped":
            advisory_counts["reportable_blocked"] += 1
    return {
        "workspace": str(workspace),
        "by_lane": by_lane,
        "advisories": advisory_counts,
    }


def render(buckets, rust_counts, sol_counts, classes, recents, gate_summary: dict[str, Any] | None = None) -> str:
    # Map bucket -> applies_to via BUG_CLASSES keyword overlap
    bucket_applies: dict[str, str] = {}
    for label, keys in buckets:
        kind = "both"
        for cname, meta in classes.items():
            hay = (cname + " " + " ".join(meta.get("keywords", []))).lower()
            if any(k.lower() in hay for k in keys):
                a = meta.get("applies_to", "both")
                if a != "both":
                    kind = a
                    break
        bucket_applies[label] = kind

    lines: list[str] = []
    lines.append("# Detector Coverage Matrix")
    lines.append("")
    lines.append("Auto-generated by `tools/detector-coverage-matrix.py`.")
    lines.append("Topic buckets imported from `tools/finding-clusterer.py::BUCKETS`.")
    lines.append("")
    lines.append(f"- rust_wave1 detectors: **{sum(rust_counts.values())}**")
    lines.append(f"- wave17 detectors: **{sum(sol_counts.values())}**")
    lines.append("")
    lines.append("## Topic coverage")
    lines.append("")
    lines.append("| topic | rust_count | sol_count | parity_status |")
    lines.append("|---|---:|---:|---|")
    all_topics = [label for label, _ in buckets] + ["unclassified"]
    for label in all_topics:
        r = rust_counts.get(label, 0)
        s = sol_counts.get(label, 0)
        applies = bucket_applies.get(label, "both")
        status = parity_status(r, s, applies)
        lines.append(f"| {label} | {r} | {s} | {status} |")
    lines.append("")
    lines.append("## Recent additions in PR #84")
    lines.append("")
    lines.append("Grouped by topic (scanning last 200 commits for phase/mine/loop/cycle).")
    lines.append("")
    if not recents:
        lines.append("_No matching commits found._")
    for label, _ in buckets:
        entries = recents.get(label, [])
        if not entries:
            continue
        lines.append(f"### {label} ({len(entries)} commits)")
        lines.append("")
        for e in entries[:8]:
            lines.append(f"- `{e}`")
        if len(entries) > 8:
            lines.append(f"- ... +{len(entries) - 8} more")
        lines.append("")
    if gate_summary:
        lines.append("## Detectorization Gate Summary")
        lines.append("")
        lines.append(f"- Workspace: `{gate_summary.get('workspace', '')}`")
        advisories = gate_summary.get("advisories") if isinstance(gate_summary.get("advisories"), dict) else {}
        lines.append(f"- Scanner promotion advisories: `{advisories.get('count', 0)}`")
        lines.append(
            f"- Reportable advisories still blocked on exact impact contracts: "
            f"`{advisories.get('reportable_blocked', 0)}`"
        )
        lines.append("")
        by_lane = gate_summary.get("by_lane") if isinstance(gate_summary.get("by_lane"), dict) else {}
        if by_lane:
            lines.append("| lane | reportable_rows | mapped_rows | blocked_rows |")
            lines.append("|---|---:|---:|---:|")
            for lane, counts in sorted(by_lane.items()):
                lines.append(
                    f"| `{lane}` | {counts.get('reportable_rows', 0)} | "
                    f"{counts.get('mapped_rows', 0)} | {counts.get('blocked_rows', 0)} |"
                )
        else:
            lines.append("_No reportable detectorization rows found in the workspace inventory._")
        lines.append("")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, default=None)
    args = parser.parse_args()
    workspace = args.workspace.expanduser().resolve() if args.workspace else None
    buckets = _load("tools/finding-clusterer.py", "BUCKETS", [])
    if not buckets:
        print("[err] could not load BUCKETS from finding-clusterer.py")
        return 2
    classes = _load("tools/parity-report.py", "BUG_CLASSES", {})
    rust_counts = scan_dir(RUST_DIR, buckets)
    sol_counts = scan_dir(SOL_DIR, buckets)
    recents = recent_additions_by_topic(buckets)
    gate_summary = load_detectorization_gate_summary(workspace)

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(render(buckets, rust_counts, sol_counts, classes, recents, gate_summary))

    # stderr summary (stdout stays clean for redirect)
    total_r = sum(rust_counts.values())
    total_s = sum(sol_counts.values())
    print(f"[coverage-matrix] buckets={len(buckets)} rust={total_r} sol={total_s}")
    print(f"[coverage-matrix] wrote {OUT.relative_to(REPO)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
