#!/usr/bin/env python3
"""cross-engagement-learner.py — cross-workspace pattern + detector-gap learner.

Indexes every workspace's SUBMISSIONS.md across ~/audits/ (read-only), classifies
each indexed finding against tools/parity-report.py::BUG_CLASSES keyword sets,
and emits a markdown report covering:

  a) Detector-gap per workspace (findings whose shape no BUG_CLASS matches).
  b) Cross-workspace pattern mirrors (BUG_CLASS used in ≥2 workspaces).
  c) Single-workspace patterns (BUG_CLASS used in only 1 workspace).
  d) Unique-shape inventory (per-class count across the corpus).
  e) "Would auditooor catch our own bugs?" per-workspace catch-rate table.

Pure stdlib. Workspaces missing or empty are SKIPPED gracefully.

CLI:
    tools/cross-engagement-learner.py [--out docs/archive/CROSS_ENGAGEMENT_LEARNINGS.md]
"""
from __future__ import annotations

import argparse
import importlib.util
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PARITY_TOOL = ROOT / "tools" / "parity-report.py"
AUDITS_ROOT = Path.home() / "audits"
WORKSPACES = ["polymarket", "centrifuge-v3", "morpho", "kiln-v1", "snowbridge", "k2"]

# Heading regex: matches `### Draft N — Title`, `## S-001 — Title`,
# `## #418 — Title`, `### #I2.B — Title`, `# Submission 2 — #I2.A — Critical`,
# and similar finding-block anchors. Skips toplevel "## 1. Submitted to Cantina"
# style index headings (handled below by the leading-number filter).
HEADING_RE = re.compile(
    r"^(?P<hashes>#{1,4})\s+"
    r"(?:[\U0001F600-\U0001FAFF\u2600-\u27BF]\s+)?"  # leading emoji ok
    r"(?P<body>(?:Submission\s+\d+|Draft\s+\d+|S-\d+|#[A-Za-z0-9.\-]+)"
    r"(?:\s+[—-]\s+.+)?)\s*$"
)
# Simple "## 3. Ready to submit" / "## 1. Submitted to Cantina" — IGNORE
SECTION_RE = re.compile(r"^#{1,3}\s+\d+\.\s")
# Submitted-table row (polymarket Section 1):
#   | **182** | 2026-04-17 | Medium | Pending | <title with backticks> |
TABLE_ROW_RE = re.compile(
    r"^\|\s*\*\*(?P<id>\d+)\*\*\s*\|\s*[^|]*\|\s*(?P<sev>[A-Za-z]+)\s*\|\s*[^|]*\|\s*(?P<title>[^|]+?)\s*\|\s*$"
)

# Severity capture inside finding bodies
SEV_LINE_RE = re.compile(r"(?im)^\s*[-*]?\s*\*?\*?Severity\*?\*?\s*[:\-]?\s*(?:\n\s*)?([A-Za-z]+)")
SEV_INLINE_RE = re.compile(r"(?im)Severity\s*:\s*([A-Za-z]+)")
TARGET_FILE_RE = re.compile(r"(?im)Target\s+(?:files?|asset)[^\n]*?[`\"]([^`\"\n]+\.(?:sol|rs|move|cairo))[`\"]")
CONTRACT_RE = re.compile(r"(?im)([A-Z][A-Za-z0-9_]+)\.(?:[a-zA-Z_][a-zA-Z0-9_]*)\s*\(")
FUNCTION_RE = re.compile(r"(?im)`([a-zA-Z_][a-zA-Z0-9_]+)\s*\(")


def import_parity():
    spec = importlib.util.spec_from_file_location("parity_report", PARITY_TOOL)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


def find_submissions_files(ws: str) -> list[Path]:
    """Return all candidate SUBMISSIONS.md files for a workspace, in priority order."""
    base = AUDITS_ROOT / ws
    if not base.is_dir():
        return []
    paths = []
    # Primary canonical locations
    for cand in (base / "SUBMISSIONS.md", base / "submissions" / "SUBMISSIONS.md"):
        if cand.is_file():
            paths.append(cand)
    return paths


def split_findings(text: str) -> list[tuple[str, str]]:
    """Split a SUBMISSIONS.md body into (title, body) chunks per finding heading."""
    lines = text.splitlines()
    chunks: list[tuple[str, list[str]]] = []
    current: tuple[str, list[str]] | None = None
    for line in lines:
        if SECTION_RE.match(line):
            # Toplevel section break flushes current chunk
            if current:
                chunks.append(current)
                current = None
            continue
        m = HEADING_RE.match(line)
        if m:
            if current:
                chunks.append(current)
            title = m.group("body").strip()
            current = (title, [])
            continue
        # Submitted-table rows are self-contained one-line findings.
        tr = TABLE_ROW_RE.match(line)
        if tr:
            if current:
                chunks.append(current)
                current = None
            row_title = f"#{tr.group('id')} — {tr.group('title').strip()}"
            row_body = f"Severity: {tr.group('sev').strip()}\n{tr.group('title').strip()}"
            chunks.append((row_title, [row_body]))
            continue
        if current is not None:
            current[1].append(line)
    if current:
        chunks.append(current)
    return [(t, "\n".join(buf)) for t, buf in chunks]


def extract_finding(title_raw: str, body: str) -> dict:
    title = title_raw.strip().strip("—-").strip()
    sev = "Unknown"
    m = SEV_LINE_RE.search(body) or SEV_INLINE_RE.search(body)
    if m:
        cand = m.group(1).strip()
        if cand and cand[0].isalpha() and len(cand) <= 16:
            sev = cand.capitalize()
    contract = ""
    fc = CONTRACT_RE.search(body)
    if fc:
        contract = fc.group(1)
    func = ""
    ff = FUNCTION_RE.search(body)
    if ff:
        func = ff.group(1)
    short = ""
    for ln in body.splitlines():
        s = ln.strip()
        if not s or s.startswith("#") or s.startswith("-") or s.startswith("*") or s.startswith("|"):
            continue
        short = s[:240]
        break
    return {
        "title": title,
        "severity": sev,
        "contract": contract,
        "function": func,
        "short_description": short,
    }


def classify_finding(parity, title: str, body: str) -> tuple[list[str], int]:
    """Return (matched_classes, top_score). Score = number of distinct keyword
    occurrences across title+body (capped per class). 0 means no match."""
    blob = f"{title}\n{body}".lower().replace("_", "-")
    hits: dict[str, int] = {}
    for cls, meta in parity.BUG_CLASSES.items():
        score = 0
        for kw in meta["keywords"]:
            if kw in blob:
                score += 1
        if score:
            hits[cls] = score
    if not hits:
        return [], 0
    top = max(hits.values())
    winners = [c for c, s in hits.items() if s == top]
    return winners, top


def index_workspace(ws: str, parity) -> tuple[list[dict], str]:
    """Return (findings, status_msg). Each finding: dict with workspace key set."""
    files = find_submissions_files(ws)
    if not files:
        return [], f"SKIPPED (no SUBMISSIONS.md found under ~/audits/{ws}/)"
    findings: list[dict] = []
    for fp in files:
        try:
            text = fp.read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            return [], f"SKIPPED (read error on {fp}: {e})"
        for title_raw, body in split_findings(text):
            f = extract_finding(title_raw, body)
            if not f["title"] or len(f["title"]) < 4:
                continue
            classes, score = classify_finding(parity, f["title"], body)
            f["workspace"] = ws
            f["source_file"] = str(fp.relative_to(Path.home())) if fp.is_relative_to(Path.home()) else str(fp)
            f["classes"] = classes
            f["score"] = score
            findings.append(f)
    if not findings:
        return [], f"SKIPPED ({files[0].name} present but no finding headings parsed)"
    return findings, f"indexed {len(findings)} finding(s) from {len(files)} file(s)"


def build_report(workspace_results: dict[str, tuple[list[dict], str]], parity) -> str:
    SCORE_THRESHOLD = 1  # findings with score < threshold = detector gap

    all_findings: list[dict] = []
    for ws, (fs, _) in workspace_results.items():
        all_findings.extend(fs)

    # (a) Detector gap per workspace
    gaps: dict[str, list[dict]] = defaultdict(list)
    for f in all_findings:
        if f["score"] < SCORE_THRESHOLD or not f["classes"]:
            gaps[f["workspace"]].append(f)

    # (b/c) Cross- vs single-workspace patterns
    cls_workspaces: dict[str, set[str]] = defaultdict(set)
    cls_count: Counter = Counter()
    for f in all_findings:
        for c in f["classes"]:
            cls_workspaces[c].add(f["workspace"])
            cls_count[c] += 1
    mirrors = {c: ws for c, ws in cls_workspaces.items() if len(ws) >= 2}
    singles = {c: ws for c, ws in cls_workspaces.items() if len(ws) == 1 and c != "unclassified"}

    # (d) Unique-shape inventory (already cls_count)

    # (e) "Would auditooor catch our own bugs?" per workspace
    catch: dict[str, tuple[int, int]] = {}
    for ws, (fs, _) in workspace_results.items():
        if not fs:
            continue
        n = sum(1 for f in fs if f["score"] >= SCORE_THRESHOLD and f["classes"])
        catch[ws] = (n, len(fs))

    # ---- assemble markdown ----
    out: list[str] = []
    out.append("# Cross-Engagement Learnings (auto-generated)\n")
    out.append(f"_Generated by `tools/cross-engagement-learner.py` from {len(all_findings)} indexed findings across "
               f"{sum(1 for fs, _ in workspace_results.values() if fs)} workspace(s)._\n")
    out.append("")
    out.append("## Workspace index status\n")
    out.append("| Workspace | Status |")
    out.append("|---|---|")
    for ws in WORKSPACES:
        _, status = workspace_results.get(ws, ([], "SKIPPED (not requested)"))
        out.append(f"| `{ws}` | {status} |")
    out.append("")

    out.append("## (e) Catch-rate — would auditooor catch our own bugs?\n")
    out.append("Per-workspace fraction of submissions whose shape plausibly matches at least one BUG_CLASS keyword set "
               "in `tools/parity-report.py`. Higher = better library coverage of that workspace's bug surface.\n")
    out.append("| Workspace | Caught (N) | Total (M) | Catch % |")
    out.append("|---|---:|---:|---:|")
    overall_n = overall_m = 0
    for ws in WORKSPACES:
        if ws not in catch:
            continue
        n, m = catch[ws]
        pct = (100.0 * n / m) if m else 0.0
        overall_n += n
        overall_m += m
        out.append(f"| `{ws}` | {n} | {m} | {pct:.1f}% |")
    if overall_m:
        out.append(f"| **TOTAL** | **{overall_n}** | **{overall_m}** | **{100.0*overall_n/overall_m:.1f}%** |")
    out.append("")

    out.append("## (a) Detector gaps per workspace\n")
    out.append("Findings whose shape did not match any BUG_CLASS keyword above the score threshold "
               f"(< {SCORE_THRESHOLD}). These are library-coverage holes — candidates for new detectors.\n")
    if not gaps:
        out.append("_None — every indexed finding matched at least one class._\n")
    for ws in WORKSPACES:
        ws_gaps = gaps.get(ws, [])
        if not ws_gaps:
            continue
        out.append(f"### `{ws}` — {len(ws_gaps)} gap finding(s)\n")
        for g in ws_gaps:
            sev = g["severity"]
            ctx = f" — `{g['contract']}.{g['function']}`" if (g["contract"] or g["function"]) else ""
            out.append(f"- detector missing for **{ws}**: _{g['title'][:160]}_  ({sev}{ctx})")
        out.append("")

    out.append("## (b) Cross-workspace pattern mirrors\n")
    out.append("BUG_CLASS submitted in ≥2 workspaces. Indicates a generalizable pattern that warrants a detector "
               "on BOTH the Solidity and Rust sides of the library.\n")
    if not mirrors:
        out.append("_None — every classified pattern is workspace-unique._\n")
    else:
        out.append("| BUG_CLASS | Workspaces | applies_to | Total findings |")
        out.append("|---|---|---|---:|")
        for c in sorted(mirrors, key=lambda x: (-len(mirrors[x]), -cls_count[x], x)):
            ws_list = ", ".join(sorted(mirrors[c]))
            applies = parity.BUG_CLASSES.get(c, {}).get("applies_to", "?")
            out.append(f"| `{c}` | {ws_list} | {applies} | {cls_count[c]} |")
    out.append("")

    out.append("## (c) Single-workspace patterns\n")
    out.append("BUG_CLASS submitted in ONLY one workspace. Likely workspace-specific — but flag as "
               "_'detector may be too narrow (only fires on this flavor)'_.\n")
    if not singles:
        out.append("_None._\n")
    else:
        out.append("| BUG_CLASS | Workspace | Findings | applies_to |")
        out.append("|---|---|---:|---|")
        for c in sorted(singles, key=lambda x: (-cls_count[x], x)):
            ws = next(iter(singles[c]))
            applies = parity.BUG_CLASSES.get(c, {}).get("applies_to", "?")
            out.append(f"| `{c}` | {ws} | {cls_count[c]} | {applies} |")
    out.append("")

    out.append("## (d) Unique-shape inventory (per-class count)\n")
    if not cls_count:
        out.append("_No classes matched._\n")
    else:
        out.append("| BUG_CLASS | # findings | # workspaces |")
        out.append("|---|---:|---:|")
        for c, n in sorted(cls_count.items(), key=lambda x: (-x[1], x[0])):
            out.append(f"| `{c}` | {n} | {len(cls_workspaces[c])} |")
    out.append("")
    out.append("---")
    out.append("_End of report._")
    return "\n".join(out) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Cross-engagement learner.")
    ap.add_argument("--out", default="docs/archive/CROSS_ENGAGEMENT_LEARNINGS.md",
                    help="output markdown path (relative to repo root)")
    args = ap.parse_args(argv)

    parity = import_parity()
    results: dict[str, tuple[list[dict], str]] = {}
    for ws in WORKSPACES:
        fs, status = index_workspace(ws, parity)
        results[ws] = (fs, status)
        print(f"[{ws}] {status}", file=sys.stderr)

    md = build_report(results, parity)
    out_path = (ROOT / args.out).resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(md, encoding="utf-8")
    total = sum(len(fs) for fs, _ in results.values())
    print(f"wrote {out_path.relative_to(ROOT)} — {total} findings indexed", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
