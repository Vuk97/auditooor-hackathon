#!/usr/bin/env python3
"""artifact-learning-loop.py - extract patterns from agent artifacts and emit weekly digest.

r36-rebuttal: registered lane mimo-harness-build-2026-05-27.

Operator question: "how are we learning from agent artifacts?"
Answer: this tool. It ingests ALL agent artifact sources, extracts patterns,
identifies which hypotheses yield real findings vs noise, surfaces
detector FP/FN gaps, and produces a markdown digest.

ARTIFACT SOURCES (auto-discovered):
  - audit/corpus_tags/derived/mimo_harness_*/*.json     (MIMO bulk-hunt outputs)
  - audit/corpus_tags/derived/mimo_reeval/*.json        (MIMO re-eval verdicts)
  - audit/corpus_tags/derived/mimo_mega_wave/*.json     (MIMO MEGA-wave outputs)
  - /Users/wolf/audits/*/agent_outputs/*                (Claude Agent drill outputs)
  - /Users/wolf/audits/*/submissions/_killed/*          (killed drafts)
  - /Users/wolf/audits/*/submissions/filed/*            (filed drafts)
  - tools/calibration/llm_budget_log.jsonl              (cost telemetry)

OUTPUT:
  - reports/learning_loop_<date>.md   (markdown digest)
  - reports/learning_loop_<date>.json (machine-readable)

USAGE:
  python3 tools/artifact-learning-loop.py [--since 7d] [--out reports/learning.md]
"""
from __future__ import annotations

import argparse
import collections
import glob
import json
import os
import re
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

AUDITOOOR_ROOT = Path(__file__).resolve().parent.parent
AUDITS_ROOT = Path.home() / "audits"


def iso_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_since(s: str) -> float:
    """Parse '7d' '24h' '30m' into a Unix timestamp cutoff."""
    if not s:
        return 0.0
    m = re.match(r"^(\d+)([dhm])$", s.strip())
    if not m:
        return 0.0
    n = int(m.group(1))
    unit = m.group(2)
    secs = {"d": 86400, "h": 3600, "m": 60}[unit] * n
    return time.time() - secs


def collect_mimo_harness(cutoff: float) -> list[dict]:
    """Walk audit/corpus_tags/derived/mimo_harness_*/ and parse each sidecar."""
    out = []
    for f in glob.glob(str(AUDITOOOR_ROOT / "audit/corpus_tags/derived/mimo_harness_*/*.json")):
        try:
            st = os.stat(f)
            if cutoff and st.st_mtime < cutoff:
                continue
            d = json.load(open(f))
            if d.get("status") != "ok":
                out.append({"file": f, "status": "failed", "applies": None,
                             "workspace": f.split("mimo_harness_")[1].split("/")[0]})
                continue
            r = d.get("result", "")
            body = r.strip().strip("`").lstrip("json").strip() if isinstance(r, str) else ""
            try:
                j = json.loads(body)
                out.append({
                    "file": f, "status": "ok",
                    "workspace": f.split("mimo_harness_")[1].split("/")[0],
                    "applies": j.get("applies_to_target"),
                    "severity": j.get("severity_estimate"),
                    "novel": j.get("novel_angle_score"),
                    "finding": j.get("candidate_finding", "")[:200],
                    "file_hint": j.get("file_path_hint", ""),
                })
            except Exception:
                out.append({"file": f, "status": "parse-fail", "applies": None,
                             "workspace": f.split("mimo_harness_")[1].split("/")[0]})
        except Exception:
            continue
    return out


def collect_killed_drafts(cutoff: float) -> list[dict]:
    """Walk ~/audits/*/submissions/_killed/ for kill reasons."""
    out = []
    if not AUDITS_ROOT.is_dir():
        return out
    for f in glob.glob(str(AUDITS_ROOT / "*/submissions/_killed/**/*.md"), recursive=True):
        try:
            st = os.stat(f)
            if cutoff and st.st_mtime < cutoff:
                continue
            text = Path(f).read_text(errors="replace")[:3000]
            kill_match = re.search(r"(?:KILL|kill|killed)[:\s-]+([^\n]{1,200})", text)
            ws = Path(f).parts[Path(f).parts.index("audits") + 1] if "audits" in Path(f).parts else "?"
            out.append({
                "file": f, "workspace": ws,
                "kill_reason": kill_match.group(1).strip() if kill_match else "<unknown>",
                "mtime": datetime.fromtimestamp(st.st_mtime, timezone.utc).strftime("%Y-%m-%d"),
            })
        except Exception:
            continue
    return out


def collect_filed_drafts() -> list[dict]:
    out = []
    if not AUDITS_ROOT.is_dir():
        return out
    for f in glob.glob(str(AUDITS_ROOT / "*/submissions/filed/**/*.md"), recursive=True):
        try:
            ws = Path(f).parts[Path(f).parts.index("audits") + 1] if "audits" in Path(f).parts else "?"
            slug = Path(f).stem
            out.append({"file": f, "workspace": ws, "slug": slug})
        except Exception:
            continue
    return out


def extract_attack_class(finding: str) -> str:
    """Heuristic: pull a one-word attack class from a finding sentence."""
    if not finding:
        return "unknown"
    keywords = [
        ("replay", "replay"), ("reentrancy", "reentrancy"), ("oracle", "oracle-staleness"),
        ("nonce", "nonce-ordering"), ("approve", "allowance-rotation"),
        ("merkle", "merkle-binding"), ("overflow", "integer-overflow"),
        ("underflow", "integer-underflow"), ("rounding", "rounding-precision"),
        ("liquidation", "liquidation-edge"), ("slippage", "slippage"),
        ("front-run", "front-running"), ("MEV", "mev"),
        ("access control", "access-control"), ("authoriz", "access-control"),
        ("cross-chain", "cross-chain-binding"), ("bridge", "bridge-settlement"),
        ("dos", "dos"), ("denial of service", "dos"),
        ("storage collision", "storage-collision"), ("init", "initialization"),
    ]
    f = finding.lower()
    for keyword, klass in keywords:
        if keyword in f:
            return klass
    return "uncategorized"


def build_digest(harness: list[dict], killed: list[dict], filed: list[dict]) -> str:
    """Build a markdown digest from the collected artifacts."""
    lines = [
        f"# Artifact Learning Loop Digest - {iso_now()}",
        "",
        "Auto-generated from `tools/artifact-learning-loop.py`. Source artifacts:",
        f"  - MIMO harness sidecars: {len(harness)}",
        f"  - Killed drafts: {len(killed)}",
        f"  - Filed drafts: {len(filed)}",
        "",
        "## 1. MIMO harness verdicts by workspace",
        "",
    ]
    by_ws = collections.defaultdict(lambda: collections.Counter())
    for h in harness:
        by_ws[h.get("workspace", "?")][h.get("applies", "no-parse") or "no-parse"] += 1
    lines.append("| Workspace | YES | MAYBE | NO | failed/no-parse |")
    lines.append("|---|---|---|---|---|")
    for ws, c in sorted(by_ws.items()):
        lines.append(f"| {ws} | {c.get('yes',0)} | {c.get('maybe',0)} | {c.get('no',0)} | "
                     f"{c.get('failed',0)+c.get('parse-fail',0)+c.get('no-parse',0)} |")
    lines.append("")

    lines.append("## 2. Attack-class frequency (top 15)")
    klass_counter = collections.Counter()
    for h in harness:
        if h.get("applies") in ("yes", "maybe"):
            klass_counter[extract_attack_class(h.get("finding", ""))] += 1
    lines.append("")
    for klass, n in klass_counter.most_common(15):
        lines.append(f"  - {klass}: {n}")
    lines.append("")

    lines.append("## 3. YES candidates (real signal)")
    lines.append("")
    yes_cands = [h for h in harness if h.get("applies") == "yes"]
    if yes_cands:
        for c in yes_cands:
            lines.append(f"  - [{c.get('workspace')}/{c.get('severity')}/n{c.get('novel')}] "
                         f"{c.get('file_hint','?')}: {c.get('finding','')[:150]}")
    else:
        lines.append("  (none in current window)")
    lines.append("")

    lines.append("## 4. Killed drafts (lessons)")
    lines.append("")
    if killed:
        kill_reason_counter = collections.Counter(k["kill_reason"][:80] for k in killed)
        for reason, n in kill_reason_counter.most_common(10):
            lines.append(f"  - x{n}: {reason}")
    else:
        lines.append("  (none in window)")
    lines.append("")

    lines.append("## 5. Filed drafts inventory")
    lines.append("")
    by_ws_filed = collections.defaultdict(list)
    for f in filed:
        by_ws_filed[f["workspace"]].append(f["slug"])
    for ws, slugs in sorted(by_ws_filed.items()):
        lines.append(f"  - **{ws}** ({len(slugs)}): " + ", ".join(slugs[:5])
                     + (" ..." if len(slugs) > 5 else ""))
    lines.append("")

    lines.append("## 6. Detector / hypothesis tuning recommendations")
    lines.append("")
    no_count = sum(1 for h in harness if h.get("applies") == "no")
    maybe_count = sum(1 for h in harness if h.get("applies") == "maybe")
    total_ok = sum(1 for h in harness if h.get("status") == "ok")
    if total_ok > 0:
        no_pct = 100 * no_count // total_ok
        maybe_pct = 100 * maybe_count // total_ok
        lines.append(f"  - {no_pct}% of MIMO outputs are applies=no (high-noise hypotheses; "
                     f"consider tightening hacker_questions corpus)")
        lines.append(f"  - {maybe_pct}% are applies=maybe (worth re-eval batches with deeper source context)")
    if klass_counter:
        top_klass = klass_counter.most_common(1)[0]
        lines.append(f"  - Most-flagged attack class: {top_klass[0]} ({top_klass[1]} hits) "
                     f"-> consider dedicated detector / pattern in tools/")
    lines.append("")

    return "\n".join(lines)


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(description="artifact learning loop digest")
    p.add_argument("--since", default="7d", help="Time window: 7d, 24h, 30m (default: 7d)")
    p.add_argument("--out", default=None, help="Output markdown path (default: reports/learning_loop_<date>.md)")
    p.add_argument("--json-out", default=None, help="Optional JSON sidecar path")
    args = p.parse_args(argv)

    cutoff = parse_since(args.since)
    sys.stderr.write(f"[learning-loop] cutoff={cutoff:.0f} ({args.since})\n")

    harness = collect_mimo_harness(cutoff)
    killed = collect_killed_drafts(cutoff)
    filed = collect_filed_drafts()

    sys.stderr.write(f"[learning-loop] ingested: harness={len(harness)} killed={len(killed)} filed={len(filed)}\n")

    digest = build_digest(harness, killed, filed)
    out_md = args.out or str(AUDITOOOR_ROOT / "reports" / f"learning_loop_{datetime.now().strftime('%Y-%m-%d')}.md")
    Path(out_md).parent.mkdir(parents=True, exist_ok=True)
    Path(out_md).write_text(digest)
    sys.stderr.write(f"[learning-loop] wrote {out_md} ({len(digest)} chars)\n")

    if args.json_out:
        Path(args.json_out).write_text(json.dumps({
            "timestamp": iso_now(), "window": args.since,
            "counts": {"harness": len(harness), "killed": len(killed), "filed": len(filed)},
            "harness": harness, "killed": killed, "filed": filed,
        }, indent=2))
        sys.stderr.write(f"[learning-loop] wrote {args.json_out}\n")

    print(digest)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
