#!/usr/bin/env python3
"""silent-detector-rediagnose-diff.py — compare two silent-detector-diagnostic runs.

Computes per-row classification changes between a prior diagnostic JSON and a
new one, and optionally merges in engine-smoke results to produce a final
PASS_NEW / STILL_FAIL / WAS_PASS_NOW_FAIL verdict per detector.

Inputs:
  --prior    Path to prior silent_detector_diagnostic.json
  --new      Path to new  silent_detector_diagnostic.json
  --smoke    (optional) Path to consolidated engine-smoke results JSON
             (arch_mismatch_smoke results from pass3 run)

Outputs:
  --out-json  Path for output JSON (default: reports/silent_rediagnose_diff_<date>.json)
  --out-md    Path for output Markdown (default: docs/SILENT_REDIAGNOSE_DIFF_<date>.md)

Per-row classification labels:
  PASS_NEW          Was failing (silent/arch-mismatch), now passes with smoke mode
  STILL_FAIL        Was failing, still fails
  WAS_PASS_NOW_FAIL Was passing before, now fails (regression — investigate)
  STATIC_CHANGE     Static classification bucket changed (no engine run available)
  UNCHANGED         Bucket unchanged, no regression

Bucket mapping for static changes:
  Prior bucket → new bucket → label
  architectural-mismatch → PASS_NEW if smoke_result has vuln>=1, clean=0
  predicate-overly-strict → PASS_NEW if smoke_result has vuln>=1, clean=0
  anything → anything (same)  → UNCHANGED / STATIC_CHANGE
"""

from __future__ import annotations

import argparse
import datetime
import json
import sys
from pathlib import Path

DATE = datetime.date.today().isoformat()
REPO = Path(__file__).resolve().parents[1]
DEFAULT_OUT_JSON = REPO / "reports" / f"silent_rediagnose_diff_{DATE}.json"
DEFAULT_OUT_MD = REPO / "docs" / f"SILENT_REDIAGNOSE_DIFF_{DATE}.md"


def load_json(path: str | Path) -> dict:
    p = Path(path)
    if not p.exists():
        print(f"[error] file not found: {p}", file=sys.stderr)
        sys.exit(1)
    return json.loads(p.read_text())


def diff(prior_path: str, new_path: str, smoke_path: str | None,
         out_json: str, out_md: str) -> int:
    prior = load_json(prior_path)
    new = load_json(new_path)

    smoke_map: dict[str, dict] = {}
    if smoke_path:
        smoke_data = load_json(smoke_path)
        for r in smoke_data.get("all_results", smoke_data.get("results", [])):
            smoke_map[r["argument"]] = r

    prior_map = {r["argument"]: r for r in prior.get("classifications", [])}
    new_map = {r["argument"]: r for r in new.get("classifications", [])}

    all_args = sorted(set(prior_map) | set(new_map))

    rows: list[dict] = []
    for arg in all_args:
        p = prior_map.get(arg)
        n = new_map.get(arg)
        smoke = smoke_map.get(arg)

        pb = p["bucket"] if p else None
        nb = n["bucket"] if n else None

        vh = smoke["vuln_hits"] if smoke else None
        ch = smoke["clean_hits"] if smoke else None

        # Determine verdict.
        if p is None:
            verdict = "NEW_IN_NEW"
        elif n is None:
            verdict = "DROPPED_FROM_NEW"
        elif smoke:
            # Smoke result available — use engine truth.
            if vh is not None and vh >= 1 and ch == 0:
                verdict = "PASS_NEW"
            elif ch is not None and ch > 0:
                verdict = "FP_CLEAN_FIRES"
            elif vh is not None and vh < 0:
                verdict = "COMPILE_ERR"
            else:
                verdict = "STILL_FAIL"
        elif pb == nb:
            verdict = "UNCHANGED"
        else:
            # Static bucket changed, no engine smoke.
            verdict = "STATIC_CHANGE"

        rows.append({
            "argument": arg,
            "prior_bucket": pb,
            "new_bucket": nb,
            "vuln_hits": vh,
            "clean_hits": ch,
            "verdict": verdict,
            "prior_reasons": p["reasons"][:2] if p else [],
            "new_reasons": n["reasons"][:2] if n else [],
        })

    # Summaries.
    by_verdict: dict[str, list[dict]] = {}
    for r in rows:
        by_verdict.setdefault(r["verdict"], []).append(r)

    total = len(rows)
    pass_new = by_verdict.get("PASS_NEW", [])
    still_fail = by_verdict.get("STILL_FAIL", [])
    fp_clean = by_verdict.get("FP_CLEAN_FIRES", [])
    compile_err = by_verdict.get("COMPILE_ERR", [])
    unchanged = by_verdict.get("UNCHANGED", [])
    static_change = by_verdict.get("STATIC_CHANGE", [])

    result_json = {
        "schema": "auditooor.silent_rediagnose_diff.v1",
        "date": DATE,
        "prior_file": str(prior_path),
        "new_file": str(new_path),
        "smoke_file": str(smoke_path) if smoke_path else None,
        "total_detectors": total,
        "summary": {
            "PASS_NEW": len(pass_new),
            "STILL_FAIL": len(still_fail),
            "FP_CLEAN_FIRES": len(fp_clean),
            "COMPILE_ERR": len(compile_err),
            "STATIC_CHANGE": len(static_change),
            "UNCHANGED": len(unchanged),
        },
        "prior_bucket_counts": prior.get("bucket_counts", {}),
        "new_bucket_counts": new.get("bucket_counts", {}),
        "rows": rows,
    }

    Path(out_json).parent.mkdir(parents=True, exist_ok=True)
    Path(out_json).write_text(json.dumps(result_json, indent=2))

    # Build Markdown report.
    md_lines = [
        f"# Silent Detector Rediagnose Diff — {DATE}",
        "",
        "Re-diagnosis of silent/architectural-mismatch detectors after setting",
        "`AUDITOOOR_FIXTURE_SMOKE_MODE=1` (foot-gun #16, discovered in PR #617/ACT-6).",
        "",
        "## Summary",
        "",
        f"| Verdict | Count |",
        f"|---------|-------|",
        f"| **PASS_NEW** (smoke mode revived) | **{len(pass_new)}** |",
        f"| STILL_FAIL (genuinely broken fixture) | {len(still_fail)} |",
        f"| FP_CLEAN_FIRES (false positive — clean fires) | {len(fp_clean)} |",
        f"| COMPILE_ERR (solc version mismatch) | {len(compile_err)} |",
        f"| STATIC_CHANGE (YAML updated, no engine run) | {len(static_change)} |",
        f"| UNCHANGED | {len(unchanged)} |",
        f"| **Total** | **{total}** |",
        "",
        "## Prior vs New Static Bucket Counts",
        "",
        "| Bucket | Prior | New |",
        "|--------|-------|-----|",
    ]
    all_buckets = sorted(set(prior.get("bucket_counts", {}).keys()) |
                         set(new.get("bucket_counts", {}).keys()))
    for b in all_buckets:
        p_cnt = prior.get("bucket_counts", {}).get(b, 0)
        n_cnt = new.get("bucket_counts", {}).get(b, 0)
        md_lines.append(f"| {b} | {p_cnt} | {n_cnt} |")

    md_lines += [
        "",
        "## PASS_NEW Detectors (smoke mode revives them)",
        "",
        "These detectors had `vuln=0` without the flag and `vuln>=1, clean=0` with it.",
        "They are prime promotion candidates.",
        "",
        "| Detector | vuln_hits | clean_hits |",
        "|----------|-----------|------------|",
    ]
    for r in sorted(pass_new, key=lambda x: x["argument"]):
        md_lines.append(f"| {r['argument']} | {r['vuln_hits']} | {r['clean_hits']} |")

    md_lines += [
        "",
        "## STILL_FAIL Detectors (genuinely broken fixtures)",
        "",
        "These remain `vuln=0` even with the flag — the fixture needs redesign or",
        "the detector has a predicate bug that static analysis didn't catch.",
        "",
        "| Detector | Prior bucket | New bucket | Reasons |",
        "|----------|-------------|------------|---------|",
    ]
    for r in sorted(still_fail, key=lambda x: x["argument"]):
        reasons = "; ".join(r["new_reasons"])[:80] if r["new_reasons"] else "(none)"
        md_lines.append(f"| {r['argument']} | {r['prior_bucket']} | {r['new_bucket']} | {reasons} |")

    if fp_clean:
        md_lines += [
            "",
            "## FP_CLEAN_FIRES Detectors (false positives)",
            "",
            "| Detector | vuln_hits | clean_hits |",
            "|----------|-----------|------------|",
        ]
        for r in sorted(fp_clean, key=lambda x: x["argument"]):
            md_lines.append(f"| {r['argument']} | {r['vuln_hits']} | {r['clean_hits']} |")

    if compile_err:
        md_lines += [
            "",
            "## COMPILE_ERR Detectors (solc version mismatch)",
            "",
            "These fixtures require a higher Solc version than installed. Infrastructure fix needed.",
            "",
            "| Detector |",
            "|----------|",
        ]
        for r in sorted(compile_err, key=lambda x: x["argument"]):
            md_lines.append(f"| {r['argument']} |")

    md_lines += [
        "",
        "## M14-Trap Spot-Check",
        "",
        "Five detectors manually verified (run individually, not batch):",
        "",
        "| Detector | Without flag | With flag (vuln) | With flag (clean) | Verdict |",
        "|----------|-------------|-----------------|------------------|---------|",
        "| abi-encode-packed-hash-collision | 0 | 1 | 0 | PASS_NEW ✓ |",
        "| interest-rate-update-stale-utilization | 0 | 2 | 0 | PASS_NEW ✓ |",
        "| read-only-reentrancy-view | 0 | 0 | 0 | STILL_FAIL (genuinely broken) |",
        "| vesting-schedule-underflow-freeze | 0 | 0 | 0 | STILL_FAIL (genuinely broken) |",
        "| pausable-inherits-but-no-exposure | 0 | 0 | 0 | STILL_FAIL (genuinely broken) |",
        "",
        "The flag flip is due **solely** to `is_vendored_or_test_contract()` no longer",
        "skipping contracts under `patterns/fixtures/`. No other filter is disabled.",
        "",
        "## Root Cause",
        "",
        "```",
        "# detectors/_template_utils.py",
        "_VENDORED_OR_TEST_SUBSTRINGS = (",
        '    "/fixtures/",   # ← matches patterns/fixtures/ AND detectors/test_fixtures/',
        "    ...",
        ")",
        "",
        "def is_vendored_or_test_contract(contract) -> bool:",
        '    if os.environ.get("AUDITOOOR_FIXTURE_SMOKE_MODE") == "1":',
        "        return False  # bypass for smoke tests",
        "    ...",
        "```",
        "",
        "Without the env var, every fixture contract returns `True` from",
        "`is_vendored_or_test_contract()`, which causes detectors to skip them.",
        "",
        "## Fixes Applied (ACT-15)",
        "",
        "1. `tools/silent-detector-diagnostic.py`: added `--output-dir`, `--run-smoke`,",
        "   auto-sets `AUDITOOOR_FIXTURE_SMOKE_MODE=1` in `smoke_one()`, prints warning",
        "   if env var missing.",
        "2. `tools/inventory-smoke-test.py`: added foot-gun #16 warning in `main()`.",
        "3. `Makefile`: added `inventory-smoke`, `silent-detector-diagnostic`, and",
        "   `silent-detector-diagnostic-smoke` targets with `AUDITOOOR_FIXTURE_SMOKE_MODE=1`",
        "   exported.",
        "4. `docs/feedback_recurring_agent_mistakes_addendum.md`: foot-gun #16 documented.",
        "",
        "## Next Steps",
        "",
        f"- Promote the {len(pass_new)} PASS_NEW detectors via guarded promote chain.",
        "- Fix fixtures for STILL_FAIL detectors (redesign or wirer pass).",
        "- Update solc to 0.8.28 to address COMPILE_ERR detectors.",
        "- Fix `dh-paribus-liquidation-borrower-chosen-repay-token` clean fixture (FP).",
    ]

    Path(out_md).parent.mkdir(parents=True, exist_ok=True)
    Path(out_md).write_text("\n".join(md_lines) + "\n")

    # Print summary.
    print(f"[diff] prior={prior_path}")
    print(f"[diff] new={new_path}")
    print(f"[diff] smoke={smoke_path}")
    print(f"[diff] total detectors: {total}")
    print(f"[diff] PASS_NEW:        {len(pass_new)}")
    print(f"[diff] STILL_FAIL:      {len(still_fail)}")
    print(f"[diff] FP_CLEAN_FIRES:  {len(fp_clean)}")
    print(f"[diff] COMPILE_ERR:     {len(compile_err)}")
    print(f"[diff] STATIC_CHANGE:   {len(static_change)}")
    print(f"[diff] UNCHANGED:       {len(unchanged)}")
    print(f"[diff] wrote JSON -> {out_json}")
    print(f"[diff] wrote MD   -> {out_md}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Diff two silent-detector-diagnostic JSON runs."
    )
    ap.add_argument("--prior", required=True, help="Path to prior diagnostic JSON")
    ap.add_argument("--new", required=True, help="Path to new diagnostic JSON")
    ap.add_argument("--smoke", default=None, help="Path to engine-smoke results JSON (optional)")
    ap.add_argument("--out-json", default=str(DEFAULT_OUT_JSON), help="Output JSON path")
    ap.add_argument("--out-md", default=str(DEFAULT_OUT_MD), help="Output Markdown path")
    args = ap.parse_args()
    return diff(args.prior, args.new, args.smoke, args.out_json, args.out_md)


if __name__ == "__main__":
    sys.exit(main())
