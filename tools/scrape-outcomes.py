#!/usr/bin/env python3
"""
scrape-outcomes.py — extract triage-outcome labels from Solodit cache (Issue #86)

Walks the cached Solodit raw JSON at detectors/_specs/solodit_raw/*.json and
produces reference/outcome_labels.yaml — one labeled row per finding.

Schema:
    - id: int                   # Solodit finding id
      title: str
      impact: HIGH|MEDIUM|LOW   # claimed severity
      quality_score: int        # 0-5 (88.8% are 0 per Issue #62)
      rarity_score: int
      finders_count: int        # 1 = primary, >1 = multi-find
      protocol_id: int
      auditfirm_id: int
      tags: str
      contest_link: str         # for diff-scraping (Issue #87)
      report_date: str
      sponsor_name: str
      outcome: paid|dupe|unknown  # derived
      outcome_reason: str

Outcome heuristic (Solodit doesn't expose payout directly — infer from
finders_count + quality_score + rarity):
  - finders_count == 1 AND quality_score >= 3 → primary/paid
  - finders_count >= 5 AND no distinguishing features → dupe-prone class
  - quality_score == 5 AND rarity >= 4 → high-value primary
  - else: unknown (we can't distinguish without triager comment parsing)

This is imperfect but gives a first-pass training label. Fine-tuning
requires per-finding triager-comment scraping from Code4rena/Cantina APIs,
which is beyond v1.

Usage:
    python3 tools/scrape-outcomes.py                    # scrape + write labels
    python3 tools/scrape-outcomes.py --summary          # stats on existing labels
"""

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

AUDITOOOR_DIR = Path(__file__).resolve().parent.parent
SOLODIT_RAW = AUDITOOOR_DIR / "detectors" / "_specs" / "solodit_raw"
OUTCOMES_OUT = AUDITOOOR_DIR / "reference" / "outcome_labels.yaml"


def infer_outcome(f):
    """Return (outcome, reason) per heuristic."""
    finders = int(f.get("finders_count", 1) or 1)
    qs = int(f.get("quality_score", 0) or 0)
    rs = int(f.get("rarity_score", 0) or 0)
    impact = (f.get("impact") or "").upper()

    if finders == 1 and qs >= 3:
        return "primary_likely_paid", f"solo find, quality={qs}"
    if finders == 1 and impact in ("HIGH", "CRITICAL"):
        return "primary_likely_paid", f"solo high-impact find"
    if finders >= 5:
        return "dupe_prone_class", f"{finders} finders → dedupe likely"
    if qs == 5 and rs >= 4:
        return "high_value_primary", f"top quality+rarity"
    if qs == 0 and finders == 1:
        return "unknown_unrated", "no quality signal"
    return "unknown", f"finders={finders}, qs={qs}, rs={rs}"


def scrape():
    import yaml

    if not SOLODIT_RAW.exists():
        print(f"[error] {SOLODIT_RAW} missing", file=sys.stderr)
        sys.exit(1)

    rows = []
    files = sorted(SOLODIT_RAW.glob("*.json"))
    print(f"[scrape] reading {len(files)} JSON files...")

    for jf in files:
        try:
            data = json.loads(jf.read_text())
        except Exception as e:
            print(f"  [warn] {jf.name}: {e}")
            continue
        for f in data.get("findings", []):
            outcome, reason = infer_outcome(f)
            rows.append({
                "id": f.get("id"),
                "title": (f.get("title") or "")[:200],
                "impact": (f.get("impact") or "").upper(),
                "quality_score": int(f.get("quality_score", 0) or 0),
                "rarity_score": int(f.get("rarity_score", 0) or 0),
                "finders_count": int(f.get("finders_count", 1) or 1),
                "protocol_id": f.get("protocol_id"),
                "auditfirm_id": f.get("auditfirm_id"),
                "tags": (f.get("tags") or "")[:200] if isinstance(f.get("tags"), str)
                         else ",".join(f.get("tags") or [])[:200],
                "contest_link": f.get("contest_link") or "",
                "report_date": f.get("report_date") or "",
                "sponsor_name": f.get("sponsor_name") or "",
                "outcome": outcome,
                "outcome_reason": reason,
            })

    print(f"[scrape] extracted {len(rows)} labeled findings")

    # Write YAML (capped at top-level for readability; full list as JSON in body)
    # Actually YAML is fine for ~20k rows, ~5MB.
    data = {
        "version": 1,
        "source": "solodit_raw heuristic inference",
        "count": len(rows),
        "outcome_distribution": dict(Counter(r["outcome"] for r in rows).most_common()),
        "severity_distribution": dict(Counter(r["impact"] for r in rows).most_common()),
        "rows": rows,
    }
    OUTCOMES_OUT.write_text(yaml.safe_dump(data, sort_keys=False, default_flow_style=False))
    print(f"[scrape] wrote {OUTCOMES_OUT}")

    print(f"\n  Outcome distribution:")
    for k, v in data["outcome_distribution"].items():
        pct = 100 * v / len(rows)
        print(f"    {k:30s} {v:>6d}  ({pct:.1f}%)")
    print(f"\n  Severity distribution:")
    for k, v in data["severity_distribution"].items():
        print(f"    {k:30s} {v:>6d}")


def summary():
    import yaml
    if not OUTCOMES_OUT.exists():
        print(f"[error] {OUTCOMES_OUT} missing — run without --summary first")
        sys.exit(1)
    data = yaml.safe_load(OUTCOMES_OUT.read_text())
    print(f"  Labeled rows: {data.get('count')}")
    print(f"  Outcomes:     {data.get('outcome_distribution')}")
    print(f"  Severities:   {data.get('severity_distribution')}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--summary", action="store_true")
    args = ap.parse_args()
    if args.summary:
        summary()
    else:
        scrape()


if __name__ == "__main__":
    main()
