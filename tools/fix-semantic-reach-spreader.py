#!/usr/bin/env python3
"""fix-semantic-reach-spreader.py - auto-feed missing-guard-callsite enumeration from prior_audits/.

r36-rebuttal: registered lane mimo-harness-build-2026-05-27.

Wraps tools/missing-guard-callsite-enumerator.sh (L30 helper) to:
  1. Parse prior_audits/*.{md,txt,pdf-extracted} for findings citing a guard.
  2. For each prior finding, extract guard name + protected sites.
  3. Grep workspace audit-pin tree for ALL call sites of that guard.
  4. Subtract: protected sites are CITED in fix-commit; unprotected sites are
     the candidate findings NOW (because the team patched some sites but not all).

Output JSONL with one record per prior finding:
  {prior_finding_id, guard_name, protected_sites: [...], unprotected_sites: [...]}

Schema: auditooor.fix_reach_audit.v1

USAGE:
  python3 tools/fix-semantic-reach-spreader.py --workspace ~/audits/<ws> \
    --prior-audits-dir ~/audits/<ws>/prior_audits --output <path.jsonl>
"""
from __future__ import annotations

import argparse
import glob
import json
import re
import subprocess
import sys
from pathlib import Path

SCHEMA = "auditooor.fix_reach_audit.v1"

GUARD_RE = re.compile(
    r"(?:require|onlyOwner|onlyAdmin|modifier|validate|assert|check|"
    r"verify|guard|require_root|ensure_signed|require!)\s*[\(_]?\s*"
    r"([a-zA-Z_][a-zA-Z0-9_]+)",
    re.IGNORECASE,
)


def parse_prior_audits(prior_dir: Path) -> list[dict]:
    """Skim prior_audits/* for guard-name mentions."""
    findings = []
    if not prior_dir.is_dir():
        return findings
    for f in glob.glob(str(prior_dir / "**" / "*"), recursive=True):
        if not Path(f).is_file():
            continue
        if not any(f.endswith(ext) for ext in (".md", ".txt", ".extracted")):
            continue
        try:
            text = Path(f).read_text(encoding="utf-8", errors="replace")[:50000]
        except Exception:
            continue
        # Find finding IDs (cantina-NNN, sec-NNN, F-NNN, NNN)
        for m in re.finditer(
            r"(?:^|\n)(?:#+\s*)?(?:Finding|Issue|F|H|M|L)[-\s#]?(\d+)[^\n]*\n",
            text,
        ):
            fid_num = m.group(1)
            section = text[m.end():m.end() + 3000]
            guard_matches = GUARD_RE.findall(section)
            if guard_matches:
                findings.append({
                    "prior_finding_id": f"{Path(f).stem}:F{fid_num}",
                    "source_file": str(f),
                    "guard_candidates": list(set(guard_matches))[:5],
                    "section_excerpt": section[:400],
                })
    return findings


def find_callsites(workspace: Path, guard_name: str) -> list[str]:
    """grep workspace for callsites of a guard function."""
    if not workspace.is_dir() or not guard_name:
        return []
    try:
        r = subprocess.run(
            ["grep", "-rn", "--include=*.sol", "--include=*.rs",
             "--include=*.go", guard_name, str(workspace)],
            timeout=30, capture_output=True, text=True,
        )
        if r.returncode != 0:
            return []
        return [l for l in r.stdout.strip().split("\n") if l][:50]
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return []


def classify_sites(sites: list[str], guard_name: str) -> tuple[list[str], list[str]]:
    """Split sites into protected (the guard is called here) vs unprotected
    (looks like it should call the guard but doesn't)."""
    protected = []
    unprotected = []
    for site in sites:
        if f"{guard_name}(" in site or f"{guard_name} (" in site:
            protected.append(site)
        else:
            unprotected.append(site)
    return protected, unprotected


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--workspace", required=True)
    p.add_argument("--prior-audits-dir", required=True)
    p.add_argument("--output", required=True)
    p.add_argument("--json", action="store_true")
    args = p.parse_args(argv)

    ws = Path(args.workspace)
    prior = Path(args.prior_audits_dir)
    out_path = Path(args.output)

    findings = parse_prior_audits(prior)
    sys.stderr.write(f"[fix-reach] parsed {len(findings)} prior findings\n")

    records = []
    for f in findings:
        for g in f["guard_candidates"][:3]:
            sites = find_callsites(ws, g)
            protected, unprotected = classify_sites(sites, g)
            records.append({
                "schema_version": SCHEMA,
                "prior_finding_id": f["prior_finding_id"],
                "guard_name": g,
                "protected_sites": protected,
                "unprotected_sites": unprotected,
                "unprotected_count": len(unprotected),
                "source_file": f["source_file"],
            })

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w") as fh:
        for r in records:
            fh.write(json.dumps(r) + "\n")
    sys.stderr.write(f"[fix-reach] wrote {len(records)} records to {out_path}\n")

    if args.json:
        print(json.dumps({"records": len(records), "out": str(out_path)}, indent=2))
    else:
        unprot = sum(1 for r in records if r["unprotected_count"])
        print(f"prior findings parsed: {len(findings)} | guard reach records: {len(records)} | "
              f"with unprotected sites: {unprot}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
