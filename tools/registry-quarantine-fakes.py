#!/usr/bin/env python3
"""registry-quarantine-fakes.py — codify the no-yaml-synthesis fake-detector
quarantine guard from the 2026-05-04 random-sample audit
(`docs/VERIFIED_AUDIT_2026-05-04.md`).

The audit found that 5/30 sampled "verified" detectors had been promoted
through a `no-yaml-synthesis` shortcut where `verified: true` was set
because the .py compiled — NOT because a differential smoke test passed.
Wilson 95% CI projected ~92/540 verified detectors are silently dead.

This tool walks every Tier-A/B/S row in `detectors/_tier_registry.yaml`,
flags those whose `reason` carries the no-yaml-synthesis fingerprint
(`vuln_hits=n/a` OR `smoke=no_fixture_compile_ok`), runs a differential
smoke test against any paired vuln/clean fixture, and downgrades rows
that fail (or have no fixture) to PAPER.

Idempotent:
  - Rows already at tier=PAPER are skipped.
  - Re-running on a clean registry produces 0 downgrades.

Exit codes:
  0 — registry was already clean OR --apply succeeded.
  1 — fakes detected, --apply not given (dry-run flag mode for CI).
  2 — invalid args / cannot read registry.

Usage:
  python3 tools/registry-quarantine-fakes.py                # dry-run (CI gate)
  python3 tools/registry-quarantine-fakes.py --apply        # mutate registry
  python3 tools/registry-quarantine-fakes.py --json-out X   # write summary
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[1]
TIER_REGISTRY = REPO / "detectors" / "_tier_registry.yaml"
RUN_CUSTOM = REPO / "detectors" / "run_custom.py"
SLITHER_PYTHON = "/opt/homebrew/opt/python@3.13/bin/python3.13"
HIGH_TIERS = {"S", "A", "B"}
SUSPECT_REASON_FRAGMENT = "no-yaml-synthesis"
SUSPECT_NEVER_FIRED = ("vuln_hits=n/a", "smoke=no_fixture_compile_ok")
QUARANTINE_TAG = "no-yaml-fake-quarantine"


def find_fixtures(arg: str) -> tuple[Path | None, Path | None]:
    """Mirror of registry-disk-consistency-check.find_fixtures()."""
    snake = arg.replace("-", "_")
    cand_v = [
        REPO / "detectors" / "test_fixtures" / f"{snake}_vulnerable.sol",
        REPO / "detectors" / "test_fixtures" / f"{snake}_vuln.sol",
        REPO / "detectors" / "test_fixtures" / f"{arg}_vulnerable.sol",
        REPO / "detectors" / "test_fixtures" / f"{arg}_vuln.sol",
        REPO / "patterns" / "fixtures" / f"{arg}_vuln.sol",
        REPO / "patterns" / "fixtures" / f"{arg}_vulnerable.sol",
        REPO / "patterns" / "fixtures" / f"{snake}_vuln.sol",
        REPO / "patterns" / "fixtures" / f"{snake}_vulnerable.sol",
        REPO / "detectors" / "wave_graveyard" / "test_fixtures" / f"{snake}_vulnerable.sol",
        REPO / "detectors" / "wave_graveyard" / "test_fixtures" / f"{snake}_vuln.sol",
        REPO / "detectors" / "rust_wave1"   / "test_fixtures" / f"{snake}_positive.rs",
        REPO / "detectors" / "circom_wave1" / "test_fixtures" / f"{snake}_positive.circom",
        REPO / "detectors" / "go_wave1"     / "test_fixtures" / f"{snake}_positive.go",
        REPO / "detectors" / "python_wave1" / "test_fixtures" / f"{snake}_positive.py",
    ]
    cand_c = [
        REPO / "detectors" / "test_fixtures" / f"{snake}_clean.sol",
        REPO / "detectors" / "test_fixtures" / f"{arg}_clean.sol",
        REPO / "patterns" / "fixtures" / f"{arg}_clean.sol",
        REPO / "patterns" / "fixtures" / f"{snake}_clean.sol",
        REPO / "detectors" / "wave_graveyard" / "test_fixtures" / f"{snake}_clean.sol",
        REPO / "detectors" / "rust_wave1"   / "test_fixtures" / f"{snake}_negative.rs",
        REPO / "detectors" / "circom_wave1" / "test_fixtures" / f"{snake}_negative.circom",
        REPO / "detectors" / "go_wave1"     / "test_fixtures" / f"{snake}_negative.go",
        REPO / "detectors" / "python_wave1" / "test_fixtures" / f"{snake}_negative.py",
    ]
    return (next((p for p in cand_v if p.exists()), None),
            next((p for p in cand_c if p.exists()), None))


_HITS_RE = re.compile(r"\[done\]\s+total hits:\s+(\d+)")


def run_smoke(arg: str, fixture: Path) -> int:
    env = os.environ.copy()
    env["AUDITOOOR_FIXTURE_SMOKE_MODE"] = "1"
    cmd = [SLITHER_PYTHON, str(RUN_CUSTOM), "--tier=ALL", str(fixture), arg]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=120, cwd=REPO, env=env)
    except subprocess.TimeoutExpired:
        return -1
    out = (proc.stdout or "") + "\n" + (proc.stderr or "")
    m = _HITS_RE.search(out)
    return int(m.group(1)) if m else -1


def is_suspect(row: dict) -> bool:
    if (row.get("tier") or "").strip() not in HIGH_TIERS:
        return False
    reason = row.get("reason") or ""
    if SUSPECT_REASON_FRAGMENT not in reason:
        return False
    return any(tag in reason for tag in SUSPECT_NEVER_FIRED)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true",
                    help="Mutate registry: downgrade fakes to PAPER.")
    ap.add_argument("--json-out", default=None,
                    help="Write JSON summary here.")
    ap.add_argument("--skip-smoke", action="store_true",
                    help="Skip live smoke; classify by fixture-presence only.")
    args = ap.parse_args()

    if not TIER_REGISTRY.exists():
        print(f"registry not found: {TIER_REGISTRY}", file=sys.stderr)
        return 2

    reg = yaml.safe_load(TIER_REGISTRY.read_text(encoding="utf-8"))
    tiers = reg.get("tiers", {}) or {}

    suspects: list[dict] = []
    for arg, row in tiers.items():
        if not is_suspect(row):
            continue
        vuln, clean = find_fixtures(arg)
        verdict = "downgrade"
        reason = "no_vulnerable_fixture"
        vh = ch = None
        if vuln is not None and not args.skip_smoke:
            vh = run_smoke(arg, vuln)
            ch = run_smoke(arg, clean) if clean is not None else 0
            if vh is not None and vh >= 1 and (ch == 0):
                verdict = "keep_real"
                reason = f"clean_hits={ch},vuln_hits={vh}"
            else:
                reason = f"smoke_no_signal: clean_hits={ch},vuln_hits={vh}"
        elif vuln is not None and args.skip_smoke:
            verdict = "keep_real"  # conservative when smoke skipped
            reason = "fixture_present_smoke_skipped"
        suspects.append({
            "argument": arg,
            "tier_now": (row.get("tier") or "").strip(),
            "vuln_fixture": str(vuln.relative_to(REPO)) if vuln else None,
            "clean_fixture": str(clean.relative_to(REPO)) if clean else None,
            "vuln_hits": vh,
            "clean_hits": ch,
            "verdict": verdict,
            "verdict_reason": reason,
        })

    fakes = [s for s in suspects if s["verdict"] == "downgrade"]
    kept = [s for s in suspects if s["verdict"] == "keep_real"]

    downgraded = 0
    if args.apply and fakes:
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        for s in fakes:
            row = tiers[s["argument"]]
            tier_now = (row.get("tier") or "").strip()
            if tier_now in ("PAPER", ""):
                continue  # idempotent
            if "tier_before_paper" not in row:
                row["tier_before_paper"] = tier_now
            row["tier"] = "PAPER"
            row["verified"] = False
            row["paper_since"] = now
            row["paper_reason"] = f"{QUARANTINE_TAG} {now[:10]}: {s['verdict_reason']}"
            downgraded += 1
        tmp = TIER_REGISTRY.with_suffix(TIER_REGISTRY.suffix + ".tmp")
        tmp.write_text(yaml.safe_dump(reg, sort_keys=False, width=120),
                       encoding="utf-8")
        os.replace(tmp, TIER_REGISTRY)

    verified_after = sum(
        1 for r in tiers.values()
        if (r.get("tier") or "").strip() in HIGH_TIERS and bool(r.get("verified"))
    )

    summary = {
        "schema": "auditooor.registry_quarantine_fakes.v1",
        "ran_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "registry": str(TIER_REGISTRY.relative_to(REPO)),
        "applied": args.apply,
        "skipped_smoke": args.skip_smoke,
        "detected_suspects": len(suspects),
        "fakes_found": len(fakes),
        "kept_real": len(kept),
        "downgraded_to_paper": downgraded,
        "verified_high_tier_after": verified_after,
        "fakes": fakes[:200],  # cap noise
    }
    if args.json_out:
        Path(args.json_out).write_text(json.dumps(summary, indent=2))

    print(f"[registry-quarantine-fakes] suspects={len(suspects)} "
          f"fakes={len(fakes)} kept_real={len(kept)} "
          f"downgraded={downgraded} verified_high_tier_after={verified_after}")

    if fakes and not args.apply:
        print()
        print(f"DRIFT: {len(fakes)} no-yaml-synthesis row(s) failed the "
              f"differential smoke gate.")
        print("Run with --apply to downgrade them to PAPER.")
        for f in fakes[:10]:
            print(f"  - [{f['tier_now']}] {f['argument']:55} "
                  f"reason={f['verdict_reason']}")
        if len(fakes) > 10:
            print(f"  ... and {len(fakes)-10} more (see --json-out)")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
