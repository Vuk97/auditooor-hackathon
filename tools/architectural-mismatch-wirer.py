#!/usr/bin/env python3
"""architectural-mismatch-wirer.py — apply LLM-redesigned fixtures from the
architectural-mismatch redesign queue.

For each LLM output file (one per detector argument):
  1. Parse the delimiter-based output (REDESIGNED_VUNERABLE_SOL / REDESIGNED_CLEAN_SOL
     / RATIONALE / METADATA). See docs/llm-codegen-format-spec.md.
  2. Back up the existing fixtures:
        <id>_vuln.sol  -> <id>_vulnerable.sol.bak
        <id>_clean.sol -> <id>_clean.sol.bak
  3. Write the new fixtures over the originals (preserving filename).
  4. Smoke-test via detectors/run_custom.py (canonical runner).
  5. PASS  → leave new fixtures, mark detector Tier-B verified in registry.
     FAIL  → restore the .bak files, log the failure, do not touch registry.

Usage:
  python3 tools/architectural-mismatch-wirer.py \
    --queue /private/tmp/auditooor-inventory/arch_redesign_queue.jsonl \
    --outputs-dir /private/tmp/auditooor-inventory/arch_redesign_outputs \
    --summary-out /private/tmp/auditooor-inventory/arch_redesign_summary.json
"""
from __future__ import annotations

import argparse
import datetime
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[1]
RUN_CUSTOM = REPO / "detectors" / "run_custom.py"
TIER_REGISTRY = REPO / "detectors" / "_tier_registry.yaml"
SLITHER_PYTHON = "/opt/homebrew/opt/python@3.13/bin/python3.13"

_DELIM_RE = re.compile(
    r"===BEGIN_REDESIGNED_VUNERABLE_SOL===\s*(.*?)\s*===END_REDESIGNED_VUNERABLE_SOL==="
    r".*?===BEGIN_REDESIGNED_CLEAN_SOL===\s*(.*?)\s*===END_REDESIGNED_CLEAN_SOL==="
    r".*?===BEGIN_RATIONALE===\s*(.*?)\s*===END_RATIONALE==="
    r".*?===BEGIN_METADATA===\s*(.*?)\s*===END_METADATA===",
    re.DOTALL,
)


def _parse(raw: str) -> dict | None:
    m = _DELIM_RE.search(raw.strip())
    if not m:
        return None
    vuln, clean, rationale, meta_block = m.groups()
    meta: dict[str, str] = {}
    for line in meta_block.splitlines():
        if ":" in line:
            k, _, v = line.partition(":")
            meta[k.strip()] = v.strip()
    return {"vuln": vuln, "clean": clean, "rationale": rationale, **meta}


def _smoke(arg: str, fixture: Path) -> tuple[int, int]:
    """Run run_custom on a fixture, return (returncode, hits). hits=-1 on parse fail."""
    try:
        proc = subprocess.run(
            [SLITHER_PYTHON, str(RUN_CUSTOM), "--tier=ALL", str(fixture), arg],
            cwd=REPO, capture_output=True, text=True, timeout=120,
        )
    except subprocess.TimeoutExpired:
        return (-1, -1)
    out = (proc.stdout or "") + "\n" + (proc.stderr or "")
    m = re.search(r"\[done\]\s+total hits:\s+(\d+)", out)
    return (proc.returncode, int(m.group(1)) if m else -1)


def _backup(p: Path) -> Path | None:
    if not p.is_file():
        return None
    bak = p.with_suffix(p.suffix + ".bak")
    shutil.copy2(p, bak)
    return bak


def _restore(p: Path, bak: Path | None) -> None:
    if bak is not None and bak.is_file():
        shutil.copy2(bak, p)
        bak.unlink()


def _promote_tier_b(arg: str, snake: str, vuln_hits: int) -> bool:
    """Mark detector as Tier-B in registry. Returns True if registry updated."""
    if not TIER_REGISTRY.is_file():
        return False
    reg = yaml.safe_load(TIER_REGISTRY.read_text()) or {}
    tiers = reg.setdefault("tiers", {})
    today = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")
    prior = tiers.get(snake, {})
    tiers[snake] = {
        "tier": "B",
        "reason": f"arch-mismatch-redesign {today}: smoke pass after fixture rebuild "
                  f"(clean=0, vuln={vuln_hits})",
        "waves": prior.get("waves", []) + ["arch_redesign"],
        "first_added": prior.get("first_added", today),
        "last_promoted": today,
        "engine": "slither",
        "argument": arg,
        "verified": True,
    }
    tmp = TIER_REGISTRY.with_suffix(".yaml.tmp")
    tmp.write_text(yaml.safe_dump(reg, default_flow_style=False, sort_keys=False))
    tmp.replace(TIER_REGISTRY)
    return True


def wire_one(task: dict, outputs_dir: Path) -> dict:
    arg = task["argument"]; snake = task["snake"]
    out_path = outputs_dir / f"redesign_{snake}.txt"
    result = {"argument": arg, "snake": snake, "ok": False, "reason": "",
              "smoke": {}, "rationale": ""}
    if not out_path.is_file():
        result["reason"] = f"output_missing: {out_path}"
        return result
    blob = _parse(out_path.read_text(encoding="utf-8"))
    if blob is None:
        result["reason"] = "delimiter_parse_failed"
        return result
    if not blob["vuln"].strip() or not blob["clean"].strip():
        result["reason"] = "empty_fixture_section"
        return result

    vuln_path = REPO / task["vuln_fixture"]
    clean_path = REPO / task["clean_fixture"]
    vuln_bak = _backup(vuln_path)
    clean_bak = _backup(clean_path)

    vuln_path.write_text(blob["vuln"], encoding="utf-8")
    clean_path.write_text(blob["clean"], encoding="utf-8")

    rc_v, hits_v = _smoke(arg, vuln_path)
    rc_c, hits_c = _smoke(arg, clean_path)
    result["smoke"] = {"vuln_rc": rc_v, "vuln_hits": hits_v,
                       "clean_rc": rc_c, "clean_hits": hits_c}
    result["rationale"] = blob.get("rationale", "").strip()[:600]

    if hits_v >= 1 and hits_c == 0:
        # Pass — keep new fixtures, drop the .bak.
        for bak in (vuln_bak, clean_bak):
            if bak and bak.is_file():
                bak.unlink()
        result["ok"] = True
        result["reason"] = "smoke_pass"
        result["registry_updated"] = _promote_tier_b(arg, snake, hits_v)
        return result

    # Fail — revert both fixtures from .bak.
    _restore(vuln_path, vuln_bak)
    _restore(clean_path, clean_bak)
    result["reason"] = (f"smoke_fail: vuln_hits={hits_v} (want >=1), "
                        f"clean_hits={hits_c} (want 0); reverted")
    return result


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--queue", required=True, help="JSONL from architectural-mismatch-fixture-redesign.py")
    ap.add_argument("--outputs-dir", required=True, help="LLM outputs directory")
    ap.add_argument("--summary-out", required=True)
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    outputs_dir = Path(args.outputs_dir)
    tasks = [json.loads(line) for line in Path(args.queue).read_text().splitlines() if line.strip()]
    if args.limit:
        tasks = tasks[: args.limit]

    if args.dry_run:
        print(f"[dry-run] would process {len(tasks)} tasks from {args.queue}")
        return 0

    results = []
    for i, t in enumerate(tasks, 1):
        r = wire_one(t, outputs_dir)
        results.append(r)
        status = "PASS" if r["ok"] else "FAIL"
        print(f"[{i}/{len(tasks)}] {status} {r['argument']}: {r['reason']}",
              file=sys.stderr, flush=True)

    passing = [r for r in results if r["ok"]]
    summary = {
        "schema": "auditooor.arch_mismatch_wirer.v1",
        "ran_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "input_count": len(tasks),
        "passing_count": len(passing),
        "fail_count": len(results) - len(passing),
        "results": results,
    }
    Path(args.summary_out).write_text(json.dumps(summary, indent=2))
    print(f"PASS={len(passing)} FAIL={len(results) - len(passing)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
