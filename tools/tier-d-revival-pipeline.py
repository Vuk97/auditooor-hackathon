#!/usr/bin/env python3
"""tier-d-revival-pipeline.py — revive Tier-D detectors back into Tier-B.

Tier-D rows in `detectors/_tier_registry.yaml` are detectors that previously
failed review/smoke (or were registered as D from inception). Many likely
still have a usable .py + YAML on disk; some are missing only fixtures, and
others may pass smoke today but were never re-tested.

This pipeline:
  1. Loads `detectors/_tier_registry.yaml` and isolates every row where
     tier == "D".
  2. For each row, inspects on-disk artifacts using the same conventions as
     `tools/registry-disk-consistency-check.py` and
     `tools/inventory-smoke-test.py`:
       - .py file (search by ARGUMENT)
       - YAML at reference/patterns.dsl/<arg>.yaml
       - vulnerable + clean fixtures (test_fixtures snake or patterns/fixtures kebab)
  3. Classifies each row into one of:
       - viable_for_synthesis : has .py + has YAML + missing fixtures
                                (Phase-B-prime style fixture synthesis revives)
       - viable_for_smoke     : has .py + has fixtures (re-run smoke; if
                                clean=0,vuln>=1 → bulk-promote to Tier-B)
       - unrevivable          : no .py or no YAML, or YAML is documentation_only
  4. Writes synthesis queue (delimiter-format Phase-B-prime style) for the
     synthesis bucket — but DOES NOT launch it. Operator decides.
  5. Runs smoke directly on the smoke bucket and builds a bulk-promote queue.
  6. Invokes `tools/inventory-bulk-promote.py` against that promote queue to
     write verified=true + Tier-B back into the registry.

Outputs (in /private/tmp/auditooor-inventory/):
  tier_d_revival_summary.json          — full classification + smoke results
  tier_d_revival_synthesis_queue.jsonl — phase-b-prime style delimiter tasks
  tier_d_revival_promote_queue.json    — payload for inventory-bulk-promote
  tier_d_revival_promote_summary.json  — output from bulk-promote
  tier_d_revival_prompts/<arg>.txt     — per-detector synthesis prompts

Usage:
  /opt/homebrew/opt/python@3.13/bin/python3.13 tools/tier-d-revival-pipeline.py \\
    --output-dir /private/tmp/auditooor-inventory
"""
from __future__ import annotations

import argparse
import concurrent.futures as futures
import datetime
import json
import re
import subprocess
import sys
import textwrap
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[1]
TIER_REGISTRY = REPO / "detectors" / "_tier_registry.yaml"
RUN_CUSTOM = REPO / "detectors" / "run_custom.py"
DSL_DIR = REPO / "reference" / "patterns.dsl"
SLITHER_PYTHON = "/opt/homebrew/opt/python@3.13/bin/python3.13"
BULK_PROMOTE_TOOL = REPO / "tools" / "inventory-bulk-promote.py"

_DONE_HITS_RE = re.compile(r"\[done\]\s+total hits:\s+(\d+)")
_ARGUMENT_RE = re.compile(r'^\s*ARGUMENT\s*=\s*[\'"]([\w\-]+)[\'"]', re.MULTILINE)


# ---------------------------------------------------------------------------
# Disk-state lookup (mirrors registry-disk-consistency-check + inventory-smoke)
# ---------------------------------------------------------------------------

def find_py_for_argument(arg: str) -> Path | None:
    snake = arg.replace("-", "_")
    for wave_dir in (REPO / "detectors").glob("wave*"):
        if not wave_dir.is_dir():
            continue
        candidate = wave_dir / f"{snake}.py"
        if candidate.exists():
            return candidate
    pattern = re.compile(rf'^\s*ARGUMENT\s*=\s*[\'"]{re.escape(arg)}[\'"]', re.MULTILINE)
    for p in (REPO / "detectors").glob("wave*/*.py"):
        if p.name.startswith("_"):
            continue
        try:
            if pattern.search(p.read_text(encoding="utf-8", errors="replace")):
                return p
        except Exception:
            continue
    return None


def find_fixtures(arg: str) -> tuple[Path | None, Path | None]:
    snake = arg.replace("-", "_")
    candidates_v = [
        REPO / "detectors" / "test_fixtures" / f"{snake}_vulnerable.sol",
        REPO / "patterns" / "fixtures" / f"{arg}_vuln.sol",
        REPO / "patterns" / "fixtures" / f"{arg}_vulnerable.sol",
    ]
    candidates_c = [
        REPO / "detectors" / "test_fixtures" / f"{snake}_clean.sol",
        REPO / "patterns" / "fixtures" / f"{arg}_clean.sol",
    ]
    vuln = next((p for p in candidates_v if p.exists()), None)
    clean = next((p for p in candidates_c if p.exists()), None)
    return vuln, clean


def yaml_info(arg: str) -> tuple[Path | None, str | None, str | None]:
    """Return (yaml_path, status, source). status='documentation_only'/'live'/None."""
    yaml_path = DSL_DIR / f"{arg}.yaml"
    if not yaml_path.exists():
        return (None, None, None)
    try:
        text = yaml_path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return (yaml_path, None, None)
    status = "live"
    if re.search(r"^\s*status\s*:\s*documentation[_-]?only\b", text,
                 re.MULTILINE | re.IGNORECASE):
        status = "documentation_only"
    src_match = re.search(r"^\s*source\s*:\s*(\S.*)$", text, re.MULTILINE)
    source = src_match.group(1).strip() if src_match else None
    return (yaml_path, status, source)


# ---------------------------------------------------------------------------
# Smoke runner
# ---------------------------------------------------------------------------

def run_smoke(arg: str, fixture: Path, timeout_sec: int = 90) -> tuple[int, str]:
    cmd = [SLITHER_PYTHON, str(RUN_CUSTOM), "--tier=ALL", str(fixture), arg]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout_sec, cwd=REPO)
    except subprocess.TimeoutExpired:
        return (-1, "TIMEOUT")
    out = (proc.stdout or "") + "\n" + (proc.stderr or "")
    m = _DONE_HITS_RE.search(out)
    if m is None:
        tail = "\n".join(out.splitlines()[-3:])[:300]
        return (-1, f"NO_DONE_LINE: {tail}")
    return (int(m.group(1)), "")


def smoke_pair(arg: str, vuln: Path, clean: Path) -> dict:
    vh, vnote = run_smoke(arg, vuln)
    ch, cnote = run_smoke(arg, clean)
    if vh < 0 or ch < 0:
        status = "parse_error"
    elif ch == 0 and vh >= 1:
        status = "smoke_pass"
    elif ch > 0:
        status = "false_positive"
    else:
        status = "silent"
    return {
        "argument": arg, "vuln_hits": vh, "clean_hits": ch,
        "status": status, "notes": f"vuln={vnote}; clean={cnote}".strip("; "),
    }


# ---------------------------------------------------------------------------
# Synthesis queue builder (Phase-B-prime delimiter format)
# ---------------------------------------------------------------------------

def build_synthesis_task(arg: str, yaml_path: Path, prompts_dir: Path,
                         outputs_dir: Path) -> dict:
    snake = arg.replace("-", "_")
    yaml_text = yaml_path.read_text(encoding="utf-8", errors="replace")
    prompt = textwrap.dedent(f"""\
        You are synthesizing a clean+vulnerable Solidity fixture pair to revive
        a Tier-D Slither detector back into Tier-B. The detector .py exists and
        compiles; we need test fixtures matching the YAML's `match:` predicates.

        === DETECTOR ARGUMENT ===
        {arg}

        === DETECTOR YAML (reference/patterns.dsl/{arg}.yaml) ===
        {yaml_text}
        === END YAML ===

        === REQUIREMENTS ===

        Produce TWO Solidity 0.8.x source files:
          1. **vulnerable.sol** — exhibits the bug described by `match:`. The
             detector MUST fire >=1 time on this fixture.
          2. **clean.sol** — minimal-diff variant that adds the missing check
             or removes the trigger pattern. The detector MUST NOT fire.

        Both files:
          - SPDX-License-Identifier: MIT
          - pragma solidity ^0.8.20;
          - 50-150 LOC each, self-contained (inline IERC20 etc.)
          - Compile cleanly with solc 0.8.20+
          - Use fresh class names, not literal names from YAML source

        === OUTPUT FORMAT (STRICT) ===

        Output ONLY three sections, each delimited verbatim. Inside each
        section, write Solidity with REAL newlines — no \\n escapes, no
        markdown fences.

        ===BEGIN_VULNERABLE_SOL===
        <vulnerable Solidity verbatim>
        ===END_VULNERABLE_SOL===
        ===BEGIN_CLEAN_SOL===
        <clean Solidity verbatim>
        ===END_CLEAN_SOL===
        ===BEGIN_METADATA===
        argument: {arg}
        snake: {snake}
        ===END_METADATA===

        The wirer writes fixtures to detectors/test_fixtures/{snake}_{{vulnerable,clean}}.sol
        and runs slither smoke; if vuln_hits == 0 OR clean_hits > 0, rejected.
    """)
    prompt_path = prompts_dir / f"tier_d_revival_{snake}.txt"
    prompt_path.write_text(prompt, encoding="utf-8")
    out_path = outputs_dir / f"tier_d_revival_{snake}.json"
    return {
        "task_id": f"tier-d-revival-{arg}",
        "provider": "minimax",
        "task_type": "fixture-synthesis",
        "prompt_path": str(prompt_path),
        "output_path": str(out_path),
        "max_tokens": 8000,
    }


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--output-dir", default="/private/tmp/auditooor-inventory")
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--no-promote", action="store_true",
                    help="Build promote queue but skip running bulk-promote.")
    args = ap.parse_args()

    out_dir = Path(args.output_dir); out_dir.mkdir(parents=True, exist_ok=True)
    prompts_dir = out_dir / "tier_d_revival_prompts"; prompts_dir.mkdir(exist_ok=True)
    synth_outputs_dir = out_dir / "tier_d_revival_outputs"; synth_outputs_dir.mkdir(exist_ok=True)

    if not TIER_REGISTRY.exists():
        print(f"registry not found: {TIER_REGISTRY}", file=sys.stderr)
        return 2
    reg = yaml.safe_load(TIER_REGISTRY.read_text(encoding="utf-8"))
    tiers = reg.get("tiers", {}) or {}
    d_rows = [(arg, row) for arg, row in tiers.items() if row.get("tier") == "D"]
    print(f"[tier-d-revival] Tier-D rows in registry: {len(d_rows)}")

    classified = {"viable_for_synthesis": [], "viable_for_smoke": [], "unrevivable": []}
    for arg, row in d_rows:
        py_path = find_py_for_argument(arg)
        vuln, clean = find_fixtures(arg)
        yaml_path, yaml_st, yaml_src = yaml_info(arg)
        rec = {
            "argument": arg,
            "prior_reason": row.get("reason", ""),
            "py_path": str(py_path.relative_to(REPO)) if py_path else None,
            "yaml_path": str(yaml_path.relative_to(REPO)) if yaml_path else None,
            "yaml_status": yaml_st,
            "yaml_source": yaml_src,
            "vuln_fixture": str(vuln.relative_to(REPO)) if vuln else None,
            "clean_fixture": str(clean.relative_to(REPO)) if clean else None,
        }
        if py_path is None:
            rec["bucket_reason"] = "no .py file on disk"
            classified["unrevivable"].append(rec); continue
        if yaml_st == "documentation_only":
            rec["bucket_reason"] = "YAML is documentation_only"
            classified["unrevivable"].append(rec); continue
        if vuln and clean:
            classified["viable_for_smoke"].append(rec); continue
        if yaml_path is not None:
            rec["bucket_reason"] = "has .py + YAML; missing fixtures"
            classified["viable_for_synthesis"].append(rec); continue
        rec["bucket_reason"] = "no YAML and no fixtures"
        classified["unrevivable"].append(rec)

    print(f"  viable_for_synthesis: {len(classified['viable_for_synthesis'])}")
    print(f"  viable_for_smoke:     {len(classified['viable_for_smoke'])}")
    print(f"  unrevivable:          {len(classified['unrevivable'])}")

    # ---- build synthesis queue (do NOT launch) ---------------------------
    synth_queue_path = out_dir / "tier_d_revival_synthesis_queue.jsonl"
    synth_tasks: list[dict] = []
    for rec in classified["viable_for_synthesis"]:
        ypath = REPO / rec["yaml_path"]
        synth_tasks.append(build_synthesis_task(rec["argument"], ypath,
                                                prompts_dir, synth_outputs_dir))
    with synth_queue_path.open("w") as f:
        for t in synth_tasks:
            f.write(json.dumps(t) + "\n")
    print(f"  synthesis queue -> {synth_queue_path} ({len(synth_tasks)} tasks)")

    # ---- run smoke on viable_for_smoke -----------------------------------
    smoke_results: list[dict] = []
    smoke_inputs = classified["viable_for_smoke"]
    print(f"[tier-d-revival] running smoke on {len(smoke_inputs)} smoke-bucket detectors "
          f"with {args.workers} workers...", flush=True)

    def _smoke(rec):
        return smoke_pair(
            rec["argument"], REPO / rec["vuln_fixture"], REPO / rec["clean_fixture"]
        ) | {"py_path": rec["py_path"], "vuln_fixture": rec["vuln_fixture"],
              "clean_fixture": rec["clean_fixture"]}

    if args.workers <= 1:
        for rec in smoke_inputs:
            smoke_results.append(_smoke(rec))
    else:
        with futures.ThreadPoolExecutor(max_workers=args.workers) as ex:
            for r in ex.map(_smoke, smoke_inputs):
                smoke_results.append(r)

    by_status: dict[str, int] = {}
    for r in smoke_results:
        by_status[r["status"]] = by_status.get(r["status"], 0) + 1
    print(f"  smoke result breakdown: {by_status}")

    passes = [r for r in smoke_results if r["status"] == "smoke_pass"]
    promote_queue = [
        {
            "argument": r["argument"],
            "py_path": r["py_path"],
            "wave": Path(r["py_path"]).parent.name,
            "vuln_fixture": r["vuln_fixture"],
            "clean_fixture": r["clean_fixture"],
            "vuln_hits": r["vuln_hits"],
            "clean_hits": r["clean_hits"],
        }
        for r in passes
    ]
    promote_queue_path = out_dir / "tier_d_revival_promote_queue.json"
    promote_queue_path.write_text(json.dumps(promote_queue, indent=2))
    print(f"  smoke passes: {len(passes)}")
    print(f"  promote queue -> {promote_queue_path}")

    # ---- bulk-promote ----------------------------------------------------
    bulk_summary_path = out_dir / "tier_d_revival_promote_summary.json"
    bulk_rc = None
    if promote_queue and not args.no_promote:
        cmd = [
            SLITHER_PYTHON, str(BULK_PROMOTE_TOOL),
            "--promote-queue", str(promote_queue_path),
            "--summary-out", str(bulk_summary_path),
        ]
        print(f"[tier-d-revival] running bulk-promote: {' '.join(cmd)}", flush=True)
        proc = subprocess.run(cmd, cwd=REPO, capture_output=True, text=True)
        bulk_rc = proc.returncode
        print(proc.stdout)
        if proc.returncode != 0:
            print(proc.stderr, file=sys.stderr)
    elif not promote_queue:
        print("[tier-d-revival] no smoke passes; skipping bulk-promote.")
    else:
        print("[tier-d-revival] --no-promote set; skipping bulk-promote.")

    # ---- summary ---------------------------------------------------------
    summary = {
        "schema": "auditooor.tier_d_revival.v1",
        "ran_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "registry": str(TIER_REGISTRY.relative_to(REPO)),
        "tier_d_count": len(d_rows),
        "buckets": {
            "viable_for_synthesis": len(classified["viable_for_synthesis"]),
            "viable_for_smoke": len(classified["viable_for_smoke"]),
            "unrevivable": len(classified["unrevivable"]),
        },
        "synthesis_queue": str(synth_queue_path),
        "synthesis_task_count": len(synth_tasks),
        "smoke_breakdown": by_status,
        "smoke_passes": len(passes),
        "promote_queue": str(promote_queue_path),
        "bulk_promote_summary": str(bulk_summary_path) if bulk_rc is not None else None,
        "bulk_promote_rc": bulk_rc,
        "classifications": classified,
        "smoke_results": smoke_results,
    }
    summary_path = out_dir / "tier_d_revival_summary.json"
    summary_path.write_text(json.dumps(summary, indent=2))
    print(f"[tier-d-revival] summary -> {summary_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
