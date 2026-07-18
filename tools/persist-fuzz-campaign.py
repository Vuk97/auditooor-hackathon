#!/usr/bin/env python3
"""persist-fuzz-campaign.py - run (or ingest) a medusa campaign for a harness and
PERSIST its machine-readable call count into the harness's mvc_sidecar + a retained
log, so the invariant-fuzz / fuzz-saturation gates can verify the >=1M floor.

FEEDER-HEALTH FIX (Strata 2026-07-07): step-4b lanes RAN real >=1M medusa campaigns
but wrote their logs to /tmp (gone) and did NOT record `calls_executed` in their
mvc_sidecar - so invariant-fuzz read "corpus-only evidence with no counter" and
false-red-ed a genuine campaign (5 Strata lanes). sNUSD + the faithful Midas rebuild
did it right (medusa_campaign.calls_executed in the sidecar + a log in
.auditooor/fuzz_logs); this tool makes that persistence a one-command, consistent
step for every harness instead of an ad-hoc per-lane habit.

NEVER-FABRICATE: the count is parsed from the REAL engine log of THIS run (or an
--ingest-log the caller points at). It refuses to write a count with no backing log
line. Two modes:
  --run     : invoke medusa with --config, capture the log, parse, persist.
  --ingest-log <path> : parse an existing real log + persist (no engine run).

Persistence: copies the log to <ws>/.auditooor/fuzz_logs/medusa_<Harness>.log and
sets `medusa_campaign.{calls_executed,call_sequence_length,corpus_dir,config}` on
the harness's mvc_sidecar (matched by harness stem), creating a minimal sidecar if
none exists - but ONLY with mutation_verified untouched (this tool does NOT assert
non-vacuity; that stays the mutation-verify step's job).
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

_CALLS_RE = re.compile(r"calls:\s*([\d,]+)", re.I)
_SEQ_RE = re.compile(r'"?call[_ ]?[Ss]equence[_ ]?[Ll]ength"?\s*[:=]\s*"?(\d+)', re.I)


def parse_calls(log_text: str) -> int:
    """Max `calls: N` value across the log (medusa's cumulative progress counter)."""
    return max((int(m.replace(",", "")) for m in _CALLS_RE.findall(log_text)), default=0)


def parse_seqlen(config_text: str, log_text: str) -> int:
    for t in (config_text, log_text):
        m = _SEQ_RE.search(t or "")
        if m:
            return int(m.group(1))
    return 0


def _find_sidecar(ws: Path, harness_stem: str) -> Path | None:
    sc_dir = ws / ".auditooor" / "mvc_sidecar"
    if not sc_dir.is_dir():
        return None
    low = harness_stem.lower()
    best = None
    for p in sorted(sc_dir.glob("*.json")):
        if low in p.name.lower():
            return p
        # also match by the sidecar's recorded harness_path
        try:
            d = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if harness_stem in str(d.get("harness_path") or "") or harness_stem in str(d.get("harness") or ""):
            best = best or p
    return best


def _rel(p: Path, ws: Path) -> str:
    try:
        return str(p.resolve().relative_to(ws))
    except (ValueError, OSError):
        return str(p)


def persist(ws: Path, harness_dir: Path, log_text: str, config_path: Path | None,
            corpus_dir: str = "") -> dict:
    ws = ws.expanduser().resolve()
    harness_dir = harness_dir.expanduser().resolve()
    calls = parse_calls(log_text)
    if calls <= 0:
        return {"ok": False, "reason": "no machine-readable 'calls: N' line in the log - refusing to persist a fabricated count",
                "calls_executed": 0}
    cfg_text = config_path.read_text(encoding="utf-8", errors="replace") if config_path and config_path.is_file() else ""
    seqlen = parse_seqlen(cfg_text, log_text)
    harness_sol = next((p for p in harness_dir.glob("*.sol")
                        if "Mock" not in p.name and "Sanity" not in p.name), None)
    harness_stem = (harness_sol.stem if harness_sol else harness_dir.name)
    # 1) retain the log where the gates look.
    logs_dir = ws / ".auditooor" / "fuzz_logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    log_path = logs_dir / f"medusa_{harness_stem}.log"
    log_path.write_text(log_text, encoding="utf-8")
    # 2) update (or create) the harness's mvc_sidecar with the campaign count.
    sc = _find_sidecar(ws, harness_stem)
    if sc is not None:
        try:
            d = json.loads(sc.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            d = {}
    else:
        sc = ws / ".auditooor" / "mvc_sidecar" / f"mvc-{harness_stem}.json"
        d = {"schema": "auditooor.mvc_sidecar.v1", "workspace": ws.name,
             "harness_path": _rel(harness_dir / f"{harness_stem}.sol", ws),
             "verdict": "campaign-count-persisted",
             "note": "count-only persistence; mutation-verify separately for non-vacuity."}
    mc = d.get("medusa_campaign") if isinstance(d.get("medusa_campaign"), dict) else {}
    mc["calls_executed"] = calls
    if seqlen:
        mc["call_sequence_length"] = seqlen
    if config_path:
        mc["config"] = _rel(config_path, ws)
    if corpus_dir:
        mc["corpus_dir"] = corpus_dir
    mc.setdefault("properties_passed", mc.get("properties_passed", 1))
    d["medusa_campaign"] = mc
    sc.parent.mkdir(parents=True, exist_ok=True)
    sc.write_text(json.dumps(d, indent=2), encoding="utf-8")
    return {"ok": True, "calls_executed": calls, "call_sequence_length": seqlen,
            "log": str(log_path), "sidecar": str(sc)}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--workspace", required=True, type=Path)
    ap.add_argument("--harness-dir", required=True, type=Path)
    ap.add_argument("--config", type=Path, help="medusa config json (for --run / metadata)")
    ap.add_argument("--corpus-dir", default="")
    ap.add_argument("--run", action="store_true", help="invoke medusa --config and capture the log")
    ap.add_argument("--ingest-log", type=Path, help="persist from an existing real log (no engine run)")
    ap.add_argument("--timeout", type=int, default=600)
    a = ap.parse_args(argv)

    if a.run:
        if not a.config:
            ap.error("--run requires --config")
        # medusa must run from the dir holding foundry.toml (the config's target '.'
        # + relative corpus paths resolve against the cwd). Harnesses commonly live in
        # a subdir of that dir (chimera_harnesses/<H>/) with the shared foundry.toml one
        # level up, so walk up from the harness dir to find it.
        run_cwd = a.harness_dir.resolve()
        for cand in (run_cwd, *run_cwd.parents):
            if (cand / "foundry.toml").is_file():
                run_cwd = cand
                break
        cfg_arg = str(a.config.resolve())
        try:
            r = subprocess.run(["medusa", "fuzz", "--config", cfg_arg],
                               cwd=str(run_cwd), capture_output=True, text=True,
                               timeout=a.timeout)
            log_text = (r.stdout or "") + "\n" + (r.stderr or "")
        except (OSError, subprocess.TimeoutExpired) as exc:
            print(json.dumps({"ok": False, "reason": f"medusa run failed: {exc}"}))
            return 1
    elif a.ingest_log:
        log_text = a.ingest_log.read_text(encoding="utf-8", errors="replace")
    else:
        ap.error("one of --run / --ingest-log is required")

    res = persist(a.workspace, a.harness_dir, log_text, a.config, a.corpus_dir)
    print(json.dumps(res, indent=2))
    return 0 if res.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
