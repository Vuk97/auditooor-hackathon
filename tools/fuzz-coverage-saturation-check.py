#!/usr/bin/env python3
"""fuzz-coverage-saturation-check.py - prove a fuzz campaign reached coverage
SATURATION, not merely a call-count FLOOR.

THE PROBLEM (operator question 2026-07-07: "why 1M calls and not 10M/100M?")
---------------------------------------------------------------------------
The invariant-fuzz gate enforces a raw call FLOOR (medusa >=1M, echidna >=500K)
and a wall-clock `coverage_plateau` heuristic ("clean pass AND duration>=60s").
Go uses a separate, unmeasured "coverage-guided-with-growth" bar. NONE of them
reads the actual coverage-over-time curve, so:

  * a campaign that hit 1M calls but whose branch/corpus coverage was STILL
    CLIMBING at the end passes the floor while being INADEQUATE (the state space
    was not explored - 10M really would have found more), and
  * a campaign that SATURATED at 150K calls is over-run to 1M for no gain.

The call count is a proxy. The real adequacy criterion is: did coverage stop
growing? A campaign is adequate iff, over the FINAL window of the run, marginal
new coverage (branches / corpus / interesting inputs) fell to ~0. That is
measurable directly from the engine's own progress log - and it unifies Solidity
(medusa/echidna) and Go (go test -fuzz) under ONE principle instead of a
per-engine magic number.

WHAT THIS DOES
--------------
Parse a campaign log's periodic coverage samples into (calls, coverage) points,
then classify:

  * SATURATED       - the final SATURATION_TAIL_FRAC of the run added
                      < PLATEAU_EPS_FRAC relative new coverage. The floor was
                      ENOUGH for this harness; adequacy PROVEN (not assumed).
  * STILL_CLIMBING  - coverage rose by >= PLATEAU_EPS_FRAC across the tail. The
                      floor was INSUFFICIENT for this state space; the honest
                      action is to EXTEND the campaign (more calls / better
                      seed), not to credit it. (This is the "why not 10M" case:
                      because 10M is only warranted when 1M is still climbing.)
  * UNMEASURED      - < MIN_SAMPLES coverage samples, or no coverage column in
                      the log (curve not retained). Cannot certify saturation.

ADVISORY-FIRST + NEVER-RETRO-RED: verdict is advisory (warn) by default; a
STILL_CLIMBING / UNMEASURED result HARD FAILS only under
AUDITOOOR_FUZZ_SATURATION_STRICT (or AUDITOOOR_L37_STRICT). Fails OPEN (verdict
UNMEASURED, rc 0) on any parse error - it never wedges a campaign, only flags
one whose curve it can actually read and that is demonstrably still climbing.

Pure stdlib, offline. Engine-aware: medusa, echidna, go-native (go test -fuzz).
"""
from __future__ import annotations

import argparse
import json
import os
import re
from pathlib import Path

# --- adequacy thresholds (the answer to "how much is enough") ----------------
# Coverage must have flatlined across the final TAIL fraction of the run.
SATURATION_TAIL_FRAC = 0.40   # examine the last 40% of calls
PLATEAU_EPS_FRAC = 0.01       # < 1% relative new coverage across the tail = flat
MIN_SAMPLES = 4               # need >=4 points to see a curve at all

# medusa >=1.5 progress line:
#   fuzz: elapsed: 15s, calls: 175464 (11469/sec), seq/s: 229, branches: 3317,
#   corpus: 37, failures: 0/3505, gas/s: ...
_MEDUSA_RE = re.compile(
    r"calls:\s*([\d,]+).*?branches:\s*([\d,]+).*?corpus:\s*([\d,]+)", re.I)
# echidna progress: "tests: N, fuzzing: X/Y, values: [...], coverage: NNN"
_ECHIDNA_RE = re.compile(
    r"fuzzing:\s*([\d,]+)/[\d,]+.*?(?:coverage|cov):\s*([\d,]+)", re.I)
# go test -fuzz: "fuzz: elapsed: 3s, execs: 123456 (41152/sec), new interesting:
#   5 (total: 30)"
_GO_RE = re.compile(
    r"execs:\s*([\d,]+).*?(?:total:\s*([\d,]+)\))", re.I)


def _n(s: str) -> int:
    return int(str(s).replace(",", "").strip() or 0)


def _read(p: Path) -> str:
    try:
        return p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def parse_samples(text: str) -> tuple[str, list[tuple[int, int]]]:
    """Return (engine, [(calls_or_execs, coverage), ...]) sorted by progress.

    coverage is the engine's best coverage proxy: medusa=branches (primary),
    echidna=coverage, go=total interesting corpus. corpus is a secondary medusa
    signal folded in only to break ties (a harness whose branches flatline but
    whose corpus is still growing is still exploring)."""
    med = []
    for m in _MEDUSA_RE.finditer(text):
        calls, branches, corpus = _n(m.group(1)), _n(m.group(2)), _n(m.group(3))
        # coverage proxy = branches, with corpus as a fractional tie-breaker so a
        # still-growing corpus at flat branches does not read as saturated.
        med.append((calls, branches * 1000 + corpus))
    if len(med) >= MIN_SAMPLES:
        return "medusa", med
    go = []
    for m in _GO_RE.finditer(text):
        execs = _n(m.group(1))
        total = _n(m.group(2)) if m.group(2) else 0
        go.append((execs, total))
    if len(go) >= MIN_SAMPLES:
        return "go-native", go
    ech = []
    for m in _ECHIDNA_RE.finditer(text):
        ech.append((_n(m.group(1)), _n(m.group(2))))
    if len(ech) >= MIN_SAMPLES:
        return "echidna", ech
    # fall back to whichever we got the most of (still < MIN_SAMPLES -> UNMEASURED)
    best = max((med, go, ech), key=len)
    engine = {id(med): "medusa", id(go): "go-native", id(ech): "echidna"}[id(best)]
    return engine, best


def classify(samples: list[tuple[int, int]]) -> dict:
    if len(samples) < MIN_SAMPLES:
        return {"verdict": "UNMEASURED",
                "reason": f"only {len(samples)} coverage sample(s) (< {MIN_SAMPLES}); "
                          "the coverage-over-time curve was not retained"}
    samples = sorted(samples)
    final_calls = samples[-1][0]
    final_cov = samples[-1][1]
    peak_cov = max(c for _, c in samples)
    if peak_cov <= 0 or final_calls <= 0:
        return {"verdict": "UNMEASURED",
                "reason": "coverage column present but all-zero"}
    # tail boundary: first sample at >= (1 - TAIL) of final calls
    tail_start_calls = final_calls * (1.0 - SATURATION_TAIL_FRAC)
    tail = [(c, v) for c, v in samples if c >= tail_start_calls]
    if len(tail) < 2:
        tail = samples[-2:]
    cov_at_tail_start = tail[0][1]
    new_cov_in_tail = final_cov - cov_at_tail_start
    rel_new = new_cov_in_tail / float(peak_cov)
    tail_call_frac = (final_calls - tail[0][0]) / float(final_calls)
    detail = {
        "final_calls": final_calls,
        "tail_call_fraction": round(tail_call_frac, 3),
        "coverage_peak": peak_cov,
        "coverage_at_tail_start": cov_at_tail_start,
        "coverage_final": final_cov,
        "relative_new_coverage_in_tail": round(rel_new, 5),
        "plateau_eps": PLATEAU_EPS_FRAC,
    }
    if rel_new < PLATEAU_EPS_FRAC:
        return {"verdict": "SATURATED",
                "reason": (f"coverage flat across the final {round(tail_call_frac*100)}% of "
                           f"calls (+{round(rel_new*100, 3)}% new < {PLATEAU_EPS_FRAC*100}% eps); "
                           "the call floor was adequate for this harness"),
                **detail}
    return {"verdict": "STILL_CLIMBING",
            "reason": (f"coverage rose +{round(rel_new*100, 2)}% across the final "
                       f"{round(tail_call_frac*100)}% of calls (>= {PLATEAU_EPS_FRAC*100}% eps); "
                       "the call floor was INSUFFICIENT - extend the campaign (more calls / "
                       "better seed) rather than crediting it"),
            **detail}


def check_log(log_path: Path) -> dict:
    text = _read(log_path)
    if not text.strip():
        return {"log": str(log_path), "verdict": "UNMEASURED",
                "reason": "log empty or unreadable"}
    engine, samples = parse_samples(text)
    res = classify(samples)
    res["engine"] = engine
    res["log"] = str(log_path)
    res["samples"] = len(samples)
    return res


def _strict() -> bool:
    for k in ("AUDITOOOR_FUZZ_SATURATION_STRICT", "AUDITOOOR_L37_STRICT"):
        if os.environ.get(k, "").strip().lower() not in ("", "0", "false", "no"):
            return True
    return False


# A file is a genuine fuzz-engine CAMPAIGN log (vs a forge/build/deploy/stderr log)
# only if it carries an actual coverage-PROGRESS line. A bare mention of the word
# "medusa"/"echidna" (e.g. an author-stdout or engine-stderr log) is NOT enough -
# that admitted 3 non-campaign logs on Strata and UNMEASURED-warned them falsely.
_FUZZ_MARKER_RE = re.compile(
    r"(fuzz:\s*elapsed|branches:\s*\d+.*corpus:\s*\d+|new interesting:\s*\d+|"
    r"coverage:\s*\d+.*(?:tests|fuzzing))", re.I)
# Directories that never hold a campaign log worth scanning (build / dep noise).
_SKIP_DIRS = {"node_modules", "lib", "out", "cache", ".git", "artifacts",
              "broadcast", "typechain", "coverage"}


def _discover_campaign_logs(ws: Path) -> list[Path]:
    """Find EVERY campaign log in the workspace, not just .auditooor/fuzz_logs.

    Serving-join fix (Strata 2026-07-07): step-4b lanes run medusa IN-PLACE under
    chimera_harnesses/<H>/ (e.g. medusa_run.log), so a gate that only globs
    .auditooor/fuzz_logs silently MISSES them and reports a false-complete
    ('9 saturated' while 3 lane campaigns were never seen). Discover logs across
    the canonical fuzz-output locations, keeping a genuine fuzz log (coverage
    marker present) and dropping build/forge noise."""
    seen: dict[str, Path] = {}
    fuzz_logs = ws / ".auditooor" / "fuzz_logs"
    # 1) the dedicated dir - every .log is a fuzz log by construction.
    if fuzz_logs.is_dir():
        for lg in fuzz_logs.glob("*.log"):
            seen.setdefault(str(lg.resolve()), lg)
    # 2) in-tree harness / corpus-run logs - admit only marker-bearing files.
    roots = [ws / "chimera_harnesses", ws / ".auditooor"]
    for root in roots:
        if not root.is_dir():
            continue
        for lg in root.rglob("*.log"):
            if any(part in _SKIP_DIRS for part in lg.parts):
                continue
            key = str(lg.resolve())
            if key in seen:
                continue
            try:
                head = lg.read_text(encoding="utf-8", errors="replace")[:20000]
            except OSError:
                continue
            if _FUZZ_MARKER_RE.search(head):
                seen[key] = lg
    return [seen[k] for k in sorted(seen)]


def check_workspace(ws: Path) -> dict:
    ws = ws.expanduser().resolve()
    results = []
    for lg in _discover_campaign_logs(ws):
        results.append(check_log(lg))
    climbing = [r for r in results if r["verdict"] == "STILL_CLIMBING"]
    unmeasured = [r for r in results if r["verdict"] == "UNMEASURED"]
    saturated = [r for r in results if r["verdict"] == "SATURATED"]
    strict = _strict()
    if not results:
        verdict = "pass-no-campaign-logs"
    elif climbing:
        verdict = "fail-fuzz-still-climbing" if strict else "warn-fuzz-still-climbing"
    elif unmeasured:
        verdict = "fail-fuzz-saturation-unmeasured" if strict else "warn-fuzz-saturation-unmeasured"
    else:
        verdict = "pass-fuzz-saturated"
    return {"workspace": str(ws), "verdict": verdict, "strict": strict,
            "campaigns": len(results), "saturated": len(saturated),
            "still_climbing": len(climbing), "unmeasured": len(unmeasured),
            "results": results}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--workspace", type=Path)
    ap.add_argument("--log", type=Path, help="check a single campaign log")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    if a.log:
        r = check_log(a.log)
        print(json.dumps(r, indent=2) if a.json else
              f"fuzz-saturation: {r['verdict']} [{r.get('engine')}] {r['reason']}")
        return 0
    if not a.workspace:
        ap.error("one of --workspace / --log is required")
    r = check_workspace(a.workspace)
    if a.json:
        print(json.dumps(r, indent=2))
    else:
        print(f"fuzz-coverage-saturation: {r['verdict']} "
              f"({r['saturated']} saturated / {r['still_climbing']} still-climbing / "
              f"{r['unmeasured']} unmeasured of {r['campaigns']})")
        for res in r["results"]:
            flag = " - " if res["verdict"] == "SATURATED" else "  <-- "
            print(f"  [{res['verdict']:16}] {os.path.basename(res['log'])}{flag}{res['reason']}")
    return 1 if r["verdict"].startswith("fail-") else 0


if __name__ == "__main__":
    raise SystemExit(main())
