#!/usr/bin/env python3
"""
slither-cache-self-test.py -- Self-test for the Slither compile cache (ACT-11).

Measures cold vs warm Slither instantiation in-process on a sample of real
fixtures.  In-process measurement avoids subprocess spawn overhead (~50ms per
call) that swamps any savings at small fixture counts.

The test:
  1. Clears the cache (or uses --skip-clear to reuse existing warm state as cold).
  2. COLD pass: calls get_or_compile_slither() on N fixtures -- each is a miss,
     so it compiles via CryticCompile + solc.
  3. WARM pass: calls get_or_compile_slither() on the same N fixtures that
     succeeded -- each should be a hit, returning Slither from cached artifact.
  4. Computes speedup = cold_total / warm_total (successful fixtures only).
  5. Saves report to reports/slither_cache_self_test.json.

Acceptance: >=10x speedup (PASS).  >=5x is ACCEPTABLE but flagged.  <5x -> exit 1.

Usage:
    python3 tools/slither-cache-self-test.py [--fixtures M] [--timeout T]
                                              [--out OUT] [--skip-clear]

Exit codes:
    0 -- speedup >= 5x (acceptable)
    1 -- speedup < 5x (cache regression -- investigate)
    2 -- fatal setup error (no slither, no fixtures, etc.)
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import random
import sys
import time
import warnings
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_JSON_OUT = REPO_ROOT / "reports" / "slither_cache_self_test.json"
FIXTURE_DIRS = [
    REPO_ROOT / "detectors" / "test_fixtures",
]


def _collect_fixtures(limit: int) -> list[Path]:
    found: list[Path] = []
    for d in FIXTURE_DIRS:
        if d.is_dir():
            found.extend(sorted(d.rglob("*.sol")))
    if not found:
        return found
    rng = random.Random(42)
    if len(found) > limit:
        found = rng.sample(found, limit)
    return found


def _load_cache_module():
    import importlib.util as ilu
    spec = ilu.spec_from_file_location(
        "slither_compile_cache",
        REPO_ROOT / "tools" / "slither-compile-cache.py",
    )
    if spec is None:
        raise RuntimeError("Cannot locate tools/slither-compile-cache.py")
    mod = ilu.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _check_slither_importable() -> None:
    try:
        import slither  # noqa: F401
    except ImportError as e:
        raise RuntimeError(f"slither-analyzer not importable: {e}") from e


def main() -> None:
    p = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--fixtures", type=int, default=10, metavar="M",
                   help="Fixture files to test (default 10)")
    p.add_argument("--timeout", type=int, default=30, metavar="T",
                   help="Per-fixture compile timeout seconds (default 30)")
    p.add_argument("--out", type=Path, default=DEFAULT_JSON_OUT,
                   help=f"Output JSON path (default {DEFAULT_JSON_OUT})")
    p.add_argument("--skip-clear", action="store_true",
                   help="Skip cache clear (use existing cache as warm baseline)")
    args = p.parse_args()

    print("=" * 60, flush=True)
    print("Slither compile cache self-test (ACT-11)", flush=True)
    print("In-process measurement -- avoids subprocess overhead", flush=True)
    print("=" * 60, flush=True)

    os.environ["SLITHER_DISABLE_WARNINGS"] = "1"

    try:
        _check_slither_importable()
    except RuntimeError as e:
        print(f"[fatal] {e}", file=sys.stderr)
        sys.exit(2)

    try:
        cache_mod = _load_cache_module()
    except Exception as e:
        print(f"[fatal] Cannot load slither-compile-cache: {e}", file=sys.stderr)
        sys.exit(2)

    fixtures = _collect_fixtures(args.fixtures)
    if not fixtures:
        print("[fatal] No .sol fixtures found", file=sys.stderr)
        sys.exit(2)
    n = len(fixtures)
    print(f"[self-test] Using {n} fixtures", flush=True)

    # Clear cache
    if not args.skip_clear:
        print("[self-test] Clearing cache...", flush=True)
        cache_mod._cmd_clear()
    else:
        print("[self-test] --skip-clear: measuring with existing cache as 'warm'", flush=True)

    # -------------------------------------------------------------------------
    # COLD pass
    # -------------------------------------------------------------------------
    print(f"\n[self-test] COLD pass ({n} fixtures, cache empty)...", flush=True)
    cold_times: dict[Path, float] = {}
    cold_ok: list[Path] = []
    cold_errors = 0

    for fx in fixtures:
        t0 = time.monotonic()
        ok = False
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                sl = cache_mod.get_or_compile_slither(fx, compile_timeout=args.timeout)
            ok = sl is not None
            if not ok:
                cold_errors += 1
        except Exception as e:
            cold_errors += 1
            print(f"  [warn] {fx.name}: {e}", flush=True)
        elapsed = time.monotonic() - t0
        cold_times[fx] = elapsed
        if ok:
            cold_ok.append(fx)
        print(f"  cold {fx.name}: {elapsed:.3f}s {'OK' if ok else 'FAIL'}", flush=True)

    # Speedup measured only on fixtures that compiled successfully
    n_ok = len(cold_ok)
    t_cold_ok = sum(cold_times[fx] for fx in cold_ok)
    avg_cold = t_cold_ok / max(n_ok, 1)
    print(
        f"[self-test] Cold (successful only): {t_cold_ok:.3f}s  "
        f"avg: {avg_cold:.3f}s/fixture  ({n_ok}/{n} succeeded)",
        flush=True,
    )

    if n_ok == 0:
        print("[fatal] All cold compilations failed -- cannot measure speedup", file=sys.stderr)
        sys.exit(2)

    # -------------------------------------------------------------------------
    # WARM pass (only fixtures that succeeded in cold pass)
    # -------------------------------------------------------------------------
    cache_mod.reset_run_stats()
    print(f"\n[self-test] WARM pass ({n_ok} successful fixtures, cache hot)...", flush=True)
    warm_times: dict[Path, float] = {}
    warm_errors = 0

    for fx in cold_ok:
        t0 = time.monotonic()
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                sl = cache_mod.get_or_compile_slither(fx, compile_timeout=args.timeout)
            if sl is None:
                warm_errors += 1
        except Exception as e:
            warm_errors += 1
            print(f"  [warn] {fx.name}: {e}", flush=True)
        elapsed = time.monotonic() - t0
        warm_times[fx] = elapsed
        print(f"  warm {fx.name}: {elapsed:.3f}s", flush=True)

    t_warm_ok = sum(warm_times.values())
    avg_warm = t_warm_ok / max(n_ok, 1)
    print(f"[self-test] Warm total: {t_warm_ok:.3f}s  avg: {avg_warm:.3f}s/fixture", flush=True)

    stats = cache_mod.get_run_stats()
    hits = stats.get("hits", 0)
    misses = stats.get("misses", 0)
    hit_rate = hits / max(hits + misses, 1)
    print(f"[self-test] Cache hits={hits}  misses={misses}  hit_rate={hit_rate:.1%}", flush=True)

    # -------------------------------------------------------------------------
    # Speedup
    # -------------------------------------------------------------------------
    speedup = t_cold_ok / max(t_warm_ok, 0.001)

    print("\n" + "=" * 60, flush=True)
    print(f"  Cold total : {t_cold_ok:.3f}s  ({avg_cold:.3f}s/fixture avg)", flush=True)
    print(f"  Warm total : {t_warm_ok:.3f}s  ({avg_warm:.3f}s/fixture avg)", flush=True)
    print(f"  Speedup    : {speedup:.1f}x", flush=True)
    print(f"  Hit rate   : {hit_rate:.1%}", flush=True)
    print(f"  Fixtures   : {n_ok} successful / {n} sampled", flush=True)
    print("=" * 60, flush=True)

    if speedup >= 10:
        verdict = f"PASS (>={speedup:.1f}x speedup)"
        exit_code = 0
    elif speedup >= 5:
        verdict = f"ACCEPTABLE ({speedup:.1f}x speedup -- >=5x but below 10x target)"
        exit_code = 0
    else:
        verdict = (
            f"FAIL ({speedup:.1f}x speedup < 5x threshold); "
            f"hit_rate={hit_rate:.1%}"
        )
        exit_code = 1

    print(f"\n  Verdict    : {verdict}", flush=True)

    # -------------------------------------------------------------------------
    # Save report
    # -------------------------------------------------------------------------
    report = {
        "test_date": datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "measurement": "in-process (avoids subprocess spawn overhead)",
        "sample_fixtures_requested": n,
        "sample_fixtures_succeeded": n_ok,
        "wall_time_cold_s": round(t_cold_ok, 3),
        "wall_time_warm_s": round(t_warm_ok, 3),
        "avg_cold_s": round(avg_cold, 3),
        "avg_warm_s": round(avg_warm, 3),
        "speedup_x": round(speedup, 2),
        "target_speedup_x": 10,
        "verdict": verdict,
        "cache_hits_warm_run": hits,
        "cache_misses_warm_run": misses,
        "cache_hit_rate_warm": round(hit_rate, 3),
        "cold_errors": cold_errors,
        "warm_errors": warm_errors,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2))
    print(f"\n[self-test] Report saved: {args.out}", flush=True)

    if exit_code != 0:
        print("\n[WARN] Speedup < 5x. Possible causes:", flush=True)
        print("  1. Slither version mismatch -- run: python3 tools/slither-compile-cache.py --invalidate-all", flush=True)
        print("  2. AUDITOOOR_SLITHER_NOCACHE=1 is set", flush=True)
        print("  3. CryticCompile Standard reload failing silently (see cache logs)", flush=True)
        print(f"  4. Hit rate was only {hit_rate:.1%} -- cold run may have failed to write cache", flush=True)

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
