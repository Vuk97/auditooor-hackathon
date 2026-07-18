#!/usr/bin/env python3
"""
detector-precision-matrix.py — Cross-product confusion matrix for Tier-A/B/S detectors.

For each verified Slither detector (tier A, B, or S) run it against EVERY known
Solidity fixture (not just its own pair).  A false-positive occurs when the detector
fires on a fixture it does not "own".  Aggregate per-detector precision and emit both
machine-parseable JSON and a human-readable Markdown table.

Usage:
    python3 tools/detector-precision-matrix.py [options]

Options:
    --detector ARG        Only test one exact detector name/argument (default: all)
    --sample-detectors N   Only test N randomly-selected detectors (default: all)
    --sample-fixtures M    Only test M randomly-selected fixtures (default: all)
    --json-out PATH        Output JSON path  (default: reports/detector_precision_matrix.json)
    --md-out PATH          Output Markdown path (default: docs/DETECTOR_PRECISION_MATRIX.md)
    --workers N            ProcessPool workers (default: min(8, cpu_count))
    --timeout N            Per-invocation wall timeout in seconds (default: 30)
    --seed N               RNG seed for reproducible sampling (default: 42)
    --no-spot-check        Skip the M14-trap spot-check of 3 random pairs
    --help / -h            Show this message and exit

Exit codes:
    0  — completed (even if some pairs timed out)
    1  — fatal error (missing deps, bad args, etc.)

Bottleneck caveat:
    Each detector×fixture pair spawns run_custom.py as a subprocess (~4-5 s overhead
    on a MacBook — Slither re-compiles the fixture from scratch every call).
    Full cross-product (599 detectors × 4434 fixtures) ≈ 890k pairs × 5 s = ~620 CPU-hours.
    Even --sample-detectors 50 --sample-fixtures 100 (5000 pairs at 8 workers) takes ~50 min.
    For quick validation use --sample-detectors 20 --sample-fixtures 25 (~500 pairs, ~5 min).
    To make the full run practical, a persistent Slither compilation cache is needed so
    that each fixture is compiled once and results are reused across detectors.
"""

import argparse
import json
import os
import random
import re
import subprocess
import sys
import time
from concurrent.futures import ProcessPoolExecutor, as_completed, wait, FIRST_COMPLETED
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
REPO_ROOT = Path(__file__).resolve().parents[1]
DETECTORS_DIR = REPO_ROOT / "detectors"
REGISTRY_PATH = DETECTORS_DIR / "_tier_registry.yaml"
DEFAULT_JSON_OUT = REPO_ROOT / "reports" / "detector_precision_matrix.json"
DEFAULT_MD_OUT = REPO_ROOT / "docs" / "DETECTOR_PRECISION_MATRIX.md"
TARGET_TIERS = {"A", "B", "S"}
CONSECUTIVE_TIMEOUT_BAIL = 10  # mark detector untestable after N consecutive timeouts
OWN_FIXTURE_SUFFIXES = ("_vulnerable.sol", "_vuln.sol")
POSITIVE_FIXTURE_NAMES = ("positive.sol", "vulnerable.sol", "vuln.sol")
NEGATIVE_FIXTURE_NAMES = ("clean.sol", "negative.sol")


def _norm_id(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_")


def _slug_variants(value: str) -> list[str]:
    raw = (value or "").strip().strip("\"'")
    if not raw:
        return []
    base = raw.replace("/", "_")
    variants = {
        base,
        base.replace("-", "_"),
        base.replace("_", "-"),
    }
    return [item for item in sorted(variants) if item]


def _canonical_fixture_dirs() -> list[Path]:
    """Return one canonical detectors/fixtures dir per normalized slug."""
    fixtures_root = DETECTORS_DIR / "fixtures"
    if not fixtures_root.is_dir():
        return []
    grouped: dict[str, list[Path]] = {}
    for path in sorted(fixtures_root.iterdir()):
        if not path.is_dir():
            continue
        positive = any((path / name).is_file() for name in POSITIVE_FIXTURE_NAMES)
        negative = any((path / name).is_file() for name in NEGATIVE_FIXTURE_NAMES)
        if positive and negative:
            grouped.setdefault(_norm_id(path.name), []).append(path)

    def rank(path: Path) -> tuple[int, int, str]:
        return (
            0 if (path / "smoke.json").is_file() else 1,
            0 if "_" in path.name else 1,
            path.name,
        )

    return [sorted(paths, key=rank)[0] for paths in grouped.values()]


def _nested_positive_fixture(slugs: list[str]) -> Optional[str]:
    dirs_by_name = {path.name: path for path in _canonical_fixture_dirs()}
    for slug in slugs:
        for name in (slug, slug.replace("-", "_"), slug.replace("_", "-")):
            candidate_dir = dirs_by_name.get(name)
            if not candidate_dir:
                continue
            for filename in POSITIVE_FIXTURE_NAMES:
                candidate = candidate_dir / filename
                if candidate.is_file():
                    return str(candidate)
    return None


# ---------------------------------------------------------------------------
# Python discovery (mirrors run-slither.sh logic)
# ---------------------------------------------------------------------------
def _find_slither_python() -> str:
    """Return the path to a Python interpreter that can `import slither`."""
    override = os.environ.get("AUDITOOOR_PYTHON_SLITHER", "")
    if override:
        try:
            subprocess.run(
                [override, "-c", "import slither"],
                check=True,
                capture_output=True,
                timeout=10,
            )
            return override
        except Exception:
            print(
                f"[warn] AUDITOOOR_PYTHON_SLITHER={override!r} cannot import slither — auto-detecting",
                file=sys.stderr,
            )
    for py in ["python3", "python3.14", "python3.13", "python3.12", "python3.11", "python"]:
        try:
            r = subprocess.run(
                [py, "-c", "import slither"],
                capture_output=True,
                timeout=10,
            )
            if r.returncode == 0:
                return py
        except FileNotFoundError:
            continue
        except Exception:
            continue
    raise RuntimeError(
        "No Python interpreter with slither-analyzer found.  "
        "Install with `pip install slither-analyzer` into your active environment, "
        "or set AUDITOOOR_PYTHON_SLITHER=/path/to/python."
    )


# ---------------------------------------------------------------------------
# Registry parsing
# ---------------------------------------------------------------------------
def load_registry() -> dict:
    try:
        import yaml  # type: ignore
    except ImportError:
        raise RuntimeError("PyYAML required: pip install pyyaml")
    with open(REGISTRY_PATH) as fh:
        raw = yaml.safe_load(fh)
    return raw.get("tiers", raw) or {}


def collect_detectors(registry: dict) -> list:
    """Return verified Slither A/B/S detector entries, with resolved own_vuln fixture path."""
    detectors = []
    for name, entry in registry.items():
        if not isinstance(entry, dict):
            continue
        if entry.get("tier") not in TARGET_TIERS:
            continue
        if not entry.get("verified"):
            continue
        if entry.get("engine", "none") != "slither":
            continue
        argument = entry.get("argument", name)
        own_vuln: Optional[str] = None
        cmd = entry.get("smoke_test_command", "")
        if cmd:
            parts = cmd.split()
            sol_parts = [p for p in parts if p.endswith(".sol")]
            if sol_parts:
                for rel in sol_parts:
                    abs_p = REPO_ROOT / rel
                    if abs_p.exists():
                        own_vuln = str(abs_p)
                        break
        if not own_vuln:
            fp = entry.get("fixture_pair", "")
            if fp:
                slugs = _slug_variants(fp)
                for base in [
                    DETECTORS_DIR / "test_fixtures",
                    REPO_ROOT / "patterns" / "fixtures",
                ]:
                    for slug in slugs:
                        for suffix in OWN_FIXTURE_SUFFIXES:
                            candidate = base / f"{slug}{suffix}"
                            if candidate.exists():
                                own_vuln = str(candidate)
                                break
                        if own_vuln:
                            break
                    if own_vuln:
                        break
                if not own_vuln:
                    own_vuln = _nested_positive_fixture(slugs)
        detectors.append(
            {
                "name": name,
                "argument": argument,
                "tier": entry.get("tier"),
                "own_vuln": own_vuln,
                "aliases": [name],
            }
        )
    deduped: dict[str, dict] = {}
    for detector in detectors:
        argument = str(detector.get("argument") or detector.get("name") or "")
        existing = deduped.get(argument)
        if existing is None:
            deduped[argument] = detector
            continue
        aliases = sorted(set(existing.get("aliases", []) + detector.get("aliases", [])))
        existing_has_fixture = bool(existing.get("own_vuln"))
        detector_has_fixture = bool(detector.get("own_vuln"))
        should_replace = (
            detector_has_fixture
            and not existing_has_fixture
        ) or (
            detector_has_fixture == existing_has_fixture
            and str(detector.get("name")) == argument
            and str(existing.get("name")) != argument
        )
        if should_replace:
            detector["aliases"] = aliases
            deduped[argument] = detector
        else:
            existing["aliases"] = aliases
    return list(deduped.values())


def resolve_selected_detector(detectors: list, selector: str) -> dict:
    """Resolve one detector by exact registry name, then exact argument."""
    by_name = [
        d
        for d in detectors
        if d.get("name") == selector or selector in d.get("aliases", [])
    ]
    if len(by_name) == 1:
        return by_name[0]
    if len(by_name) > 1:
        raise ValueError(f"ambiguous detector selector by name: {selector}")

    by_argument = [d for d in detectors if d.get("argument") == selector]
    if len(by_argument) == 1:
        return by_argument[0]
    if len(by_argument) > 1:
        raise ValueError(f"ambiguous detector selector by argument: {selector}")
    raise ValueError(f"unknown detector: {selector}")


# ---------------------------------------------------------------------------
# Fixture universe
# ---------------------------------------------------------------------------
def collect_fixtures() -> list:
    """Return Solidity fixtures from flat and canonical nested fixture corpora."""
    paths = []
    for base in [
        DETECTORS_DIR / "test_fixtures",
        REPO_ROOT / "patterns" / "fixtures",
    ]:
        if base.is_dir():
            paths.extend(str(p) for p in sorted(base.glob("*.sol")))
    for fixture_dir in _canonical_fixture_dirs():
        for filename in (*POSITIVE_FIXTURE_NAMES, *NEGATIVE_FIXTURE_NAMES):
            candidate = fixture_dir / filename
            if candidate.is_file():
                paths.append(str(candidate))
    return paths


# ---------------------------------------------------------------------------
# Per-pair worker (called in subprocess via ProcessPoolExecutor)
# ---------------------------------------------------------------------------
def _run_pair(args):
    """
    Run one detector against one fixture.
    Returns dict: detector_name, argument, fixture_path, hit_count, timed_out, errored, elapsed
    """
    detector_name, argument, fixture_path, slither_python, timeout_sec = args
    run_script = str(DETECTORS_DIR / "run_custom.py")
    cmd = [
        slither_python,
        run_script,
        "--tier=ALL",
        fixture_path,
        argument,
    ]
    t0 = time.monotonic()
    timed_out = False
    errored = False
    hit_count = 0
    try:
        smoke_env = os.environ.copy()
        smoke_env["AUDITOOOR_FIXTURE_SMOKE_MODE"] = "1"
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_sec,
            cwd=str(REPO_ROOT),
            env=smoke_env,
        )
        elapsed = time.monotonic() - t0
        output = result.stdout + result.stderr
        m = re.search(r"\[done\] total hits:\s*(\d+)", output)
        if m:
            hit_count = int(m.group(1))
        elif result.returncode != 0:
            errored = True
    except subprocess.TimeoutExpired:
        timed_out = True
        elapsed = time.monotonic() - t0
    except Exception:
        errored = True
        elapsed = time.monotonic() - t0

    return {
        "detector_name": detector_name,
        "argument": argument,
        "fixture_path": fixture_path,
        "hit_count": hit_count,
        "timed_out": timed_out,
        "errored": errored,
        "elapsed": round(elapsed, 2),
    }


# ---------------------------------------------------------------------------
# Main matrix builder
# ---------------------------------------------------------------------------
def _is_own_fixture(fixture_path: str, own_vuln: str | None) -> bool:
    if not own_vuln:
        return False
    return os.path.abspath(fixture_path) == os.path.abspath(own_vuln)


def _record_pair_hit(stats_row: dict, pair_result: dict) -> None:
    hits = pair_result["hit_count"]
    if hits <= 0:
        return

    if _is_own_fixture(pair_result["fixture_path"], stats_row.get("own_vuln")):
        stats_row["tp_count"] += 1
        return

    fx_name = Path(pair_result["fixture_path"]).name
    stats_row["fp_count"] += 1
    stats_row["_fp_details"].append({"fixture": fx_name, "hit_count": hits})


def build_matrix(detectors, fixtures, slither_python, workers, timeout_sec):
    """
    Run each detector against each fixture.
    Returns a dict: meta + per-detector aggregate stats.
    """
    work = []
    for d in detectors:
        for fx in fixtures:
            work.append((d["name"], d["argument"], fx, slither_python, timeout_sec))

    total_pairs = len(work)
    print(
        f"[matrix] {len(detectors)} detectors × {len(fixtures)} fixtures "
        f"= {total_pairs} detector×fixture pairs",
        flush=True,
    )
    print(f"[matrix] workers={workers}, timeout={timeout_sec}s", flush=True)

    stats = {}
    for d in detectors:
        stats[d["name"]] = {
            "argument": d["argument"],
            "tier": d["tier"],
            "own_vuln": d.get("own_vuln"),
            "total_fixtures_tested": 0,
            "fp_count": 0,
            "tp_count": 0,
            "timeout_count": 0,
            "error_count": 0,
            "untestable": False,
            "top_5_unintended_fires": [],
            "_fp_details": [],
            "_consecutive_timeouts": 0,
        }

    bailed = set()
    completed = 0
    t0_global = time.monotonic()

    with ProcessPoolExecutor(max_workers=workers) as executor:
        future_to_work = {}
        CHUNK = workers * 4
        pending = list(work)
        submitted = []

        def submit_more():
            while pending and len(submitted) < CHUNK:
                item = pending.pop(0)
                if item[0] in bailed:
                    continue
                fut = executor.submit(_run_pair, item)
                future_to_work[fut] = item
                submitted.append(fut)

        submit_more()

        while submitted:
            done_set, _ = wait(submitted, return_when=FIRST_COMPLETED, timeout=5)

            for fut in list(done_set):
                submitted.remove(fut)
                item = future_to_work.pop(fut, None)
                if item is None:
                    continue

                det_name = item[0]
                try:
                    r = fut.result(timeout=0)
                except Exception:
                    r = {
                        "detector_name": det_name,
                        "argument": item[1],
                        "fixture_path": item[2],
                        "hit_count": 0,
                        "timed_out": False,
                        "errored": True,
                        "elapsed": 0,
                    }

                completed += 1
                s = stats.get(det_name)
                if s is None:
                    continue

                if r["timed_out"]:
                    s["timeout_count"] += 1
                    s["_consecutive_timeouts"] = s.get("_consecutive_timeouts", 0) + 1
                    if s["_consecutive_timeouts"] >= CONSECUTIVE_TIMEOUT_BAIL:
                        s["untestable"] = True
                        bailed.add(det_name)
                else:
                    s["_consecutive_timeouts"] = 0

                if r["errored"] and not r["timed_out"]:
                    s["error_count"] += 1
                    continue

                if r["timed_out"] or det_name in bailed:
                    continue

                s["total_fixtures_tested"] += 1
                _record_pair_hit(s, r)

                if completed % 200 == 0:
                    elapsed = time.monotonic() - t0_global
                    rate = completed / elapsed if elapsed > 0 else 0
                    remaining = total_pairs - completed
                    eta = remaining / rate if rate > 0 else float("inf")
                    print(
                        f"[matrix] {completed}/{total_pairs} pairs done "
                        f"({rate:.1f}/s, ETA {eta/60:.1f}m)",
                        flush=True,
                    )

            submit_more()

    for det_name, s in stats.items():
        tp = s["tp_count"]
        fp = s["fp_count"]
        denom = tp + fp
        s["precision"] = round(tp / denom, 4) if denom > 0 else None
        top5 = sorted(s["_fp_details"], key=lambda x: -x["hit_count"])[:5]
        s["top_5_unintended_fires"] = top5
        del s["_fp_details"]
        del s["_consecutive_timeouts"]

    total_elapsed = time.monotonic() - t0_global
    return {
        "detectors": stats,
        "meta": {
            "detector_count": len(detectors),
            "fixture_count": len(fixtures),
            "total_pairs": total_pairs,
            "completed_pairs": completed,
            "elapsed_seconds": round(total_elapsed, 1),
            "workers": workers,
            "timeout_per_pair": timeout_sec,
        },
    }


# ---------------------------------------------------------------------------
# M14-trap spot-check
# ---------------------------------------------------------------------------
def spot_check(detectors, fixtures, slither_python, timeout_sec, seed):
    """
    Run 3 random cross-product pairs manually to verify the harness is not silently
    erroring and counting errors as 0-hit (which would falsely inflate precision).
    """
    rng = random.Random(seed + 999)
    sample_d = rng.sample(detectors[:50], min(3, len(detectors)))
    sample_f = rng.sample(fixtures[:200], min(3, len(fixtures)))
    pairs = list(zip(sample_d, sample_f))
    print("[spot-check] Verifying 3 random pairs manually (M14-trap)...", flush=True)
    all_ok = True
    for d, fx in pairs:
        r = _run_pair((d["name"], d["argument"], fx, slither_python, timeout_sec))
        own_vuln = d.get("own_vuln") or ""
        label = "SELF-PAIR" if os.path.abspath(fx) == os.path.abspath(own_vuln) else "cross-pair"
        status = "TIMEOUT" if r["timed_out"] else ("ERROR" if r["errored"] else f"hits={r['hit_count']}")
        print(
            f"  [spot-check] det={d['name'][:40]} fix={Path(fx).name[:40]} "
            f"({label}) => {status} in {r['elapsed']:.1f}s",
            flush=True,
        )
        if r["errored"] and not r["timed_out"]:
            print(
                "  [spot-check] WARNING: pair errored — check that run_custom.py is reachable "
                "and slither python is correct",
                flush=True,
            )
            all_ok = False
    return all_ok


# ---------------------------------------------------------------------------
# JSON / Markdown output
# ---------------------------------------------------------------------------
def write_json(result, path):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as fh:
        json.dump(result, fh, indent=2)
    print(f"[out] JSON written to {path}", flush=True)


def write_markdown(result, path):
    meta = result["meta"]
    detectors = result["detectors"]

    rows = []
    for name, s in detectors.items():
        fp = s["fp_count"]
        total = s["total_fixtures_tested"]
        fp_rate = fp / total if total > 0 else 0.0
        prec = s["precision"]
        rows.append((name, s, fp_rate, prec))
    rows.sort(key=lambda x: -x[2])

    tested_rows = [r for r in rows if r[1]["total_fixtures_tested"] > 0]
    precisions = [r[3] for r in tested_rows if r[3] is not None]
    avg_prec = sum(precisions) / len(precisions) if precisions else 0.0
    count_low_prec = sum(1 for p in precisions if p < 0.5)
    count_high_fp = sum(1 for r in tested_rows if r[2] > 0.20)
    untestable_count = sum(1 for _, s, _, _ in rows if s.get("untestable"))

    lines = [
        "# Detector Precision Matrix",
        "",
        f"Generated: {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}",
        "",
        "## Summary",
        "",
        "| Metric | Value |",
        "|--------|-------|",
        f"| Detectors in sample | {meta['detector_count']} |",
        f"| Fixtures in sample | {meta['fixture_count']} |",
        f"| Total pairs evaluated | {meta['completed_pairs']} / {meta['total_pairs']} |",
        f"| Wall time | {meta['elapsed_seconds']:.0f}s |",
        f"| Workers | {meta['workers']} |",
        f"| Per-pair timeout | {meta['timeout_per_pair']}s |",
        f"| Avg precision (detectors that fired) | {avg_prec:.3f} |",
        f"| Detectors with precision < 0.5 | {count_low_prec} |",
        f"| Detectors with FP rate > 20% | {count_high_fp} |",
        f"| Untestable (10+ consecutive timeouts) | {untestable_count} |",
        "",
        "## Bottleneck / Caveats",
        "",
        "**Performance bottleneck:** Each detector×fixture pair spawns `run_custom.py` as a "
        "fresh subprocess (~4-5 s on this hardware — Slither re-compiles the fixture from "
        "scratch every invocation).  "
        f"Full cross-product ({meta.get('detector_count', 599)} detectors × "
        "4434 total fixtures) ≈ 890k pairs × 5 s = **~620 CPU-hours**.  "
        f"Even `--sample-detectors 50 --sample-fixtures 100` (5000 pairs at "
        f"{meta['workers']} workers) takes ~50 min.  "
        "**Recommendation:** build a persistent Slither AST/compilation cache keyed "
        "on (fixture_hash, solc_version) so each fixture compiles once and results "
        "are replayed for all detectors.  This would reduce per-pair cost to <50 ms "
        "and make the full cross-product practical.",
        "",
        "**Precision definition:** `TP / (TP + FP)` where TP = fires on the detector's "
        "*own* vulnerable fixture (if that fixture was included in this sample), "
        "FP = fires on any non-owned fixture.  "
        "`None` precision = the detector never fired on any tested fixture "
        "(not a precision problem — just did not trigger in this sample).",
        "",
        "## Per-Detector Results (sorted by FP rate descending)",
        "",
        "| Detector | Tier | Fixtures Tested | FP Count | TP Count | FP Rate | Precision | Top Unintended Fire |",
        "|----------|------|----------------|----------|----------|---------|-----------|---------------------|",
    ]

    for name, s, fp_rate, prec in rows:
        total = s["total_fixtures_tested"]
        fp = s["fp_count"]
        tp = s["tp_count"]
        prec_str = f"{prec:.3f}" if prec is not None else "N/A"
        fp_rate_str = f"{fp_rate:.1%}" if total > 0 else "—"
        top_fire = s["top_5_unintended_fires"][0]["fixture"][:50] if s["top_5_unintended_fires"] else "—"
        untestable_flag = " *(untestable)*" if s.get("untestable") else ""
        lines.append(
            f"| `{name}`{untestable_flag} | {s['tier']} | {total} | {fp} | {tp} | "
            f"{fp_rate_str} | {prec_str} | {top_fire} |"
        )

    lines += [
        "",
        "## Top-5 Unintended Fires per Detector (worst 20 by FP rate)",
        "",
    ]
    for name, s, fp_rate, prec in rows[:20]:
        if not s["top_5_unintended_fires"]:
            continue
        lines.append(f"### `{name}` (FP rate: {fp_rate:.1%})")
        lines.append("")
        lines.append("| Fixture | Hits |")
        lines.append("|---------|------|")
        for entry in s["top_5_unintended_fires"]:
            lines.append(f"| `{entry['fixture']}` | {entry['hit_count']} |")
        lines.append("")

    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as fh:
        fh.write("\n".join(lines) + "\n")
    print(f"[out] Markdown written to {path}", flush=True)


# ---------------------------------------------------------------------------
# ACT-11: cache module loader (lazy, no hard dependency)
# ---------------------------------------------------------------------------

def _try_load_cache_module():
    """Return slither_compile_cache module, or None if unavailable."""
    try:
        import importlib.util as _ilu
        spec = _ilu.spec_from_file_location(
            "slither_compile_cache",
            REPO_ROOT / "tools" / "slither-compile-cache.py",
        )
        if spec is None:
            return None
        mod = _ilu.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod
    except Exception:
        return None


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def parse_args(argv=None):
    p = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--detector", type=str, default=None, metavar="ARG",
                   help="Only test one exact detector name/argument (default: all)")
    p.add_argument("--sample-detectors", type=int, default=None, metavar="N",
                   help="Only test N randomly-selected detectors (default: all)")
    p.add_argument("--sample-fixtures", type=int, default=None, metavar="M",
                   help="Only test M randomly-selected fixtures (default: all)")
    p.add_argument("--json-out", type=Path, default=DEFAULT_JSON_OUT, metavar="PATH",
                   help=f"Output JSON path (default: {DEFAULT_JSON_OUT})")
    p.add_argument("--md-out", type=Path, default=DEFAULT_MD_OUT, metavar="PATH",
                   help=f"Output Markdown path (default: {DEFAULT_MD_OUT})")
    p.add_argument("--workers", type=int, default=None, metavar="N",
                   help="ProcessPool workers (default: min(8, cpu_count))")
    p.add_argument("--timeout", type=int, default=30, metavar="N",
                   help="Per-invocation wall timeout in seconds (default: 30)")
    p.add_argument("--seed", type=int, default=42, metavar="N",
                   help="RNG seed for reproducible sampling (default: 42)")
    p.add_argument("--no-spot-check", action="store_true",
                   help="Skip the M14-trap spot-check of 3 random pairs")
    p.add_argument("--cache-stats", action="store_true",
                   help="Reset and print Slither compile-cache hit/miss counters (ACT-11)")
    p.add_argument("--no-cache", action="store_true",
                   help="Bypass Slither compile cache entirely for this run (ACT-11)")
    args = p.parse_args(argv)
    if args.detector and args.sample_detectors is not None:
        p.error("--detector cannot be combined with --sample-detectors")
    return args


def main(argv=None):
    args = parse_args(argv)

    # ACT-11: cache flag handling
    _cache_mod = None
    if args.no_cache:
        os.environ["AUDITOOOR_SLITHER_NOCACHE"] = "1"
        print("[cache] compile cache DISABLED for this run (--no-cache)", flush=True)
    else:
        os.environ.pop("AUDITOOOR_SLITHER_NOCACHE", None)
        if args.cache_stats:
            _cache_mod = _try_load_cache_module()
            if _cache_mod is not None:
                _cache_mod.reset_run_stats()
                print("[cache] hit/miss counters reset", flush=True)
            else:
                print("[cache] warn: cache module not found; --cache-stats unavailable", flush=True)

    workers = args.workers or min(8, os.cpu_count() or 4)
    timeout_sec = args.timeout

    print(f"[init] Repo root: {REPO_ROOT}", flush=True)
    print(f"[init] Registry: {REGISTRY_PATH}", flush=True)

    try:
        slither_python = _find_slither_python()
        print(f"[init] Slither python: {slither_python}", flush=True)
    except RuntimeError as e:
        print(f"[fatal] {e}", file=sys.stderr)
        sys.exit(1)

    try:
        registry = load_registry()
    except Exception as e:
        print(f"[fatal] Failed to load registry: {e}", file=sys.stderr)
        sys.exit(1)

    all_detectors = collect_detectors(registry)
    print(f"[init] Verified Slither A/B/S detectors: {len(all_detectors)}", flush=True)

    all_fixtures = collect_fixtures()
    print(f"[init] Fixture universe: {len(all_fixtures)} .sol files", flush=True)

    rng = random.Random(args.seed)
    detectors = all_detectors
    fixtures = all_fixtures

    if args.detector:
        try:
            selected = resolve_selected_detector(all_detectors, args.detector)
        except ValueError as e:
            print(f"[fatal] {e}", file=sys.stderr)
            sys.exit(2)
        detectors = [selected]
        print(
            f"[select] detector={selected['name']} argument={selected['argument']}",
            flush=True,
        )

    if args.sample_detectors is not None:
        n = min(args.sample_detectors, len(detectors))
        detectors = rng.sample(detectors, n)
        print(f"[sample] Using {n} detectors (--sample-detectors {args.sample_detectors})", flush=True)

    if args.sample_fixtures is not None:
        m = min(args.sample_fixtures, len(fixtures))
        fixtures = rng.sample(fixtures, m)
        print(f"[sample] Using {m} fixtures (--sample-fixtures {args.sample_fixtures})", flush=True)

    if not detectors:
        print("[fatal] No detectors to test.", file=sys.stderr)
        sys.exit(1)
    if not fixtures:
        print("[fatal] No fixtures to test against.", file=sys.stderr)
        sys.exit(1)

    n_pairs = len(detectors) * len(fixtures)
    est_cpu_sec = n_pairs * 5.0  # ~5s per pair (measured)
    est_wall_sec = est_cpu_sec / workers
    print(
        f"[estimate] ~{n_pairs} pairs, ~{est_cpu_sec/3600:.1f} CPU-hours, "
        f"~{est_wall_sec/60:.1f} min wall time at {workers} workers",
        flush=True,
    )
    if est_wall_sec > 600:
        print(
            f"[warn] Estimated wall time {est_wall_sec/60:.0f}m exceeds 10 min.  "
            "Use --sample-detectors 20 --sample-fixtures 25 for a sub-5-min run.",
            flush=True,
        )

    if not args.no_spot_check:
        ok = spot_check(detectors, fixtures, slither_python, timeout_sec, args.seed)
        if not ok:
            print(
                "[warn] Spot-check found errors — results may be unreliable. "
                "Check AUDITOOOR_PYTHON_SLITHER and slither installation.",
                flush=True,
            )

    result = build_matrix(detectors, fixtures, slither_python, workers, timeout_sec)

    write_json(result, args.json_out)
    write_markdown(result, args.md_out)

    meta = result["meta"]
    dets = result["detectors"]
    tested = [s for s in dets.values() if s["total_fixtures_tested"] > 0]
    any_fp = [s for s in tested if s["fp_count"] > 0]
    print(
        f"\n[done] {meta['completed_pairs']} pairs evaluated in {meta['elapsed_seconds']:.0f}s  "
        f"| detectors with FPs: {len(any_fp)}/{len(tested)} tested  "
        f"| untestable: {sum(1 for s in dets.values() if s.get('untestable'))}",
        flush=True,
    )

    # ACT-11: print cache stats if requested
    if args.cache_stats and _cache_mod is not None:
        stats = _cache_mod.get_run_stats()
        hits = stats.get("hits", 0)
        misses = stats.get("misses", 0)
        total = hits + misses
        hit_rate = hits / total if total > 0 else 0.0
        print(
            f"[cache] hits={hits}  misses={misses}  hit_rate={hit_rate:.2%}",
            flush=True,
        )


if __name__ == "__main__":
    main()
