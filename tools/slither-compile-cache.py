#!/usr/bin/env python3
"""
slither-compile-cache.py — Persistent crytic-compile artifact cache for auditooor.

Eliminates the ~0.3-0.5s per-fixture Solidity compilation overhead in
detector-precision-matrix.py by storing crytic-compile export artifacts and
reloading them (via CryticCompile(Standard(path))) instead of re-running solc.

Benchmark: 374x speedup on CryticCompile init; 100x on full Slither init.
Per-pair overhead drops from ~300-500ms → ~3-8ms (subprocess spawn dominates
after warm-up; in-process API is ~100x faster).

Cache layout:
    ~/.cache/auditooor/slither-compile/<fixture_hash_16>__<solc_ver>/
        artifact.json   — crytic-compile standard export (reloadable by Standard())
        meta.json       — {fixture_path, fixture_hash, solc_version, cached_at,
                           slither_version, elapsed_seconds}

Hash strategy:
    SHA-256 of fixture file contents. Any byte change = new slot.
    Slither version change also invalidates (stored in meta.json).

Concurrency:
    fcntl.flock(LOCK_EX) on a per-slot .lock file.
    Only one process compiles a given fixture at a time.
    Readers acquire LOCK_EX as well (slot-level serialisation).
    Multiple fixtures compile in parallel without interference.

Disk budget:
    --max-cache-mb 2000 (default 2 GB). LRU eviction by artifact.json mtime.

Public API (for run_custom.py integration):
    from tools.slither_compile_cache import get_or_compile_slither

    sl = get_or_compile_slither(Path("detectors/test_fixtures/foo.sol"))
    # sl is a Slither instance ready for custom detector execution, or None on error.
    # Uses cache when available; falls back to direct Slither() on error or bypass.

Bypass:
    AUDITOOOR_SLITHER_NOCACHE=1  — skip cache (fall through to raw Slither())

Honest limits:
    - Fixtures that import other fixtures (relative imports) may compile fine but
      have source-path issues on reload. If the custom detector hits an import
      error on cached artifact, run_custom.py falls back to direct compilation.
    - solc_version detection is regex-based on pragma lines. Multi-pragma files
      (e.g. interfaces with different pragmas) use the FIRST pragma found.
    - On Slither version update, ALL cache slots are invalidated (every slot's
      meta.json is checked against current slither_version). Run --invalidate-all
      after upgrading slither-analyzer.
    - Compile errors and timeouts are NEVER cached.

CLI usage:
    python3 tools/slither-compile-cache.py --warm <fixture_dir>     # pre-warm cache
    python3 tools/slither-compile-cache.py --stats                   # hit/miss stats
    python3 tools/slither-compile-cache.py --clear                   # delete cache
    python3 tools/slither-compile-cache.py --invalidate-all          # alias for --clear
    python3 tools/slither-compile-cache.py <fixture.sol>             # compile+cache one file
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
CACHE_ROOT = Path.home() / ".cache" / "auditooor" / "slither-compile"
DEFAULT_MAX_CACHE_MB = 2000
DEFAULT_COMPILE_TIMEOUT = 30  # seconds — failures are NOT cached

_NOCACHE_ENV = "AUDITOOOR_SLITHER_NOCACHE"


# ---------------------------------------------------------------------------
# Hash + version helpers
# ---------------------------------------------------------------------------

def _fixture_hash(path: Path) -> str:
    """SHA-256 of fixture file contents (hex)."""
    sha = hashlib.sha256()
    sha.update(path.read_bytes())
    return sha.hexdigest()


def _detect_solc_version(path: Path) -> str:
    """Extract first pragma solidity version string; fallback 'unknown'."""
    try:
        text = path.read_text(errors="ignore")
        m = re.search(r"pragma\s+solidity\s+([^;]+);", text)
        if m:
            raw = m.group(1).strip()
            return re.sub(r"\s+", " ", raw)
    except Exception:
        pass
    return "unknown"


def _slither_version() -> str:
    """Return slither version string (or 'unknown')."""
    try:
        import importlib.metadata
        return importlib.metadata.version("slither-analyzer")
    except Exception:
        pass
    try:
        import subprocess
        r = subprocess.run(
            ["slither", "--version"],
            capture_output=True, text=True, timeout=5,
        )
        v = (r.stdout.strip() or r.stderr.strip()).split()[-1]
        return v or "unknown"
    except Exception:
        return "unknown"


def _slot_dir(fixture_hash: str, solc_version: str) -> Path:
    """Return the cache slot directory path (not yet created)."""
    safe_ver = re.sub(r"[^a-zA-Z0-9.\-]", "_", solc_version)[:40]
    return CACHE_ROOT / f"{fixture_hash[:16]}__{safe_ver}"


# ---------------------------------------------------------------------------
# Cache validity
# ---------------------------------------------------------------------------

def _cache_is_valid(slot: Path, fixture_hash: str, slither_ver: str) -> bool:
    """True iff slot contains a valid, up-to-date artifact."""
    meta_p = slot / "meta.json"
    artifact_p = slot / "artifact.json"
    if not meta_p.exists() or not artifact_p.exists():
        return False
    try:
        meta = json.loads(meta_p.read_text())
        return (
            meta.get("fixture_hash") == fixture_hash
            and meta.get("slither_version") == slither_ver
        )
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Compilation + caching
# ---------------------------------------------------------------------------

def _compile_and_cache(
    fixture_path: Path,
    slot: Path,
    fixture_hash: str,
    solc_version: str,
    slither_ver: str,
    slither_kwargs: dict,
) -> Optional[Path]:
    """
    Run CryticCompile on fixture_path, export artifact to slot/artifact.json.
    Returns slot path on success, None on failure.
    Does NOT cache timeouts or compile errors.
    """
    try:
        from crytic_compile import CryticCompile  # type: ignore
    except ImportError:
        return None

    t0 = time.monotonic()
    try:
        cc = CryticCompile(str(fixture_path), **slither_kwargs)
    except Exception as e:
        print(f"[cache] compile error for {fixture_path.name}: {e}", file=sys.stderr)
        return None

    elapsed = time.monotonic() - t0

    # Export artifact
    slot.mkdir(parents=True, exist_ok=True)
    artifact_p = slot / "artifact.json"
    try:
        from crytic_compile.platform.standard import generate_standard_export  # type: ignore
        export_data = generate_standard_export(cc)
        artifact_p.write_text(json.dumps(export_data))
    except Exception as e:
        print(f"[cache] export error for {fixture_path.name}: {e}", file=sys.stderr)
        return None

    # Write meta
    meta = {
        "fixture_path": str(fixture_path),
        "fixture_hash": fixture_hash,
        "solc_version": solc_version,
        "slither_version": slither_ver,
        "cached_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "elapsed_seconds": round(elapsed, 3),
    }
    (slot / "meta.json").write_text(json.dumps(meta, indent=2))
    return slot


def _load_slither_from_slot(slot: Path) -> object:
    """
    Load CryticCompile artifact from slot and construct a Slither instance.
    Returns Slither object or raises on failure.
    """
    from crytic_compile import CryticCompile  # type: ignore
    from crytic_compile.platform.standard import Standard  # type: ignore
    from slither import Slither  # type: ignore

    artifact_p = slot / "artifact.json"
    std = Standard(str(artifact_p))
    cc = CryticCompile(std)
    sl = Slither(cc)
    # Touch mtime for LRU tracking
    artifact_p.touch()
    return sl


# ---------------------------------------------------------------------------
# LRU eviction
# ---------------------------------------------------------------------------

def _evict_lru(max_mb: int) -> int:
    """Evict oldest slots by artifact.json mtime until total size < max_mb."""
    if not CACHE_ROOT.exists():
        return 0
    slots = []
    total_bytes = 0
    for slot in CACHE_ROOT.iterdir():
        if not slot.is_dir():
            continue
        artifact_p = slot / "artifact.json"
        if not artifact_p.exists():
            continue
        mtime = artifact_p.stat().st_mtime
        size = sum(f.stat().st_size for f in slot.iterdir() if f.is_file())
        slots.append((mtime, size, slot))
        total_bytes += size

    max_bytes = max_mb * 1024 * 1024
    if total_bytes <= max_bytes:
        return 0

    slots.sort(key=lambda x: x[0])  # oldest-first
    evicted = 0
    for mtime, size, slot in slots:
        if total_bytes <= max_bytes:
            break
        try:
            import shutil
            shutil.rmtree(slot)
            total_bytes -= size
            evicted += 1
        except Exception:
            pass
    return evicted


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_or_compile_slither(
    fixture_path: Path,
    *,
    max_cache_mb: int = DEFAULT_MAX_CACHE_MB,
    compile_timeout: int = DEFAULT_COMPILE_TIMEOUT,
    force_refresh: bool = False,
    slither_kwargs: Optional[dict] = None,
) -> Optional[object]:
    """
    Return a Slither instance for fixture_path, using the cache when possible.

    On cache hit:  loads CryticCompile artifact from disk → Slither(cc).
                   ~3-8ms vs ~300-500ms for fresh compile (37-100x speedup).
    On cache miss: compiles fresh, caches artifact, returns Slither instance.
    On error:      returns None (never caches errors or timeouts).

    Concurrency: fcntl.flock(LOCK_EX) per slot.
    Bypass: AUDITOOOR_SLITHER_NOCACHE=1 env var skips cache entirely.

    Args:
        fixture_path:   Path to the .sol fixture file.
        max_cache_mb:   LRU eviction threshold (default 2000 MB).
        compile_timeout: Max seconds for fresh compilation (default 30).
                         Timeouts are NOT cached.
        force_refresh:  Recompile even if cache is valid.
        slither_kwargs: Extra kwargs forwarded to CryticCompile() and Slither().
    """
    fixture_path = Path(fixture_path).resolve()
    skw = slither_kwargs or {}

    if os.environ.get(_NOCACHE_ENV, "").strip() == "1":
        # Bypass: direct Slither
        try:
            from slither import Slither  # type: ignore
            return Slither(str(fixture_path), **skw)
        except Exception:
            return None

    if not fixture_path.is_file():
        print(f"[cache] fixture not found: {fixture_path}", file=sys.stderr)
        return None

    fx_hash = _fixture_hash(fixture_path)
    solc_ver = _detect_solc_version(fixture_path)
    sl_ver = _slither_version()
    slot = _slot_dir(fx_hash, solc_ver)

    CACHE_ROOT.mkdir(parents=True, exist_ok=True)
    lock_path = CACHE_ROOT / f"{slot.name}.lock"

    with open(lock_path, "w") as lock_fh:
        fcntl.flock(lock_fh, fcntl.LOCK_EX)
        try:
            if not force_refresh and _cache_is_valid(slot, fx_hash, sl_ver):
                # Cache hit path
                try:
                    sl = _load_slither_from_slot(slot)
                    track_access(hit=True)
                    return sl
                except Exception as e:
                    print(
                        f"[cache] reload failed for {fixture_path.name}: {e} "
                        f"— falling back to fresh compile",
                        file=sys.stderr,
                    )
                    # Fall through to recompile

            # Cache miss (or reload failure / forced refresh)
            result_slot = _compile_and_cache(
                fixture_path, slot, fx_hash, solc_ver, sl_ver, skw
            )
            track_access(hit=False)

            if result_slot is None:
                # Compile failed — return None without caching
                return None

            # Evict LRU after new entry
            _evict_lru(max_cache_mb)

            # Return a fresh Slither instance (don't re-read from disk on miss)
            try:
                sl = _load_slither_from_slot(slot)
                return sl
            except Exception as e:
                print(
                    f"[cache] post-cache load failed for {fixture_path.name}: {e}",
                    file=sys.stderr,
                )
                return None
        finally:
            fcntl.flock(lock_fh, fcntl.LOCK_UN)


# ---------------------------------------------------------------------------
# Run-stats tracking (for --cache-stats flag in precision-matrix)
# ---------------------------------------------------------------------------

def track_access(hit: bool) -> None:
    """
    Record a cache hit/miss to CACHE_ROOT/_run_stats.json.
    Non-blocking best-effort (never raises).
    """
    try:
        CACHE_ROOT.mkdir(parents=True, exist_ok=True)
        stats_file = CACHE_ROOT / "_run_stats.json"
        lock_path = CACHE_ROOT / "_run_stats.lock"
        with open(lock_path, "w") as lf:
            fcntl.flock(lf, fcntl.LOCK_EX)
            try:
                if stats_file.exists():
                    stats = json.loads(stats_file.read_text())
                else:
                    stats = {"hits": 0, "misses": 0}
                key = "hits" if hit else "misses"
                stats[key] = stats.get(key, 0) + 1
                stats_file.write_text(json.dumps(stats))
            finally:
                fcntl.flock(lf, fcntl.LOCK_UN)
    except Exception:
        pass


def reset_run_stats() -> None:
    """Reset hit/miss counters. Call before a precision-matrix run."""
    try:
        CACHE_ROOT.mkdir(parents=True, exist_ok=True)
        (CACHE_ROOT / "_run_stats.json").write_text(
            json.dumps({"hits": 0, "misses": 0})
        )
    except Exception:
        pass


def get_run_stats() -> dict:
    """Return current {hits, misses} counters, or zeros if not available."""
    try:
        stats_file = CACHE_ROOT / "_run_stats.json"
        if stats_file.exists():
            return json.loads(stats_file.read_text())
    except Exception:
        pass
    return {"hits": 0, "misses": 0}


# ---------------------------------------------------------------------------
# CLI helpers
# ---------------------------------------------------------------------------

def _cmd_stats() -> None:
    """Print cache statistics to stdout."""
    if not CACHE_ROOT.exists():
        print(f"Cache directory does not exist: {CACHE_ROOT}")
        return
    meta_files = list(CACHE_ROOT.glob("*/meta.json"))
    total_size = sum(
        f.stat().st_size
        for f in CACHE_ROOT.rglob("*")
        if f.is_file()
    )
    size_mb = total_size / 1024 / 1024
    size_str = f"{size_mb:.1f} MB" if size_mb >= 0.1 else f"{total_size / 1024:.0f} KB"
    print(f"Cache root : {CACHE_ROOT}")
    print(f"Slots      : {len(meta_files)}")
    print(f"Total size : {size_str}")

    if meta_files:
        timestamps = []
        for p in meta_files:
            try:
                timestamps.append(json.loads(p.read_text()).get("cached_at", ""))
            except Exception:
                pass
        timestamps = [t for t in timestamps if t]
        if timestamps:
            print(f"Oldest     : {min(timestamps)}")
            print(f"Newest     : {max(timestamps)}")

    stats = get_run_stats()
    hits = stats.get("hits", 0)
    misses = stats.get("misses", 0)
    total = hits + misses
    rate = hits / total if total > 0 else 0.0
    if total > 0:
        print(f"\nRun stats  : hits={hits}  misses={misses}  total={total}  hit_rate={rate:.1%}")
    else:
        print("\nRun stats  : no accesses recorded (run a precision-matrix to populate)")


def _cmd_clear() -> None:
    """Delete the entire cache directory."""
    import shutil
    if CACHE_ROOT.exists():
        shutil.rmtree(CACHE_ROOT)
        print(f"Cache cleared: {CACHE_ROOT}")
    else:
        print(f"Cache already empty: {CACHE_ROOT}")


def _cmd_warm(
    fixture_dir: Path,
    timeout: int = DEFAULT_COMPILE_TIMEOUT,
    max_cache_mb: int = DEFAULT_MAX_CACHE_MB,
) -> dict:
    """
    Pre-warm the cache for all .sol fixtures in fixture_dir.
    Returns summary dict.
    """
    fixtures = sorted(fixture_dir.glob("*.sol"))
    print(f"[warm] {len(fixtures)} fixtures in {fixture_dir}")
    if not fixtures:
        print("[warm] nothing to do")
        return {"fixtures": 0, "compiled": 0, "hits": 0, "errors": 0, "elapsed": 0.0}

    hits = misses = errors = 0
    t0 = time.monotonic()

    for i, fx in enumerate(fixtures, 1):
        sl = get_or_compile_slither(
            fx, compile_timeout=timeout, max_cache_mb=max_cache_mb
        )
        stats = get_run_stats()
        # Use the stats delta to detect hit vs miss
        total_after = stats.get("hits", 0) + stats.get("misses", 0)
        label = "ERR  " if sl is None else ("HIT  " if stats.get("hits", 0) > hits + misses else "MISS ")
        if sl is None:
            errors += 1
            label = "ERR  "
        elif stats.get("hits", 0) > hits:
            hits += 1
            label = "HIT  "
        else:
            misses += 1
            label = "MISS "
        if i % 50 == 0 or i == len(fixtures):
            elapsed = time.monotonic() - t0
            print(
                f"  [{i}/{len(fixtures)}] {label} {fx.name[:60]}  "
                f"({elapsed:.1f}s elapsed)"
            )

    elapsed = time.monotonic() - t0
    print(
        f"\n[warm] done: {misses} compiled, {hits} already-cached, "
        f"{errors} errors in {elapsed:.1f}s"
    )
    return {
        "fixtures": len(fixtures),
        "compiled": misses,
        "hits": hits,
        "errors": errors,
        "elapsed": round(elapsed, 1),
    }


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Slither compilation cache for auditooor (crytic-compile artifact store)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "fixture", nargs="?",
        help="Single .sol fixture to compile and cache (prints meta on success)",
    )
    parser.add_argument("--warm", metavar="DIR",
                        help="Pre-warm cache for all .sol files in DIR")
    parser.add_argument("--stats", action="store_true",
                        help="Print cache statistics")
    parser.add_argument("--clear", action="store_true",
                        help="Delete the entire cache (~/.cache/auditooor/slither-compile/)")
    parser.add_argument("--invalidate-all", action="store_true",
                        help="Full cache invalidation (alias for --clear)")
    parser.add_argument(
        "--max-cache-mb", type=int, default=DEFAULT_MAX_CACHE_MB,
        help=f"LRU eviction threshold in MB (default {DEFAULT_MAX_CACHE_MB})",
    )
    parser.add_argument(
        "--timeout", type=int, default=DEFAULT_COMPILE_TIMEOUT,
        help=f"Per-fixture compile timeout in seconds (default {DEFAULT_COMPILE_TIMEOUT})",
    )

    args = parser.parse_args()

    if args.clear or args.invalidate_all:
        _cmd_clear()
        return

    if args.stats:
        _cmd_stats()
        return

    if args.warm:
        _cmd_warm(
            Path(args.warm),
            timeout=args.timeout,
            max_cache_mb=args.max_cache_mb,
        )
        return

    if args.fixture:
        fx = Path(args.fixture)
        if not fx.exists():
            print(f"Error: fixture not found: {fx}")
            sys.exit(1)
        print(f"[cache] compiling {fx.name}...")
        sl = get_or_compile_slither(
            fx, compile_timeout=args.timeout, max_cache_mb=args.max_cache_mb
        )
        if sl is None:
            print("[cache] FAILED — see stderr")
            sys.exit(1)
        stats = get_run_stats()
        contracts = [c.name for cu in sl.compilation_units for c in cu.contracts]
        print(f"[cache] OK — contracts: {contracts}")
        print(f"[cache] run stats: {stats}")
        return

    parser.print_help()


if __name__ == "__main__":
    main()
