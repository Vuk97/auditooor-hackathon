#!/usr/bin/env python3
"""
run_custom.py — run auditooor custom Slither detectors against a target.

Usage:
    python3 detectors/run_custom.py <target-dir> [detector_name]

Loads every auditooor/detectors/*.py file that exports a class inheriting from
AbstractDetector and runs it against the target. If `detector_name` is given,
only runs that specific detector.

Slither doesn't accept `--detect-file` on the CLI (plugins must be pip-installed
with entry points). This script sidesteps that by using Slither's Python API
directly.

Fixes SKILL_ISSUE #31 (Round B — first custom detector).
"""

import importlib.util
import os
import re
import sys
import inspect
from functools import lru_cache
from pathlib import Path

# NOTE: `slither` is imported lazily inside the functions that need it (see
# `_import_slither` / `_import_abstract_detector` below). Importing this module
# must succeed even when slither-analyzer is not installed — the CI preflight
# runs `python -m unittest discover tools/tests/` without slither, and the
# documentation-only YAML guard plus the helpers under test do not need it.
# The slither-dependent code paths (`main`, `batch_main`, `load_detectors`)
# raise a clear RuntimeError if slither is missing at call time.


SLITHER_DSL_BACKENDS = {
    "solidity",
    "slither",
    "slither_source_shape",
    "evm",
    "vyper",
}


def _import_slither():
    """Lazy-import `Slither`. Raises RuntimeError with a clear install hint
    when slither-analyzer is not installed."""
    try:
        from slither import Slither  # type: ignore
    except ImportError as e:
        raise RuntimeError(
            "slither-analyzer not installed; install with "
            "`pip install slither-analyzer`"
        ) from e
    return Slither


# ---------------------------------------------------------------------------
# ACT-11: persistent Slither compile cache integration
# ---------------------------------------------------------------------------

def _try_load_cache_module():
    """Return slither_compile_cache module, or None if unavailable."""
    try:
        here = Path(__file__).resolve().parent.parent
        spec = importlib.util.spec_from_file_location(
            "slither_compile_cache",
            here / "tools" / "slither-compile-cache.py",
        )
        if spec is None:
            return None
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod
    except Exception:
        return None


def _slither_cache_disabled() -> tuple[bool, str]:
    if os.environ.get("AUDITOOOR_SLITHER_NOCACHE", "").strip() == "1":
        return True, "AUDITOOOR_SLITHER_NOCACHE=1"
    if (
        os.environ.get("AUDITOOOR_FIXTURE_SMOKE_MODE", "").strip() == "1"
        and os.environ.get("AUDITOOOR_SLITHER_CACHE_IN_FIXTURE_SMOKE", "").strip() != "1"
    ):
        return True, "fixture-smoke-mode"
    return False, "cache-enabled"


def _get_slither_cached(target, slither_kwargs):
    """Return a Slither instance, using the compile cache when available.

    Bypass: set AUDITOOOR_SLITHER_NOCACHE=1 in the environment.
    Fixture smoke mode also bypasses by default because fixture rows often edit
    small source files and must prefer fresh correctness over cache speed.
    Set AUDITOOOR_SLITHER_CACHE_IN_FIXTURE_SMOKE=1 to opt back into caching.
    Falls back to direct Slither() on any cache error.
    """
    cache_disabled, _reason = _slither_cache_disabled()
    if not cache_disabled:
        cache_mod = _try_load_cache_module()
        if cache_mod is not None:
            try:
                sl = cache_mod.get_or_compile_slither(
                    Path(target), slither_kwargs=slither_kwargs or {}
                )
                if sl is not None:
                    return sl
            except Exception:
                pass
    Slither = _import_slither()
    return Slither(target, **(slither_kwargs or {}))


def _import_abstract_detector():
    """Lazy-import `AbstractDetector`. Same contract as `_import_slither`."""
    try:
        from slither.detectors.abstract_detector import AbstractDetector  # type: ignore
    except ImportError as e:
        raise RuntimeError(
            "slither-analyzer not installed; install with "
            "`pip install slither-analyzer`"
        ) from e
    return AbstractDetector


def _slither_available() -> bool:
    """True iff slither-analyzer can be imported. Used by tests that want to
    skip cleanly under CI when slither is absent."""
    try:
        import slither  # type: ignore  # noqa: F401
        import slither.detectors.abstract_detector  # type: ignore  # noqa: F401
    except ImportError:
        return False
    return True


def _load_tier_registry(detectors_dir: Path):
    """Load _tier_registry.yaml if it exists. Returns dict: detector argument -> tier.

    Older registry rows sometimes use an underscore YAML key while the detector
    class exposes a kebab-case ARGUMENT. Index both forms so tier gating does
    not silently demote those detectors to Tier-D.
    """
    registry_path = detectors_dir / "_tier_registry.yaml"
    if not registry_path.exists():
        return {}
    try:
        import yaml
    except ImportError:
        print("[warn] PyYAML not installed — tier filtering disabled", file=sys.stderr)
        return {}
    data = yaml.safe_load(registry_path.read_text()) or {}
    tiers = data.get("tiers", {}) or {}
    tier_map = {}
    argument_sources = {}
    for name, entry in tiers.items():
        if not isinstance(entry, dict):
            continue
        tier = str(entry.get("tier", "D")).upper()
        name = str(name)
        tier_map[name] = tier

        argument = str(entry.get("argument", "")).strip()
        if not argument:
            continue

        # Prefer the canonical YAML row whose key equals the Slither ARGUMENT,
        # but still map argument-only rows when no canonical key is present.
        current_source = argument_sources.get(argument)
        if current_source is None or name == argument:
            tier_map[argument] = tier
            argument_sources[argument] = name
    return tier_map


def _resolve_foundry_profile_remaps(target: Path):
    """SKILL_ISSUES #204 (Phase 37b): walk up from `target` to find a
    `foundry.toml`; parse the active profile (FOUNDRY_PROFILE env var, default
    to "default"); return (project_root, src_path, remappings_list, profile_name).

    Falls through with all-None when the workspace has no foundry.toml — caller
    treats this as "no Foundry config, use legacy behavior."

    Stdlib-only: prefers tomllib (3.11+); falls back to a regex parser that
    handles the [profile.X] / src = "..." / remappings = [...] shape.
    """
    try:
        target = Path(target).resolve()
        root = None
        cur = target if target.is_dir() else target.parent
        for p in [cur, *cur.parents]:
            if (p / "foundry.toml").is_file():
                root = p
                break
        if root is None:
            return (None, None, None, None)
        toml_path = root / "foundry.toml"

        try:
            import tomllib
            with open(toml_path, "rb") as f:
                data = tomllib.load(f)
        except Exception:
            data = {"profile": {}}
            cur_p = None
            import re as _re
            for line in toml_path.read_text().splitlines():
                s = line.strip()
                if s.startswith("[profile.") and s.endswith("]"):
                    cur_p = data["profile"].setdefault(s[len("[profile."):-1], {})
                    continue
                if cur_p is None:
                    continue
                m = _re.match(r'^src\s*=\s*"([^"]+)"', s)
                if m:
                    cur_p["src"] = m.group(1)
                m = _re.match(r'^remappings\s*=\s*\[(.*)\]', s)
                if m:
                    items = _re.findall(r'"([^"]+)"', m.group(1))
                    cur_p["remappings"] = items

        profiles = data.get("profile", {}) or {}
        env_profile = os.environ.get("FOUNDRY_PROFILE", "default")
        cfg = profiles.get(env_profile) or profiles.get("default") or {}
        return (root, cfg.get("src"), cfg.get("remappings"), env_profile)
    except Exception:
        return (None, None, None, None)


def _canonical_dsl_backend(spec: dict) -> str:
    for key in ("backend", "engine", "language"):
        value = str(spec.get(key, "")).strip().lower()
        if not value:
            continue
        parts = [part for part in re.split(r"[^a-z0-9_]+", value) if part]
        return parts[0] if parts else value
    return ""


@lru_cache(maxsize=4096)
def _pattern_yaml_metadata(argument: str, repo_root_str: str) -> tuple[bool, str, str]:
    if not argument:
        return (False, "", "")
    yaml_path = Path(repo_root_str) / "reference" / "patterns.dsl" / f"{argument}.yaml"
    if not yaml_path.is_file():
        return (False, "", "")
    try:
        import yaml
    except ImportError:
        return (False, "", "")
    try:
        spec = yaml.safe_load(yaml_path.read_text()) or {}
    except Exception:
        return (False, "", "")
    status = str(spec.get("status", "")).strip().lower()
    backend = _canonical_dsl_backend(spec)
    return (True, status, backend)


def _check_non_slither_backend_yaml(argument: str, repo_root: Path) -> tuple[bool, str]:
    """Return True when a canonical DSL row declares a backend Slither cannot run.

    Generated wave17 detectors sometimes came from Rust/Go/Circom corpus rows.
    Running those through Slither is a false authority signal: at best they match
    raw Solidity comments/strings that contain foreign-language tokens. Keep the
    row available to hacker-logic/corpus recall, but do not load it as a Slither
    detector.
    """
    exists, _status, backend = _pattern_yaml_metadata(argument, str(repo_root))
    if not exists or not backend:
        return (False, "")
    if backend in SLITHER_DSL_BACKENDS:
        return (False, backend)
    return (True, backend)


def _check_documentation_only_yaml(argument: str, repo_root: Path):
    """I-22 (PR #158 follow-up): mirrors PR #133's pattern-compile.py guard.

    When the operator runs `run_custom.py <target> <detector_argument>` and the
    matching `reference/patterns.dsl/<argument>.yaml` is flagged
    `status: documentation-only`, there is no compiled detector to run — the
    canonical implementation lives by hand under `detectors/wave18/`.

    Returns a tuple (is_doc_only, canonical_path_or_none):
      - (False, None)  → YAML missing OR YAML status is not documentation-only;
                         caller falls through to the existing load-detectors path
                         (preserving the current "no YAML / unknown name" error
                         path unchanged).
      - (True,  path)  → YAML status is documentation-only; caller should print
                         the skip message and exit 0. `path` is the canonical
                         hand-written wave18 .py if it exists on disk, else None.
    """
    if not argument:
        return (False, None)
    exists, status, _backend = _pattern_yaml_metadata(argument, str(repo_root))
    if not exists:
        # Don't change error path for missing YAMLs — fall through.
        return (False, None)
    if status != "documentation-only":
        return (False, None)
    # Canonical hand-written detector lives in detectors/wave18/<arg_underscored>.py
    arg_underscored = argument.replace("-", "_")
    canonical = repo_root / "detectors" / "wave18" / f"{arg_underscored}.py"
    return (True, canonical if canonical.is_file() else None)


def _workspace_is_inverse_cei(ws_path: Path) -> bool:
    """SKILL_ISSUES #102: true iff `<ws>/.skill_state.yaml` declares
    `inverse_cei_architecture: true` (e.g. Morpho Blue). When set, the runner
    skips every detector class whose DSL flagged itself `inverse_cei: true`."""
    try:
        state = ws_path / ".skill_state.yaml"
        if not state.exists():
            return False
        import yaml
        data = yaml.safe_load(state.read_text()) or {}
        return bool(data.get("inverse_cei_architecture", False))
    except Exception:
        return False


def _detector_py_files(detectors_dir: Path, include_graveyard: bool) -> list[Path]:
    py_files = sorted(detectors_dir.glob("*.py")) + sorted(detectors_dir.glob("wave*/*.py"))
    if include_graveyard:
        py_files += sorted(detectors_dir.glob("wave_graveyard/*/*.py"))
    return py_files


def _targeted_detector_py_files(detectors_dir: Path, name_filter: str | None, include_graveyard: bool) -> list[Path]:
    if not name_filter:
        return []
    stem = name_filter.replace("-", "_")
    candidates = [detectors_dir / f"{stem}.py", *detectors_dir.glob(f"wave*/{stem}.py")]
    if include_graveyard:
        candidates += list(detectors_dir.glob(f"wave_graveyard/*/{stem}.py"))
    return sorted({path for path in candidates if path.is_file()})


def load_detectors(detectors_dir: Path, name_filter: str = None,
                   include_graveyard: bool = False, tier_filter: str = None,
                   skip_inverse_cei: bool = False):
    """Import every .py file in detectors_dir and its wave*/ subdirs, collecting
    AbstractDetector subclasses. Top-level underscore-prefixed files and the
    runner itself are skipped. When include_graveyard=True, also loads detectors
    from wave_graveyard/*/ — used by Round 22 cross-corpus rescan and fixture
    smoke rows parked under syntax_broken.

    tier_filter (Issue #76): comma-separated list of tiers to include, e.g.
    "S", "S,E", "S,E,D". None = "S,E,A" by default (Tier-A is corpus-noise-probed
    promotions from B; Tier-B/D are opt-in only). Unlisted detectors default to
    Tier-D.

    skip_inverse_cei (SKILL_ISSUES #102): when True, drop every detector whose
    class-level `_INVERSE_CEI = True`. Set by --inverse-cei-workspace.
    """
    # Resolve tier filter
    if tier_filter is None:
        # default: skip ONLY unvalidated drafts (D). Include S, E, validated A
        # (corpus-noise-probed) AND B. B-tier detectors are wired + smoke-tested at
        # promotion (the W1-W6 glider gaps: two-step-ownership, signature-replay,
        # callback-reentrancy, chainlink-try-catch, etc.); keeping them opt-in meant
        # they NEVER fired in a standard audit (strata 2026-06-30 fire-audit: ~10 dark
        # validated detectors). In an audit you want max recall - the adversarial-verify
        # layer triages FPs downstream. Only genuinely-unvalidated drafts (D) stay off.
        allowed_tiers = {"S", "E", "A", "B"}
    else:
        allowed_tiers = {t.strip().upper() for t in tier_filter.split(",") if t.strip()}
        if "ALL" in allowed_tiers:
            allowed_tiers = {"S", "E", "A", "B", "D", "PAPER"}

    # Lazy-import slither's AbstractDetector — needed for the issubclass check
    # below. Raises a clean RuntimeError when slither-analyzer is missing.
    AbstractDetector = _import_abstract_detector()

    tier_map = _load_tier_registry(detectors_dir)

    detectors = []
    detectors_root = str(detectors_dir.resolve())
    if detectors_root not in sys.path:
        sys.path.insert(0, detectors_root)
    py_files = _targeted_detector_py_files(detectors_dir, name_filter, include_graveyard)
    if not py_files:
        py_files = _detector_py_files(detectors_dir, include_graveyard)
    for py_file in py_files:
        if py_file.name.startswith("_") or py_file.name in ("run_custom.py",):
            continue
        spec = importlib.util.spec_from_file_location(py_file.stem, py_file)
        module = importlib.util.module_from_spec(spec)
        # Register in sys.modules BEFORE exec_module so @dataclass decorator
        # can resolve cls.__module__ during class definition (Python 3.13+
        # dataclasses.py calls sys.modules.get(cls.__module__).__dict__ to
        # introspect KW_ONLY sentinels; without pre-registration this returns
        # None and raises AttributeError). See docs/SLITHER_IR_BROKEN_DETECTORS_2026-05-16.md.
        sys.modules[py_file.stem] = module
        try:
            spec.loader.exec_module(module)
        except Exception as e:
            # Remove half-loaded module so we don't leak partial state to siblings.
            sys.modules.pop(py_file.stem, None)
            print(f"[warn] skipping {py_file.name}: {e}")
            continue
        for name, obj in inspect.getmembers(module, inspect.isclass):
            if obj is AbstractDetector:
                continue
            if not issubclass(obj, AbstractDetector):
                continue
            if name_filter and obj.ARGUMENT != name_filter:
                continue
            non_slither, backend = _check_non_slither_backend_yaml(
                obj.ARGUMENT, detectors_dir.parent
            )
            if non_slither:
                if name_filter:
                    print(
                        f"[run_custom] SKIP {obj.ARGUMENT}: backend: {backend} "
                        "is not a Slither backend"
                    )
                continue
            # Tier gating — only load detectors whose tier is in allowed_tiers.
            # Unlisted detectors default to Tier-D.
            det_tier = tier_map.get(obj.ARGUMENT, "D")
            if det_tier not in allowed_tiers:
                continue
            # SKILL_ISSUES #102: skip reentrancy-class detectors on inverse-CEI
            # workspaces. `_INVERSE_CEI` is emitted by tools/pattern-compile.py
            # when the DSL sets `inverse_cei: true`.
            if skip_inverse_cei and getattr(obj, "_INVERSE_CEI", False):
                continue
            detectors.append(obj)
    return detectors


def _pool_worker(args):
    """One target scan — invoked by pool_main via multiprocessing.Pool."""
    target, log_path, include_graveyard = args
    import subprocess, os
    # Re-invoke this same script as a subprocess to fully isolate Slither's
    # global state per target (Slither mutates globals on compile).
    here = Path(__file__).resolve()
    env = os.environ.copy()
    env["PATH"] = f"{Path.home()}/.foundry/bin:" + env.get("PATH", "")
    cmd = ["python3", str(here)]
    if include_graveyard:
        cmd.append("--include-graveyard")
    cmd.append(target)
    try:
        with open(log_path, "w") as f:
            p = subprocess.run(cmd, stdout=f, stderr=subprocess.STDOUT,
                               env=env, timeout=1800)
        return (target, p.returncode, log_path)
    except subprocess.TimeoutExpired:
        return (target, -1, log_path)
    except Exception as e:
        return (target, -2, f"{log_path} (err: {e})")


def pool_main(argv):
    """Multi-target parallel scan driver.

    Spawns POOL_WORKERS workers (default 32), each runs one target scan
    through run_custom.py as a subprocess. Targets are queued by the
    multiprocessing.Pool; the first N run immediately, the rest get picked
    up as workers free. Each target's output goes to $POOL_LOG_DIR/scan_
    <slug>.log.

    Usage:
        run_custom.py --pool <target1> <target2> ... [--include-graveyard]
        POOL_WORKERS=32 POOL_LOG_DIR=/tmp run_custom.py --pool ...
    """
    import os, time
    from multiprocessing import Pool

    include_graveyard = False
    if "--include-graveyard" in argv:
        include_graveyard = True
        argv = [a for a in argv if a != "--include-graveyard"]

    targets = [str(Path(t).resolve()) for t in argv]
    if not targets:
        print("Error: --pool requires at least one target path")
        sys.exit(1)

    workers = int(os.environ.get("POOL_WORKERS", "32"))
    log_dir = Path(os.environ.get("POOL_LOG_DIR", "/tmp"))
    log_dir.mkdir(parents=True, exist_ok=True)

    def slug(path: str) -> str:
        return Path(path).name.replace("/", "_") or "target"

    jobs = []
    for t in targets:
        log = log_dir / f"scan_pool_{slug(t)}.log"
        jobs.append((t, str(log), include_graveyard))

    print(f"[pool] workers={workers}, targets={len(targets)}, log_dir={log_dir}")
    for j in jobs:
        print(f"  - {j[0]} -> {j[1]}")

    t0 = time.time()
    results = []
    with Pool(processes=min(workers, len(targets))) as pool:
        for i, r in enumerate(pool.imap_unordered(_pool_worker, jobs)):
            target, rc, log = r
            status = "OK" if rc == 0 else f"RC={rc}"
            elapsed = time.time() - t0
            print(f"[pool {i+1}/{len(targets)}] {status:5} {elapsed:6.0f}s  "
                  f"{Path(target).name}  -> {Path(log).name}")
            results.append(r)
    print(f"\n[pool] done in {time.time()-t0:.0f}s")

    # Summarize hit counts per target
    print("\n=== per-target hits ===")
    for target, rc, log in results:
        if rc != 0:
            print(f"  {Path(target).name}: SKIPPED (rc={rc})")
            continue
        try:
            text = Path(log).read_text(errors="ignore")
        except Exception:
            continue
        import re as _re
        m = _re.search(r"total hits:\s*(\d+)", text)
        hits = int(m.group(1)) if m else -1
        n_dets = len(_re.findall(r"=== Running ", text))
        print(f"  {Path(target).name}: total_hits={hits}  detectors_executed={n_dets}")


def _print_usage() -> None:
    print("Usage:")
    print("  python3 run_custom.py <target> [detector_name]           # single target (classic)")
    print("  python3 run_custom.py --batch <fixture_dir>              # batch all fixtures + all detectors")
    print("  python3 run_custom.py --batch <fixture_dir> <expected.tsv>  # batch + regression check")
    print("  python3 run_custom.py --pool <target1> <target2> ...     # multi-target pool scan")
    print("     env: POOL_WORKERS=N (default 32), POOL_LOG_DIR=/tmp")
    print("  Flags:")
    print("    --tier=S|E|A|B|D|ALL                                   # Issue #76 tier filter (default: S,E,A)")
    print("    --mode=discovery|maintenance                           # Issue #104 (maintenance = Tier-S only)")


def main():
    if len(sys.argv) < 2:
        _print_usage()
        sys.exit(1)
    if sys.argv[1] in ("-h", "--help", "help"):
        _print_usage()
        sys.exit(0)

    if sys.argv[1] == "--batch":
        # Pass through --tier= filter if present
        batch_argv = sys.argv[2:]
        batch_main(batch_argv)
        return

    if sys.argv[1] == "--pool":
        pool_main(sys.argv[2:])
        return

    # --include-graveyard flag for Round 22 Phase 1 cross-corpus rescan
    # --tier=S|E|A|B|D|ALL (Issue #76) — filter by detector tier. Default: S,E,A
    # --mode=discovery|maintenance (Issue #104) — discovery=full library (default),
    #   maintenance=high-confidence Tier-S detectors only. Takes precedence when set.
    argv = sys.argv[1:]
    include_graveyard = False
    tier_filter = None  # None = default (S,E)
    mode = None  # Issue #104
    inverse_cei_ws = None  # SKILL_ISSUES #102: workspace path to check for .skill_state.yaml
    new_argv = []
    for a in argv:
        if a == "--include-graveyard":
            include_graveyard = True
        elif a.startswith("--tier="):
            tier_filter = a.split("=", 1)[1]
        elif a.startswith("--mode="):
            mode = a.split("=", 1)[1]
        elif a.startswith("--inverse-cei-workspace="):
            inverse_cei_ws = a.split("=", 1)[1]
        elif a == "--tier" and False:  # placeholder for space-separated form
            pass
        else:
            new_argv.append(a)
    # Also handle space-separated --tier S,E and --mode discovery
    argv = new_argv
    cleaned = []
    skip = False
    for i, a in enumerate(argv):
        if skip:
            skip = False
            continue
        if a == "--tier" and i + 1 < len(argv):
            tier_filter = argv[i + 1]
            skip = True
        elif a == "--mode" and i + 1 < len(argv):
            mode = argv[i + 1]
            skip = True
        elif a == "--inverse-cei-workspace" and i + 1 < len(argv):
            inverse_cei_ws = argv[i + 1]
            skip = True
        else:
            cleaned.append(a)
    argv = cleaned

    # SKILL_ISSUES #102: resolve the inverse-CEI workspace gate. When the user
    # points us at a workspace whose `.skill_state.yaml:inverse_cei_architecture`
    # is true (e.g. Morpho Blue), we drop every detector class flagged
    # `inverse_cei: true` in its source DSL.
    skip_inverse_cei = False
    if inverse_cei_ws:
        skip_inverse_cei = _workspace_is_inverse_cei(Path(inverse_cei_ws))
        if skip_inverse_cei:
            print(f"[inverse-cei] workspace {inverse_cei_ws} is inverse-CEI → skipping reentrancy-class detectors")

    # Issue #104: --mode=maintenance restricts to Tier-S (high-confidence) only.
    # --mode=discovery is the default (full library, honors --tier if given).
    if mode is not None:
        mode = mode.strip().lower()
        if mode not in ("discovery", "maintenance"):
            print(f"Error: --mode must be 'discovery' or 'maintenance' (got {mode!r})")
            sys.exit(2)
        if mode == "maintenance":
            # Maintenance mode: Tier-S only. Explicit --tier= override wins if set.
            if tier_filter is None:
                tier_filter = "S"

    target = argv[0]
    name_filter = argv[1] if len(argv) > 1 else None

    detectors_dir = Path(__file__).parent
    # I-22 (PR #158 follow-up): if the operator passed a detector name whose
    # `reference/patterns.dsl/<name>.yaml` is flagged `status: documentation-only`,
    # skip cleanly with a message pointing at the canonical wave18 detector
    # (mirrors PR #133's pattern-compile.py skip). Only triggered when name_filter
    # is set — bare-target invocations are unaffected.
    if name_filter:
        repo_root = detectors_dir.parent
        is_doc_only, canonical_path = _check_documentation_only_yaml(name_filter, repo_root)
        if is_doc_only:
            print(f"[run_custom] SKIP {name_filter}: status: documentation-only")
            if canonical_path is not None:
                print(f"              → canonical hand-written detector at {canonical_path}")
            else:
                print(f"              → no compiled detector")
            sys.exit(0)
        non_slither, backend = _check_non_slither_backend_yaml(name_filter, repo_root)
        if non_slither:
            print(f"[run_custom] SKIP {name_filter}: backend: {backend} is not a Slither backend")
            print("              → keep as corpus/hacker-logic context until a language-native runner exists")
            sys.exit(0)

    detectors = load_detectors(detectors_dir, name_filter,
                               include_graveyard=include_graveyard,
                               tier_filter=tier_filter,
                               skip_inverse_cei=skip_inverse_cei)

    if not detectors:
        print("No custom detectors found in", detectors_dir)
        print(f"(tier filter: {tier_filter or 'S,E,A (default)'})")
        print("To run unvalidated drafts too: add --tier=S,E,A,D or --tier=ALL")
        sys.exit(1)

    print(f"[ok] loaded {len(detectors)} custom detector(s) (tier filter: {tier_filter or 'S,E,A default'}):")
    for d in detectors:
        print(f"  - {d.ARGUMENT}: {d.HELP[:100]}...")
    print()

    # SKILL_ISSUES #204 (Phase 37b): if target sits inside a Foundry workspace,
    # resolve the active profile's `src=` + `remappings=` from foundry.toml so
    # crytic-compile / Slither pick up the right paths. FOUNDRY_PROFILE is read
    # from env (the multisolc shell wrapper sets it per-subtree).
    fnd_root, fnd_src, fnd_remaps, fnd_profile = _resolve_foundry_profile_remaps(Path(target))
    slither_kwargs = {}
    if fnd_root is not None:
        print(f"[foundry] root={fnd_root}  profile={fnd_profile}  src={fnd_src or '<inherit>'}")
        if fnd_remaps:
            # crytic-compile expects a list of "from=to" strings. Normalize relative
            # `to` paths against the Foundry project root so Slither resolves them
            # the same way `forge build` would.
            norm = []
            for rm in fnd_remaps:
                if "=" not in rm:
                    continue
                lhs, rhs = rm.split("=", 1)
                if not rhs.startswith("/"):
                    rhs = str((fnd_root / rhs).resolve())
                norm.append(f"{lhs}={rhs}")
            slither_kwargs["solc_remaps"] = norm
            print(f"[foundry] injected {len(norm)} solc_remaps from profile {fnd_profile}")

    cache_disabled, cache_reason = _slither_cache_disabled()
    cache_label = f"off: {cache_reason}" if cache_disabled else "on"
    print(f"[ok] compiling {target} (cache: {cache_label})...")
    # filter_paths rationale:
    # Slither's AbstractDetector.detect() → core.valid_result(r) iterates
    # every source element and FLIPS a 'matching' flag on any filter match.
    # With MULTIPLE filter patterns, consecutive matches flip the flag even
    # times → result accidentally UNFILTERED. With a SINGLE pattern a result
    # is filtered iff it references that path.
    #
    # Using only "lib/" drops vendored Solady / forge-std noise without
    # affecting results in src/. Round 10 discovery: the old
    # "lib/|test/|dev/" filter was hiding 39+ real role-grant hits on
    # Polymarket v2 because production results cross-referenced src/test/
    # files (contract names shared between .sol and .t.sol) → flag flipped
    # twice → filter accidentally let everything through OR stripped
    # everything depending on pattern order.
    #
    # Detectors already filter test/mock/fixture by NAME internally via
    # SKIP_KEYWORDS. Single-pattern path filter is the sweet spot.
    try:
        slither = _get_slither_cached(target, slither_kwargs)
    except Exception as e:
        print(f"PREREQ MISSING: Error compiling target: {e}")
        print("Remediation: run make slither-cache-warm or fix the Solidity project compilation inputs.")
        sys.exit(2)
    if slither is None:
        print("PREREQ MISSING: Error compiling target: compilation failed")
        print("Remediation: run make slither-cache-warm or fix the Solidity project compilation inputs.")
        sys.exit(2)

    # Post-filter: drop results whose primary source is in vendored paths.
    # This is the safe way to exclude lib/ noise without triggering Slither's
    # filter_paths cross-reference bug (see comment above).
    VENDORED_MARKERS = ("/lib/", "forge-std", "solady/src", "solmate/src",
                        "openzeppelin", "/node_modules/")

    def _result_is_vendored(r):
        for elem in r.get("elements", []):
            src = elem.get("source_mapping") or {}
            path = src.get("filename_absolute") or src.get("filename_relative") or ""
            if any(m in path for m in VENDORED_MARKERS):
                return True
        return False

    total_hits = 0
    for DetectorClass in detectors:
        print(f"\n=== Running {DetectorClass.ARGUMENT} ===")
        import logging
        logger = logging.getLogger(f"auditooor.{DetectorClass.ARGUMENT}")
        for cu in slither.compilation_units:
            try:
                detector = DetectorClass(cu, slither, logger)
            except Exception as e:
                print(f"  [init-error] {e}")
                continue
            try:
                results = detector.detect()
            except Exception as e:
                print(f"  [error] {e}")
                continue
            if not results:
                continue
            kept = [r for r in results if not _result_is_vendored(r)]
            if not kept:
                continue
            total_hits += len(kept)
            for result in kept:
                print(f"  [{DetectorClass.IMPACT.name}] {result.get('description', '?')[:300]}")

    print(f"\n[done] total hits: {total_hits}")

    # Auto-save full output to workspace log file (fixes SKILL_ISSUE #65)
    target_path = Path(target)
    log_candidates = [
        target_path.parent / "custom-detectors.log",       # workspace/custom-detectors.log
        target_path / "custom-detectors.log",               # target IS the workspace
        Path("/tmp") / f"custom-detectors-{target_path.name}.log",  # fallback
    ]
    for log_path in log_candidates:
        try:
            log_path.parent.mkdir(parents=True, exist_ok=True)
            # We can't retroactively capture stdout, but we note the path for
            # callers to redirect: python3 run_custom.py <target> 2>&1 | tee <log>
            print(f"[hint] save full output: python3 {__file__} {target} 2>&1 | tee {log_path}")
            break
        except Exception:
            continue


def batch_main(argv):
    """Batch mode: compile ALL fixtures in one Slither invocation, then loop
    detectors against the compiled artifacts. 30-50x faster than the per-test
    serial path because forge compile + slither load happen ONCE, not per-test.

    Usage:
        run_custom.py --batch <fixture_dir>              # print pass/fail per detector
        run_custom.py --batch <fixture_dir> <regression> # regression mode (see below)

    Regression TSV format (one line per expected test, tab-separated):
        <mode>\\t<detector>\\t<fixture>\\t<label>
        vuln\\tforwarder-nonce-increment-on-revert\\tforwarder_nonce_increment_on_revert_vulnerable.sol\\tforwarder-...
        clean\\tforwarder-nonce-increment-on-revert\\tforwarder_nonce_increment_on_revert_clean.sol\\tforwarder-... (clean)

    Without a regression file, the tool just prints "<detector>: N hits on M
    fixtures" for every fixture+detector combo.
    """
    if not argv:
        print("Error: --batch requires a fixture directory")
        sys.exit(1)

    # Extract runner flags if present
    tier_filter = None
    include_graveyard = False
    cleaned = []
    for a in argv:
        if a.startswith("--tier="):
            tier_filter = a.split("=", 1)[1]
        elif a == "--include-graveyard":
            include_graveyard = True
        else:
            cleaned.append(a)
    argv = cleaned

    fixture_dir = Path(argv[0]).resolve()
    regression_file = Path(argv[1]) if len(argv) > 1 else None

    detectors_dir = Path(__file__).parent

    print(f"[batch] loading custom detectors (tier filter: {tier_filter or 'S,E,A default'})...")
    detectors = load_detectors(
        detectors_dir,
        include_graveyard=include_graveyard,
        tier_filter=tier_filter,
    )
    if not detectors:
        print("No custom detectors found in", detectors_dir)
        sys.exit(1)
    print(f"[batch] loaded {len(detectors)} detectors")

    # Index detectors by ARGUMENT for quick lookup in regression mode
    det_by_arg = {d.ARGUMENT: d for d in detectors}

    print(f"[batch] compiling {fixture_dir} with Slither (single pass)...")
    import time
    Slither = _import_slither()
    t0 = time.time()
    try:
        slither = Slither(str(fixture_dir))
    except Exception as e:
        print(f"[error] Slither compile failed: {e}")
        sys.exit(1)
    t_compile = time.time() - t0
    print(f"[batch] compiled in {t_compile:.1f}s, {len(slither.compilation_units)} compilation units")

    # Build an index: contract filename stem → list of Slither Contract objects
    # so we can map a fixture name like "foo_vulnerable.sol" to its Contract
    # objects in the compilation unit.
    from collections import defaultdict
    contracts_by_file = defaultdict(list)
    for cu in slither.compilation_units:
        for c in cu.contracts:
            # Use the normalized filename (stem + .sol) as the key
            try:
                fname = c.source_mapping.filename.relative
                if not fname:
                    fname = c.source_mapping.filename.absolute
                if fname:
                    # Normalize to just the basename
                    base = Path(fname).name
                    contracts_by_file[base].append((c, cu))
            except Exception:
                continue

    print(f"[batch] indexed {sum(len(v) for v in contracts_by_file.values())} contracts "
          f"across {len(contracts_by_file)} files")

    # VENDORED_MARKERS shared with classic mode
    VENDORED_MARKERS = ("/lib/", "forge-std", "solady/src", "solmate/src",
                        "openzeppelin", "/node_modules/")

    def _result_is_vendored(r):
        for elem in r.get("elements", []):
            src = elem.get("source_mapping") or {}
            path = src.get("filename_absolute") or src.get("filename_relative") or ""
            if any(m in path for m in VENDORED_MARKERS):
                return True
        return False

    # Cache: (detector_arg, fixture_stem) → hit count
    results_cache = {}

    def _run_detector_on_fixture(detector_arg, fixture_stem):
        """Run ONE detector against ONE fixture's contracts. Memoized."""
        key = (detector_arg, fixture_stem)
        if key in results_cache:
            return results_cache[key]
        fixture_base = Path(fixture_stem).name
        cu_pairs = contracts_by_file.get(fixture_base, [])
        if not cu_pairs:
            results_cache[key] = -1  # fixture not found
            return -1

        DetectorClass = det_by_arg.get(detector_arg)
        if not DetectorClass:
            results_cache[key] = -2  # detector not found
            return -2

        # Run detector against the compilation unit(s) that contain the fixture
        import logging
        logger = logging.getLogger(f"auditooor.batch.{detector_arg}")
        seen_cus = set()
        total = 0
        for contract, cu in cu_pairs:
            if id(cu) in seen_cus:
                continue
            seen_cus.add(id(cu))
            try:
                det = DetectorClass(cu, slither, logger)
                results = det.detect() or []
            except Exception:
                continue
            # Filter to results whose source is the target fixture (not other fixtures)
            for r in results:
                if _result_is_vendored(r):
                    continue
                for elem in r.get("elements", []):
                    src = elem.get("source_mapping") or {}
                    path = src.get("filename_absolute") or src.get("filename_relative") or ""
                    if fixture_base in path:
                        total += 1
                        break
        results_cache[key] = total
        return total

    if regression_file and regression_file.exists():
        # Regression mode: read TSV, run each expected test, report pass/fail
        print(f"[batch] regression mode — reading {regression_file}")
        total_pass = 0
        total_fail = 0
        fails = []
        t1 = time.time()
        with open(regression_file) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split("\t")
                if len(parts) < 4:
                    continue
                mode, det_arg, fixture, label = parts[:4]
                hits = _run_detector_on_fixture(det_arg, fixture)
                if hits < 0:
                    total_fail += 1
                    fails.append(f"{label} ({det_arg}) — missing ({'fixture' if hits == -1 else 'detector'})")
                    continue
                if mode == "vuln":
                    if hits >= 1:
                        total_pass += 1
                    else:
                        total_fail += 1
                        fails.append(f"{label} ({det_arg}) — 0 hits (expected >=1)")
                else:  # clean
                    if hits == 0:
                        total_pass += 1
                    else:
                        total_fail += 1
                        fails.append(f"{label} ({det_arg}) — {hits} hits on CLEAN (FP)")
        t_run = time.time() - t1
        total = total_pass + total_fail
        print(f"\n=========================================")
        print(f" Batch regression: {total_pass}/{total} passed, {total_fail} failed")
        print(f" Compile: {t_compile:.1f}s   Detection: {t_run:.1f}s   Total: {t_compile+t_run:.1f}s")
        print(f"=========================================")
        if fails:
            print("\nFailed (first 30):")
            for f in fails[:30]:
                print(f"  - {f}")
            sys.exit(1)
        sys.exit(0)

    # Non-regression: just print per-detector hits across all fixtures
    total_hits = 0
    for DetectorClass in detectors:
        for cu in slither.compilation_units:
            import logging
            logger = logging.getLogger(f"auditooor.batch.{DetectorClass.ARGUMENT}")
            try:
                det = DetectorClass(cu, slither, logger)
                results = det.detect() or []
            except Exception:
                continue
            kept = [r for r in results if not _result_is_vendored(r)]
            if kept:
                total_hits += len(kept)
                for r in kept[:3]:
                    print(f"  [{DetectorClass.IMPACT.name}] {DetectorClass.ARGUMENT}: {r.get('description', '?')[:200]}")
    print(f"\n[batch] total hits across all detectors + fixtures: {total_hits}")


if __name__ == "__main__":
    main()
