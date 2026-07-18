#!/usr/bin/env python3
"""realworld-recall-scoreboard.py - honest real-world recall measurement of the
auditooor detector library against INDEPENDENT known-vulnerable samples.

Why this exists (read before trusting the number)
--------------------------------------------------
`tools/audit/detector-catch-rate-backtest.py` measures 73.1% catch-rate, but
that is a SELF-TEST: every DSL pattern is scored against the exact fixture pair
it was authored from. A detector that catches the one contract it was hand-
written for proves only that the author did not typo the regex. It says nothing
about real-world recall - whether the library catches a vulnerability it was
NOT written from.

This tool measures real-world recall with a held-out, cross-detector design:

  * The held-out set is every DSL pattern that ships an on-disk known-vulnerable
    fixture (`fixtures.vuln`). Each such fixture is a known-vulnerable sample.
  * For each held-out fixture X, we run the WHOLE detector library against X
    but EXCLUDE the one detector authored from X (slug == X's pattern). That
    excluded detector is the in-sample detector; every other detector is
    independent of X.
  * The HEADLINE real-world recall = of N known-vulnerable held-out samples,
    on how many does an independent (not-own) detector of the SAME attack
    class fire. Same-class is the honest metric: a correct-class detector
    firing is meaningful generalisation.
  * We ALSO report the looser "any independent detector at all" number, but
    that one is a noise-prone UPPER BOUND, not real recall: with a
    1500+-detector library of broad regex patterns, some detector fires on
    almost any contract. Do not read the "any" number as recall - it is
    reported only to bound the noise floor.

A SAME-CLASS detector NOT authored from fixture X firing on X is genuine
real-world recall: the library generalised beyond the single hand-written
rule. If only the own-detector ever fires, real-world recall collapses far
below the 73.1% self-test headline - and that is the honest number a hunter
needs.

Honest limitations (reported, not hidden)
-----------------------------------------
* The held-out samples are auditooor-internal synthesised fixtures, not raw
  third-party repo snapshots. They are derived from real Solodit / audit-firm
  findings but were hand-shaped for the detector corpus. They are independent
  of every detector EXCEPT their own (which we exclude), but they are not
  pristine external code. The scoreboard says so in its output and in the
  emitted JSON `limitations` block. Treat the number as a lower bound on
  self-test inflation, not as an external-repo recall figure.
* attack_class is derived from the SAME shared taxonomy the self-test uses
  (imported from detector-catch-rate-backtest.py), so the class-level recall is
  only as good as that map. The "any independent detector" number does not
  depend on the taxonomy.
* DSL patterns whose fixture file is not on disk are skipped (reported as
  `held_out_skipped_no_fixture`).

Output
------
  * <out>/realworld_recall_scoreboard.json  (schema
    auditooor.realworld_recall_scoreboard.v1)
  * <out>/realworld_recall_scoreboard.md    (human-readable scoreboard)
  * stdout summary.

Usage
-----
  python3 tools/audit/realworld-recall-scoreboard.py [--limit N]
      [--patterns-dir DIR] [--external-manifest manifest.json]
      [--external-only] [--attack-class CLASS] [--out-dir DIR] [--quiet]

External sample manifests are JSON:

  {
    "schema": "auditooor.external_recall_samples.v1",
    "samples": [
      {
        "id": "compound-c4-2022-m-01",
        "path": "snapshots/CompoundLike.sol",
        "attack_class": "accounting-state",
        "severity": "HIGH",
        "source": "external_repo:c4/compound",
        "exclude_detector_slug": ""
      }
    ]
  }

Stdlib + pyyaml + slither-analyzer. Exits 0 always (measurement tool).
"""

import argparse
import importlib.util
import json
import os
import re
import sys
import threading
import tempfile
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
DETECTORS_DIR = REPO_ROOT / "detectors"
DEFAULT_PATTERNS_DIR = REPO_ROOT / "reference" / "patterns.dsl"
GO_WAVE1_DIR = DETECTORS_DIR / "go_wave1"
RUST_WAVE1_DIR = DETECTORS_DIR / "rust_wave1"
SOLIDITY_WAVE17_DIR = DETECTORS_DIR / "wave17"
SCHEMA = "auditooor.realworld_recall_scoreboard.v1"
EXTERNAL_MANIFEST_SCHEMA = "auditooor.external_recall_samples.v1"
SOLC_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")
_SOLC_ENV_LOCK = threading.Lock()
SLITHER_LANGUAGES = {"solidity", "vyper", "yul"}
KNOWN_TARGET_LANGUAGES = {"solidity", "vyper", "yul", "go", "rust", "move", "cairo"}
LANGUAGE_BY_SUFFIX = {
    ".sol": "solidity",
    ".vy": "vyper",
    ".yul": "yul",
    ".go": "go",
    ".rs": "rust",
    ".move": "move",
    ".cairo": "cairo",
}

# Force fixture-smoke mode so detectors are not suppressed on fixture-named
# contracts. Must be set before _template_utils is imported.
os.environ["AUDITOOOR_FIXTURE_SMOKE_MODE"] = "1"
sys.path.insert(0, str(DETECTORS_DIR))


def _normalize_solc_version(value) -> str:
    """Return a solc-select friendly version string from manifest metadata."""
    if value is None:
        return ""
    text = str(value).strip()
    if not text:
        return ""
    if text.startswith("v"):
        text = text[1:]
    if "+" in text:
        text = text.split("+", 1)[0]
    return text.strip()


def _normalize_language(value) -> str:
    text = str(value or "").strip().lower()
    if not text:
        return ""
    aliases = {
        "sol": "solidity",
        "evm": "solidity",
        "slither": "solidity",
        "slither_dsl": "solidity",
        "slither-source-shape": "solidity",
        "slither_source_shape": "solidity",
        "source_shape": "solidity",
        "golang": "go",
        "cosmos": "go",
        "cosmos-go": "go",
        "cosmos_dsl": "go",
        "cosmos-dsl": "go",
        "substrate": "rust",
        "consensus": "rust",
        "rust_wave1": "rust",
        "rust-wave1": "rust",
        "near": "rust",
        "zebra": "rust",
        "rs": "rust",
    }
    language = aliases.get(text, text)
    return language if language in KNOWN_TARGET_LANGUAGES else ""


def infer_target_language(path, spec=None) -> str:
    """Infer the sample language from explicit metadata, then file suffix."""
    spec = spec if isinstance(spec, dict) else {}
    explicit = (
        spec.get("target_language")
        or spec.get("language")
        or spec.get("lang")
        or spec.get("backend")
    )
    language = _normalize_language(explicit)
    if language:
        return language
    suffix = Path(str(path or "")).suffix.lower()
    return LANGUAGE_BY_SUFFIX.get(suffix, "unknown")


def parse_attack_class_filter(values) -> list[str]:
    """Normalize repeated or comma-separated attack-class filters."""
    allowed = set()
    for value in values or []:
        for raw in re.split(r"[,\s]+", str(value or "")):
            text = raw.strip()
            if not text:
                continue
            allowed.add(normalize_attack_class(text))
    return sorted(allowed)


def sample_matches_attack_class_filter(sample: dict, allowed: set[str]) -> bool:
    """Return True when a sample belongs to any requested attack class."""
    if not allowed:
        return True
    classes = set()
    primary = str(sample.get("attack_class") or "").strip()
    if primary:
        classes.add(normalize_attack_class(primary))
    for cls in sample.get("attack_classes") or []:
        text = str(cls or "").strip()
        if text:
            classes.add(normalize_attack_class(text))
    return bool(classes & allowed)


def filter_by_attack_class(rows: list[dict], allowed_classes: list[str]) -> list[dict]:
    """Filter sample/result rows by primary class or explicit class aliases."""
    allowed = set(allowed_classes or [])
    if not allowed:
        return rows
    return [row for row in rows if sample_matches_attack_class_filter(row, allowed)]


def _dsl_detector_engine(spec: dict) -> str:
    backend = str(spec.get("backend") or "").strip().lower()
    explicit_engine = str(spec.get("engine") or "").strip().lower()
    if explicit_engine in {"go_wave1", "rust_wave1", "cosmos_dsl", "slither_dsl"}:
        return explicit_engine
    if backend == "cosmos":
        return "cosmos_dsl"
    return "slither_dsl"


def _sample_engine_for_language(target_language: str, spec: dict | None = None) -> str:
    spec = spec if isinstance(spec, dict) else {}
    explicit = str(spec.get("engine") or "").strip().lower()
    if explicit in {"go_wave1", "rust_wave1", "cosmos_dsl", "slither_dsl"}:
        return explicit
    backend = str(spec.get("backend") or "").strip().lower()
    if backend == "cosmos":
        return "cosmos_dsl"
    language = _normalize_language(target_language)
    if language == "go":
        return "go_wave1"
    if language == "rust":
        return "rust_wave1"
    return "slither_dsl"


def _import_module_from_path(module_name: str, path: Path):
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot import {path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _nearest_parent_with_file(path: Path, filename: str) -> Path | None:
    cur = path if path.is_dir() else path.parent
    for parent in [cur, *cur.parents]:
        if (parent / filename).exists():
            return parent
        if parent == REPO_ROOT:
            break
    return None


# --------------------------------------------------------------------------
# Reuse the self-test's attack_class taxonomy so the two scoreboards are
# directly comparable. If the import fails we fall back to "uncategorized"
# everywhere - the headline "any independent detector" number is unaffected.
# --------------------------------------------------------------------------
def _load_attack_class_helpers():
    tool = REPO_ROOT / "tools" / "audit" / "detector-catch-rate-backtest.py"
    try:
        spec = importlib.util.spec_from_file_location(
            "_detector_catch_rate_backtest", tool)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod.derive_attack_class, mod.derive_attack_classes, mod.normalize_attack_class
    except Exception:
        return (
            lambda slug, tags: "uncategorized",
            lambda slug, tags: set(),
            lambda attack_class: str(attack_class or "uncategorized").strip() or "uncategorized",
        )


derive_attack_class, derive_attack_classes, normalize_attack_class = _load_attack_class_helpers()


# --------------------------------------------------------------------------
# Engine import.
# --------------------------------------------------------------------------
def _import_engine():
    from _predicate_engine import eval_preconditions, eval_function_match
    from _template_utils import is_leaf_helper, is_vendored_or_test_contract
    return (eval_preconditions, eval_function_match,
            is_leaf_helper, is_vendored_or_test_contract)


# --------------------------------------------------------------------------
# Corpus discovery.
# --------------------------------------------------------------------------
def discover_held_out(patterns_dir: Path):
    """Every DSL pattern with an on-disk vuln fixture is a held-out sample.

    Returns (samples, skipped_no_fixture). Each sample carries its own slug
    (used to EXCLUDE its in-sample detector), its compiled detector spec
    (preconditions/match), its attack_class, and the fixture path.
    """
    import yaml
    samples = []
    skipped = 0
    for yf in sorted(patterns_dir.glob("*.yaml")):
        try:
            spec = yaml.safe_load(yf.read_text())
        except Exception:
            continue
        if not isinstance(spec, dict):
            continue
        slug = spec.get("pattern") or yf.stem
        fx = spec.get("fixtures") or {}
        vuln = fx.get("vuln")
        if not vuln:
            continue
        vp = (REPO_ROOT / vuln) if not os.path.isabs(vuln) else Path(vuln)
        if not vp.exists():
            skipped += 1
            continue
        samples.append({
            "slug": slug,
            "exclude_detector_slug": slug,
            "engine": _dsl_detector_engine(spec),
            "yaml": yf,
            "spec": spec,
            "vuln_path": vp,
            "target_language": infer_target_language(vp, spec),
            "severity": str(spec.get("severity", "")).upper() or "UNKNOWN",
            "attack_class": derive_attack_class(slug, spec.get("tags")),
            "attack_classes": sorted(derive_attack_classes(slug, spec.get("tags"))),
            "source": str(spec.get("source", "")) or "unknown",
            "sample_origin": "internal_fixture",
        })
    return samples, skipped


def _native_fixture_slug(path: Path, marker: str) -> tuple[str, str] | None:
    stem = path.stem
    if marker not in stem:
        return None
    detector_slug = stem.split(marker, 1)[0]
    if not detector_slug:
        return None
    sample_slug = stem.replace("_", "-")
    return detector_slug, sample_slug


def _has_matching_negative_fixture(path: Path, positive_marker: str) -> bool:
    stem = path.stem
    if positive_marker not in stem:
        return False
    detector_slug, suffix = stem.split(positive_marker, 1)
    negative = path.with_name(f"{detector_slug}_negative{suffix}{path.suffix}")
    return negative.exists()


def discover_go_wave1_held_out(detectors_dir: Path = GO_WAVE1_DIR):
    """Discover go_wave1 positive fixtures as held-out Go samples."""
    samples = []
    skipped = 0
    fixtures_dir = detectors_dir / "test_fixtures"
    if not fixtures_dir.exists():
        return samples, skipped
    try:
        active_slugs = {
            slug
            for slug, _mod in _load_lang_detect_module()._load_detectors(detectors_dir, None)
        }
    except Exception:
        active_slugs = {
            py.stem for py in detectors_dir.glob("*.py")
            if not py.name.startswith("_")
        }
    for fp in sorted(fixtures_dir.glob("*_positive.go")):
        pair = _native_fixture_slug(fp, "_positive")
        if pair is None:
            continue
        if not _has_matching_negative_fixture(fp, "_positive"):
            skipped += 1
            continue
        detector_slug, sample_slug = pair
        if detector_slug == "proof_of_life":
            continue
        if detector_slug not in active_slugs:
            skipped += 1
            continue
        samples.append({
            "slug": sample_slug,
            "exclude_detector_slug": detector_slug,
            "engine": "go_wave1",
            "yaml": fp,
            "spec": {"target_language": "go"},
            "vuln_path": fp,
            "target_language": "go",
            "severity": "UNKNOWN",
            "attack_class": derive_attack_class(detector_slug, None),
            "attack_classes": sorted(derive_attack_classes(detector_slug, None)),
            "source": f"go_wave1:{detector_slug}",
            "sample_origin": "internal_fixture",
        })
    return samples, skipped


def discover_rust_wave1_held_out(detectors_dir: Path = RUST_WAVE1_DIR):
    """Discover rust_wave1 positive fixtures as held-out Rust samples."""
    samples = []
    skipped = 0
    fixtures_dir = detectors_dir / "test_fixtures"
    if not fixtures_dir.exists():
        return samples, skipped
    try:
        active_slugs = {
            slug
            for slug, _mod, _accepts_engine in _load_rust_detect_module()._load_detectors(detectors_dir, None)
        }
    except Exception:
        active_slugs = {
            py.stem for py in detectors_dir.glob("*.py")
            if not py.name.startswith("_") and not py.name.startswith("DRAFT_")
        }
    for fp in sorted(fixtures_dir.glob("*_positive*.rs")):
        pair = _native_fixture_slug(fp, "_positive")
        if pair is None:
            continue
        if not _has_matching_negative_fixture(fp, "_positive"):
            skipped += 1
            continue
        detector_slug, sample_slug = pair
        if detector_slug.startswith("DRAFT_"):
            continue
        if detector_slug not in active_slugs:
            skipped += 1
            continue
        samples.append({
            "slug": sample_slug,
            "exclude_detector_slug": detector_slug,
            "engine": "rust_wave1",
            "yaml": fp,
            "spec": {"target_language": "rust"},
            "vuln_path": fp,
            "target_language": "rust",
            "severity": "UNKNOWN",
            "attack_class": derive_attack_class(detector_slug, None),
            "attack_classes": sorted(derive_attack_classes(detector_slug, None)),
            "source": f"rust_wave1:{detector_slug}",
            "sample_origin": "internal_fixture",
        })
    return samples, skipped


def discover_external_manifest(manifest_path: Path):
    """Load third-party known-vulnerable samples from a bounded manifest."""
    manifest_path = manifest_path.expanduser().resolve()
    if not manifest_path.exists():
        return [], [{"code": "manifest_missing", "message": f"external manifest not found: {manifest_path}"}]

    try:
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception as exc:
        return [], [{"code": "manifest_parse_error", "message": f"cannot parse {manifest_path}: {exc}"}]

    if not isinstance(payload, dict):
        return [], [{"code": "manifest_shape_error", "message": "external manifest must be a JSON object"}]
    raw_samples = payload.get("samples") or []
    if not isinstance(raw_samples, list):
        return [], [{"code": "manifest_samples_error", "message": "external manifest samples must be a list"}]

    samples = []
    errors = []
    base = manifest_path.parent
    payload_repo_root = str(payload.get("repo_root") or "").strip()
    manifest_solc_version = _normalize_solc_version(
        payload.get("solc_version") or payload.get("compiler_version") or ""
    )
    manifest_language = _normalize_language(
        payload.get("target_language") or payload.get("language") or ""
    )
    compile_cwd = ""
    if payload_repo_root:
        rp = Path(payload_repo_root).expanduser()
        if not rp.is_absolute():
            rp = (base / rp).resolve()
        compile_cwd = str(rp)
    for idx, row in enumerate(raw_samples, 1):
        if not isinstance(row, dict):
            errors.append({"code": "sample_shape_error", "message": f"sample {idx} is not an object"})
            continue
        sample_id = str(row.get("id") or row.get("slug") or f"external-{idx}").strip()
        raw_path = str(row.get("path") or row.get("vuln_path") or "").strip()
        raw_attack_class = str(row.get("attack_class") or "").strip()
        attack_class = normalize_attack_class(raw_attack_class)
        if not raw_path or not raw_attack_class:
            errors.append({
                "code": "sample_required_field_missing",
                "message": f"sample {sample_id} requires path and attack_class",
            })
            continue
        vp = Path(raw_path).expanduser()
        if not vp.is_absolute():
            vp = (base / vp).resolve()
        if not vp.exists():
            errors.append({
                "code": "sample_file_missing",
                "message": f"sample {sample_id} file not found: {vp}",
            })
            continue
        target_language = _normalize_language(
            row.get("target_language") or row.get("language") or ""
        ) or manifest_language or infer_target_language(vp, row)
        samples.append({
            "slug": sample_id,
            "exclude_detector_slug": str(row.get("exclude_detector_slug") or "").strip(),
            "engine": _sample_engine_for_language(target_language, row),
            "yaml": manifest_path,
            "spec": row,
            "vuln_path": vp,
            "target_language": target_language,
            "compile_cwd": compile_cwd,
            "solc_version": _normalize_solc_version(
                row.get("solc_version") or row.get("compiler_version") or manifest_solc_version
            ),
            "severity": str(row.get("severity") or "UNKNOWN").upper(),
            "attack_class": attack_class,
            "attack_classes": [attack_class] if attack_class != "uncategorized" else [],
            "source": str(row.get("source") or "external_manifest"),
            "sample_origin": "external_repo",
        })
    return samples, errors


def load_detector_library(patterns_dir: Path):
    """The detector library = every DSL pattern's compiled predicate spec.

    A detector is identified by its slug. preconditions+match are the same
    thing tools/pattern-compile.py bakes into the wave* .py tree, so driving
    the engine directly keeps this independent of the compiled tree being in
    sync (identical method to the self-test backtest).
    """
    import yaml
    library = []
    for yf in sorted(patterns_dir.glob("*.yaml")):
        try:
            spec = yaml.safe_load(yf.read_text())
        except Exception:
            continue
        if not isinstance(spec, dict):
            continue
        slug = spec.get("pattern") or yf.stem
        detector_engine = _dsl_detector_engine(spec)
        library.append({
            "slug": slug,
            "engine": detector_engine,
            "target_language": _normalize_language(spec.get("backend")) or "solidity",
            "yaml": yf,
            "attack_class": derive_attack_class(slug, spec.get("tags")),
            "attack_classes": sorted(derive_attack_classes(slug, spec.get("tags"))),
            "preconditions": spec.get("preconditions") or [],
            "match": spec.get("match") or [],
            "include_leaf": bool(spec.get("include_leaf_helpers", False)),
        })
    return library


def _load_lang_detect_module():
    return _import_module_from_path(
        "_auditooor_lang_detect",
        REPO_ROOT / "tools" / "lang-detect.py",
    )


def _load_rust_detect_module():
    return _import_module_from_path(
        "_auditooor_rust_detect",
        REPO_ROOT / "tools" / "rust-detect.py",
    )


def _load_ast_engine_module():
    return _import_module_from_path(
        "_auditooor_ast_engine",
        REPO_ROOT / "tools" / "ast-engine.py",
    )


def _load_cosmos_runner_module():
    return _import_module_from_path(
        "_auditooor_cosmos_detector_runner",
        REPO_ROOT / "tools" / "cosmos-detector-runner.py",
    )


def _load_regex_runner_module():
    return _import_module_from_path(
        "_auditooor_regex_detector_runner",
        DETECTORS_DIR / "run_regex_detectors.py",
    )


def load_go_wave1_library(detectors_dir: Path = GO_WAVE1_DIR):
    """Load active Go detector modules into scoreboard-library rows."""
    if not detectors_dir.exists():
        return []
    lang_detect = _load_lang_detect_module()
    out = []
    for slug, mod in lang_detect._load_detectors(detectors_dir, None):
        if slug == "proof_of_life":
            continue
        out.append({
            "slug": slug,
            "engine": "go_wave1",
            "target_language": "go",
            "module": mod,
            "attack_class": derive_attack_class(slug, None),
            "attack_classes": sorted(derive_attack_classes(slug, None)),
        })
    return out


def load_rust_wave1_library(detectors_dir: Path = RUST_WAVE1_DIR):
    """Load active Rust detector modules into scoreboard-library rows."""
    if not detectors_dir.exists():
        return []
    rust_detect = _load_rust_detect_module()
    out = []
    for slug, mod, accepts_engine in rust_detect._load_detectors(detectors_dir, None):
        if slug.startswith("DRAFT_"):
            continue
        out.append({
            "slug": slug,
            "engine": "rust_wave1",
            "target_language": "rust",
            "module": mod,
            "accepts_engine": bool(accepts_engine),
            "attack_class": derive_attack_class(slug, None),
            "attack_classes": sorted(derive_attack_classes(slug, None)),
        })
    return out


def load_solidity_wave17_regex_library(detectors_dir: Path = SOLIDITY_WAVE17_DIR):
    """Load standalone Solidity wave17 source-scan detector modules."""
    if not detectors_dir.exists():
        return []
    regex_runner = _load_regex_runner_module()
    out = []
    seen_slugs: set[str] = set()
    for source_path in sorted(detectors_dir.glob("*.py")):
        if source_path.name.startswith("_"):
            continue
        mod_name = "_auditooor_recall_wave17_" + source_path.stem
        spec = importlib.util.spec_from_file_location(mod_name, source_path)
        if spec is None or spec.loader is None:
            continue
        mod = importlib.util.module_from_spec(spec)
        sys.modules[mod_name] = mod
        try:
            spec.loader.exec_module(mod)
        except Exception:
            sys.modules.pop(mod_name, None)
            continue
        if not regex_runner._looks_like_regex_scan(mod):
            continue
        slug = getattr(mod, "DETECTOR_NAME", source_path.stem)
        if slug in seen_slugs:
            continue
        seen_slugs.add(slug)
        out.append({
            "slug": slug,
            "engine": "solidity_regex",
            "target_language": "solidity",
            "module": mod,
            "source_path": source_path,
            "attack_class": derive_attack_class(slug, None),
            "attack_classes": sorted(derive_attack_classes(slug, None)),
        })
    return out


# --------------------------------------------------------------------------
# Detector evaluation.
# --------------------------------------------------------------------------
def _compile_sample(sol_path, engine, compile_cwd=None, solc_version=None):
    """Compile one fixture once; return (slither_obj, error)."""
    try:
        from slither import Slither
    except ImportError as e:
        return None, f"slither-import-error: {e}"
    normalized_solc = _normalize_solc_version(solc_version)
    if normalized_solc and not SOLC_VERSION_RE.fullmatch(normalized_solc):
        return None, f"invalid-solc-version: {normalized_solc!r}; expected X.Y.Z"
    with _SOLC_ENV_LOCK:
        old_cwd = None
        old_solc_version = os.environ.get("SOLC_VERSION")
        try:
            if normalized_solc:
                # solc-select honors SOLC_VERSION without mutating the user's
                # global compiler selection. External recall manifests can then
                # carry the exact compiler needed by each repo snapshot.
                os.environ["SOLC_VERSION"] = normalized_solc
            if compile_cwd:
                cwd = Path(str(compile_cwd)).expanduser()
                if cwd.is_dir():
                    old_cwd = os.getcwd()
                    os.chdir(cwd)
            return Slither(str(sol_path)), None
        except Exception as e:
            return None, f"compile-error: {type(e).__name__}: {str(e)[:160]}"
        finally:
            if old_cwd is not None:
                os.chdir(old_cwd)
            if old_solc_version is None:
                os.environ.pop("SOLC_VERSION", None)
            else:
                os.environ["SOLC_VERSION"] = old_solc_version


def _detector_fires(sl, detector, engine):
    """Return True if `detector` fires anywhere in the compiled fixture."""
    eval_pre, eval_match, is_leaf, is_vendored = engine
    preconds = detector["preconditions"]
    matches = detector["match"]
    include_leaf = detector["include_leaf"]
    if not matches:
        return False
    try:
        for c in sl.contracts:
            if is_vendored(c):
                continue
            if not eval_pre(c, preconds):
                continue
            for fn in c.functions_and_modifiers_declared:
                if not include_leaf and is_leaf(fn):
                    continue
                if eval_match(fn, matches):
                    return True
    except Exception:
        return False
    return False


def _run_go_detectors(path: Path, detectors: list[dict], ast_engine_mod):
    hits: dict[str, bool] = {}
    for det in detectors:
        hits[det["slug"]] = False

    paths = [path]
    if path.is_dir():
        paths = sorted(p for p in path.rglob("*.go") if p.is_file())
    if not paths:
        return None, f"go-parse-error: no Go files under {path}"

    first_error = None
    parsed_any = False
    for fp in paths:
        try:
            source = fp.read_bytes()
            go_engine = ast_engine_mod.AstEngine("go", source)
            go_engine.parse()
            parsed_any = True
        except Exception as exc:
            if first_error is None:
                first_error = f"go-parse-error: {type(exc).__name__}: {str(exc)[:160]}"
            continue
        for det in detectors:
            if hits.get(det["slug"]):
                continue
            try:
                fired = bool(det["module"].run(go_engine, str(fp)) or [])
            except Exception:
                fired = False
            hits[det["slug"]] = fired
    if not parsed_any and first_error:
        return None, first_error
    return hits, None


def _run_rust_detectors(path: Path, detectors: list[dict], ast_engine_mod):
    try:
        source = path.read_bytes()
        rust_engine = ast_engine_mod.AstEngine("rust", source)
        tree = rust_engine.parse()
    except Exception as exc:
        return None, f"rust-parse-error: {type(exc).__name__}: {str(exc)[:160]}"
    hits: dict[str, bool] = {}
    for det in detectors:
        try:
            if det.get("accepts_engine"):
                fired = bool(
                    det["module"].run(tree, source, str(path), engine=rust_engine)
                    or []
                )
            else:
                fired = bool(det["module"].run(tree, source, str(path)) or [])
        except Exception:
            fired = False
        hits[det["slug"]] = fired
    return hits, None


def _run_cosmos_detectors(sample: dict, detectors: list[dict], cosmos_runner):
    path = Path(sample["vuln_path"]).resolve()
    workspace = path if path.is_dir() else _nearest_parent_with_file(path, "go.mod")
    if workspace is None:
        return None, "cosmos-workspace-error: no go.mod parent for sample"
    hits: dict[str, bool] = {det["slug"]: False for det in detectors}
    for det in detectors:
        try:
            with tempfile.TemporaryDirectory(prefix="recall-cosmos-") as td:
                out_path = Path(td) / "findings.json"
                cosmos_runner.run(
                    workspace,
                    only=det["slug"],
                    patterns_dir=DEFAULT_PATTERNS_DIR,
                    out_path=out_path,
                    quiet=True,
                )
                payload = json.loads(out_path.read_text(encoding="utf-8"))
                findings = payload.get("findings") or []
                hits[det["slug"]] = any(
                    str(f.get("pattern") or "") == det["slug"]
                    for f in findings
                )
        except Exception:
            hits[det["slug"]] = False
    return hits, None


def _run_solidity_regex_detectors(path: Path, detectors: list[dict]):
    hits: dict[str, bool] = {det["slug"]: False for det in detectors}
    if path.is_dir():
        paths = sorted(
            fp for fp in path.rglob("*.sol")
            if fp.is_file()
        )
    else:
        paths = [path]
    if not paths:
        return hits, None

    for fp in paths:
        try:
            source = fp.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        for det in detectors:
            if hits.get(det["slug"]):
                continue
            try:
                hits[det["slug"]] = bool(det["module"].scan(source, str(fp)) or [])
            except Exception:
                hits[det["slug"]] = False
    return hits, None


def _hits_for_sample(sample: dict, library: list[dict], engine_bundle):
    if not isinstance(engine_bundle, dict):
        engine_bundle = {
            "slither_engine": engine_bundle,
            "ast_engine": _load_ast_engine_module(),
            "cosmos_runner": _load_cosmos_runner_module(),
        }
    sample_engine = sample.get("engine") or "slither_dsl"
    compatible = [
        det for det in library
        if str(det.get("engine") or "slither_dsl") == sample_engine
    ]
    target_language = infer_target_language(sample.get("vuln_path"), sample.get("spec"))
    supplemental_solidity_regex = []
    if sample_engine == "slither_dsl" and target_language in SLITHER_LANGUAGES:
        supplemental_solidity_regex = [
            det for det in library
            if str(det.get("engine") or "") == "solidity_regex"
        ]
    supplemental_go = []
    if sample_engine == "cosmos_dsl" and target_language == "go":
        supplemental_go = [
            det for det in library
            if str(det.get("engine") or "") == "go_wave1"
        ]
    if sample_engine == "slither_dsl":
        sl, err = _compile_sample(
            sample["vuln_path"],
            engine_bundle["slither_engine"],
            sample.get("compile_cwd"),
            sample.get("solc_version"),
        )
        if err:
            return None, err, compatible
        hits = {
            det["slug"]: _detector_fires(sl, det, engine_bundle["slither_engine"])
            for det in compatible
        }
        if supplemental_solidity_regex:
            regex_hits, _regex_err = _run_solidity_regex_detectors(
                Path(sample["vuln_path"]),
                supplemental_solidity_regex,
            )
            if regex_hits:
                hits.update(regex_hits)
                compatible = compatible + supplemental_solidity_regex
        return hits, None, compatible
    if sample_engine == "go_wave1":
        hits, err = _run_go_detectors(
            Path(sample["vuln_path"]),
            compatible,
            engine_bundle["ast_engine"],
        )
        return hits, err, compatible
    if sample_engine == "rust_wave1":
        hits, err = _run_rust_detectors(
            Path(sample["vuln_path"]),
            compatible,
            engine_bundle["ast_engine"],
        )
        return hits, err, compatible
    if sample_engine == "cosmos_dsl":
        hits, err = _run_cosmos_detectors(
            sample,
            compatible,
            engine_bundle["cosmos_runner"],
        )
        if err:
            return hits, err, compatible
        if supplemental_go:
            go_hits, _go_err = _run_go_detectors(
                Path(sample["vuln_path"]),
                supplemental_go,
                engine_bundle["ast_engine"],
            )
            if go_hits:
                hits.update(go_hits)
                compatible = compatible + supplemental_go
        return hits, err, compatible
    return None, f"unsupported-language-runner: {sample_engine}", compatible


def _result_base(sample: dict) -> dict:
    return {
        "slug": sample["slug"],
        "attack_class": sample["attack_class"],
        "attack_classes": sample.get("attack_classes") or [],
        "severity": sample["severity"],
        "source": sample["source"],
        "sample_origin": sample.get("sample_origin", "internal_fixture"),
        "target_language": (
            sample.get("target_language")
            or infer_target_language(sample.get("vuln_path"), sample.get("spec"))
        ),
        "engine": sample.get("engine") or "slither_dsl",
        "excluded_detector_slug": sample.get("exclude_detector_slug", ""),
        "compile_cwd": sample.get("compile_cwd", ""),
        "solc_version": sample.get("solc_version", ""),
    }


# --------------------------------------------------------------------------
# Scoreboard.
# --------------------------------------------------------------------------
def run_scoreboard(samples, library, engine, quiet=False):
    """For each held-out sample, run the whole library minus its own detector."""
    # index detectors by attack_class for the class-scoped recall metric
    results = []
    n = len(samples)
    t0 = time.time()
    for i, smp in enumerate(samples, 1):
        hits, err, compatible_library = _hits_for_sample(smp, library, engine)
        if err:
            row = _result_base(smp)
            row.update({
                "compile_error": err,
                "own_detector_fired": False,
                "independent_any_fired": False,
                "independent_same_class_fired": False,
                "independent_firing_detectors": [],
                "same_class_matching_detectors": [],
            })
            results.append(row)
            continue
        own_fired = False
        indep_any = False
        indep_same_class = False
        firing = []
        same_class_matches = []
        for det in compatible_library:
            exclude_slug = str(smp.get("exclude_detector_slug") or "")
            is_own = bool(exclude_slug) and det["slug"] == exclude_slug
            fired = bool((hits or {}).get(det["slug"]))
            if not fired:
                continue
            if is_own:
                own_fired = True
                continue
            # independent detector fired on this held-out sample
            indep_any = True
            if len(firing) < 12:
                firing.append(det["slug"])
            detector_classes = set(det.get("attack_classes") or [det["attack_class"]])
            sample_classes = set(smp.get("attack_classes") or [smp["attack_class"]])
            matched_classes = sorted(detector_classes & sample_classes)
            if matched_classes and smp["attack_class"] != "uncategorized":
                indep_same_class = True
                if len(same_class_matches) < 12:
                    same_class_matches.append({
                        "detector": det["slug"],
                        "matched_classes": matched_classes,
                        "match_mode": (
                            "primary"
                            if det["attack_class"] == smp["attack_class"]
                            else "explicit-alias"
                        ),
                    })
        row = _result_base(smp)
        row.update({
            "compile_error": None,
            "own_detector_fired": own_fired,
            "independent_any_fired": indep_any,
            "independent_same_class_fired": indep_same_class,
            "independent_firing_detectors": firing,
            "same_class_matching_detectors": same_class_matches,
        })
        results.append(row)
        if not quiet and (i % 10 == 0 or i == n):
            elapsed = time.time() - t0
            rate = i / elapsed if elapsed else 0
            sys.stderr.write(f"  [{i}/{n}] {elapsed:.0f}s ({rate:.2f}/s)\n")
            sys.stderr.flush()
    return results


def aggregate(results):
    scorable = [r for r in results if not r["compile_error"]]
    n = len(scorable)
    own = sum(1 for r in scorable if r["own_detector_fired"])
    indep_any = sum(1 for r in scorable if r["independent_any_fired"])
    indep_same = sum(1 for r in scorable if r["independent_same_class_fired"])
    compile_fail = sum(1 for r in results if r["compile_error"])
    def bucket_metrics(bucket_results):
        bucket_scorable = [r for r in bucket_results if not r["compile_error"]]
        bn = len(bucket_scorable)
        return {
            "held_out_samples_total": len(bucket_results),
            "held_out_compile_failed": sum(1 for r in bucket_results if r["compile_error"]),
            "held_out_scorable": bn,
            "self_test_own_detector_recall": round(
                sum(1 for r in bucket_scorable if r["own_detector_fired"]) / bn, 4
            ) if bn else 0.0,
            "realworld_recall_any_independent": round(
                sum(1 for r in bucket_scorable if r["independent_any_fired"]) / bn, 4
            ) if bn else 0.0,
            "realworld_recall_same_class": round(
                sum(1 for r in bucket_scorable if r["independent_same_class_fired"]) / bn, 4
            ) if bn else 0.0,
        }

    by_origin = {}
    for origin in sorted({str(r.get("sample_origin") or "internal_fixture") for r in results}):
        by_origin[origin] = bucket_metrics([
            r for r in results
            if str(r.get("sample_origin") or "internal_fixture") == origin
        ])

    by_language = {}
    for language in sorted({str(r.get("target_language") or "unknown") for r in results}):
        by_language[language] = bucket_metrics([
            r for r in results
            if str(r.get("target_language") or "unknown") == language
        ])

    overall = {
        "held_out_samples_total": len(results),
        "held_out_compile_failed": compile_fail,
        "held_out_scorable": n,
        # self-test number: own detector caught its own fixture
        "self_test_own_detector_recall": round(own / n, 4) if n else 0.0,
        # real-world: ANY independent (not-own) detector fired
        "realworld_recall_any_independent": round(indep_any / n, 4) if n else 0.0,
        # real-world, class-scoped: an independent SAME-class detector fired
        "realworld_recall_same_class": round(indep_same / n, 4) if n else 0.0,
        "self_test_catches": own,
        "realworld_any_catches": indep_any,
        "realworld_same_class_catches": indep_same,
        "by_origin": by_origin,
        "by_language": by_language,
    }
    # per attack class
    per_class = {}
    for r in scorable:
        c = r["attack_class"]
        d = per_class.setdefault(c, {"n": 0, "indep_any": 0, "indep_same": 0,
                                     "own": 0})
        d["n"] += 1
        if r["independent_any_fired"]:
            d["indep_any"] += 1
        if r["independent_same_class_fired"]:
            d["indep_same"] += 1
        if r["own_detector_fired"]:
            d["own"] += 1
    class_rows = []
    for c, d in per_class.items():
        nn = d["n"]
        class_rows.append({
            "attack_class": c,
            "samples": nn,
            "self_test_recall": round(d["own"] / nn, 4) if nn else 0.0,
            "realworld_recall_any": round(d["indep_any"] / nn, 4) if nn else 0.0,
            "realworld_recall_same_class": round(d["indep_same"] / nn, 4) if nn else 0.0,
        })
    class_rows.sort(key=lambda x: (x["realworld_recall_same_class"],
                                   -x["samples"]))
    return overall, class_rows


LIMITATIONS = [
    "The any-independent-detector metric is a noise-prone UPPER BOUND, not "
    "real recall. With a 1500+-detector broad-regex library, some detector "
    "fires on nearly any contract, so a high any-independent number reflects "
    "library breadth/noise, not generalisation. The same-class metric is the "
    "honest real-world recall figure.",
    "Held-out samples are auditooor-internal synthesised fixtures derived from "
    "real Solodit / audit-firm findings, NOT pristine third-party repo "
    "snapshots. Each sample is independent of every detector EXCEPT its own "
    "(which is excluded), so the cross-detector recall is honest, but the "
    "number is a lower bound on self-test inflation, not an external-repo "
    "recall figure.",
    "attack_class is derived by the same shared detector taxonomy the self-test "
    "uses; the same-class recall metric is only as good as that map. The "
    "any-independent-detector metric does not depend on the taxonomy.",
    "DSL patterns whose vuln fixture file is absent on disk are skipped and "
    "counted in held_out_skipped_no_fixture.",
]


def limitations_for_overall(overall):
    by_origin = overall.get("by_origin") or {}
    has_internal = "internal_fixture" in by_origin
    has_external = "external_repo" in by_origin

    limitations = [
        LIMITATIONS[0],
    ]
    if has_internal:
        limitations.append(LIMITATIONS[1])
    if has_external:
        limitations.append(
            "External-manifest samples are production-source snapshots selected "
            "from third-party/local audit workspaces. In external-only mode there "
            "is usually no own detector authored from the sample, so the "
            "self-test/excluded-detector column is not comparable to the internal "
            "fixture self-test headline; read same-class external recall as the "
            "measurement."
        )
    limitations.extend(LIMITATIONS[2:])
    return limitations


def build_markdown(overall, class_rows, skipped, generated_at, filters=None):
    filters = filters or {}
    L = []
    L.append("# auditooor detector library - real-world recall scoreboard")
    L.append("")
    L.append(f"Generated: {generated_at}")
    L.append(f"Schema: `{SCHEMA}`")
    attack_classes = filters.get("attack_classes") or []
    if attack_classes:
        L.append(f"Filter: attack_class in `{', '.join(attack_classes)}`")
    L.append("")
    L.append("## Method")
    L.append("")
    by_origin = overall.get("by_origin") or {}
    has_internal = "internal_fixture" in by_origin
    has_external = "external_repo" in by_origin
    if has_external and not has_internal:
        L.append("External-manifest, cross-detector design. The held-out set is "
                 "the bounded list of production-source samples supplied by the "
                 "manifest. The whole detector library is run against each "
                 "sample; `exclude_detector_slug` is honored when present. A "
                 "same-class independent detector firing on the sample is counted "
                 "as external recall.")
    else:
        L.append("Held-out, cross-detector design. The held-out set is every DSL "
                 "pattern that ships an on-disk known-vulnerable fixture. For "
                 "each held-out fixture X the WHOLE detector library is run "
                 "against X with the one detector authored from X excluded. A "
                 "not-own detector firing on X is genuine real-world recall.")
    L.append("")
    L.append("## Headline numbers")
    L.append("")
    L.append("| Metric | Value |")
    L.append("|--------|-------|")
    L.append(f"| Held-out known-vulnerable samples | {overall['held_out_samples_total']} |")
    L.append(f"| Skipped (no fixture on disk) | {skipped} |")
    L.append(f"| Compile-failed (excluded) | {overall['held_out_compile_failed']} |")
    L.append(f"| Scorable | {overall['held_out_scorable']} |")
    L.append(f"| **Self-test recall** (own detector on own fixture) | "
             f"**{overall['self_test_own_detector_recall']*100:.1f}%** |")
    L.append(f"| **Real-world recall** (ANY independent detector fires) | "
             f"**{overall['realworld_recall_any_independent']*100:.1f}%** |")
    L.append(f"| **Real-world recall, class-scoped** (independent SAME-class "
             f"detector fires) | "
             f"**{overall['realworld_recall_same_class']*100:.1f}%** |")
    external = by_origin.get("external_repo") or {}
    if external:
        L.append(f"| External-repo samples (scorable) | {external.get('held_out_scorable', 0)} |")
        L.append(f"| External-repo same-class recall | "
                 f"**{float(external.get('realworld_recall_same_class', 0.0))*100:.1f}%** |")
    L.append("")
    gap = (overall['self_test_own_detector_recall']
           - overall['realworld_recall_same_class']) * 100
    if has_external and not has_internal:
        L.append("**External-only run:** self-test gap is not applicable because "
                 "these production-source samples do not have in-sample detector "
                 "fixtures unless an explicit `exclude_detector_slug` is "
                 "provided. The honest external same-class recall of the detector "
                 f"library is **{overall['realworld_recall_same_class']*100:.1f}%**.")
    else:
        L.append(f"**Self-test vs real-world gap: {gap:.1f} percentage points.** "
                 "The self-test (73%-class headline) overstates real-world "
                 "same-class recall by this much. The honest real-world recall "
                 f"of the detector library is "
                 f"**{overall['realworld_recall_same_class']*100:.1f}%**.")
    L.append("")
    L.append("> The `any-independent` column is a noise-prone UPPER BOUND, "
             "not recall: with a 1500+-detector broad-regex library, some "
             "detector fires on almost any contract. Read the `same-class` "
             "column as the honest number.")
    L.append("")
    if by_origin:
        L.append("## Origin breakdown")
        L.append("")
        L.append("| origin | scorable | same-class | any-indep | self-test/excluded |")
        L.append("|--------|---------:|-----------:|----------:|-------------------:|")
        for origin, row in sorted(by_origin.items()):
            L.append(
                f"| {origin} | {row.get('held_out_scorable', 0)} | "
                f"{float(row.get('realworld_recall_same_class', 0.0))*100:.1f}% | "
                f"{float(row.get('realworld_recall_any_independent', 0.0))*100:.1f}% | "
                f"{float(row.get('self_test_own_detector_recall', 0.0))*100:.1f}% |"
            )
        L.append("")
        if "external_repo" not in by_origin:
            L.append("> No external-repo manifest was provided. This run remains "
                     "the internal held-out fixture scoreboard, not an "
                     "external-repo recall measurement.")
            L.append("")
    by_language = overall.get("by_language") or {}
    if by_language:
        L.append("## Language breakdown")
        L.append("")
        L.append("| language | total | scorable | compile-failed | same-class | any-indep | self-test/excluded |")
        L.append("|----------|------:|---------:|---------------:|-----------:|----------:|-------------------:|")
        for language, row in sorted(by_language.items()):
            L.append(
                f"| {language} | {row.get('held_out_samples_total', 0)} | "
                f"{row.get('held_out_scorable', 0)} | "
                f"{row.get('held_out_compile_failed', 0)} | "
                f"{float(row.get('realworld_recall_same_class', 0.0))*100:.1f}% | "
                f"{float(row.get('realworld_recall_any_independent', 0.0))*100:.1f}% | "
                f"{float(row.get('self_test_own_detector_recall', 0.0))*100:.1f}% |"
            )
        L.append("")
    L.append("## Attack classes ranked by real-world (same-class) recall - "
             "weakest first")
    L.append("")
    L.append("| same-class | any-indep | self-test | samples | attack_class |")
    L.append("|-----------:|----------:|----------:|--------:|--------------|")
    for r in class_rows:
        L.append(f"| {r['realworld_recall_same_class']*100:.1f}% | "
                 f"{r['realworld_recall_any']*100:.1f}% | "
                 f"{r['self_test_recall']*100:.1f}% | {r['samples']} | "
                 f"{r['attack_class']} |")
    L.append("")
    L.append("## Honest limitations")
    L.append("")
    for lim in limitations_for_overall(overall):
        L.append(f"- {lim}")
    L.append("")
    return "\n".join(L)


def build_stdout(overall, skipped, filters=None):
    filters = filters or {}
    L = []
    L.append("=" * 72)
    L.append("auditooor detector library - REAL-WORLD recall scoreboard")
    L.append("=" * 72)
    L.append("")
    L.append("METHOD: held-out cross-detector test. Each known-vulnerable")
    L.append("fixture is scored by the whole library MINUS its own detector.")
    L.append("")
    L.append(f"  held-out samples           : {overall['held_out_samples_total']}")
    L.append(f"  skipped (no fixture)       : {skipped}")
    L.append(f"  compile-failed (excluded)  : {overall['held_out_compile_failed']}")
    L.append(f"  scorable                   : {overall['held_out_scorable']}")
    attack_classes = filters.get("attack_classes") or []
    if attack_classes:
        L.append(f"  attack-class filter        : {', '.join(attack_classes)}")
    L.append("")
    L.append(f"  >>> SELF-TEST recall (own detector)        : "
             f"{overall['self_test_own_detector_recall']*100:.1f}%")
    L.append(f"  >>> REAL-WORLD recall (any independent)    : "
             f"{overall['realworld_recall_any_independent']*100:.1f}%")
    L.append(f"  >>> REAL-WORLD recall (same-class indep.)  : "
             f"{overall['realworld_recall_same_class']*100:.1f}%")
    by_language = overall.get("by_language") or {}
    if by_language:
        L.append("")
        L.append("  by language same-class recall:")
        for language, row in sorted(by_language.items()):
            L.append(
                f"    {language:12s}: "
                f"{float(row.get('realworld_recall_same_class', 0.0))*100:.1f}% "
                f"({row.get('held_out_scorable', 0)} scorable, "
                f"{row.get('held_out_compile_failed', 0)} compile-failed)"
            )
    L.append("")
    L.append("  NOTE: 'any independent' is a noise-prone UPPER BOUND, not")
    L.append("  recall. The honest number is 'same-class indep.'.")
    by_origin = overall.get("by_origin") or {}
    if "external_repo" in by_origin and "internal_fixture" not in by_origin:
        L.append("  external-only run: self-test gap is not applicable")
    else:
        gap = (overall['self_test_own_detector_recall']
               - overall['realworld_recall_same_class']) * 100
        L.append(f"  self-test OVERSTATES real (same-class) recall by {gap:.1f} pts")
    L.append("=" * 72)
    return "\n".join(L)


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--patterns-dir", default=str(DEFAULT_PATTERNS_DIR))
    ap.add_argument("--limit", type=int, default=0,
                    help="cap held-out samples (0 = all). For smoke/CI.")
    ap.add_argument("--out-dir", default=str(REPO_ROOT / "reports"))
    ap.add_argument("--external-manifest", default=None,
                    help="JSON manifest of third-party known-vulnerable samples")
    ap.add_argument("--external-only", action="store_true",
                    help="score only --external-manifest samples")
    ap.add_argument("--attack-class", action="append", default=[],
                    help="score only samples whose primary or alias attack_class "
                         "matches CLASS; may be repeated or comma-separated")
    ap.add_argument("--from-json", default=None,
                    help="re-render the scoreboard from a prior JSON run "
                         "(per_sample reused; detectors NOT re-run)")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    attack_class_filter = parse_attack_class_filter(args.attack_class)

    if args.from_json:
        prior = json.loads(Path(args.from_json).read_text())
        results = filter_by_attack_class(prior["per_sample"], attack_class_filter)
        skipped = prior.get("held_out_skipped_no_fixture", 0)
        library_count = prior.get("library_detector_count", 0)
        patterns_dir = Path(prior.get("patterns_dir", DEFAULT_PATTERNS_DIR))
        external_errors = prior.get("external_manifest_errors", [])
        external_manifest = str(
            args.external_manifest or prior.get("external_manifest") or ""
        )
    else:
        patterns_dir = Path(args.patterns_dir)
        if not patterns_dir.exists():
            sys.stderr.write(f"patterns dir not found: {patterns_dir}\n")
            return 0
        engine = _import_engine()
        ast_engine = _load_ast_engine_module()
        cosmos_runner = _load_cosmos_runner_module()
        engine_bundle = {
            "slither_engine": engine,
            "ast_engine": ast_engine,
            "cosmos_runner": cosmos_runner,
        }
        samples = []
        skipped = 0
        external_errors = []
        if not args.external_only:
            samples, skipped = discover_held_out(patterns_dir)
            go_samples, go_skipped = discover_go_wave1_held_out()
            rust_samples, rust_skipped = discover_rust_wave1_held_out()
            samples.extend(go_samples)
            samples.extend(rust_samples)
            skipped += go_skipped + rust_skipped
        if args.external_manifest:
            external_samples, external_errors = discover_external_manifest(
                Path(args.external_manifest)
            )
            samples.extend(external_samples)
        samples = filter_by_attack_class(samples, attack_class_filter)
        library = (
            load_detector_library(patterns_dir)
            + load_go_wave1_library()
            + load_rust_wave1_library()
            + load_solidity_wave17_regex_library()
        )
        if args.limit:
            samples = samples[:args.limit]
        if not args.quiet:
            sys.stderr.write(
                f"[scoreboard] {len(samples)} held-out known-vulnerable "
                f"samples; library {len(library)} detectors; {skipped} "
                f"skipped no-fixture\n")
        results = run_scoreboard(samples, library, engine_bundle, quiet=args.quiet)
        library_count = len(library)
        external_manifest = (
            str(Path(args.external_manifest).expanduser().resolve())
            if args.external_manifest else ""
        )

    overall, class_rows = aggregate(results)

    generated_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    out = {
        "schema": SCHEMA,
        "generated_at": generated_at,
        "patterns_dir": str(patterns_dir),
        "method": "held-out-cross-detector-own-detector-excluded",
        "fixture_smoke_mode": True,
        "filters": {
            "attack_classes": attack_class_filter,
        },
        "library_detector_count": library_count,
        "held_out_skipped_no_fixture": skipped,
        "external_manifest": external_manifest,
        "external_manifest_errors": external_errors,
        "overall": overall,
        "by_language": overall.get("by_language", {}),
        "attack_classes": class_rows,
        "limitations": limitations_for_overall(overall),
        "per_sample": results,
    }
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / "realworld_recall_scoreboard.json"
    md_path = out_dir / "realworld_recall_scoreboard.md"
    json_path.write_text(json.dumps(out, indent=2))
    md_path.write_text(build_markdown(overall, class_rows, skipped,
                                      generated_at, out["filters"]))

    print(build_stdout(overall, skipped, out["filters"]))
    print(f"\n[json] {json_path}")
    print(f"[md]   {md_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
