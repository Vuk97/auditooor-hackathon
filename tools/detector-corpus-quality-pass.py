#!/usr/bin/env python3
"""Detector corpus quality pass.

RELATED TOOLS:
- tools/multi-language-detector-audit.py: broad language inventory, but no
  broken/quarantine accounting, clean-input FP measurement, or tier rollup.
- tools/detector-precision-matrix.py: Slither Tier A/B/S precision matrix, but
  not the regex, Rust, Go, quarantine, or R37 corpus-wide quality pass.
- tools/scanner-wiring-truth-inventory.py: wiring truth ledger, but not
  detector-file pruning pressure or false-positive measurement.
- tools/hackerman-stratify-verification-tier.py: R37 corpus record tier
  stratification, but not detector-module metadata coverage.

This tool is intentionally conservative. It reports current corpus quality and
quarantine recommendations; it does not delete or move files. A later pruning
lane can consume the JSON after human review or after a tighter automated
policy is agreed.
"""

from __future__ import annotations

import argparse
import importlib.util
import inspect
import json
import py_compile
import re
import sys
import tempfile
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


SCHEMA = "auditooor.detector_corpus_quality_pass.v1"
DETECTOR_SUFFIXES = {".py", ".yaml", ".yml"}
DEFAULT_FP_THRESHOLD = 0.10
DEFAULT_FP_MIN_CLEAN_FIXTURES = 5
BROKEN_BUCKETS = {
    "wave12_broken",
    "wave13_broken",
    "wave14_broken",
    "structurally_broken",
    "syntax_broken",
}
GRAVEYARD_BUCKETS = {"wave_graveyard"}


@dataclass(frozen=True)
class DetectorFile:
    path: str
    suffix: str
    status_bucket: str
    runner_surface: str
    verification_tier: str
    effective_verification_tier: str
    verification_tier_source: str
    py_compile_status: str
    py_compile_error: str = ""


@dataclass(frozen=True)
class FpRow:
    detector_name: str
    detector_path: str
    clean_fixtures_scanned: int
    clean_fixtures_hit: int
    clean_fixtures_exception: int
    fp_rate: float
    recommendation: str
    hit_examples: list[str]
    exception_examples: list[str]


@dataclass(frozen=True)
class LanguageFpRow:
    language: str
    detector_name: str
    detector_path: str
    clean_fixtures_scanned: int
    clean_fixtures_hit: int
    clean_fixtures_exception: int
    fp_rate: float
    recommendation: str
    hit_examples: list[str]
    exception_examples: list[str]


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def rel(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except (OSError, ValueError):
        return path.as_posix()


def detector_like_files(root: Path) -> list[Path]:
    detectors = root / "detectors"
    if not detectors.is_dir():
        return []
    out: list[Path] = []
    for path in detectors.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix not in DETECTOR_SUFFIXES:
            continue
        if "__pycache__" in path.parts:
            continue
        out.append(path)
    return sorted(out, key=lambda p: rel(p, root))


def classify_status(path: Path) -> str:
    parts = path.parts
    lowered_parts = [part.lower() for part in parts]
    if "wave17_graveyard_reactivated" in lowered_parts:
        return "reactivated"
    if any(part.startswith("_quarantine") or part == "wave_overnight_quarantine" for part in lowered_parts):
        return "quarantine"
    if any(part in GRAVEYARD_BUCKETS for part in lowered_parts):
        return "graveyard"
    if any(part in BROKEN_BUCKETS for part in lowered_parts):
        return "broken"
    return "live"


def runner_surface(path: Path, root: Path) -> str:
    try:
        rel_parts = path.relative_to(root / "detectors").parts
    except ValueError:
        return "unknown"
    if path.suffix != ".py":
        return "dsl_or_spec"
    if not rel_parts:
        return "unknown"
    wave = rel_parts[0]
    name = path.name
    if wave.startswith("wave") and len(rel_parts) == 2 and not name.startswith("_"):
        return "solidity_regex_candidate"
    if wave == "rust_wave1" and not name.startswith("_") and "test_fixtures" not in rel_parts:
        if len(rel_parts) == 2 or (len(rel_parts) > 2 and rel_parts[1].startswith("nested_")):
            return "rust_detect_visible"
        return "rust_nested_not_visible"
    if wave == "go_wave1" and len(rel_parts) == 2 and not name.startswith("_"):
        return "go_lang_detect_visible"
    if wave in {"python_wave1", "move_wave2"} and len(rel_parts) == 2 and not name.startswith("_"):
        return f"{wave}_lang_detect_candidate"
    return "not_runner_visible"


_TIER_RE = re.compile(r"(?im)^\s*verification_tier\s*[:=]\s*[\"']?([A-Za-z0-9_-]+)")


def verification_tier(path: Path) -> str:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return "unreadable"
    match = _TIER_RE.search(text)
    if match:
        return match.group(1).strip()
    return "missing"


def infer_effective_tier(path: Path, status_bucket: str, raw_tier: str) -> tuple[str, str]:
    if raw_tier not in {"missing", "unreadable", ""}:
        return raw_tier, "explicit"
    lowered_parts = [part.lower() for part in path.parts]
    if status_bucket == "quarantine":
        return "tier-5-quarantine", "inferred-quarantine-bucket"
    if "fixtures" in lowered_parts or "test_fixtures" in lowered_parts:
        return "tier-4-bundled-fixture", "inferred-fixture-path"
    return "tier-3-synthetic-taxonomy-anchored", "inferred-missing-metadata-default"


def compile_status(path: Path) -> tuple[str, str]:
    if path.suffix != ".py":
        return ("not_python", "")
    try:
        with tempfile.TemporaryDirectory(prefix="detector_quality_compile_") as tmp:
            cfile = Path(tmp) / (path.name + ".pyc")
            py_compile.compile(str(path), cfile=str(cfile), doraise=True)
    except py_compile.PyCompileError as exc:
        return ("compile_failed", str(exc).splitlines()[-1][:400])
    except Exception as exc:  # pragma: no cover - defensive around filesystem edge cases
        return ("compile_error", repr(exc)[:400])
    return ("ok", "")


def inspect_detector_file(path: Path, root: Path) -> DetectorFile:
    status, error = compile_status(path)
    status_bucket = classify_status(path)
    raw_tier = verification_tier(path)
    effective_tier, tier_source = infer_effective_tier(path, status_bucket, raw_tier)
    return DetectorFile(
        path=rel(path, root),
        suffix=path.suffix,
        status_bucket=status_bucket,
        runner_surface=runner_surface(path, root),
        verification_tier=raw_tier,
        effective_verification_tier=effective_tier,
        verification_tier_source=tier_source,
        py_compile_status=status,
        py_compile_error=error,
    )


def clean_solidity_fixtures(root: Path, limit: int) -> list[Path]:
    candidates: list[Path] = []
    bases = [
        root / "detectors" / "test_fixtures",
        root / "detectors" / "fixtures",
    ]
    for base in bases:
        if not base.is_dir():
            continue
        for path in base.rglob("*.sol"):
            lname = path.name.lower()
            if "negative" in lname or "clean" in lname or path.parent.name.lower() in {"negative", "clean"}:
                candidates.append(path)
    unique = sorted({p.resolve() for p in candidates}, key=lambda p: rel(p, root))
    return unique[:limit] if limit > 0 else unique


def clean_language_fixtures(root: Path, language: str, limit: int) -> list[Path]:
    config = {
        "go": ("go_wave1", ".go", ("negative", "clean")),
        "rust": ("rust_wave1", ".rs", ("negative", "clean")),
        "python": ("python_wave1", ".py", ("negative", "clean")),
        "move": ("move_wave2", ".move", ("clean", "negative")),
    }
    if language not in config:
        return []
    wave, suffix, markers = config[language]
    base = root / "detectors" / wave / "test_fixtures"
    if not base.is_dir():
        return []
    out: list[Path] = []
    for path in base.rglob(f"*{suffix}"):
        lname = path.name.lower()
        if any(marker in lname for marker in markers):
            out.append(path)
    unique = sorted({p.resolve() for p in out}, key=lambda p: rel(p, root))
    return unique[:limit] if limit > 0 else unique


def _load_regex_detector(path: Path) -> tuple[str, Any] | None:
    name = "quality_pass_regex_" + re.sub(r"[^A-Za-z0-9_]+", "_", path.with_suffix("").as_posix())
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        return None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    old_dont_write_bytecode = sys.dont_write_bytecode
    try:
        sys.dont_write_bytecode = True
        spec.loader.exec_module(module)
    except Exception:
        sys.modules.pop(name, None)
        return None
    finally:
        sys.dont_write_bytecode = old_dont_write_bytecode
    scan = getattr(module, "scan", None)
    if not callable(scan):
        return None
    det_name = str(getattr(module, "DETECTOR_NAME", path.stem))
    return det_name, scan


def _module_from_file(path: Path, module_name: str) -> tuple[Any | None, str]:
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        return None, "no loader"
    module = importlib.util.module_from_spec(spec)
    old_dont_write_bytecode = sys.dont_write_bytecode
    try:
        sys.dont_write_bytecode = True
        sys.modules[module_name] = module
        spec.loader.exec_module(module)
    except Exception as exc:
        sys.modules.pop(module_name, None)
        return None, f"{type(exc).__name__}: {str(exc)[:240]}"
    finally:
        sys.dont_write_bytecode = old_dont_write_bytecode
    return module, ""


def _load_ast_engine(root: Path) -> Any:
    module, error = _module_from_file(root / "tools" / "ast-engine.py", "quality_pass_ast_engine")
    if module is None:
        raise RuntimeError(f"could not load ast-engine.py: {error}")
    return module


def language_detector_paths(root: Path, language: str) -> list[Path]:
    detectors = root / "detectors"
    if language in {"go", "python"}:
        base = detectors / f"{language}_wave1"
        if not base.is_dir():
            return []
        return sorted(
            path for path in base.glob("*.py")
            if not path.name.startswith("_") and path.name != "__init__.py"
        )
    if language == "move":
        base = detectors / "move_wave2"
        if not base.is_dir():
            return []
        return sorted(
            path for path in base.glob("*.py")
            if not path.name.startswith("_") and path.name != "__init__.py"
        )
    if language == "rust":
        base = detectors / "rust_wave1"
        if not base.is_dir():
            return []
        out: list[Path] = []
        for path in base.rglob("*.py"):
            rel_parts = path.relative_to(base).parts
            if path.name.startswith("_") or path.name == "__init__.py":
                continue
            if any(part in {"test_fixtures", "__pycache__"} for part in rel_parts[:-1]):
                continue
            if len(rel_parts) > 1 and not rel_parts[0].startswith("nested_"):
                continue
            out.append(path)
        return sorted(out, key=lambda p: p.relative_to(base).as_posix())
    return []


def _load_language_detector(root: Path, path: Path, language: str) -> tuple[str, Any | None, str, bool]:
    wave_dir = path.parent
    if language == "rust":
        wave_dir = root / "detectors" / "rust_wave1"
    else:
        wave_dir = root / "detectors" / f"{language}_wave1"
        if language == "move":
            wave_dir = root / "detectors" / "move_wave2"
    for candidate in (str(wave_dir), str(path.parent)):
        if candidate not in sys.path:
            sys.path.insert(0, candidate)
    mod_name = "quality_pass_lang_" + re.sub(r"[^A-Za-z0-9_]+", "_", path.with_suffix("").as_posix())
    module, error = _module_from_file(path, mod_name)
    if module is None:
        return path.stem, None, error, False
    if language == "move":
        scan = getattr(module, "run_text", None) or getattr(module, "scan_text", None) or getattr(module, "scan_file", None)
        if not callable(scan):
            return path.stem, None, "missing run_text, scan_text, or scan_file", False
        return path.stem, scan, "", False
    run = getattr(module, "run", None)
    if not callable(run):
        return path.stem, None, "missing run", False
    accepts_engine = False
    if language == "rust":
        try:
            accepts_engine = "engine" in inspect.signature(run).parameters
        except (TypeError, ValueError):
            accepts_engine = False
    return path.stem, run, "", accepts_engine


def language_fp_backtest(
    root: Path,
    languages: list[str],
    *,
    max_detectors: int,
    max_clean_fixtures: int,
    fp_threshold: float,
    min_clean_fixtures: int,
) -> list[LanguageFpRow]:
    ast_engine: Any | None = None
    rows: list[LanguageFpRow] = []
    for language in languages:
        detectors = language_detector_paths(root, language)
        if max_detectors > 0:
            detectors = detectors[:max_detectors]
        clean = clean_language_fixtures(root, language, max_clean_fixtures)
        if not detectors or not clean:
            continue
        parsed: list[tuple[Path, bytes, Any | None, Any | None, str]] = []
        if language in {"go", "python", "rust"}:
            if ast_engine is None:
                ast_engine = _load_ast_engine(root)
            for fixture in clean:
                source = fixture.read_bytes()
                try:
                    engine = ast_engine.AstEngine(language, source)
                    tree = engine.parse()
                    parsed.append((fixture, source, engine, tree, ""))
                except Exception as exc:
                    parsed.append((fixture, source, None, None, f"{type(exc).__name__}: {str(exc)[:160]}"))
        else:
            for fixture in clean:
                parsed.append((fixture, fixture.read_bytes(), None, None, ""))

        for detector in detectors:
            name, callable_obj, load_error, accepts_engine = _load_language_detector(root, detector, language)
            hit_examples: list[str] = []
            exception_examples: list[str] = []
            hit_count = 0
            exception_count = 0
            if callable_obj is None:
                exception_count = len(clean)
                exception_examples.append(f"load {rel(detector, root)}: {load_error}")
            else:
                for fixture, source, engine, tree, parse_error in parsed:
                    try:
                        if parse_error:
                            raise RuntimeError(parse_error)
                        if language == "rust":
                            if accepts_engine:
                                findings = callable_obj(tree, source, str(fixture), engine=engine) or []
                            else:
                                findings = callable_obj(tree, source, str(fixture)) or []
                        elif language in {"go", "python"}:
                            findings = callable_obj(engine, str(fixture)) or []
                        else:
                            if getattr(callable_obj, "__name__", "") == "scan_file":
                                findings = callable_obj(fixture) or []
                            else:
                                findings = callable_obj(source.decode("utf-8", errors="replace"), str(fixture)) or []
                    except Exception as exc:
                        exception_count += 1
                        if len(exception_examples) < 5:
                            exception_examples.append(f"{rel(fixture, root)}: {type(exc).__name__}: {str(exc)[:160]}")
                        findings = []
                    if findings:
                        hit_count += 1
                        if len(hit_examples) < 5:
                            hit_examples.append(rel(fixture, root))
            scanned = len(clean)
            rate = (hit_count / scanned) if scanned else 0.0
            if scanned >= min_clean_fixtures and exception_count:
                recommendation = "quarantine_candidate_clean_scan_exception"
            elif scanned >= min_clean_fixtures and rate > fp_threshold:
                recommendation = "quarantine_candidate_high_clean_fp"
            else:
                recommendation = "keep_measured_clean_fp_within_threshold"
            rows.append(
                LanguageFpRow(
                    language=language,
                    detector_name=name,
                    detector_path=rel(detector, root),
                    clean_fixtures_scanned=scanned,
                    clean_fixtures_hit=hit_count,
                    clean_fixtures_exception=exception_count,
                    fp_rate=rate,
                    recommendation=recommendation,
                    hit_examples=hit_examples,
                    exception_examples=exception_examples,
                )
            )
    return rows


def regex_fp_backtest(
    root: Path,
    detector_rows: list[DetectorFile],
    *,
    max_detectors: int,
    max_clean_fixtures: int,
    fp_threshold: float,
    min_clean_fixtures: int,
) -> list[FpRow]:
    clean = clean_solidity_fixtures(root, max_clean_fixtures)
    selected: list[DetectorFile] = []
    for row in detector_rows:
        if row.status_bucket != "live":
            continue
        if row.runner_surface != "solidity_regex_candidate":
            continue
        if row.py_compile_status != "ok":
            continue
        try:
            text = (root / row.path).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if re.search(r"(?m)^\s*def\s+scan\s*\(", text):
            selected.append(row)
    if max_detectors > 0:
        selected = selected[:max_detectors]

    rows: list[FpRow] = []
    for row in selected:
        path = root / row.path
        loaded = _load_regex_detector(path)
        if loaded is None:
            continue
        det_name, scan = loaded
        hit_examples: list[str] = []
        exception_examples: list[str] = []
        hit_count = 0
        exception_count = 0
        for fixture in clean:
            try:
                source = fixture.read_text(encoding="utf-8", errors="replace")
                findings = scan(source, str(fixture)) or []
            except Exception as exc:
                exception_count += 1
                if len(exception_examples) < 5:
                    exception_examples.append(f"{rel(fixture, root)}: {type(exc).__name__}: {str(exc)[:160]}")
                findings = []
            if findings:
                hit_count += 1
                if len(hit_examples) < 5:
                    hit_examples.append(rel(fixture, root))
        scanned = len(clean)
        rate = (hit_count / scanned) if scanned else 0.0
        if scanned >= min_clean_fixtures and exception_count:
            recommendation = "quarantine_candidate_clean_scan_exception"
        elif scanned >= min_clean_fixtures and rate > fp_threshold:
            recommendation = "quarantine_candidate_high_clean_fp"
        else:
            recommendation = "keep_measured_clean_fp_within_threshold"
        rows.append(
            FpRow(
                detector_name=det_name,
                detector_path=row.path,
                clean_fixtures_scanned=scanned,
                clean_fixtures_hit=hit_count,
                clean_fixtures_exception=exception_count,
                fp_rate=rate,
                recommendation=recommendation,
                hit_examples=hit_examples,
                exception_examples=exception_examples,
            )
        )
    return rows


def summarize(rows: list[DetectorFile], fp_rows: list[FpRow], language_fp_rows: list[LanguageFpRow]) -> dict[str, Any]:
    total = len(rows)
    by_status = Counter(row.status_bucket for row in rows)
    by_surface = Counter(row.runner_surface for row in rows)
    by_tier = Counter(row.verification_tier for row in rows)
    by_effective_tier = Counter(row.effective_verification_tier for row in rows)
    by_compile = Counter(row.py_compile_status for row in rows)
    dead_statuses = {"broken", "graveyard", "quarantine"}
    survivor_statuses = {"live", "reactivated"}
    dead_like = sum(1 for row in rows if row.status_bucket in dead_statuses)
    live_like = sum(1 for row in rows if row.status_bucket == "live")
    survivors = [row for row in rows if row.status_bucket in survivor_statuses]
    compile_fail_live = [row for row in rows if row.status_bucket == "live" and row.py_compile_status not in {"ok", "not_python"}]
    missing_tier_live = [row for row in rows if row.status_bucket == "live" and row.verification_tier == "missing"]
    noisy = [row for row in fp_rows if row.recommendation.startswith("quarantine_candidate_")]
    language_noisy = [row for row in language_fp_rows if row.recommendation.startswith("quarantine_candidate_")]
    return {
        "total_detector_like_files": total,
        "live_detector_like_files": live_like,
        "dead_weight_detector_like_files": dead_like,
        "status_distribution": dict(sorted(by_status.items())),
        "runner_surface_distribution": dict(sorted(by_surface.items())),
        "verification_tier_distribution": dict(sorted(by_tier.items())),
        "effective_verification_tier_distribution": dict(sorted(by_effective_tier.items())),
        "survivor_effective_verification_tier_distribution": dict(
            sorted(Counter(row.effective_verification_tier for row in survivors).items())
        ),
        "survivor_missing_effective_verification_tier_count": sum(
            1 for row in survivors if not row.effective_verification_tier
        ),
        "py_compile_distribution": dict(sorted(by_compile.items())),
        "live_compile_fail_count": len(compile_fail_live),
        "live_missing_verification_tier_count": len(missing_tier_live),
        "fp_backtest_detector_count": len(fp_rows),
        "fp_quarantine_recommendation_count": len(noisy),
        "language_fp_backtest_detector_count": len(language_fp_rows),
        "language_fp_quarantine_recommendation_count": len(language_noisy),
    }


def load_wiring_manifests(root: Path, manifest_paths: Iterable[str]) -> list[dict[str, Any]]:
    manifests: list[dict[str, Any]] = []
    for raw in manifest_paths:
        path = Path(raw).expanduser()
        if not path.is_absolute():
            path = root / path
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            manifests.append({"path": str(path), "status": "unreadable", "error": repr(exc)})
            continue
        counts = data.get("per_detector_counts") or {}
        fired = sorted([str(name) for name, count in counts.items() if count])
        manifests.append(
            {
                "path": str(path),
                "status": "ok",
                "schema": data.get("schema"),
                "workspace": data.get("workspace"),
                "target": data.get("target"),
                "files_scanned": data.get("files_scanned"),
                "detectors_loaded": len(data.get("detectors") or []),
                "findings_count": len(data.get("findings") or []),
                "fired_detector_count": len(fired),
                "fired_detectors": fired,
            }
        )
    return manifests


def write_markdown(path: Path, payload: dict[str, Any]) -> None:
    summary = payload["summary"]
    fp_rows = payload.get("fp_backtest", [])
    language_fp_rows = payload.get("language_fp_backtest", [])
    compile_fail = payload.get("live_compile_fail_examples", [])
    missing_tier = payload.get("live_missing_tier_examples", [])
    lines = [
        "# Detector Corpus Quality Pass",
        "",
        f"Generated: {payload['generated_at']}",
        f"Schema: `{payload['schema']}`",
        "",
        "## Corpus Counts",
        "",
        f"- Detector-like files: {summary['total_detector_like_files']}",
        f"- Live detector-like files: {summary['live_detector_like_files']}",
        f"- Broken/graveyard/quarantine detector-like files: {summary['dead_weight_detector_like_files']}",
        "",
        "## Status Distribution",
        "",
    ]
    for key, value in summary["status_distribution"].items():
        lines.append(f"- `{key}`: {value}")
    lines.extend(["", "## Runner Surface Distribution", ""])
    for key, value in summary["runner_surface_distribution"].items():
        lines.append(f"- `{key}`: {value}")
    lines.extend(["", "## R37 Verification Tier Distribution", ""])
    for key, value in summary["verification_tier_distribution"].items():
        lines.append(f"- `{key}`: {value}")
    lines.extend(["", "## R37 Effective Survivor Tier Distribution", ""])
    for key, value in summary["survivor_effective_verification_tier_distribution"].items():
        lines.append(f"- `{key}`: {value}")
    lines.extend([
        "",
        f"- Survivor missing effective tier count: {summary['survivor_missing_effective_verification_tier_count']}",
        "- Effective tiers are explicit when present; otherwise this report uses conservative inference.",
        "- Missing source anchors are classified as `tier-3-synthetic-taxonomy-anchored`, not source-verified.",
    ])
    lines.extend(["", "## Python Compile Distribution", ""])
    for key, value in summary["py_compile_distribution"].items():
        lines.append(f"- `{key}`: {value}")
    lines.extend(["", "## Live Compile Fail Examples", ""])
    if compile_fail:
        for row in compile_fail[:25]:
            lines.append(f"- `{row['path']}`: {row['py_compile_status']} - {row['py_compile_error']}")
    else:
        lines.append("- None in sampled/current scan.")
    lines.extend(["", "## Live Missing Tier Examples", ""])
    if missing_tier:
        for row in missing_tier[:25]:
            lines.append(f"- `{row['path']}`")
    else:
        lines.append("- None.")
    lines.extend(["", "## Clean-Fixture FP Backtest", ""])
    if fp_rows:
        lines.append("| Detector | Clean fixtures | Hits | Exceptions | FP rate | Recommendation |")
        lines.append("|---|---:|---:|---:|---:|---|")
        for row in fp_rows:
            lines.append(
                f"| `{row['detector_name']}` | {row['clean_fixtures_scanned']} | "
                f"{row['clean_fixtures_hit']} | {row['clean_fixtures_exception']} | "
                f"{row['fp_rate']:.2%} | `{row['recommendation']}` |"
            )
    else:
        lines.append("- Not run. Pass `--fp-backtest` to measure clean-input FP rates.")
    lines.extend(["", "## Language Clean-Fixture FP Backtest", ""])
    if language_fp_rows:
        lines.append("| Language | Detector | Clean fixtures | Hits | Exceptions | FP rate | Recommendation |")
        lines.append("|---|---|---:|---:|---:|---:|---|")
        for row in language_fp_rows:
            lines.append(
                f"| `{row['language']}` | `{row['detector_name']}` | {row['clean_fixtures_scanned']} | "
                f"{row['clean_fixtures_hit']} | {row['clean_fixtures_exception']} | "
                f"{row['fp_rate']:.2%} | `{row['recommendation']}` |"
            )
    else:
        lines.append(
            "- Not run. Pass `--language-fp-backtest` to measure Go, Rust, Python, and Move clean fixtures."
        )
    lines.extend(["", "## Confirmed Runner Wiring", ""])
    wiring = payload.get("wiring_manifests", [])
    if wiring:
        lines.append("| Manifest | Files | Loaded | Findings | Fired detectors |")
        lines.append("|---|---:|---:|---:|---|")
        for row in wiring:
            if row.get("status") != "ok":
                lines.append(f"| `{row.get('path')}` | n/a | n/a | n/a | `{row.get('status')}` |")
                continue
            fired = ", ".join(f"`{name}`" for name in row.get("fired_detectors", [])[:8])
            if row.get("fired_detector_count", 0) > 8:
                fired += f", ... +{row['fired_detector_count'] - 8}"
            lines.append(
                f"| `{row.get('path')}` | {row.get('files_scanned')} | "
                f"{row.get('detectors_loaded')} | {row.get('findings_count')} | {fired or 'none'} |"
            )
    else:
        lines.append("- No runner manifests supplied. Pass `--audit-manifest` to include make audit or regex-detectors evidence.")
    lines.extend([
        "",
        "## Quarantine Recommendations",
        "",
    ])
    noisy = [row for row in fp_rows if row["recommendation"].startswith("quarantine_candidate_")]
    noisy.extend(
        row for row in language_fp_rows
        if row["recommendation"].startswith("quarantine_candidate_")
    )
    if noisy:
        for row in noisy:
            detector_path = row["detector_path"]
            if row["recommendation"] == "quarantine_candidate_clean_scan_exception":
                lines.append(
                    f"- `{detector_path}` raised exceptions on "
                    f"{row['clean_fixtures_exception']}/{row['clean_fixtures_scanned']} clean fixtures."
                )
            else:
                lines.append(f"- `{detector_path}` hit {row['clean_fixtures_hit']}/{row['clean_fixtures_scanned']} clean fixtures.")
    else:
        lines.append("- No FP quarantine candidates in this run.")
    lines.extend([
        "",
        "## Notes",
        "",
        "- This tool is measurement-only. The prune itself is visible in the git diff.",
        "- Detector hits remain source-review candidates only, not filing proof under R40, R76, or R80.",
        "- R37 effective tiers are conservative sidecar classifications unless embedded metadata exists.",
        "",
    ])
    path.write_text("\n".join(lines), encoding="utf-8")


def write_tier_jsonl(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    rows = payload.get("detector_files", [])
    survivor_rows = [
        row for row in rows
        if row.get("status_bucket") in {"live", "reactivated"}
    ]
    with path.open("w", encoding="utf-8") as fh:
        for row in survivor_rows:
            out = {
                "schema": "auditooor.detector_survivor_verification_tier.v1",
                "path": row["path"],
                "status_bucket": row["status_bucket"],
                "verification_tier": row["effective_verification_tier"],
                "verification_tier_source": row["verification_tier_source"],
                "raw_verification_tier": row["verification_tier"],
            }
            fh.write(json.dumps(out, sort_keys=True) + "\n")


def build_payload(args: argparse.Namespace) -> dict[str, Any]:
    root = Path(args.repo).resolve()
    rows = [inspect_detector_file(path, root) for path in detector_like_files(root)]
    fp_rows: list[FpRow] = []
    if args.fp_backtest:
        fp_rows = regex_fp_backtest(
            root,
            rows,
            max_detectors=args.max_fp_detectors,
            max_clean_fixtures=args.max_clean_fixtures,
            fp_threshold=args.fp_threshold,
            min_clean_fixtures=args.fp_min_clean_fixtures,
        )
    language_fp_rows: list[LanguageFpRow] = []
    if args.language_fp_backtest:
        language_fp_rows = language_fp_backtest(
            root,
            [item.strip() for item in args.language_fp_langs.split(",") if item.strip()],
            max_detectors=args.max_language_fp_detectors,
            max_clean_fixtures=args.max_language_clean_fixtures,
            fp_threshold=args.fp_threshold,
            min_clean_fixtures=args.fp_min_clean_fixtures,
        )
    summary = summarize(rows, fp_rows, language_fp_rows)
    wiring_manifests = load_wiring_manifests(root, args.audit_manifest or [])
    fired_union = sorted({
        detector
        for manifest in wiring_manifests
        for detector in manifest.get("fired_detectors", [])
        if manifest.get("status") == "ok"
    })
    summary["wiring_confirmed_detector_count"] = len(fired_union)
    summary["wiring_confirmed_detectors"] = fired_union
    live_compile_fail = [
        asdict(row) for row in rows
        if row.status_bucket == "live" and row.py_compile_status not in {"ok", "not_python"}
    ]
    live_missing_tier = [
        asdict(row) for row in rows
        if row.status_bucket == "live" and row.verification_tier == "missing"
    ]
    dead_examples = [
        asdict(row) for row in rows
        if row.status_bucket in {"broken", "graveyard", "quarantine"}
    ][:100]
    return {
        "schema": SCHEMA,
        "generated_at": utc_now(),
        "repo": str(root),
        "options": {
            "fp_backtest": bool(args.fp_backtest),
            "max_fp_detectors": args.max_fp_detectors,
            "max_clean_fixtures": args.max_clean_fixtures,
            "fp_threshold": args.fp_threshold,
            "fp_min_clean_fixtures": args.fp_min_clean_fixtures,
            "language_fp_backtest": bool(args.language_fp_backtest),
            "language_fp_langs": args.language_fp_langs,
            "max_language_fp_detectors": args.max_language_fp_detectors,
            "max_language_clean_fixtures": args.max_language_clean_fixtures,
        },
        "summary": summary,
        "dead_weight_examples": dead_examples,
        "live_compile_fail_examples": live_compile_fail[:100],
        "live_missing_tier_examples": live_missing_tier[:100],
        "detector_files": [asdict(row) for row in rows],
        "fp_backtest": [asdict(row) for row in fp_rows],
        "language_fp_backtest": [asdict(row) for row in language_fp_rows],
        "wiring_manifests": wiring_manifests,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Measure detector corpus quality before pruning.")
    parser.add_argument("--repo", default=".", help="Repo root, default current directory.")
    parser.add_argument("--out-json", default="reports/detector_quality_pass_20260605/quality_pass.json")
    parser.add_argument("--out-md", default="reports/detector_quality_pass_20260605/quality_pass.md")
    parser.add_argument("--out-tiers-jsonl", default="")
    parser.add_argument("--fp-backtest", action="store_true", help="Run clean Solidity fixture FP backtest.")
    parser.add_argument("--max-fp-detectors", type=int, default=50, help="Max live regex detectors to FP-test; 0 means all.")
    parser.add_argument("--max-clean-fixtures", type=int, default=50, help="Max clean Solidity fixtures to scan; 0 means all.")
    parser.add_argument("--fp-threshold", type=float, default=DEFAULT_FP_THRESHOLD)
    parser.add_argument("--fp-min-clean-fixtures", type=int, default=DEFAULT_FP_MIN_CLEAN_FIXTURES)
    parser.add_argument("--language-fp-backtest", action="store_true", help="Run clean fixture FP backtest for runnable non-regex detector families.")
    parser.add_argument("--language-fp-langs", default="go,rust,python,move", help="Comma-separated language detector families to test.")
    parser.add_argument("--max-language-fp-detectors", type=int, default=0, help="Max language detectors per family; 0 means all.")
    parser.add_argument("--max-language-clean-fixtures", type=int, default=0, help="Max clean fixtures per language; 0 means all.")
    parser.add_argument(
        "--audit-manifest",
        action="append",
        default=[],
        help="Include an existing make audit or regex-detectors manifest; may be repeated.",
    )
    args = parser.parse_args(argv)

    payload = build_payload(args)
    out_json = Path(args.out_json)
    out_md = Path(args.out_md)
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    write_markdown(out_md, payload)
    if args.out_tiers_jsonl:
        write_tier_jsonl(Path(args.out_tiers_jsonl), payload)
    print(json.dumps({"schema": SCHEMA, "summary": payload["summary"], "out_json": str(out_json), "out_md": str(out_md)}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
