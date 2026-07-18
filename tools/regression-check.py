#!/usr/bin/env python3
"""
regression-check.py — ground-truth regression baselines for custom detectors.

Why this exists (K11 + M5 design, meta-infra gap):
    Recent PR history shows recurring "build-then-fix" cycles (#153 → #164,
    #154 → #155) and "false-positive flake" cycles (#167) where an existing
    detector starts firing differently against historical fixtures and the
    drift is only noticed after a flake or a triage round. Kimi-K11 flagged
    this as the largest open coverage gap: ground-truth regression
    infrastructure is missing — we keep shipping detectors faster than the
    metastructure to keep them consistent.

    `detectors/run_custom.py --batch <dir> <expected.tsv>` already exists and
    does pass/fail regression on the binary signal "vuln has >=1 hit, clean
    has 0". This tool is COMPLEMENTARY: it locks in the exact integer hit
    count + severity at a known-good commit (baseline_sha), so any future
    change that perturbs a detector's behaviour against the same fixture is
    surfaced as a diff before it lands.

Schema (one JSON file per detector at tools/baselines/<detector>.json):
    {
      "detector_name":     "role-grant-divergence",
      "fixture_path":      "detectors/test_fixtures/role_grant_divergence_vulnerable.sol",
      "expected_hits":     1,
      "expected_severity": "HIGH",
      "baseline_date":     "2026-04-25",
      "baseline_sha":      "5110095ac..."
    }

Usage:
    tools/regression-check.py                       # run all baselines, exit 0/1/2
    tools/regression-check.py --seed                # seed missing baselines
    tools/regression-check.py --seed <detector>     # seed one detector
    tools/regression-check.py --baselines-dir DIR   # override baselines dir
    tools/regression-check.py --filter <name>       # only check one baseline

Exit codes:
    0   all baselines passed
    1   at least one baseline FAILED (hits or severity drift)
    2   at least one detector listed in baselines is missing (or an error)

Hard rules:
    - stdlib only (subprocess + json + argparse), plus slither (already a
      hard dep of the detector library; imported lazily).
    - Does NOT mutate detector source. Does NOT touch the tier registry.
    - Schema validation is testable without slither (see
      tools/tests/test_regression_check.py).
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from datetime import date
from pathlib import Path
from typing import Any


REPO = Path(__file__).resolve().parents[1]
DEFAULT_BASELINES_DIR = REPO / "tools" / "baselines"
RUN_CUSTOM = REPO / "detectors" / "run_custom.py"

REQUIRED_KEYS = (
    "detector_name",
    "fixture_path",
    "expected_hits",
    "expected_severity",
    "baseline_date",
    "baseline_sha",
)
VALID_SEVERITIES = {"INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "OPTIMIZATION"}


# ---------- schema ----------

def validate_baseline(payload: dict, path: Path | None = None) -> list[str]:
    """Return a list of error strings; empty list = valid."""
    errors: list[str] = []
    where = f" (in {path})" if path else ""
    if not isinstance(payload, dict):
        return [f"baseline payload must be a dict{where}"]
    for k in REQUIRED_KEYS:
        if k not in payload:
            errors.append(f"missing key {k!r}{where}")
    if errors:
        return errors
    if not isinstance(payload["detector_name"], str) or not payload["detector_name"]:
        errors.append(f"detector_name must be a non-empty string{where}")
    if not isinstance(payload["fixture_path"], str) or not payload["fixture_path"]:
        errors.append(f"fixture_path must be a non-empty string{where}")
    if not isinstance(payload["expected_hits"], int) or payload["expected_hits"] < 0:
        errors.append(f"expected_hits must be a non-negative int{where}")
    sev = payload["expected_severity"]
    if not isinstance(sev, str) or sev.upper() not in VALID_SEVERITIES:
        errors.append(
            f"expected_severity must be one of {sorted(VALID_SEVERITIES)}{where} "
            f"(got {sev!r})"
        )
    if not isinstance(payload["baseline_date"], str) or len(payload["baseline_date"]) != 10:
        errors.append(f"baseline_date must be YYYY-MM-DD{where}")
    if not isinstance(payload["baseline_sha"], str) or len(payload["baseline_sha"]) < 7:
        errors.append(f"baseline_sha must be a git sha (>=7 chars){where}")
    return errors


def load_baselines(baselines_dir: Path) -> list[tuple[Path, dict]]:
    """Load every *.json under baselines_dir. Skip .keep and hidden files."""
    out: list[tuple[Path, dict]] = []
    if not baselines_dir.exists():
        return out
    for f in sorted(baselines_dir.glob("*.json")):
        if f.name.startswith("."):
            continue
        try:
            data = json.loads(f.read_text())
        except Exception as e:
            raise SystemExit(f"[regression-check] failed to parse {f}: {e}")
        out.append((f, data))
    return out


# ---------- detector execution ----------

def _git_head_sha() -> str:
    try:
        sha = subprocess.check_output(
            ["git", "-C", str(REPO), "rev-parse", "HEAD"],
            stderr=subprocess.DEVNULL,
        ).decode().strip()
        return sha or "unknown"
    except Exception:
        return "unknown"


def _import_run_custom():
    """Lazily import detectors/run_custom.py without invoking its CLI."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("run_custom", RUN_CUSTOM)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {RUN_CUSTOM}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run_detector(detector_name: str, fixture_path: Path) -> tuple[int, str]:
    """Run a single detector against a single fixture. Returns (hit_count, severity).

    Severity is the detector class's IMPACT.name (e.g. "HIGH"). On 0 hits,
    severity is reported from the detector class itself (so baselines can
    record severity even when expected_hits is 0 — useful for clean fixtures).
    """
    rc_mod = _import_run_custom()
    try:
        from slither import Slither  # noqa: F401  — imported for side effects
    except ImportError:
        raise RuntimeError(
            "slither-analyzer not installed. Run: pip install slither-analyzer"
        )

    detectors_dir = REPO / "detectors"
    # Tier filter ALL so a Tier-D detector can still have a baseline if the
    # caller seeds it explicitly. Tier-S/E load by default.
    detectors = rc_mod.load_detectors(
        detectors_dir, name_filter=detector_name, tier_filter="ALL"
    )
    if not detectors:
        raise RuntimeError(
            f"detector {detector_name!r} not found in {detectors_dir} "
            f"(check ARGUMENT spelling and tier registry)"
        )
    DetectorClass = detectors[0]
    severity = DetectorClass.IMPACT.name

    from slither import Slither
    slither = Slither(str(fixture_path))

    import logging
    logger = logging.getLogger(f"auditooor.regression.{detector_name}")
    total = 0
    for cu in slither.compilation_units:
        try:
            det = DetectorClass(cu, slither, logger)
            results = det.detect() or []
        except Exception as e:
            raise RuntimeError(f"detector run failed: {e}")
        for r in results:
            if rc_mod is None:
                continue
            # Reuse run_custom's vendored filter so we agree with the runner.
            elements = r.get("elements", []) or []
            vendored = False
            for elem in elements:
                src = elem.get("source_mapping") or {}
                p = src.get("filename_absolute") or src.get("filename_relative") or ""
                if any(m in p for m in ("/lib/", "forge-std", "solady/src",
                                        "solmate/src", "openzeppelin",
                                        "/node_modules/")):
                    vendored = True
                    break
            if not vendored:
                total += 1
    return total, severity


# ---------- modes ----------

def cmd_check(baselines_dir: Path, name_filter: str | None) -> int:
    baselines = load_baselines(baselines_dir)
    if not baselines:
        print(f"[regression-check] no baselines found in {baselines_dir}")
        print("[regression-check] hint: tools/regression-check.py --seed <detector>")
        return 0

    n_pass = 0
    n_fail = 0
    n_missing = 0
    failures: list[str] = []

    for path, data in baselines:
        errs = validate_baseline(data, path)
        if errs:
            n_missing += 1
            print(f"FAIL  {path.name}: schema invalid")
            for e in errs:
                print(f"        {e}")
            failures.append(path.name)
            continue

        det = data["detector_name"]
        if name_filter and det != name_filter:
            continue

        fixture = REPO / data["fixture_path"]
        if not fixture.exists():
            n_missing += 1
            print(f"FAIL  {det}: fixture not found at {data['fixture_path']}")
            failures.append(det)
            continue

        try:
            hits, sev = run_detector(det, fixture)
        except Exception as e:
            n_missing += 1
            print(f"FAIL  {det}: {e}")
            failures.append(det)
            continue

        ok = (hits == data["expected_hits"]
              and sev.upper() == data["expected_severity"].upper())
        if ok:
            n_pass += 1
            print(f"PASS  {det}: hits={hits} severity={sev}  "
                  f"(baseline_sha={data['baseline_sha'][:7]})")
        else:
            n_fail += 1
            print(f"FAIL  {det}:")
            print(f"        expected hits={data['expected_hits']} severity={data['expected_severity']}")
            print(f"        actual   hits={hits} severity={sev}")
            print(f"        fixture: {data['fixture_path']}")
            print(f"        baseline_sha: {data['baseline_sha']}  baseline_date: {data['baseline_date']}")
            failures.append(det)

    total = n_pass + n_fail + n_missing
    print()
    print(f"[regression-check] {n_pass}/{total} passed, "
          f"{n_fail} failed, {n_missing} missing/error")
    if n_fail:
        return 1
    if n_missing:
        return 2
    return 0


def cmd_seed(baselines_dir: Path, detector_name: str | None) -> int:
    """Seed baselines.

    Without `detector_name`: walk the tier registry, pick every detector that
    has a fixture pair AND no existing baseline, and seed.

    With `detector_name`: seed exactly that detector. The fixture is resolved
    via the tier registry's `fixture_pair` if present, otherwise expected at
    `detectors/test_fixtures/<detector_with_underscores>_vulnerable.sol`.
    """
    baselines_dir.mkdir(parents=True, exist_ok=True)
    sha = _git_head_sha()
    today = date.today().isoformat()

    # Tier registry → fixture lookup
    fixture_lookup: dict[str, str] = {}
    try:
        import yaml  # PyYAML is already in repo deps (used widely)
        reg = REPO / "detectors" / "_tier_registry.yaml"
        if reg.exists():
            data = yaml.safe_load(reg.read_text()) or {}
            for name, entry in (data.get("tiers") or {}).items():
                fp = (entry or {}).get("fixture_pair")
                if fp:
                    fixture_lookup[name] = fp
    except ImportError:
        pass

    targets: list[str]
    if detector_name:
        targets = [detector_name]
    else:
        targets = sorted(fixture_lookup.keys())

    seeded = 0
    skipped = 0
    errors = 0

    for det in targets:
        out_path = baselines_dir / f"{det}.json"
        if out_path.exists() and not detector_name:
            skipped += 1
            continue

        # Resolve fixture path
        fp_rel: str | None = None
        fp_hint = fixture_lookup.get(det)
        if fp_hint:
            # `wave1/role_grant_divergence` → detectors/test_fixtures/role_grant_divergence_vulnerable.sol
            stem = Path(fp_hint).name
            cand = REPO / "detectors" / "test_fixtures" / f"{stem}_vulnerable.sol"
            if cand.exists():
                fp_rel = str(cand.relative_to(REPO))
        if fp_rel is None:
            # Conventional fallback
            stem = det.replace("-", "_")
            cand = REPO / "detectors" / "test_fixtures" / f"{stem}_vulnerable.sol"
            if cand.exists():
                fp_rel = str(cand.relative_to(REPO))
        if fp_rel is None:
            print(f"SKIP  {det}: no vulnerable fixture found (looked at "
                  f"{stem}_vulnerable.sol)")
            errors += 1
            continue

        try:
            hits, sev = run_detector(det, REPO / fp_rel)
        except Exception as e:
            print(f"SKIP  {det}: {e}")
            errors += 1
            continue

        payload = {
            "detector_name":     det,
            "fixture_path":      fp_rel,
            "expected_hits":     hits,
            "expected_severity": sev,
            "baseline_date":     today,
            "baseline_sha":      sha,
        }
        # Stable formatting so diffs read cleanly
        out_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
        seeded += 1
        print(f"SEED  {det}: hits={hits} severity={sev}  -> {out_path.relative_to(REPO)}")

    print()
    print(f"[regression-check --seed] seeded={seeded} skipped_existing={skipped} errors={errors}")
    return 0 if errors == 0 else 2


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="regression-check",
        description="Ground-truth regression baselines for auditooor detectors.",
    )
    p.add_argument("--seed", nargs="?", const="__all__",
                   help="Seed baselines. With no value: seed every detector "
                        "that has a fixture pair and no existing baseline. "
                        "With a value: seed exactly that detector.")
    p.add_argument("--baselines-dir", default=str(DEFAULT_BASELINES_DIR),
                   help="Directory of baseline JSON files "
                        "(default: tools/baselines/).")
    p.add_argument("--filter", default=None,
                   help="Only check baselines whose detector_name matches.")
    args = p.parse_args(argv)

    baselines_dir = Path(args.baselines_dir).resolve()

    if args.seed is not None:
        det = None if args.seed == "__all__" else args.seed
        return cmd_seed(baselines_dir, det)
    return cmd_check(baselines_dir, args.filter)


if __name__ == "__main__":
    sys.exit(main())
