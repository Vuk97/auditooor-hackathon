#!/usr/bin/env python3
"""
build-detector-pack.py — Master Mandate § 7.4 / Pub-1

Deterministic, idempotent build of `packaging/auditooor_detectors/`.

Steps performed:
  4. Copy `.py` detector files for every Tier-S/A/B *verified* registry row
     under `auditooor_detectors/detectors/<wave>/<name>.py`.
  5. Copy `_predicate_engine.py` to the package `detectors/` root.
  6. Copy `_template_utils.py` to the package `detectors/` root.
  6b. Copy each rust wave's `_util.py` next to the rust detectors.
  7. Emit a slim `registry.json` of just the bundled detectors.

Run:
    python3 tools/build-detector-pack.py [--dry-run]

This script does NOT regenerate `pyproject.toml`, `README.md`, or `tests/` —
those are authored once and live in git. It only rebuilds the detector
payload, the helper modules, and the slim registry index.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import re
import shutil
import sys
from pathlib import Path

import yaml

# ---------------------------------------------------------------------------
REPO_ROOT = Path(__file__).resolve().parent.parent
DETECTORS_DIR = REPO_ROOT / "detectors"
REGISTRY_PATH = DETECTORS_DIR / "_tier_registry.yaml"

PKG_ROOT = REPO_ROOT / "packaging" / "auditooor_detectors"
PKG_PY = PKG_ROOT / "auditooor_detectors"
PKG_DETECTORS = PKG_PY / "detectors"
PYPROJECT_PATH = PKG_ROOT / "pyproject.toml"

# Default location of the strict-smoke verification report, produced by
# `tools/registry-disk-consistency-check.py --strict-smoke --json-out=...`.
STRICT_SMOKE_DEFAULT = Path("/private/tmp/auditooor-inventory/strict_smoke_verified.json")
# Default location of the rust inventory-smoke summary, produced by
# `tools/inventory-smoke-rust.py`.
RUST_SMOKE_DEFAULT = Path("/tmp/auditooor-rust-smoke/inventory_smoke_rust_summary.json")

PY_RE = re.compile(r"py=(detectors/[\w_/-]+\.py)")
SMOKE_PY_RE = re.compile(r"detectors/(wave[\w_]+)/([\w_]+\.py)")

# Reason fragment that marks a detector as a "no-yaml-synthesis fake":
# YAML compiled but no fixture was actually run, so vuln_hits is unverified.
NO_YAML_FAKE_MARKERS = ("no-yaml-synthesis", "vuln_hits=n/a")

ELIGIBLE_TIERS = ("S", "A", "B")
# ---------------------------------------------------------------------------


def load_registry() -> dict:
    with REGISTRY_PATH.open() as fh:
        return yaml.safe_load(fh)


def resolve_py_path(arg: str, row: dict) -> Path | None:
    """Return absolute on-disk path of the detector's .py file, or None."""
    reason = row.get("reason", "") or ""
    m = PY_RE.search(reason)
    if m:
        cand = REPO_ROOT / m.group(1)
        if cand.exists():
            return cand
    smoke = row.get("smoke_test_command", "") or ""
    m = SMOKE_PY_RE.search(smoke)
    if m:
        cand = DETECTORS_DIR / m.group(1) / m.group(2)
        if cand.exists():
            return cand
    fixture_pair = row.get("fixture_pair", "") or ""
    if fixture_pair:
        wave = fixture_pair.split("/", 1)[0]
        cand = DETECTORS_DIR / wave / (arg.replace("-", "_") + ".py")
        if cand.exists():
            return cand
    return None


def _is_no_yaml_synthesis_fake(reason: str) -> bool:
    return all(m in (reason or "") for m in NO_YAML_FAKE_MARKERS)


def load_strict_smoke_args(path: Path) -> set[str]:
    """Load the set of detector ARGUMENTs that passed strict-smoke (Solidity)."""
    if not path.exists():
        raise FileNotFoundError(
            f"strict-smoke report missing at {path}. "
            "Run: python3 tools/registry-disk-consistency-check.py "
            "--strict-smoke --json-out " + str(path)
        )
    data = json.loads(path.read_text())
    if not data.get("strict_smoke"):
        raise ValueError(f"{path} was not produced with --strict-smoke")
    return {row["argument"] for row in data.get("ok_rows", []) or []}


def load_rust_smoke_args(path: Path) -> set[str]:
    """Load the set of Rust detectors that passed inventory-smoke-rust."""
    if not path.exists():
        raise FileNotFoundError(f"rust-smoke report missing at {path}")
    data = json.loads(path.read_text())
    return {
        row["id"]
        for row in data.get("results", []) or []
        if row.get("status") == "smoke_pass"
    }


def select_bundled(
    registry: dict,
    *,
    strict_only: bool = False,
    strict_args: set[str] | None = None,
    rust_strict_args: set[str] | None = None,
) -> list[dict]:
    """Return one record per detector destined for the bundle.

    When ``strict_only`` is True, restrict to:
      - Solidity rows whose ARGUMENT is in ``strict_args`` (passed
        strict-smoke against on-disk fixtures), AND
      - Rust rows whose ARGUMENT is in ``rust_strict_args`` (passed
        inventory-smoke-rust), AND
      - row reason does NOT match the no-yaml-synthesis fake pattern.
    """
    tiers = registry.get("tiers", {})
    out: list[dict] = []
    skipped_no_yaml = 0
    skipped_not_strict = 0
    for arg, row in tiers.items():
        if row.get("tier") not in ELIGIBLE_TIERS:
            continue
        if row.get("verified") is not True:
            continue
        reason = row.get("reason", "") or ""
        if strict_only and _is_no_yaml_synthesis_fake(reason):
            skipped_no_yaml += 1
            continue
        engine = row.get("engine", "slither") or "slither"
        if strict_only:
            if engine == "rust":
                if rust_strict_args is None or arg not in rust_strict_args:
                    skipped_not_strict += 1
                    continue
            else:
                if strict_args is None or arg not in strict_args:
                    skipped_not_strict += 1
                    continue
        py = resolve_py_path(arg, row)
        if py is None:
            print(f"[skip] {arg}: cannot resolve py file", file=sys.stderr)
            continue
        rel = py.relative_to(DETECTORS_DIR)  # e.g. wave16/foo.py
        out.append(
            {
                "argument": arg,
                "tier": row["tier"],
                "py_file": str(rel).replace(os.sep, "/"),
                "wave": rel.parts[0],
                "engine": engine,
                "smoke_test_clean_hits": row.get("smoke_test_clean_hits"),
                "smoke_test_vuln_hits": row.get("smoke_test_vuln_hits"),
                "verified_at": str(row.get("verified_at", "")),
                "fixture_pair": row.get("fixture_pair"),
            }
        )
    out.sort(key=lambda r: (r["wave"], r["argument"]))
    if strict_only:
        print(
            f"[strict-only] dropped {skipped_no_yaml} no-yaml-synthesis fakes, "
            f"{skipped_not_strict} not-strict-confirmed",
            file=sys.stderr,
        )
    return out


def write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)


def copy_file(src: Path, dst: Path) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(src, dst)


def reset_detectors_dir() -> None:
    """Idempotent: blow away and recreate just the detector payload."""
    if PKG_DETECTORS.exists():
        shutil.rmtree(PKG_DETECTORS)
    PKG_DETECTORS.mkdir(parents=True)


def emit_init_files(waves: set[str]) -> None:
    """Place __init__.py at every package level so wheels include them."""
    init_header = '"""auditooor-detectors bundled detector payload."""\n'
    write_text(PKG_DETECTORS / "__init__.py", init_header)
    for wave in sorted(waves):
        write_text(PKG_DETECTORS / wave / "__init__.py", init_header)


def emit_helpers() -> None:
    """Copy _predicate_engine.py + _template_utils.py to detectors/ root."""
    copy_file(DETECTORS_DIR / "_predicate_engine.py", PKG_DETECTORS / "_predicate_engine.py")
    copy_file(DETECTORS_DIR / "_template_utils.py", PKG_DETECTORS / "_template_utils.py")
    # Rust detectors import sibling `_util.py`
    rust_util = DETECTORS_DIR / "rust_wave1" / "_util.py"
    if rust_util.exists():
        copy_file(rust_util, PKG_DETECTORS / "rust_wave1" / "_util.py")


def emit_registry_json(records: list[dict], *, strict_only: bool = False) -> None:
    payload = {
        "schema_version": 2 if strict_only else 1,
        "generated_at": _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"),
        "detector_count": len(records),
        "tiers_included": list(ELIGIBLE_TIERS),
        "trust_contract": (
            "strict-smoke (slither + run_custom.py --tier=ALL on disk fixtures; "
            "inventory-smoke-rust for Rust); no-yaml-synthesis fakes excluded"
            if strict_only
            else "Tier-S/A/B verified=true (registry only)"
        ),
        "detectors": records,
    }
    (PKG_PY / "registry.json").write_text(json.dumps(payload, indent=2, sort_keys=False) + "\n")


_VERSION_RE = re.compile(r'^version\s*=\s*"[^"]+"', re.MULTILINE)
_DUNDER_VERSION_RE = re.compile(r'^__version__\s*=\s*"[^"]+"', re.MULTILINE)


def bump_pyproject_version(new_version: str) -> str | None:
    """Rewrite pyproject.toml's version line. Returns previous version or None."""
    if not PYPROJECT_PATH.exists():
        return None
    text = PYPROJECT_PATH.read_text()
    m = _VERSION_RE.search(text)
    prev = m.group(0) if m else None
    new_line = f'version = "{new_version}"'
    if m:
        text = _VERSION_RE.sub(new_line, text, count=1)
    else:
        text += "\n" + new_line + "\n"
    PYPROJECT_PATH.write_text(text)

    # Keep the package-level __version__ in sync with pyproject.
    init_path = PKG_PY / "__init__.py"
    if init_path.exists():
        itext = init_path.read_text()
        new_dunder = f'__version__ = "{new_version}"'
        if _DUNDER_VERSION_RE.search(itext):
            itext = _DUNDER_VERSION_RE.sub(new_dunder, itext, count=1)
            init_path.write_text(itext)
    return prev


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument(
        "--strict-only",
        action="store_true",
        help=(
            "v2 trust contract: bundle ONLY detectors that pass strict-smoke "
            "(slither+run_custom.py against on-disk fixtures for Solidity, "
            "inventory-smoke-rust for Rust). Excludes no-yaml-synthesis fakes. "
            "Bumps version to 0.2.YYYYMMDD."
        ),
    )
    ap.add_argument(
        "--strict-smoke-report",
        type=Path,
        default=STRICT_SMOKE_DEFAULT,
        help=f"Path to strict-smoke JSON (default {STRICT_SMOKE_DEFAULT}).",
    )
    ap.add_argument(
        "--rust-smoke-report",
        type=Path,
        default=RUST_SMOKE_DEFAULT,
        help=f"Path to inventory-smoke-rust JSON (default {RUST_SMOKE_DEFAULT}).",
    )
    args = ap.parse_args()

    if not REGISTRY_PATH.exists():
        print(f"FATAL: registry missing at {REGISTRY_PATH}", file=sys.stderr)
        return 2

    strict_args: set[str] | None = None
    rust_strict_args: set[str] | None = None
    if args.strict_only:
        strict_args = load_strict_smoke_args(args.strict_smoke_report)
        rust_strict_args = load_rust_smoke_args(args.rust_smoke_report)
        print(
            f"[strict-only] sol-strict-confirmed={len(strict_args)}, "
            f"rust-strict-confirmed={len(rust_strict_args)}"
        )

    registry = load_registry()
    records = select_bundled(
        registry,
        strict_only=args.strict_only,
        strict_args=strict_args,
        rust_strict_args=rust_strict_args,
    )
    waves = {r["wave"] for r in records}

    label = "strict-smoke-confirmed" if args.strict_only else "verified"
    print(
        f"selected {len(records)} {label} Tier-{'/'.join(ELIGIBLE_TIERS)} detectors"
    )
    print(f"wave folders: {sorted(waves)}")

    if args.dry_run:
        for r in records[:10]:
            print("  ", r["wave"], r["argument"], r["tier"])
        print(f"(showing first 10 / {len(records)})")
        return 0

    PKG_PY.mkdir(parents=True, exist_ok=True)
    reset_detectors_dir()
    emit_init_files(waves)

    copied = 0
    for r in records:
        src = DETECTORS_DIR / r["py_file"]
        dst = PKG_DETECTORS / r["py_file"]
        copy_file(src, dst)
        copied += 1

    emit_helpers()
    emit_registry_json(records, strict_only=args.strict_only)

    if args.strict_only:
        today = _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%d")
        new_version = f"0.2.{today}"
        prev = bump_pyproject_version(new_version)
        print(f"pyproject.toml version: {prev} -> version = \"{new_version}\"")

    print(f"copied {copied} detector .py files")
    print(f"helpers: _predicate_engine.py, _template_utils.py, rust_wave1/_util.py")
    print(f"registry.json: {len(records)} detectors")
    print(f"output root: {PKG_ROOT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
