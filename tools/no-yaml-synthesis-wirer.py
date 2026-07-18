#!/usr/bin/env python3
"""no-yaml-synthesis-wirer.py — parse LLM YAML outputs, compile, smoke-test, register.

For each LLM response emitted by the no-yaml-synthesis queue, this script:
  1. Parses the delimiter-separated output (YAML / RATIONALE / METADATA sections)
  2. Writes YAML to reference/patterns.dsl/<argument>.yaml
  3. Compiles via tools/pattern-compile.py → detectors/wave17/<argument>.py
  4. Verifies the compiled .py ARGUMENT matches the source detector's ARGUMENT
  5. If on-disk fixtures exist, smoke-tests the new compiled detector
  6. If smoke passes AND old detector smoke also passes (or was silent),
     registers as Tier-B verified in detectors/_tier_registry.yaml

Input: a directory of LLM response text files (one .txt per queue entry).
Each file must carry the argument in its stem: <argument>.txt

Usage:
    python3 tools/no-yaml-synthesis-wirer.py \\
        --inputs-dir /tmp/no-yaml-synthesis-outputs \\
        --summary-out /tmp/no-yaml-synthesis-summary.json \\
        [--update-registry]   # actually write to _tier_registry.yaml
        [--dry-run]           # parse + compile but do not mutate disk state
"""
from __future__ import annotations

import argparse
import datetime
import json
import re
import subprocess
import sys
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[1]
DSL_DIR = REPO / "reference" / "patterns.dsl"
TIER_REGISTRY = REPO / "detectors" / "_tier_registry.yaml"
RUN_CUSTOM = REPO / "detectors" / "run_custom.py"
PATTERN_COMPILE = REPO / "tools" / "pattern-compile.py"
SLITHER_PYTHON = "/opt/homebrew/opt/python@3.13/bin/python3.13"

_FIXTURE_ROOTS = [
    REPO / "patterns" / "fixtures",
    REPO / "detectors" / "test_fixtures",
]

# Delimiter parser — matches the 3-section format from no-yaml-synthesis.py
_DELIM_RE = re.compile(
    r"===BEGIN_YAML===\s*(.*?)\s*===END_YAML==="
    r".*?===BEGIN_RATIONALE===\s*(.*?)\s*===END_RATIONALE==="
    r".*?===BEGIN_METADATA===\s*(.*?)\s*===END_METADATA===",
    re.DOTALL,
)


def _parse_output(raw: str) -> dict | None:
    """Return {yaml_text, rationale, argument, source_py} or None."""
    m = _DELIM_RE.search(raw)
    if not m:
        return None
    yaml_text, rationale, meta_block = m.groups()
    meta: dict[str, str] = {}
    for line in meta_block.splitlines():
        if ":" in line:
            k, _, v = line.partition(":")
            meta[k.strip()] = v.strip()
    return {
        "yaml_text": yaml_text.strip(),
        "rationale": rationale.strip(),
        "argument": meta.get("argument", ""),
        "source_py": meta.get("source_py", ""),
    }


def _find_fixtures(argument: str) -> dict[str, Path | None]:
    slug = argument.replace("-", "_")
    candidates = {
        "vuln": [f"{slug}_vuln.sol", f"{slug}_vulnerable.sol", f"{slug}_bad.sol"],
        "clean": [f"{slug}_clean.sol", f"{slug}_safe.sol"],
    }
    result: dict[str, Path | None] = {"vuln": None, "clean": None}
    for label, names in candidates.items():
        for root in _FIXTURE_ROOTS:
            for name in names:
                p = root / name
                if p.exists():
                    result[label] = p
                    break
            if result[label]:
                break
    return result


def _slither_smoke(argument: str, fixture_path: Path, timeout: int = 90) -> tuple[str, int]:
    """Run run_custom.py on fixture; return (status, hit_count)."""
    cmd = [SLITHER_PYTHON, str(RUN_CUSTOM), "--tier=ALL", str(fixture_path), argument]
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, cwd=REPO,
            env={**__import__("os").environ, "AUDITOOOR_INCLUDE_OVERNIGHT": "1"},
        )
    except subprocess.TimeoutExpired:
        return ("timeout", -1)
    out = (proc.stdout or "") + "\n" + (proc.stderr or "")
    m = re.search(r"\[done\]\s+total hits:\s+(\d+)", out)
    hits = int(m.group(1)) if m else 0
    return ("ok", hits)


def _extract_argument_from_py(py_path: Path) -> str | None:
    """Grep ARGUMENT = '...' from the compiled .py."""
    if not py_path.exists():
        return None
    m = re.search(r'ARGUMENT\s*=\s*["\']([^"\']+)["\']', py_path.read_text())
    return m.group(1) if m else None


def wire_one(input_path: Path, dry_run: bool = False) -> dict:
    result: dict = {
        "input": str(input_path),
        "ok": False,
        "reason": "",
        "argument": None,
        "yaml_path": None,
        "compiled_py": None,
        "smoke": {},
    }

    raw = input_path.read_text(errors="replace")
    parsed = _parse_output(raw)
    if not parsed:
        result["reason"] = "parse_fail: delimiters not found"
        return result

    argument = parsed["argument"]
    if not argument:
        result["reason"] = "parse_fail: missing argument in METADATA"
        return result

    result["argument"] = argument

    # 1. Validate YAML is parseable
    try:
        yaml.safe_load(parsed["yaml_text"])
    except yaml.YAMLError as exc:
        result["reason"] = f"yaml_invalid: {exc}"
        return result

    yaml_path = DSL_DIR / f"{argument}.yaml"
    compiled_py = REPO / "detectors" / "wave17" / f"{argument.replace('-', '_')}.py"
    result["yaml_path"] = str(yaml_path)
    result["compiled_py"] = str(compiled_py)

    if not dry_run:
        # 2. Write YAML
        yaml_path.write_text(parsed["yaml_text"] + "\n", encoding="utf-8")

        # 3. Compile
        # Trust-calibration audit 2026-05-04: prevent fake detectors with unknown predicate keys.
        compile_proc = subprocess.run(
            [sys.executable, str(PATTERN_COMPILE), "--strict-unsupported-keys", str(yaml_path)],
            capture_output=True, text=True, cwd=REPO,
        )
        if compile_proc.returncode != 0:
            result["reason"] = f"compile_fail: {compile_proc.stderr.strip()[-300:]}"
            return result

        # 4. Verify ARGUMENT in compiled .py
        compiled_arg = _extract_argument_from_py(compiled_py)
        if compiled_arg != argument:
            result["reason"] = (
                f"argument_mismatch: compiled={compiled_arg!r} expected={argument!r}"
            )
            return result

    # 5. Smoke-test with fixtures if they exist
    fixtures = _find_fixtures(argument)
    smoke: dict[str, object] = {}

    if not dry_run and (fixtures["vuln"] or fixtures["clean"]):
        src_py = REPO / parsed["source_py"] if parsed["source_py"] else None

        if fixtures["vuln"]:
            status, hits = _slither_smoke(argument, fixtures["vuln"])
            smoke["new_vuln_hits"] = hits
            smoke["new_vuln_status"] = status

            # Also smoke the OLD detector on the same fixture
            old_hits: int | None = None
            if src_py and src_py.exists():
                old_arg = _extract_argument_from_py(src_py) or argument
                old_status, old_hits = _slither_smoke(old_arg, fixtures["vuln"])
                smoke["old_vuln_hits"] = old_hits
                smoke["old_vuln_status"] = old_status

            if status != "ok":
                result["reason"] = f"smoke_timeout_vuln"
                result["smoke"] = smoke
                return result

        if fixtures["clean"]:
            status, hits = _slither_smoke(argument, fixtures["clean"])
            smoke["new_clean_hits"] = hits
            smoke["new_clean_status"] = status
            if hits > 0:
                result["reason"] = f"smoke_fp: clean fixture has {hits} hit(s)"
                result["smoke"] = smoke
                return result

    result["smoke"] = smoke

    # 6. Determine pass/fail
    vuln_hits = smoke.get("new_vuln_hits", None)
    old_vuln_hits = smoke.get("old_vuln_hits", None)
    has_fixture = fixtures["vuln"] is not None

    if has_fixture and not dry_run:
        if vuln_hits is None or vuln_hits < 1:
            result["reason"] = f"smoke_miss: new detector got {vuln_hits} hits on vuln fixture"
            return result
        # Old detector must pass or be absent/silent
        if old_vuln_hits is not None and old_vuln_hits < 1:
            result["reason"] = (
                f"smoke_regression: old detector got {old_vuln_hits} hits on same fixture"
            )
            return result

    result["ok"] = True
    result["reason"] = "smoke_pass" if has_fixture else "no_fixture_compile_ok"
    return result


def update_registry(passing: list[dict]) -> int:
    if not TIER_REGISTRY.exists():
        return 0
    reg = yaml.safe_load(TIER_REGISTRY.read_text()) or {}
    tiers = reg.setdefault("tiers", {})
    today = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")
    added = 0
    for r in passing:
        arg = r["argument"]
        if not arg:
            continue
        prior = tiers.get(arg, {})
        tiers[arg] = {
            "tier": "B",
            "reason": (
                f"no-yaml-synthesis {today}: YAML generated + compiled; "
                f"smoke={r['reason']}; vuln_hits={r['smoke'].get('new_vuln_hits', 'n/a')}"
            ),
            "waves": list(dict.fromkeys(prior.get("waves", []) + ["wave17"])),
            "first_added": prior.get("first_added", today),
            "last_promoted": today,
            "fixture_pair": arg,
            "engine": "slither",
            "argument": arg,
            "verified": True,
            "verified_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }
        added += 1
    tmp = TIER_REGISTRY.with_suffix(".yaml.tmp")
    tmp.write_text(yaml.safe_dump(reg, default_flow_style=False, sort_keys=False))
    tmp.replace(TIER_REGISTRY)
    return added


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--inputs-dir", required=True,
                    help="Directory of LLM response .txt files, named <argument>.txt")
    ap.add_argument("--summary-out", required=True)
    ap.add_argument("--update-registry", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--limit", type=int, default=0)
    args = ap.parse_args()

    inputs = sorted(Path(args.inputs_dir).glob("*.txt"))
    if args.limit:
        inputs = inputs[: args.limit]

    results = []
    for i, inp in enumerate(inputs, 1):
        r = wire_one(inp, dry_run=args.dry_run)
        results.append(r)
        status = "PASS" if r["ok"] else "FAIL"
        print(f"[{i}/{len(inputs)}] {status} {r['argument'] or inp.stem}: {r['reason']}",
              file=sys.stderr, flush=True)

    passing = [r for r in results if r["ok"]]
    registry_added = 0
    if args.update_registry and not args.dry_run and passing:
        registry_added = update_registry(passing)

    summary = {
        "schema": "auditooor.no-yaml-synthesis-wirer.v1",
        "ran_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "inputs_dir": args.inputs_dir,
        "input_count": len(inputs),
        "pass_count": len(passing),
        "fail_count": len(results) - len(passing),
        "registry_added": registry_added,
        "results": results,
    }
    Path(args.summary_out).write_text(json.dumps(summary, indent=2))
    print(f"PASS={len(passing)} FAIL={len(results) - len(passing)} REGISTRY_ADDED={registry_added}")


if __name__ == "__main__":
    main()
