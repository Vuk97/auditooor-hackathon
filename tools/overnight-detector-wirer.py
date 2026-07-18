#!/usr/bin/env python3
"""overnight-detector-wirer.py — turn LLM JSON outputs into actually-wired Slither detectors.

Input: a directory of LLM-emitted JSON files, one per detector. Each JSON carries
the full source of:
  - the Slither AbstractDetector .py file
  - the clean fixture .sol
  - the vulnerable fixture .sol
  - the slither --detect ARGUMENT string

For each input JSON, this script:
  1. Writes detector .py to detectors/wave_overnight/<id>.py
  2. Writes clean fixture to detectors/test_fixtures/<id>_clean.sol
  3. Writes vulnerable fixture to detectors/test_fixtures/<id>_vulnerable.sol
  4. Compiles + runs slither --detect <ARGUMENT> on each fixture
  5. Verifies clean=0 hits, vulnerable>=1 hit
  6. On pass: adds an entry to detectors/_tier_registry.yaml as Tier-B (verified)
  7. On fail: writes the reason to wirer_failures.jsonl + leaves the .py
     in detectors/wave_overnight_quarantine/ so it doesn't break CI

Usage:
  python3 tools/overnight-detector-wirer.py \
    --inputs-dir /private/tmp/auditooor-overnight/wire_outputs \
    --summary-out /private/tmp/auditooor-overnight/wire_summary.json
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
DET_DIR = REPO / "detectors" / "wave_overnight"
QUARANTINE_DIR = REPO / "detectors" / "wave_overnight_quarantine"
FIX_DIR = REPO / "detectors" / "test_fixtures"
TIER_REGISTRY = REPO / "detectors" / "_tier_registry.yaml"
RUN_CUSTOM = REPO / "detectors" / "run_custom.py"
# Slither lives in Homebrew's python3.13, not the .venv. Use that interpreter
# so `import slither` works inside run_custom.py.
SLITHER_PYTHON = "/opt/homebrew/opt/python@3.13/bin/python3.13"

_FENCE_RE = re.compile(r"^\s*```(?:json|JSON|python|py|solidity|sol)?\s*\n(.*?)\n\s*```\s*$", re.DOTALL)


def _load_json_strip_fences(path: Path):
    raw = path.read_text(encoding="utf-8").strip()
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        pass
    m = _FENCE_RE.match(raw)
    if m:
        try:
            return json.loads(m.group(1))
        except json.JSONDecodeError:
            pass
    for opener, closer in [("{", "}"), ("[", "]")]:
        i = raw.find(opener)
        j = raw.rfind(closer)
        if i >= 0 and j > i:
            try:
                return json.loads(raw[i : j + 1])
            except json.JSONDecodeError:
                continue
    raise json.JSONDecodeError(f"could not parse {path}", raw, 0)


def _strip_code_fence(s: str) -> str:
    """Strip a leading ```python or ```sol fence from a code string if present."""
    if not s:
        return s
    m = _FENCE_RE.match(s.strip())
    if m:
        return m.group(1)
    return s


# Tolerate content immediately after the BEGIN tag (no newline required).
_DELIM_RE = re.compile(
    r"===BEGIN_DETECTOR_PY===\s*(.*?)\s*===END_DETECTOR_PY==="
    r".*?===BEGIN_CLEAN_SOL===\s*(.*?)\s*===END_CLEAN_SOL==="
    r".*?===BEGIN_VULNERABLE_SOL===\s*(.*?)\s*===END_VULNERABLE_SOL==="
    r".*?===BEGIN_METADATA===\s*(.*?)\s*===END_METADATA===",
    re.DOTALL,
)


def _parse_delimited(raw: str) -> dict | None:
    """Parse the strict delimiter-based output. Returns dict on success, None on
    fail. Strips an outer JSON wrapper or fence if present (defensive)."""
    s = raw.strip()
    # Some LLMs may still wrap in ```...``` — strip a single outer fence.
    m = _FENCE_RE.match(s)
    if m:
        s = m.group(1)
    m = _DELIM_RE.search(s)
    if not m:
        return None
    py, clean, vuln, meta_block = m.groups()
    meta = {}
    for line in meta_block.splitlines():
        if ":" in line:
            k, _, v = line.partition(":")
            meta[k.strip()] = v.strip()
    return {
        "detector_id": meta.get("detector_id", ""),
        "slither_argument": meta.get("slither_argument", ""),
        "detector_py": py,
        "fixture_pair_clean_sol": clean,
        "fixture_pair_vulnerable_sol": vuln,
        "expected_clean_hits": int(meta.get("expected_clean_hits", 0) or 0),
        "expected_vulnerable_hits_min": int(meta.get("expected_vulnerable_hits_min", 1) or 1),
    }


def _unescape_if_double_escaped(s: str) -> str:
    """If the string was double-escaped by the LLM (JSON-emitted with literal
    ``\\n`` sequences instead of real newlines), convert ``\\n`` -> newline,
    ``\\t`` -> tab, ``\\"`` -> ", ``\\\\`` -> \\.

    Heuristic: if the string is >200 chars AND has fewer than 3 actual
    newlines AND has at least 20 literal ``\\n`` sequences, unescape.
    """
    if not s or len(s) < 200:
        return s
    real_newlines = s.count("\n")
    literal_backslash_n = s.count("\\n")
    if real_newlines < 3 and literal_backslash_n >= 20:
        # Use a sequential unescape so we don't double-process \\\\.
        out = []
        i = 0
        while i < len(s):
            if s[i] == "\\" and i + 1 < len(s):
                nxt = s[i + 1]
                if nxt == "n":
                    out.append("\n"); i += 2; continue
                if nxt == "t":
                    out.append("\t"); i += 2; continue
                if nxt == "r":
                    out.append("\r"); i += 2; continue
                if nxt == '"':
                    out.append('"'); i += 2; continue
                if nxt == "'":
                    out.append("'"); i += 2; continue
                if nxt == "\\":
                    out.append("\\"); i += 2; continue
            out.append(s[i]); i += 1
        return "".join(out)
    return s


def _slug(s: str) -> str:
    return re.sub(r"[^a-zA-Z0-9]+", "_", s).strip("_").lower()


_HIT_LINE_RE = re.compile(r"^\s*-\s*\[")  # run_custom prints hits as "  - [<file>:..."


def _slither_smoke(detector_argument: str, fixture_path: Path, detector_id: str, timeout_sec: int = 90):
    """Run `run_custom.py --tier=ALL <fixture> <ARGUMENT>` (canonical runner that
    loads .py via Slither's Python API). Return (rc, summary, hit_count).

    name_filter inside run_custom matches obj.ARGUMENT (kebab-case slither name),
    not the file/detector_id. Pass argument here.
    """
    cmd = [SLITHER_PYTHON, str(RUN_CUSTOM), "--tier=ALL", str(fixture_path), detector_argument]
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout_sec, cwd=REPO,
            env={**__import__("os").environ, "AUDITOOOR_INCLUDE_OVERNIGHT": "1"},
        )
    except subprocess.TimeoutExpired:
        return ("timeout", "", -1)
    out = proc.stdout or ""
    err = proc.stderr or ""
    hits = 0
    # run_custom emits: "[done] total hits: <N>"
    m = re.search(r"\[done\]\s+total hits:\s+(\d+)", out + "\n" + err)
    if m:
        hits = int(m.group(1))
    tail = (out.splitlines() + err.splitlines())[-3:] if (out or err) else []
    return (proc.returncode, " | ".join(tail), hits)


def wire_one(input_path: Path, dry_run: bool = False) -> dict:
    """Process one LLM output JSON. Returns a result dict."""
    result = {
        "input": str(input_path),
        "ok": False,
        "reason": "",
        "detector_id": None,
        "argument": None,
        "smoke": {},
    }
    raw = input_path.read_text(encoding="utf-8")
    blob = _parse_delimited(raw)
    if blob is None:
        # Legacy JSON fallback for any leftover outputs.
        try:
            blob = _load_json_strip_fences(input_path)
        except json.JSONDecodeError as e:
            result["reason"] = f"parse_failed (no delimiters, no valid JSON): {e}"
            return result

    det_id = blob.get("detector_id")
    if not det_id:
        result["reason"] = "missing detector_id"
        return result
    det_id = _slug(det_id)
    result["detector_id"] = det_id

    detector_py = _unescape_if_double_escaped(_strip_code_fence(blob.get("detector_py", "")))
    clean_sol = _unescape_if_double_escaped(_strip_code_fence(blob.get("fixture_pair_clean_sol", "")))
    vuln_sol = _unescape_if_double_escaped(_strip_code_fence(blob.get("fixture_pair_vulnerable_sol", "")))
    argument = blob.get("slither_argument") or det_id.replace("_", "-")
    result["argument"] = argument

    if not (detector_py and clean_sol and vuln_sol):
        missing = []
        for k, v in [("detector_py", detector_py), ("clean", clean_sol), ("vuln", vuln_sol)]:
            if not v:
                missing.append(k)
        result["reason"] = f"missing fields: {missing}"
        return result

    # Sanity-check the .py has the right shape.
    if "AbstractDetector" not in detector_py or f'ARGUMENT = "{argument}"' not in detector_py:
        # Try to be lenient about quoting
        if "AbstractDetector" not in detector_py:
            result["reason"] = "detector_py missing AbstractDetector base"
            return result
        if argument not in detector_py:
            result["reason"] = f"detector_py argument mismatch (expected {argument})"
            return result

    if dry_run:
        result["ok"] = True
        result["reason"] = "dry_run"
        return result

    # Write fixtures + detector to disk.
    DET_DIR.mkdir(parents=True, exist_ok=True)
    QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
    FIX_DIR.mkdir(parents=True, exist_ok=True)

    det_path = DET_DIR / f"{det_id}.py"
    clean_path = FIX_DIR / f"{det_id}_clean.sol"
    vuln_path = FIX_DIR / f"{det_id}_vulnerable.sol"
    det_path.write_text(detector_py, encoding="utf-8")
    clean_path.write_text(clean_sol, encoding="utf-8")
    vuln_path.write_text(vuln_sol, encoding="utf-8")

    # Smoke test (run_custom expects the detector_id, not the argument).
    rc_c, sum_c, hits_c = _slither_smoke(argument, clean_path, det_id)
    rc_v, sum_v, hits_v = _slither_smoke(argument, vuln_path, det_id)
    result["smoke"] = {
        "clean_rc": rc_c, "clean_hits": hits_c, "clean_summary": sum_c,
        "vuln_rc": rc_v, "vuln_hits": hits_v, "vuln_summary": sum_v,
    }

    if rc_c == "timeout" or rc_v == "timeout":
        result["reason"] = "slither_timeout"
        # Quarantine
        quarantine_path = QUARANTINE_DIR / det_path.name
        det_path.rename(quarantine_path)
        return result

    # Pass criteria: clean has 0 hits AND vulnerable has at least 1.
    if hits_c == 0 and hits_v >= 1:
        result["ok"] = True
        result["reason"] = "smoke_pass"
        return result

    # Fail: quarantine
    result["reason"] = (
        f"smoke_fail: clean_hits={hits_c} (want 0), vuln_hits={hits_v} (want >=1)"
    )
    quarantine_path = QUARANTINE_DIR / det_path.name
    det_path.rename(quarantine_path)
    return result


def update_registry(passing_results: list[dict]) -> int:
    if not TIER_REGISTRY.exists():
        return 0
    reg = yaml.safe_load(TIER_REGISTRY.read_text())
    tiers = reg.setdefault("tiers", {})
    today = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")
    added = 0
    for r in passing_results:
        did = r["detector_id"]
        if not did:
            continue
        prior = tiers.get(did, {})
        prior_tier = prior.get("tier", "")
        tiers[did] = {
            "tier": "B",
            "reason": f"wired-overnight {today}: slither smoke pass (clean=0, vuln={r['smoke']['vuln_hits']})",
            "waves": ["wave_overnight"],
            "first_added": prior.get("first_added", today),
            "last_promoted": today,
            "fixture_pair": f"test_fixtures/{did}",
            "engine": "slither",
            "argument": r["argument"],
            "verified": True,
        }
        added += 1
    tmp = TIER_REGISTRY.with_suffix(".yaml.tmp")
    tmp.write_text(yaml.safe_dump(reg, default_flow_style=False, sort_keys=False))
    tmp.replace(TIER_REGISTRY)
    return added


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--inputs-dir", required=True)
    ap.add_argument("--summary-out", required=True)
    ap.add_argument("--update-registry", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--limit", type=int, default=0,
                    help="If >0, process at most this many inputs.")
    args = ap.parse_args()

    inputs = sorted(p for p in Path(args.inputs_dir).glob("*.json")
                    if not p.name.endswith(".stderr"))
    if args.limit:
        inputs = inputs[: args.limit]

    results = []
    for i, inp in enumerate(inputs, 1):
        r = wire_one(inp, dry_run=args.dry_run)
        results.append(r)
        status = "PASS" if r["ok"] else "FAIL"
        print(f"[{i}/{len(inputs)}] {status} {r['detector_id'] or inp.stem}: {r['reason']}",
              file=sys.stderr, flush=True)

    passing = [r for r in results if r["ok"] and r["reason"] == "smoke_pass"]

    registry_added = 0
    if args.update_registry and not args.dry_run and passing:
        registry_added = update_registry(passing)

    summary = {
        "schema": "auditooor.overnight.wirer.v1",
        "ran_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "inputs_dir": args.inputs_dir,
        "input_count": len(inputs),
        "results": results,
        "passing_count": len(passing),
        "fail_count": len(results) - len(passing),
        "registry_added": registry_added,
    }
    Path(args.summary_out).write_text(json.dumps(summary, indent=2))
    print(f"PASS={len(passing)} FAIL={len(results)-len(passing)} REGISTRY_ADDED={registry_added}")


if __name__ == "__main__":
    main()
