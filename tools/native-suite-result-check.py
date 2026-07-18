#!/usr/bin/env python3
"""native-suite-result-check.py - R21/R27 READER (advisory-first): did the Go/Rust
native test suite PASS, or did a core-surface test fail while the audit greened?

THE gap (README_ENFORCEMENT_GAP_AUDIT.md R21/R27): a ws whose native `go test` /
`cargo test` core suite FAILS still passes audit-complete - the arms WARN-continue
and no gate parses the result. This reader consumes the artifact written by
`native-suite-run.py` (<ws>/.auditooor/native_suite_result.json) and classifies:

  pass  - no artifact (suite not captured / not applicable) OR status skipped
          (non-Go/Rust ws, toolchain absent) OR total_failed == 0.
  FLAG  - status ran/parsed AND total_failed >= 1: a native core test FAILED; a
          failing native suite over the CUT is R27 "failing native test = finding".

PRODUCER-CONDITIONAL + FAIL-OPEN: an absent/skipped artifact never FLAGs, so a
non-Go/Rust ws or a ws that has not captured its suite yet is NEVER false-red'd.
Advisory by default (rc 0). Under AUDITOOOR_NATIVE_SUITE_STRICT=1 a FLAG is rc 1.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

SCHEMA = "auditooor.native_suite_result_check.v1"
_ARTIFACT_REL = os.path.join(".auditooor", "native_suite_result.json")


def check(ws: Path) -> dict:
    ws = Path(ws)
    p = ws / _ARTIFACT_REL
    if not p.is_file():
        return {"schema": SCHEMA, "verdict": "pass",
                "reason": "no native_suite_result.json (suite not captured / not applicable)"}
    try:
        obj = json.loads(p.read_text(encoding="utf-8", errors="replace"))
    except (ValueError, OSError) as exc:
        # A malformed artifact is NOT a native-test failure -> fail-open advisory.
        return {"schema": SCHEMA, "verdict": "pass",
                "reason": f"native_suite_result.json unreadable ({type(exc).__name__}); fail-open"}
    if not isinstance(obj, dict):
        return {"schema": SCHEMA, "verdict": "pass", "reason": "artifact not an object; fail-open"}
    status = obj.get("status", "")
    lang = obj.get("lang", "none")
    if status == "skipped" or lang == "none":
        return {"schema": SCHEMA, "verdict": "pass", "lang": lang, "status": status,
                "reason": f"native suite skipped ({obj.get('reason','') or 'non-Go/Rust / toolchain absent'})"}
    try:
        total_failed = int(obj.get("total_failed") or 0)
    except (TypeError, ValueError):
        total_failed = 0
    failing = obj.get("failing") or []
    payload = {"schema": SCHEMA, "lang": lang, "status": status,
               "total_passed": obj.get("total_passed"), "total_failed": total_failed,
               "failing": failing[:50]}
    if total_failed >= 1:
        payload["verdict"] = "FLAG"
        payload["reason"] = (f"native {lang} suite has {total_failed} FAILING test(s) over the CUT "
                             f"({', '.join(failing[:5])}{' ...' if len(failing) > 5 else ''}); "
                             "a failing core-surface native test is R27 'failing native test = finding' "
                             "- resolve the failure or file it, do not green the audit over it.")
        return payload
    payload["verdict"] = "pass"
    payload["reason"] = f"native {lang} suite clean ({obj.get('total_passed')} passed, 0 failed)"
    return payload


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("workspace")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    rep = check(Path(a.workspace).expanduser())
    if a.json:
        print(json.dumps(rep, indent=2))
    else:
        print(f"[native-suite-result-check] {rep['verdict']}: {rep.get('reason','')}")
    strict = os.environ.get("AUDITOOOR_NATIVE_SUITE_STRICT", "").strip().lower() in ("1", "true", "yes", "on")
    if rep["verdict"] == "FLAG" and strict:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
