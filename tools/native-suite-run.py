#!/usr/bin/env python3
"""native-suite-run.py - R21/R27 PRODUCER: capture the Go/Rust native test-suite
result into a machine-readable artifact so a FAILING core-surface native test can
be enforced (it currently greens `make audit-complete STRICT=1` - no gate reads
cargo/go test results).

THE gap (README_ENFORCEMENT_GAP_AUDIT.md R21/R27): a Go/Rust workspace whose core
native suite FAILS still passes audit-complete because the arms WARN-continue and
no result artifact exists for a gate to read. This tool is the missing producer;
`native-suite-result-check.py` is the (advisory-first) reader.

Two modes:
  --parse-transcript <file> --lang go|rust --out <json>
      Parse a previously-captured `go test ./... -json` (one JSON event per line)
      or `cargo test --message-format=json` transcript into the result artifact.
      Pure + toolchain-free -> unit-testable, and lets a slow suite be captured
      once (feedback_no_long_rescans) then re-parsed.
  --run <ws> [--out <json>]
      LIVE: detect the ws language, run the suite, write the artifact. Fail-open
      (writes an artifact with lang=none / status=skipped) when the toolchain or a
      go.mod/Cargo.toml is absent, so a non-Go/Rust ws is never false-red'd.

Artifact schema `auditooor.native_suite_result.v1`:
  {schema, lang, status, packages:{pkg:{passed,failed,skipped,failing_tests[]}},
   total_passed, total_failed, total_skipped, failing[]}
`failing` is the flat list of "pkg::Test" ids the reader keys on.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    from go_toolchain_env import apply_go_toolchain as _apply_go_toolchain
except Exception:  # pragma: no cover - helper must be a sibling in tools/
    def _apply_go_toolchain(env, cwd, **_kw):  # type: ignore
        return ""

SCHEMA = "auditooor.native_suite_result.v1"
_ARTIFACT_REL = os.path.join(".auditooor", "native_suite_result.json")


def _blank(lang: str, status: str, reason: str = "") -> dict:
    return {"schema": SCHEMA, "lang": lang, "status": status, "reason": reason,
            "packages": {}, "total_passed": 0, "total_failed": 0,
            "total_skipped": 0, "failing": []}


def parse_go_transcript(text: str) -> dict:
    """Parse `go test ./... -json` output (one test2json event per line)."""
    res = _blank("go", "parsed")
    pkgs = res["packages"]
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            ev = json.loads(line)
        except (ValueError, TypeError):
            continue
        if not isinstance(ev, dict):
            continue
        action = ev.get("Action")
        pkg = ev.get("Package") or "?"
        test = ev.get("Test")
        if not test:
            continue  # package-level summary event, not a test result
        if action not in ("pass", "fail", "skip"):
            continue
        p = pkgs.setdefault(pkg, {"passed": 0, "failed": 0, "skipped": 0, "failing_tests": []})
        if action == "pass":
            p["passed"] += 1
        elif action == "skip":
            p["skipped"] += 1
        else:
            p["failed"] += 1
            p["failing_tests"].append(test)
            res["failing"].append(f"{pkg}::{test}")
    _totalize(res)
    return res


def parse_cargo_transcript(text: str) -> dict:
    """Parse `cargo test --message-format=json` (libtest JSON events)."""
    res = _blank("rust", "parsed")
    pkgs = res["packages"]
    # libtest emits {"type":"test","event":"ok|failed|ignored","name":"..."} lines;
    # cargo may also wrap them - we scan every JSON line for a test event.
    pkg = "crate"
    p = pkgs.setdefault(pkg, {"passed": 0, "failed": 0, "skipped": 0, "failing_tests": []})
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            ev = json.loads(line)
        except (ValueError, TypeError):
            continue
        if not isinstance(ev, dict) or ev.get("type") != "test":
            continue
        event = ev.get("event")
        name = ev.get("name") or "?"
        if event == "ok":
            p["passed"] += 1
        elif event == "ignored":
            p["skipped"] += 1
        elif event == "failed":
            p["failed"] += 1
            p["failing_tests"].append(name)
            res["failing"].append(f"{pkg}::{name}")
    _totalize(res)
    return res


_GO_PLAIN_FAIL_RE = re.compile(r"^--- FAIL:\s+(\S+)")
_GO_PLAIN_PASS_RE = re.compile(r"^--- PASS:\s+(\S+)")
_GO_PLAIN_SKIP_RE = re.compile(r"^--- SKIP:\s+(\S+)")
_GO_PLAIN_PKG_FAIL_RE = re.compile(r"^FAIL\s+(\S+)")
_CARGO_PLAIN_LINE_RE = re.compile(r"^test\s+(\S+)\s+\.\.\.\s+(ok|FAILED|ignored)\b")


def parse_go_plaintext(text: str) -> dict:
    """Parse PLAIN `go test ./...` output (--- FAIL/PASS/SKIP + package FAIL lines).
    This is what the existing engine-runner logs contain (they do not pass -json)."""
    res = _blank("go", "parsed")
    pkgs = res["packages"]
    cur_pkg = "?"
    for line in text.splitlines():
        s = line.strip()
        mp = _GO_PLAIN_PKG_FAIL_RE.match(s)
        if mp and "/" in mp.group(1):
            cur_pkg = mp.group(1)
        p = pkgs.setdefault(cur_pkg, {"passed": 0, "failed": 0, "skipped": 0, "failing_tests": []})
        mf = _GO_PLAIN_FAIL_RE.match(s)
        if mf:
            p["failed"] += 1
            p["failing_tests"].append(mf.group(1))
            res["failing"].append(f"{cur_pkg}::{mf.group(1)}")
            continue
        if _GO_PLAIN_PASS_RE.match(s):
            p["passed"] += 1
            continue
        if _GO_PLAIN_SKIP_RE.match(s):
            p["skipped"] += 1
    _totalize(res)
    return res


def parse_cargo_plaintext(text: str) -> dict:
    """Parse PLAIN `cargo test` output (`test <name> ... ok|FAILED|ignored`)."""
    res = _blank("rust", "parsed")
    p = res["packages"].setdefault("crate", {"passed": 0, "failed": 0, "skipped": 0, "failing_tests": []})
    for line in text.splitlines():
        m = _CARGO_PLAIN_LINE_RE.match(line.strip())
        if not m:
            continue
        name, outcome = m.group(1), m.group(2)
        if outcome == "ok":
            p["passed"] += 1
        elif outcome == "ignored":
            p["skipped"] += 1
        else:
            p["failed"] += 1
            p["failing_tests"].append(name)
            res["failing"].append(f"crate::{name}")
    _totalize(res)
    return res


def _looks_like_json_transcript(text: str) -> bool:
    """True if the first non-empty line is a test2json / libtest JSON event."""
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            ev = json.loads(line)
        except (ValueError, TypeError):
            return False
        return isinstance(ev, dict) and (("Action" in ev) or (ev.get("type") == "test"))
    return False


def parse_transcript(text: str, lang: str) -> dict:
    """Auto-detect json-vs-plaintext and dispatch to the right parser."""
    if _looks_like_json_transcript(text):
        return parse_go_transcript(text) if lang == "go" else parse_cargo_transcript(text)
    return parse_go_plaintext(text) if lang == "go" else parse_cargo_plaintext(text)


def _totalize(res: dict) -> None:
    tp = tf = ts = 0
    for p in res["packages"].values():
        tp += p["passed"]
        tf += p["failed"]
        ts += p["skipped"]
    res["total_passed"], res["total_failed"], res["total_skipped"] = tp, tf, ts


def _detect_lang(ws: Path) -> str:
    if list(ws.rglob("go.mod")):
        return "go"
    if list(ws.rglob("Cargo.toml")):
        return "rust"
    return "none"


def run_live(ws: Path) -> dict:
    """Detect + run the native suite. Fail-open on absent toolchain / manifest."""
    ws = Path(ws)
    lang = _detect_lang(ws)
    if lang == "none":
        return _blank("none", "skipped", "no go.mod / Cargo.toml under workspace")
    tool = "go" if lang == "go" else "cargo"
    if shutil.which(tool) is None:
        return _blank(lang, "skipped", f"{tool} toolchain not on PATH")
    cmd = (["go", "test", "./...", "-json"] if lang == "go"
           else ["cargo", "test", "--message-format=json"])
    env = dict(os.environ)
    if lang == "go":
        # Honor the workspace's pinned Go toolchain so a dep that only compiles under it is
        # not a silent build_failed on the host default (GOTOOLCHAIN suspected class).
        _apply_go_toolchain(env, ws, log_prefix="native-suite-run")
    try:
        proc = subprocess.run(cmd, cwd=str(ws), env=env, capture_output=True, text=True,
                              timeout=3600)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return _blank(lang, "skipped", f"suite did not run: {type(exc).__name__}")
    res = parse_transcript(proc.stdout, lang)
    res["status"] = "ran"
    return res


def _write(res: dict, out: Path) -> None:
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(res, indent=2), encoding="utf-8")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--parse-transcript", help="captured go/cargo test json transcript")
    ap.add_argument("--lang", choices=["go", "rust"], help="language for --parse-transcript")
    ap.add_argument("--run", help="workspace root to run the live suite in")
    ap.add_argument("--out", help="artifact path (default <ws>/.auditooor/native_suite_result.json)")
    a = ap.parse_args(argv)

    if a.parse_transcript:
        if not a.lang:
            print("ERROR: --lang required with --parse-transcript", file=sys.stderr)
            return 2
        text = Path(a.parse_transcript).read_text(encoding="utf-8", errors="replace")
        res = parse_transcript(text, a.lang)  # auto-detects json vs plain-text
        out = Path(a.out) if a.out else Path("native_suite_result.json")
        _write(res, out)
        print(json.dumps({k: res[k] for k in ("lang", "status", "total_passed",
                                              "total_failed", "total_skipped")}))
        return 0

    if a.run:
        ws = Path(os.path.expanduser(a.run)).resolve()
        res = run_live(ws)
        out = Path(a.out) if a.out else ws / _ARTIFACT_REL
        _write(res, out)
        print(json.dumps({k: res[k] for k in ("lang", "status", "total_passed",
                                              "total_failed", "total_skipped")}))
        return 0

    ap.print_help(sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
