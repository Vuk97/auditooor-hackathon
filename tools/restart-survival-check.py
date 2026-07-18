#!/usr/bin/env python3
"""Rule 22 restart-survival preflight.

Persistence, permanent-freeze, halt, hardfork, and persistent-divergence
claims must show restart-survival evidence or honestly disclose that restart
heals the condition.

Restart-survival evidence is detected language-agnostically: a Go/cosmos-IAVL
close+reopen, a Rust sled/RocksDB/ParityDB drop-or-flush+reopen, or an
EVM/Foundry fork re-creation / fresh setUp after a persisted-state cheat all
count. Restart-named test functions are matched for Go, Python, Rust, and
Foundry/Solidity.

Env override:
  AUDITOOOR_R22_CLOSE_REOPEN_PATTERNS - newline-separated regexes appended to
  the default close-reopen detector (mirrors the _compile env hook in
  tools/in-process-vs-node-level-check.py). Each appended regex is matched
  standalone.

Exit codes:
  0 - pass, out-of-scope, honest disclosure, or accepted rebuttal
  1 - Rule 22 violation
  2 - input error
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lib.rebuttal_util import apply_rebuttal_gate  # noqa: E402


SCHEMA_VERSION = "auditooor.restart_survival_check.v1"
GATE = "R22-RESTART-SURVIVAL-REQUIRED"

TRIGGER_RE = re.compile(
    r"permanent freezing|permanent loss|chain halt|block production halt|"
    r"\bhalt\b|requires hardfork|hardfork|requires governance intervention|"
    r"persistent AppHash divergence|persistent durability divergence|"
    r"unrecoverable without|denial of service that recovery requires|"
    r"restart-survival|required restart survival",
    re.IGNORECASE,
)

NEGATIVE_SCOPE_RE = re.compile(
    r"\b(?:not[_ -]?proven(?:_\w+)?|not claimed|does not claim|no claim|"
    r"not in scope|not part of this report|not alleged|not demonstrated)\b",
    re.IGNORECASE,
)

HONEST_DISCLOSURE_RE = re.compile(
    r"restart clears the staleness|restart heals|restart resolves the bug|"
    r"failure does not persist (?:post-restart|across restart)|"
    r"no persistent durability divergence|process restart clears|"
    r"bug does not cause persistent|on-disk state is (?:correct|canonical)|"
    r"a process restart clears",
    re.IGNORECASE,
)

TEST_NAME_RE = re.compile(
    # Go: TestFoo_Restart...
    r"\b(?:Test\w*(?:Restart|AfterRestart|PostRestart|RestartSurvival|RestartRepro|"
    r"RestartHeals|NoShim_Restart|Reopen|Recovery)\w*|"
    # Python: def test_..._restart
    r"def\s+test_\w*(?:restart|after_restart|post_restart|restart_survival|"
    r"restart_repro|restart_heals|reopen|recovery)\w*|"
    # Rust: fn ..._restart / fn ..._reopen / fn ..._after_restart / fn ..._recovery
    r"fn\s+\w*(?:restart|reopen|after_restart|recovery)\w*|"
    # Foundry/Solidity: function testRestart... / testReopen... / testRecovery...
    r"function\s+test\w*(?:Restart|Reopen|Recovery)\w*)\b",
    re.IGNORECASE,
)

# Language-agnostic close/reopen detection: any "close / drop / stop / shutdown"
# idiom within CLOSE_REOPEN_WINDOW characters of an "open / reopen / restart /
# reload / re-create" idiom counts as restart-survival evidence.
CLOSE_REOPEN_WINDOW = 600

# Idioms that tear down / persist-then-release a store or node.
_CLOSE_DEFAULTS = [
    # Go / cosmos
    r"(?:db|app|store)\.Close\(\)",
    # Rust: explicit drop of the handle, or an explicit flush before reopen
    r"drop\(\s*\w*(?:db|store|tree|node)\w*\s*\)",
    r"\b\w*(?:db|store)\w*\.flush\(\)",
    r"\bstd::mem::drop\(",
    # EVM / Foundry: persisted-state cheats that precede a fresh fork/setUp
    r"vm\.snapshot\(\)",
    r"vm\.makePersistent\(",
    r"makePersistent\(",
    # generic lifecycle
    r"\.(?:close|stop|shutdown|teardown|kill|terminate)\(\)",
]

# Idioms that bring a store or node back up after teardown.
_REOPEN_DEFAULTS = [
    # Go / cosmos-IAVL
    r"NewMutableTree",
    r"NewIavl\w*",
    r"rootmulti\.NewStore",
    r"OpenDB\(",
    r"NewApp\(",
    # Rust persistent stores
    r"sled::open\(",
    r"Db::open\(",
    r"rocksdb::DB::open\w*\(",
    r"DB::open\w*\(",
    r"paritydb::Db::open\(",
    r"ParityDb::open\(",
    # EVM / Foundry fork re-creation and fresh setup
    r"vm\.createSelectFork\(",
    r"vm\.createFork\(",
    r"vm\.selectFork\(",
    r"vm\.revertTo\(",
    r"\bsetUp\(\)",
    # generic lifecycle
    r"\b(?:re-?open|re-?load|re-?create|re-?start|restart)\b",
]


def _close_reopen_re(env_name: str | None = None) -> re.Pattern[str]:
    """Build the language-agnostic close-then-reopen detector.

    Mirrors the ``_compile`` env-extension pattern in
    ``tools/in-process-vs-node-level-check.py``: regexes from
    ``env_name`` (newline-separated) are appended to the defaults.
    Each appended pattern is treated as a standalone close-reopen
    proof (matched on its own, not windowed) so callers can supply
    full bespoke idioms.
    """
    close_alt = "|".join(f"(?:{p})" for p in _CLOSE_DEFAULTS)
    reopen_alt = "|".join(f"(?:{p})" for p in _REOPEN_DEFAULTS)
    windowed = (
        rf"(?:{close_alt})[\s\S]{{0,{CLOSE_REOPEN_WINDOW}}}(?:{reopen_alt})"
    )
    # Phased-scaffold idiom (PHASE 1 seed -> PHASE 2 restart) kept verbatim.
    phased = r"PHASE\s*1[\s\S]{0,1500}PHASE\s*2[\s\S]{0,800}(?:restart|reopen|reload)"
    alternatives = [windowed, phased]
    if env_name and os.environ.get(env_name):
        alternatives.extend(
            line.strip()
            for line in os.environ[env_name].splitlines()
            if line.strip()
        )
    return re.compile(
        "|".join(f"(?:{alt})" for alt in alternatives),
        re.IGNORECASE,
    )


CLOSE_REOPEN_RE = _close_reopen_re("AUDITOOOR_R22_CLOSE_REOPEN_PATTERNS")

REBUTTAL_RE = re.compile(r"<!--\s*r22-rebuttal:\s*(.*?)\s*-->", re.IGNORECASE | re.DOTALL)

CODE_SUFFIXES = {".go", ".rs", ".sol", ".ts", ".tsx", ".js", ".mjs", ".py", ".move", ".cairo", ".vy", ".log", ".txt"}


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _workspace_root(draft: Path) -> Path:
    cur = draft.resolve().parent
    for parent in [cur, *cur.parents]:
        if (parent / "poc-tests").is_dir() or (parent / "submissions").is_dir():
            return parent
    return draft.resolve().parent


def _clean_ref(raw: str) -> str:
    return raw.strip().strip("`'\"").rstrip(").,;:")


def _resolve_poc_paths(draft: Path, text: str, explicit: list[str]) -> list[Path]:
    root = _workspace_root(draft)
    refs = list(explicit)
    refs.extend(match.group(1) for match in re.finditer(r"<!--\s*poc-dir:\s*([^>]+?)\s*-->", text, re.IGNORECASE))
    refs.extend(
        match.group(1)
        for match in re.finditer(r"(?im)^\s*(?:poc[_ -]?dir|poc[_ -]?path|PoC directory|PoC)\s*:\s*(.+?)\s*$", text)
    )
    refs.extend(match.group(0) for match in re.finditer(r"\bpoc-tests/[A-Za-z0-9_.\-/]+", text))

    resolved: list[Path] = []
    for raw in refs:
        ref = _clean_ref(raw)
        if not ref or "<" in ref or ">" in ref:
            continue
        path = Path(ref).expanduser()
        candidates = [path] if path.is_absolute() else [root / path, draft.parent / path, Path.cwd() / path]
        for candidate in candidates:
            if candidate.exists() and candidate not in resolved:
                resolved.append(candidate)
                break
    return resolved


def _source_files(paths: list[Path]) -> list[Path]:
    files: list[Path] = []
    for path in paths:
        if path.is_file() and path.suffix in CODE_SUFFIXES:
            files.append(path)
        elif path.is_dir():
            files.extend(sorted(p for p in path.rglob("*") if p.is_file() and p.suffix in CODE_SUFFIXES))
    return files


def _combined_text(draft: Path, draft_text: str, poc_paths: list[Path]) -> tuple[str, list[str]]:
    chunks = [draft_text]
    scanned: list[str] = []
    for path in _source_files(poc_paths):
        try:
            chunks.append(_read_text(path))
            scanned.append(str(path))
        except Exception:
            continue
    return "\n".join(chunks), scanned


def _line_hits(text: str, pattern: re.Pattern[str], limit: int = 12) -> list[dict[str, Any]]:
    hits: list[dict[str, Any]] = []
    for idx, line in enumerate(text.splitlines(), start=1):
        if pattern.search(line):
            hits.append({"line": idx, "text": line.strip()[:240]})
            if len(hits) >= limit:
                break
    return hits


def _rebuttal(text: str) -> str | None:
    match = REBUTTAL_RE.search(text)
    if not match:
        return None
    return " ".join(match.group(1).split())


_BELOW_THRESHOLD_SEVERITIES = {"low", "info", "informational"}


def run(
    draft: Path,
    *,
    poc_dir: list[str] | None = None,
    strict: bool = False,
    severity: str | None = None,
) -> tuple[int, dict[str, Any]]:
    try:
        text = _read_text(draft)
    except Exception as exc:
        return 2, {
            "schema_version": SCHEMA_VERSION,
            "gate": GATE,
            "file": str(draft),
            "verdict": "error",
            "error": f"cannot read draft: {exc}",
        }

    # Severity gate: LOW/INFO drafts are out-of-scope for R22.
    _sev_key = (severity or "").strip().lower()
    if not _sev_key:
        # Try to infer severity from the draft text (same regex as R21).
        _sev_match = re.search(
            r"(?im)^\s*(?:severity|impact|risk)\s*:\s*(critical|high|medium|low|informational|info)\b",
            text,
        )
        if _sev_match:
            _sev_key = _sev_match.group(1).lower()
    if _sev_key in _BELOW_THRESHOLD_SEVERITIES and not strict:
        return 0, {
            "schema_version": SCHEMA_VERSION,
            "gate": GATE,
            "file": str(draft),
            "strict": strict,
            "severity": _sev_key,
            "verdict": "pass-out-of-scope",
            "reason": f"severity {_sev_key!r} is below HIGH/CRITICAL threshold; R22 not required",
            "evidence": {},
        }

    payload: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "gate": GATE,
        "file": str(draft),
        "strict": strict,
        "evidence": {},
        "remediation_options": [
            "Add restart-survival evidence for persistence/halt/permanent-impact claims.",
            "Add a restart/reopen test or close-and-reopen harness transcript.",
            "Honestly disclose that restart heals the condition and walk severity to a non-persistent tier.",
            "Use <!-- r22-rebuttal: reason --> only for a bounded, source-backed exception.",
        ],
    }

    trigger_hits = [
        hit
        for hit in _line_hits(text, TRIGGER_RE)
        if not NEGATIVE_SCOPE_RE.search(hit.get("text") or "")
    ]
    if not trigger_hits:
        payload["verdict"] = "pass-out-of-scope"
        payload["reason"] = "no persistence/halt/permanent-impact trigger"
        return 0, payload

    rebuttal = _rebuttal(text)
    if apply_rebuttal_gate(payload, rebuttal):
        return 0, payload

    poc_paths = _resolve_poc_paths(draft, text, poc_dir or [])
    combined, scanned = _combined_text(draft, text, poc_paths)
    honest_hits = _line_hits(text, HONEST_DISCLOSURE_RE)
    test_hits = _line_hits(combined, TEST_NAME_RE)
    # Recompile per-call so AUDITOOOR_R22_CLOSE_REOPEN_PATTERNS set after
    # import (e.g. in tests) is honored.
    close_reopen = _close_reopen_re("AUDITOOOR_R22_CLOSE_REOPEN_PATTERNS").search(combined)
    close_reopen_hits = []
    if close_reopen:
        close_reopen_hits.append({"line": None, "text": close_reopen.group(0)[:240]})

    payload["poc_paths"] = [str(path) for path in poc_paths]
    payload["evidence"] = {
        "trigger_hits": trigger_hits,
        "honest_disclosure_hits": honest_hits,
        "restart_test_hits": test_hits,
        "close_reopen_hits": close_reopen_hits,
        "scanned_files": scanned,
    }

    if test_hits or close_reopen_hits:
        payload["verdict"] = "pass-restart-survival"
        payload["reason"] = "restart-survival evidence found"
        return 0, payload
    if honest_hits:
        if strict:
            payload["verdict"] = "fail-strict-contradiction"
            payload["reason"] = "persistence claim trigger present with restart-heals disclosure under strict mode"
            return 1, payload
        payload["verdict"] = "pass-honest-disclosure"
        payload["reason"] = "draft discloses restart heals the condition"
        return 0, payload

    payload["verdict"] = "fail-missing-restart-survival"
    payload["reason"] = "persistence/halt/permanent-impact claim lacks restart-survival evidence"
    return 1, payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("draft", type=Path)
    parser.add_argument("--poc-dir", action="append", default=[])
    parser.add_argument("--strict", action="store_true")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--severity", default=None, help="override severity (e.g. Low, High, Critical)")
    args = parser.parse_args(argv)

    rc, payload = run(args.draft, poc_dir=args.poc_dir, strict=args.strict, severity=args.severity)
    print(json.dumps(payload, indent=2, sort_keys=True))
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
