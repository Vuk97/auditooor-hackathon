#!/usr/bin/env python3
# r36: lane IGAL registered in .auditooor/agent_pathspec.json
"""incomplete-guard-acknowledgement-scanner.py  (IGAL) - Incomplete-Guard
Acknowledgement Lane.

WHAT THIS TOOL DOES
===================
A Step-1/2 DISCOVERY lane that greps in-scope source AT HEAD for developer-authored
SELF-ACKNOWLEDGEMENTS-OF-INCOMPLETENESS (FIXME / TODO / HACK / "for now" /
unimplemented! / "we don't necessarily have access" ...) that are CO-LOCATED with a
guard / validation / early-return / security sink, ranks each candidate by proximity
to security keywords, and emits one ``needs-fuzz`` hypothesis per candidate.

This is the EXACT shape behind the op-reth Isthmus case: the FIXME comment at
``engine.rs:135-137`` sits inside the ``let Ok(state) = ... else {`` block whose body
is ``return Ok(());`` - a self-acknowledged incomplete guard that silently skips
``isthmus::verify_withdrawals_root_prehashed``.

NOT THE R47 GATE
================
This is a discovery scanner over IN-TREE source comments. It is distinct from the
EXTERNAL R47 acknowledged-wont-fix gate (``acknowledged-wont-fix-check.py``), which
scans ``prior_audits/`` / ``SECURITY.md`` / GHSA and never reads in-tree comments.
R47 = external acknowledgements; IGAL = developer self-acknowledgements in source.

DETECTION (per in-scope source file, line-indexed; .rs .go .sol .move .cairo .py)
=================================================================================
  STAGE 1 - ACK MARKER scan.   union regex over self-ack-of-incompleteness markers.
  STAGE 2 - EARLY-SKIP detect.  per-language early short-circuit returns
            (Rust ``return Ok(())``, Go ``return nil`` / ``return true``,
            Sol ``return;`` / ``return true;``, generic continue/break).
  STAGE 3 - GUARD/SINK co-location.  a candidate fires ONLY when an ACK marker is
            within +/- AUDITOOOR_IGAL_PROXIMITY (default 6) lines of EITHER an
            early-skip return OR a guard/validation/sink keyword line.
  STAGE 4 - SECURITY-KEYWORD PROXIMITY RANKING.  score by distinct security keywords
            in a wider (+/- 12) window + enclosing fn signature, + a bonus when the
            sink is an early-skip and when a SKIPPED CALL is detectable in the
            not-taken branch.  rank_bucket high/med/low (>=6 / 3-5 / <3).

NO-AUTO-CREDIT CONTRACT (R80)
=============================
Every emitted record carries verdict="needs-fuzz". This tool NEVER credits a
coverage / audit-complete gate, never writes a depth cert, never resolves a unit
verdict. Hypothesis-only; the LLM hunt + fuzz must confirm. ``attack_class`` is the
fixed string ``incomplete-guard-self-acknowledged`` for downstream class
normalization.

REUSE (tool-duplication preflight, per CLAUDE.md)
=================================================
Reuses ``tools/lib/scope_exclusion.py`` (resolve_source_roots / is_in_scope /
is_oos / rust_test_line_ranges) - no new OOS heuristics. Mirrors the CLI + emit /
--check shape of ``self-dealing-hypothesis-lane.py`` and
``guard-negative-space-analyzer.py``. Outputs to ``<ws>/.auditooor/``.
Dependency-free stdlib python3.

SCHEMA: auditooor.incomplete_guard_ack.v1

CLI
===
  python3 tools/incomplete-guard-acknowledgement-scanner.py --workspace <ws> [--emit]
  python3 tools/incomplete-guard-acknowledgement-scanner.py --workspace <ws> --check
  --out <path>   override output (default <ws>/.auditooor/incomplete_guard_ack_hypotheses.jsonl)
  --json         machine-readable output

The SCANNER always returns rc=0 (the GATE - incomplete-guard-ack-gate.py - is the
separate fail-closed tool).
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA = "auditooor.incomplete_guard_ack.v1"
SOURCE = "IGAL"
ATTACK_CLASS = "incomplete-guard-self-acknowledged"
VERDICT = "needs-fuzz"

# ---------------------------------------------------------------------------
# Single-source-of-truth scope exclusion (reuse; never re-derive OOS).
# Path-load it (mirrors the sibling-tool loaders) so this script runs both as a
# package module and as a bare ``python3 tools/...-scanner.py``.
# ---------------------------------------------------------------------------
try:  # normal package import
    from tools.lib import scope_exclusion as _scope  # type: ignore
except Exception:  # pragma: no cover - direct-script / odd-sys.path fallback
    _spec = importlib.util.spec_from_file_location(
        "scope_exclusion",
        Path(__file__).resolve().with_name("lib") / "scope_exclusion.py",
    )
    _scope = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_scope)  # type: ignore[union-attr]

# Languages this lane scans (suffix -> short language tag).
_LANG_BY_EXT: dict[str, str] = {
    ".rs": "rs",
    ".go": "go",
    ".sol": "sol",
    ".move": "move",
    ".cairo": "cairo",
    ".py": "py",
}

# ---------------------------------------------------------------------------
# STAGE 1 - ACK MARKER union. Each entry is (canonical-token, compiled-regex).
# Markers split into "code" markers (fire on any line) and "comment-only" markers
# (the bare-word ones like 'should' / 'for now' that must be on a comment line so a
# plain code identifier does not trip them).
# ---------------------------------------------------------------------------
# (token, regex, comment_only)
_ACK_PATTERNS: list[tuple[str, "re.Pattern[str]", bool]] = [
    ("FIXME", re.compile(r"\bFIXME\b", re.IGNORECASE), False),
    ("TODO", re.compile(r"\bTODO\b", re.IGNORECASE), False),
    ("HACK", re.compile(r"\bHACK\b", re.IGNORECASE), False),
    ("XXX", re.compile(r"\bXXX\b"), False),
    ("unimplemented", re.compile(r"\bunimplemented!\s*\("), False),
    ("todo-macro", re.compile(r"\btodo!\s*\("), False),
    ("panic-not-implemented", re.compile(r'\bpanic!\(\s*"not\s+implemented', re.IGNORECASE), False),
    ("not-implemented", re.compile(r"\bnot\s+implemented\b", re.IGNORECASE), False),
    ("placeholder", re.compile(r"\bplaceholder\b", re.IGNORECASE), False),
    ("stub", re.compile(r"\bstub\b(?:\s*(?:impl|implementation)?)?", re.IGNORECASE), False),
    ("temporary", re.compile(r"\btemporar(?:il)?y\b", re.IGNORECASE), False),
    ("for-now", re.compile(r"\bfor\s+now\b", re.IGNORECASE), True),
    ("should", re.compile(r"\bshould\b", re.IGNORECASE), True),
    ("workaround", re.compile(r"\bworkaround\b", re.IGNORECASE), False),
    ("doesnt-handle", re.compile(
        r"\bdoes(?:n'?t|\s+not)\s+(?:yet\s+)?(?:handle|cover|check|validate)\b",
        re.IGNORECASE), False),
    # The literal op-reth comment shape.
    ("no-access", re.compile(
        r"\bwe\s+don'?t\s+(?:necessarily\s+)?have\s+access\b", re.IGNORECASE), False),
]

# A line is a comment when it starts with a comment leader OR (best-effort) contains
# one after some code. Used to gate comment-only markers.
_COMMENT_LEADERS = ("//", "#", "*", "/*", "--")


def _is_comment_line(line: str) -> bool:
    s = line.strip()
    if not s:
        return False
    if s.startswith(_COMMENT_LEADERS):
        return True
    # trailing comment after code: look for a // or # that is plausibly a comment.
    # (Best-effort; a marker in a trailing comment still counts.)
    return ("//" in line) or (re.search(r"(?<!:)#(?!\{)", line) is not None and line.lstrip().startswith("#"))


def _has_trailing_or_leading_comment(line: str) -> bool:
    """True when the line carries comment text (leading OR trailing)."""
    s = line.strip()
    if s.startswith(_COMMENT_LEADERS):
        return True
    # crude trailing-comment detector for the comment-only markers
    return "//" in line or "/*" in line or s.startswith("#")


# ---------------------------------------------------------------------------
# STAGE 2 - EARLY-SKIP returns, per language. Each is a list of compiled regexes.
# The match means: a short-circuit return that SILENTLY skips the rest of the body.
# ---------------------------------------------------------------------------
_EARLY_SKIP_BY_LANG: dict[str, list["re.Pattern[str]"]] = {
    "rs": [
        re.compile(r"\breturn\s+Ok\(\s*\(\s*\)\s*\)\s*;"),   # return Ok(());
        re.compile(r"\breturn\s+Ok\([^;)]*\)\s*;"),          # return Ok(x);
        re.compile(r"^\s*Ok\(\s*\(\s*\)\s*\)\s*$"),          # bare Ok(()) tail-expr
    ],
    "go": [
        # return nil  (no error/condition expression after - bare skip)
        re.compile(r"\breturn\s+nil\s*$"),
        re.compile(r"\breturn\s+true\s*$"),
    ],
    "sol": [
        re.compile(r"\breturn\s+true\s*;"),
        re.compile(r"\breturn\s*;"),
    ],
    "move": [
        re.compile(r"\breturn\s*;"),
        re.compile(r"\breturn\s+true\s*;"),
    ],
    "cairo": [
        re.compile(r"\breturn\s*\(\s*\)\s*;"),
        re.compile(r"\breturn\s+true\s*;"),
    ],
    "py": [
        re.compile(r"\breturn\s+True\s*$"),
        re.compile(r"\breturn\s+None\s*$"),
        re.compile(r"\breturn\s*$"),
    ],
}
# generic continue/break inside a (validation) loop - applies to all languages.
_GENERIC_SKIP = [
    re.compile(r"\bcontinue\s*;?\s*$"),
    re.compile(r"\bbreak\s*;?\s*$"),
]

# ---------------------------------------------------------------------------
# STAGE 3 - GUARD / VALIDATION / SINK keyword line (case-insensitive).
# ---------------------------------------------------------------------------
_GUARD_KEYWORD_RE = re.compile(
    r"(?:"
    r"\bif\s*\(|let\s+Ok\b|let\s+Some\b|require\s*\(|\bassert\b|\brevert\b|"
    r"\bverify\b|\bvalidate\b|\bcheck\b|\bguard\b|\bensure\b|"
    r"\bonlyOwner\b|_checkRole\b|nonReentrant\b|\belse\s*\{"
    r")",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# STAGE 4 - SECURITY keyword set for ranking.
# ---------------------------------------------------------------------------
_SECURITY_KEYWORDS: tuple[str, ...] = (
    "verify", "validate", "check", "auth", "withdraw", "mint", "transfer",
    "root", "proof", "signature", "sig", "nonce", "balance",
    "slash", "collateral", "liquidat", "reentr", "owner", "admin",
)

# enclosing-fn signature finder (best-effort).
_FN_SIG_RE = re.compile(r"\b(?:fn|func|function)\s+([A-Za-z_]\w*)")

# A function-call expression on a line (best-effort): name(... .
_CALL_RE = re.compile(r"\b([A-Za-z_][\w:]*\s*)\(")
# tokens that are not "skipped calls" even though they look like calls.
_CALL_STOPWORDS = frozenset({
    "if", "while", "for", "match", "return", "switch", "Ok", "Err", "Some",
    "None", "require", "assert", "ensure", "println", "format", "vec", "panic",
})


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _proximity() -> int:
    try:
        v = int(os.environ.get("AUDITOOOR_IGAL_PROXIMITY", "") or 6)
        return max(0, v)
    except (TypeError, ValueError):
        return 6


# ---------------------------------------------------------------------------
# Per-file line classification.
# ---------------------------------------------------------------------------
def _ack_marker_lines(lines: list[str], test_idx: set[int]) -> list[tuple[int, str, str]]:
    """Return (0-based line idx, token, trimmed text) for each ACK marker line."""
    out: list[tuple[int, str, str]] = []
    for i, raw in enumerate(lines):
        if i in test_idx:
            continue
        for token, rx, comment_only in _ACK_PATTERNS:
            if not rx.search(raw):
                continue
            if comment_only and not _has_trailing_or_leading_comment(raw):
                continue
            text = raw.strip()
            if len(text) > 240:
                text = text[:240]
            out.append((i, token, text))
            break  # one record per line (first marker wins)
    return out


def _early_skip_lines(lines: list[str], lang: str, test_idx: set[int]) -> set[int]:
    """0-based line indices that are an early short-circuit skip."""
    pats = list(_EARLY_SKIP_BY_LANG.get(lang, [])) + _GENERIC_SKIP
    out: set[int] = set()
    for i, raw in enumerate(lines):
        if i in test_idx:
            continue
        stripped = raw.strip()
        if not stripped or stripped.startswith(_COMMENT_LEADERS):
            continue
        for rx in pats:
            if rx.search(stripped):
                out.add(i)
                break
    return out


def _guard_lines(lines: list[str], test_idx: set[int]) -> set[int]:
    """0-based line indices that carry a guard/validation/sink keyword."""
    out: set[int] = set()
    for i, raw in enumerate(lines):
        if i in test_idx:
            continue
        stripped = raw.strip()
        if not stripped or stripped.startswith(_COMMENT_LEADERS):
            continue
        if _GUARD_KEYWORD_RE.search(raw):
            out.add(i)
    return out


def _enclosing_fn(lines: list[str], idx: int) -> tuple[str, int]:
    """Nearest preceding ``fn|func|function NAME`` -> (name, 0-based line)."""
    for j in range(idx, -1, -1):
        m = _FN_SIG_RE.search(lines[j])
        if m:
            return m.group(1), j
    return "?", -1


def _security_keywords_in_window(
    lines: list[str], lo: int, hi: int, extra_lines: list[str]
) -> list[str]:
    """Distinct security keywords appearing in lines[lo:hi] plus extra_lines."""
    blob = "\n".join(lines[max(0, lo): hi]).lower()
    blob += "\n" + "\n".join(extra_lines).lower()
    found: list[str] = []
    for kw in _SECURITY_KEYWORDS:
        if kw in blob and kw not in found:
            found.append(kw)
    return found


def _skipped_call_for(lines: list[str], skip_idx: int, fn_close_hint: int) -> str:
    """Best-effort: the first fn-call expression that appears AFTER the early-skip
    line (i.e. in the not-taken / would-have-run branch), within a bounded window.

    For the op-reth shape the early-skip ``return Ok(());`` is inside the ``else``
    block; the skipped call (``verify_withdrawals_root_prehashed(...)``) follows the
    close of that block. We scan a window after the skip line for a call whose name
    is not a control-flow/stdlib stopword.
    """
    window = lines[skip_idx + 1: skip_idx + 1 + 40]
    candidates: list[str] = []
    for raw in window:
        stripped = raw.strip()
        if not stripped or stripped.startswith(_COMMENT_LEADERS):
            continue
        for m in _CALL_RE.finditer(raw):
            name = m.group(1).strip().rstrip(":")
            short = name.split("::")[-1].split(".")[-1]
            if not short or short in _CALL_STOPWORDS:
                continue
            # accept lower-case method/fn calls or snake_case (skip Type::new ctors).
            if short[0].isupper() and "_" not in short:
                continue
            candidates.append(name.strip())
    if not candidates:
        return ""
    # Prefer the call that itself looks security-relevant (the verification the
    # early-skip bypassed), e.g. verify_withdrawals_root_prehashed - over a trivial
    # accessor like `.get`. Fall back to the first candidate otherwise.
    for c in candidates:
        cl = c.lower()
        if any(kw in cl for kw in _SECURITY_KEYWORDS):
            return c
    # next preference: a multi-segment snake_case call (more semantically loaded).
    for c in candidates:
        short = c.split("::")[-1].split(".")[-1]
        if "_" in short:
            return c
    return candidates[0]


def _rank_bucket(score: int) -> str:
    if score >= 6:
        return "high"
    if score >= 3:
        return "med"
    return "low"


# ---------------------------------------------------------------------------
# Per-file candidate emit.
# ---------------------------------------------------------------------------
def scan_source(
    *, source: str, rel: str, lang: str, ws_abs: str
) -> list[dict[str, Any]]:
    """Scan one in-scope source string and return IGAL hypothesis records."""
    lines = source.splitlines()
    # Rust inline #[cfg(test)] spans are test oracles, not production guards.
    test_idx: set[int] = (
        _scope.rust_test_line_ranges(lines) if lang == "rs" else set()
    )

    ack_lines = _ack_marker_lines(lines, test_idx)
    if not ack_lines:
        return []
    skip_set = _early_skip_lines(lines, lang, test_idx)
    guard_set = _guard_lines(lines, test_idx)
    prox = _proximity()

    records: list[dict[str, Any]] = []
    # ONE candidate per distinct SINK: a multi-line ACK comment (e.g. the op-reth
    # FIXME block whose 2nd/3rd lines also trip the 'should' comment-only marker)
    # is a SINGLE incomplete guard, not N. Collapse all ACK markers that resolve to
    # the same sink line to one record, keeping the strongest marker (the first,
    # which is the leading FIXME/TODO/etc.).
    seen_sink: set[int] = set()
    for ack_idx, token, ack_text in ack_lines:
        # STAGE 3: co-location within +/- prox of an early-skip OR a guard line.
        near_skip = [
            s for s in skip_set if abs(s - ack_idx) <= prox
        ]
        near_guard = [
            g for g in guard_set if abs(g - ack_idx) <= prox
        ]
        if not near_skip and not near_guard:
            continue  # ACK present but NOT co-located -> not a candidate

        # Choose the sink: prefer the nearest early-skip (stronger signal).
        if near_skip:
            sink_idx = min(near_skip, key=lambda s: abs(s - ack_idx))
            sink_kind = "early-skip-return"
        else:
            sink_idx = min(near_guard, key=lambda g: abs(g - ack_idx))
            # distinguish validation-call guards from plain guards
            gtext = lines[sink_idx]
            if re.search(r"\b(verify|validate|check|ensure)\b", gtext, re.IGNORECASE):
                sink_kind = "validation"
            else:
                sink_kind = "guard"
        if sink_idx in seen_sink:
            continue  # same incomplete guard already recorded
        seen_sink.add(sink_idx)
        sink_text = lines[sink_idx].strip()
        if len(sink_text) > 240:
            sink_text = sink_text[:240]

        # enclosing function name/signature.
        fn_name, fn_idx = _enclosing_fn(lines, ack_idx)
        fn_sig_lines = [lines[fn_idx]] if fn_idx >= 0 else []

        # STAGE 4 ranking. Security keywords are counted in a +/- 12-line window
        # plus the enclosing-fn signature AND the skipped-call text (the bypassed
        # verification is the most security-relevant context of all). The skipped
        # call is resolved first so its own tokens count toward the score.
        is_early_skip = sink_kind == "early-skip-return"
        skipped_call = ""
        if is_early_skip:
            skipped_call = _skipped_call_for(lines, sink_idx, ack_idx + 13)
        lo = ack_idx - 12
        hi = ack_idx + 13
        extra = list(fn_sig_lines)
        if skipped_call:
            extra.append(skipped_call)
        sec_kw = _security_keywords_in_window(lines, lo, hi, extra)
        score = (
            len(sec_kw) * 2
            + (3 if is_early_skip else 0)
            + (2 if skipped_call else 0)
        )
        bucket = _rank_bucket(score)

        note = (
            f"ACK marker '{token}' co-located with {sink_kind} "
            f"(@ {rel}:{ack_idx + 1}, sink @ {rel}:{sink_idx + 1}); "
            f"nearby security context: {', '.join(sec_kw) if sec_kw else 'none'}"
            + (f"; skipped call '{skipped_call}'" if skipped_call else "")
        )

        records.append({
            "schema_version": SCHEMA,
            "workspace": ws_abs,
            "file": rel,
            "function": fn_name,
            "language": lang,
            "ack_line": ack_idx + 1,
            "ack_token": token,
            "ack_text": ack_text,
            "sink_kind": sink_kind,
            "sink_line": sink_idx + 1,
            "sink_text": sink_text,
            "skipped_call": skipped_call,
            "security_keywords": sec_kw,
            "rank_score": score,
            "rank_bucket": bucket,
            "attack_class": ATTACK_CLASS,
            "source": SOURCE,
            "verdict": VERDICT,
            "note": note,
        })
    # score-descending order; stable secondary sort by (file, ack_line).
    records.sort(key=lambda r: (-r["rank_score"], r["file"], r["ack_line"]))
    return records


# ---------------------------------------------------------------------------
# Workspace runner.
# ---------------------------------------------------------------------------
def _iter_inscope_source_files(ws: Path) -> list[str]:
    """Return relative in-scope source paths (manifest-authoritative when present)."""
    manifest = _scope.load_inscope_manifest(ws)
    rels: list[str] = []
    seen: set[str] = set()
    if manifest is not None:
        # Manifest is authoritative for INCLUSION; intersect with markers via
        # is_in_scope (which re-applies the OOS markers + manifest membership).
        for norm in sorted(manifest):
            rel = norm.lstrip("/")
            ext = Path(rel).suffix.lower()
            if ext not in _LANG_BY_EXT:
                continue
            if rel in seen:
                continue
            if not _scope.is_in_scope(rel, workspace=ws):
                continue
            seen.add(rel)
            rels.append(rel)
        return rels
    # No manifest: walk the resolved source roots, keep not-OOS source files.
    roots = _scope.resolve_source_roots(ws)
    for root in roots:
        root = Path(root)
        if not root.exists():
            continue
        base = root if root.is_dir() else root.parent
        for p in sorted(base.rglob("*")):
            if not p.is_file():
                continue
            ext = p.suffix.lower()
            if ext not in _LANG_BY_EXT:
                continue
            try:
                rel = str(p.resolve().relative_to(ws.resolve()))
            except ValueError:
                rel = str(p)
            if rel in seen:
                continue
            if not _scope.is_in_scope(rel, workspace=ws):
                continue
            seen.add(rel)
            rels.append(rel)
    return rels


def run(ws: Path, out_path: Path | None = None) -> dict[str, Any]:
    """Run IGAL over ``ws``, write the hypotheses JSONL + last-run marker."""
    ws = ws.resolve()
    ws_abs = str(ws)
    rels = _iter_inscope_source_files(ws)

    all_records: list[dict[str, Any]] = []
    files_scanned = 0
    for rel in rels:
        abs_path = ws / rel
        if not abs_path.is_file():
            continue
        try:
            source = abs_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        files_scanned += 1
        lang = _LANG_BY_EXT.get(abs_path.suffix.lower(), "?")
        recs = scan_source(source=source, rel=rel, lang=lang, ws_abs=ws_abs)
        all_records.extend(recs)

    # global stable sort: score desc, then file/line.
    all_records.sort(key=lambda r: (-r["rank_score"], r["file"], r["ack_line"]))

    out = (
        Path(out_path)
        if out_path is not None
        else ws / ".auditooor" / "incomplete_guard_ack_hypotheses.jsonl"
    )
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as fh:
        for rec in all_records:
            fh.write(json.dumps(rec) + "\n")

    high = sum(1 for r in all_records if r["rank_bucket"] == "high")
    med = sum(1 for r in all_records if r["rank_bucket"] == "med")
    low = sum(1 for r in all_records if r["rank_bucket"] == "low")

    # Freshness marker for the gate (NEVER self-credits; head_sha is recomputed by
    # the gate against real HEAD, so a hand-edited marker cannot green the gate).
    marker = {
        "schema_version": "auditooor.incomplete_guard_ack_last_run.v1",
        "run_id": _now(),
        "utc_ts": _now(),
        "head_sha": _git_head(ws),
        "files_scanned": files_scanned,
        "records_emitted": len(all_records),
        "high_bucket": high,
        "med_bucket": med,
        "low_bucket": low,
        "output_path": str(out),
    }
    marker_path = ws / ".auditooor" / "incomplete_guard_ack_last_run.json"
    try:
        marker_path.parent.mkdir(parents=True, exist_ok=True)
        marker_path.write_text(json.dumps(marker, indent=2), encoding="utf-8")
    except OSError:
        pass

    return {
        "schema_version": SCHEMA,
        "source": SOURCE,
        "workspace": ws_abs,
        "files_scanned": files_scanned,
        "records_emitted": len(all_records),
        "high_bucket": high,
        "med_bucket": med,
        "low_bucket": low,
        "output_path": str(out),
    }


def _git_head(ws: Path) -> str:
    """Best-effort current HEAD sha (stdlib only; reads .git/HEAD + ref)."""
    git = ws / ".git"
    try:
        if git.is_file():
            # worktree: ".git" is a file pointing at the real gitdir
            txt = git.read_text(encoding="utf-8").strip()
            if txt.startswith("gitdir:"):
                git = Path(txt.split(":", 1)[1].strip())
        head = (git / "HEAD")
        if not head.is_file():
            return ""
        content = head.read_text(encoding="utf-8").strip()
        if content.startswith("ref:"):
            ref = content.split(":", 1)[1].strip()
            ref_path = git / ref
            if ref_path.is_file():
                return ref_path.read_text(encoding="utf-8").strip()
            # packed-refs fallback
            packed = git / "packed-refs"
            if packed.is_file():
                for line in packed.read_text(encoding="utf-8").splitlines():
                    line = line.strip()
                    if line.endswith(" " + ref):
                        return line.split(" ", 1)[0]
            return ""
        return content  # detached HEAD: HEAD holds the sha directly
    except OSError:
        return ""


def check(ws: Path) -> dict[str, Any]:
    """--check: counts + verdict. Always rc 0 for the scanner (the GATE fails)."""
    ws = ws.resolve()
    out = ws / ".auditooor" / "incomplete_guard_ack_hypotheses.jsonl"
    if not out.is_file():
        return {
            "schema_version": SCHEMA,
            "mode": "check",
            "verdict": "not-run",
            "records_emitted": 0,
            "high_bucket": 0,
            "med_bucket": 0,
            "low_bucket": 0,
            "detail": "no incomplete_guard_ack_hypotheses.jsonl - run --emit",
        }
    high = med = low = total = 0
    try:
        for line in out.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except ValueError:
                continue
            total += 1
            b = r.get("rank_bucket")
            if b == "high":
                high += 1
            elif b == "med":
                med += 1
            else:
                low += 1
    except OSError:
        pass
    return {
        "schema_version": SCHEMA,
        "mode": "check",
        "verdict": "scanned",
        "records_emitted": total,
        "high_bucket": high,
        "med_bucket": med,
        "low_bucket": low,
        "output_path": str(out),
    }


# ---------------------------------------------------------------------------
# Public test helper (no workspace dir required).
# ---------------------------------------------------------------------------
def hypotheses_from_source(
    source: str,
    language: str,
    file_rel: str = "fixture.rs",
    ws_abs: str = "/tmp/igal_fixture_ws",
) -> list[dict[str, Any]]:
    """Return IGAL hypotheses for one source string. Convenience for unit tests."""
    return scan_source(source=source, rel=file_rel, lang=language, ws_abs=ws_abs)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def _main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="IGAL: scan in-scope source for self-acknowledged incomplete guards."
    )
    ap.add_argument("--workspace", required=True, help="workspace root path")
    ap.add_argument("--emit", action="store_true",
                    help="enumerate + write hypotheses (default mode)")
    ap.add_argument("--check", action="store_true", help="verdict + counts only")
    ap.add_argument("--out", default=None, help="override hypotheses output path")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args(argv)

    ws = Path(args.workspace).expanduser()
    if not ws.is_dir():
        msg = f"ERROR: workspace not found: {ws}"
        print(json.dumps({"verdict": "error", "error": msg}) if args.json else msg,
              file=sys.stderr)
        return 0  # scanner never hard-exits non-zero; the GATE is fail-closed.

    if args.check:
        res = check(ws)
    else:
        res = run(ws, out_path=Path(args.out) if args.out else None)

    if args.json:
        print(json.dumps(res, indent=2))
    else:
        if res.get("mode") == "check":
            print(f"IGAL --check: {res['verdict']} "
                  f"({res['records_emitted']} records; "
                  f"high={res['high_bucket']} med={res['med_bucket']} low={res['low_bucket']})")
        else:
            print(f"IGAL: {res['records_emitted']} incomplete-guard-ack hypotheses "
                  f"(high={res['high_bucket']} med={res['med_bucket']} low={res['low_bucket']}) "
                  f"-> {res['output_path']}")
    return 0


if __name__ == "__main__":
    sys.exit(_main())
