#!/usr/bin/env python3
"""access-control-coverage.py  (ACL-COV) - Access-Control Coverage Lane.

WHAT THIS TOOL DOES
===================
Detects privileged admin/governance functions that are callable WITHOUT the
expected authorization guard, across all three language families supported by
the auditooor harness.

It is a THIN ADAPTER that invokes the three EXISTING detectors as subprocesses,
normalizes their output into a single sidecar JSONL, and applies the canonical
scope_exclusion OOS filter.  Detection logic lives in the existing tools; this
file only wires them together.

DETECTORS INVOKED
=================
- Solidity:  tools/acl-matrix.py <workspace>
    Requires Slither. If Slither is absent (non-zero exit + "[err] Slither
    required" on stderr), OR if acl-matrix.py times out (>300 s), the Solidity
    arm falls back to the REGEX FALLBACK (see below) instead of a plain skip.

- Go/Cosmos:  tools/detectors/go_permissionless_admin_key_sentinel.py <repo>
    stdlib-only, always runs.

- Rust/Substrate:  detectors/rust-substrate-origin-privileged-effect-missing-guard.py
    stdlib-only, runs over every in-scope *.rs file via scan_file().

SOLIDITY REGEX FALLBACK (ACL-COV-REGEX-FALLBACK)
=================================================
Fires ONLY when the Slither-backed acl-matrix.py arm is unavailable (timeout
OR Slither absent).  This is an HONEST DEGRADED MODE - it does NOT claim to be
a Slither result.  Every record emitted by the fallback carries:
  source = "ACL-COV-REGEX-FALLBACK"
  verdict = "needs-fuzz"
  guard_reason = "... [DEGRADED: regex-only, no Slither; treat as hint, not proof]"

Admin-class function name triggers (case-sensitive prefix match on the
camelCase word boundary):
  set[A-Z], update[A-Z], grant, revoke, pause, unpause, upgrade, setOwner,
  setAdmin, setFee, setOracle, transferOwnership, initialize, reinitialize

A function is NOT flagged (guard suppressor) when the body/header contains any of:
  - Any non-visibility modifier in the function header (onlyOwner, onlyRole, etc.)
  - require(msg.sender == ...)  or  require(... == msg.sender ...)
  - _checkRole(  /  hasRole(  /  _checkOwner(
  - A body call to _authorizeUpgrade(  [UUPS delegation - upgradeTo/upgradeToAndCall
    that delegate to _authorizeUpgrade carry the guard there; flagging them is an FP]
  - view or pure visibility
  - constructor keyword
  - function name is initialize / reinitialize / __init

OUTPUT
======
<ws>/.auditooor/access_control_hypotheses.jsonl
  One record per hit (needs-fuzz, never auto-credited).
  Fields: file, function, language, admin_action, guard_check, guard_reason,
          attack_class, source, verdict, fuzz_oracle_hint.

SLITHER-GRACEFUL rule
=====================
If acl-matrix.py exits non-zero OR prints "[err] Slither required" OR times out,
the Regex Fallback runs instead (degraded mode, clearly labeled).  The Go and
Rust arms are stdlib-only and always run.

NO-AUTO-CREDIT
==============
Every emitted record carries verdict="needs-fuzz". This tool NEVER increments
per_function_verified, never flips a gate to pass, and never resolves a unit.

Usage:
  python3 tools/access-control-coverage.py <workspace> [--out OUT]
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Resolve paths relative to THIS file so the tool works regardless of cwd.
# ---------------------------------------------------------------------------
_HERE = Path(__file__).resolve().parent
_REPO_ROOT = _HERE.parent  # one level up from tools/

# ---------------------------------------------------------------------------
# Compose with scope_exclusion (single source of truth OOS guard).
# ---------------------------------------------------------------------------
try:
    from tools.lib.scope_exclusion import is_oos, resolve_source_roots  # type: ignore
except Exception:
    _LIB = _HERE / "lib"
    if str(_LIB) not in sys.path:
        sys.path.insert(0, str(_LIB))
    try:
        from scope_exclusion import is_oos, resolve_source_roots  # type: ignore
    except Exception:
        def is_oos(rel: str, **_) -> bool:  # type: ignore[misc]
            n = ("/" + rel.replace("\\", "/")).lower()
            for marker in (
                "/test/", "/tests/", "_test.", ".t.sol", "/vendor/", "/lib/",
                "/node_modules/", "/out/", "/build/", "/target/",
                "/.auditooor/",
            ):
                if marker in n:
                    return True
            return False

        def resolve_source_roots(workspace) -> list:  # type: ignore[misc]
            return [Path(workspace)]

# ---------------------------------------------------------------------------
# Sidecar path constant (mirrors the RDL/MOL pattern in auto-coverage-closer).
# ---------------------------------------------------------------------------
ACCESS_CONTROL_HYPOTHESES_REL = os.path.join(".auditooor", "access_control_hypotheses.jsonl")
ATTACK_CLASS = "missing-authorization-privilege-escalation"
SOURCE_LABEL = "ACL-COV"
SOURCE_LABEL_FALLBACK = "ACL-COV-REGEX-FALLBACK"

# ---------------------------------------------------------------------------
# Language detection helpers.
# ---------------------------------------------------------------------------
_SOL_SUFFIXES = {".sol", ".vy"}
_GO_SUFFIXES  = {".go"}
_RS_SUFFIXES  = {".rs"}

_SKIP_DIR_PARTS = {
    "vendor", "node_modules", ".git", "lib", "out", "artifacts", "cache",
    "target", "third_party", "external", "test", "tests", "mocks", "mock",
    ".audit_logs", ".auditooor", "submissions", "prior_audits", "reports", "docs",
}


def _has_language(ws: Path, suffixes: set[str]) -> bool:
    """Return True if any in-scope file with the given suffix exists.

    Uses an early-exit rglob so large workspaces don't incur a full scan.
    """
    for suffix in suffixes:
        # glob suffix directly for speed (O(matches) not O(all-files))
        for p in ws.rglob(f"*{suffix}"):
            if not p.is_file():
                continue
            rel_parts = p.parts[len(ws.parts):]
            if any(part.lower() in _SKIP_DIR_PARTS or part.startswith(".") for part in rel_parts):
                continue
            return True
    return False


def _rs_files(ws: Path) -> list[Path]:
    """Yield in-scope .rs files under ws."""
    result: list[Path] = []
    for p in ws.rglob("*.rs"):
        if not p.is_file():
            continue
        rel_parts = p.parts[len(ws.parts):]
        if any(part.lower() in _SKIP_DIR_PARTS or part.startswith(".") for part in rel_parts):
            continue
        result.append(p)
    return result


# ---------------------------------------------------------------------------
# Helper: make a relative path string for is_oos checks.
# ---------------------------------------------------------------------------
def _relpath(ws: Path, p: Path) -> str:
    try:
        return str(p.relative_to(ws))
    except ValueError:
        return str(p)


# ---------------------------------------------------------------------------
# Solidity regex fallback (ACL-COV-REGEX-FALLBACK).
#
# Fires ONLY when Slither/acl-matrix is absent or times out - honest degraded
# mode, clearly labeled.  Does NOT masquerade as a Slither result.
# ---------------------------------------------------------------------------
import re as _re  # noqa: E402 - module-level import kept here for locality

# Admin-class function name pattern.  Triggers on camelCase admin-verb prefixes.
_REGEX_FB_ADMIN_NAME_RE = _re.compile(
    r"^("
    r"set[A-Z]|update[A-Z]|grant|revoke|pause|unpause|upgrade|"
    r"setOwner|setAdmin|setFee|setOracle|transferOwnership"
    r")"
)

# Visibility keywords that indicate the function is read-only (skip).
_REGEX_FB_SKIP_MUTABILITY_RE = _re.compile(r"\b(view|pure)\b")

# Constructor and initializer patterns - skip these.
_REGEX_FB_SKIP_NAMES_RE = _re.compile(
    r"^(constructor|initialize|reinitialize|__init|_init)\b"
)

# Guard suppressors - if ANY appear in the function header+body the function
# is considered guarded and must NOT be flagged.
_REGEX_FB_GUARD_PATTERNS: list[_re.Pattern] = [
    # Delegated-guard: upgradeTo / upgradeToAndCall body calls _authorizeUpgrade()
    # which carries the real guard.  This is the UUPS override pattern - suppressor
    # for the FP that caused the original revert.
    _re.compile(r"\b_authorizeUpgrade\s*\("),
    # require(msg.sender == ...) or require(... == msg.sender)
    _re.compile(r"\brequire\s*\([^)]*\bmsg\.sender\b", _re.S),
    # _checkRole / hasRole / _checkOwner / _checkAccess
    _re.compile(r"\b(_checkRole|hasRole|_checkOwner|_checkAccess)\s*\("),
    # OZ-style _requireOwner / _requireCallerHasRole / _onlyOwner
    _re.compile(r"\b(_requireOwner|_requireCallerHasRole|_onlyOwner)\s*\("),
    # mapping[msg.sender] per-user writes - not admin-class
    _re.compile(r"\bmapping\s*\(.*msg\.sender", _re.S),
]

# Solidity function signature line.  Group 1 = name.
_REGEX_FB_FN_SIG_RE = _re.compile(r"\bfunction\s+([A-Za-z_]\w*)\s*\(")

# Non-visibility modifier: any word in the header (after param close) that is
# NOT a Solidity keyword.  Presence of a non-keyword modifier = guarded.
_SOL_KW: frozenset[str] = frozenset({
    "public", "external", "internal", "private",
    "pure", "view", "payable", "virtual", "override",
    "returns", "memory", "calldata", "storage",
    "function", "constructor", "modifier", "event",
    "indexed", "anonymous", "emit", "delete",
})


def _regex_fb_has_modifier(header_text: str) -> bool:
    """Return True if the function header contains a non-visibility modifier.

    We strip the function keyword + name + params and scan remaining words for
    identifiers that are not Solidity keywords.  E.g. `onlyOwner`, `onlyRole`,
    `whenNotPaused` would return True.
    """
    # Find closing ')' of param list.
    depth = 0
    param_end = -1
    for i, ch in enumerate(header_text):
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                param_end = i
                break
    if param_end == -1:
        return False
    after_params = header_text[param_end + 1:]
    # Strip returns(...) clause.
    after_params = _re.sub(r"\breturns\s*\(.*?\)", "", after_params, flags=_re.S)
    words = _re.findall(r"\b([A-Za-z_]\w*)\b", after_params)
    for w in words:
        if w not in _SOL_KW:
            return True
    return False


def _extract_sol_fn_body(source: str, sig_start: int) -> str:
    """Extract the body text of a Solidity function starting at sig_start.

    Returns text from the opening brace to the matching close brace.
    Returns empty string if no body found (abstract / interface declaration).
    """
    brace_pos = source.find("{", sig_start)
    if brace_pos == -1:
        return ""
    depth = 0
    for i in range(brace_pos, len(source)):
        if source[i] == "{":
            depth += 1
        elif source[i] == "}":
            depth -= 1
            if depth == 0:
                return source[brace_pos:i + 1]
    return source[brace_pos:]


def _run_solidity_regex_fallback(ws: Path) -> list[dict]:
    """Pure-regex Solidity admin-guard scan.

    Scans all in-scope .sol files under ws for admin-class functions that lack
    a recognizable guard.  Returns a list of raw hit dicts (pre-normalization).

    This is an honest DEGRADED MODE.  Every record carries
    source=ACL-COV-REGEX-FALLBACK and a guard_reason suffix that flags it as
    regex-only.  Callers must NOT promote these to Slither-grade evidence.
    """
    hits: list[dict] = []
    skip_dirs = _SKIP_DIR_PARTS | {"node_modules", "lib", "out", "artifacts", "cache"}

    for sol_file in ws.rglob("*.sol"):
        if not sol_file.is_file():
            continue
        rel_parts = sol_file.parts[len(ws.parts):]
        if any(part.lower() in skip_dirs or part.startswith(".") for part in rel_parts):
            continue
        rel = _relpath(ws, sol_file)
        if is_oos(rel):
            continue
        try:
            source = sol_file.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue

        for m in _REGEX_FB_FN_SIG_RE.finditer(source):
            fn_name = m.group(1)

            # Skip constructors and initializers by name.
            if _REGEX_FB_SKIP_NAMES_RE.match(fn_name):
                continue

            # Must match admin-class name pattern.
            if not _REGEX_FB_ADMIN_NAME_RE.match(fn_name):
                continue

            sig_start = m.start()
            # Extract header text (from fn keyword to opening brace).
            brace_pos = source.find("{", m.end())
            semi_pos = source.find(";", m.end())
            if brace_pos == -1:
                header_end = semi_pos if semi_pos != -1 else min(sig_start + 800, len(source))
            else:
                header_end = brace_pos
            header_text = source[sig_start:header_end]

            # Skip view/pure functions.
            if _REGEX_FB_SKIP_MUTABILITY_RE.search(header_text):
                continue

            # Suppress: non-visibility modifier in header means guarded.
            if _regex_fb_has_modifier(header_text):
                continue

            # Extract body.
            body_text = _extract_sol_fn_body(source, sig_start)
            combined = header_text + "\n" + body_text

            # Suppress: any guard pattern in header+body.
            guarded = False
            for guard_pat in _REGEX_FB_GUARD_PATTERNS:
                if guard_pat.search(combined):
                    guarded = True
                    break
            if guarded:
                continue

            hits.append({
                "file": str(sol_file),
                "function": fn_name,
                "language": "solidity",
                "admin_action": f"{fn_name} in {sol_file.name} - admin-class fn name match",
                "guard_check": "UNGUARDED",
                "guard_reason": (
                    f"no recognized guard modifier/require(msg.sender)/role-check found "
                    f"in function header or body "
                    f"[DEGRADED: regex-only, no Slither; treat as hint, not proof]"
                ),
                "_fallback_source": SOURCE_LABEL_FALLBACK,
            })
    return hits


# ---------------------------------------------------------------------------
# Solidity arm - invokes tools/acl-matrix.py as a subprocess.
# ---------------------------------------------------------------------------
def _sol_source_roots(ws: Path) -> list[Path]:
    """Resolve the narrowest in-scope Solidity source root(s) for ws.

    Uses scope_exclusion.resolve_source_roots (which delegates to
    source_root_resolver) to find the tightest common in-scope parent dir that
    still contains all Solidity sources. Passing this narrower root to
    acl-matrix avoids Slither compiling node_modules/lib/test trees, which
    causes the >300 s timeout on large workspaces (e.g. beanstalk's 4795 .sol
    files).

    Falls back to [ws] when the resolver is unavailable (fail-safe).
    """
    try:
        roots = resolve_source_roots(ws)
    except Exception:
        roots = [ws]
    if not roots:
        return [ws]
    return roots


def _run_solidity_arm(ws: Path) -> tuple[list[dict], dict | None]:
    """Run acl-matrix.py over each in-scope source root. Returns (hits, skip_note_or_None).

    When Slither is absent OR acl-matrix times out, falls back to the regex
    fallback (_run_solidity_regex_fallback) instead of a plain skip.  The
    fallback records carry source=ACL-COV-REGEX-FALLBACK and a guard_reason
    suffix that flags them as degraded hints.

    A typed skip note is still appended to the sidecar (honest accounting) even
    when the fallback runs.

    Scope-narrowing: resolves in-scope Solidity source roots via
    resolve_source_roots() and invokes acl-matrix once per root. This prevents
    Slither from compiling node_modules/lib/test on large workspaces.
    """
    acl_tool = _HERE / "acl-matrix.py"
    if not acl_tool.is_file():
        fallback_hits = _run_solidity_regex_fallback(ws)
        return fallback_hits, _skip_note(
            "solidity",
            "acl-matrix.py not present in tools/; regex fallback active",
        )

    roots = _sol_source_roots(ws)
    all_hits: list[dict] = []

    for src_root in roots:
        try:
            result = subprocess.run(
                [sys.executable, str(acl_tool), str(src_root)],
                capture_output=True,
                text=True,
                timeout=300,
            )
        except subprocess.TimeoutExpired:
            # Fallback: still timed out even on the narrowed root.
            root_label = (
                str(src_root.relative_to(ws)) if src_root != ws else ws.name
            )
            fallback_hits = _run_solidity_regex_fallback(ws)
            return all_hits + fallback_hits, _skip_note(
                "solidity",
                f"acl-matrix.py timed out (>300 s) even on narrowed root {root_label}; "
                f"Slither compile too slow for this workspace; "
                f"regex fallback active ({len(fallback_hits)} hits)",
            )
        except Exception as exc:
            fallback_hits = _run_solidity_regex_fallback(ws)
            return fallback_hits, _skip_note(
                "solidity",
                f"acl-matrix.py subprocess failed: {exc}; regex fallback active",
            )

        # Slither-absent guard: acl-matrix prints "[err] Slither required" to stderr
        # and exits non-zero.
        stderr_lower = result.stderr.lower()
        if result.returncode != 0 or "[err] slither required" in stderr_lower:
            reason = (
                "Slither not installed"
                if "[err] slither required" in stderr_lower
                else f"acl-matrix exited {result.returncode}"
            )
            fallback_hits = _run_solidity_regex_fallback(ws)
            return fallback_hits, _skip_note(
                "solidity",
                f"{reason}; regex fallback active ({len(fallback_hits)} hits)",
            )

        # acl-matrix.py writes acl_matrix.md relative to the root it was given.
        # When src_root differs from ws, look there first, then fall back to ws.
        acl_md = src_root / "acl_matrix.md"
        if not acl_md.is_file():
            acl_md = ws / "acl_matrix.md"
        if not acl_md.is_file():
            continue  # this root produced no output - move to next root

        in_ungated = False
        for line in acl_md.read_text(encoding="utf-8", errors="replace").splitlines():
            if "Ungated functions writing privileged state" in line:
                in_ungated = True
                continue
            if in_ungated and line.startswith("##"):
                in_ungated = False
            if not in_ungated:
                continue
            # Table rows: | `ContractName` | `fnName` | writes |
            if not line.startswith("|") or "|---|" in line or "Contract" in line:
                continue
            parts = [p.strip().strip("`") for p in line.split("|") if p.strip()]
            if len(parts) < 3:
                continue
            contract, fn_name, writes = parts[0], parts[1], parts[2]
            # Try to map to a file - we use the workspace root as fallback.
            file_hint = str(ws)
            all_hits.append({
                "file": file_hint,
                "function": fn_name,
                "language": "solidity",
                "admin_action": f"{contract}.{fn_name} writes {writes}",
                "guard_check": "UNGUARDED",
                "guard_reason": f"no modifier/require gate found for privileged state write: {writes}",
            })

    return all_hits, None


# ---------------------------------------------------------------------------
# Go arm - invokes go_permissionless_admin_key_sentinel.py as a subprocess.
# ---------------------------------------------------------------------------
def _run_go_arm(ws: Path) -> tuple[list[dict], dict | None]:
    go_tool = _HERE / "detectors" / "go_permissionless_admin_key_sentinel.py"
    if not go_tool.is_file():
        return [], _skip_note("go", "go_permissionless_admin_key_sentinel.py not present")

    tmp_out = ws / ".auditooor" / "_acl_go_sentinel_tmp.json"
    tmp_out.parent.mkdir(parents=True, exist_ok=True)
    try:
        result = subprocess.run(
            [sys.executable, str(go_tool), str(ws), "--out", str(tmp_out),
             "--entrypoints-only"],
            capture_output=True,
            text=True,
            timeout=300,
        )
    except Exception as exc:
        return [], _skip_note("go", f"go sentinel subprocess failed: {exc}")

    if result.returncode not in (0, 1):
        return [], _skip_note("go", f"go sentinel exited {result.returncode}")

    if not tmp_out.is_file():
        return [], None  # no sentinels - empty workspace

    try:
        payload = json.loads(tmp_out.read_text(encoding="utf-8"))
    except Exception:
        return [], _skip_note("go", "go sentinel output is not valid JSON")
    finally:
        try:
            tmp_out.unlink(missing_ok=True)
        except Exception:
            pass

    sentinels = payload.get("sentinels", [])
    hits: list[dict] = []
    for s in sentinels:
        hits.append({
            "file": s.get("file", ""),
            "function": s.get("method", "?"),
            "language": "go",
            "admin_action": f"pattern={s.get('pattern','?')}; {s.get('evidence','')[:200]}",
            "guard_check": "UNGUARDED",
            "guard_reason": (
                "MsgServer method writes state without authority check (Pattern A)"
                if s.get("pattern") == "A"
                else f"admin-key cluster (Pattern {s.get('pattern','?')}); severity_hint={s.get('severity_hint','?')}"
            ),
        })
    return hits, None


# ---------------------------------------------------------------------------
# Rust arm - imports and calls scan_file() directly (no subprocess needed).
# ---------------------------------------------------------------------------
def _run_rust_arm(ws: Path) -> tuple[list[dict], dict | None]:
    rust_detector_path = _REPO_ROOT / "detectors" / "rust-substrate-origin-privileged-effect-missing-guard.py"
    if not rust_detector_path.is_file():
        return [], _skip_note("rust", "rust-substrate-origin-privileged-effect-missing-guard.py not present")

    # Import the module dynamically by path.
    try:
        spec = importlib.util.spec_from_file_location("rust_acl_detector", rust_detector_path)
        mod = importlib.util.module_from_spec(spec)  # type: ignore
        spec.loader.exec_module(mod)  # type: ignore
    except Exception as exc:
        return [], _skip_note("rust", f"failed to import rust detector: {exc}")

    rs_files = _rs_files(ws)
    hits: list[dict] = []
    for rs_file in rs_files:
        rel = _relpath(ws, rs_file)
        if is_oos(rel):
            continue
        try:
            file_hits: list[dict[str, Any]] = mod.scan_file(str(rs_file))
        except Exception:
            continue
        for h in file_hits:
            hits.append({
                "file": h.get("file", str(rs_file)),
                "function": _extract_fn_from_snippet(h.get("snippet", ""), h.get("message", "")),
                "language": "rust",
                "admin_action": h.get("snippet", "")[:200],
                "guard_check": "UNGUARDED",
                "guard_reason": h.get("message", "")[:300],
            })
    return hits, None


def _extract_fn_from_snippet(snippet: str, message: str) -> str:
    """Best-effort: extract function name from detector message/snippet."""
    import re
    # rust detector message: "Substrate dispatchable `name` accepts ..."
    m = re.search(r"dispatchable `([^`]+)`", message)
    if m:
        return m.group(1)
    # fallback: first word in snippet
    m2 = re.search(r"\bfn\s+([A-Za-z_][A-Za-z0-9_]*)", snippet)
    if m2:
        return m2.group(1)
    return "?"


# ---------------------------------------------------------------------------
# Scope-authoritative filter (mirrors the FIX-FCC-SCOPE-AUTHORITATIVE pattern
# from function-coverage-completeness.py commit 5dd42eca4a).
#
# On multi-package monorepos (OP Stack, Cosmos chains) walking src_roots via
# rglob counts OUT-OF-SCOPE packages in the denominator. When an authoritative
# in-scope manifest exists (.auditooor/inscope_units.jsonl), we filter the
# normalized hits to only those files that appear in that manifest.
# If the manifest is absent/empty -> return None -> NO filter (legacy behavior).
# Honor env AUDITOOOR_FCC_NO_SCOPE_FILTER to skip filtering.
# ---------------------------------------------------------------------------
def _load_inscope_file_set(ws: Path):
    """Return the authoritative in-scope file set from .auditooor/inscope_units.jsonl,
    or None when no manifest exists (then no filtering - legacy behavior preserved).
    """
    if os.environ.get("AUDITOOOR_FCC_NO_SCOPE_FILTER"):
        return None
    manifest = ws / ".auditooor" / "inscope_units.jsonl"
    if not manifest.is_file():
        return None
    files: set = set()
    for line in manifest.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            continue
        f = str(row.get("file") or "").strip().lstrip("./").replace("\\", "/")
        if f:
            files.add(f)
    return files or None


def _norm_path(p: str) -> str:
    """Normalize a ws-relative path for in-scope set membership check."""
    return str(p or "").strip().lstrip("./").replace("\\", "/")


# ---------------------------------------------------------------------------
# Typed skip note builder (mirrors emit_typed_deep_engine_skip style).
# ---------------------------------------------------------------------------
def _skip_note(language: str, reason: str) -> dict:
    return {
        "_acl_skip": True,
        "language": language,
        "reason": reason,
        "source": SOURCE_LABEL,
        "verdict": "typed-skip",
    }


# ---------------------------------------------------------------------------
# Normalize hits into canonical access_control_hypotheses.jsonl records.
# ---------------------------------------------------------------------------
def _normalize_hit(ws: Path, hit: dict) -> dict | None:
    """Convert a raw hit dict to a canonical sidecar record.

    Returns None if the hit's file is OOS/test/.auditooor.
    """
    file_abs = hit.get("file", "")
    rel = _relpath(ws, Path(file_abs)) if file_abs else ""
    if rel and is_oos(rel):
        return None
    # Also drop anything inside .auditooor explicitly.
    if ".auditooor" in rel.replace("\\", "/"):
        return None

    fn_name = hit.get("function", "?")
    lang = hit.get("language", "unknown")
    admin_action = hit.get("admin_action", "")
    guard_reason = hit.get("guard_reason", "")

    fuzz_hint = (
        f"Write a test that calls {fn_name} from an unprivileged address "
        f"and asserts the privileged state did NOT change. "
        f"If the call succeeds and state changes, the guard is missing."
    )

    # Preserve the fallback source label so downstream tools can distinguish
    # regex-fallback hints from Slither-verified results.
    source = hit.get("_fallback_source") or SOURCE_LABEL

    return {
        "file": rel or file_abs,
        "function": fn_name,
        "language": lang,
        "admin_action": admin_action,
        "guard_check": "UNGUARDED",
        "guard_reason": guard_reason,
        "attack_class": ATTACK_CLASS,
        "source": source,
        "verdict": "needs-fuzz",
        "fuzz_oracle_hint": fuzz_hint,
    }


# ---------------------------------------------------------------------------
# Main entry point.
# ---------------------------------------------------------------------------
def run(ws_path: Path, out_path: Path) -> dict:
    """Run all applicable arms and write the sidecar JSONL.

    Returns a summary dict.
    """
    out_path.parent.mkdir(parents=True, exist_ok=True)

    all_records: list[dict] = []
    skip_notes: list[dict] = []
    arm_summary: dict[str, Any] = {}

    # --- Solidity arm ---
    has_sol = _has_language(ws_path, _SOL_SUFFIXES)
    if has_sol:
        sol_hits, sol_skip = _run_solidity_arm(ws_path)
        if sol_skip:
            skip_notes.append(sol_skip)
            # Distinguish: if fallback returned hits, label as fallback active.
            fallback_hits = [h for h in sol_hits if h.get("_fallback_source") == SOURCE_LABEL_FALLBACK]
            slither_hits = [h for h in sol_hits if h.get("_fallback_source") != SOURCE_LABEL_FALLBACK]
            if fallback_hits:
                arm_summary["solidity"] = (
                    f"slither-skip ({sol_skip['reason'][:80]}...); "
                    f"regex-fallback: {len(fallback_hits)} hint(s)"
                )
            else:
                arm_summary["solidity"] = f"skipped: {sol_skip['reason']}"
        else:
            arm_summary["solidity"] = f"{len(sol_hits)} hits"
        all_records.extend(sol_hits)
    else:
        arm_summary["solidity"] = "no Solidity source detected"

    # --- Go arm ---
    has_go = _has_language(ws_path, _GO_SUFFIXES)
    if has_go:
        go_hits, go_skip = _run_go_arm(ws_path)
        if go_skip:
            skip_notes.append(go_skip)
            arm_summary["go"] = f"skipped: {go_skip['reason']}"
        else:
            arm_summary["go"] = f"{len(go_hits)} hits"
        all_records.extend(go_hits)
    else:
        arm_summary["go"] = "no Go source detected"

    # --- Rust arm ---
    has_rs = _has_language(ws_path, _RS_SUFFIXES)
    if has_rs:
        rs_hits, rs_skip = _run_rust_arm(ws_path)
        if rs_skip:
            skip_notes.append(rs_skip)
            arm_summary["rust"] = f"skipped: {rs_skip['reason']}"
        else:
            arm_summary["rust"] = f"{len(rs_hits)} hits"
        all_records.extend(rs_hits)
    else:
        arm_summary["rust"] = "no Rust source detected"

    # --- Normalize + OOS-filter ---
    normalized: list[dict] = []
    oos_dropped = 0
    for hit in all_records:
        rec = _normalize_hit(ws_path, hit)
        if rec is None:
            oos_dropped += 1
        else:
            normalized.append(rec)

    # --- Scope-authoritative filter (inscope_units.jsonl manifest) ---
    # Mirrors the FIX-FCC-SCOPE-AUTHORITATIVE pattern: when the manifest exists,
    # only keep records whose file is in the authoritative in-scope set. This
    # prevents OOS packages on multi-package monorepos from polluting the output.
    _inscope = _load_inscope_file_set(ws_path)
    scope_filtered_out = 0
    if _inscope is not None:
        kept: list[dict] = []
        for rec in normalized:
            if _norm_path(rec.get("file", "")) in _inscope:
                kept.append(rec)
            else:
                scope_filtered_out += 1
        if scope_filtered_out:
            print(
                f"[acl-cov] scope-filter: dropped {scope_filtered_out} OOS records "
                f"(not in .auditooor/inscope_units.jsonl)",
                file=sys.stderr,
            )
        normalized = kept

    # --- Write sidecar JSONL ---
    with out_path.open("w", encoding="utf-8") as fh:
        for rec in normalized:
            fh.write(json.dumps(rec) + "\n")
        # Append typed skip notes so the absence of a Slither run is honest.
        for note in skip_notes:
            fh.write(json.dumps(note) + "\n")

    total_hypotheses = len(normalized)
    summary = {
        "workspace": str(ws_path),
        "out": str(out_path),
        "hypotheses": total_hypotheses,
        "oos_dropped": oos_dropped,
        "scope_filter": {
            "applied": _inscope is not None,
            "source": ".auditooor/inscope_units.jsonl" if _inscope is not None else None,
            "in_scope_files": (len(_inscope) if _inscope is not None else None),
            "out_of_scope_dropped": scope_filtered_out,
        },
        "skip_notes": len(skip_notes),
        "arms": arm_summary,
    }
    return summary


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="ACL-COV: access-control coverage lane (wires existing detectors)"
    )
    ap.add_argument("workspace", type=Path, help="Workspace root directory")
    ap.add_argument("--out", type=Path, default=None,
                    help="Output JSONL path (default: <ws>/.auditooor/access_control_hypotheses.jsonl)")
    args = ap.parse_args(argv)

    ws = args.workspace.resolve()
    if not ws.is_dir():
        print(f"[err] workspace not found: {ws}", file=sys.stderr)
        return 1

    out = args.out or (ws / ACCESS_CONTROL_HYPOTHESES_REL)

    summary = run(ws, out)

    print(f"[ok] access-control-coverage wrote {out}")
    print(f"     hypotheses (needs-fuzz): {summary['hypotheses']}")
    print(f"     oos_dropped: {summary['oos_dropped']}")
    print(f"     typed_skip_notes: {summary['skip_notes']}")
    for lang, status in summary["arms"].items():
        print(f"     [{lang}] {status}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
