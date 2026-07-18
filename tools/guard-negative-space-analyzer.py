#!/usr/bin/env python3
"""Per-guard negative-space worklist analyzer (mechanical extract + agentic probe).

For every guard / validation in the in-scope source surface, this tool emits a
NEGATIVE-SPACE worklist row asking the question that static analysis cannot
answer on its own:

    "what does this guard NOT check; can an input pass it yet violate the
     invariant it is supposed to protect?"

This mirrors how the exploit-queue / dispatch worklists work: a MECHANICAL
extract step enumerates the surface and writes a per-guard worklist, then an
AGENTIC probe step (the workers) answers each row, and an INGEST step folds the
verdicts back in. The --check verdict certifies the per-guard delta layer is
complete (every in-scope guard has both a worklist row AND a probe verdict).

Files (all under <ws>/.auditooor/):
  inscope_units.jsonl            (denominator; read-only input)
  negative_space_worklist.jsonl  (--emit-worklist output, schema below)
  negative_space_gaps.jsonl      (--ingest output)

This pass does NOT write the R81 depth certificate. It only emits the per-row
worklist + gaps JSONL above; the SINGLE cert writer is
``tools/depth-certificate-build.py``, which rolls these rows up into
``<ws>/.auditooor/depth_certificate.json``. The depth-certificate GATE
(``tools/depth-certificate-check.py``) then reads that cert.

Schema: auditooor.guard_negative_space.v1

Modes:
  --workspace <ws> --emit-worklist        enumerate guards -> worklist rows
  --workspace <ws> --ingest <verdicts>     fold agent verdicts -> gaps file
  --workspace <ws> --check                 verdict + blindspot count
  [--json]                                 machine-readable output

Generic: any workspace, any language. Dependency-free stdlib python3.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA = "auditooor.guard_negative_space.v1"

# ---------------------------------------------------------------------------
# Single-source-of-truth scope exclusion. The OOS/test/vendored/generated
# decision lives in tools/lib/scope_exclusion.py so every coverage/depth gate
# agrees about "is this path in-scope protocol source". Path-load it (mirrors
# the sibling-tool loaders elsewhere in tools/) so this script runs both as a
# package module and as a bare ``python3 tools/guard-negative-space-analyzer.py``.
# ---------------------------------------------------------------------------
try:  # normal package import
    from tools.lib import scope_exclusion as _scope_exclusion  # type: ignore
except Exception:  # pragma: no cover - direct-script / odd-sys.path fallback
    _spec = importlib.util.spec_from_file_location(
        "scope_exclusion",
        Path(__file__).resolve().with_name("lib") / "scope_exclusion.py",
    )
    _scope_exclusion = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_scope_exclusion)

# Source-file extensions we will scan for guards. Anything else (docs, configs,
# vendored blobs) is skipped. This language-suffix filter is tool-specific and
# is kept separate from the shared scope-exclusion helper on purpose.
_SOURCE_EXTS = {".sol", ".vy", ".go", ".rs", ".move", ".cairo", ".ts", ".js", ".py"}

# ---------------------------------------------------------------------------
# Guard / validation detection patterns. Each entry is (kind, compiled-regex).
# These are deliberately language-agnostic and best-effort: the worklist row is
# a PROMPT for an agent, not a finding, so over-inclusion is acceptable. The
# agentic probe step is where false positives get ruled out.
# ---------------------------------------------------------------------------
_GUARD_PATTERNS: list[tuple[str, "re.Pattern[str]"]] = [
    # Solidity / generic require-style
    ("require", re.compile(r"\brequire\s*\(")),
    ("assert", re.compile(r"\bassert\s*\(")),
    ("revert", re.compile(r"\brevert\b")),
    ("if-revert", re.compile(r"\bif\s*\(.*\)\s*(\{)?\s*revert\b")),
    ("modifier", re.compile(r"\bmodifier\s+[A-Za-z_]\w*\s*\(")),
    ("modifier-use", re.compile(r"\bonly[A-Z]\w*\b")),
    # Rust / Move ensure / require / assert / early-return-Err
    ("ensure", re.compile(r"\bensure!\s*\(")),
    ("ensure-fn", re.compile(r"\bensure\s*\(")),
    ("rust-assert", re.compile(r"\b(assert!|assert_eq!|assert_ne!|debug_assert!)\s*\(")),
    ("return-err", re.compile(r"\breturn\s+Err\s*\(")),
    ("bail", re.compile(r"\bbail!\s*\(")),
    ("require-rs", re.compile(r"\brequire!\s*\(")),
    # Go / generic error-return guard
    ("go-err-return", re.compile(r"\bif\s+err\s*!=\s*nil\s*\{")),
    ("go-nil-check", re.compile(r"\bif\s+\w+\s*==\s*nil\s*\{")),
    # Go / Cosmos-SDK guard idioms (CamelCase + panic + error-return). The lowercase
    # verify/validate/check patterns below miss cosmos's CamelCase (ValidateBasic,
    # HasPermission, VerifySignature) and its primary guard form panic()/return
    # sdkerrors.Wrap - so cosmos-sdk/cometbft were extracting ~0 guards (bank
    # keeper.go: 10+ real guards, only 2 found). These restore cosmos/cometbft depth
    # coverage.
    ("go-panic", re.compile(r"\bpanic\s*\(")),
    ("cosmos-err-return", re.compile(r"\breturn\b.*\b(sdkerrors|errorsmod|cosmoserrors|ibcerrors)\.")),
    ("go-has-permission", re.compile(r"\bHasPermission\s*\(")),
    ("camel-verify-call", re.compile(r"\b(Verify|Validate|Check|Assert|Ensure|Require)[A-Za-z]*\s*\(")),
    # verify_* / validate_* / check_* style helper calls
    ("verify-call", re.compile(r"\b(verify|validate|check|assert)[A-Za-z_]*\s*\(")),
    ("verify-snake", re.compile(r"\b(verify|validate|check|assert)_[a-z_]+\s*\(")),
]

# ---------------------------------------------------------------------------
# Per-language guard-shape PRUNING (LG3). The broad _GUARD_PATTERNS above are
# language-agnostic and deliberately over-include (a worklist row is a PROMPT,
# not a finding). But on Go the broad set tags idiomatic boilerplate -
# ``if err != nil``, bare ``if x == nil { return ... }`` error-propagation,
# struct-field declarations, and bodyless interface method signatures - as
# "guards", which measured ~56% noise on bor. A real GUARD is a SECURITY-relevant
# check (auth / bounds / state), not control-flow plumbing.
#
# So after the broad match we apply a PER-LANGUAGE filter:
#   - solidity / vyper : keep require/revert/assert/modifier/if-revert and any
#                        comparison on state/auth/bounds; that is already the
#                        bulk of the broad set, so behavior is ~unchanged.
#   - go               : DROP bare error/nil-propagation, struct field decls, and
#                        bodyless interface signatures; KEEP auth/bounds/state
#                        conditionals and require/assert-style checks.
#   - rust             : keep require!/ensure!/assert!/bail!/return Err on a real
#                        condition and match-guards; DROP bodyless trait method
#                        signatures.
#   - default/unknown  : KEEP-ALL broad behavior (completeness-safe: over-include,
#                        never drop) and emit a loud WARN that precision for this
#                        language is degraded with a one-line manual step.
#
# The filter NEVER drops a line the broad set did not already match; it only
# prunes Go/Rust/Solidity boilerplate the broad set over-matched. Unknown
# languages are never pruned, so a brand-new language regresses to today's
# (broad) behavior, not to under-scoping.
# ---------------------------------------------------------------------------

_LANG_BY_EXT = {
    ".sol": "solidity",
    ".vy": "vyper",
    ".go": "go",
    ".rs": "rust",
    ".move": "move",
    ".cairo": "cairo",
    ".ts": "ts",
    ".js": "js",
    ".py": "py",
    ".huff": "huff",
}

# Languages we have a precision filter for. Anything else -> broad + WARN.
_PRECISION_LANGS = {"solidity", "vyper", "go", "rust"}

# Comparison / boolean operators - a line with one is a real conditional check
# rather than a bare declaration. Defined here (above the per-language filter
# that consumes it) so the boilerplate pruner can tell a struct-field decl from
# an ``if`` guard.
_COMPARISON_RE = re.compile(r"(==|!=|<=|>=|<|>|&&|\|\|)")

# Tokens that make a conditional SECURITY-relevant (auth / bounds / state).
# Used to rescue a Go ``if`` that the boilerplate filter would otherwise drop.
_SECURITY_COND_TOKENS = (
    "owner", "admin", "auth", "authorized", "sender", "caller", "isadmin",
    "permission", "role", "signer", "whitelist", "blacklist", "allowed",
    "balance", "amount", "supply", "len(", "length", "index", "cap",
    "bound", "limit", "min", "max", "overflow", "underflow", "exceed",
    "status", "state", "paused", "frozen", "locked", "active", "enabled",
    "expir", "deadline", "nonce", "replay", "valid", "verif",
)

# Go control-flow boilerplate that is NOT a security guard.
_GO_ERR_PROPAGATE_RE = re.compile(r"^if\s+err\s*(!=|==)\s*nil\s*\{?$")
# bare ``if x == nil {`` (single identifier vs nil) with no other condition.
_GO_BARE_NIL_RE = re.compile(r"^if\s+[A-Za-z_]\w*(\.[A-Za-z_]\w*)*\s*==\s*nil\s*\{?$")
# struct-field declaration line: ``Name Type`` / ``Name Type `tag`` `` inside a
# struct body - identifier(s) then a type, no call/comparison/keyword.
_GO_STRUCT_FIELD_RE = re.compile(
    r"^[A-Za-z_]\w*(\s*,\s*[A-Za-z_]\w*)*\s+[\*\[\]A-Za-z_][\w\.\*\[\]\{\}]*\s*(`[^`]*`)?$"
)
# bodyless interface method signature: ``Foo(args) ret`` with no ``{`` body and
# no leading ``func`` (we are inside an interface block). Ends without ``{``.
_GO_IFACE_SIG_RE = re.compile(r"^[A-Z]\w*\s*\([^)]*\)\s*[\w\.\*\[\]\(\), ]*$")
# Rust bodyless trait method signature: ``fn foo(&self, ...) -> T;`` ends with ;
_RUST_TRAIT_SIG_RE = re.compile(r"^(pub\s+)?fn\s+[A-Za-z_]\w*\s*[<(].*;\s*$")


def _detect_lang(rel: str) -> str:
    """Map a source path to a language id from its suffix (unknown -> ""))."""
    return _LANG_BY_EXT.get(Path(rel).suffix.lower(), "")


def _is_security_conditional(stripped: str) -> bool:
    """True if a conditional line references an auth / bounds / state token.

    Used to RESCUE a Go ``if`` that the boilerplate filter would drop: an
    ``if amount > cap`` or ``if !authorized`` is a real guard, only the bare
    err/nil-propagation plumbing is noise.
    """
    low = stripped.lower()
    if "!" in stripped and "!=" not in stripped:
        return True  # negation guard, e.g. ``if !authorized {`` / ``if !ok {``
    return any(tok in low for tok in _SECURITY_COND_TOKENS)


def _keep_guard_line(lang: str, stripped: str, kinds: list[str]) -> bool:
    """Per-language precision filter.

    Returns True to KEEP the line as a guard, False to PRUNE it as boilerplate.
    Only languages in _PRECISION_LANGS are pruned; every other language returns
    True (broad / completeness-safe). The caller is responsible for the unknown-
    language WARN.
    """
    if lang not in _PRECISION_LANGS:
        return True  # unknown language: never prune (over-include, never drop)

    if lang == "go":
        # Bare error / nil propagation: ``if err != nil {`` and a bare single-
        # identifier ``if x == nil {`` that the broad go-err/go-nil patterns
        # tagged. Drop UNLESS the line also carries a security token (defensive:
        # ``if owner == nil`` is a real auth guard).
        if _GO_ERR_PROPAGATE_RE.match(stripped) and not _is_security_conditional(stripped):
            return False
        if _GO_BARE_NIL_RE.match(stripped) and not _is_security_conditional(stripped):
            return False
        # struct-field declaration: only flagged because a field name contains a
        # verify/validate/check substring (the verify-call/snake patterns). A
        # field decl has no call/comparison -> prune.
        if _GO_STRUCT_FIELD_RE.match(stripped) and not _COMPARISON_RE.search(stripped) \
                and "(" not in stripped:
            return False
        # bodyless interface method signature flagged by verify-call: no body,
        # no comparison, ends without ``{`` -> a signature, not a runtime guard.
        if (_GO_IFACE_SIG_RE.match(stripped) and not stripped.rstrip().endswith("{")
                and not _COMPARISON_RE.search(stripped)
                and not any(k in kinds for k in ("require", "assert", "revert"))):
            return False
        return True

    if lang == "rust":
        # bodyless trait method signature (``fn foo(..) -> T;``) flagged by the
        # verify-call pattern when the fn name starts with verify/validate/check.
        if _RUST_TRAIT_SIG_RE.match(stripped):
            return False
        return True

    # solidity / vyper: the broad set is already require/revert/assert/modifier
    # plus comparisons - all security-relevant. Keep all.
    return True


# Patterns whose match is the WHOLE-LINE guard intent (cheap "checks_what" hint).
_COMPARISON_RE = re.compile(r"(==|!=|<=|>=|<|>|&&|\|\|)")
_INVARIANT_HINT_TOKENS = [
    ("balance", "value-conservation / balance non-underflow"),
    ("amount", "amount bound / non-zero / non-overflow"),
    ("owner", "authorization: caller is owner"),
    ("auth", "authorization invariant"),
    ("sender", "msg.sender / caller identity"),
    ("nonce", "replay protection (nonce monotonicity)"),
    ("deadline", "time / expiry bound"),
    ("expir", "time / expiry bound"),
    ("signature", "signature validity / non-replay"),
    ("sig", "signature validity / non-replay"),
    ("status", "state-machine status invariant"),
    ("leaf", "tree-state / leaf-status invariant"),
    ("price", "price-bound / oracle-freshness"),
    ("slippage", "slippage bound"),
    ("supply", "total-supply conservation"),
    ("len", "length / bounds check"),
    ("index", "index in-bounds"),
    ("zero", "non-zero / zero-address guard"),
    ("paused", "pause-state guard"),
    ("reentr", "reentrancy guard"),
]


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _is_vendored(rel: str) -> bool:
    """OOS (test / vendored-DIR / dependency / generated) classifier for rows that
    are ALREADY in the curated, fork-scoped inscope_units.jsonl manifest.

    Uses scope_exclusion.is_oos_DIR (directory-shape only), NOT is_oos: is_oos
    treats cosmos-sdk / cometbft / wasmd as vendored NAME markers and would drop
    the in-scope FORK repos that ARE the audit target (e.g. an audit of
    0xPolygon/cosmos-sdk under src/cosmos-sdk) - measured: it dropped ALL cosmos-sdk
    (435) + cometbft (72) guards to 0. is_oos_dir drops test/mock/generated/
    vendored-DIR pollution (_test.go, .pb.go, DO NOT EDIT, vendor/) while KEEPING
    the fork's production source. This mirrors scope_exclusion.is_in_scope's own
    pollution backstop (is_oos_dir, not is_oos) for manifest rows. bor/Solidity are
    unaffected (they are not vendored NAME markers). The worklist must never emit an
    OOS-guard packet, but must also never drop an in-scope fork.
    """
    return _scope_exclusion.is_oos_dir(rel)


# Dev-tooling / build-config files carry NO on-chain value-moving guard: they are
# never deployed and never an enforcement point (a hardhat.config.js "guard" at
# line 1 is a negative-space FP that pins the depth cert at depth-pending). Exclude
# them by BASENAME only - a name-based filter is safe here (unlike the cosmos-sdk
# NAME markers that would drop in-scope forks), and it must NOT touch real Oscript/
# JS contract sources (obyte AAs are objects, never *.config.js / build manifests).
_DEV_TOOLING_CONFIG_BASENAMES = {
    "hardhat.config.js", "hardhat.config.ts", "foundry.toml", "remappings.txt",
    "truffle-config.js", "truffle.js", "package.json", "package-lock.json",
    "tsconfig.json", "babel.config.js", "jest.config.js", "solhint.config.js",
    "webpack.config.js", "rollup.config.js", "commitlint.config.js",
    ".eslintrc.js", ".prettierrc.js",
}
_DEV_TOOLING_CONFIG_SUFFIXES = (
    ".config.js", ".config.ts", ".config.mjs", ".config.cjs",
)


def _is_dev_tooling_config(rel: str) -> bool:
    base = (rel or "").rsplit("/", 1)[-1].lower()
    if base in _DEV_TOOLING_CONFIG_BASENAMES:
        return True
    return base.endswith(_DEV_TOOLING_CONFIG_SUFFIXES)


def _norm_rel(file_part: str) -> str:
    return (file_part or "").strip().lstrip("./")


def _load_inscope_units(ws: Path) -> list[dict]:
    """Load in-scope units as {file, function, file_line} dicts (best-effort).

    Accepts rows of shape {"file","function","file_line"} or {"unit":"path::fn"}.
    Vendored / test units are filtered out. The set of in-scope FILES (derived
    from these units) is the denominator for guard enumeration.
    """
    p = ws / ".auditooor" / "inscope_units.jsonl"
    if not p.is_file():
        return []
    out: list[dict] = []
    seen: set[str] = set()
    try:
        lines = p.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            d = json.loads(line)
        except ValueError:
            continue
        fp = fn = fl = None
        if d.get("unit") and "::" in str(d["unit"]):
            fp, fn = str(d["unit"]).rsplit("::", 1)
        elif d.get("file"):
            fp, fn = str(d["file"]), str(d.get("function") or "")
        if not fp:
            continue
        fl = str(d.get("file_line") or "")
        rel = _norm_rel(fp)
        if not rel or _is_vendored(rel) or _is_dev_tooling_config(rel):
            continue
        key = f"{rel}::{fn}::{fl}"
        if key in seen:
            continue
        seen.add(key)
        out.append({"file": rel, "function": fn, "file_line": fl})
    return out


def _inscope_files(ws: Path, units: list[dict]) -> list[str]:
    """Unique in-scope source files (relative paths) with a scannable extension."""
    files: list[str] = []
    seen: set[str] = set()
    for u in units:
        rel = u.get("file") or ""
        if not rel or rel in seen:
            continue
        if Path(rel).suffix.lower() not in _SOURCE_EXTS:
            continue
        seen.add(rel)
        files.append(rel)
    return files


def _checks_what(line: str) -> str:
    """Best-effort static description of what a guard line checks."""
    snippet = line.strip()
    if len(snippet) > 160:
        snippet = snippet[:157] + "..."
    return snippet


def _invariant_hint(line: str) -> str:
    low = line.lower()
    hints: list[str] = []
    for tok, hint in _INVARIANT_HINT_TOKENS:
        if tok in low:
            hints.append(hint)
    if hints:
        # dedupe preserving order
        seen: set[str] = set()
        uniq = [h for h in hints if not (h in seen or seen.add(h))]
        return "; ".join(uniq[:3])
    return "unknown - agent to infer the protected invariant from context"


def _scan_file_for_guards(ws: Path, rel: str) -> list[dict]:
    """Scan one in-scope source file and return raw guard hits."""
    p = ws / rel
    if not p.is_file():
        return []
    try:
        text = p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    lines = text.splitlines()
    # TEST FILTER: a guard inside a Rust #[cfg(test)]/#[test] item is a TEST
    # oracle, not a production runtime guard. Skip those spans so the worklist
    # this tool emits agrees with the probe-packet set guard-context-extract.py
    # emits - otherwise the cert enumerates guards the probe never receives and
    # depth_certificate is pinned at depth-pending forever (optimism op-reth:
    # ~910 of 1905 worklist rows were #[cfg(test)] assert_eq! oracles). Shared,
    # single-source helper so the two tools cannot drift.
    test_lines = _scope_exclusion.rust_test_line_ranges(lines)  # 0-based indices
    # Per-language guard-shape precision (LG3). Unknown languages keep the broad
    # behavior (over-include, never drop) and surface a one-time WARN so the
    # degraded precision is loud, never silent.
    lang = _detect_lang(rel)
    if lang not in _PRECISION_LANGS:
        print(
            f"[guard-negative-space-analyzer] WARN guard-shape precision is "
            f"DEGRADED for '{rel}' (language='{lang or 'unknown'}'): no "
            f"per-language boilerplate filter, keeping ALL matched lines "
            f"(completeness-safe over-include). Manual step: review "
            f"negative_space_worklist.jsonl rows for this language and prune "
            f"non-security boilerplate by hand, or add '{lang or Path(rel).suffix}' "
            f"to _PRECISION_LANGS with a filter in guard-negative-space-analyzer.py.",
            file=sys.stderr,
        )
    hits: list[dict] = []
    for lineno, raw in enumerate(lines, start=1):
        if (lineno - 1) in test_lines:
            continue
        stripped = raw.strip()
        if not stripped:
            continue
        # skip pure comment lines (cheap, language-agnostic)
        if stripped.startswith(("//", "#", "*", "/*")):
            continue
        kinds: list[str] = []
        for kind, rx in _GUARD_PATTERNS:
            if rx.search(raw):
                kinds.append(kind)
        if not kinds:
            continue
        # PER-LANGUAGE PRUNE: drop language-idiom boilerplate (Go err/nil
        # propagation, struct-field decls, bodyless interface/trait signatures)
        # that the broad set over-matched. Unknown langs are never pruned.
        if not _keep_guard_line(lang, stripped, kinds):
            continue
        hits.append({
            "file": rel,
            "line": lineno,
            "kinds": sorted(set(kinds)),
            "text": raw.rstrip(),
        })
    return hits


def _guard_subject(rel: str, text: str) -> str:
    """Guard IDENTITY key for de-duplication. The negative-space question is a
    property of the GUARD (the checked function / condition), not each call
    site. So all call sites of one guard fn collapse to a single worklist row,
    while genuinely-distinct inline guards (asserts/conditions) stay separate.
    Generic / language-agnostic (best-effort identifier extraction)."""
    t = text.strip()
    m = re.search(r"\bfn\s+([A-Za-z_][A-Za-z0-9_]*)\s*[<(]", t)
    if m:
        return f"{rel}::fn::{m.group(1)}"            # guard definition
    m = re.match(r"\s*([A-Za-z_][A-Za-z0-9_]*)\s*!\s*\(", t)
    if m:                                            # macro guard: keep the condition so distinct asserts stay distinct
        cond = re.sub(r"\s+", "", t)[:80]
        return f"{rel}::{m.group(1)}::{cond}"
    m = re.match(r"\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(", t)
    if m and m.group(1) not in ("if", "while", "for", "match", "return"):
        return f"{rel}::call::{m.group(1)}"          # call site of a check fn -> collapse all args/lines
    return f"{rel}::{re.sub(r'\s+', '', t)[:80]}"   # inline guard -> normalized condition


def _guard_id(rel: str, line: int, text: str) -> str:
    h = hashlib.sha256(f"{rel}:{line}:{text.strip()}".encode("utf-8")).hexdigest()[:12]
    return f"NS-{h}"


def emit_worklist(ws: Path) -> dict:
    """Mechanical extract: enumerate every in-scope guard -> worklist rows."""
    units = _load_inscope_units(ws)
    files = _inscope_files(ws, units)
    rows: list[dict] = []
    for rel in files:
        for hit in _scan_file_for_guards(ws, rel):
            text = hit["text"]
            gid = _guard_id(rel, hit["line"], text)
            rows.append({
                "schema": SCHEMA,
                "guard_id": gid,
                "file_line": f"{rel}:{hit['line']}",
                "kinds": hit["kinds"],
                "checks": _checks_what(text),
                "invariant_hint": _invariant_hint(text),
                "question": (
                    "what does this guard NOT check; can an input pass it yet "
                    "violate the invariant"
                ),
                "emitted_at": _now(),
            })
    # de-dupe by guard SUBJECT (the checked fn / condition identity), not by
    # file+line+text: all call sites of one guard fn collapse to a single row so
    # the depth probe is not over-enumerated and honest analysis of repeated code
    # is not rejected as a near-identical template cluster. (Sibling-path
    # asymmetry across call sites is the SEPARATE sibling-diff depth pass.)
    seen: set[str] = set()
    uniq: list[dict] = []
    for r in rows:
        rel_f = str(r["file_line"]).rsplit(":", 1)[0]
        subj = _guard_subject(rel_f, str(r.get("checks") or ""))
        if subj in seen:
            continue
        seen.add(subj)
        uniq.append(r)

    out_dir = ws / ".auditooor"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "negative_space_worklist.jsonl"
    with out_path.open("w", encoding="utf-8") as fh:
        for r in uniq:
            fh.write(json.dumps(r, sort_keys=True) + "\n")
    return {
        "schema": SCHEMA,
        "mode": "emit-worklist",
        "inscope_files": len(files),
        "inscope_units": len(units),
        "guards_enumerated": len(uniq),
        "worklist_path": str(out_path),
    }


def _load_worklist(ws: Path) -> list[dict]:
    p = ws / ".auditooor" / "negative_space_worklist.jsonl"
    if not p.is_file():
        return []
    rows: list[dict] = []
    try:
        for line in p.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except ValueError:
                continue
    except OSError:
        return []
    return rows


def ingest(ws: Path, verdicts_path: Path) -> dict:
    """Fold agent verdicts back in -> negative_space_gaps.jsonl.

    Each verdict row is expected to carry at least:
      guard_id            (matches a worklist row)
      gap_found           (bool)
      kind                (free-form classification of the gap)
      passing_but_malicious_input  (the input that passes the guard yet breaks
                                    the invariant; the exploitation-attempt seed)

    Verdicts referencing an unknown guard_id are kept but flagged
    unknown_guard:true so nothing is silently dropped.
    """
    worklist = {r.get("guard_id"): r for r in _load_worklist(ws)}
    if not verdicts_path.is_file():
        return {
            "schema": SCHEMA,
            "mode": "ingest",
            "error": f"verdicts file not found: {verdicts_path}",
            "ingested": 0,
        }
    gaps: list[dict] = []
    ingested = 0
    try:
        lines = verdicts_path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        return {
            "schema": SCHEMA,
            "mode": "ingest",
            "error": f"cannot read verdicts: {exc}",
            "ingested": 0,
        }
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            v = json.loads(line)
        except ValueError:
            continue
        gid = v.get("guard_id")
        if not gid:
            continue
        ingested += 1
        wl = worklist.get(gid)
        gap = {
            "schema": SCHEMA,
            "guard_id": gid,
            "file_line": (wl or {}).get("file_line") or v.get("file_line") or "",
            "gap_found": bool(v.get("gap_found")),
            "kind": v.get("kind") or "",
            "passing_but_malicious_input": v.get("passing_but_malicious_input") or "",
            "exploitation_attempt_artifact": (
                v.get("exploitation_attempt_artifact")
                or v.get("ruled_out")
                or ""
            ),
            "unknown_guard": wl is None,
            "ingested_at": _now(),
        }
        gaps.append(gap)

    out_path = ws / ".auditooor" / "negative_space_gaps.jsonl"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as fh:
        for g in gaps:
            fh.write(json.dumps(g, sort_keys=True) + "\n")
    return {
        "schema": SCHEMA,
        "mode": "ingest",
        "ingested": ingested,
        "gaps_found": sum(1 for g in gaps if g["gap_found"]),
        "gaps_path": str(out_path),
    }


def _load_gaps(ws: Path) -> dict[str, dict]:
    p = ws / ".auditooor" / "negative_space_gaps.jsonl"
    out: dict[str, dict] = {}
    if not p.is_file():
        return out
    try:
        for line in p.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                g = json.loads(line)
            except ValueError:
                continue
            gid = g.get("guard_id")
            if gid:
                out[gid] = g
    except OSError:
        return out
    return out


def check(ws: Path) -> dict:
    """--check verdict: is the per-guard negative-space layer complete?

    pass-negative-space-complete iff EVERY in-scope guard (worklist row) has a
    matching verdict (gap row). Otherwise:
      fail-no-worklist           no worklist emitted at all
      needs-probing              worklist exists but >=1 guard has no verdict
    The blindspot is the count of guards with NO exploitation-attempt verdict.
    """
    worklist = _load_worklist(ws)
    gaps = _load_gaps(ws)
    total_guards = len(worklist)
    if total_guards == 0:
        return {
            "schema": SCHEMA,
            "mode": "check",
            "verdict": "fail-no-worklist",
            "total_guards": 0,
            "guards_with_verdict": 0,
            "blindspot_no_exploitation_attempt": 0,
            "coverage_pct": 0.0,
            "detail": "no negative_space_worklist.jsonl - run --emit-worklist",
        }
    probed = 0
    no_attempt: list[str] = []
    for r in worklist:
        gid = r.get("guard_id")
        g = gaps.get(gid)
        if g is None:
            no_attempt.append(gid)
            continue
        probed += 1
        # a verdict counts as a real exploitation-attempt only if it carries
        # either an exploitation artifact OR an explicit ruled-out citation.
        if not (g.get("exploitation_attempt_artifact") or "").strip():
            no_attempt.append(gid)
    coverage = round(probed / total_guards, 4) if total_guards else 0.0
    blindspot = len(no_attempt)
    if blindspot == 0 and probed == total_guards:
        verdict = "pass-negative-space-complete"
    elif probed == 0:
        verdict = "needs-probing"
    else:
        verdict = "coverage-below"
    return {
        "schema": SCHEMA,
        "mode": "check",
        "verdict": verdict,
        "total_guards": total_guards,
        "guards_with_verdict": probed,
        "blindspot_no_exploitation_attempt": blindspot,
        "blindspot_guard_ids": no_attempt[:40],
        "coverage_pct": coverage,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--workspace", required=True, help="workspace root")
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--emit-worklist", action="store_true")
    mode.add_argument("--ingest", metavar="VERDICTS_JSONL")
    mode.add_argument("--check", action="store_true")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    ws = Path(args.workspace).expanduser().resolve()
    if not ws.is_dir():
        out = {"schema": SCHEMA, "error": f"workspace not found: {ws}"}
        print(json.dumps(out) if args.json else out["error"], file=sys.stderr)
        return 2

    if args.emit_worklist:
        res = emit_worklist(ws)
    elif args.ingest:
        res = ingest(ws, Path(args.ingest).expanduser().resolve())
    else:
        res = check(ws)

    if args.json:
        print(json.dumps(res, indent=2, sort_keys=True))
    else:
        for k, v in res.items():
            print(f"{k}: {v}")

    # Exit non-zero only for the --check fail verdicts so the gate can branch.
    if res.get("mode") == "check":
        if res.get("verdict") != "pass-negative-space-complete":
            return 1
    if res.get("error"):
        return 2
    # Precondition failure: inscope_units.jsonl is absent or empty.
    # Return rc=1 so the Makefile advisory WARN fires visibly instead of
    # silently producing an empty worklist.  rc=1 is distinct from rc=2
    # (hard error); the Makefile treats both as WARN-and-continue.
    if res.get("mode") == "emit-worklist" and res.get("inscope_files", -1) == 0:
        if not args.json:
            print(
                "[guard-negative-space-analyzer] WARN inscope_units.jsonl has 0 units "
                "- run 'make audit WS=<ws>' or "
                "'python3 tools/workspace-coverage-heatmap.py --emit-inscope-manifest "
                "--workspace-path <ws> --force' first",
                file=sys.stderr,
            )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
