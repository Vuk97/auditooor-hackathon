#!/usr/bin/env python3
"""toolchain-flag-drift-screen.py - GEN-EL6, the TOOLCHAIN-FLAG SEMANTIC-DRIFT
screen (enforcement-layer = build-config).

GENERAL LOGIC (impact-agnostic, NORTH-STAR; the BUILD TOOLCHAIN is a TRUSTED
enforcement - source-level safety assumptions are only real if the compile flags
PRESERVE the semantics the source assumes). A build/toolchain flag that changes
program SEMANTICS (not merely optimization) can SILENTLY INVALIDATE a source-
level safety assumption. This tool is a CONFIG-FILE screen (parse
Cargo.toml / foundry.toml / hardhat.config / go build tags) that flags the
semantic-changing flags, JOINED against the source assumption where detectable.

FIRE (semantic flags only - see FP-CONTROL, never a plain optimizer toggle):
  (1) RUST overflow-checks (Cargo.toml [profile.release]): overflow-checks off
      or DEFAULTED-off in the release profile WHILE the source relies on
      arithmetic-overflow PANIC as a safety check. In release, `a + b` WRAPS
      silently instead of panicking - a checked security invariant disappears.
      REQUIRES BOTH: (config) overflow-checks false/defaulted in release, AND
      (source) >=1 site with security-relevant BARE arithmetic (+/-/* on
      integers, not checked_add / saturating_ / wrapping_). Config alone on a
      repo that uses only checked_* is LOW/SKIP.  drift_kind=overflow-checks-off
  (2) SOLIDITY evmVersion (foundry.toml/hardhat): evm_version = cancun|prague
      enables TSTORE/TLOAD/MCOPY (transient storage + memcopy) opcodes the source
      may not expect (transient-storage reentrancy surface), or a target chain
      that does not support the opcode = deploy-time brick; shanghai enables
      PUSH0 (older L2s brick).  drift_kind=evmversion-opcode
      If the SAME config declares TWO DIFFERENT evm_versions across profiles /
      additional_compilers, that is an intra-config semantic split
      (drift_kind=pin-flag-mismatch, higher severity).
  (3) SOLIDITY viaIR (via_ir = true) JOINED against an inline-`assembly {` /
      codegen assumption in source - the IR pipeline changes codegen and stack
      layout an assembly block may rely on.  drift_kind=viair-codegen
  (4) GO build tags (`//go:build !prod` / `// +build !prod`) that gate OUT a
      validation / guard path in ONE build config.  drift_kind=build-tag-gate

FP-CONTROL (semantic flags only, NOT benign optimization):
  * plain `optimizer = true` / `opt-level = 3` is PURE optimization -> NEVER
    flagged. The signal is a flag that changes OBSERVABLE SEMANTICS:
    overflow-checks (panic-vs-wrap), evmVersion (opcode availability), a code-
    path-gating build tag, viaIR only paired with an assembly/codegen assumption.
  * RUST overflow arm requires BOTH config AND >=1 bare-arithmetic source site.
    overflow-checks = true -> SILENT. A crate that only ever calls checked_add /
    saturating_add -> SILENT even with overflow-checks off.
  * SOLIDITY paris/london/etc evm_version (no new opcode) -> SILENT.
  * viaIR without any inline assembly in source -> SILENT.

DEDUP / distinctness (per dispatch brief):
  * stale-pin-check.py checks the local src git HEAD vs the DECLARED pin
    (source-tree-vs-pin) - it never parses build FLAGS. GEN-EL6 adds the
    build-flag / evmVersion axis at an IDENTICAL source pin. Decision: kept as a
    SIBLING screen (not an in-place extension) because stale-pin-check has a
    different CLI shape (positional workspace, no JSONL sidecar), a different
    schema, and mixes a git-SHA concern with this config-flag concern; a callable
    `check_toolchain_flag_drift(ws)` API is exposed so stale-pin-check MAY call
    it, without coupling the two strict-exit semantics.
  * compiler-known-bug-shape-join / E2 (compiler-feature-screen) check a solc
    VERSION feature-window BUG (version-in-affected-range + source shape). GEN-EL6
    checks a build-FLAG-changes-semantics vs deployed/source mismatch - a flag
    axis, not a compiler-version-bug axis.
  * GEN-EL5 gas-repricing-fragility screens a source GAS CONSTANT (a magic number
    in source), not a config flag.
  GEN-EL6 = the build-flag-changes-semantics vs source-assumption JOIN.

ADVISORY-FIRST: every row carries verdict='needs-fuzz', advisory=True,
auto_credit=False; the tool exits 0 by default. The opt-in env
AUDITOOOR_TOOLCHAIN_FLAG_DRIFT_STRICT (or --strict) raises the exit code when a
fired row exists.

Excludes machine-generated + test + vendored config/source via the shared libs.

Usage:
  --workspace <ws>   scan <ws> (src/ preferred) -> .auditooor/
                     toolchain_flag_drift_hypotheses.jsonl + summary
  --source <dir>     scan an arbitrary dir, print rows as JSON (NO sidecar)
  --check            re-read the emitted sidecar, print cert verdict (advisory)
  --strict           (or env) elevate exit code when a fired row exists
  --json             machine summary to stdout
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path

HYP_SCHEMA = "auditooor.toolchain_flag_drift_hypotheses.v1"
_SIDE_NAME = "toolchain_flag_drift_hypotheses.jsonl"
_STRICT_ENV = "AUDITOOOR_TOOLCHAIN_FLAG_DRIFT_STRICT"
_CAPABILITY = "GEN_EL6"

TOOLS_DIR = Path(__file__).resolve().parent
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

# --- shared exclusion (reuse, never rebuild) --------------------------------
try:  # tools/lib/synthetic_target_exclusion.py
    from lib.synthetic_target_exclusion import (  # noqa: E402
        is_chimera_mutation_harness_path,
        is_codegen_path,
        is_test_target_path,
    )
except Exception:  # pragma: no cover - degrade to no-op if lib unavailable
    def is_test_target_path(_p):  # type: ignore
        return False

    def is_codegen_path(_p, workspace=None):  # type: ignore
        return False

    def is_chimera_mutation_harness_path(_p):  # type: ignore
        return False


_SKIP_DIRS = {"target", ".git", "node_modules", "vendor", "_archive", "out",
              "cache", "lib", "__pycache__", "dist", "build", ".auditooor",
              "benches", "benchmarks", "script", "scripts", "deployments",
              "prior_audits", "reference", "certora", "simulation", "testdata",
              "mocks", "mock", "artifacts", "chimera_harnesses", "poc-tests"}
_TEST_HINT = re.compile(
    r"(^|/)(tests?|testutil|testonly|testhelper|test_fixtures|mock|mocks|"
    r"benches|benchmarks?|examples|fixtures|simulation|simapp|testdata|poc|"
    r"poc-tests|chimera_harnesses|"
    r"[a-z0-9_.-]*test[_-]?contracts?[a-z0-9_.-]*)(/|$)")

# opcode-introducing EVM versions (each introduces observable new opcodes)
_EVM_OPCODE_INTRO = {
    "shanghai": "PUSH0",
    "cancun": "TSTORE/TLOAD/MCOPY",
    "prague": "TSTORE/TLOAD/MCOPY (+EIP-7702 set-code)",
    "osaka": "TSTORE/TLOAD/MCOPY",
}
# semantically-neutral (no new opcode) -> SILENT for the opcode arm
_EVM_NEUTRAL = {"homestead", "tangerinewhistle", "spuriousdragon", "byzantium",
                "constantinople", "petersburg", "istanbul", "berlin", "london",
                "paris"}


# ============================================================================
# stable id + helpers
# ============================================================================
def _stable_id(rel, drift_kind, subject, line):
    h = hashlib.sha1()
    h.update(f"{rel}|{drift_kind}|{subject}|{line}".encode())
    return h.hexdigest()[:16]


def _line_of_offset(text: str, off: int) -> int:
    return text.count("\n", 0, off) + 1


def _excerpt_line(text: str, off: int) -> str:
    ls = text.rfind("\n", 0, off) + 1
    le = text.find("\n", off)
    if le == -1:
        le = len(text)
    return text[ls:le].strip()[:200]


# ============================================================================
# row builder
# ============================================================================
def _mk_row(rel, line, lang, config_key, config_value, drift_kind,
            source_assumption, excerpt, severity, why):
    return {
        "schema": HYP_SCHEMA,
        "capability": _CAPABILITY,
        "id": _stable_id(rel, drift_kind, f"{config_key}|{config_value}", line),
        "file": rel,
        "line": line,
        "config_key": config_key,
        "config_value": config_value,
        "lang": lang,
        "drift_kind": drift_kind,
        "source_assumption": source_assumption,
        "excerpt": excerpt,
        "severity": severity,
        "why_severity_anchored": why,
        "fires": True,
        "verdict": "needs-fuzz",
        "advisory": True,
        "auto_credit": False,
    }


# ============================================================================
# RUST arm: Cargo.toml [profile.release] overflow-checks JOIN source arithmetic
# ============================================================================
# find a `[profile.release]` (or bench, which inherits release) header line
_PROFILE_HEADER_RE = re.compile(r"^\s*\[profile\.(release|bench)\]\s*$")
_OVERFLOW_RE = re.compile(r"^\s*overflow-checks\s*=\s*(true|false)\b")
_TABLE_HEADER_RE = re.compile(r"^\s*\[")

# bare arithmetic in Rust source: WORD op WORD where op in + - *, excluding the
# safe wrapping/checked helpers and obvious non-arithmetic uses.
_RUST_ARITH_RE = re.compile(
    r"[A-Za-z_][\w.]*(?:\[[^\]\n]*\])?\s*([+\-*])\s*"
    r"[A-Za-z_0-9][\w.]*(?:\[[^\]\n]*\])?")
_RUST_SAFE_HINT = re.compile(
    r"checked_(add|sub|mul|div|pow)|saturating_|wrapping_|overflowing_|"
    r"checked_add|\.pow\(")
# lines that are trait bounds / generics / pointers where + / * are not arith
_RUST_NONARITH_LINE = re.compile(
    r"\bwhere\b|\bimpl\b|\bdyn\b|\+\s*'|\bfn\s+\w+\s*<|->\s*impl|"
    r"\*mut\b|\*const\b|use\s+|#\[|derive\(")


def _rust_release_overflow_state(toml_text: str):
    """Return (state, line, excerpt) for the release/bench profile:
       state in {'true','false','defaulted','none'}.
       'defaulted' = release profile block present but overflow-checks absent
       (cargo defaults overflow-checks OFF in release).
       'none' = no release/bench profile block at all."""
    lines = toml_text.splitlines()
    in_release = False
    release_line = 0
    release_excerpt = ""
    seen_release = False
    for i, ln in enumerate(lines):
        if _PROFILE_HEADER_RE.match(ln):
            in_release = True
            seen_release = True
            release_line = i + 1
            release_excerpt = ln.strip()
            continue
        if in_release and _TABLE_HEADER_RE.match(ln):
            in_release = False
        if in_release:
            m = _OVERFLOW_RE.match(ln)
            if m:
                return m.group(1), i + 1, ln.strip()
    if seen_release:
        return "defaulted", release_line, release_excerpt
    return "none", 0, ""


def _rust_bare_arith_site(rs_text: str):
    """First (line, excerpt) with a security-relevant bare arithmetic op, or
    None. Comments/strings are not fully masked (cheap heuristic) but // and
    safe-helper lines are skipped."""
    for i, ln in enumerate(rs_text.splitlines()):
        code = ln.split("//", 1)[0]
        if not code.strip():
            continue
        if _RUST_SAFE_HINT.search(code) or _RUST_NONARITH_LINE.search(code):
            continue
        m = _RUST_ARITH_RE.search(code)
        if not m:
            continue
        # a lone `*` that is really a deref (unary) won't match because we
        # require a word char immediately before the operator group.
        return i + 1, code.strip()[:200]
    return None


def _iter_rust_sources(root: Path, workspace: Path = None):
    for dp, dn, fn in os.walk(root):
        dn[:] = [d for d in dn if d not in _SKIP_DIRS]
        if _TEST_HINT.search(dp.replace(os.sep, "/")):
            continue
        for f in fn:
            if not f.endswith(".rs"):
                continue
            low = f.lower()
            if low.startswith("test") or "_test" in low or low == "tests.rs":
                continue
            p = Path(dp) / f
            rel = str(p)
            if (is_test_target_path(rel)
                    or is_chimera_mutation_harness_path(rel)
                    or is_codegen_path(rel, workspace)):
                continue
            yield p


def _scan_cargo(path: Path, rel: str, cargo_dir: Path, workspace: Path,
                rows, toml_text: str = None):
    txt = toml_text if toml_text is not None else path.read_text(
        encoding="utf-8", errors="ignore")
    state, line, excerpt = _rust_release_overflow_state(txt)
    if state == "true" or state == "none":
        # overflow-checks explicitly ON, or no release profile here -> SILENT.
        return
    # config side satisfied (false or defaulted-off). JOIN against source.
    site = None
    for rs in _iter_rust_sources(cargo_dir, workspace):
        site = _rust_bare_arith_site(
            rs.read_text(encoding="utf-8", errors="ignore"))
        if site:
            src_rel = str(rs)
            try:
                src_rel = str(rs.relative_to(cargo_dir))
            except ValueError:
                pass
            break
    if not site:
        # config alone, no bare arithmetic (all checked_*) -> SKIP (FP-control).
        return
    src_line, src_excerpt = site
    off_state = "explicitly false" if state == "false" else \
        "DEFAULTED off (cargo release default)"
    rows.append(_mk_row(
        rel, line, "rust", "profile.release.overflow-checks",
        state if state == "false" else "<absent:defaulted-false>",
        "overflow-checks-off",
        f"{src_rel}:{src_line} `{src_excerpt}` - bare integer arithmetic that "
        f"relies on debug overflow PANIC as a safety check",
        excerpt or "[profile.release]", "medium",
        f"Cargo release profile has overflow-checks {off_state}, so integer "
        f"`+`/`-`/`*` WRAP silently in the deployed release build instead of "
        f"panicking. Source site `{src_excerpt}` uses BARE arithmetic (not "
        f"checked_*/saturating_*), so an overflow-panic safety assumption that "
        f"holds under `cargo test`/debug DISAPPEARS in release - a checked "
        f"security invariant is silently invalidated by the build flag. Use "
        f"checked_*/saturating_* or set overflow-checks = true."))


# ============================================================================
# SOLIDITY arm: foundry.toml / hardhat.config evmVersion + viaIR
# ============================================================================
_EVM_VERSION_RE = re.compile(
    r"""evm[_-]?version\s*[:=]\s*['"]?([A-Za-z0-9]+)['"]?""", re.I)
_VIA_IR_RE = re.compile(r"""via[_-]?ir\s*[:=]\s*(true)\b""", re.I)


def _has_inline_assembly(sol_root: Path, workspace: Path = None) -> bool:
    for dp, dn, fn in os.walk(sol_root):
        dn[:] = [d for d in dn if d not in _SKIP_DIRS]
        if _TEST_HINT.search(dp.replace(os.sep, "/")):
            continue
        for f in fn:
            if not f.endswith(".sol"):
                continue
            low = f.lower()
            if low.endswith(".t.sol") or low.endswith(".s.sol") \
                    or low.startswith("mock") or low.startswith("test"):
                continue
            p = Path(dp) / f
            if (is_test_target_path(str(p))
                    or is_codegen_path(str(p), workspace)):
                continue
            try:
                if re.search(r"\bassembly\s*(\"memory-safe\"\s*)?\{",
                             p.read_text(encoding="utf-8", errors="ignore")):
                    return True
            except OSError:
                continue
    return False


def _scan_foundry(path: Path, rel: str, cfg_dir: Path, workspace: Path,
                  rows, cfg_text: str = None):
    txt = cfg_text if cfg_text is not None else path.read_text(
        encoding="utf-8", errors="ignore")
    lines = txt.splitlines()

    # --- evmVersion (opcode availability) -----------------------------------
    versions = []  # (version_lower, line, excerpt)
    for i, ln in enumerate(lines):
        for m in _EVM_VERSION_RE.finditer(ln):
            versions.append((m.group(1).lower(), i + 1, ln.strip()[:200]))
    distinct = {v for v, _, _ in versions}
    opcode_versions = [t for t in versions if t[0] in _EVM_OPCODE_INTRO]

    # intra-config split: >=2 distinct evm_versions declared -> semantic drift.
    if len(distinct) >= 2:
        v0, line0, exc0 = versions[0]
        rows.append(_mk_row(
            rel, line0, "solidity", "evm_version", "|".join(sorted(distinct)),
            "pin-flag-mismatch",
            "the same build config compiles different sources under different "
            "EVM versions - opcode availability differs per profile/path",
            exc0, "medium",
            f"foundry config declares MULTIPLE distinct evm_versions "
            f"({sorted(distinct)}) across profiles/additional_compilers, so "
            f"different contracts are built with a different opcode set (e.g. "
            f"one path gets TSTORE/TLOAD/MCOPY, another does not). A source "
            f"assumption valid under one evm_version (transient storage, mcopy, "
            f"push0) is INVALID for the sibling profile - a silent semantic "
            f"split. Pin a single evm_version or prove each path's opcode set."))

    for ver, line, exc in opcode_versions:
        opcodes = _EVM_OPCODE_INTRO[ver]
        sev = "medium" if ver in ("cancun", "prague") else "low"
        rows.append(_mk_row(
            rel, line, "solidity", "evm_version", ver, "evmversion-opcode",
            f"deployed bytecode may emit {opcodes}; source may not expect "
            f"transient-storage reentrancy surface, and a target chain that "
            f"lacks these opcodes bricks at deploy",
            exc, sev,
            f"foundry evm_version = '{ver}' enables the {opcodes} opcode(s). "
            f"This CHANGES SEMANTICS, not just optimization: (a) TSTORE/TLOAD "
            f"open a transient-storage reentrancy surface the source may not "
            f"guard, and (b) if the DEPLOY TARGET chain (or a fork/L2) does not "
            f"support {opcodes}, the contract bricks at deploy or reverts on the "
            f"opcode. Confirm the deploy chain supports '{ver}' and that no "
            f"transient/mcopy assumption is unguarded."))

    # --- viaIR JOINED against an inline-assembly source assumption -----------
    for i, ln in enumerate(lines):
        if _VIA_IR_RE.search(ln):
            if not _has_inline_assembly(cfg_dir, workspace):
                continue  # viaIR alone (no assembly) -> pure-codegen, SILENT.
            rows.append(_mk_row(
                rel, i + 1, "solidity", "via_ir", "true", "viair-codegen",
                "source contains inline `assembly {...}` whose stack/memory "
                "layout / codegen may differ between the legacy and IR pipelines",
                ln.strip()[:200], "low",
                "via_ir = true switches to the Yul/IR codegen pipeline, which "
                "reorders stack slots and memory layout differently from the "
                "legacy pipeline. The source uses inline assembly, whose "
                "correctness can depend on the codegen it was written/tested "
                "against - a viaIR toggle can silently change the emitted "
                "behavior of an assembly block. Re-verify assembly under the "
                "shipped via_ir setting."))
            break  # one viaIR note per config is enough


# ============================================================================
# GO arm (secondary): build tag that gates OUT a validation/guard path.
# ============================================================================
_GO_BUILD_TAG_RE = re.compile(
    r"^\s*//\s*(?:go:build\s+(?P<a>[^\n]+)|\+build\s+(?P<b>[^\n]+))")
_GO_GUARD_HINT = re.compile(
    r"(?i)\b(validate|verify|require|check|assert|guard|authoriz|permission|"
    r"panic|must|invariant)\w*")
_GO_NEGATED_TAG_RE = re.compile(r"!\s*([A-Za-z_]\w*)")


def _scan_go_file(path: Path, rel: str, rows, go_text: str = None):
    txt = go_text if go_text is not None else path.read_text(
        encoding="utf-8", errors="ignore")
    lines = txt.splitlines()
    # build constraints live at the top of the file (before package clause).
    header = []
    for i, ln in enumerate(lines[:30]):
        if ln.strip().startswith("package "):
            break
        m = _GO_BUILD_TAG_RE.match(ln)
        if m:
            header.append((i + 1, (m.group("a") or m.group("b")).strip(),
                           ln.strip()))
    if not header:
        return
    # only interesting when the constraint is NEGATED (gates a path OUT of a
    # build) AND the file body contains a validation/guard construct.
    if not _GO_GUARD_HINT.search(txt):
        return
    for line, expr, exc in header:
        neg = _GO_NEGATED_TAG_RE.search(expr)
        if not neg:
            continue
        tag = neg.group(1)
        rows.append(_mk_row(
            rel, line, "go", "go:build", expr, "build-tag-gate",
            f"a validation/guard path in this file is compiled ONLY when tag "
            f"`{tag}` is absent; the `{tag}` build omits it",
            exc, "medium",
            f"build constraint `{exc}` gates this file (which contains a "
            f"validation/guard construct) OUT of any build where `{tag}` is set "
            f"(e.g. a `{tag}`/prod build). The guard is present in the "
            f"tested/default config and SILENTLY ABSENT in the `{tag}` build - "
            f"a semantic difference introduced by a toolchain tag, not "
            f"optimization. Confirm the guarded invariant is enforced in the "
            f"`{tag}` build too."))
        break


# ============================================================================
# workspace walk + config discovery
# ============================================================================
def _iter_config_and_go(root: Path):
    for dp, dn, fn in os.walk(root):
        dn[:] = [d for d in dn if d not in _SKIP_DIRS]
        rel_dp = dp.replace(os.sep, "/")
        skip_dir = bool(_TEST_HINT.search(rel_dp))
        for f in fn:
            p = Path(dp) / f
            if f == "Cargo.toml" and not skip_dir:
                yield ("cargo", p)
            elif f == "foundry.toml" and not skip_dir:
                yield ("foundry", p)
            elif (f.startswith("hardhat.config.") and not skip_dir):
                yield ("foundry", p)  # same evmVersion/viaIR parser
            elif f.endswith(".go") and not skip_dir:
                low = f.lower()
                if low.endswith("_test.go") or low.startswith("mock") \
                        or low.startswith("test"):
                    continue
                if (is_test_target_path(str(p))
                        or is_codegen_path(str(p), root)):
                    continue
                yield ("go", p)


def scan_workspace(ws: Path):
    ws = Path(ws)
    src = ws / "src"
    root = src if src.is_dir() else ws
    rows = []
    for kind, p in _iter_config_and_go(root):
        try:
            rel = str(p.relative_to(root))
        except ValueError:
            rel = str(p)
        try:
            if kind == "cargo":
                _scan_cargo(p, rel, p.parent, ws, rows)
            elif kind == "foundry":
                _scan_foundry(p, rel, p.parent, ws, rows)
            elif kind == "go":
                _scan_go_file(p, rel, rows)
        except Exception:
            continue
    # dedup: identical ids (same flag via multiple walks) AND collapse repeated
    # evmversion-opcode rows that declare the SAME version in the SAME file
    # across multiple profiles (one advisory per (file, value) is enough).
    seen = set()
    uniq = []
    for r in rows:
        if r["drift_kind"] == "evmversion-opcode":
            key = ("evmopcode", r["file"], r["config_value"])
        else:
            key = r["id"]
        if key in seen:
            continue
        seen.add(key)
        uniq.append(r)
    return uniq


def check_toolchain_flag_drift(ws) -> dict:
    """Public API (a sibling stale-pin-check MAY call): scan + summarize."""
    rows = scan_workspace(Path(ws))
    return _summary(rows, rows)


# ============================================================================
# sidecar + summary
# ============================================================================
def _emit_sidecar(ws: Path, rows):
    outdir = ws / ".auditooor"
    outdir.mkdir(parents=True, exist_ok=True)
    out = outdir / _SIDE_NAME
    with out.open("w") as fh:
        for r in rows:
            fh.write(json.dumps(r) + "\n")
    return out


def _count(rows, key):
    out = {}
    for r in rows:
        v = str(r.get(key, ""))
        out[v] = out.get(v, 0) + 1
    return out


def _summary(rows, fired_rows=None):
    fired = fired_rows if fired_rows is not None else [
        r for r in rows if r.get("fires")]
    return {
        "schema": HYP_SCHEMA,
        "capability": _CAPABILITY,
        "config_sites": len(rows),
        "fired": len(fired),
        "by_drift_kind": _count(rows, "drift_kind"),
        "by_lang": _count(rows, "lang"),
        "by_severity": _count(rows, "severity"),
        "verdict": "needs-fuzz" if fired else "clean-advisory",
        "advisory": True,
        "auto_credit": False,
    }


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="GEN-EL6 toolchain-flag semantic-drift screen "
                    "(Rust overflow-checks + Solidity evmVersion/viaIR + Go "
                    "build tags, advisory)")
    ap.add_argument("--workspace", "--ws")
    ap.add_argument("--source")
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--strict", action="store_true")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    strict = args.strict or os.environ.get(
        _STRICT_ENV, "").strip() not in ("", "0", "false")

    if args.source:
        rows = scan_workspace(Path(args.source))
        print(json.dumps(rows, indent=2))
        return 0

    if not args.workspace:
        ap.error("one of --workspace / --source is required")

    ws = Path(args.workspace)
    if not ws.is_absolute():
        cand = Path("/Users/wolf/audits") / args.workspace
        if cand.exists():
            ws = cand
    side = ws / ".auditooor" / _SIDE_NAME

    if args.check:
        rows = []
        if side.exists():
            rows = [json.loads(l) for l in side.read_text().splitlines()
                    if l.strip()]
        summ = _summary(rows)
        summ["source"] = "sidecar"
        print(json.dumps(summ, indent=2))
        return 1 if (strict and summ["fired"]) else 0

    rows = scan_workspace(ws)
    _emit_sidecar(ws, rows)
    summ = _summary(rows)
    print(json.dumps(summ, indent=2))
    return 1 if (strict and summ["fired"]) else 0


if __name__ == "__main__":
    sys.exit(main())
