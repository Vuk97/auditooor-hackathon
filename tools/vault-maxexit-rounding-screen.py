#!/usr/bin/env python3
"""vault-maxexit-rounding-screen.py - GEN-4A, the VAULT MAX/PREVIEW-HELPER vs
PAIRED-EXIT ROUNDING-CONSISTENCY screen (layer = pattern-lift, ERC-4626-family +
analogs).

A GENERAL advisory screen - a CROSS-FUNCTION rounding-consistency check, never a
single-expression detector.

GENERAL LOGIC. An ERC-4626-style max/preview helper (maxWithdraw / maxRedeem /
maxDeposit / maxMint / previewWithdraw / previewRedeem / previewDeposit /
previewMint) and its PAIRED state-changing exit (withdraw / redeem / deposit /
mint) must use CONSISTENT rounding on the SAME conserved asset<->share
conversion. The EIP-4626 rule is that every conversion rounds in the direction
that favors the VAULT, never the caller. If a helper rounds UP (Ceil / mulDivUp /
+1 residual - the recipient-favoring direction) while its paired exit rounds DOWN
(Floor / mulDivDown) on the SAME conserved pair (or vice-versa), a caller passing
exactly maxWithdraw() / previewRedeem() either exits MORE than the vault can
honor (over-exit / other-holder dilution) or reverts (griefing).

The conserved-pair GROUPS (each member computes the SAME quantity+direction on
the SAME conserved pair, so all members must agree):
  * A  assets<-shares (exit side, canon DOWN):  maxWithdraw, previewRedeem, redeem
  * B  shares<-assets (withdraw side, canon UP): previewWithdraw, withdraw
  * C  shares<-assets (deposit side, canon DOWN):previewDeposit, deposit
  * D  assets<-shares (mint side, canon UP):     previewMint, mint

FIRES when, inside ONE contract/impl, a GROUP has >=2 members whose rounding
direction is DETECTABLE and those directions are PROVABLY OPPOSITE (an explicit
Ceil/Up/mulDivUp/divUp token in one member and Floor/Down/mulDivDown/divDown in
another). The row anchors on the member whose direction DEVIATES from the group
canon and names the consistent paired member it contradicts.

FP-CONTROL (critical - this is a two-function JOIN, keep it targeted):
  * BOTH functions must EXIST, convert the SAME conserved pair (same group), AND
    round in provably-opposite directions. A group with only one detectable
    member is SILENT (an exit that DELEGATES to its preview - the OZ shape -
    carries no independent rounding token, so the group has a single detectable
    direction -> SILENT, correct: it cannot be inconsistent).
  * A helper with NO paired exit / preview in the same group is SILENT.
  * A function whose body contains BOTH an UP and a DOWN token (multiple
    conversions in one body) has an AMBIGUOUS direction -> not counted (SILENT),
    conservative.
  * non-vault math (a mulDiv with no vault max/preview/exit fn) is SILENT.
  * Unconfirmed pairing (a max*/preview helper vs a delegating or ambiguous exit)
    -> severity `medium`; a preview-or-max helper contradicting a same-group
    state-changing exit that BOTH carry an explicit token -> `high` candidate,
    still advisory (`needs-fuzz`).

DEDUP (tool-duplication preflight, do-NOT #10 - cite):
  * GEN-4B (generic divide-before-multiply / rounding-direction on ANY conserved
    split): a SINGLE-EXPRESSION rounding-direction fault on one split. GEN-4A is
    the SPECIFIC max-helper-vs-paired-exit CONSISTENCY JOIN ACROSS TWO functions -
    it never fires on a lone expression; it fires only when two named vault
    functions in the same conserved group disagree.
  * A site that is a single rounding expression with no cross-function partner is
    left to GEN-4B and dropped here.

NUVA-VERIFY: GO/EVM capability - nuva has an EVM vault surface (0xC360...);
nuva-verify is IN SCOPE and recorded in the dispatch (nuva_verdict).

ADVISORY-FIRST: every row carries verdict='needs-fuzz', advisory=True,
auto_credit=False; exit 0 by default. The opt-in env
AUDITOOOR_VAULT_MAXEXIT_ROUNDING_STRICT (or --strict) raises the exit code when a
fired row exists.

Excludes test / vendor / codegen via the shared exclusion libs.

Usage:
  --workspace <ws>   scan <ws>/src (or <ws>) -> .auditooor/
                     vault_maxexit_rounding_hypotheses.jsonl + summary
  --source <dir>     scan an arbitrary dir, print rows as JSON (NO sidecar)
  --file <f>         scan a single .sol/.rs/.go file, print rows as JSON
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

HYP_SCHEMA = "auditooor.vault_maxexit_rounding_hypotheses.v1"
_SIDE_NAME = "vault_maxexit_rounding_hypotheses.jsonl"
_STRICT_ENV = "AUDITOOOR_VAULT_MAXEXIT_ROUNDING_STRICT"
_CAPABILITY = "GEN_4A"

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
              "cache", "__pycache__", "dist", "build", ".auditooor",
              "benches", "benchmarks", "examples", "example", "script",
              "scripts", "deployments", "prior_audits", "reference", "certora",
              "simulation", "testdata", "mocks", "mock", "artifacts", "fuzz",
              "chimera_harnesses", "lib", "node_modules"}
_TEST_HINT = re.compile(
    r"(^|/)(tests?|testutil|testonly|testhelper|test_fixtures|mock|mocks|"
    r"benches|benchmarks?|examples?|fixtures|simulation|testdata|poc|pocs|"
    r"chimera_harnesses)(/|$)")
_CODEGEN_SENTINEL = re.compile(r"Code generated .{0,80}?DO NOT EDIT", re.I)

# ============================================================================
# per-language config
# ============================================================================
# fn-decl regex per language (capture group 'name').
_FN_DECL = {
    "solidity": re.compile(r"\bfunction\s+(?P<name>[A-Za-z_]\w*)"),
    "rust": re.compile(
        r"\bfn\s+(?P<name>[A-Za-z_]\w*)"),
    "go": re.compile(
        r"\bfunc\s+(?:\([^)]*\)\s*)?(?P<name>[A-Za-z_]\w*)"),
}
_EXTS = {".sol": "solidity", ".rs": "rust", ".go": "go"}

# rounding-direction token sets per language. UP = recipient-favoring on a
# growing quantity / vault-favoring on a shrinking one; the point is the
# DIRECTION, and two same-group members must agree.
_UP_TOKENS = {
    "solidity": re.compile(
        r"\bRounding\s*\.\s*Ceil\b|\bRounding\s*\.\s*Up\b|\bmulDivUp\b|"
        r"\bmulDivRoundingUp\b|\bdivUp\b|\bceilDiv\b|\bmulDivCeil\b|"
        r"\brayDivUp\b|\bwadDivUp\b|\bMathUpgradeable\s*\.\s*Rounding\s*\.\s*(?:Ceil|Up)\b"),
    "rust": re.compile(
        r"\bRounding\s*::\s*Up\b|\bRoundingMode\s*::\s*Up\b|\bdiv_ceil\b|"
        r"\bmul_div_ceil\b|\bmul_div_up\b|\bceil_div\b|\bcheckedCeilDiv\b|"
        r"\bround_up\b"),
    "go": re.compile(
        r"\bRoundUp\b|\bRoundingUp\b|\bDivCeil\b|\bCeilDiv\b|\bMulDivUp\b|"
        r"\bDivRoundUp\b|\bceilDiv\b|\bdivUp\b"),
}
_DOWN_TOKENS = {
    "solidity": re.compile(
        r"\bRounding\s*\.\s*Floor\b|\bRounding\s*\.\s*Down\b|\bmulDivDown\b|"
        r"\bmulDivRoundingDown\b|\bdivDown\b|\bfloorDiv\b|\bmulDivFloor\b|"
        r"\brayDivDown\b|\bwadDivDown\b|\bMathUpgradeable\s*\.\s*Rounding\s*\.\s*(?:Floor|Down)\b"),
    "rust": re.compile(
        r"\bRounding\s*::\s*Down\b|\bRoundingMode\s*::\s*Down\b|\bdiv_floor\b|"
        r"\bmul_div_floor\b|\bmul_div_down\b|\bfloor_div\b|\bround_down\b"),
    "go": re.compile(
        r"\bRoundDown\b|\bRoundingDown\b|\bDivFloor\b|\bFloorDiv\b|\bMulDivDown\b|"
        r"\bDivRoundDown\b|\bfloorDiv\b|\bdivDown\b"),
}

# ============================================================================
# conserved-pair GROUPS: normalized-fn-name -> (group_key, conserved_pair,
# canonical_direction, is_state_changing_exit).  Names normalized by lowercasing
# and stripping underscores (maxWithdraw / max_withdraw -> "maxwithdraw").
# ============================================================================
UP, DOWN = "up", "down"
_GROUP = {
    # A: assets<-shares, exit side, canon DOWN (favor vault: send fewer assets).
    "maxwithdraw":    ("A_assets_from_shares_exit", "assets<-shares", DOWN, False),
    "previewredeem":  ("A_assets_from_shares_exit", "assets<-shares", DOWN, False),
    "redeem":         ("A_assets_from_shares_exit", "assets<-shares", DOWN, True),
    # B: shares<-assets, withdraw side, canon UP (favor vault: burn more shares).
    "previewwithdraw": ("B_shares_from_assets_withdraw", "shares<-assets", UP, False),
    "withdraw":        ("B_shares_from_assets_withdraw", "shares<-assets", UP, True),
    # C: shares<-assets, deposit side, canon DOWN (favor vault: mint fewer shares).
    "previewdeposit": ("C_shares_from_assets_deposit", "shares<-assets", DOWN, False),
    "deposit":        ("C_shares_from_assets_deposit", "shares<-assets", DOWN, True),
    # D: assets<-shares, mint side, canon UP (favor vault: pull more assets).
    "previewmint":    ("D_assets_from_shares_mint", "assets<-shares", UP, False),
    "mint":           ("D_assets_from_shares_mint", "assets<-shares", UP, True),
}
_GROUP_LABEL = {
    "A_assets_from_shares_exit": "withdraw/redeem exit (assets<-shares)",
    "B_shares_from_assets_withdraw": "withdraw (shares<-assets)",
    "C_shares_from_assets_deposit": "deposit (shares<-assets)",
    "D_assets_from_shares_mint": "mint (assets<-shares)",
}
# fn names we care about at all (fast pre-filter).
_HELPER_HINT = re.compile(
    r"\b(?:function\s+|fn\s+|func\s+(?:\([^)]*\)\s*)?)?"
    r"_?(?:max_?withdraw|preview_?redeem|redeem|preview_?withdraw|"
    r"withdraw|preview_?deposit|deposit|preview_?mint|mint)\b", re.I)


def _norm_name(name: str) -> str:
    return name.replace("_", "").lower()


# ============================================================================
# language-aware comment / string masking.
# ============================================================================
def _mask(text: str, lang: str) -> str:
    # Rust: do NOT treat ' as a string delimiter (lifetimes). Go/Solidity: mask
    # ', ", and (Go) ` raw strings.
    mask_single = lang != "rust"
    mask_backtick = lang == "go"
    out = []
    i, n = 0, len(text)
    in_line = in_block = in_dq = in_sq = in_bt = False
    while i < n:
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if in_line:
            out.append("\n" if c == "\n" else " ")
            if c == "\n":
                in_line = False
            i += 1
        elif in_block:
            if c == "*" and nxt == "/":
                out.append("  ")
                i += 2
                in_block = False
            else:
                out.append("\n" if c == "\n" else " ")
                i += 1
        elif in_dq:
            out.append(" ")
            if c == "\\":
                out.append(" ")
                i += 2
                continue
            if c == '"':
                in_dq = False
            i += 1
        elif in_sq:
            out.append(" ")
            if c == "\\":
                out.append(" ")
                i += 2
                continue
            if c == "'":
                in_sq = False
            i += 1
        elif in_bt:
            out.append("\n" if c == "\n" else " ")
            if c == "`":
                in_bt = False
            i += 1
        elif c == "/" and nxt == "/":
            in_line = True
            out.append("  ")
            i += 2
        elif c == "/" and nxt == "*":
            in_block = True
            out.append("  ")
            i += 2
        elif c == '"':
            in_dq = True
            out.append(" ")
            i += 1
        elif mask_single and c == "'":
            in_sq = True
            out.append(" ")
            i += 1
        elif mask_backtick and c == "`":
            in_bt = True
            out.append(" ")
            i += 1
        else:
            out.append(c)
            i += 1
    return "".join(out)


def _line_of_offset(text: str, off: int) -> int:
    return text.count("\n", 0, off) + 1


def _excerpt(text: str, off: int) -> str:
    ls = text.rfind("\n", 0, off) + 1
    le = text.find("\n", off)
    if le == -1:
        le = len(text)
    return text[ls:le].strip()[:200]


def _stable_id(rel, group, dev_fn, other_fn, line):
    h = hashlib.sha1()
    h.update(f"{rel}|{group}|{dev_fn}|{other_fn}|{line}".encode())
    return h.hexdigest()[:16]


# ============================================================================
# balanced extraction
# ============================================================================
def _balanced_parens(text: str, open_idx: int):
    depth, n, i = 0, len(text), open_idx
    while i < n:
        ch = text[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return text[open_idx + 1:i], i
        i += 1
    return "", -1


# ============================================================================
# function extraction: (name, decl_off, body, body_off)
# ============================================================================
def _iter_functions(text: str, lang: str):
    rx = _FN_DECL[lang]
    n = len(text)
    for m in rx.finditer(text):
        popen = text.find("(", m.end())
        if popen == -1:
            continue
        _sig, pclose = _balanced_parens(text, popen)
        if pclose == -1:
            continue
        bopen = text.find("{", pclose)
        if bopen == -1:
            continue
        semi = text.find(";", pclose)
        if semi != -1 and semi < bopen:
            # a ';' before '{' -> interface / abstract decl (no body).
            yield (m.group("name"), m.start(), "", -1)
            continue
        depth, i = 0, bopen
        while i < n:
            ch = text[i]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        yield (m.group("name"), m.start(), text[bopen:i + 1], bopen)


def _direction(body: str, lang: str):
    """UP / DOWN / None. None when neither or BOTH token families appear."""
    up = bool(_UP_TOKENS[lang].search(body))
    down = bool(_DOWN_TOKENS[lang].search(body))
    if up and not down:
        return UP
    if down and not up:
        return DOWN
    return None


# ============================================================================
# scan a single file
# ============================================================================
def _mk_row(rel, group_key, conserved, canon, dev_fn, dev_dir, dev_line,
            dev_off, other_fn, other_dir, other_exit, lang, excerpt, severity,
            why):
    return {
        "schema": HYP_SCHEMA,
        "capability": _CAPABILITY,
        "id": _stable_id(rel, group_key, dev_fn, other_fn, dev_line),
        "file": rel,
        "line": dev_line,
        "function": dev_fn,
        "lang": lang,
        "conserved_pair": conserved,
        "group": _GROUP_LABEL.get(group_key, group_key),
        "canonical_direction": canon,
        "helper_fn": dev_fn,
        "helper_rounding": dev_dir,
        "paired_fn": other_fn,
        "paired_rounding": other_dir,
        "paired_is_state_changing_exit": other_exit,
        "excerpt": excerpt,
        "severity": severity,
        "why_severity_anchored": why,
        "fires": True,
        "verdict": "needs-fuzz",
        "advisory": True,
        "auto_credit": False,
    }


def scan_file(path: Path, rel: str, file_text: str = None):
    raw = file_text if file_text is not None else path.read_text(
        encoding="utf-8", errors="ignore")
    ext = "." + rel.rsplit(".", 1)[-1].lower() if "." in rel else ""
    lang = _EXTS.get(ext)
    if lang is None:
        return []
    if not _HELPER_HINT.search(raw):
        return []
    text = _mask(raw, lang)
    rows = []

    # Collect, per group, the members with a DETECTABLE direction. Because a
    # file may contain several contracts/impls, we also key on the enclosing
    # brace-scope via a coarse contract/impl boundary offset so two DIFFERENT
    # vaults in one file are not cross-matched.
    scopes = _scope_bounds(text, lang)

    # scope_id -> group_key -> list of member dicts.
    collected: dict = {}
    for name, decl_off, body, body_off in _iter_functions(text, lang):
        norm = _norm_name(name)
        info = _GROUP.get(norm)
        if info is None:
            continue
        group_key, conserved, canon, is_exit = info
        direction = _direction(body, lang) if body else None
        if direction is None:
            continue
        sid = _scope_of(decl_off, scopes)
        collected.setdefault(sid, {}).setdefault(group_key, []).append({
            "name": name, "norm": norm, "dir": direction, "canon": canon,
            "conserved": conserved, "is_exit": is_exit,
            "decl_off": decl_off,
        })

    seen = set()
    for sid, groups in collected.items():
        for group_key, members in groups.items():
            dirs = {mm["dir"] for mm in members}
            if UP not in dirs or DOWN not in dirs:
                continue  # not provably opposite (single direction) -> SILENT
            canon = members[0]["canon"]
            conserved = members[0]["conserved"]
            # deviating member(s): direction != canon. anchor there, cite a
            # canonical-direction partner (prefer a state-changing exit).
            deviating = [mm for mm in members if mm["dir"] != canon]
            canonical = [mm for mm in members if mm["dir"] == canon]
            if not deviating or not canonical:
                # both sides deviate from canon impossible (2 dirs, canon is
                # one of them); but guard defensively.
                deviating = deviating or [members[0]]
                canonical = canonical or [members[-1]]
            # prefer the deviating member that is a helper (max*/preview*).
            deviating.sort(key=lambda mm: (mm["is_exit"], mm["decl_off"]))
            partner = sorted(
                canonical, key=lambda mm: (not mm["is_exit"], mm["decl_off"]))[0]
            dev = deviating[0]
            line = _line_of_offset(text, dev["decl_off"])
            key = (sid, group_key)
            if key in seen:
                continue
            seen.add(key)
            partner_exit = partner["is_exit"]
            # The conflict is exploitable-shaped (over-exit / griefing) when it
            # pits a max/preview HELPER against a state-changing EXIT that round
            # opposite; two helpers (e.g. maxWithdraw vs previewRedeem) is a
            # weaker, unconfirmed pairing -> medium.
            severity = ("high" if (dev["is_exit"] or partner["is_exit"])
                        else "medium")
            why = (
                "EIP-4626 requires every conversion on a conserved asset<->share "
                "pair to round in the SAME (vault-favoring) direction across a "
                "helper and its paired exit. In the `%s` group (%s, canon %s) "
                "`%s` rounds %s while `%s` rounds %s on the SAME conserved pair - "
                "provably OPPOSITE. A caller passing exactly `%s()` into the exit "
                "then either exits MORE than the vault can honor (over-exit / "
                "other-holder dilution) or reverts (griefing). %s Advisory: "
                "cross-function inconsistency, confirm the reachable exit path "
                "under fuzz. (Distinct from GEN-4B single-expression rounding; "
                "this is the two-function max/preview-vs-exit CONSISTENCY join.)"
            ) % (
                _GROUP_LABEL.get(group_key, group_key), conserved, canon,
                dev["name"], dev["dir"], partner["name"], partner["dir"],
                dev["name"],
                ("The deviating side is a max/preview helper contradicting a "
                 "state-changing exit -> high candidate."
                 if severity == "high" else
                 "Pairing unconfirmed (no state-changing exit anchor) -> medium."),
            )
            rows.append(_mk_row(
                rel, group_key, conserved, canon, dev["name"], dev["dir"], line,
                dev["decl_off"], partner["name"], partner["dir"], partner_exit,
                lang, _excerpt(text, dev["decl_off"]), severity, why))
    return rows


def _scope_bounds(text: str, lang: str):
    """Return sorted list of (start_off, name) for each contract/impl/type scope
    so functions in DIFFERENT vaults in one file are not cross-matched. Coarse:
    solidity `contract|library|abstract contract X`, rust `impl ... {`, go we
    treat the whole file as one scope (receiver types vary)."""
    bounds = []
    if lang == "solidity":
        for m in re.finditer(
                r"\b(?:abstract\s+)?(?:contract|library|interface)\s+"
                r"([A-Za-z_]\w*)", text):
            bounds.append((m.start(), m.group(1)))
    elif lang == "rust":
        for m in re.finditer(r"\bimpl\b[^\{;]*\bfor\s+([A-Za-z_]\w*)|"
                             r"\bimpl\s+([A-Za-z_]\w*)", text):
            bounds.append((m.start(), m.group(1) or m.group(2) or "impl"))
    if not bounds:
        bounds = [(0, "<file>")]
    bounds.sort()
    return bounds


def _scope_of(off: int, bounds):
    sid = bounds[0][1]
    for start, name in bounds:
        if start <= off:
            sid = name
        else:
            break
    return sid


# ============================================================================
# tree walk + sidecar
# ============================================================================
def _iter_source_files(root: Path, workspace: Path = None):
    for dp, dn, fn in os.walk(root):
        dn[:] = [d for d in dn if d not in _SKIP_DIRS]
        norm = dp.replace(os.sep, "/")
        if _TEST_HINT.search(norm):
            continue
        for f in fn:
            low = f.lower()
            ext = "." + low.rsplit(".", 1)[-1] if "." in low else ""
            if ext not in _EXTS:
                continue
            if low.endswith((".t.sol", ".s.sol", "_test.go", "_test.rs")) \
                    or low.startswith(("test", "mock")):
                continue
            if _TEST_HINT.search(f):
                continue
            p = Path(dp) / f
            rel = str(p)
            if (is_test_target_path(rel)
                    or is_chimera_mutation_harness_path(rel)
                    or is_codegen_path(rel, workspace)):
                continue
            try:
                head = p.read_text(encoding="utf-8", errors="replace")[:4096]
                if _CODEGEN_SENTINEL.search(head):
                    continue
            except OSError:
                continue
            yield p


def scan_tree(root: Path, workspace: Path = None):
    rows = []
    for p in _iter_source_files(root, workspace):
        try:
            rel = str(p.relative_to(root))
        except ValueError:
            rel = str(p)
        try:
            rows.extend(scan_file(p, rel))
        except Exception:
            continue
    return rows


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


def _summary(rows):
    fired = [r for r in rows if r.get("fires")]
    return {
        "schema": HYP_SCHEMA,
        "capability": _CAPABILITY,
        "sites": len(rows),
        "fired": len(fired),
        "by_group": _count(rows, "group"),
        "by_lang": _count(rows, "lang"),
        "by_severity": _count(rows, "severity"),
        "verdict": "needs-fuzz" if fired else "clean-advisory",
        "advisory": True,
        "auto_credit": False,
    }


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="GEN-4A vault max/preview-helper vs paired-exit rounding-"
                    "consistency screen (Sol/Rust/Go, advisory)")
    ap.add_argument("--workspace", "--ws")
    ap.add_argument("--source")
    ap.add_argument("--file")
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--strict", action="store_true")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    strict = args.strict or os.environ.get(
        _STRICT_ENV, "").strip() not in ("", "0", "false")

    if args.file:
        p = Path(args.file)
        rows = scan_file(p, p.name)
        print(json.dumps(rows, indent=2))
        return 0

    if args.source:
        rows = scan_tree(Path(args.source))
        print(json.dumps(rows, indent=2))
        return 0

    if not args.workspace:
        ap.error("one of --workspace / --source / --file is required")

    ws = Path(args.workspace)
    if not ws.is_absolute():
        for base in ("/Users/wolf/audits", os.getcwd()):
            cand = Path(base) / args.workspace
            if cand.exists():
                ws = cand
                break
    side = ws / ".auditooor" / _SIDE_NAME

    if args.check:
        rows = []
        if side.exists():
            rows = [json.loads(line) for line in side.read_text().splitlines()
                    if line.strip()]
        summ = _summary(rows)
        summ["source"] = "sidecar"
        print(json.dumps(summ, indent=2))
        return 1 if (strict and summ["fired"]) else 0

    src = ws / "src"
    root = src if src.exists() else ws
    rows = scan_tree(root, workspace=ws)
    _emit_sidecar(ws, rows)
    summ = _summary(rows)
    print(json.dumps(summ, indent=2))
    return 1 if (strict and summ["fired"]) else 0


if __name__ == "__main__":
    sys.exit(main())
