#!/usr/bin/env python3
"""rounding-direction-consistency-screen.py - the ROUNDING-DIRECTION screen (MQ-C01).

GENERAL VALUE-INVARIANT class (never a bug SHAPE). It instantiates one
value-conservation property that no per-function detector owns:

  DELEGATED-TRUSTED INVARIANT : on every value-conservation / amount-gate path
    (deposit->mint-shares, mint, withdraw, redeem, borrow->debt, repay,
    fee-accrual, LP / exchange-rate conversion) the ROUNDING DIRECTION of each
    fixed-point mul/div/mulDiv is PROTOCOL-favorable and consistent end-to-end.
  PRIVATE INVARIANT           : the quantity a user RECEIVES (a credit - shares
    minted on deposit, assets paid out on withdraw/redeem/borrow, debt reduced on
    repay) is rounded DOWN; the quantity a user PAYS or that is burned/charged
    against them (a debit - assets paid in, shares burned, debt created) is
    rounded UP. This one rule also enforces round-trip safety: because BOTH the
    deposit-credit and the withdraw-credit round DOWN, a deposit+withdraw cycle
    can never net positive.
  ATTACK                      : a conversion on a value path rounds the WRONG way
    - a credit rounds UP (mint/credit-favorable to the caller) or a debit rounds
    DOWN (burn/debit-favorable to the caller). A dust-granularity repeat of that
    favorable rounding nets value out of the protocol; an inconsistent round-trip
    (deposit rounds one way, its inverse the opposite) lets deposit+withdraw net
    positive.

Enforcement points = every classifiable SHARES conversion site on a
value-conservation path. The screen decides favorability from the SINK direction
(the credit vs debit side, keyed off the enclosing verb) AND the ROUNDING form
(Math.Rounding.Ceil/Floor, mulDivUp/mulDivDown, FullMath.mulDiv[RoundingUp],
*Up/*Down helpers, and the raw `a * b / c` mul-then-div truncation). It flags
(WARN, verdict=needs-fuzz) ONLY when the SHARES quantity is rounded the wrong way
- a shares CREDIT (minted on deposit/mint, debt reduced on repay) rounds UP, or a
shares DEBIT (burned on withdraw/redeem, debt created on borrow) rounds DOWN.

PRECISION LEVER (why shares-only): the shares basis is the one place the sink
direction is UNAMBIGUOUS from the static verb. The ASSETS basis is deliberately
left to fuzzing (silent) because its direction depends on whether the conversion
is an input valuation, an output disbursement, a cost, or a token->base price -
which a name-level screen cannot reliably disambiguate. On the real fleet
(morpho, strata, spark, etherfi, lido) EVERY assets-basis site is intentionally
protocol-favorable, so firing on them would be a false positive. A lone `/` (no
multiply) - a scale / index / gwei / merkle op, never a value conversion - is also
silent. Every other site (unknown verb, unknown basis, rounding carried in a
variable) is SILENT. This is a PRECISE screen, not an enumerator: it biases hard
toward silence so its fire rate on a large workspace stays near zero (measured 0
across morpho/strata/spark/etherfi/lido src, fires only on a weakened copy).

Advisory-first: every row carries verdict='needs-fuzz', advisory=True,
auto_credit=False. It NEVER auto-credits and NEVER fail-closes in default mode;
the opt-in AUDITOOOR_ROUNDING_DIRECTION_STRICT (or --strict) only raises the exit
code. Solidity-only (the fleet language where discretized share/asset accounting
lives); silent on every other tree.

Usage:
  --workspace <ws>   scan <ws>/src -> .auditooor/rounding_direction_consistency_hypotheses.jsonl + summary
  --source <dir>     scan an arbitrary dir, print rows as JSON
  --file <f>         scan a single .sol file, print rows as JSON
  --check            re-read the emitted sidecar, print cert verdict (advisory)
  --strict           (or env) elevate exit code when a mismatched rounding exists
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

HYP_SCHEMA = "auditooor.rounding_direction_consistency_hypotheses.v1"
_SIDE_NAME = "rounding_direction_consistency_hypotheses.jsonl"
_STRICT_ENV = "AUDITOOOR_ROUNDING_DIRECTION_STRICT"
_CAPABILITY = "MQC01"

_SKIP_DIRS = {"target", ".git", "node_modules", "vendor", "_archive", "out",
              "cache", "lib", "__pycache__", "dist", "build", ".auditooor",
              "benches", "benchmarks", "script", "scripts", "deployments",
              "certora", "specs"}
_TEST_HINT = re.compile(
    r"(^|/)(tests?|test_fixtures|mock|mocks|examples|fixtures)(/|$)")

# --- value-path verb -> which of {shares, assets} is the CREDIT side ---------
# CREDIT side = the quantity that benefits the caller (received / debt reduced).
# The other basis on that path is the DEBIT side (paid in / burned / debt up).
#   credit  -> must round DOWN (protocol keeps the dust)
#   debit   -> must round UP   (protocol keeps the dust)
# Keys are the substrings matched against a function name (longest-first).
_VERB_CREDIT_SIDE = {
    # user puts value IN, receives SHARES (or reduces own debt) -> shares = credit
    "supplycollateral": None,          # pure collateral transfer, no conversion
    "withdrawcollateral": None,
    "deposit": "shares",
    "supply": "shares",
    "mint": "shares",
    "issue": "shares",
    "stake": "shares",
    "repay": "shares",                 # repaid debt-shares are credited to caller
    # user takes value OUT, receives ASSETS; shares/debt are the debit side
    "withdraw": "assets",
    "redeem": "assets",
    "borrow": "assets",
    "unstake": "assets",
}
# order verbs longest-first so "supplycollateral" wins over "supply", etc.
_VERB_ORDER = sorted(_VERB_CREDIT_SIDE, key=len, reverse=True)

_SKIP_DIRS_RE = None


def _mask_comments(text: str) -> str:
    """Blank out // and /* */ comments and string literals, preserving newlines /
    length so line indices stay source-accurate. Errs toward SILENCE."""
    out = []
    i, n = 0, len(text)
    in_line = in_block = in_str = False
    quote = ""
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
        elif in_str:
            out.append(c)
            if c == "\\":
                out.append(nxt)
                i += 2
                continue
            if c == quote:
                in_str = False
            i += 1
        elif c in ('"', "'"):
            in_str = True
            quote = c
            out.append(c)
            i += 1
        elif c == "/" and nxt == "/":
            in_line = True
            out.append("  ")
            i += 2
        elif c == "/" and nxt == "*":
            in_block = True
            out.append("  ")
            i += 2
        else:
            out.append(c)
            i += 1
    return "".join(out)


def _iter_source_files(root: Path):
    for dp, dn, fn in os.walk(root):
        dn[:] = [d for d in dn if d not in _SKIP_DIRS]
        if _TEST_HINT.search(dp.replace(os.sep, "/")):
            continue
        for f in fn:
            low = f.lower()
            if not low.endswith(".sol"):
                continue
            if low.endswith(".t.sol"):
                continue
            if _TEST_HINT.search(f):
                continue
            yield Path(dp) / f


# --- function extraction (brace-matched, Solidity) --------------------------
_FN_DECL_RE = re.compile(
    r"^\s*(?:function\s+([A-Za-z_]\w*)"
    r"|(constructor)\b"
    r"|(fallback|receive)\s*\()")


def _fn_name(m):
    return m.group(1) or m.group(2) or m.group(3)


def _functions(lines):
    """Yield (name, decl_idx, [(abs_idx, line), ...]) for each function body."""
    i, n = 0, len(lines)
    while i < n:
        m = _FN_DECL_RE.match(lines[i])
        if not m:
            i += 1
            continue
        name = _fn_name(m) or "<anon>"
        depth = 0
        started = False
        body = []
        j = i
        seen_brace = False
        while j < n:
            line = lines[j]
            depth += line.count("{") - line.count("}")
            body.append((j, line))
            if "{" in line:
                started = True
                seen_brace = True
            if started and depth <= 0:
                break
            j += 1
        yield name, i, body
        i = max(j, i + 1)


def _verb_of(fn_name: str):
    """Return (verb, credit_side) for the enclosing function, or (None, None).

    The verb must be a WHOLE leading camelCase token of the function name (after
    stripping leading underscores and an optional ERC4626 `preview` prefix) - it
    is matched only when the character following it is a token boundary
    (uppercase / digit / underscore / end). This is the precision lever: it keeps
    the mutating entrypoints (supply / withdraw / borrow / repay, previewDeposit,
    _deposit) but REJECTS valuation / view helpers whose name merely CONTAINS a
    verb substring (expectedSupplyAssets, _accruedSupplyBalance,
    expectedBorrowAssets, withdrawableAssets) - there the rounding of a claim
    (down) or a debt (up) is already correct and must stay SILENT.

    credit_side is 'shares' | 'assets' | None (None = a matched verb that carries
    no share/asset conversion, e.g. *Collateral - keep silent)."""
    norm = fn_name.lstrip("_")
    if norm.lower().startswith("preview"):
        norm = norm[len("preview"):]
    for verb in _VERB_ORDER:            # longest-first: supplyCollateral > supply
        if re.match(re.escape(verb) + r"($|[A-Z0-9_])", norm, re.IGNORECASE):
            return verb, _VERB_CREDIT_SIDE[verb]
    return None, None


# --- rounding-form detection ------------------------------------------------
# helper / call tokens that FIX a rounding direction (checked on the RHS text).
_UP_TOKENS = re.compile(
    r"(mulDivUp|divUp|divWadUp|wDivUp|wMulUp|mulWadUp|mulDivRoundingUp"
    r"|toSharesUp|toAssetsUp|ceilDiv|roundUp|\.ceil\b"
    r"|Rounding\s*\.\s*Ceil|Rounding\s*\.\s*Up)", re.I)
_DOWN_TOKENS = re.compile(
    r"(mulDivDown|divDown|divWadDown|wDivDown|wMulDown|mulWadDown"
    r"|toSharesDown|toAssetsDown|floorDiv|roundDown|\.floor\b"
    r"|Rounding\s*\.\s*Floor|Rounding\s*\.\s*Down|Rounding\s*\.\s*Trunc)", re.I)
# a fixed-point mul/div that TRUNCATES (floor) by construction.
_FULLMATH_FLOOR = re.compile(r"\bFullMath\s*\.\s*mulDiv\s*\(", re.I)
_FULLMATH_UP = re.compile(r"\bFullMath\s*\.\s*mulDivRoundingUp\s*\(", re.I)
# OZ Math.mulDiv with an explicit Rounding argument is handled by _UP/_DOWN
# tokens; a 3-arg Math.mulDiv (no Rounding) truncates -> floor/down.
_OZ_MULDIV = re.compile(r"\bMath\s*\.\s*mulDiv\s*\(", re.I)
# a Rounding value carried in a NON-literal (a parameter/variable) -> unknown at
# this site (the caller decides); stay silent.
_ROUNDING_VAR = re.compile(r"Rounding\b(?!\s*\.\s*(?:Ceil|Floor|Up|Down|Trunc))",
                           re.I)

# basis (shares vs assets) tokens on the conversion (callee or LHS).
_SHARES_CALLEE = re.compile(
    r"(toShares(?:Up|Down)?|convertToShares|_convertToShares|previewDeposit"
    r"|previewMint|assetsToShares|toShares)\b", re.I)
_ASSETS_CALLEE = re.compile(
    r"(toAssets(?:Up|Down)?|convertToAssets|_convertToAssets|previewRedeem"
    r"|previewWithdraw|sharesToAssets|toAssets)\b", re.I)

_ASSIGN_RE = re.compile(
    r"([A-Za-z_][A-Za-z0-9_]*(?:\s*\.\s*[A-Za-z_]\w*|\s*\[[^\]]*\])*)"
    r"\s*=\s*([^=;][^;]*?)\s*;")
_RETURN_RE = re.compile(r"\breturn\b\s+([^;]+?)\s*;")

# a conversion is present only if the RHS actually does a fixed-point op.
_DIV_PRESENT = re.compile(
    r"(mulDiv|divWad|wDiv|wMul|mulWad|convertTo(?:Shares|Assets)"
    r"|to(?:Shares|Assets)(?:Up|Down)?|FullMath\.|Rounding\s*\.|/)")


def _rounding_of(rhs: str):
    """Return 'up' | 'down' | None (unknown) for a conversion RHS."""
    up = bool(_UP_TOKENS.search(rhs)) or bool(_FULLMATH_UP.search(rhs))
    down = bool(_DOWN_TOKENS.search(rhs))
    # OZ / FullMath truncating mulDiv (no explicit Rounding token) -> floor/down
    if not up and not down:
        if _FULLMATH_FLOOR.search(rhs):
            down = True
        elif _OZ_MULDIV.search(rhs) and not _ROUNDING_VAR.search(rhs):
            down = True
    if up and down:
        return None            # mixed forms on one line -> ambiguous, stay silent
    if up:
        return "up"
    if down:
        return "down"
    # a raw truncating division -> floor/down, but ONLY the genuine fixed-point
    # idiom `a * b / c` (a multiply AND a divide on the RHS). A lone `/` with no
    # `*` is a scale / index / gwei / merkle op, NOT a value conversion - firing
    # on it was the fleet false-positive source (lido beacon deposit-root math),
    # so it stays SILENT.
    if _ROUNDING_VAR.search(rhs):
        return None            # rounding carried in a variable -> caller decides
    if "/" in rhs and "*" in rhs and not re.search(r"[<>]=?|<<|>>", rhs):
        return "down"
    return None


def _basis_of(rhs: str, lhs: str):
    """Return 'shares' | 'assets' | None for the conversion's quantity basis.

    Callee name is authoritative (toShares* -> shares); else fall back to the
    LHS / return-target identifier lexicon. None when neither is decisive."""
    sh_c = bool(_SHARES_CALLEE.search(rhs))
    as_c = bool(_ASSETS_CALLEE.search(rhs))
    if sh_c and not as_c:
        return "shares"
    if as_c and not sh_c:
        return "assets"
    # fall back to the assignment/return target name
    tl = (lhs or "").lower()
    has_sh = "share" in tl
    has_as = "asset" in tl or "amount" in tl or "collateral" in tl
    if has_sh and not has_as:
        return "shares"
    if has_as and not has_sh:
        return "assets"
    return None


def _stable_id(rel, fn, line):
    h = hashlib.sha1()
    h.update(f"{rel}|{fn}|{line}".encode())
    return h.hexdigest()[:16]


def _classify_site(verb, credit_side, basis, rounding):
    """Return (sink_kind, expected_rounding, fires).

    sink_kind = 'credit' | 'debit'; expected = 'down' | 'up'."""
    sink = "credit" if basis == credit_side else "debit"
    expected = "down" if sink == "credit" else "up"
    fires = (rounding is not None) and (rounding != expected)
    return sink, expected, fires


def scan_file(path: Path, rel: str, file_text: str = None):
    raw = file_text if file_text is not None else path.read_text(
        encoding="utf-8", errors="ignore")
    if not rel.lower().endswith(".sol"):
        return []
    text = _mask_comments(raw)
    lines = text.split("\n")
    rows = []
    for name, _decl, body in _functions(lines):
        verb, credit_side = _verb_of(name)
        if verb is None or credit_side is None:
            continue                       # not a classifiable value-path verb
        for abs_idx, line in body:
            # candidate conversion sites = an assignment or a return whose RHS
            # performs a fixed-point op.
            targets = []  # (lhs, rhs)
            for m in _ASSIGN_RE.finditer(line):
                targets.append((m.group(1), m.group(2)))
            rm = _RETURN_RE.search(line)
            if rm:
                targets.append(("", rm.group(1)))
            for lhs, rhs in targets:
                if not _DIV_PRESENT.search(rhs):
                    continue
                rounding = _rounding_of(rhs)
                if rounding is None:
                    continue               # rounding not decisively known -> silent
                basis = _basis_of(rhs, lhs)
                if basis != "shares":
                    # PRECISION LEVER: fire only on the SHARES basis, where the
                    # sink direction is UNAMBIGUOUS from the verb (shares
                    # minted/credited on deposit/mint/repay -> down; shares
                    # burned/charged on withdraw/redeem/borrow -> up). The ASSETS
                    # basis is intentionally left to fuzzing (silent): its
                    # direction depends on whether the conversion is an input
                    # valuation, an output disbursement, a cost, or a token->base
                    # price - which static verb analysis cannot reliably
                    # disambiguate (proven on the strata/etherfi/lido fleet where
                    # every assets-basis site is deliberately protocol-favorable).
                    continue
                sink, expected, fires = _classify_site(
                    verb, credit_side, basis, rounding)
                if not fires:
                    continue               # PRECISE screen: emit only mismatches
                rows.append({
                    "schema": HYP_SCHEMA,
                    "capability": _CAPABILITY,
                    "id": _stable_id(rel, name, abs_idx),
                    "file": rel,
                    "line": abs_idx + 1,
                    "function": name,
                    "lang": "solidity",
                    "verb": verb,
                    "basis": basis,
                    "sink_kind": sink,
                    "rounding": rounding,
                    "expected_rounding": expected,
                    "value_path": True,
                    "fires": True,
                    "verdict": "needs-fuzz",
                    "advisory": True,
                    "auto_credit": False,
                    "question": (
                        f"`{name}` computes a {basis} {sink} on a value-conservation "
                        f"path but rounds {rounding.upper()} (protocol-favorable is "
                        f"{expected.upper()}); can a dust-granularity repeat net value "
                        f"out, or does a deposit+withdraw round-trip net positive?"),
                })
    return rows


def scan_tree(root: Path):
    rows = []
    for p in _iter_source_files(root):
        try:
            rel = str(p.relative_to(root))
        except ValueError:
            rel = str(p)
        rows.extend(scan_file(p, rel))
    return rows


def _emit_sidecar(ws: Path, rows):
    outdir = ws / ".auditooor"
    outdir.mkdir(parents=True, exist_ok=True)
    out = outdir / _SIDE_NAME
    with out.open("w") as fh:
        for r in rows:
            fh.write(json.dumps(r) + "\n")
    return out


def _summary(rows):
    fired = [r for r in rows if r.get("fires")]
    return {
        "schema": HYP_SCHEMA,
        "capability": _CAPABILITY,
        "enforcement_points": len(rows),
        "fired": len(fired),
        "verdict": "needs-fuzz" if fired else "clean-advisory",
        "advisory": True,
        "auto_credit": False,
    }


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="MQ-C01 rounding-direction-consistency screen (advisory)")
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
        cand = Path("/Users/wolf/audits") / args.workspace
        if cand.exists():
            ws = cand
    side = ws / ".auditooor" / _SIDE_NAME

    if args.check:
        rows = []
        if side.exists():
            rows = [json.loads(l) for l in side.read_text().splitlines() if l.strip()]
        summ = _summary(rows)
        summ["source"] = "sidecar"
        print(json.dumps(summ, indent=2))
        return 1 if (strict and summ["fired"]) else 0

    src = ws / "src"
    root = src if src.exists() else ws
    rows = scan_tree(root)
    _emit_sidecar(ws, rows)
    summ = _summary(rows)
    print(json.dumps(summ, indent=2))
    return 1 if (strict and summ["fired"]) else 0


if __name__ == "__main__":
    sys.exit(main())
