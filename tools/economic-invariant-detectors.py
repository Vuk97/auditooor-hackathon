#!/usr/bin/env python3
"""Economic / liveness invariant detector pack (generic, workspace-driven).

The 27k shape-detector corpus is overwhelmingly POSITIVE-PRESENCE: it flags the
existence of a bad pattern (a reentrancy call, a missing modifier, an unchecked
return). It is structurally blind to a whole bug CLASS that is defined by the
ABSENCE of an economic floor or by a LIVENESS coupling that only a domain reader
spots:

  * dust-debt / dust-collateral positions that are unprofitable to liquidate
    (no minimum-position / min-debt floor enforced anywhere).
  * liquidation that allows a partial / residual leftover (no full-close gate),
    leaving an unprofitable-to-clean residue.
  * withdrawal-liveness: a user's withdrawable amount gated on a SHARED pool that
    others must first repay into (withdraw can revert through no fault of the
    withdrawer).
  * bad-debt-socialization: loss spread across a shared index / lossFactor with
    no per-position floor bounding how small a socialized position can be.
  * oracle-liveness DoS on supply / collateral-add paths: an oracle call that can
    revert (price()==0 reverting, stale-revert) sitting on a path that should not
    need a live oracle, freezing deposits.

This pack pattern-matches the SOURCE for the STRUCTURAL ABSENCE of the economic
floor, plus the STRUCTURAL PRESENCE of the liveness coupling. Each hit is a
PROMPT for an agentic verdict, not a finding: over-inclusion is acceptable, the
verdict step rules out false positives.

Anchor bug families (the classes positive-presence shape-detectors miss):
  * dust-debt / dust-collateral unprofitable to liquidate (no min-position floor).
  * liquidators allowed to leave a dust collateral/debt residual (no full-close).
  * deposit / add-collateral path coupled to a live oracle that can revert.

GENERICITY: this tool has NO hardcoded workspace path, function name, finding id,
or contract name in its body. It takes --workspace <path> and operates on ANY
workspace's source. It is language-aware (Solidity + Rust/Go/Move/Cairo) via
extensible pattern tables and env hooks. The validation anchors and any target-
specific names live ONLY in the sibling unittest, never in this tool body.

Schema: auditooor.economic_invariant_detectors.v1

Env extension hooks (newline-separated regex appended to the builtin table):
  AUDITOOOR_ECON_DEBT_SINK_PATTERNS      - extra debt/credit state-write idioms
  AUDITOOOR_ECON_COLLATERAL_PATTERNS     - extra collateral state-write idioms
  AUDITOOOR_ECON_FLOOR_PATTERNS          - extra min-floor guard idioms (suppressors)
  AUDITOOOR_ECON_FULLCLOSE_PATTERNS      - extra full-close gate idioms (suppressors)
  AUDITOOOR_ECON_ORACLE_CALL_PATTERNS    - extra oracle-read idioms
  AUDITOOOR_ECON_SHARED_POOL_PATTERNS    - extra shared-pool / withdrawable idioms
  AUDITOOOR_ECON_LIQUIDATE_PATTERNS      - extra liquidation-entry idioms
  AUDITOOOR_ECON_SUPPLY_PATTERNS         - extra supply/deposit-entry idioms

Generic: any workspace, any language. Dependency-free stdlib python3.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA = "auditooor.economic_invariant_detectors.v1"

# Source-file extensions we will scan. Anything else is skipped.
_SOURCE_EXTS = {".sol", ".vy", ".rs", ".go", ".move", ".cairo"}

# Directory components that mark a vendored / dependency / generated / test tree.
_VENDOR_MARKERS = {
    "node_modules", "vendor", "lib", "third_party", "thirdparty",
    "dependencies", ".git", "target", "out", "artifacts", "cache",
    "build", "dist", "generated", "mock", "mocks", "test", "tests",
    "script", "scripts",
}


def _env_patterns(name: str) -> list[str]:
    raw = os.environ.get(name, "")
    return [ln.strip() for ln in raw.splitlines() if ln.strip()]


def _compile(patterns: list[str]) -> list["re.Pattern[str]"]:
    out: list[re.Pattern[str]] = []
    for p in patterns:
        try:
            out.append(re.compile(p))
        except re.error:
            continue
    return out


# ---------------------------------------------------------------------------
# Pattern tables. Language-agnostic, best-effort. Each is a list of raw regex
# strings; env hooks append to the builtin list before compilation.
# ---------------------------------------------------------------------------

# A function-entry header (any supported language).
_FN_HEADER = [
    r"\bfunction\s+([A-Za-z_]\w*)\s*\(",        # solidity / vyper-ish
    r"\bdef\s+([A-Za-z_]\w*)\s*\(",             # vyper
    r"\bfn\s+([A-Za-z_]\w*)\s*[<(]",            # rust
    r"\bfunc\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)\s*\(",  # go (incl receivers)
    r"\bpublic\s+(?:entry\s+)?fun\s+([A-Za-z_]\w*)\s*[<(]",  # move
    r"\bfn\s+([A-Za-z_]\w*)\s*\(",              # cairo
]

# Liquidation entrypoint name idioms (the function whose RESIDUAL we care about).
_LIQUIDATE_PATTERNS = [
    r"\bliquidat",      # liquidate / liquidation / liquidatePosition
    r"\bseize\b",
    r"\bclose[_A-Z]?[Pp]osition",
    r"\bforeclos",
]

# Debt / credit state-write idioms - the position-debt sink we want a floor on.
_DEBT_SINK_PATTERNS = [
    r"\.debt\s*[-+]?=",
    r"\.debt\b",
    r"\.credit\s*[-+]?=",
    r"\bdebt\s*[-+:]?=",
    r"\bborrow(ed)?[_A-Za-z]*\s*[-+:]?=",
    r"\bdebt_shares?\b",
    r"\btotal_?debt\b",
]

# Collateral state-write idioms.
_COLLATERAL_PATTERNS = [
    r"\.collateral\b",
    r"\bcollateral\s*[-+:]?=",
    r"\bcollateral_?balance\b",
    r"\bseizedAssets?\b",
]

# Min-floor / dust-floor SUPPRESSOR idioms. If a liquidation/borrow/withdraw
# function contains one of these, the dust-floor smell is suppressed for it.
_FLOOR_PATTERNS = [
    r"\bMIN_?[A-Z_]*(DEBT|POSITION|COLLATERAL|BORROW|LOAN|AMOUNT|SIZE)\b",
    r"\bmin[_A-Za-z]*(Debt|Position|Collateral|Borrow|Loan|Amount|Size)\b",
    r"\bdust\b",
    r"\bDUST\b",
    r"\bminBorrow\b",
    r"\bminLoan\b",
    r"\bfloor\b",                # min-floor guards (zeroFloorSub is excluded below)
    r"\brequire\s*\([^)]*>=?\s*MIN",
]

# zeroFloorSub-style helpers are NOT min-floor guards; exclude them from the
# floor suppressor when they are the only "floor" token on the line.
_FALSE_FLOOR_RE = re.compile(r"zeroFloorSub|floorDiv|floorLog")

# Full-close gate SUPPRESSOR idioms: liquidation that forces position to fully
# close (no residual) -> suppresses the residual-dust smell.
_FULLCLOSE_PATTERNS = [
    r"\bdebt\s*==\s*0\b",
    r"\b==\s*0\b.*\b(close|clear|delete)\b",
    r"\bdelete\s+position\b",
    r"\bfullClose\b",
    r"\bfull_?close\b",
    r"\brepayAll\b",
    r"\bcloseFactor\s*==\s*WAD\b",
    r"\bonlyFullLiquidation\b",
]

# Oracle-read idioms (an external price/rate call that can revert).
_ORACLE_CALL_PATTERNS = [
    r"\.price\s*\(",
    r"\bIOracle\b",
    r"\boracle\.[A-Za-z_]\w*\s*\(",
    r"\blatestAnswer\s*\(",
    r"\blatestRoundData\s*\(",
    r"\bgetPrice\s*\(",
    r"\bget_price\s*\(",
    r"\bpeek\s*\(",
    r"\bquote\s*\(",
]

# Supply / collateral-add / deposit entrypoint name idioms (paths that should
# not strictly need a live oracle but might call one -> liveness DoS).
_SUPPLY_PATTERNS = [
    r"\bsupply[_A-Z]?[Cc]ollateral",
    r"\bsupply\b",
    r"\bdeposit[_A-Za-z]*\b",
    r"\baddCollateral\b",
    r"\badd_?collateral\b",
    r"\bmint\b",
]

# Shared-pool / withdrawable-coupling idioms: a withdraw whose amount is gated on
# a SHARED accumulator that others must replenish (liveness coupling).
_SHARED_POOL_PATTERNS = [
    r"\bwithdrawable\b",
    r"\btotalAssets?\b",
    r"\btotalSupply\b",
    r"\bavailableLiquidity\b",
    r"\bavailable_?liquidity\b",
    r"\btotalLiquidity\b",
    r"\btotal_?liquidity\b",
    r"\bcash\b",
    r"\bpool[_A-Za-z]*[Bb]alance\b",
    r"\bfree_?liquidity\b",
]

# Withdraw entrypoint idioms.
_WITHDRAW_PATTERNS = [
    r"\bwithdraw\b",
    r"\bredeem\b",
    r"\bunstake\b",
]

# Bad-debt socialization idioms (loss spread over a shared index).
_SOCIALIZE_PATTERNS = [
    r"\blossFactor\b",
    r"\bloss_?factor\b",
    r"\bbadDebt\b",
    r"\bbad_?debt\b",
    r"\bsocializ",
    r"\bwriteOff\b",
    r"\bwrite_?off\b",
]


def _build_table(builtin: list[str], env_name: str) -> list["re.Pattern[str]"]:
    return _compile(builtin + _env_patterns(env_name))


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _is_vendored(rel: str) -> bool:
    parts = [p for p in re.split(r"[\\/]", rel) if p]
    return any(p.lower() in _VENDOR_MARKERS for p in parts)


# ---------------------------------------------------------------------------
# Source-surface discovery.
# ---------------------------------------------------------------------------

def _discover_source_root(ws: Path) -> Path:
    """Canonical source root (tools/lib/source_root_resolver.py): the deepest dir
    containing ALL workspace source (Cargo crates/* aware, not src/src-biased)."""
    import importlib.util as _ilu
    _p = Path(__file__).resolve().parent / "lib" / "source_root_resolver.py"
    _s = _ilu.spec_from_file_location("auditooor_source_root_resolver", _p)
    _m = _ilu.module_from_spec(_s)
    _s.loader.exec_module(_m)
    return _m.resolve_src_roots(ws)[0]


def _load_inscope_file_set(ws: Path):
    """Return the AUTHORITATIVE in-scope file set from ``.auditooor/inscope_units.jsonl``
    (each line is JSON with a ``file`` key, ws-relative posix path), or ``None`` when
    no manifest exists (then no filtering - preserves legacy behavior).

    WHY: ``_discover_source_root`` walks the whole workspace, so on a multi-package
    monorepo the denominator gets polluted with OUT-OF-SCOPE packages. Honoring the
    in-scope manifest restores a scope-correct denominator. Disable with
    AUDITOOOR_FCC_NO_SCOPE_FILTER=1.
    """
    if os.environ.get("AUDITOOOR_FCC_NO_SCOPE_FILTER"):
        return None
    manifest = ws / ".auditooor" / "inscope_units.jsonl"
    if not manifest.is_file():
        return None
    files: set[str] = set()
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


def _norm_inscope(p: str) -> str:
    return str(p or "").strip().lstrip("./").replace("\\", "/")


def _iter_source_files(root: Path) -> list[Path]:
    out: list[Path] = []
    for p in sorted(root.rglob("*")):
        if not p.is_file():
            continue
        if p.suffix.lower() not in _SOURCE_EXTS:
            continue
        try:
            rel = str(p.relative_to(root))
        except ValueError:
            rel = str(p)
        if _is_vendored(rel):
            continue
        out.append(p)
    return out


_FN_HEADER_RES = _compile(_FN_HEADER)

# Comment strippers. Comments must not satisfy a guard (false suppression) nor
# create a false oracle/debt hit. We blank out // line comments, /* */ block
# comments, and # line comments (rust/go/move/cairo all use // or #).
_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)
_LINE_COMMENT_RE = re.compile(r"(//|#).*?$", re.MULTILINE)


def _strip_comments(text: str) -> str:
    # replace block comments with equal-length newlines to preserve line numbers
    def _blank_block(m: "re.Match[str]") -> str:
        return "".join("\n" if c == "\n" else " " for c in m.group(0))
    text = _BLOCK_COMMENT_RE.sub(_blank_block, text)
    text = _LINE_COMMENT_RE.sub("", text)
    return text


def _split_functions(text: str) -> list[dict]:
    """Best-effort split of a source file into function spans.

    Returns a list of {name, start_line, end_line, body}. Uses brace-depth
    tracking from each function header to the matching close brace. For
    brace-less languages (vyper python-style) we fall back to next-header span.
    """
    lines = text.splitlines()
    headers: list[tuple[int, str]] = []  # (line_index, fn_name)
    for i, ln in enumerate(lines):
        for rx in _FN_HEADER_RES:
            m = rx.search(ln)
            if m:
                name = m.group(1) if m.groups() else ln.strip()[:40]
                headers.append((i, name))
                break
    funcs: list[dict] = []
    has_braces = "{" in text
    for idx, (hline, name) in enumerate(headers):
        if has_braces:
            # brace-depth walk
            depth = 0
            started = False
            end = hline
            for j in range(hline, len(lines)):
                depth += lines[j].count("{") - lines[j].count("}")
                if "{" in lines[j]:
                    started = True
                if started and depth <= 0:
                    end = j
                    break
            else:
                end = len(lines) - 1
        else:
            end = headers[idx + 1][0] - 1 if idx + 1 < len(headers) else len(lines) - 1
        body = "\n".join(lines[hline : end + 1])
        funcs.append(
            {"name": name, "start_line": hline + 1, "end_line": end + 1, "body": body}
        )
    return funcs


def _any(res: list["re.Pattern[str]"], s: str) -> bool:
    return any(rx.search(s) for rx in res)


def _floor_present(res: list["re.Pattern[str]"], body: str) -> bool:
    """A floor guard is present only if a floor token appears that is NOT merely
    a zeroFloorSub-style helper."""
    for rx in res:
        for m in rx.finditer(body):
            seg = body[max(0, m.start() - 20) : m.end() + 20]
            if _FALSE_FLOOR_RE.search(seg) and rx.pattern == r"\bfloor\b":
                continue
            return True
    return False


# An assignment / state-mutation operator (so we only fire on functions that
# actually WRITE state, not interface declarations or pure getters).
_ASSIGN_RE = re.compile(r"[-+*/]?=(?!=)|\bdelete\b|\bpush\s*\(|\bsetBit\b|\bclearBit\b")
# Signature-only declaration (no body): interface / abstract function rows end in
# ';' with no '{'. We skip those for the write-path detectors.
def _is_implemented(body: str) -> bool:
    return "{" in body


def _has_assignment(body: str) -> bool:
    # strip the header line so the param list '=' defaults don't count
    return bool(_ASSIGN_RE.search(body))


# Oracle-call-inside-a-loop: a price/oracle read inside a while/for loop on a
# liquidation path is a liveness DoS - one reverting oracle bricks the whole
# liquidation (all collaterals are iterated).
_LOOP_RE = re.compile(r"\b(while|for)\b[^{;]*\{")


def _oracle_in_loop(oracle_res: list["re.Pattern[str]"], body: str) -> bool:
    # crude: find a loop opener, then check for an oracle call after it within
    # the same brace block (best-effort: anywhere after the first loop opener).
    m = _LOOP_RE.search(body)
    if not m:
        return False
    tail = body[m.start():]
    return _any(oracle_res, tail)


# ---------------------------------------------------------------------------
# Detectors. Each returns a list of hit dicts.
# ---------------------------------------------------------------------------

def _detect(ws: Path) -> dict:
    tbl = {
        "liquidate": _build_table(_LIQUIDATE_PATTERNS, "AUDITOOOR_ECON_LIQUIDATE_PATTERNS"),
        "debt": _build_table(_DEBT_SINK_PATTERNS, "AUDITOOOR_ECON_DEBT_SINK_PATTERNS"),
        "collateral": _build_table(_COLLATERAL_PATTERNS, "AUDITOOOR_ECON_COLLATERAL_PATTERNS"),
        "floor": _build_table(_FLOOR_PATTERNS, "AUDITOOOR_ECON_FLOOR_PATTERNS"),
        "fullclose": _build_table(_FULLCLOSE_PATTERNS, "AUDITOOOR_ECON_FULLCLOSE_PATTERNS"),
        "oracle": _build_table(_ORACLE_CALL_PATTERNS, "AUDITOOOR_ECON_ORACLE_CALL_PATTERNS"),
        "supply": _build_table(_SUPPLY_PATTERNS, "AUDITOOOR_ECON_SUPPLY_PATTERNS"),
        "shared": _build_table(_SHARED_POOL_PATTERNS, "AUDITOOOR_ECON_SHARED_POOL_PATTERNS"),
        "withdraw": _compile(_WITHDRAW_PATTERNS),
        "socialize": _compile(_SOCIALIZE_PATTERNS),
    }

    root = _discover_source_root(ws)
    files = _iter_source_files(root)

    # SCOPE-AUTHORITATIVE filter: when an in-scope manifest exists, drop files
    # whose ws-relative path is not listed (preserves legacy when manifest absent).
    _inscope = _load_inscope_file_set(ws)
    out_of_scope_dropped = 0
    if _inscope is not None:
        kept: list[Path] = []
        for fp in files:
            try:
                rel_fp = _norm_inscope(str(fp.relative_to(ws)))
            except ValueError:
                rel_fp = _norm_inscope(fp.name)
            if rel_fp in _inscope:
                kept.append(fp)
            else:
                out_of_scope_dropped += 1
        files = kept

    hits: list[dict] = []
    files_scanned = 0
    functions_scanned = 0

    for fp in files:
        try:
            text = fp.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        files_scanned += 1
        try:
            rel = str(fp.relative_to(root))
        except ValueError:
            rel = fp.name
        text = _strip_comments(text)
        funcs = _split_functions(text)
        functions_scanned += len(funcs)
        for fn in funcs:
            name = fn["name"]
            body = fn["body"]
            loc = f"{rel}:{fn['start_line']}"

            # Skip interface / abstract declarations and pure getters: the
            # economic-floor detectors are about WRITE paths. A function with no
            # body or no assignment is a signature/view -> not a write path.
            implemented = _is_implemented(body)
            writes = implemented and _has_assignment(body)

            is_liq = _any(tbl["liquidate"], name)
            is_supply = _any(tbl["supply"], name)
            is_withdraw = _any(tbl["withdraw"], name)
            touches_debt = _any(tbl["debt"], body)
            touches_collat = _any(tbl["collateral"], body)
            has_floor = _floor_present(tbl["floor"], body)
            has_fullclose = _any(tbl["fullclose"], body)
            calls_oracle = _any(tbl["oracle"], body)
            oracle_in_loop = _oracle_in_loop(tbl["oracle"], body)
            touches_shared = _any(tbl["shared"], body)
            socializes = _any(tbl["socialize"], body)

            # DET-1: dust-debt / dust-collateral floor missing on a debt/collateral
            # mutating entrypoint (borrow, liquidate, withdraw-collateral). The
            # smell fires when a position-debt or collateral WRITE exists with NO
            # min-floor guard in the same function.
            if writes and (touches_debt or touches_collat) and not has_floor:
                hits.append({
                    "detector": "ECON-DET-1-dust-position-no-min-floor",
                    "class": "dust-debt / dust-collateral (unprofitable-to-liquidate)",
                    "file_line": loc,
                    "function": name,
                    "evidence": "debt/collateral state-write with no minimum-position floor guard in scope",
                    "anchor": "TRST-M-3 / Cantina-3.1.1",
                    "question": (
                        f"Can {name} leave a position whose debt/collateral is so small "
                        "that the gas to liquidate it exceeds the seized value? "
                        "Is there ANY min-debt / min-position floor enforced elsewhere?"
                    ),
                })

            # DET-2: liquidation allows partial/residual (no full-close gate).
            if is_liq and writes and (touches_debt or touches_collat) and not has_fullclose and not has_floor:
                hits.append({
                    "detector": "ECON-DET-2-liquidation-allows-residual-dust",
                    "class": "liquidation-residual-dust (partial close leaves dust)",
                    "file_line": loc,
                    "function": name,
                    "evidence": "liquidation entrypoint with no full-close gate and no min-floor on the residual",
                    "anchor": "Cantina-3.1.1 / TRST-M-3",
                    "question": (
                        f"Does {name} require the position be fully closed, or can a "
                        "liquidator repay/seize a partial amount and leave a dust residue "
                        "that no one is then incentivized to clean up?"
                    ),
                })

            # DET-3: bad-debt socialization with no per-position floor. Only on a
            # real write path (skips interface getters that merely NAME lossFactor).
            if writes and socializes and not has_floor:
                hits.append({
                    "detector": "ECON-DET-3-bad-debt-socialization-no-floor",
                    "class": "bad-debt-socialization (loss spread, no min-position floor)",
                    "file_line": loc,
                    "function": name,
                    "evidence": "bad-debt / lossFactor socialization with no min-position floor bounding the socialized residue",
                    "anchor": "TRST-M-3 (dust feeds socialized bad debt)",
                    "question": (
                        f"Does {name} socialize loss across a shared index/lossFactor? "
                        "Can a flood of dust positions amplify the socialized loss because "
                        "no min-position floor bounds how small each contributor can be?"
                    ),
                })

            # DET-4a: oracle-liveness DoS on a supply/collateral-add path - the
            # path reads a live oracle that should not be needed (adding
            # collateral only INCREASES safety) -> a reverting oracle freezes
            # deposits. Cantina-3.1.2 is the INVERSE recommendation (revert
            # supplyCollateral if oracle broken); both framings live on the same
            # supply<->oracle coupling surface, so we surface the coupling for
            # the agentic verdict either way.
            if is_supply and implemented and calls_oracle:
                hits.append({
                    "detector": "ECON-DET-4-oracle-liveness-dos-on-supply",
                    "class": "oracle-liveness-DoS (deposit/supply path coupled to live oracle)",
                    "file_line": loc,
                    "function": name,
                    "evidence": "supply/deposit entrypoint reads an oracle that can revert (price()==0 / stale-revert)",
                    "anchor": "Cantina-3.1.2",
                    "question": (
                        f"Does {name} depend on a live oracle on a path that should not "
                        "need one? If the collateral oracle reverts/returns 0, are deposits "
                        "frozen (or does the add-collateral path fail to revert when it should)?"
                    ),
                })

            # DET-4b: oracle-read INSIDE A LOOP on a liquidation / health path.
            # All collaterals are iterated; one reverting oracle bricks the whole
            # liquidation (the position becomes un-liquidatable -> bad-debt / DoS).
            if implemented and oracle_in_loop and (is_liq or touches_debt or touches_collat):
                hits.append({
                    "detector": "ECON-DET-4-oracle-liveness-dos-in-loop",
                    "class": "oracle-liveness-DoS (looped oracle read; one revert bricks liquidation/health)",
                    "file_line": loc,
                    "function": name,
                    "evidence": "oracle price() read inside a loop over collaterals; a single reverting oracle DoSes the whole path",
                    "anchor": "Cantina-3.1.2 (oracle-liveness family)",
                    "question": (
                        f"Does {name} loop over collaterals calling oracle.price()? If ONE "
                        "collateral oracle reverts, is the WHOLE position un-liquidatable, "
                        "letting the borrower block liquidation and force bad debt?"
                    ),
                })

            # DET-5: withdrawal-liveness coupling on a shared pool.
            if is_withdraw and implemented and touches_shared:
                hits.append({
                    "detector": "ECON-DET-5-withdraw-liveness-shared-pool",
                    "class": "withdrawal-liveness (withdrawable gated on shared pool others must replenish)",
                    "file_line": loc,
                    "function": name,
                    "evidence": "withdraw amount gated on a shared accumulator (withdrawable/totalAssets/cash) that others must repay into",
                    "anchor": "withdrawal-liveness class (TRST/Cantina liveness family)",
                    "question": (
                        f"Can {name} revert because a SHARED pool (withdrawable/cash) is "
                        "insufficient even though the withdrawer's own accounting is solvent? "
                        "Is a user's liveness coupled to whether OTHER borrowers repay?"
                    ),
                })

    # de-dup identical (detector,file_line)
    seen: set[str] = set()
    uniq: list[dict] = []
    for h in hits:
        k = f"{h['detector']}|{h['file_line']}"
        if k in seen:
            continue
        seen.add(k)
        uniq.append(h)

    by_detector: dict[str, int] = {}
    for h in uniq:
        by_detector[h["detector"]] = by_detector.get(h["detector"], 0) + 1

    return {
        "schema": SCHEMA,
        "generated_at": _now(),
        "workspace": str(ws),
        "source_root": str(root),
        "files_scanned": files_scanned,
        "functions_scanned": functions_scanned,
        "hit_count": len(uniq),
        "by_detector": by_detector,
        "hits": uniq,
        "verdict": "hits-found" if uniq else "no-economic-invariant-smell",
        "scope_filter": {
            "applied": _inscope is not None,
            "source": ".auditooor/inscope_units.jsonl" if _inscope is not None else None,
            "in_scope_files": (len(_inscope) if _inscope is not None else None),
            "out_of_scope_dropped": out_of_scope_dropped,
        },
    }


def _emit_human(res: dict) -> str:
    out: list[str] = []
    out.append(f"economic-invariant-detectors :: {res['workspace']}")
    out.append(f"source-root: {res['source_root']}")
    out.append(
        f"scanned {res['files_scanned']} files / {res['functions_scanned']} functions "
        f"-> {res['hit_count']} hits"
    )
    if not res["hits"]:
        out.append("verdict: no-economic-invariant-smell (honest empty)")
        return "\n".join(out)
    for det, n in sorted(res["by_detector"].items()):
        out.append(f"  {det}: {n}")
    out.append("")
    for h in res["hits"]:
        out.append(f"[{h['detector']}] {h['file_line']}  ({h['function']})")
        out.append(f"    class:    {h['class']}")
        out.append(f"    anchor:   {h['anchor']}")
        out.append(f"    evidence: {h['evidence']}")
        out.append(f"    Q:        {h['question']}")
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Economic / liveness invariant detector pack (generic).",
    )
    ap.add_argument("--workspace", required=True, help="audit workspace root")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument(
        "--only",
        default="",
        help="comma-separated detector substrings to filter (e.g. DET-1,DET-4)",
    )
    args = ap.parse_args(argv)

    ws = Path(args.workspace).expanduser()
    if not ws.is_dir():
        err = {"schema": SCHEMA, "verdict": "error", "error": f"workspace not found: {ws}"}
        print(json.dumps(err) if args.json else f"error: workspace not found: {ws}", file=sys.stderr)
        return 2

    res = _detect(ws)

    if args.only.strip():
        wants = [w.strip() for w in args.only.split(",") if w.strip()]
        res["hits"] = [h for h in res["hits"] if any(w in h["detector"] for w in wants)]
        res["hit_count"] = len(res["hits"])
        by: dict[str, int] = {}
        for h in res["hits"]:
            by[h["detector"]] = by.get(h["detector"], 0) + 1
        res["by_detector"] = by

    if args.json:
        print(json.dumps(res, indent=2))
    else:
        print(_emit_human(res))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
