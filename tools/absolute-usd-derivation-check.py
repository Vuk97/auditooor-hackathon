#!/usr/bin/env python3
"""absolute-usd-derivation-check.py - ABSOLUTE-USD-DERIVATION gate (pre-submit Check #148).

The predmkt lesson (2026-07-09, ground truth). A driving agent OVER-CLAIMED a
prediction-markets redeem slippage sandwich as "clears $1000 comfortably", citing a
Node.js "sweep" artifact that does NOT exist in the workspace. Independent verify:
the loss-denomination asset is GBYTE (obyte factory.oscript:58 default reserve_asset
'base'); victim loss 26,341,593 bytes; 1 GBYTE = 1e9 bytes; GBYTE ~ $5 => ~$0.13 -
roughly FOUR orders of magnitude UNDER the program's USD-1000 fund-loss floor (obyte
program_rules.json). A raw-unit PoC delta is NOT a dollar impact.

Every existing impact-family gate MISSED it:
  - Check #124 (r74-dollar-impact-gate) fires only when a dollar_impact sidecar exists;
    the draft cited a "sweep", not a sidecar -> pass-not-applicable.
  - Check #145 (program-rules-check) does a FULL-PHRASE substring test; the floor
    sentence never appears verbatim in a draft -> no match.
  - Check #137 (impact-characterization) has NO absolute-USD axis.
  - Check #35 (financial-impact) only requires an assertEq near a hedge phrase.

This gate makes a HIGH/CRITICAL fund-loss finding on a floor-declaring program carry a
four-part, source-anchored USD derivation, and flags any cited evidence artifact absent
from the workspace tree.

TRIGGER (gate is N/A unless ALL hold; else verdict=pass-not-applicable, rc=0):
  1. claimed tier in {HIGH, CRITICAL}
  2. the workspace declares a fund-loss USD floor
  3. the finding is fund-loss / value-extraction

DERIVATION CHECK (when triggered) - require all four parts, each source-anchored:
  (a) ASSET-IDENTITY: the loss-denomination asset named AND cited to an in-scope
      file:line.
  (b) UNIT->USD CONVERSION: a unit-scale line (e.g. "1 GBYTE = 1e9 bytes") AND a price
      carrying a named source (coingecko / oracle / spot / "as of" ...).
  (c) MARKET-SIZE / TVL SCENARIO: an explicit victim-size / TVL / order-size figure
      producing the raw delta.
  (d) ABSOLUTE $ FIGURE vs FLOOR: a computed absolute USD result shown against the floor
      (a $<n> figure AND an explicit >= / < comparison).
Plus a best-effort magnitude recompute: when the draft's own asset+unit+size numbers are
extractable, compute derived_usd and FLAG a >2 order-of-magnitude gap vs every stated $
figure (the predmkt ~$0.13-vs-$1000 gap).
Plus an artifact-existence sub-check: a cited evidence artifact (a .js/.json/.log/... file
name) absent from the workspace tree is FLAGGED.

Advisory-first: WARN by default (byte-compatible with today's output); hard-BLOCK only
under AUDITOOOR_ABSOLUTE_USD_STRICT (or --strict), mirroring Checks #138-140.

Verdicts: pass-not-applicable | pass-derivation-complete | warn-derivation-incomplete
(default) | fail-derivation-incomplete (strict) | ok-rebuttal.

Rebuttal marker (greens with an operator note; same convention as r74 / mock-reference):
    <!-- absolute-usd-rebuttal: <reason up to 200 chars> -->

CLI:
    absolute-usd-derivation-check.py --workspace <ws> --draft <md>
        [--severity S] [--poc-dir <dir>] [--strict] [--json]
    (--severity is case-insensitive: auto / low / medium / high / critical, or the
    title-case form pre-submit-check.sh passes, e.g. "High".)
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

TOOLS_DIR = Path(__file__).resolve().parent

SCHEMA = "auditooor.absolute_usd_derivation.v1"
GATE = "ABSOLUTE-USD-DERIVATION"

# --- reuse: sibling-module loader (copied verbatim from
# impact-characterization-completeness-check.py:63-77) so classify_axes is the SAME
# classifier Check #137 uses; do NOT write a new impact classifier. ---
def _load_module(filename: str, modname: str):
    import importlib.util

    path = TOOLS_DIR / filename
    if not path.is_file():
        return None
    spec = importlib.util.spec_from_file_location(modname, path)
    if spec is None or spec.loader is None:
        return None
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)  # type: ignore[union-attr]
    except Exception:
        return None
    return mod


_SEVCAL = _load_module("severity-calibration-gate.py", "_ausd_sevcal")

# --- shared label source of truth (Task 2): the four required-derivation labels are
# defined ONCE in tools/lib/dollar_impact_labels.py and reused by BOTH this gate and the
# filing brief in dispatch-agent-with-prebriefing.py, so the brief that INSTRUCTS an agent
# and the gate that CHECKS it cannot drift. A fallback keeps the gate importable in
# isolation; a test asserts brief==gate==lib so any real drift is caught. ---
try:
    import sys as _sys
    if str(TOOLS_DIR) not in _sys.path:
        _sys.path.insert(0, str(TOOLS_DIR))
    from lib import dollar_impact_labels as _dil  # type: ignore
    DERIVATION_LABELS = tuple(_dil.DOLLAR_IMPACT_DERIVATION_LABELS)
    _PART_KEYS = tuple(_dil.DERIVATION_PART_KEYS)
except Exception:  # pragma: no cover - lib optional; degrade to an identical fallback
    DERIVATION_LABELS = (
        "Asset identity", "Unit->USD", "Market-size scenario", "Absolute $ vs floor")
    _PART_KEYS = ("asset_identity", "unit_to_usd", "market_size", "absolute_vs_floor")

# The canonical required-derivation labels this gate enforces (exported for the
# brief<->gate no-drift test). Ordered (a)-(d), aligned 1:1 with _PART_KEYS.
REQUIRED_DERIVATION_LABELS = DERIVATION_LABELS

# Fund-loss impact_kinds emitted by classify_axes (severity-calibration-gate.py).
_FUND_LOSS_KINDS = {
    "user_fund_theft", "protocol_yield_theft", "permanent_freeze", "temporary_freeze",
}

# --- regexes ---
# reuse r74-dollar-impact-gate.py:37-41 SEVERITY_RE convention.
SEVERITY_RE = re.compile(
    r"^(?:#+\s*)?severity\s*[:=]?\s*(low|medium|high|critical)\b",
    re.IGNORECASE | re.MULTILINE,
)
REBUTTAL_RE = re.compile(
    r"<!--\s*absolute-usd-rebuttal:\s*(.{1,200}?)\s*-->", re.IGNORECASE | re.DOTALL,
)
# Task 3: accepted rebuttal form is `absolute-usd-rebuttal: receipt:<id> <reason>`. A bare
# reason (no `receipt:` reference) no longer self-clears UNDER STRICT - it must point at an
# independent-verification receipt validated by verification-receipt-check.py (gate=absolute-usd).
RECEIPT_REF_RE = re.compile(r"^\s*receipt:\s*([\w./-]+)", re.IGNORECASE)
# gate id used when validating the receipt via verification-receipt-check.py
RECEIPT_GATE = "absolute-usd"
# reuse impact-characterization-completeness-check.py:180 SOURCE_CITED_RE (file.ext:line).
SOURCE_CITED_RE = re.compile(r"[\w./-]+\.\w+:\d+")

# A bare dollar figure. $1,000 / $1000 / USD 1000 / USD 1,000.50
DOLLAR_RE = re.compile(r"(?:\$|USD\s?)\s?(\d[\d,]*(?:\.\d+)?)", re.IGNORECASE)
# Floor-clearing / floor-referencing language (the OR-arm signal that catches the
# predmkt "clears $1000 comfortably" even when classify_axes returns unknown).
CLEAR_KW_RE = re.compile(
    r"\b(clear(?:s|ed)?|exceed(?:s|ed)?|above|comfortabl[ey]|floor|minimum|"
    r"well over|surpass(?:es|ed)?|greater than|more than)\b",
    re.IGNORECASE,
)
# Asset-identity keywords (loss-denomination asset).
ASSET_KW_RE = re.compile(
    r"\b(reserve[_ ]?asset|reserve|asset|token|denominat\w+|currency|collateral|"
    r"coin|stablecoin|underlying)\b",
    re.IGNORECASE,
)
# Unit-scale line: "1 GBYTE = 1e9 bytes", "1 ETH = 1e18 wei".
UNIT_SCALE_RE = re.compile(
    r"\b\d[\d,.]*\s*[A-Za-z]{2,}\s*=\s*[\d.,]*\s*(?:e\d+|[A-Za-z0-9][\w]*)",
)
PRICE_RE = re.compile(r"(?:\$|USD\s?)\s?\d[\d,]*(?:\.\d+)?", re.IGNORECASE)
PRICE_SOURCE_KW_RE = re.compile(
    r"\b(coingecko|coinmarketcap|coin ?gecko|cmc|oracle|as of|price source|"
    r"spot|binance|kraken|coinbase|chainlink|market price)\b",
    re.IGNORECASE,
)
MARKET_KW_RE = re.compile(
    r"\b(TVL|market size|market cap|victim|order size|position size|position|"
    r"liquidity|notional|volume|trade size|bet size|pool size|deposit size|principal)\b",
    re.IGNORECASE,
)
NUM_RE = re.compile(r"\d")
COMPARE_RE = re.compile(
    r"(>=|<=|>|<|≥|≤|\babove\b|\bbelow\b|\bexceed(?:s|ed)?\b|\bunder\b|"
    r"\bover\b|\bgreater than\b|\bless than\b|\bat least\b|\bmore than\b)",
    re.IGNORECASE,
)

# Evidence-artifact extensions (an output/script/log the finding cites as proof).
# Deliberately EXCLUDES source extensions (.sol/.oscript/.rs/.go/.move/.aa/...) so a
# legitimate source citation (factory.oscript:58) is never mistaken for a missing
# evidence artifact.
_ARTIFACT_EXTS = (
    "js", "mjs", "cjs", "json", "jsonl", "ndjson", "log", "py", "sh",
    "txt", "csv", "out", "tsv", "html",
)
_ARTIFACT_FILE_RE = re.compile(
    r"\b([\w./-]+\.(?:" + "|".join(_ARTIFACT_EXTS) + r"))\b",
    re.IGNORECASE,
)
# Well-known runtime / library tokens that lexically look like "<name>.js" but are NOT
# cited evidence artifacts (Node.js is the runtime, not a file in the workspace). Skipping
# them keeps the artifact-existence flag pointed at the real absent evidence file.
_NON_ARTIFACT_BASENAMES = frozenset({
    "node.js", "vue.js", "react.js", "next.js", "nuxt.js", "d3.js", "three.js",
    "chart.js", "ember.js", "backbone.js", "angular.js", "express.js", "jquery.js",
    "typescript.js", "javascript.js", "ecma.js",
})


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", s or "").strip().lower()


# --- reuse: program_rules.json loader (from program-rules-check.py:40-47) ---
def _load_rules(ws: Path) -> dict | None:
    p = ws / ".auditooor" / "program_rules.json"
    if not p.is_file():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (ValueError, OSError):
        return None


def _to_num(s: str) -> float | None:
    """Parse a human number: commas, decimals, or scientific (1e9)."""
    if not s:
        return None
    s = s.strip().replace(",", "")
    try:
        return float(s)
    except ValueError:
        return None


def parse_floor(rules: dict | None, ws: Path) -> tuple[int | None, str]:
    """Discover the program's fund-loss USD floor.

    Priority:
      (i)   explicit `fund_loss_floor_usd` key in program_rules.json.
      (ii)  regex over program_rules.json `invalid_impact_conditions` entries whose text
            contains "floor" or "below" (matches Obyte's "...below USD 1000 (fund-loss
            floor)" -> 1000). No schema change needed.
      (iii) SEVERITY.md lines carrying a floor-signal keyword (minimum impact / floor /
            below / at least) AND a USD / $ figure. (Reward-tier "up to $X" maxima carry no
            floor keyword, so they are NOT mistaken for a floor.)
    """
    # (i)
    if isinstance(rules, dict):
        v = rules.get("fund_loss_floor_usd")
        if isinstance(v, (int, float)) and v > 0:
            return int(v), "program_rules.json:fund_loss_floor_usd"
        if isinstance(v, str):
            n = _to_num(v)
            if n and n > 0:
                return int(n), "program_rules.json:fund_loss_floor_usd"

    # (ii)
    if isinstance(rules, dict):
        for entry in rules.get("invalid_impact_conditions") or []:
            low = _norm(str(entry))
            if "floor" not in low and "below" not in low:
                continue
            m = re.search(r"(?:usd|\$)\s*([\d,]+(?:\.\d+)?)", low)
            if m:
                n = _to_num(m.group(1))
                if n and n > 0:
                    return int(n), "program_rules.json:invalid_impact_conditions"

    # (iii)
    sev_md = ws / "SEVERITY.md"
    if sev_md.is_file():
        try:
            for line in sev_md.read_text(encoding="utf-8", errors="replace").splitlines():
                low = line.lower()
                if not any(k in low for k in
                           ("minimum impact", "floor", "below", "at least")):
                    continue
                m = re.search(r"(?:usd|\$)\s*([\d,]+(?:\.\d+)?)", low)
                if m:
                    n = _to_num(m.group(1))
                    if n and n > 0:
                        return int(n), "SEVERITY.md"
        except OSError:
            pass

    return None, "no-floor-declared"


def detect_severity(text: str, override: str | None) -> str:
    if override and override.lower() != "auto":
        return override.upper()
    m = SEVERITY_RE.findall(text)
    return m[0].upper() if m else "UNKNOWN"


def _line_has_both(text: str, re_a: re.Pattern, re_b: re.Pattern) -> bool:
    for line in text.splitlines():
        if re_a.search(line) and re_b.search(line):
            return True
    return False


# Task 1: a properly-derived bullet that hard-wraps across physical lines must not
# FALSE-FAIL. Group physical lines into LOGICAL units so a markdown bullet + its
# contiguous continuation lines are scanned as one unit, WITHOUT collapsing unrelated
# prose paragraphs together (which would false-PASS the predmkt bare-assertion, whose
# asset keyword and a stray number live on different prose lines).
_BULLET_RE = re.compile(r"^\s*(?:[-*+]|\d+[.)])\s+")


def _logical_units(text: str) -> list[str]:
    """Return logical units. A bullet line opens a unit and absorbs its contiguous
    continuation lines (non-blank, non-bullet, non-heading); a blank line or a new
    bullet/heading closes it. Every non-bullet prose/heading line that is NOT a
    continuation stays its own single-line unit (preserving per-physical-line behavior
    for prose, so a prose paragraph is never joined into a single scannable block)."""
    units: list[str] = []
    cur: list[str] | None = None

    def _flush() -> None:
        nonlocal cur
        if cur is not None:
            units.append(" ".join(cur))
            cur = None

    for line in text.splitlines():
        if _BULLET_RE.match(line):
            _flush()
            cur = [line]
        elif line.strip() == "":
            _flush()
        elif line.lstrip().startswith("#"):
            _flush()
            units.append(line)
        else:
            if cur is not None:  # continuation of an open bullet (hard-wrap)
                cur.append(line)
            else:                # standalone prose -> its own single-line unit
                units.append(line)
    _flush()
    return units


def _unit_has_both(units: list[str], re_a: re.Pattern, re_b: re.Pattern) -> bool:
    return any(re_a.search(u) and re_b.search(u) for u in units)


def is_fund_loss(text: str) -> tuple[bool, str]:
    """Fund-loss classification: classify_axes impact_kind membership OR a fallback
    signal that the draft asserts a bare dollar figure near a floor-clearing claim.

    The OR-arm is what actually catches the predmkt "clears $1000 comfortably" even when
    classify_axes returns unknown for a slippage/sandwich framing."""
    kind = "unknown"
    if _SEVCAL is not None:
        try:
            kind = _SEVCAL.classify_axes(text).get("impact_kind", "unknown")
        except Exception:
            kind = "unknown"
    if kind in _FUND_LOSS_KINDS:
        return True, f"classify_axes:{kind}"
    # fallback: $ figure co-occurring with a floor-clearing keyword on the same line.
    if _line_has_both(text, DOLLAR_RE, CLEAR_KW_RE):
        return True, "dollar-near-floor-claim"
    return False, f"classify_axes:{kind}"


def _magnitude_flag(text: str) -> str | None:
    """Best-effort recompute. When a unit-scale (X unit = Y base), a raw base delta, and a
    price are all extractable, compute derived_usd and FLAG a >2 order-of-magnitude gap vs
    EVERY stated $ figure (predmkt: ~$0.13 derived vs a claimed >$1000). Fully guarded:
    any parse uncertainty -> no flag (the (a)-(d) presence checks are the primary gate)."""
    try:
        um = re.search(
            r"\b1\s*([A-Za-z]{2,})\s*=\s*([\d.,]+(?:e\d+)?)\s*([A-Za-z]+)", text)
        if not um:
            return None
        big_unit, factor_s, small_unit = um.group(1), um.group(2), um.group(3)
        factor = _to_num(factor_s)
        if not factor or factor <= 0:
            return None
        # raw base-unit delta: the LARGEST number immediately followed by small_unit,
        # excluding the unit-scale definition value itself.
        deltas = []
        for m in re.finditer(
            r"([\d][\d,]*(?:\.\d+)?(?:e\d+)?)\s*" + re.escape(small_unit), text,
            re.IGNORECASE,
        ):
            n = _to_num(m.group(1))
            if n is not None and n != factor:
                deltas.append(n)
        if not deltas:
            return None
        base_delta = max(deltas)
        # price: a $ figure on a line that also names big_unit or a price source.
        price = None
        for line in text.splitlines():
            if big_unit.lower() in line.lower() or PRICE_SOURCE_KW_RE.search(line):
                pm = re.search(r"(?:\$|USD\s?)\s?([\d,]+(?:\.\d+)?)", line, re.IGNORECASE)
                if pm:
                    price = _to_num(pm.group(1))
                    if price and price > 0:
                        break
        if not price or price <= 0:
            return None
        derived = base_delta / factor * price
        if derived <= 0:
            return None
        # all stated $ figures.
        figures = [_to_num(g) for g in DOLLAR_RE.findall(text)]
        figures = [f for f in figures if f and f > 0]
        if not figures:
            return None
        close = any(0.01 <= (derived / f) <= 100 for f in figures)
        if not close:
            near = max(figures)
            return (f"derived USD ~{derived:.4g} is >2 orders of magnitude off every "
                    f"stated $ figure (nearest ${near:g})")
        return None
    except Exception:
        return None


def _find_in_ws(ws: Path, basename: str, timeout: int = 25) -> bool:
    """Bounded existence check (R76 workspace-grep idiom, adapted to filenames). Prunes
    node_modules/.git for speed on large trees; on timeout/error returns True (do not
    false-fail), mirroring r76-hallucination-guard.grep_excerpt."""
    if not basename:
        return True
    try:
        proc = subprocess.run(
            ["find", str(ws),
             "(", "-path", "*/node_modules", "-o", "-path", "*/.git", ")", "-prune",
             "-o", "-type", "f", "-name", basename, "-print"],
            capture_output=True, text=True, timeout=timeout,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return True
    return bool(proc.stdout.strip())


def check_artifacts(text: str, ws: Path | None) -> list[str]:
    """Scan the draft for cited evidence artifacts and FLAG any absent from the workspace.

    Predmkt cited a Node.js "sweep" (e.g. redeem-slippage-sweep.js) absent from the ws.
    Only concrete filenames with an EVIDENCE extension are checked - source citations
    (factory.oscript:58) carry a source extension and are ignored. Note the bare word
    "sweep" is NOT used as an existence key: the ws already ships aa-sweep-*.json files,
    so a keyword test would false-negative; a named .js artifact is what is verified."""
    if ws is None or not ws.is_dir():
        return []
    flagged: list[str] = []
    seen: set[str] = set()
    for m in _ARTIFACT_FILE_RE.finditer(text):
        raw = m.group(1)
        base = Path(raw).name
        if not base or base in seen:
            continue
        seen.add(base)
        if base.lower() in _NON_ARTIFACT_BASENAMES:
            continue
        if not _find_in_ws(ws, base):
            flagged.append(base)
    return sorted(set(flagged))


def check_derivation(text: str) -> tuple[dict[str, bool], list[str], str | None]:
    """Score parts (a)-(d) + the magnitude recompute. Returns (parts, missing, mag_flag)."""
    parts: dict[str, bool] = {}
    # Logical units so a hard-wrapped bullet is scanned as one unit (Task 1).
    units = _logical_units(text)
    # (a) ASSET-IDENTITY: asset keyword + a file:line citation within one logical unit.
    parts["asset_identity"] = _unit_has_both(units, ASSET_KW_RE, SOURCE_CITED_RE)
    # (b) UNIT->USD: a unit-scale line ANYWHERE + a price carrying a named source
    # (one logical unit: a $ figure + a source keyword).
    has_unit_scale = bool(UNIT_SCALE_RE.search(text))
    has_priced_source = _unit_has_both(units, PRICE_RE, PRICE_SOURCE_KW_RE)
    parts["unit_to_usd"] = has_unit_scale and has_priced_source
    # (c) MARKET-SIZE / TVL: a market-size keyword + a number within one logical unit.
    parts["market_size"] = _unit_has_both(units, MARKET_KW_RE, NUM_RE)
    # (d) ABSOLUTE $ vs FLOOR: a $ figure + an explicit comparison + a floor reference
    # (the word "floor" or a second $ figure) within one logical unit.
    part_d = False
    for u in units:
        if not (DOLLAR_RE.search(u) and COMPARE_RE.search(u)):
            continue
        if re.search(r"\bfloor\b", u, re.IGNORECASE) or len(DOLLAR_RE.findall(u)) >= 2:
            part_d = True
            break
    parts["absolute_vs_floor"] = part_d

    # Labels prefixed with the shared canonical DERIVATION_LABELS (Task 2 no-drift binding).
    _a, _b, _c, _d = DERIVATION_LABELS
    label = {
        "asset_identity": f"(a) {_a}: loss-denomination asset named + cited to "
                          "an in-scope file:line",
        "unit_to_usd": f"(b) {_b}: a unit-scale line + a price carrying a named source",
        "market_size": f"(c) {_c}: an explicit victim/TVL/order-size figure",
        "absolute_vs_floor": f"(d) {_d}: a computed $ result compared "
                             "(>=/</above/below) to the floor",
    }
    missing = [label[k] for k, ok in parts.items() if not ok]
    mag_flag = _magnitude_flag(text)
    return parts, missing, mag_flag


def _env_receipt_strict() -> bool:
    """Task 3: the receipt-backing requirement hard-blocks under this gate's own strict
    env OR the shared verification-receipt strict env. (The `strict` arg already folds in
    AUDITOOOR_ABSOLUTE_USD_STRICT / --strict.)"""
    v = os.environ.get("AUDITOOOR_VERIFICATION_RECEIPT_STRICT", "").strip().lower()
    return v in {"1", "true", "yes", "on"}


def _validate_receipt(ws: Path, draft: Path | None, text: str,
                      receipt_id: str) -> tuple[bool, str]:
    """Validate an absolute-usd-rebuttal `receipt:<id>` reference via the shared
    verification-receipt-check.py primitive (gate=absolute-usd). We synthesize the
    `verification-receipt: absolute-usd=<id>` marker the validator scans for and hand it
    the real draft path (for receipt/dispatch-log discovery). Returns (ok, detail).

    First consumer of the verification-receipt primitive: greens only on an independent,
    dispatch-bound, CONFIRMED receipt - a bare prose rebuttal or a hand-written receipt
    with no matching dispatch entry does NOT validate."""
    vrc = _load_module("verification-receipt-check.py", "_ausd_vrc")
    if vrc is None:
        return False, "verification-receipt-check.py unavailable"
    synth = f"{text}\n<!-- verification-receipt: {RECEIPT_GATE}={receipt_id} -->\n"
    try:
        r = vrc.check(
            str(ws),
            draft=str(draft) if draft is not None else None,
            draft_text=synth,
            gate=RECEIPT_GATE,
        )
    except Exception as exc:  # pragma: no cover - defensive
        return False, f"receipt validation error: {exc}"
    ok = str(r.get("verdict", "")).startswith("pass")
    detail = "; ".join(
        str(i.get("detail", "")) for i in r.get("items", []) if i.get("detail"))
    return ok, (detail or str(r.get("verdict", "")))


def check(ws: Path, draft: Path, severity: str, strict: bool,
          poc_dir: Path | None = None) -> dict[str, Any]:
    text = draft.read_text(encoding="utf-8", errors="replace") if draft.is_file() else ""

    rb = REBUTTAL_RE.search(text)
    if rb and rb.group(1).strip():
        reason = rb.group(1).strip()
        meta = {"schema": SCHEMA, "gate": GATE, "draft": str(draft), "strict": strict}
        receipt_strict = bool(strict) or _env_receipt_strict()
        m = RECEIPT_REF_RE.match(reason)
        receipt_id = m.group(1) if m else None
        if receipt_id:
            ok, detail = _validate_receipt(ws, draft, text, receipt_id)
            if ok:
                return {**meta, "verdict": "ok-rebuttal", "receipt_id": receipt_id,
                        "receipt_validated": True,
                        "reason": (f"absolute-usd-rebuttal backed by verification receipt "
                                   f"'{receipt_id}': {detail[:160]}")}
            verdict = "fail-rebuttal-unverified" if receipt_strict \
                else "warn-rebuttal-unverified"
            return {**meta, "verdict": verdict, "receipt_id": receipt_id,
                    "receipt_validated": False,
                    "reason": (f"absolute-usd-rebuttal references receipt '{receipt_id}' "
                               f"but it did not validate for gate={RECEIPT_GATE}"
                               + (" (advisory; set AUDITOOOR_ABSOLUTE_USD_STRICT=1 or "
                                  "AUDITOOOR_VERIFICATION_RECEIPT_STRICT=1 to enforce)"
                                  if not receipt_strict else "")
                               + f": {detail[:160]}")}
        # bare-prose rebuttal (no `receipt:<id>` reference)
        if receipt_strict:
            return {**meta, "verdict": "fail-rebuttal-unverified",
                    "receipt_validated": False,
                    "reason": ("bare-prose absolute-usd-rebuttal no longer self-clears "
                               "under strict; reference an independent-verification receipt "
                               "(`absolute-usd-rebuttal: receipt:<id> <reason>`): "
                               f"{reason[:160]}")}
        return {**meta, "verdict": "warn-rebuttal-unverified", "receipt_validated": False,
                "reason": ("absolute-usd-rebuttal accepted (advisory; NOT receipt-backed - "
                           "add `receipt:<id>` for an independent-verification receipt; set "
                           "AUDITOOOR_ABSOLUTE_USD_STRICT=1 to enforce): "
                           f"{reason[:160]}")}

    rules = _load_rules(ws)
    floor_usd, floor_source = parse_floor(rules, ws)
    sev = detect_severity(text, severity)
    fund_loss, fl_reason = is_fund_loss(text)

    trigger = {
        "tier_high_plus": sev in ("HIGH", "CRITICAL"),
        "floor_declared": floor_usd is not None,
        "fund_loss": fund_loss,
    }
    base = {
        "schema": SCHEMA, "gate": GATE, "draft": str(draft),
        "severity_detected": sev, "floor_usd": floor_usd, "floor_source": floor_source,
        "fund_loss_reason": fl_reason, "trigger": trigger, "strict": strict,
    }

    if not all(trigger.values()):
        why = []
        if not trigger["tier_high_plus"]:
            why.append(f"severity={sev} (gate fires HIGH+ only)")
        if not trigger["floor_declared"]:
            why.append("no fund-loss USD floor declared for this workspace")
        if not trigger["fund_loss"]:
            why.append("finding not classified fund-loss/value-extraction")
        return {**base, "verdict": "pass-not-applicable", "reason": "; ".join(why)}

    parts, missing, mag_flag = check_derivation(text)
    missing_artifacts = check_artifacts(text, ws)

    problems: list[str] = list(missing)
    if mag_flag:
        problems.append(f"magnitude recompute: {mag_flag}")
    if missing_artifacts:
        problems.append("cited evidence artifact(s) absent from the workspace: "
                        + ", ".join(missing_artifacts))

    incomplete = bool(problems)
    if not incomplete:
        verdict = "pass-derivation-complete"
    elif strict:
        verdict = "fail-derivation-incomplete"
    else:
        verdict = "warn-derivation-incomplete"

    return {
        **base,
        "derivation_parts": parts,
        "missing_parts": missing,
        "magnitude_flag": mag_flag,
        "missing_artifacts": missing_artifacts,
        "problems": problems,
        "verdict": verdict,
        "reason": (f"floor=${floor_usd} ({floor_source}); "
                   + ("derivation complete" if not incomplete
                      else f"{len(problems)} derivation gap(s)")),
    }


def render_stub(floor_usd: int | None = None) -> str:
    fl = f"${floor_usd}" if floor_usd else "$<floor>"
    return (
        "## Absolute USD Impact Derivation\n"
        "\n"
        "- (a) ASSET-IDENTITY: loss is denominated in <ASSET> "
        "(<file.ext:line> default reserve/denomination)\n"
        "- (b) UNIT->USD: 1 <ASSET> = <N> <base-unit>; <ASSET> ~ $<price> "
        "(<coingecko|oracle|spot> as of <date>)\n"
        "- (c) MARKET-SIZE: at a <TVL|order size|victim position> of <N> <ASSET>, the raw "
        "loss delta is <N> <base-unit>\n"
        f"- (d) ABSOLUTE $ vs FLOOR: derived loss = $<N>, which is >= / < the {fl} "
        "fund-loss floor\n"
    )


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="ABSOLUTE-USD-DERIVATION gate (Check #148)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--workspace", required=True, type=Path)
    ap.add_argument("--draft", required=True, type=Path)
    # No argparse `choices`: pre-submit passes title-case ("High"); detect_severity
    # normalizes case. Mirrors impact-characterization-completeness-check.py (#137).
    ap.add_argument("--severity", default="auto")
    ap.add_argument("--poc-dir", type=Path)
    ap.add_argument("--strict", action="store_true")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--emit-stub", action="store_true",
                    help="print a fillable ## Absolute USD Impact Derivation stub and exit")
    args = ap.parse_args(argv)

    ws = args.workspace.expanduser().resolve()

    if args.emit_stub:
        floor_usd, _ = parse_floor(_load_rules(ws), ws)
        sys.stdout.write(render_stub(floor_usd))
        return 0

    if not args.draft.is_file():
        print(f"[{GATE}] no such draft: {args.draft}")
        return 2

    env_strict = os.environ.get("AUDITOOOR_ABSOLUTE_USD_STRICT", "").strip().lower()
    strict = bool(args.strict) or env_strict in {"1", "true", "yes", "on"}

    poc = args.poc_dir.expanduser().resolve() if args.poc_dir else None
    out = check(ws, args.draft.expanduser().resolve(), args.severity, strict, poc)

    if args.json:
        print(json.dumps(out, indent=2, sort_keys=True))
    else:
        print(f"[{GATE}] {out['verdict']}: {out.get('reason','')}")
        for p in out.get("problems", []):
            print(f"  - {p}")
        if not strict and out.get("problems"):
            print("  (advisory: set AUDITOOOR_ABSOLUTE_USD_STRICT=1 to enforce)")

    return 1 if out["verdict"].startswith("fail") else 0


if __name__ == "__main__":
    raise SystemExit(main())
