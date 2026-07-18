#!/usr/bin/env python3
# <!-- r36-rebuttal: lane protocol-invariant-synth registered via dispatch report; enforcement lane owns runbook wiring -->
"""protocol-invariant-synth-violation-search.py  (PISVS)

NOVELTY-GENERATION LAYER primitive (docs/LOGIC_ARSENAL_ROADMAP.md).

WHAT MAKES THIS DIFFERENT FROM value-conservation-invariant-synth (VCIS) AND
cross-function-invariant-coverage (CFIC)
========================================================================
VCIS/CFIC take a KNOWN invariant SHAPE (solvency-floor, round-trip conservation)
and synthesise a harness / check whether a mutation-verified test exists.  Both
START from a shape the operator already named.

PISVS goes one level up: it DERIVES the workspace's OWN invariants directly from
the code + dataflow backends the pipeline already produced, and then emits, for
each derived invariant, an OBLIGATION to search for a reachable VIOLATION.  The
load-bearing property (the roadmap "novelty" bar) is:

    a surfaced violation need NOT match any known corpus attack class.

The engine reasons over an OWNED backend (value_moving_functions.json + a
source-level division/mutator scan).  It does NOT consult a corpus class list to
decide WHAT to look for; the corpus is consulted ONLY afterwards to LABEL a
derived violation as KNOWN (matches an existing class) or NOVEL (matches none),
and a NOVEL one is fed back as a proposed new corpus class - the flywheel.

DERIVED INVARIANT FORMS (all derived from code, none from a class list)
======================================================================
D1  RATIO-AUTHORITY-CONSISTENCY  (the dual-accounting form)
      A quantity computed as  N / D  (price / nav / rate / pro-rata / share).
      Invariant: every mutator of the numerator N must also be an authorised
      mutator of the denominator D (or be gated by the same authority domain).
      DERIVATION: a division site whose numerator dataflow reaches an EXTERNAL
      balance read (GetAllBalances / GetBalance / balanceOf / BankKeeper) while
      the denominator is an INTERNALLY-tracked field (only written by protocol
      mint/burn ledger writes) => the two feeders of the same conserved ratio
      live in DIVERGENT write-authority domains => the ratio is manipulable by
      whoever can move N without moving D.
      This is exactly the NUVA share-price / TotalShares dual-accounting shape
      (valuation_engine.go: tvv.Quo(vault.TotalShares.Amount) where tvv =
      BankKeeper.GetAllBalances(marker)) - and PISVS derives it WITHOUT being
      told the class.

D2  ESCROW-EQUALS-LIABILITY
      A function that both moves tokens (transfer_hit) AND writes a liability
      ledger field.  Invariant: held balance >= sum(liability fields).

D3  SUPPLY-MONOTONICITY / CONSERVATION
      A *supply* / *total* field written with BOTH increment and decrement
      forms across the mutator set.  Invariant: the field only changes through
      a matched mint/burn pair (no unpaired write).

Each derived invariant -> one obligation record with:
  - the invariant statement (human + machine),
  - a static reachability question (which mutator reaches N-without-D / an
    unpaired write),
  - an invariant-fuzz SEED (target fn set + property skeleton) for the search,
  - a corpus-match verdict (KNOWN / NOVEL) computed AFTER derivation.

OUTPUT (advisory; NEVER self-credits genuine coverage)
======================================================
<ws>/.auditooor/pisvs/
  derived_invariants.jsonl     - one derived invariant per line
  violation_obligations.jsonl  - one search obligation per derived invariant
  pisvs_manifest.json          - summary + novel-class proposals
Every obligation carries "verdict": "needs-search" until an executed PoC / fuzz
campaign confirms or refutes it.  PISVS does not decide reachability itself.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

# --------------------------------------------------------------------------
# ORCHESTRATION GAP (documented) + self-run guard.
# --------------------------------------------------------------------------
# PISVS is the step-2b-pisvs SUBSTRATE PRODUCER, but NO Makefile pipeline step
# invoked it directly: sei / obyte both had VMF present yet no
# <ws>/.auditooor/pisvs/ artifact, so the derived-invariant substrate silently
# read as empty for every downstream consumer (DIRM, the logic-obligation gate,
# the exploit-queue novelty consumer).  The only self-run was
# differential-invariant-residual-miner._ensure_pisvs_substrate, which fires
# ONLY when DIRM runs - a producer-after-consumer ordering hole.
#
# FIX: expose `ensure_pisvs(ws)` mirroring DIRM._ensure_pisvs_substrate so ANY
# entry point (orchestration, a consumer, or a bare invocation) can materialize
# the artifact when VMF is present but the pisvs artifact is absent.  The
# Makefile step-2b-pisvs target and any consumer SHOULD call this so PISVS is
# self-sufficient regardless of invocation order.
_PISVS_ARTIFACT = ("pisvs", "derived_invariants.jsonl")


def ensure_pisvs(ws: Path, autorun: bool = True,
                 out_dir: "Path | None" = None,
                 corpus: "list[dict] | None" = None) -> dict:
    """If the durable PISVS artifact is absent but VMF is present, materialize it
    by running the synthesizer directly on <ws>.  Mirrors DIRM's
    _ensure_pisvs_substrate (never raises - a failed producer still leaves the
    honest empty-substrate path).  Returns a self-run log entry."""
    ws = Path(ws)
    artifact = ws.joinpath(".auditooor", *_PISVS_ARTIFACT)
    if artifact.is_file():
        return {"ran": False, "reason": "artifact-present", "artifact": str(artifact)}
    if not autorun:
        return {"ran": False, "reason": "artifact-absent-autorun-disabled",
                "artifact": str(artifact)}
    vmf_path = ws / ".auditooor" / "value_moving_functions.json"
    if not vmf_path.is_file():
        return {"ran": False, "reason": "vmf-absent-run-make-audit-first",
                "vmf": str(vmf_path)}
    try:
        res = synthesise(ws, out_dir, corpus)
        return {"ran": True, "ok": bool(res.get("ok")),
                "artifact_present_after": artifact.is_file(),
                "derived_count": res.get("manifest", {}).get("derived_count"),
                "error": res.get("error")}
    except Exception as exc:  # noqa: BLE001 - report, never crash the caller
        return {"ran": True, "ok": False, "reason": f"{type(exc).__name__}: {exc}"}

# --------------------------------------------------------------------------
# Source signals (derivation vocabulary - describes CODE shapes, not attack
# classes).  These are structural code tokens, not a corpus class taxonomy.
# --------------------------------------------------------------------------
EXTERNAL_BALANCE_READ = re.compile(
    r"\b(GetAllBalances|GetBalance|SpendableCoins|balanceOf|BankKeeper|"
    r"\.balance\b)\s*\(", re.I)
DIV_GO = re.compile(r"(\w[\w.]*)\.Quo(?:Int|Raw|Truncate)?\(\s*([\w.]+)")
DIV_SOL = re.compile(r"([\w.]+)\s*(?:/|\.mulDiv\(|\.div\()\s*([\w.]+)")
RATIO_NAME = re.compile(r"(price|nav|rate|pro[_ ]?rata|share|exchange|index|"
                        r"tvv|value.?per|per.?share)", re.I)
INC_FORM = re.compile(r"(\+=|\.Add\(|\bmint\b|Increment|\.Plus\()", re.I)
DEC_FORM = re.compile(r"(-=|\.Sub\(|\bburn\b|Decrement|\.Minus\()", re.I)

# --------------------------------------------------------------------------
# Extra derivation vocabulary for D4-D8 (structural CODE shapes, not classes).
# --------------------------------------------------------------------------
# D4 - authority guard tokens + privileged-field write forms.
GUARD_TOKEN = re.compile(
    r"onlyOwner|onlyAdmin|onlyRole|hasRole|_checkOwner|_checkRole|onlyGovernance|"
    r"onlyGuardian|onlyManager|require\s*\(\s*msg\.sender|require\s*\(\s*_?msgSender|"
    r"isAuthorized|_authorizeUpgrade|ensureAuthorized|k\.authority|GetAuthority|"
    r"assert\s*\(\s*msg\.sender", re.I)
PRIV_WRITE = re.compile(
    r"\b(owner|admin|_owner|_admin|paused|_paused|whitelisted?|blacklisted?|"
    r"cap|maxCap|feeRate|governance|guardian|operator|treasury|minter|pauser|"
    r"authority)\b\s*(?:\[[^\]]*\])?\s*=(?!=)")
# D5 - stored ratio/price fields whose read must be preceded by an update.
RATIO_FIELD = re.compile(
    r"\b(lastPrice|price|nav|rewardPerToken|rewardIndex|cumulativeIndex|"
    r"exchangeRate|pricePerShare|indexValue|lastUpdate\w*|lastUpdated\w*)\b")
# D6 - aggregate totals vs per-account parts.
# NOTE (Sol/Rust vocabulary): Solidity/Rust ledgers name the aggregate with a
# leading underscore (`_totalSupply`) and the per-account map likewise
# (`_balances[...]`).  `\btotal` will NOT match inside `_totalSupply` (no word
# boundary between `_` and `total`), which is why D6 emitted 0 across the
# nuva-evm / obyte Solidity ledgers.  Allow an OPTIONAL leading underscore and
# anchor on a non-identifier char so both `TotalShares` (Go) and `_totalSupply`
# (Sol) are captured.  Additive only - the Go match set is unchanged.
AGG_FIELD = re.compile(r"(?<![A-Za-z0-9])(_?[Tt]otal[A-Za-z]\w*)\b")
PART_MAP = re.compile(
    r"\b(balances|balanceOf|_balances|shares|_shares|deposits|_deposits|"
    r"staked|stakes|_staked)\s*\[")
# D7 - consumed-marker / nonce uniqueness write forms.
MARKER_WRITE = re.compile(
    r"\b(used|processed|executed|consumed|claimed|seen|isUsed|filled|redeemed|"
    r"spent|nullifiers?)\b\s*\[[^\]]*\]\s*=(?!=)|"
    r"\bnonce\w*\s*(?:\[[^\]]*\])?\s*(?:\+\+|\+=)|\+\+\s*nonce\w*")
# D8 - declared min/max/cap bound names + comparison sites.
BOUND_TOKEN = re.compile(r"MAX|CAP|Cap|Max")
CMP = re.compile(r"([\w.]+)\s*(<=|<|>=|>)\s*([\w.]+)")
# Rust idiom: a bound check reads a length/size via a method call
# (`session_nonce.len() > SESSION_NONCE_LENGTH_MAX`), which the Go/Sol CMP misses
# because the `()` breaks the `[\w.]+` operand.  CMP_RUST additionally accepts a
# trailing `()` on either operand so length/size bound checks over crypto buffers
# (tofn/tofnd) are captured.  Applied ONLY to `.rs` files - Go/Sol keep CMP.
CMP_RUST = re.compile(r"([\w.]+(?:\(\))?)\s*(<=|<|>=|>)\s*([\w.]+(?:\(\))?)")

# A minimal builtin corpus for the KNOWN/NOVEL label.  Deliberately does NOT
# contain a "dual accounting" / "ratio authority" class, to demonstrate that
# PISVS surfaces the NUVA ratio candidate by DERIVATION even when no class in
# the corpus matches it (proof the engine generates rather than matches).
_BUILTIN_CORPUS = [
    {"class": "reentrancy", "keywords": ["reentr", "callback", "cei"]},
    {"class": "access-control-missing-guard", "keywords": ["onlyowner", "authz", "missing guard"]},
    {"class": "unchecked-return", "keywords": ["unchecked return", "ignored return"]},
    {"class": "integer-overflow", "keywords": ["overflow", "underflow"]},
    {"class": "rounding-direction", "keywords": ["round up", "round down", "mulDiv rounding"]},
]


def _read_vmf(ws: Path) -> dict:
    p = ws / ".auditooor" / "value_moving_functions.json"
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text())
    except Exception:
        return {}


def _iter_source(ws: Path, exts=(".go", ".sol", ".rs")):
    src = ws / "src"
    root = src if src.is_dir() else ws
    for f in root.rglob("*"):
        if f.suffix not in exts:
            continue
        parts = set(f.parts)
        if "node_modules" in parts or "_test" in f.name or f.name.endswith("_test.go"):
            continue
        if "test" in parts or "mocks" in parts:
            continue
        # skip build/artifact trees (Rust target/, vendored deps, git)
        if parts & {"target", "vendor", ".git", "dist"}:
            continue
        yield f


def _ledger_fields(vmf: dict) -> dict:
    """Map identifier-lowercased -> set of functions that write it (internal
    tracked liability/supply fields)."""
    field_writers: dict[str, set] = {}
    for fn in vmf.get("functions", []):
        for fld in fn.get("ledger_write_evidence", []) or []:
            field_writers.setdefault(fld.lower(), set()).add(
                f"{Path(fn['file']).name}:{fn['function']}")
    return field_writers


def _authz_gated(vmf: dict) -> dict:
    g = {}
    for fn in vmf.get("functions", []):
        g[f"{Path(fn['file']).name}:{fn['function']}"] = bool(fn.get("authz_write_hit"))
    return g


def _classify_corpus(statement: str, corpus: list[dict]) -> dict:
    s = statement.lower()
    for c in corpus:
        for kw in c["keywords"]:
            if kw in s:
                return {"match": "KNOWN", "class": c["class"], "keyword": kw}
    return {"match": "NOVEL", "class": None, "keyword": None}


def _balance_derived_functions(ws: Path) -> dict:
    """Return {func_name: evidence_line} for every function whose body contains an
    EXTERNAL balance read - so a numerator assigned from such a call is treated as
    balance-derived (transitive one-hop, matching real code where the TVV read and
    the division live in different functions)."""
    funcs: dict[str, str] = {}
    func_hdr = re.compile(r"func\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)\s*\(")
    for f in _iter_source(ws):
        try:
            lines = f.read_text(errors="replace").splitlines()
        except Exception:
            continue
        cur = None
        for line in lines:
            h = func_hdr.search(line)
            if h:
                cur = h.group(1)
            if cur and EXTERNAL_BALANCE_READ.search(line):
                funcs.setdefault(cur, line.strip()[:120])
    return funcs


def _func_def_line(ws: Path, file_rel: str, func_name: str) -> int | None:
    """Best-effort: line of the definition header of func_name in file_rel."""
    if not func_name:
        return None
    p = ws / file_rel
    if not p.is_file():
        p = Path(file_rel)
        if not p.is_file():
            return None
    try:
        lines = p.read_text(errors="replace").splitlines()
    except Exception:
        return None
    pats = [
        re.compile(rf"func\s+(?:\([^)]*\)\s*)?{re.escape(func_name)}\s*\("),
        re.compile(rf"\bfunction\s+{re.escape(func_name)}\b"),
        re.compile(rf"\bfn\s+{re.escape(func_name)}\b"),
    ]
    for i, line in enumerate(lines):
        for pat in pats:
            if pat.search(line):
                return i + 1
    return None


def _enclosing_func(ws: Path, file_rel: str, line: int | None) -> str | None:
    """Name of the function lexically enclosing `line` in file_rel (best-effort)."""
    if not line:
        return None
    p = ws / file_rel
    if not p.is_file():
        p = Path(file_rel)
        if not p.is_file():
            return None
    try:
        lines = p.read_text(errors="replace").splitlines()
    except Exception:
        return None
    hdr = re.compile(r"(?:func\s+(?:\([^)]*\)\s*)?|function\s+|fn\s+)([A-Za-z_]\w*)\s*\(")
    cur = None
    for i in range(min(line, len(lines))):
        h = hdr.search(lines[i])
        if h:
            cur = h.group(1)
    return cur


def _derive_ratio_invariants(ws: Path, field_writers: dict) -> list[dict]:
    """D1 - RATIO-AUTHORITY-CONSISTENCY. Derive from division sites."""
    out = []
    tracked = set(field_writers.keys())
    bal_funcs = _balance_derived_functions(ws)
    bal_func_re = re.compile(r"\b(" + "|".join(re.escape(n) for n in bal_funcs) + r")\s*\(") if bal_funcs else None
    for f in _iter_source(ws):
        try:
            lines = f.read_text(errors="replace").splitlines()
        except Exception:
            continue
        # Scan a window: numerator identifier may be assigned above the div.
        for i, line in enumerate(lines):
            for pat in (DIV_GO, DIV_SOL):
                m = pat.search(line)
                if not m:
                    continue
                num, den = m.group(1), m.group(2)
                # denominator must be an internally-tracked field
                den_key = den.split(".")[-1].lower()
                if den_key not in tracked and not RATIO_NAME.search(den):
                    # still allow well-known share-supply denominators
                    if "share" not in den.lower() and "supply" not in den.lower():
                        continue
                # the result / surrounding context must look like a ratio
                context = "\n".join(lines[max(0, i - 8):i + 2])
                if not RATIO_NAME.search(context):
                    continue
                # numerator dataflow must reach an external balance read:
                # trace the numerator identifier's most recent assignment above.
                num_base = num.split(".")[-1]
                ext_hit = None
                for j in range(i, max(0, i - 20), -1):
                    a = lines[j]
                    # allow multi-assign (Go `tvv, err := ...`): identifier then
                    # any non-'=' run up to an assignment operator.
                    if not re.search(rf"\b{re.escape(num_base)}\b[^=\n]*:?=", a):
                        continue
                    # direct: the numerator is assigned straight from a balance read
                    if EXTERNAL_BALANCE_READ.search(a):
                        ext_hit = a.strip()
                        break
                    # transitive one-hop: assigned from a function whose body reads
                    # an external balance (e.g. tvv := k.GetTVVInUnderlyingAsset(...)
                    # where GetTVV... calls BankKeeper.GetAllBalances).
                    if bal_func_re and bal_func_re.search(a):
                        callee = bal_func_re.search(a).group(1)
                        ext_hit = f"{a.strip()}  ->[{callee}]: {bal_funcs.get(callee, '')}"
                        break
                    # assignment that itself contains the ext read on the num line
                if ext_hit is None and EXTERNAL_BALANCE_READ.search(context):
                    # numerator source is an external balance read somewhere in
                    # the immediate lexical scope feeding this ratio
                    ext_hit = next((l.strip() for l in context.splitlines()
                                    if EXTERNAL_BALANCE_READ.search(l)), None)
                if ext_hit is None:
                    continue
                den_writers = sorted(field_writers.get(den_key, []))
                stmt = (f"RATIO-AUTHORITY-CONSISTENCY: the ratio {num}/{den} "
                        f"(a price/nav/share quantity) must not change unless BOTH "
                        f"its numerator and denominator move under the same write "
                        f"authority. Numerator {num} is fed by an EXTERNAL balance "
                        f"read ({ext_hit[:80]}) reachable by any account that can "
                        f"move tokens into the accounted address; denominator {den} "
                        f"is an internally-tracked field written only by "
                        f"{den_writers or 'protocol mint/burn'}. Divergent authority "
                        f"domains => the ratio is manipulable without minting shares.")
                out.append({
                    "form": "D1_RATIO_AUTHORITY_CONSISTENCY",
                    "file": str(f.relative_to(ws)) if str(f).startswith(str(ws)) else str(f),
                    "line": i + 1,
                    "numerator": num,
                    "denominator": den,
                    "numerator_external_source": ext_hit[:160],
                    "denominator_internal_writers": den_writers,
                    "statement": stmt,
                    "search_question": (
                        f"Find a reachable path that increases the numerator source "
                        f"({num}) WITHOUT a matching write to {den}. Any permissionless "
                        f"token transfer into the accounted address is the primary "
                        f"candidate."),
                    "fuzz_seed": {
                        "targets": ["<token-transfer-into-accounted-address>",
                                    *den_writers],
                        "property": f"assert(ratio({num}/{den}) changes only when {den} changes)",
                    },
                })
    return out


def _derive_escrow_liability(vmf: dict) -> list[dict]:
    out = []
    for fn in vmf.get("functions", []):
        if fn.get("transfer_hit") and (fn.get("ledger_write_evidence") or []):
            key = f"{Path(fn['file']).name}:{fn['function']}"
            out.append({
                "form": "D2_ESCROW_EQUALS_LIABILITY",
                "file": fn["file"], "line": None,
                "function": key,
                "liability_fields": fn["ledger_write_evidence"],
                "statement": (f"ESCROW-EQUALS-LIABILITY at {key}: held token balance "
                              f">= sum({fn['ledger_write_evidence']}); a token move that "
                              f"is not matched by the liability write breaks solvency."),
                "search_question": (f"Does any path let {key} write the liability field "
                                    f"without the matching token flow (or vice-versa)?"),
                "fuzz_seed": {"targets": [key],
                              "property": "assert(balance >= sum(liability_fields))"},
            })
    return out


def _derive_supply_monotonic(vmf: dict, ws: Path) -> list[dict]:
    """D3 - a *supply*/*total* field written with BOTH inc and dec forms."""
    out = []
    # collect supply-ish fields and which files touch inc/dec forms
    supply_fields = {}
    for fn in vmf.get("functions", []):
        for fld in fn.get("ledger_write_evidence", []) or []:
            if re.search(r"supply|total|shares", fld, re.I):
                supply_fields.setdefault(fld, set()).add(
                    f"{Path(fn['file']).name}:{fn['function']}")
    for fld, writers in supply_fields.items():
        inc = dec = False
        site_file = None
        site_line = None
        for f in _iter_source(ws):
            try:
                lines = f.read_text(errors="replace").splitlines()
            except Exception:
                continue
            for i, line in enumerate(lines):
                if fld in line:
                    hit_inc = bool(INC_FORM.search(line))
                    hit_dec = bool(DEC_FORM.search(line))
                    inc = inc or hit_inc
                    dec = dec or hit_dec
                    # ground the invariant to the first concrete inc/dec write site
                    if (hit_inc or hit_dec) and site_file is None:
                        site_file = (str(f.relative_to(ws))
                                     if str(f).startswith(str(ws)) else str(f))
                        site_line = i + 1
        if inc and dec and site_file is not None:
            out.append({
                "form": "D3_SUPPLY_MONOTONICITY",
                "file": site_file, "line": site_line,
                "function": _enclosing_func(ws, site_file, site_line),
                "field": fld, "writers": sorted(writers),
                "statement": (f"SUPPLY-CONSERVATION for {fld}: it is written with both "
                              f"increment and decrement forms; every change must be a "
                              f"matched mint/burn - an unpaired write breaks supply "
                              f"conservation."),
                "search_question": f"Is there a mutator of {fld} whose write is not "
                                   f"paired with a corresponding token/share move?",
                "fuzz_seed": {"targets": sorted(writers),
                              "property": f"assert(delta({fld}) matched by mint/burn)"},
            })
    return out


def _rel(f: Path, ws: Path) -> str:
    return str(f.relative_to(ws)) if str(f).startswith(str(ws)) else str(f)


def _iter_func_bodies(ws: Path):
    """Yield (file_rel, func_name, start_idx, body_lines) for each function - a
    best-effort lexical split by function headers.  body_lines runs from the
    header line up to the next header (used for guard / same-scope analysis)."""
    hdr = re.compile(r"(?:func\s+(?:\([^)]*\)\s*)?|function\s+|fn\s+)([A-Za-z_]\w*)\s*\(")
    for f in _iter_source(ws):
        try:
            lines = f.read_text(errors="replace").splitlines()
        except Exception:
            continue
        file_rel = _rel(f, ws)
        idxs = []
        for i, l in enumerate(lines):
            h = hdr.search(l)
            if h:
                idxs.append((i, h.group(1)))
        for k, (start, name) in enumerate(idxs):
            end = idxs[k + 1][0] if k + 1 < len(idxs) else len(lines)
            yield file_rel, name, start, lines[start:end]


def _derive_authority_monotonicity(ws: Path) -> list[dict]:
    """D4 - AUTHORITY-MONOTONICITY. A privileged/permissioned state field
    (owner/admin/paused/whitelist/cap/rate/...) may transition ONLY under an
    authority guard.  DERIVE the field + the set of writers; fire when the field
    is demonstrably treated as privileged (>=1 guarded writer) yet ALSO has an
    unguarded writer (excluding constructor/initialize) - the write-authority
    asymmetry a violation of which lets any caller move a permissioned field.
    DROP (trivially satisfied) when every writer is guarded."""
    out = []
    fields: dict[str, dict] = {}
    for file_rel, name, start, body in _iter_func_bodies(ws):
        guarded = bool(GUARD_TOKEN.search("\n".join(body)))
        is_init = name.lower() in ("constructor", "initialize", "init",
                                   "_initialize", "setup", "_setup")
        for j, l in enumerate(body):
            m = PRIV_WRITE.search(l)
            if not m:
                continue
            field = m.group(1).lower().lstrip("_")
            rec = fields.setdefault(field, {"guarded": [], "unguarded": []})
            entry = (file_rel, start + j + 1, name, l.strip()[:120])
            (rec["guarded"] if (guarded or is_init) else rec["unguarded"]).append(entry)
    for field, rec in fields.items():
        if not rec["guarded"] or not rec["unguarded"]:
            continue  # all-guarded (trivially satisfied) or never-guarded (not privileged)
        f_rel, line, fn, ev = rec["unguarded"][0]
        gwriters = sorted({f"{Path(g[0]).name}:{g[2]}" for g in rec["guarded"]})
        stmt = (f"AUTHORITY-MONOTONICITY for privileged field '{field}': it is written "
                f"under an authority guard in {gwriters} but ALSO written WITHOUT any "
                f"authority guard at {Path(f_rel).name}:{fn} ({ev}); a permissioned state "
                f"field must transition only through an authorised writer, so the "
                f"unguarded writer lets any caller move it.")
        out.append({
            "form": "D4_AUTHORITY_MONOTONICITY",
            "file": f_rel, "line": line, "function": fn, "field": field,
            "guarded_writers": gwriters,
            "statement": stmt,
            "search_question": (f"Find a reachable call to {Path(f_rel).name}:{fn} that "
                                f"writes '{field}' without passing an authority guard."),
            "fuzz_seed": {"targets": [f"{Path(f_rel).name}:{fn}", *gwriters],
                          "property": f"assert('{field}' changes only from an authorised caller)"},
        })
    return out


def _derive_temporal_ordering(ws: Path) -> list[dict]:
    """D5 - TEMPORAL-ORDERING (staleness). A stored value read (price/nav/reward
    index) must be preceded by its update within the same tx.  DERIVE the read +
    its updater; fire on a function that READS a stored ratio field (that has an
    updater elsewhere) WITHOUT writing it in the same body.  DROP (trivially
    satisfied) when the reading function also writes the field (fresh this tx)."""
    out = []
    writers: dict[str, list] = {}
    bodies = list(_iter_func_bodies(ws))

    def _is_write(sym: str, line: str) -> bool:
        return bool(re.search(re.escape(sym) + r"\s*(?:\[[^\]]*\])?\s*=(?!=)", line)
                    or re.search(re.escape(sym) + r"\s*\.\s*Set\w*\(", line))

    for file_rel, name, start, body in bodies:
        for j, l in enumerate(body):
            for m in RATIO_FIELD.finditer(l):
                if _is_write(m.group(1), l):
                    writers.setdefault(m.group(1).lower(), []).append(
                        (file_rel, start + j + 1, name))
    seen = set()
    for file_rel, name, start, body in bodies:
        writes_here = set()
        for l in body:
            for m in RATIO_FIELD.finditer(l):
                if _is_write(m.group(1), l):
                    writes_here.add(m.group(1).lower())
        for j, l in enumerate(body):
            for m in RATIO_FIELD.finditer(l):
                fld = m.group(1).lower()
                if fld not in writers or fld in writes_here:
                    continue  # not a stored field, or fresh in this tx (trivially satisfied)
                if _is_write(m.group(1), l):
                    continue  # this occurrence is the write, not a read
                if name in {w[2] for w in writers[fld]}:
                    continue  # the updater itself
                key = (file_rel, name, fld)
                if key in seen:
                    continue
                seen.add(key)
                upd = sorted({f"{Path(w[0]).name}:{w[2]}:{w[1]}" for w in writers[fld]})
                stmt = (f"TEMPORAL-ORDERING for stored value '{fld}': the read at "
                        f"{Path(file_rel).name}:{name} is not preceded by a same-tx update "
                        f"of '{fld}' (updater(s): {upd}); a consumer that reads a stored "
                        f"price/nav/reward without a fresh update within the block can act "
                        f"on a stale value.")
                out.append({
                    "form": "D5_TEMPORAL_ORDERING",
                    "file": file_rel, "line": start + j + 1, "function": name,
                    "field": fld, "updaters": upd,
                    "statement": stmt,
                    "search_question": (f"Is there a path where {Path(file_rel).name}:{name} "
                                        f"reads '{fld}' after a delay / without the updater "
                                        f"having run this block (stale-read)?"),
                    "fuzz_seed": {"targets": [f"{Path(file_rel).name}:{name}", *upd],
                                  "property": f"assert('{fld}' updated within same block before read)"},
                })
    return out


def _derive_sum_conservation(ws: Path) -> list[dict]:
    """D6 - SUM-CONSERVATION. A total/aggregate field equals the sum of its parts
    (sum(shares)==totalShares, sum(balances)==totalSupply, ...).  DERIVE a written
    aggregate field AND a written per-account part mapping whose roots relate; fire
    on the matched pair.  DROP (trivially satisfied) when an aggregate has no
    per-part ledger (or vice-versa) - conservation is unstatable."""
    aliases = {"balances": "supply", "balanceof": "supply", "_balances": "supply",
               "shares": "shares", "_shares": "shares", "deposits": "deposits",
               "_deposits": "deposits", "staked": "staked", "stakes": "staked",
               "_staked": "staked"}
    agg: dict[str, tuple] = {}
    part: dict[str, tuple] = {}
    wr = r"\s*(?:\[[^\]]*\])?\s*(?:=(?!=)|\+=|-=|\.Add\(|\.Sub\()"
    for file_rel, name, start, body in _iter_func_bodies(ws):
        for j, l in enumerate(body):
            am = AGG_FIELD.search(l)
            if am and re.search(re.escape(am.group(1)) + wr, l):
                # strip a leading underscore (Sol `_totalSupply`) BEFORE removing
                # the `total` prefix so the root joins the Sol/Go part-map roots.
                root = am.group(1).lower().lstrip("_").replace("total", "", 1)
                if root:
                    agg.setdefault(root, (file_rel, start + j + 1, name, am.group(1)))
            pm = PART_MAP.search(l)
            if pm and re.search(re.escape(pm.group(1)) + r"\s*\[[^\]]*\]" +
                                r"\s*(?:=(?!=)|\+=|-=|\.Add\(|\.Sub\()", l):
                root = aliases.get(pm.group(1).lower(), pm.group(1).lower())
                part.setdefault(root, (file_rel, start + j + 1, name, pm.group(1)))
    out = []
    for root, (af, aline, aname, asym) in agg.items():
        match = None
        for proot, pv in part.items():
            if root and (root == proot or root in proot or proot in root):
                match = (proot, *pv)
                break
        if not match:
            continue  # aggregate with no per-part ledger -> conservation unstatable
        proot, pf, pline, pname, psym = match
        stmt = (f"SUM-CONSERVATION: aggregate '{asym}' must equal the sum of its parts "
                f"'{psym}[...]' (updated at {Path(pf).name}:{pname}:{pline}); any writer "
                f"that changes '{asym}' without an offsetting change to the '{psym}' "
                f"mapping (or vice-versa) breaks sum(parts)==total.")
        out.append({
            "form": "D6_SUM_CONSERVATION",
            "file": af, "line": aline, "function": aname,
            "field": asym, "part_symbol": psym,
            "statement": stmt,
            "search_question": (f"Find a mutator that changes '{asym}' without a matched "
                                f"change to '{psym}[...]' (broken aggregate)."),
            "fuzz_seed": {"targets": [f"{Path(af).name}:{aname}", f"{Path(pf).name}:{pname}"],
                          "property": f"assert(sum({psym})=={asym})"},
        })
    return out


def _derive_uniqueness_nonce(ws: Path) -> list[dict]:
    """D7 - UNIQUENESS / NONCE-MONOTONIC. A consumed-marker / nonce / epoch key is
    strictly-once (no replay).  DERIVE the marker + its consume-write; fire when a
    marker mapping is written WITHOUT a same-body guard asserting it was unset
    (require(!used[x]) / a revert-if-set check).  DROP (trivially satisfied) when
    such a replay guard is present."""
    out = []
    seen = set()
    for file_rel, name, start, body in _iter_func_bodies(ws):
        body_txt = "\n".join(body)
        for j, l in enumerate(body):
            m = MARKER_WRITE.search(l)
            if not m:
                continue
            base_m = re.search(r"[A-Za-z_]\w*", m.group(0))
            if not base_m:
                continue
            base = base_m.group(0)
            is_nonce = base.lower().startswith("nonce")
            if not is_nonce:
                guarded = (re.search(r"require\s*\(\s*!\s*" + re.escape(base), body_txt)
                           or re.search(r"!\s*" + re.escape(base) + r"\s*\[", body_txt)
                           or re.search(r"require\s*\(\s*" + re.escape(base) +
                                        r"\s*\[[^\]]*\]\s*(?:==\s*(?:false|0)|,)", body_txt))
                if guarded:
                    continue  # replay-guarded -> trivially satisfied
            key = (file_rel, name, base.lower())
            if key in seen:
                continue
            seen.add(key)
            kind = "monotonic nonce" if is_nonce else "consumed marker"
            stmt = (f"UNIQUENESS/NONCE-MONOTONIC for {kind} '{base}': the consume-write at "
                    f"{Path(file_rel).name}:{name} must be strictly-once - the same key must "
                    f"never be consumed twice. "
                    + ("" if is_nonce else "No same-scope guard asserts the key was unset "
                       "before this write, so a replay of the same key is a candidate."))
            out.append({
                "form": "D7_UNIQUENESS_NONCE",
                "file": file_rel, "line": start + j + 1, "function": name,
                "field": base, "marker_kind": kind,
                "statement": stmt,
                "search_question": (f"Can {Path(file_rel).name}:{name} be re-entered with the "
                                    f"same '{base}' key (replay / double-consume)?"),
                "fuzz_seed": {"targets": [f"{Path(file_rel).name}:{name}"],
                              "property": f"assert('{base}' consumed at most once per key)"},
            })
    return out


def _derive_bound_invariant(ws: Path) -> list[dict]:
    """D8 - BOUND-INVARIANT. A value stays within a declared min/max/cap bound.
    DERIVE the field + its declared bound from a comparison site against a
    MAX/CAP-named constant (require(fee <= MAX_FEE)).  Fire on the bounded field.
    DROP (trivially satisfied) when a MAX/CAP constant is declared but never used
    in a comparison (no enforced field -> nothing to violate)."""
    out = []
    seen = set()
    for file_rel, name, start, body in _iter_func_bodies(ws):
        # Rust length/size bound checks read the operand via a method call
        # (`buf.len() > MAX`); use the parens-aware CMP for .rs so those fire.
        cmp_re = CMP_RUST if str(file_rel).endswith(".rs") else CMP
        for j, l in enumerate(body):
            for cm in cmp_re.finditer(l):
                lhs, op, rhs = cm.group(1), cm.group(2), cm.group(3)
                field = bound = None
                if BOUND_TOKEN.search(rhs) and not BOUND_TOKEN.search(lhs):
                    field, bound = lhs, rhs
                elif BOUND_TOKEN.search(lhs) and not BOUND_TOKEN.search(rhs):
                    field, bound = rhs, lhs
                if not field or not bound:
                    continue
                # allow a trailing `()` (Rust `.len()`); Go/Sol operands never
                # carry parens under CMP so this is a no-op for them.
                if field.isdigit() or not re.fullmatch(r"[\w.]+(?:\(\))?", field):
                    continue
                key = (file_rel, field.lower(), bound)
                if key in seen:
                    continue
                seen.add(key)
                stmt = (f"BOUND-INVARIANT for '{field}': it is compared against the declared "
                        f"bound '{bound}' at {Path(file_rel).name}:{name} (line {start + j + 1}); "
                        f"'{field}' must satisfy this bound across ALL of its writers - a writer "
                        f"that sets '{field}' past '{bound}' violates the declared limit.")
                out.append({
                    "form": "D8_BOUND_INVARIANT",
                    "file": file_rel, "line": start + j + 1, "function": name,
                    "field": field, "bound": bound,
                    "statement": stmt,
                    "search_question": (f"Find a writer of '{field}' that does NOT re-check "
                                        f"'{field}' against '{bound}' (out-of-bound write)."),
                    "fuzz_seed": {"targets": [f"{Path(file_rel).name}:{name}"],
                                  "property": f"assert('{field}' within '{bound}' at every writer)"},
                })
    return out


def synthesise(ws: Path, out_dir: Path | None, corpus: list[dict] | None) -> dict:
    vmf = _read_vmf(ws)
    if not vmf:
        return {"ok": False, "error": "no value_moving_functions.json - run make audit first"}
    corpus = corpus if corpus is not None else _BUILTIN_CORPUS
    field_writers = _ledger_fields(vmf)

    derived = []
    derived += _derive_ratio_invariants(ws, field_writers)
    derived += _derive_escrow_liability(vmf)
    derived += _derive_supply_monotonic(vmf, ws)
    derived += _derive_authority_monotonicity(ws)
    derived += _derive_temporal_ordering(ws)
    derived += _derive_sum_conservation(ws)
    derived += _derive_uniqueness_nonce(ws)
    derived += _derive_bound_invariant(ws)

    # ---- FAIL-LOUD blind markers ----------------------------------------
    # A source-scannable language (.go/.sol/.rs) PRESENT in the workspace but for
    # which the derivation emitted 0 rows must NOT silently read as "clean".
    # Emit a status:"blind" marker row per such language so a 0-row-for-a-present
    # -language state is explicit (degrade_reason carried).  These marker rows are
    # NOT grounded and are skipped by the obligation loop (never become searches).
    _EXT_LANG = {".go": "go", ".sol": "sol", ".rs": "rust"}
    present_langs = {_EXT_LANG[f.suffix] for f in _iter_source(ws)
                     if f.suffix in _EXT_LANG}
    _emitted_ext = {"go": "go", "sol": "sol", "rs": "rust"}
    emitted_langs = {_emitted_ext.get(str(d.get("file", "")).rsplit(".", 1)[-1])
                     for d in derived}
    emitted_langs.discard(None)
    blind_langs = sorted(present_langs - emitted_langs)
    for lang in blind_langs:
        derived.append({
            "form": "BLIND_MARKER",
            "status": "blind",
            "language": lang,
            "file": None, "line": None,
            "degrade_reason": (f"{lang} source files present in workspace but the "
                               f"PISVS derivation emitted 0 invariant rows for {lang}; "
                               f"no {lang} idiom fired - substrate is BLIND for this "
                               f"language, not confirmed-clean."),
            "statement": (f"PISVS-BLIND[{lang}]: no derived invariant cites a {lang} "
                          f"source site - fail-loud marker, not a clean signal."),
        })

    obligations = []
    novel_proposals = []
    dropped_ungrounded = []
    for d in derived:
        if d.get("form") == "BLIND_MARKER":
            continue  # fail-loud marker - never grounded into a search obligation
        label = _classify_corpus(d["statement"], corpus)
        # ---- GROUND the invariant to a real file:line + violating function ----
        # An obligation the engine cannot cite to source (no file:line) is NOT
        # groundable and MUST NOT be emitted as a NOVEL candidate (honest drop) -
        # a None-cited row cannot flow to a hunt and would be theater.
        form = d["form"]
        file_rel = d.get("file")
        line = d.get("line")
        func = None
        if form.startswith("D2"):
            # D2 carries file + "basename:fn"; resolve the definition line.
            func = str(d.get("function") or "").split(":")[-1] or None
            if line is None:
                line = _func_def_line(ws, file_rel, func)
        elif form.startswith("D1"):
            # D1 carries file + division-site line; recover the enclosing fn.
            func = _enclosing_func(ws, file_rel, line)
        elif form.startswith("D3"):
            # D3 now carries the concrete inc/dec write site file + line.
            func = d.get("function") or _enclosing_func(ws, file_rel, line)
        else:
            # D4-D8 each carry their own file + write/read-site line + function.
            func = d.get("function") or _enclosing_func(ws, file_rel, line)

        if not file_rel or not line:
            dropped_ungrounded.append(
                {"form": form, "reason": "no groundable file:line", "field": d.get("field"),
                 "function": d.get("function")})
            continue

        invariant_id = "pisvs-" + form.split("_", 1)[0].lower() + "-" + hashlib.sha1(
            f"{form}|{file_rel}|{line}|{func}|{d.get('numerator')}|"
            f"{d.get('denominator')}|{d.get('field')}".encode()).hexdigest()[:10]
        source_refs = [f"{file_rel}:{line}"]
        ext = d.get("numerator_external_source")
        if ext:
            source_refs.append(str(ext)[:160])
        for w in (d.get("denominator_internal_writers") or d.get("writers") or []):
            source_refs.append(str(w))

        ob = {
            "obligation_id": invariant_id,
            "invariant_id": invariant_id,
            "invariant_form": form,
            "invariant_text": d["statement"],
            "invariant_statement": d["statement"],  # back-compat alias
            "file": file_rel,
            "line": line,
            "function": func,
            "search_question": d.get("search_question"),
            "fuzz_seed": d.get("fuzz_seed"),
            "source_refs": source_refs,
            # Novelty label: NOVEL when it matches NO known corpus class; corpus_class
            # is null explicitly for a NOVEL row (the generated-not-matched property).
            "verdict": label["match"],
            "corpus_verdict": label["match"],
            "corpus_class": label["class"],
            "attack_class": "novel-protocol-invariant-violation",
            # resolution/search status - OPEN until a hunt or cited-disposition
            # drives it to a terminal verdict (logic-obligation-resolution-check).
            "search_status": "needs-search",
            "proof_status": "open",
            "site": {"file": file_rel, "line": line, "function": func,
                     **{k: d.get(k) for k in ("field", "numerator", "denominator")
                        if k in d}},
        }
        obligations.append(ob)
        if label["match"] == "NOVEL":
            # flywheel: feed the derived (unmatched) invariant back as a proposed
            # new corpus class.
            novel_proposals.append({
                "proposed_class": form.lower().replace("_", "-"),
                "seed_statement": d["statement"][:200],
                "provenance": "PISVS-derived-no-corpus-match",
            })

    out = out_dir or (ws / ".auditooor" / "pisvs")
    out.mkdir(parents=True, exist_ok=True)
    (out / "derived_invariants.jsonl").write_text(
        "".join(json.dumps(d) + "\n" for d in derived))
    (out / "violation_obligations.jsonl").write_text(
        "".join(json.dumps(o) + "\n" for o in obligations))
    # Also publish the obligation ledger at the workspace .auditooor root as
    # novelty_obligations.jsonl - the name the logic-obligation-resolution gate
    # and the exploit-queue novelty consumer key on (enforced, not advisory).
    aud = ws / ".auditooor"
    aud.mkdir(parents=True, exist_ok=True)
    (aud / "novelty_obligations.jsonl").write_text(
        "".join(json.dumps(o) + "\n" for o in obligations))
    real = [d for d in derived if d.get("form") != "BLIND_MARKER"]
    _ext2lang = {"go": "go", "sol": "sol", "rs": "rust"}
    by_language: dict[str, int] = {}
    for d in real:
        lang = _ext2lang.get(str(d.get("file", "")).rsplit(".", 1)[-1])
        if lang:
            by_language[lang] = by_language.get(lang, 0) + 1
    manifest = {
        "workspace": str(ws),
        "derived_count": len(real),
        "obligation_count": len(obligations),
        "by_form": {f: sum(1 for d in real if d["form"] == f)
                    for f in {d["form"] for d in real}},
        "by_language": by_language,
        # FAIL-LOUD: languages present in the ws that the derivation was BLIND for
        # (0 rows) - a non-empty list here means the substrate is incomplete for
        # those languages, NOT confirmed-clean.
        "blind_languages": blind_langs,
        "novel_count": len(novel_proposals),
        "known_count": sum(1 for o in obligations if o["corpus_verdict"] == "KNOWN"),
        "dropped_ungrounded_count": len(dropped_ungrounded),
        "dropped_ungrounded": dropped_ungrounded[:50],
        "novel_class_proposals": novel_proposals[:50],
        "note": "advisory; every obligation search_status=needs-search / proof_status=open "
                "until an executed PoC/fuzz campaign confirms or refutes. Rows lacking a "
                "groundable file:line are DROPPED (honest), never emitted None-cited. "
                "blind_languages non-empty => substrate BLIND (fail-loud), not clean. "
                "PISVS never self-credits.",
    }
    (out / "pisvs_manifest.json").write_text(json.dumps(manifest, indent=1))
    return {"ok": True, "out_dir": str(out), "manifest": manifest,
            "derived": derived, "obligations": obligations,
            "dropped_ungrounded": dropped_ungrounded}


def _main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="PISVS - derive protocol invariants "
                                             "from code and emit violation-search obligations.")
    ap.add_argument("workspace")
    ap.add_argument("--out", default=None)
    ap.add_argument("--corpus", default=None,
                    help="JSON file: [{class, keywords:[...]}] for KNOWN/NOVEL label")
    ap.add_argument("--form", default=None, help="Filter output to one form (D1/D2/D3)")
    args = ap.parse_args(argv)

    ws = Path(args.workspace)
    if not ws.is_dir():
        print(f"ERROR: workspace not found: {ws}", file=sys.stderr)
        return 1
    corpus = None
    if args.corpus:
        corpus = json.loads(Path(args.corpus).read_text())
    res = synthesise(ws, Path(args.out) if args.out else None, corpus)
    if not res["ok"]:
        print(f"ERROR: {res['error']}", file=sys.stderr)
        return 1
    m = res["manifest"]
    print(f"PISVS: {m['derived_count']} invariant(s) DERIVED FROM CODE -> {res['out_dir']}")
    print(f"  by_form={m['by_form']}  known={m['known_count']}  NOVEL={m['novel_count']}")
    flt = args.form
    for o in res["obligations"]:
        if flt and not o["invariant_form"].startswith(f"{flt}_") and not o["invariant_form"].startswith(flt):
            continue
        site = o["site"]
        loc = site.get("function") or f"{site.get('file')}:{site.get('line')}" or site.get("field")
        print(f"  [{o['corpus_verdict']:5}] {o['invariant_form']}  @ {loc}")
        if o["invariant_form"].startswith("D1"):
            print(f"          {o['invariant_statement'][:180]}")
    print("NOTE: verdict='needs-search' for all - a violation need NOT match a known "
          "corpus class (NOVEL rows are the generated-not-matched proof).")
    return 0


if __name__ == "__main__":
    sys.exit(_main())
