#!/usr/bin/env python3
"""enforcement-layer-census.py (ELC) - Enforcement-Layer Census (B3).

WHY THIS EXISTS
===============
A per-workspace hunt can be broad on some enforcement surfaces and BLIND on
others. Each hunt sidecar carries a class (bug_class / attack_class / impact
class); the census walk (hunt-coverage-gate.py) already counts those. But a
Counter over classes cannot answer "which enforcement LAYER present in the
source got ZERO hunt attention?" - the false-negative that matters.

This tool joins two planes:
  (a) PRESENT layers  - grep the in-scope source for per-layer cues (the same
      cue idea as completeness-matrix-build.py _CATEGORY_CUES; the present+
      covered adapter access-control-coverage.py is the sibling for one layer).
  (b) HUNTED layers   - count hunt sidecars mapped to each layer via a fixed
      LAYER_MAP over the sidecar class fields (bug_class / attack_class + the
      impact-class fields real sidecars carry in the fleet).

FLAG a layer that is PRESENT in source (source_hits>=MIN) AND has ZERO mapped
sidecars: a present-but-unhunted enforcement surface. Advisory-first, exit 0
without ``--strict``; strict mode requires canonical inputs and exact typed
stable-ID dispositions for every applicable gap.

Emits <ws>/.auditooor/enforcement_layer_census.json
(schema auditooor.enforcement_layer_census.v1).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path

_TOOLS = Path(__file__).resolve().parent
if str(_TOOLS) not in sys.path:
    sys.path.insert(0, str(_TOOLS))

try:
    from lib.source_extensions import is_source_file  # type: ignore
except Exception:  # pragma: no cover - degraded import
    _SRC = {".sol", ".vy", ".rs", ".go", ".ts", ".js", ".py", ".oscript",
            ".aa", ".cairo", ".move", ".circom", ".clar", ".nr", ".zok"}

    def is_source_file(path: str) -> bool:  # type: ignore
        return os.path.splitext(str(path))[1].lower() in _SRC

SCHEMA = "auditooor.enforcement_layer_census.v1"
DEFAULT_MIN = 3
DISPOSITIONS_REL = os.path.join(
    ".auditooor", "enforcement_layer_census_dispositions.jsonl")
_TERMINAL_DISPOSITIONS = frozenset({
    "covered", "covered-by-fuzz", "disposed", "killed", "not-applicable",
    "not_applicable", "oos", "out-of-scope", "refuted", "resolved",
    "ruled-out", "ruled_out", "ruled-out-source-cited",
})

# The source_mined queue exploit-queue.py:_gather_from_source_mined_queue ingests.
SOURCE_MINED_REL = os.path.join(".auditooor", "exploit_queue.source_mined.json")
SOURCE_MINED_SCHEMA = "auditooor.exploit_queue.v1"
# dedup namespace - distinct from unhunted-surface / mechanism-finding so seeds
# never collide with foreign rows and reruns are idempotent.
ELC_SEED_SOURCE = "unhunted-enforcement-layer"

# The 7 enforcement layers this census tracks.
LAYERS = ("access-control", "crypto", "serialization", "consensus",
          "upgrade", "oracle", "conservation")

# (a) PRESENT cues: layer -> combined regex over source content.
LAYER_CUES = {
    "access-control": r"onlyOwner|AccessControl|hasRole|_checkRole|MsgServer",
    "crypto": r"ecrecover|EIP712|keccak256\(abi\.encode|verify\(",
    "serialization": r"abi\.decode|borsh|serde::Deserialize",
    "consensus": r"BeginBlock|EndBlock|KVStore|cometbft",
    "upgrade": r"_authorizeUpgrade|UUPS|initializer|proxy",
    "oracle": r"latestRoundData|TWAP|getPrice",
    "conservation": r"totalAssets|totalSupply",
}
_LAYER_RE = {k: re.compile(v) for k, v in LAYER_CUES.items()}

# (b1-CREDIT) TIGHT credit cues: layer -> anchored regex used ONLY to credit a
# MIMO ``code_excerpt`` (never for present-detection, which stays loose above).
# The loose LAYER_CUES over-credit when reused for CREDIT: a bare ``proxy`` is
# pervasive in Cosmos/cometbft Go (ABCI / light-client / p2p proxy), a bare
# ``verify(`` / ``initializer`` / ``MsgServer`` / ``KVStore`` / ``cometbft``
# fire on unrelated (often NEGATIVE / OOS) hunts and falsely green a layer the
# workspace does not actually implement (measured: sei/upgrade flipped
# flagged->unflagged off 9 spurious 'proxy'/fixture creditors). Present-detection
# is intentionally BROADER than credit so an unhunted layer STAYS flagged
# (advisory over-flag is safe; a false-green is the bug we are killing).
LAYER_CREDIT_CUES = {
    "access-control": r"onlyOwner|AccessControl|hasRole|_checkRole|onlyRole|_checkOwner",
    # crypto is NOT EVM-gated: it must credit Rust/Go signature+curve crypto too
    # (e.g. monero-oxide MLSAG/bulletproof ``pub fn verify(...)``), so beyond the
    # EVM primitives we keep an ANCHORED verify-CALL form (``verify...(`` - a call
    # or def, never a bare word) plus common non-EVM curve/signature primitives.
    "crypto": (r"ecrecover\(|ECDSA\.recover|\bEIP712|keccak256\(abi\.encode|"
               r"SignatureChecker|toEthSignedMessageHash|"
               r"\bverify\w*\s*\(|batch_verify|verify_signature|verify_proof|"
               r"\bed25519|\bschnorr|ring[_ ]?signature|key_image|\.recover\(|"
               r"secp256k1|ristretto|\bScalar\b|EdwardsPoint|Signature::"),
    "serialization": r"abi\.decode\(|borsh::|BorshDeserialize|serde::Deserialize",
    "consensus": r"BeginBlock|EndBlock|BeginBlocker|EndBlocker|PreBlocker|FinalizeBlock",
    "upgrade": (r"_authorizeUpgrade|\bUUPS|ERC1967|upgradeToAndCall|"
                r"\bupgradeTo\b|proxiableUUID"),
    "oracle": r"latestRoundData|\bTWAP\b|getPrice\(|AggregatorV3|_getPrice\(",
    "conservation": r"totalAssets\b|totalSupply\b",
}
_LAYER_CREDIT_RE = {k: re.compile(v) for k, v in LAYER_CREDIT_CUES.items()}

# EVM-ONLY layers: UUPS / ERC1967 / proxy-upgrade is an EVM concept, so a
# non-.sol/.vy anchor can NEVER credit it (kills the Go ``InitializePrecompiles``
# + cometbft-proxy false-credits). Gated in BOTH MIMO arms (b1 excerpt + b2 fn).
EVM_CREDIT_LAYERS = {"upgrade"}
_EVM_EXTS = {".sol", ".vy"}

# (b) LAYER_MAP: sidecar class token -> layer. Substring match (lowercased).
# Keyed off bug_class/attack_class first; impact-class synonyms added because
# real fleet sidecars carry the class in impact_class* / impact_lens / impact.
LAYER_MAP = {
    "access-control": ["access-control", "admin-bypass", "authorization",
                       "auth-bypass", "access control", "unauthorized-access",
                       "privilege"],
    "crypto": ["signature-replay", "signature-forgery", "sig-replay",
               "crypto", "ecdsa", "malleab", "forged-signature"],
    "serialization": ["serialization", "deserialization", "malformed-input",
                      "decode-panic", "encoding"],
    "consensus": ["chain-halt", "chain-split", "consensus", "bc-consensus",
                  "liveness", "fork"],
    "upgrade": ["upgradability", "upgradeability", "upgrade", "uninitialized",
                "init-frontrun", "reinit"],
    "oracle": ["oracle-manipulation", "oracle-staleness", "oracle",
               "stale-price", "price-manipulation"],
    "conservation": ["conservation", "inflation", "unauthorized-mint",
                     "direct-loss", "loss-of-funds", "insolven", "over-credit"],
}

# Sidecar fields that may carry a class token (str or list).
_CLASS_STR_FIELDS = ("bug_class", "attack_class", "impact_class", "impact_lens",
                     "impact", "attacker_role")
_CLASS_LIST_FIELDS = ("attack_classes_to_try", "impact_class_considered",
                      "impact_classes_considered", "impact_considered")

# (b2) MIMO/haiku per-fn schema fallback: layer -> anchored function-name cue.
# The dominant hunt fleet (per-fn MIMO + batch) carries NO _CLASS_*_FIELDS token,
# so its ONLY layer signals are (i) the verbatim ``code_excerpt`` (matched by the
# TIGHT LAYER_CREDIT_CUES - b1, deliberately NARROWER than the loose present-
# detection cues) and (ii) the anchored function name from function_anchor.fn /
# unit (this map - b2). Tokens here are
# ANCHORED/whitelisted (a function whose name IS a layer operation), never a bare
# short substring: e.g. crypto is ``verifyaml|ecdsa|permit\b`` not ``sign``/
# ``recover`` (which would falsely credit assign / recoverERC20), so a layer with
# ZERO sidecars targeting a cue-bearing function still counts 0 and STAYS flagged.
LAYER_FN_CUES = {
    "access-control": (r"grantrole|revokerole|renouncerole|_checkrole|_setuprole|"
                       r"setadmin|addadmin|removeadmin|setowner|transferownership|"
                       r"acceptownership|_authorizeadmin"),
    "crypto": (r"verifyaml|verifysig|verifysignature|verifyproof|verifymerkle|"
               r"ecrecover|ecdsa|checksig|permit\b|eip712|recoversigner|"
               r"getmessagehash|hashtypeddata"),
    "serialization": (r"deserialize|unmarshal|_decode|decodemessage|frombytes|"
                      r"parsepayload"),
    "consensus": (r"beginblock|endblock|beginblocker|endblocker|preblocker|"
                  r"finalizeblock"),
    "upgrade": (r"\binitialize|reinitialize|_authorizeupgrade|upgradeto|migrateto|"
                r"_migrate|_disableinitializers"),
    "oracle": (r"latestrounddata|_getprice|getprice\b|updateprice|setprice|"
               r"consultoracle|reportprice"),
    "conservation": (r"_mint\b|_burn\b|totalsupply|totalassets|_rebase|"
                     r"settotalsupply"),
}
_LAYER_FN_RE = {k: re.compile(v) for k, v in LAYER_FN_CUES.items()}

_SKIP_DIRS = {".auditooor", ".git", "node_modules", "lib", "out",
              "artifacts", "cache", "target", "vendor", ".venv"}


def _inscope_source_files(ws: Path, *, canonical=False) -> list[Path]:
    """Resolve in-scope source files from inscope_units.jsonl (file field)."""
    inscope = ws / ".auditooor" / "inscope_units.jsonl"
    seen: set[str] = set()
    out: list[Path] = []
    if inscope.is_file():
        for line in inscope.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            f = rec.get("file") or rec.get("file_line") or ""
            f = str(f).split(":")[0].strip()
            if not f or f in seen or not is_source_file(f):
                continue
            seen.add(f)
            p = (ws / f) if not os.path.isabs(f) else Path(f)
            if p.is_file():
                out.append(p)
    if out or canonical:
        return out
    # Fallback: walk the workspace tree for source files (bounded).
    for root, dirs, names in os.walk(ws):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for n in names:
            p = Path(root) / n
            if is_source_file(str(p)):
                out.append(p)
        if len(out) > 20000:
            break
    return out


def detect_present(ws: Path, *, canonical=False) -> dict[str, int]:
    """layer -> count of in-scope source files whose content matches the cue."""
    hits = {ly: 0 for ly in LAYERS}
    for p in _inscope_source_files(ws, canonical=canonical):
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for ly, rx in _LAYER_RE.items():
            if rx.search(text):
                hits[ly] += 1
    return hits


def _sidecar_tokens(rec: dict) -> str:
    parts: list[str] = []
    for f in _CLASS_STR_FIELDS:
        v = rec.get(f)
        if isinstance(v, str):
            parts.append(v.lower())
    for f in _CLASS_LIST_FIELDS:
        v = rec.get(f)
        if isinstance(v, list):
            parts.extend(str(x).lower() for x in v)
        elif isinstance(v, str):
            parts.append(v.lower())
    return " || ".join(parts)


def _mimo_result_dict(rec: dict) -> dict:
    """Parse the ``result`` field once when it is a stringified JSON object.

    Batch MIMO sidecars (hunt__<file>__<fn>__batchN_taskM.json) wrap the whole
    per-fn verdict - including ``code_excerpt`` - inside a stringified JSON blob
    at ``result``. Per-fn MIMO sidecars keep those fields at top level (no
    wrapper). Returns the parsed dict, or {} when there is no string object."""
    res = rec.get("result")
    if isinstance(res, str) and res.lstrip().startswith("{"):
        try:
            parsed = json.loads(res)
        except (ValueError, TypeError):
            return {}
        return parsed if isinstance(parsed, dict) else {}
    return {}


def _mimo_excerpt(rec: dict) -> str:
    """Verbatim in-scope ``code_excerpt`` from a MIMO/haiku sidecar (b1 input).

    Reads the nested (stringified ``result``) excerpt first, then the top-level
    one - never the prose fields (candidate_finding / falsification_attempt),
    so a "no keccak256 issue" / "verify() is safe" mention on an unrelated fn
    can never credit a layer (R76: credit only from verbatim source)."""
    res = _mimo_result_dict(rec)
    exc = res.get("code_excerpt") if res else None
    if not (isinstance(exc, str) and exc):
        exc = rec.get("code_excerpt")
    return exc if isinstance(exc, str) else ""


def _mimo_fn_token(rec: dict) -> str:
    """Anchored function-name token from a MIMO/haiku sidecar (b2 input).

    Mirrors the canonical function-coverage / hunt-coverage readers: accept
    ``function_anchor`` as a dict {fn|function}, a JSON-serialised dict string,
    or a "File::fn[:line]" string; fall back to a "File::fn" ``unit``. The
    MIMO/haiku placeholder anchor (fn='?') carries no real location and is
    rejected so it never emits a junk credit."""
    def _from_pair_str(s: str) -> str:
        # "File::fn" or "File::fn:line" -> fn segment.
        fn = s.split("::", 1)[1].split(":", 1)[0].strip()
        return fn

    anc = rec.get("function_anchor")
    if isinstance(anc, str):
        s = anc.strip()
        if s.startswith("{"):
            try:
                anc = json.loads(s)
            except (ValueError, TypeError):
                anc = None
        elif "::" in s:
            fn = _from_pair_str(s)
            if fn and fn != "?":
                return fn.lower()
            anc = None
        else:
            anc = None
    if isinstance(anc, dict):
        fn = str(anc.get("fn") or anc.get("function") or "").strip()
        if fn and fn != "?":
            return fn.lower()
    unit = rec.get("unit")
    if isinstance(unit, str) and "::" in unit:
        fn = _from_pair_str(unit)
        if fn and fn != "?":
            return fn.lower()
    return ""


def _anchor_file(rec: dict) -> str:
    """Best-effort anchored source-file PATH from a MIMO/haiku sidecar.

    Mirrors _mimo_fn_token's schema handling but returns the FILE segment:
    function_anchor as {file}, a JSON-serialised dict string, or a
    "File::fn[:line]" pair; else the ``unit`` "File::fn". Empty when unknown."""
    anc = rec.get("function_anchor")
    if isinstance(anc, dict):
        return str(anc.get("file") or anc.get("path") or "").strip()
    if isinstance(anc, str):
        s = anc.strip()
        if s.startswith("{"):
            try:
                d = json.loads(s)
            except (ValueError, TypeError):
                d = None
            if isinstance(d, dict):
                return str(d.get("file") or d.get("path") or "").strip()
        elif "::" in s:
            return s.split("::", 1)[0].strip()
    unit = rec.get("unit")
    if isinstance(unit, str) and "::" in unit:
        return unit.split("::", 1)[0].strip()
    return ""


def _is_evm_file(path: str) -> bool:
    """True iff the anchored file is an EVM contract (.sol/.vy)."""
    return bool(path) and os.path.splitext(path)[1].lower() in _EVM_EXTS


def _inscope_identities(ws: Path):
    """(abspaths, basenames) of every in-scope file, or None if unknown.

    Read straight from inscope_units.jsonl (the authoritative CUT manifest) -
    NOT filtered by is_file so a moved-but-in-scope unit is never mislabelled
    not-in-CUT. Returns None when the manifest is absent (disables the
    not-in-CUT credit exclusion, since scope cannot be established)."""
    inscope = ws / ".auditooor" / "inscope_units.jsonl"
    if not inscope.is_file():
        return None
    absset: set[str] = set()
    baseset: set[str] = set()
    for line in inscope.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        f = rec.get("file") or rec.get("file_line") or ""
        f = str(f).split(":")[0].strip()
        if not f:
            continue
        p = Path(f) if os.path.isabs(f) else (ws / f)
        try:
            absset.add(str(p.resolve()))
        except OSError:
            absset.add(os.path.normpath(str(p)))
        baseset.add(os.path.basename(f))
    return (absset, baseset)


def _in_cut(path: str, inscope_ids) -> bool:
    """True iff the anchored file is inside the in-scope CUT.

    abspath OR basename match (basename is the format-agnostic safety net so a
    genuinely in-scope hunt is never wrongly excluded). Callers only invoke this
    when inscope_ids is not None."""
    absset, baseset = inscope_ids
    try:
        rp = str(Path(path).resolve())
    except OSError:
        rp = os.path.normpath(path)
    return rp in absset or os.path.basename(path) in baseset


# A bodyless interface / abstract declaration - a function SIGNATURE terminated
# by ``;`` with no body ``{`` anywhere in the excerpt. Such a decl carries no
# enforcement logic to hunt, so it must never credit any layer (the sei
# bodyless-interface false-creditor).
_BODYLESS_FN_RE = re.compile(r"\bfunction\b[^{};]*\([^{};]*\)[^{}]*;")


def _is_bodyless_decl(excerpt: str) -> bool:
    e = excerpt.strip()
    if not e or "{" in e:
        return False
    return bool(_BODYLESS_FN_RE.search(e))


# A hunt that CONCLUDED the target itself is a non-CUT artifact did not cover
# in-scope enforcement: exclude it from credit. Requires a NEGATIVE applicability
# verdict AND a phrase that labels the WHOLE TARGET a fixture / reference-mirror /
# vendored dep / not-in-the-CUT. Deliberately NOT bare "out of scope" or bare
# "OOS": those appear in prior-art-dedup and tangential-sub-point reasoning of
# GENUINE in-scope hunts (measured morpho FPs: "Prior OOS clauses noted but
# extension-distinct", "...core protocol invariant and OOS per SCOPE.md") and
# over-excluding them false-flags a real serialization/etc. layer. The robust
# not-in-CUT catch is the structural file-membership guard (2b) above; this prose
# arm is the narrow belt-and-suspenders for a self-labelled fixture in the CUT.
_NEG_VERDICT_RE = re.compile(
    r"^\s*(no|n/?a|none|false|negative|not[\s-]?applicable|"
    r"does[\s-]not[\s-]apply|out[\s-]of[\s-]scope)\b", re.I)
_OOS_PROSE_RE = re.compile(
    r"not[\s-]in[\s-](?:the[\s-])?cut|"
    r"reference[\s-](?:mirror|implementation)|"
    r"(?:test|vendored|external|third[\s-]?party)[\s-]?fixture|"
    r"deployed[\s-]?zip|"
    r"out[\s-]of[\s-]scope[\s-](?:contract|file|fixture|target|mock|mirror|"
    r"reference|artifact|dependency|library|module)", re.I)
_VERDICT_FIELDS = ("applies_to_target", "verdict", "disposition", "applies",
                   "conclusion")
_PROSE_FIELDS = ("candidate_finding", "falsification_attempt", "notes",
                 "dupe_check", "chain_with", "scope", "scope_note", "reason",
                 "disposition_reason")


def _verdict_negative(rec: dict) -> bool:
    res = _mimo_result_dict(rec)
    for src in (res, rec):
        if not isinstance(src, dict):
            continue
        for k in _VERDICT_FIELDS:
            v = src.get(k)
            if isinstance(v, str) and _NEG_VERDICT_RE.match(v.strip().lower()):
                return True
    return False


def _oos_declared(rec: dict) -> bool:
    res = _mimo_result_dict(rec)
    parts: list[str] = []
    for src in (res, rec):
        if not isinstance(src, dict):
            continue
        for k in _PROSE_FIELDS:
            v = src.get(k)
            if isinstance(v, str):
                parts.append(v)
    return bool(_OOS_PROSE_RE.search(" \n ".join(parts).lower()))


def _mimo_credit_excluded(rec: dict, excerpt: str, anchor: str, inscope_ids) -> bool:
    """True iff this MIMO/haiku sidecar must NOT credit ANY layer (b1 or b2).

    Three fleet-safety guards, any of which excludes the row:
      (2a) bodyless interface / abstract decl  - no enforcement body to hunt;
      (2b) not-in-CUT                          - anchored file outside the CUT;
      (2c) NEGATIVE verdict self-declaring OOS - the hunt concluded the target
           is out-of-scope, so it did not cover in-scope enforcement.
    The class-token arm is unaffected (it returns before this is reached)."""
    if excerpt and _is_bodyless_decl(excerpt):
        return True
    if inscope_ids is not None and anchor and not _in_cut(anchor, inscope_ids):
        return True
    if _verdict_negative(rec) and _oos_declared(rec):
        return True
    return False


def _credit_layers(rec: dict, counts: dict[str, int], inscope_ids=None) -> None:
    """Increment counts[layer] for every layer this sidecar hunted.

    Precedence (dedup superset - a sidecar credits via exactly ONE arm):
      (a) CLASS token   - the existing LAYER_MAP path, unchanged. The 90/1260
          real-token nuva sidecars count EXACTLY as before.
      (b1) MIMO excerpt - when no class token, credit layer L iff the TIGHT
          LAYER_CREDIT_CUES regex (anchored primitives, NOT the loose present-
          detection cues) matches the verbatim ``code_excerpt``.
      (b2) MIMO fn name - credit any layer b1 did NOT already credit for this
          row (COMPLEMENTARY, not mutually-exclusive: a fn that is an
          ``initialize`` (upgrade, b2) whose body also carries ``onlyOwner``
          (access-control, b1) must credit BOTH; only same-layer double-count is
          suppressed) iff the anchored function name matches LAYER_FN_CUES.
    Both MIMO arms are gated by three over-credit guards (bodyless-decl /
    not-in-CUT / NEGATIVE-OOS via _mimo_credit_excluded) and EVM-only layers
    additionally require a .sol/.vy anchor. A genuinely-unhunted layer still
    counts 0 and STAYS flagged (advisory over-flag is safe; false-green is not)."""
    tok = _sidecar_tokens(rec)
    if tok:
        for ly, keys in LAYER_MAP.items():
            if any(k in tok for k in keys):
                counts[ly] += 1
        return
    # (b1) verbatim code_excerpt matched by the TIGHT credit cues.
    excerpt = _mimo_excerpt(rec)
    anchor = _anchor_file(rec)
    if _mimo_credit_excluded(rec, excerpt, anchor, inscope_ids):
        return
    credited_layers: set[str] = set()
    if excerpt:
        for ly, rx in _LAYER_CREDIT_RE.items():
            if ly in EVM_CREDIT_LAYERS and not _is_evm_file(anchor):
                continue
            if rx.search(excerpt):
                counts[ly] += 1
                credited_layers.add(ly)
    # (b2) anchored function name - credit the layers b1 did not already credit.
    fn = _mimo_fn_token(rec)
    if fn:
        for ly, rx in _LAYER_FN_RE.items():
            if ly in credited_layers:
                continue
            if ly in EVM_CREDIT_LAYERS and not _is_evm_file(anchor):
                continue
            if rx.search(fn):
                counts[ly] += 1


def count_sidecars(ws: Path, *, canonical=False) -> dict[str, int]:
    """layer -> count of hunt sidecars whose class/excerpt/anchor maps to it."""
    counts = {ly: 0 for ly in LAYERS}
    inscope_ids = _inscope_identities(ws)
    dirs = (ws / ".auditooor" / "hunt_findings_sidecars",) if canonical else (
        ws / ".auditooor" / "hunt_findings_sidecars",
        ws / "hunt_findings_sidecars",
    )
    for d in dirs:
        if not d.is_dir():
            continue
        for path in sorted(d.glob("*.json")):
            try:
                rec = json.loads(path.read_text(encoding="utf-8", errors="replace"))
            except (OSError, ValueError):
                continue
            if not isinstance(rec, dict):
                continue
            _credit_layers(rec, counts, inscope_ids)
    return counts


def layer_stable_id(ws: Path, layer: str) -> str:
    """Return the deterministic identity of one workspace/layer gap."""
    raw = f"{ws.name}|{layer}"
    return "ELC-" + layer + "-" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def load_typed_dispositions(ws: Path):
    """Return ``(valid_ids, invalid_rows)`` for exact strict closure rows."""
    path = ws / DISPOSITIONS_REL
    if not path.is_file():
        return {}, []
    valid = {}
    invalid = []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        return {}, [{"line": 0, "reason": f"read-error:{exc}"}]
    for line_no, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            invalid.append({"line": line_no, "reason": "invalid-json"})
            continue
        if not isinstance(row, dict):
            invalid.append({"line": line_no, "reason": "row-not-object"})
            continue
        ids = [row.get(k) for k in ("stable_id", "gap_id", "id")
               if isinstance(row.get(k), str) and row.get(k).strip()]
        dtype = row.get("disposition")
        if row.get("disposition_type") is not None:
            if dtype is not None and str(dtype).strip().lower() != str(
                    row.get("disposition_type")).strip().lower():
                invalid.append({"line": line_no, "reason": "conflicting-disposition-type"})
                continue
            dtype = row.get("disposition_type")
        if len(ids) != 1 or str(dtype or "").strip().lower() not in _TERMINAL_DISPOSITIONS:
            invalid.append({"line": line_no, "reason": "missing-exact-id-or-terminal-type"})
            continue
        valid[ids[0].strip()] = str(dtype).strip().lower()
    return valid, invalid


def strict_prerequisites(ws: Path):
    """Validate the canonical source and sidecar inputs used by strict ELC."""
    blockers = []
    inscope = ws / ".auditooor" / "inscope_units.jsonl"
    if not inscope.is_file():
        blockers.append("missing-inscope-inventory")
    else:
        rows = []
        for line_no, line in enumerate(
                inscope.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except (json.JSONDecodeError, ValueError):
                blockers.append(f"malformed-inscope-row:{line_no}")
                continue
            if not isinstance(row, dict) or not str(
                    row.get("file") or row.get("file_line") or "").strip():
                blockers.append(f"malformed-inscope-row:{line_no}")
                continue
            rows.append(row)
        if not rows:
            blockers.append("empty-inscope-inventory")
        for row in rows:
            raw = str(row.get("file") or row.get("file_line") or "").split(":")[0].strip()
            path = Path(raw) if os.path.isabs(raw) else ws / raw
            if not is_source_file(raw):
                blockers.append(f"non-source-inscope-unit:{raw}")
            elif not path.is_file():
                blockers.append(f"missing-inscope-source:{raw}")
    sidecars = ws / ".auditooor" / "hunt_findings_sidecars"
    if not sidecars.is_dir():
        blockers.append("missing-canonical-hunt-sidecar-directory")
    else:
        for path in sorted(sidecars.glob("*.json")):
            try:
                row = json.loads(path.read_text(encoding="utf-8", errors="replace"))
            except (OSError, json.JSONDecodeError, ValueError):
                blockers.append(f"malformed-hunt-sidecar:{path.name}")
                continue
            if not isinstance(row, dict):
                blockers.append(f"malformed-hunt-sidecar:{path.name}")
    return sorted(set(blockers))


def build_census(ws: Path, min_hits: int = DEFAULT_MIN, *, strict=False,
                 dispositions=None) -> dict:
    present = detect_present(ws, canonical=strict)
    sidecar = count_sidecars(ws, canonical=strict)
    layers = {}
    flagged: list[str] = []
    dispositioned: list[str] = []
    unresolved: list[dict] = []
    valid_dispositions = dispositions or {}
    for ly in LAYERS:
        sh = present[ly]
        sc = sidecar[ly]
        is_present = sh > 0
        flag = is_present and sh >= min_hits and sc == 0
        layers[ly] = {
            "present": is_present,
            "source_hits": sh,
            "sidecar_count": sc,
            "flagged": flag,
            "stable_id": layer_stable_id(ws, ly),
            "gap_id": layer_stable_id(ws, ly),
        }
        if flag:
            flagged.append(ly)
            stable_id = layer_stable_id(ws, ly)
            if strict and stable_id in valid_dispositions:
                dispositioned.append(stable_id)
            else:
                unresolved.append({"stable_id": stable_id, "layer": ly})
    prereq_blockers = strict_prerequisites(ws) if strict else []
    strict_ok = bool(strict and not prereq_blockers and not unresolved)
    return {
        "schema": SCHEMA,
        "workspace": str(ws),
        "min_source_hits": min_hits,
        "layers": layers,
        "flagged_layers": flagged,
        "unresolved_gaps": unresolved,
        "dispositioned_gaps": dispositioned,
        "prerequisite_blockers": prereq_blockers,
        "strict_blockers": list(prereq_blockers) + (
            ["unresolved-applicable-census-gaps"] if unresolved else []),
        "strict": bool(strict),
        "strict_ok": strict_ok if strict else True,
        "mode": "canonical-strict" if strict else "legacy-advisory",
        "status": ("strict-pass" if strict_ok else "strict-fail") if strict
                  else "advisory",
        "advisory": not strict,
    }


def build_layer_seed(ws_name: str, layer: str, source_hits: int) -> dict:
    """One auditooor.exploit_queue.v1 seed row for a FLAGGED enforcement layer.

    Claim-free go-look target: it asserts only that the layer is PRESENT in
    source yet has ZERO hunt sidecars. No severity, no attack narrative. The
    lead_id is deterministic over (ws, layer) so reruns dedup idempotently.
    source_refs is EMPTY (no phantom file:line -> never R76-quarantined)."""
    ident = ws_name + "|" + layer
    ident_hash = hashlib.sha256(ident.encode("utf-8", errors="replace")).hexdigest()[:12]
    note = ("layer present (%d source hits) with 0 hunt sidecars - hunt this layer"
            % source_hits)
    return {
        "lead_id": "F-ENFLAYER-" + layer + "-" + ident_hash,
        "title": "unhunted enforcement layer: " + layer,
        "kind": ELC_SEED_SOURCE,
        "target": layer,
        "note": note,
        "unit_id": "enforcement-layer::" + layer,
        "proof_status": "open",
        "quality_gate_status": "open",
        "attack_class": ELC_SEED_SOURCE,
        "learning_route": "mine-source",
        "source": ELC_SEED_SOURCE,
        "source_refs": [],
        "blockers": [],
    }


def seed_flagged_layers(ws: Path, census: dict) -> int:
    """Append one seed per FLAGGED layer into exploit_queue.source_mined.json.

    ADDITIVE + idempotent: existing rows are preserved; a seed already present
    (same lead_id) is skipped. Non-vacuous: 0 flagged layers -> 0 rows appended
    (and no file is created). Returns the number of rows newly appended."""
    flagged = census.get("flagged_layers") or []
    if not flagged:
        return 0
    layers = census.get("layers") or {}
    seeds = [build_layer_seed(ws.name, ly, int((layers.get(ly) or {}).get("source_hits", 0)))
             for ly in flagged]

    path = ws / SOURCE_MINED_REL
    payload: dict = {}
    if path.is_file():
        try:
            loaded = json.loads(path.read_text(encoding="utf-8", errors="replace"))
            if isinstance(loaded, dict):
                payload = loaded
        except (OSError, ValueError):
            payload = {}
    payload.setdefault("schema", SOURCE_MINED_SCHEMA)
    payload.setdefault("workspace", str(ws))
    queue = payload.get("queue")
    if not isinstance(queue, list):
        queue = []
        payload["queue"] = queue

    existing_ids = {r.get("lead_id") for r in queue if isinstance(r, dict)}
    added = 0
    for row in seeds:
        if row["lead_id"] in existing_ids:
            continue
        queue.append(row)
        existing_ids.add(row["lead_id"])
        added += 1
    if added == 0:
        return 0

    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    except OSError:
        return 0
    return added


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Enforcement-layer census.")
    ap.add_argument("--workspace", required=True)
    ap.add_argument("--min", type=int, default=DEFAULT_MIN,
                    help="min source_hits for a layer to be flag-eligible")
    ap.add_argument("--json", action="store_true", help="print census JSON")
    ap.add_argument("--strict", action="store_true",
                    help="canonical fail-closed mode")
    args = ap.parse_args(argv)

    ws = Path(args.workspace).resolve()
    dispositions, invalid_dispositions = load_typed_dispositions(ws)
    census = build_census(ws, args.min, strict=args.strict,
                          dispositions=dispositions)
    if args.strict and invalid_dispositions:
        census["invalid_dispositions"] = invalid_dispositions
        census["strict_blockers"].append("invalid-disposition-rows")
        census["strict_ok"] = False
        census["status"] = "strict-fail"
    elif not args.strict:
        census["invalid_dispositions"] = []

    out = ws / ".auditooor" / "enforcement_layer_census.json"
    try:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(census, indent=2), encoding="utf-8")
    except OSError:
        pass

    # Compound the census into the hunt: seed one go-look row per FLAGGED layer
    # into the source_mined queue exploit-queue.py ingests. Additive, idempotent.
    seed_census = census
    if args.strict:
        # Strict mode does not re-seed a row already closed by an exact typed
        # disposition.  The raw ``flagged_layers`` field remains available for
        # compatibility and auditability.
        seed_census = dict(census)
        seed_census["flagged_layers"] = [
            row["layer"] for row in census.get("unresolved_gaps", [])]
    seeded = seed_flagged_layers(ws, seed_census)

    if args.json:
        print(json.dumps(census, indent=2))
    else:
        fl = census["flagged_layers"]
        prefix = "[ok]" if not args.strict or census.get("strict_ok") else "[fail]"
        print(f"{prefix} [ELC] {ws.name}: status={census['status']} "
              f"flagged={fl or 'none'} seeded={seeded}")
        for ly in LAYERS:
            d = census["layers"][ly]
            print(f"  {ly:16s} present={int(d['present'])} "
                  f"src={d['source_hits']:5d} sidecars={d['sidecar_count']:5d} "
                  f"flagged={int(d['flagged'])}")
        if args.strict and census.get("strict_blockers"):
            print("  strict blockers: " + "; ".join(census["strict_blockers"]))
    return 0 if not args.strict or census.get("strict_ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
