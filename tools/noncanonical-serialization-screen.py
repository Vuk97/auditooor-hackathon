#!/usr/bin/env python3
"""noncanonical-serialization-screen.py - GEN-EL3, the NON-CANONICAL
SERIALIZATION ACCEPTANCE screen (enforcement-layer = serialization).
Go-primary (Cosmos proto/amino/json), Rust (borsh/serde) + Solidity (abi.decode)
secondary.

GENERAL LOGIC (impact-agnostic, NORTH-STAR trust-boundary class, never a bug
SHAPE). When a decoded value flows into a CANONICALITY-SENSITIVE sink - a hash,
a map-key insert, a dedup-set insert, a byte-identity equality, a merkle leaf, a
replay-nonce - two DIFFERENT non-canonical encodings of the SAME logical value
must not produce two DIFFERENT keys. The safe forms:

  (a) the decoder REJECTS non-canonical bytes: a canonical-form / re-encode-and-
      compare check (`proto.Marshal(&x)` re-serialized and `bytes.Equal`d against
      the raw input), OR
  (b) the downstream keys on the DECODED LOGICAL VALUE - the struct fields, or a
      re-serialized-canonical form - NOT the raw input bytes.

The bug class: a decode is followed by a canonicality-sensitive sink keyed on the
RAW input bytes with NO canonical check. Two byte-distinct encodings of one
logical value (proto unknown-field padding, non-minimal varints, map/field
reordering, amino/json whitespace, borsh trailing bytes) then produce two
distinct hashes / map keys / dedup entries - replay, double-spend, dedup bypass,
merkle-inclusion divergence.

Concretely (Go, hand-written CALLERS of the excluded proto codegen):
  proto.Unmarshal(raw, &x) / amino.Unmarshal(bz, &x) / json.Unmarshal(raw, &x)
  THEN
  sha256(raw) / crypto.Sha256(bz) as a store key, m[string(raw)] map insert,
  seen[string(bz)] dedup, bytes.Equal(raw, other) identity - instead of keying
  on x's fields or a re-Marshal(&x). Rust: try_from_slice(&raw) / from_slice
  then raw hashed / HashSet<Vec<u8>> insert of raw. Solidity (narrow):
  abi.decode(data,...) then keccak256(data) as a dedup key.

FIRE when a decode is followed by a canonicality-sensitive sink keyed on the raw
bytes AND no re-encode/canonical check exists in the function (biased to silence:
any re-Marshal of the decoded value suppresses).

DEDUP / distinctness (per dispatch):
  * E1-consensus-decode-differential checks round-trip re-encode EQUALITY as a
    differential oracle (a decode/encode fuzz differential) - a different lens.
    GEN-EL3 is a STATIC decode->sink-keyed-on-raw JOIN, and in fact a present
    re-encode-compare is exactly what GEN-EL3 treats as the safe form (a) and
    stays SILENT on.
  * A4-namespace-uniqueness (domain-disjointness-assumption-screen / namespace
    arm) checks an APP-LEVEL uniqueness FLAG, not encoding-canonicalization.
  * tools/total-order-comparator-screen.py checks ORDERING/comparator totality,
    not encoding canonicalization - no keyed-on-raw notion.
  * tools/deserialize-precap-amplification-screen.py (E7) checks decode ->
    amplified pre-cap ALLOCATION (a resource-DoS axis), never the identity/key
    canonicalization of the decoded bytes.
  GEN-EL3 is the decode -> canonicality-sensitive-sink-keyed-on-RAW-bytes JOIN;
  if a site reduces to one of the above, it is dropped as overlap.

ADVISORY-FIRST: every row carries verdict='needs-fuzz', advisory=True,
auto_credit=False, and the tool exits 0 by default. The opt-in env
AUDITOOOR_NONCANONICAL_SERIALIZATION_STRICT (or --strict) raises the exit code
when a fired row exists.

Excludes machine-generated (.pb.go/.pulsar.go + "DO NOT EDIT" - so we detect the
hand-written CALLER of proto.Unmarshal, never the codegen), test, sim and
vendored code via the shared exclusion libs. Silent on other trees.

Usage:
  --workspace <ws>   scan <ws>/src (or <ws>) -> .auditooor/
                     noncanonical_serialization_hypotheses.jsonl + summary
  --source <dir>     scan an arbitrary dir, print rows as JSON (NO sidecar)
  --file <f>         scan a single .go/.rs/.sol file, print rows as JSON
  --check            re-read the emitted sidecar, print cert verdict (advisory)
  --strict           (or env) elevate exit code when a fired row exists
  --json             machine summary to stdout
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import sys
from pathlib import Path

HYP_SCHEMA = "auditooor.noncanonical_serialization_hypotheses.v1"
_SIDE_NAME = "noncanonical_serialization_hypotheses.jsonl"
_STRICT_ENV = "AUDITOOOR_NONCANONICAL_SERIALIZATION_STRICT"
_CAPABILITY = "GEN_EL3"

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


def _load_codegen_sentinel():
    """Reuse declared-control-mutator-completeness-screen.py::_is_generated_source
    (the .go/.sol/.rs codegen sentinel) rather than re-inline the DO-NOT-EDIT
    logic - proto codegen (.pb.go/.pulsar.go) is skipped, so we screen the
    hand-written CALLER of proto.Unmarshal."""
    tool = TOOLS_DIR / "declared-control-mutator-completeness-screen.py"
    try:
        spec = importlib.util.spec_from_file_location("_dc_screen_ncs", tool)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)  # type: ignore
        return mod._is_generated_source
    except Exception:  # pragma: no cover
        _SUF = (".pb.go", ".pulsar.go", ".pb.gw.go", "_gen.go", ".gen.go",
                "_generated.go")
        _SENT = re.compile(r"Code generated .{0,80}?DO NOT EDIT", re.I)

        def _fallback(path: Path) -> bool:
            if path.name.lower().endswith(_SUF):
                return True
            try:
                return bool(_SENT.search(
                    path.read_text(encoding="utf-8", errors="replace")[:4096]))
            except OSError:
                return False
        return _fallback


_is_generated_source = _load_codegen_sentinel()

_SKIP_DIRS = {"target", ".git", "node_modules", "vendor", "_archive", "out",
              "cache", "lib", "__pycache__", "dist", "build", ".auditooor",
              "benches", "benchmarks", "script", "scripts", "deployments",
              "prior_audits", "reference", "certora", "simulation", "simapp",
              "node", "testdata"}
_TEST_HINT = re.compile(
    r"(^|/)(tests?|testutil|testonly|testhelper|test_fixtures|mock|mocks|"
    r"benches|benchmarks?|examples|fixtures|simulation|simapp|testdata)(/|$)")


# ============================================================================
# comment/string masking + function extraction (Go + Rust + Solidity)
# (shape-shared with traversal-terminal-canonicalization-screen.py)
# ============================================================================
def _mask_comments(text: str) -> str:
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
            out.append(" ")
            if c == "\\":
                out.append(" ")
                i += 2
                continue
            if c == quote:
                in_str = False
            i += 1
        elif c in ('"', "'", "`"):
            in_str = True
            quote = c
            out.append(" ")
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


_FN_DECL_RE = re.compile(
    r"^\s*(?:"
    r"function\s+([A-Za-z_]\w*)"                       # Solidity function foo
    r"|(constructor)\b"                                # Solidity constructor
    r"|func\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)"         # Go func (recv) Foo
    r"|(?:pub\s+)?(?:async\s+)?(?:unsafe\s+)?fn\s+([A-Za-z_]\w*)"  # Rust fn foo
    r")")


def _fn_name(m):
    return m.group(1) or m.group(2) or m.group(3) or m.group(4)


def _functions(lines):
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
        sig_parts = []
        j = i
        seen_brace = False
        while j < n:
            line = lines[j]
            if not seen_brace:
                sig_parts.append(line)
                if "{" in line:
                    seen_brace = True
            depth += line.count("{") - line.count("}")
            body.append((j, line))
            if "{" in line:
                started = True
            if started and depth <= 0:
                break
            j += 1
        yield name, i, "\n".join(sig_parts), body
        i = max(j, i + 1)


def _body_after_sig(body_lines) -> str:
    joined = "\n".join(l for _i, l in body_lines)
    brace = joined.find("{")
    return joined[brace + 1:] if brace >= 0 else joined


def _line_of_offset(text: str, off: int) -> int:
    return text.count("\n", 0, off) + 1


def _stable_id(rel, fn, sink, var, line):
    h = hashlib.sha1()
    h.update(f"{rel}|{fn}|{sink}|{var}|{line}".encode())
    return h.hexdigest()[:16]


def _excerpt(text: str, off: int) -> str:
    ls = text.rfind("\n", 0, off) + 1
    le = text.find("\n", off)
    if le == -1:
        le = len(text)
    return text[ls:le].strip()[:180]


# ============================================================================
# decode-call extraction (raw-bytes -> decoded-struct), per language
# ============================================================================
# Go: <pkg-or-recv>.Unmarshal[Binary|JSON](raw, &x) - proto/amino/cdc/codec/json.
_DECODE_GO = re.compile(
    r"\b([A-Za-z_]\w*)\.Unmarshal(?:Binary|JSON)?\s*\(\s*"
    r"([A-Za-z_]\w*)\s*,\s*&?\s*([A-Za-z_][\w.]*)")
# Rust: let x = T::try_from_slice(&raw) / from_slice(&raw) / deserialize(&raw)
_DECODE_RS = re.compile(
    r"\blet\s+(?:mut\s+)?([A-Za-z_]\w*)\s*=\s*[^;=]*?"
    r"(?:try_from_slice|from_slice|deserialize|try_from_bytes)\s*\(\s*&?\s*"
    r"([A-Za-z_]\w*)")
# Solidity: abi.decode(data, (...))  -> raw = the calldata/bytes slice
_DECODE_SOL = re.compile(r"\babi\.decode\s*\(\s*([A-Za-z_]\w*)")


def _extract_decodes(body: str, lang: str):
    """Return (list of (raw, decoded, off, call), raw_var_set, decoded_var_set)."""
    decodes = []
    if lang == "go":
        for m in _DECODE_GO.finditer(body):
            pkg, raw, dec = m.group(1), m.group(2), m.group(3)
            decodes.append((raw, dec.split(".")[0], m.start(),
                            f"{pkg}.Unmarshal"))
    elif lang == "rust":
        for m in _DECODE_RS.finditer(body):
            dec, raw = m.group(1), m.group(2)
            decodes.append((raw, dec, m.start(), "try_from_slice/deserialize"))
    elif lang == "solidity":
        for m in _DECODE_SOL.finditer(body):
            decodes.append((m.group(1), None, m.start(), "abi.decode"))
    raw_vars = {d[0] for d in decodes if d[0]}
    decoded_vars = {d[1] for d in decodes if d[1]}
    return decodes, raw_vars, decoded_vars


# ============================================================================
# canonical-check suppressor (the safe form (a): a re-encode of the decoded
# value present in the function => bias to SILENCE)
# ============================================================================
_REENCODE_GO = re.compile(
    r"\b(?:[A-Za-z_]\w*\.)?Marshal(?:Binary|JSON)?\s*\(\s*&?\s*([A-Za-z_][\w.]*)")
_REENCODE_SOL = re.compile(r"\babi\.encode(?:Packed)?\s*\(")


def _rs_reencodes_decoded(body: str, decoded_vars) -> bool:
    """A canonical re-encode of the DECODED value: `<dec>.try_to_vec()` /
    `<dec>.serialize(..)` / `to_vec(&<dec>)` / `serialize(&<dec>)`. A bare
    `raw.to_vec()` (a copy of the raw input) is NOT a canonicalization."""
    for dv in decoded_vars:
        if re.search(
            rf"\b{re.escape(dv)}\s*\.\s*(?:try_to_vec|to_vec|serialize|to_bytes)"
            rf"\s*\(", body):
            return True
        if re.search(
            rf"\b(?:try_to_vec|to_vec|serialize|to_bytes|to_writer)\s*\(\s*&?\s*"
            rf"{re.escape(dv)}\b", body):
            return True
    return False


def _has_canonical_check(body: str, decoded_vars, lang: str) -> bool:
    if lang == "go":
        for m in _REENCODE_GO.finditer(body):
            base = m.group(1).split(".")[0]
            if base in decoded_vars:
                return True
        return False
    if lang == "rust":
        return _rs_reencodes_decoded(body, decoded_vars)
    if lang == "solidity":
        return bool(_REENCODE_SOL.search(body))
    return False


# ============================================================================
# canonicality-sensitive sinks keyed on a RAW-bytes variable
# ============================================================================
# hash: crypto hashers over a var (sha256 / sha3 / keccak / blake2 / tmhash /
# Sum256). Anchored to a store/key context to avoid logging-hash spray.
_HASH_RE = re.compile(
    r"\b(?:sha256|Sha256|sha3|Sha3|Sum256|Keccak256|keccak256|"
    r"blake2b?|Blake2b?|tmhash|Hash256|hasher\.write|hasher\.update)\s*"
    r"(?:\.\w+\s*)?\(\s*(?:\[\]byte\s*\(\s*)?&?\s*([A-Za-z_]\w*)")
# map-index / dedup-set: m[string(raw)] , m[raw] , seen[raw]
_MAPKEY_RE = re.compile(
    r"\b([A-Za-z_]\w*)\s*\[\s*(?:string\s*\(\s*)?&?\s*([A-Za-z_]\w*)\s*\)?\s*\]")
# byte-identity equality: bytes.Equal(raw, x) / x.Equal(raw)
_EQ_RE = re.compile(
    r"\bbytes\.Equal\s*\(\s*([A-Za-z_]\w*)\s*,\s*([A-Za-z_]\w*)")
# rust HashSet/BTreeSet insert of a raw var
_RS_SET_RE = re.compile(
    r"\b([A-Za-z_]\w*)\.(?:insert|contains|contains_key)\s*\(\s*&?\s*"
    r"([A-Za-z_]\w*)")

# a store / identity context that anchors the hash arm (else logging-hash spray)
_STORE_CTX = re.compile(
    r"(?i)\b(store|set\s*\(|\.set\b|commit|key\b|keys?\b|root|leaf|nonce|"
    r"dedup|seen|exists?|register|cache|index|id\b|ledger|state)\b")
# nouns that specialise a sink category
_DEDUP_NOUN = re.compile(r"(?i)seen|dedup|dup|processed|known|used|exist|unique")
_NONCE_NOUN = re.compile(r"(?i)nonce|replay|antireplay|anti_replay")
_MERKLE_NOUN = re.compile(r"(?i)merkle|leaf|smt|iavl|proof|tree")


def _near(body: str, off: int, rx, radius: int = 90) -> bool:
    return bool(rx.search(body[max(0, off - radius):off + radius]))


def _classify_hash(body: str, off: int) -> str:
    if _near(body, off, _NONCE_NOUN):
        return "replay-nonce"
    if _near(body, off, _MERKLE_NOUN):
        return "merkle-leaf"
    return "hash"


def _classify_map(mapvar: str) -> str:
    if _NONCE_NOUN.search(mapvar):
        return "replay-nonce"
    if _DEDUP_NOUN.search(mapvar):
        return "dedup"
    return "mapkey"


# ============================================================================
# core per-function scan
# ============================================================================
def _scan_fn(rel, name, decl_idx, body, lang, rows):
    decodes, raw_vars, decoded_vars = _extract_decodes(body, lang)
    if not raw_vars:
        return
    if _has_canonical_check(body, decoded_vars, lang):
        return  # safe form (a): decoder re-encode/canonical check present
    first_decode = min(d[2] for d in decodes)
    call = decodes[0][3]
    store_ctx = bool(_STORE_CTX.search(body))
    seen_keys = set()

    def _add(off, var, sink):
        line = _line_of_offset(body, off) + decl_idx
        key = (var, sink)
        if key in seen_keys:
            return
        seen_keys.add(key)
        rows.append(_mk_row(rel, name, line, lang, call, sink, var,
                            _excerpt(body, off)))

    # --- hash sink (anchored to a store/identity context) --------------------
    if store_ctx:
        for m in _HASH_RE.finditer(body):
            var = m.group(1)
            if var not in raw_vars or m.start() < first_decode:
                continue
            _add(m.start(), var, _classify_hash(body, m.start()))

    # --- map-key / dedup-set index sink --------------------------------------
    for m in _MAPKEY_RE.finditer(body):
        mapvar, keyvar = m.group(1), m.group(2)
        if keyvar not in raw_vars or m.start() < first_decode:
            continue
        _add(m.start(), keyvar, _classify_map(mapvar))

    # --- byte-identity equality sink -----------------------------------------
    for m in _EQ_RE.finditer(body):
        a, b = m.group(1), m.group(2)
        var = a if a in raw_vars else (b if b in raw_vars else None)
        if not var or m.start() < first_decode:
            continue
        _add(m.start(), var, "equality")

    # --- rust HashSet/BTreeSet insert of raw bytes ---------------------------
    if lang == "rust":
        for m in _RS_SET_RE.finditer(body):
            setvar, var = m.group(1), m.group(2)
            if var not in raw_vars or m.start() < first_decode:
                continue
            _add(m.start(), var, "dedup" if _DEDUP_NOUN.search(setvar)
                 else "mapkey")


# ============================================================================
# row + summary
# ============================================================================
_SINK_WHY = {
    "hash":
        "a hash keyed on the RAW decoded bytes as a store/identity key",
    "mapkey":
        "a map-key insert on the RAW decoded bytes",
    "dedup":
        "a dedup-set insert on the RAW decoded bytes",
    "equality":
        "a byte-identity equality on the RAW decoded bytes",
    "merkle-leaf":
        "a merkle-leaf hash keyed on the RAW decoded bytes",
    "replay-nonce":
        "a replay/nonce key on the RAW decoded bytes",
}


def _mk_row(rel, fn, line, lang, call, sink, var, excerpt):
    why = (
        f"`{call}` decodes into a logical value, then {_SINK_WHY.get(sink, sink)} "
        f"(`{var}`) with NO re-encode/canonical check in `{fn}` - two byte-distinct "
        f"non-canonical encodings of the SAME logical value (proto unknown-field / "
        f"non-minimal varint / field-reorder, amino/json whitespace, borsh trailing "
        f"bytes) yield two DIFFERENT keys. Safe form is to reject non-canonical "
        f"bytes (re-Marshal-and-compare) or key on the DECODED fields, not the raw "
        f"input. Replay / double-spend / dedup-bypass / merkle-inclusion divergence.")
    return {
        "schema": HYP_SCHEMA,
        "capability": _CAPABILITY,
        "id": _stable_id(rel, fn, sink, var, line),
        "file": rel,
        "line": line,
        "function": fn,
        "context": fn,
        "lang": lang,
        "decode_call": call,
        "sink": sink,
        "subject": var,
        "keyed_on_raw_bytes": True,
        "missing_canonical_check": True,
        "excerpt": excerpt,
        "why_severity_anchored": why,
        "fires": True,
        "verdict": "needs-fuzz",
        "advisory": True,
        "auto_credit": False,
    }


def _lang_of(rel: str) -> str:
    low = rel.lower()
    if low.endswith(".go"):
        return "go"
    if low.endswith(".rs"):
        return "rust"
    return "solidity"


def scan_file(path: Path, rel: str, file_text: str = None):
    raw = file_text if file_text is not None else path.read_text(
        encoding="utf-8", errors="ignore")
    text = _mask_comments(raw)
    lang = _lang_of(rel)
    lines = text.split("\n")
    rows = []
    for name, decl_idx, sig, body_lines in _functions(lines):
        body = _body_after_sig(body_lines)
        _scan_fn(rel, name, decl_idx, body, lang, rows)
    return rows


def _iter_source_files(root: Path, workspace: Path = None):
    for dp, dn, fn in os.walk(root):
        dn[:] = [d for d in dn if d not in _SKIP_DIRS]
        if _TEST_HINT.search(dp.replace(os.sep, "/")):
            continue
        for f in fn:
            low = f.lower()
            if not (low.endswith(".sol") or low.endswith(".go")
                    or low.endswith(".rs")):
                continue
            if (low.endswith("_test.go") or low.endswith(".t.sol")
                    or low.endswith("_test.rs")):
                continue
            if _TEST_HINT.search(f):
                continue
            p = Path(dp) / f
            rel = str(p)
            if (is_test_target_path(rel) or is_chimera_mutation_harness_path(rel)
                    or is_codegen_path(rel, workspace)):
                continue
            if _is_generated_source(p):
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
        "decode_sink_sites": len(rows),
        "fired": len(fired),
        "by_sink": _count(rows, "sink"),
        "by_lang": _count(rows, "lang"),
        "by_decode_call": _count(rows, "decode_call"),
        "verdict": "needs-fuzz" if fired else "clean-advisory",
        "advisory": True,
        "auto_credit": False,
    }


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="GEN-EL3 non-canonical serialization acceptance screen "
                    "(Go + Rust + Solidity, advisory)")
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
            rows = [json.loads(l) for l in side.read_text().splitlines()
                    if l.strip()]
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
