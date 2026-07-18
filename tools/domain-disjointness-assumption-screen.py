#!/usr/bin/env python3
"""domain-disjointness-assumption-screen.py - GEN-A5, the IMPLICIT
DOMAIN-DISJOINTNESS ASSUMPTION screen (Solidity primary; Rust + Go secondary).

GENERAL LOGIC / whole-system-trust class (impact-agnostic, NORTH-STAR, never a
bug SHAPE). An acceptance predicate TRUSTS an UNSTATED "X cannot inhabit type Y"
domain-separation assumption without either a domain-separation tag or a
structural-impossibility proof. The value that is trusted to be OUTSIDE a
forbidden sub-domain is attacker-influenced, and the forbidden element (a
constructing contract that reads code.length==0, the zero-address ecrecover
returns on a malformed signature, a raw blob that abi.decodes into a privileged
struct, a reserved sentinel id, an untagged discriminant) is REACHABLE.

We do NOT try to detect the abstract class in full - only its CONCRETE,
HIGH-CONFIDENCE instances, one advisory row each, biased HARD toward silence.

Pattern classes
---------------
Solidity (PRIMARY):
  * A1  assumption=eoa-not-contract  (S_EOA_CODESIZE):
      an `extcodesize(x)==0` / `x.code.length==0` gate on an ACCOUNT-like subject
      (msg.sender/sender/caller/account/user/from/owner) used to decide "is EOA /
      is not a contract", WITHOUT a companion `tx.origin == msg.sender` check.
      Missing proof: during a contract's CONSTRUCTION its code.length is 0, so a
      contract calling from its constructor passes the "is EOA" gate.
      -> missing_proof = "no tx.origin==msg.sender; code.length==0 during construction".
      (A `.code.length > 0` token-EXISTENCE check on a token-like subject is NOT an
       EOA gate and is deliberately SILENT - that is not this class.)
  * A2  assumption=zero-signer  (S_ECRECOVER_ZERO):
      `addr = ecrecover(...)` whose result is used as an authorized signer WITHOUT
      a `!= address(0)` reject anywhere in the function. Missing proof: a malformed
      signature makes ecrecover return address(0) - the zero-address domain - which
      then authorizes if any compared identity can be zero.
      -> missing_proof = "ecrecover result not rejected against address(0)".
  * A3  assumption=decode-into-type  (S_DECODE_PRIVILEGED):
      `abi.decode(<attacker bytes param>, (address | <StructType>))` with NO
      `require(<param>.length ...)` domain assertion. Missing proof: a raw hash /
      short blob parses as the privileged type (address / admin struct); nothing
      proves the bytes actually inhabit that type's domain.
      -> missing_proof = "attacker bytes decoded into privileged type w/o length/domain assert".
  * A4  assumption=reserved-id-collision  (S_RESERVED_ID):
      a user-supplied id/index/key param WRITTEN as a mapping key or array index
      (`m[id]=...`) with NO `require(id != 0 | id != type(uint).max | id != RESERVED)`
      guard, in a file that ALSO defines a reserved sentinel constant/handle.
      Missing proof: the user id shares a namespace with the reserved sentinel.
      -> missing_proof = "user id written to keyed store shares namespace w/ reserved sentinel".
Rust / Go (SECONDARY):
  * A5  assumption=untagged-discriminant  (R_/G_DECODE_UNTAGGED):
      a decode / from_bytes / try_from_slice / Unmarshal of an UNTRUSTED byte
      buffer (a param named data/bytes/buf/input/raw/payload/msg/slice) into a
      NAMED type, with NO version / tag / magic / prefix / discriminant / network /
      chain-id domain check in the function. Missing proof: the bytes are trusted to
      inhabit the target type/variant with no domain separator - an untagged union
      decodes into the wrong variant, or an address is parsed without a network/
      version prefix.
      -> missing_proof = "byte buffer decoded into named type w/o version/tag/network domain check".

DEDUP / distinctness (hard, per dispatch):
  * tools/journal-collision-scanner.py detects keccak(abi.encodePacked(dynA,dynB))
    DOMAIN-BYTE COLLISION - two packed preimages that can produce byte-identical
    output. GEN-A5 is disjointness of TYPE / IDENTITY (is X an EOA? is this addr
    the zero-signer? does this blob inhabit an admin struct? does this id collide
    with a reserved handle?), NOT packed-encoding ambiguity. No overlap: A5 never
    inspects abi.encodePacked argument schemas.
  * tools/generic-type-vs-runtime-selector-desync-screen.py couples a COMPILE-TIME
    generic/phantom `<T>` (a Coin<T>/Balance<T> wrapper) to a RUNTIME asset
    selector. GEN-A5 has NO generic-vs-selector axis; it is broader and orthogonal
    (EOA / zero-signer / decode-into-type / reserved-id / untagged discriminant).
  Neither existing tool owns the EOA-construction, zero-address-ecrecover,
  decode-into-privileged-type, reserved-id, or untagged-byte-discriminant instances.

ADVISORY-FIRST: every row carries verdict='needs-fuzz', advisory=True,
auto_credit=False, and the tool exits 0 by default. The opt-in env
AUDITOOOR_DOMAIN_DISJOINTNESS_STRICT (or --strict) raises the exit code when a
fired row exists.

Excludes machine-generated (.pb.go/.pulsar.go + "DO NOT EDIT"), test, sim and
vendored code via the shared exclusion libs. Silent on other trees.

Usage:
  --workspace <ws>   scan <ws>/src -> .auditooor/domain_disjointness_hypotheses.jsonl + summary
  --source <dir>     scan an arbitrary dir, print rows as JSON (NO sidecar - tests/verify)
  --file <f>         scan a single .sol/.rs/.go file, print rows as JSON
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

HYP_SCHEMA = "auditooor.domain_disjointness_hypotheses.v1"
_SIDE_NAME = "domain_disjointness_hypotheses.jsonl"
_STRICT_ENV = "AUDITOOOR_DOMAIN_DISJOINTNESS_STRICT"
_CAPABILITY = "GEN_A5"

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
    """Reuse the .go/.sol codegen (DO-NOT-EDIT) sentinel rather than re-inline it."""
    tool = TOOLS_DIR / "declared-control-mutator-completeness-screen.py"
    try:
        spec = importlib.util.spec_from_file_location("_dc_screen_a5", tool)
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
              "node", "testdata", "audits", "mocks"}
_TEST_HINT = re.compile(
    r"(^|/)(tests?|test_fixtures|mock|mocks|benches|benchmarks?|examples|"
    r"fixtures|simulation|simapp|testdata)(/|$)")


# ============================================================================
# comment/string masking + function extraction (Solidity / Rust / Go)
# ============================================================================
def _mask_comments(text: str) -> str:
    """Blank // and /* */ comments and string literals, preserving newlines /
    length so offsets stay source-accurate. Errs toward SILENCE."""
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
    r"(?:function\s+([A-Za-z_]\w*))"                       # Solidity function foo
    r"|(?:modifier\s+([A-Za-z_]\w*))"                      # Solidity modifier m
    r"|(constructor|receive|fallback)\b"                   # Solidity special
    r"|(?:func\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*))"         # Go func (recv) Foo
    r"|(?:(?:pub\s+)?(?:async\s+)?(?:unsafe\s+)?fn\s+([A-Za-z_]\w*))"  # Rust fn
    r")")


def _fn_name(m):
    return (m.group(1) or m.group(2) or m.group(3) or m.group(4)
            or m.group(5) or "<anon>")


def _functions(lines):
    """Yield (name, decl_idx, sig_text, body_lines) for each brace-matched fn."""
    i, n = 0, len(lines)
    while i < n:
        m = _FN_DECL_RE.match(lines[i])
        if not m:
            i += 1
            continue
        name = _fn_name(m)
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


def _stable_id(rel, fn, kind, tok, line):
    h = hashlib.sha1()
    h.update(f"{rel}|{fn}|{kind}|{tok}|{line}".encode())
    return h.hexdigest()[:16]


def _excerpt(text: str, off: int) -> str:
    ls = text.rfind("\n", 0, off) + 1
    le = text.find("\n", off)
    if le == -1:
        le = len(text)
    return text[ls:le].strip()[:180]


# ============================================================================
# Solidity arms
# ============================================================================
# account-like vs token-like subject names (EOA gate vs token-existence check)
_ACCOUNT_NAME = re.compile(
    r"(?i)\b(msg\.sender|tx\.origin|sender|caller|account|user|owner|from|to|"
    r"beneficiary|recipient|spender|operator|signer|_account|_user|addr)\b")
_TOKEN_NAME = re.compile(
    r"(?i)\b(token|asset|pair|pool|vault|market|reward|underlying|collateral|"
    r"loan|weth|erc20|erc721|implementation|impl|target|factory|module|adapter|"
    r"strategy|oracle|registry)\b")

# A1: codesize/code.length used as an EOA "is not a contract" gate (== 0 / != 0)
_A1_CODESIZE_RE = re.compile(
    r"(?:extcodesize\s*\(\s*([A-Za-z_][\w.]*)\s*\)|"
    r"([A-Za-z_][\w.]*)\s*\.\s*code\s*\.\s*length)"
    r"\s*(==|!=|<)\s*(?:0\b|1\b)")

# A2: assigned ecrecover result
_A2_ECRECOVER_RE = re.compile(
    r"\baddress\s+(?:payable\s+)?([A-Za-z_]\w*)\s*=\s*ecrecover\s*\(")

# A3: abi.decode(src, (types))
_A3_DECODE_RE = re.compile(
    r"abi\.decode\s*\(\s*([A-Za-z_]\w*)\s*,\s*\(([^)]*)\)\s*\)")

# A4: mapping/array WRITE keyed by an id-like param
_ID_NAME = re.compile(
    r"(?i)^(?:_?)(id|idx|index|key|handle|slot|tokenId|marketId|poolId|"
    r"assetId|nftId|itemId|position(?:Id)?|nonce|epoch|round)$")
_A4_WRITE_RE = re.compile(
    r"\b([A-Za-z_]\w*)\s*\[\s*([A-Za-z_]\w*)\s*\]\s*(?:\.[A-Za-z_]\w*\s*)?"
    r"(?:=(?!=)|\+\+|--)")
_RESERVED_SENTINEL_RE = re.compile(
    r"(?i)(?:\b(?:RESERVED|SENTINEL|EMPTY_?ID|NULL_?ID|MAX_?ID|NO_?ID|"
    r"UNSET_?ID)\w*"
    r"|type\s*\(\s*uint\d*\s*\)\s*\.\s*max)")


def _bytes_params(sig: str):
    """Names of `bytes`(calldata/memory) params in a Solidity signature."""
    out = set()
    for m in re.finditer(
            r"\bbytes(?:\d*)?\s+(?:(?:calldata|memory|storage)\s+)?"
            r"([A-Za-z_]\w*)", sig):
        out.add(m.group(1))
    return out


def _has_zero_reject(body: str, var: str) -> bool:
    """True if `var` is compared against address(0) anywhere (either polarity)."""
    pat = re.compile(
        r"\b" + re.escape(var) + r"\s*(==|!=)\s*address\s*\(\s*0\s*\)"
        r"|address\s*\(\s*0\s*\)\s*(==|!=)\s*\b" + re.escape(var) + r"\b")
    return bool(pat.search(body))


def _scan_sol_fn(rel, name, decl_idx, sig, body, rows):
    fired_here = set()

    # ---- A1: EOA-via-codesize without tx.origin companion -----------------
    for m in _A1_CODESIZE_RE.finditer(body):
        subj = (m.group(1) or m.group(2) or "").strip()
        op = m.group(3)
        # token-existence check (`token.code.length > 0` / != 0 on a token) is
        # NOT an EOA gate -> silent. Only an account-like subject asserting EOA.
        if not _ACCOUNT_NAME.search(subj):
            continue
        if _TOKEN_NAME.search(subj):
            continue
        # `!= 0` on an account = "must BE a contract" (not the EOA-construction
        # trap). The construction bypass is the "must be EOA" gate: == 0 / < 1.
        if op == "!=":
            continue
        if re.search(r"tx\s*\.\s*origin\s*==\s*msg\s*\.\s*sender", body) or \
           re.search(r"msg\s*\.\s*sender\s*==\s*tx\s*\.\s*origin", body):
            continue
        off = m.start()
        rows.append(_mk_row(
            rel, name, _line_of_offset(body, off) + decl_idx, "solidity",
            "S_EOA_CODESIZE", "eoa-not-contract", subj,
            "no tx.origin==msg.sender; code.length==0 during construction",
            _excerpt(body, off),
            f"a codesize/`code.length` gate on account-like `{subj}` decides "
            f"'is EOA / not a contract' with no `tx.origin==msg.sender` companion "
            f"- during a contract's CONSTRUCTION its code.length is 0, so a "
            f"contract calling from its constructor inhabits the 'EOA' domain the "
            f"predicate trusts it cannot (constructor-reentrancy bypass)."))
        fired_here.add("A1")
        break

    # ---- A2: ecrecover result used without address(0) reject --------------
    for m in _A2_ECRECOVER_RE.finditer(body):
        var = m.group(1)
        if _has_zero_reject(body, var):
            continue
        off = m.start()
        rows.append(_mk_row(
            rel, name, _line_of_offset(body, off) + decl_idx, "solidity",
            "S_ECRECOVER_ZERO", "zero-signer", var,
            "ecrecover result not rejected against address(0)",
            _excerpt(body, off),
            f"`{var} = ecrecover(...)` is used as an authorized signer with no "
            f"`{var} != address(0)` reject - a malformed signature makes ecrecover "
            f"return address(0) (the zero-signer domain); if any compared identity "
            f"can be zero the predicate authorizes an unsigned message."))
        fired_here.add("A2")
        break

    # ---- A3: abi.decode of attacker bytes into a privileged type ----------
    bparams = _bytes_params(sig)
    for m in _A3_DECODE_RE.finditer(body):
        src, types = m.group(1), m.group(2)
        if src not in bparams:
            continue  # only attacker-controlled bytes params (bias to silence)
        # privileged target: an address, or a CamelCase struct-ish type
        has_addr = bool(re.search(r"\baddress\b", types))
        has_struct = bool(re.search(r"\b[A-Z][A-Za-z0-9_]*\b", types))
        if not (has_addr or has_struct):
            continue
        if re.search(r"\brequire\s*\(\s*" + re.escape(src) + r"\s*\.\s*length",
                     body):
            continue  # a length/domain assertion on the bytes -> guarded
        off = m.start()
        rows.append(_mk_row(
            rel, name, _line_of_offset(body, off) + decl_idx, "solidity",
            "S_DECODE_PRIVILEGED", "decode-into-type", src,
            "attacker bytes decoded into privileged type w/o length/domain assert",
            _excerpt(body, off),
            f"`abi.decode({src}, ({types.strip()}))` parses attacker-controlled "
            f"bytes `{src}` into a privileged type with no `require({src}.length "
            f"...)` domain assertion - a raw hash / short blob is trusted to "
            f"inhabit the (address / admin-struct) domain; nothing proves the "
            f"bytes actually encode that type."))
        fired_here.add("A3")
        break

    # ---- A4: reserved-id-collision (conservative: needs a sentinel in file) -
    if _RESERVED_SENTINEL_RE.search(body) or getattr(_scan_sol_fn,
                                                     "_file_has_sentinel", False):
        # param names available from signature
        params = set(re.findall(r"\b([A-Za-z_]\w*)\s*(?:,|\))", sig))
        for m in _A4_WRITE_RE.finditer(body):
            key = m.group(2)
            if not _ID_NAME.match(key):
                continue
            if key not in _id_like_params(sig):
                continue  # must be an externally-supplied param id
            if re.search(
                    r"\brequire\s*\([^;]*\b" + re.escape(key) +
                    r"\b[^;]*(?:!=\s*0|!=\s*type\s*\(|!=\s*RESERVED)", body):
                continue
            off = m.start()
            rows.append(_mk_row(
                rel, name, _line_of_offset(body, off) + decl_idx, "solidity",
                "S_RESERVED_ID", "reserved-id-collision", key,
                "user id written to keyed store shares namespace w/ reserved sentinel",
                _excerpt(body, off),
                f"user-supplied id `{key}` is written as a store key "
                f"(`{m.group(1)}[{key}]`) with no `require({key} != 0 / != "
                f"type(uint).max / != RESERVED)` guard, while the file defines a "
                f"reserved sentinel - the id domain is trusted to be disjoint from "
                f"the reserved handle, but a caller can supply the sentinel value."))
            fired_here.add("A4")
            break


def _id_like_params(sig: str):
    """INTEGER id/index-like Solidity params. A collision with a reserved
    sentinel (0 / type(uint).max) is only realistic for a small-integer id
    space - a bytes32 keccak handle cannot practically equal the sentinel, so
    bytes32 params are excluded (bias to silence)."""
    out = set()
    for m in re.finditer(r"\buint(?:\d+)?\s+([A-Za-z_]\w*)", sig):
        if _ID_NAME.match(m.group(1)):
            out.add(m.group(1))
    return out


# ============================================================================
# Rust / Go arm: A5 untagged-discriminant decode
# ============================================================================
# A5 is the CONCRETE, high-confidence instance of "trusts a discriminant it did
# NOT domain-separate": a POSITIONAL tag/discriminant read from an untrusted RAW
# byte buffer that then drives a `match`/`switch` variant dispatch, with no
# length / magic / version domain check. This deliberately does NOT fire on
# serde/Borsh `deserialize` / `try_from_slice` / proto `Unmarshal` - those
# self-describe the variant tag (they ARE domain-separated), so flagging them is
# a false positive (the near-fleet Borsh spray).
_DOMAIN_TAG_TOKEN = re.compile(
    r"(?i)\b(version|magic|prefix|discriminant|expected_?(?:type|tag)|"
    r"chain_?id|network_?(?:id|byte)|domain_?sep|checksum|_MAGIC|_PREFIX|"
    r"VERSION|MAGIC|PREFIX)\b")
# untrusted RAW buffer name (a param or local named like external bytes)
_RAW_BUF = (r"(?:data|bytes|buf|buffer|input|raw|payload|msg|message|slice|"
            r"blob|encoded|serialized|packet|frame|b|src)")
# Rust: `match <raw>[<idx>]` / `match <raw>.get(<idx>)` / `match <raw>.first()`
_RS_TAG_DISPATCH_RE = re.compile(
    r"\bmatch\s+(" + _RAW_BUF + r")\s*(?:"
    r"\[\s*\w+\s*\]"                       # raw[idx]
    r"|\.\s*get\s*\(\s*\w+\s*\)"           # raw.get(idx)
    r"|\.\s*first\s*\(\s*\)"               # raw.first()
    r")")
# Go: `switch <raw>[<idx>]` positional-byte tag dispatch
_GO_TAG_DISPATCH_RE = re.compile(
    r"\bswitch\s+(" + _RAW_BUF + r")\s*\[\s*\w+\s*\]")


def _scan_rust_fn(rel, name, decl_idx, sig, body, rows):
    m = _RS_TAG_DISPATCH_RE.search(body)
    if not m:
        return
    if _DOMAIN_TAG_TOKEN.search(body):
        return  # a version/magic/network domain check is present -> guarded
    src = m.group(1)
    off = m.start()
    rows.append(_mk_row(
        rel, name, _line_of_offset(body, off) + decl_idx, "rust",
        "R_DECODE_UNTAGGED", "untagged-discriminant", src,
        "positional tag byte matched from untrusted buffer w/o magic/version/domain check",
        _excerpt(body, off),
        f"a variant discriminant is read POSITIONALLY from untrusted buffer "
        f"`{src}` (`{_excerpt(body, off)[:60]}`) and `match`ed with no magic / "
        f"version / network domain check - the tag byte is trusted to name the "
        f"intended variant, but the buffer is an untagged union the caller "
        f"controls (an unstated 'this byte cannot mean another variant' domain "
        f"assumption)."))


def _scan_go_fn(rel, name, decl_idx, sig, body, rows):
    m = _GO_TAG_DISPATCH_RE.search(body)
    if not m:
        return
    if _DOMAIN_TAG_TOKEN.search(body):
        return
    src = m.group(1)
    off = m.start()
    rows.append(_mk_row(
        rel, name, _line_of_offset(body, off) + decl_idx, "go",
        "G_DECODE_UNTAGGED", "untagged-discriminant", src,
        "positional tag byte switched from untrusted buffer w/o magic/version/domain check",
        _excerpt(body, off),
        f"a variant discriminant is read POSITIONALLY from untrusted buffer "
        f"`{src}` (`{_excerpt(body, off)[:60]}`) and `switch`ed with no magic / "
        f"version / network domain check - the tag byte is trusted to name the "
        f"intended variant, but the buffer is an untagged union the caller "
        f"controls."))


# ============================================================================
# row + summary
# ============================================================================
def _mk_row(rel, fn, line, lang, pattern_id, assumption, token, missing_proof,
            excerpt, why):
    return {
        "schema": HYP_SCHEMA,
        "capability": _CAPABILITY,
        "id": _stable_id(rel, fn, pattern_id, token, line),
        "file": rel,
        "line": line,
        "function": fn,
        "context": fn,
        "lang": lang,
        "pattern_id": pattern_id,
        "assumption": assumption,
        "token": token,
        "missing_proof": missing_proof,
        "excerpt": excerpt,
        "why_severity_anchored": why,
        "fires": True,
        "verdict": "needs-fuzz",
        "advisory": True,
        "auto_credit": False,
    }


def scan_file(path: Path, rel: str, file_text: str = None):
    raw = file_text if file_text is not None else path.read_text(
        encoding="utf-8", errors="ignore")
    text = _mask_comments(raw)
    low = rel.lower()
    if low.endswith(".rs"):
        lang = "rust"
    elif low.endswith(".go"):
        lang = "go"
    else:
        lang = "solidity"
    lines = text.split("\n")
    # file-wide reserved sentinel presence (A4 gate); set as fn attr for reuse
    _scan_sol_fn._file_has_sentinel = bool(_RESERVED_SENTINEL_RE.search(text))
    rows = []
    for name, decl_idx, sig, body_lines in _functions(lines):
        body = _body_after_sig(body_lines)
        if lang == "solidity":
            _scan_sol_fn(rel, name, decl_idx, sig, body, rows)
        elif lang == "rust":
            _scan_rust_fn(rel, name, decl_idx, sig, body, rows)
        else:
            _scan_go_fn(rel, name, decl_idx, sig, body, rows)
    return rows


def _iter_source_files(root: Path, workspace: Path = None):
    for dp, dn, fn in os.walk(root):
        dn[:] = [d for d in dn if d not in _SKIP_DIRS]
        if _TEST_HINT.search(dp.replace(os.sep, "/")):
            continue
        for f in fn:
            low = f.lower()
            if not (low.endswith(".sol") or low.endswith(".rs")
                    or low.endswith(".go")):
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
        "candidates": len(rows),
        "fired": len(fired),
        "by_pattern": _count(rows, "pattern_id"),
        "by_assumption": _count(rows, "assumption"),
        "by_lang": _count(rows, "lang"),
        "verdict": "needs-fuzz" if fired else "clean-advisory",
        "advisory": True,
        "auto_credit": False,
    }


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="GEN-A5 implicit domain-disjointness assumption screen "
                    "(Solidity primary; Rust + Go secondary; advisory)")
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
