#!/usr/bin/env python3
"""crypto-preimage-soundness-screen.py - GEN-EL4, the CRYPTO-PREIMAGE SOUNDNESS
census (enforcement-layer = crypto primitive). Solidity-primary; a narrow
Rust/Go ARM-N (fixed-IV/nonce) secondary.

GENERAL LOGIC (impact-agnostic, NORTH-STAR; the crypto primitive is a TRUSTED
enforcement - it only delivers its soundness property when the caller supplies
the guard the primitive assumes). Every signature-verify / AEAD / commit-open
site DELEGATES a soundness property to the primitive that the caller must
re-establish. Census each such site for the MISSING caller-side guard; fire only
when the guard is ABSENT (bias hard to silence).

Arms (each fires only when its guard is absent AT a real verify/hash-commit
site; never on a bare keccak):
  * ARM D  domain-sep-absent  (D_NO_DOMAIN_SEP):
      a signature digest is hashed and recovered (ecrecover / ECDSA.recover)
      WITHOUT a binding domain-separator in the preimage: no EIP-712
      domainSeparator / _hashTypedDataV4, no block.chainid, no address(this),
      no `\x19\x01` prefix anywhere in the verifying function. Cross-chain /
      cross-contract signature replay.
  * ARM N  nonce-reuse  (N_NONCE_NOT_BUMPED):
      a signature-verifying function READS a nonce-like mapping for replay
      protection but the mapping is NEVER incremented anywhere in the file
      (no `nonce[..]++` / `+= 1` / OZ `_useNonce`) - the same signature replays.
      (Rust/Go: a fixed/zero IV or a module-const nonce fed to an AEAD
      encrypt/seal - IV reuse breaks the AEAD's confidentiality/integrity.)
  * ARM M  malleability-low-s  (M_NO_LOW_S):
      a RAW `ecrecover(` recovery with NO low-s enforcement (no OZ
      ECDSA.recover which rejects high-s, no `s <= N/2` half-order check) -
      signature malleability (a second valid (r,s') for the same message).
  * ARM E  empty-signer-array  (E_EMPTY_SIGNERS):
      a threshold/quorum verify loop over a signatures/signers array that can
      ACCEPT with 0 signers - no `require(sigs.length >= threshold)` /
      `require(sigs.length > 0)` before/around the loop.

DEDUP / distinctness (hard, per dispatch):
  * tools/domain-disjointness-assumption-screen.py (GEN-A5) OWNS the zero-signer
    `ecrecover == address(0)` case (its S_ECRECOVER_ZERO arm). GEN-EL4 does NOT
    re-emit that: ARM M is about LOW-S malleability (a high-s twin of a VALID
    signature), which is orthogonal to the address(0) malformed-signature domain.
    A5 also owns Rust/Go "decoded bytes with no version/network/domain check"
    (R_/G_DECODE_UNTAGGED) - so GEN-EL4's Rust/Go surface is restricted to the
    AEAD fixed-IV/nonce arm (ARM N), which A5 has no notion of.
  * tools/journal-collision-scanner.py OWNS keccak(abi.encodePacked(dynA,dynB))
    BYTE-COLLISION (two packed preimages producing byte-identical output).
    GEN-EL4 ARM D is domain-separator ABSENCE in the preimage (a missing binding
    tag), never packed-encoding ambiguity - it inspects no encodePacked schema.
  * crypto-deep-runner / stale-immutable-hash-preimage-scanner are different
    axes (fuzz driver / immutable-hash staleness), no verdict overlap.

ADVISORY-FIRST: every row carries verdict='needs-fuzz', advisory=True,
auto_credit=False, and the tool exits 0 by default. The opt-in env
AUDITOOOR_CRYPTO_PREIMAGE_STRICT (or --strict) raises the exit code when a fired
row exists.

Excludes machine-generated (.pb.go/.pulsar.go + "DO NOT EDIT"), test, sim and
vendored code via the shared exclusion libs. Silent on other trees.

Usage:
  --workspace <ws>   scan <ws>/src -> .auditooor/crypto_preimage_soundness_
                     hypotheses.jsonl + summary
  --source <dir>     scan an arbitrary dir, print rows as JSON (NO sidecar)
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

HYP_SCHEMA = "auditooor.crypto_preimage_soundness_hypotheses.v1"
_SIDE_NAME = "crypto_preimage_soundness_hypotheses.jsonl"
_STRICT_ENV = "AUDITOOOR_CRYPTO_PREIMAGE_STRICT"
_CAPABILITY = "GEN_EL4"

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
    """Reuse the .go/.sol codegen (DO-NOT-EDIT) sentinel rather than re-inline."""
    tool = TOOLS_DIR / "declared-control-mutator-completeness-screen.py"
    try:
        spec = importlib.util.spec_from_file_location("_dc_screen_el4", tool)
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
              "node", "testdata", "audits", "mocks", "mock", "fixtures",
              "flattened", "artifacts", "crytic-export"}
_TEST_HINT = re.compile(
    r"(^|/)(tests?|test_fixtures|mock|mocks|benches|benchmarks?|examples|"
    r"fixtures|simulation|simapp|testdata|flattened)(/|$)")


# ============================================================================
# comment/string masking + function extraction (Solidity / Rust / Go)
# ============================================================================
def _mask_comments(text: str) -> str:
    """Blank // and /* */ comments and string literals, preserving newlines /
    length so offsets stay source-accurate. Errs toward SILENCE.

    NOTE: we deliberately preserve the domain-separator prefix literal
    ``\\x19\\x01`` by leaving a sentinel where a string literal contained it, so
    ARM D still sees EIP-712 prefixing even though strings are masked."""
    out = []
    i, n = 0, len(text)
    in_line = in_block = in_str = False
    quote = ""
    str_buf = []
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
            str_buf.append(c)
            out.append(" ")
            if c == "\\":
                str_buf.append(nxt)
                out.append(" ")
                i += 2
                continue
            if c == quote:
                # emit a domain-prefix sentinel if the literal held \x19\x01
                if "\\x19" in "".join(str_buf) and "\\x01" in "".join(str_buf):
                    if len(out) >= 6:
                        out[-6:] = list("D0MSEP")
                in_str = False
                str_buf = []
            i += 1
        elif c in ('"', "'"):
            in_str = True
            quote = c
            str_buf = []
            out.append(" ")
            i += 1
        elif c == "`":
            in_str = True
            quote = c
            str_buf = []
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
    r"(?:function\s+([A-Za-z_]\w*))"                       # Solidity function
    r"|(?:modifier\s+([A-Za-z_]\w*))"                      # Solidity modifier
    r"|(constructor|receive|fallback)\b"                   # Solidity special
    r"|(?:func\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*))"         # Go func (recv) Foo
    r"|(?:(?:pub\s+)?(?:async\s+)?(?:unsafe\s+)?fn\s+([A-Za-z_]\w*))"  # Rust fn
    r")")


def _fn_name(m):
    return (m.group(1) or m.group(2) or m.group(3) or m.group(4)
            or m.group(5) or "<anon>")


def _functions(lines):
    """Yield (name, decl_idx, sig_text, body_after_sig) for each fn."""
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
            body.append(line)
            if "{" in line:
                started = True
            if started and depth <= 0:
                break
            j += 1
        joined = "\n".join(body)
        brace = joined.find("{")
        body_after = joined[brace + 1:] if brace >= 0 else joined
        yield name, i, "\n".join(sig_parts), body_after
        i = max(j, i + 1)


def _line_of_offset(text: str, off: int) -> int:
    return text.count("\n", 0, off) + 1


def _stable_id(rel, fn, arm, tok, line):
    h = hashlib.sha1()
    h.update(f"{rel}|{fn}|{arm}|{tok}|{line}".encode())
    return h.hexdigest()[:16]


def _excerpt(text: str, off: int) -> str:
    ls = text.rfind("\n", 0, off) + 1
    le = text.find("\n", off)
    if le == -1:
        le = len(text)
    return text[ls:le].strip()[:180]


# ============================================================================
# Solidity primitives / guard tokens
# ============================================================================
_RAW_ECRECOVER = re.compile(r"\becrecover\s*\(")
# an OZ-style .recover( (ECDSA.recover / SignatureChecker) - rejects high-s
_OZ_RECOVER = re.compile(
    r"\b(?:ECDSA\s*\.\s*(?:recover|tryRecover)|SignatureChecker(?:Lib)?\s*\."
    r"\s*isValidSignatureNow(?:Calldata)?|\.\s*recover\s*\()")
_KECCAK = re.compile(r"\bkeccak256\s*\(")

# ARM D: a CHAIN/CONTRACT-binding domain-separator token present in the
# verifying fn -> guarded. Besides the canonical EIP-712 tokens, an UPPER_CASE
# constant/immutable whose name ends in a domain-binding suffix (_PREFIX /
# _SEPARATOR / _DOMAIN / _MAGIC) counts as a domain tag when hashed into the
# preimage - e.g. Lido's ATTEST_MESSAGE_PREFIX (constructor-bound to
# block.chainid + address(this)). We bias HARD to silence.
# NOTE: a bare `*_TYPEHASH` is deliberately NOT a domain guard - a typehash binds
# only the message TYPE/purpose, not the chain/contract, so it does NOT prevent
# cross-chain / cross-contract replay (the ARM-D impact). EIP-712 code that binds
# a domain is still silenced via domainSeparator / _hashTypedDataV4 / \x19\x01.
_DOMAIN_TOKEN = re.compile(
    r"\b(?:DOMAIN_?SEPARATOR|domainSeparator|_domainSeparatorV4|"
    r"_hashTypedDataV4|EIP712|buildDomainSeparator)\b"
    r"|block\s*\.\s*chainid|\bchainid\s*\(\s*\)|address\s*\(\s*this\s*\)"
    r"|\b[A-Z][A-Z0-9_]*_(?:PREFIX|SEPARATOR|DOMAIN|MAGIC)\b"
    r"|D0MSEP", re.I)   # \x19\x01 masking sentinel from _mask_comments

# ARM M: an explicit low-s / malleability guard present -> guarded
_LOW_S_GUARD = re.compile(
    r"(?i)7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0"
    r"|\blow_?s\b|\bmalleab|\bhalf_?n\b|N\s*/\s*2\b"
    r"|s\s*(?:<=|>)\s*0x[0-9a-fA-F]{8,}")

# ARM N: nonce-like mapping read, plus file-scope increment detection
_NONCE_READ = re.compile(
    r"\b(_?nonces?|_?sigNonces?|_?authNonces?|_?permitNonces?)\s*\[")
_OZ_NONCE_USE = re.compile(
    r"(?i)\b_?useNonce\s*\(|\.\s*current\s*\(\s*\)")


def _nonce_incremented(text: str, mapname: str) -> bool:
    """True if `mapname[...]` is incremented anywhere in `text`."""
    esc = re.escape(mapname)
    pats = (
        rf"\b{esc}\s*\[[^\]]*\]\s*\+\+",          # nonce[x]++
        rf"\+\+\s*{esc}\s*\[[^\]]*\]",            # ++nonce[x]
        rf"\b{esc}\s*\[[^\]]*\]\s*\+=",           # nonce[x] += ...
        rf"\b{esc}\s*\[[^\]]*\]\s*=\s*[^;]*\+\s*1",  # nonce[x] = ...+1
    )
    return any(re.search(p, text) for p in pats)


# ARM E: signature/signer array param names, threshold tokens, loop
_SIG_ARRAY_PARAM = re.compile(
    r"\b(?:bytes(?:\[\]|\s*\[\s*\]\s*(?:calldata|memory))|address\s*\[\s*\]"
    r"\s*(?:calldata|memory)?)\s*(?:calldata\s+|memory\s+)?"
    r"([A-Za-z_]*(?:sig|signer|signature)s?[A-Za-z_]*)", re.I)
_THRESHOLD_TOKEN = re.compile(
    r"(?i)\b(threshold|quorum|minSigners|requiredSign|numRequired|_required)\b")
_FOR_LOOP = re.compile(r"\bfor\s*\(")


def _len_guard(body: str, arr: str) -> bool:
    """True if body requires arr.length >= something / > 0, or reverts on 0."""
    esc = re.escape(arr)
    pats = (
        rf"require\s*\([^;]*{esc}\s*\.\s*length\s*(?:>=|>)",
        rf"require\s*\([^;]*{esc}\s*\.\s*length\s*!=\s*0",
        rf"if\s*\(\s*{esc}\s*\.\s*length\s*(?:==\s*0|<)\b[^;{{]*\)\s*"
        rf"(?:revert|return)",
        rf"{esc}\s*\.\s*length\s*==\s*0[^;]*revert",
    )
    return any(re.search(p, body) for p in pats)


# ============================================================================
# Solidity arm scanner (per function)
# ============================================================================
def _scan_sol_fn(rel, name, decl_idx, sig, body, full_text, rows):
    has_raw = bool(_RAW_ECRECOVER.search(body))
    has_oz = bool(_OZ_RECOVER.search(body))
    verifies = has_raw or has_oz

    # ---- ARM D: domain-separator absent from the signed preimage ----------
    if verifies and _KECCAK.search(body) and not _DOMAIN_TOKEN.search(body):
        m = _RAW_ECRECOVER.search(body) or _OZ_RECOVER.search(body)
        off = m.start()
        rows.append(_mk_row(
            rel, name, _line_of_offset(body, off) + decl_idx, "solidity",
            "D_NO_DOMAIN_SEP", "domain-sep-absent",
            "no domainSeparator / block.chainid / address(this) / \\x19\\x01 "
            "in the signed preimage",
            _excerpt(body, off),
            f"a signature is recovered in `{name}` over a keccak256 preimage "
            f"that binds NO domain-separator (no EIP-712 domainSeparator / "
            f"_hashTypedDataV4, no block.chainid, no address(this), no "
            f"`\\x19\\x01` prefix) - the same signed message is valid on every "
            f"chain and every contract deploying this code, enabling "
            f"cross-chain / cross-contract signature replay."))

    # ---- ARM M: raw ecrecover with no low-s malleability guard -------------
    # A5 owns the address(0) zero-signer case; ARM M is the DISTINCT high-s
    # malleability twin. Fire only on RAW ecrecover (OZ .recover rejects high-s).
    if has_raw and not _LOW_S_GUARD.search(body) and not (
            has_oz and not has_raw):
        m = _RAW_ECRECOVER.search(body)
        off = m.start()
        rows.append(_mk_row(
            rel, name, _line_of_offset(body, off) + decl_idx, "solidity",
            "M_NO_LOW_S", "malleability-low-s",
            "raw ecrecover with no `s <= N/2` low-s / OZ ECDSA malleability "
            "rejection",
            _excerpt(body, off),
            f"`{name}` recovers via RAW `ecrecover` with no low-s enforcement "
            f"(no `s <= secp256k1n/2` half-order check, not OZ `ECDSA.recover` "
            f"which rejects high-s) - every valid signature `(r,s)` has a "
            f"malleable twin `(r, N-s)` that also recovers, so any invariant "
            f"keyed on the signature bytes (dedup set / replay guard / "
            f"processed-hash) is bypassable."))

    # ---- ARM N: nonce read but never incremented in the file --------------
    if verifies:
        nm = _NONCE_READ.search(body)
        if nm and not _OZ_NONCE_USE.search(body):
            mapname = nm.group(1)
            if not _nonce_incremented(full_text, mapname) and \
                    not _OZ_NONCE_USE.search(full_text):
                off = nm.start()
                rows.append(_mk_row(
                    rel, name, _line_of_offset(body, off) + decl_idx,
                    "solidity", "N_NONCE_NOT_BUMPED", "nonce-reuse",
                    f"`{mapname}[...]` read for replay protection but never "
                    f"incremented (no ++ / += 1 / _useNonce) in the file",
                    _excerpt(body, off),
                    f"`{name}` verifies a signature and reads the replay-"
                    f"protection nonce `{mapname}[...]`, but that mapping is "
                    f"never incremented anywhere in the file - the nonce is not "
                    f"consumed, so the SAME signed message can be replayed "
                    f"unboundedly."))

    # ---- ARM E: threshold verify loop that can accept 0 signers -----------
    if _THRESHOLD_TOKEN.search(body) and _FOR_LOOP.search(body):
        for am in _SIG_ARRAY_PARAM.finditer(sig):
            arr = am.group(1)
            if not re.search(r"\b" + re.escape(arr) + r"\b", body):
                continue
            if _len_guard(body, arr):
                continue
            off = body.find("for")
            if off < 0:
                off = 0
            rows.append(_mk_row(
                rel, name, _line_of_offset(body, off) + decl_idx, "solidity",
                "E_EMPTY_SIGNERS", "empty-signer-array",
                f"threshold/quorum loop over `{arr}` with no "
                f"`require({arr}.length >= threshold)` / `> 0` guard",
                _excerpt(body, off),
                f"`{name}` accumulates a threshold/quorum over signer array "
                f"`{arr}` in a for-loop but never requires "
                f"`{arr}.length >= threshold` (or `> 0`) - an EMPTY `{arr}` "
                f"skips the loop and can satisfy a `count >= threshold` check "
                f"when threshold is 0 / never reached, authorizing with ZERO "
                f"valid signatures."))
            break


# ============================================================================
# Rust / Go ARM N: fixed / zero IV or module-const nonce fed to an AEAD
# ============================================================================
# A5 owns the Rust/Go "decoded bytes, no domain/version check" surface; GEN-EL4
# on Rust/Go is restricted to AEAD IV/nonce REUSE, which A5 has no notion of.
_AEAD_CALL = re.compile(
    r"\.\s*(?:encrypt|encrypt_in_place|encrypt_in_place_detached|seal|"
    r"seal_in_place)\s*\(")
# a nonce/IV argument that is fixed: a zero array, a module const (UPPER_CASE),
# or Nonce::from_slice of a const.
_FIXED_IV = re.compile(
    r"(?:Nonce|Iv|IV|GenericArray)\s*::\s*from_slice\s*\(\s*&?\s*"
    r"(?:[A-Z][A-Z0-9_]{2,}|\[\s*0(?:u8)?\s*;)"
    r"|\bnonce\s*[:=]\s*&?\s*\[\s*0(?:u8)?\s*;"
    r"|\biv\s*[:=]\s*&?\s*\[\s*0(?:u8)?\s*;"
    r"|\bnonce\s*[:=]\s*&?[A-Z][A-Z0-9_]{2,}\b")
# rotation evidence: nonce derived from a counter / random / increment -> guarded
_NONCE_ROTATION = re.compile(
    r"(?i)\b(rand|thread_rng|OsRng|getrandom|fill_bytes|random_|counter|"
    r"increment|next_nonce|generate_nonce|rng\.)")


def _scan_rustgo_fn(rel, name, decl_idx, sig, body, lang, rows):
    if not _AEAD_CALL.search(body):
        return
    if not _FIXED_IV.search(body):
        return
    if _NONCE_ROTATION.search(body):
        return  # nonce is rotated / random -> guarded, silent
    m = _AEAD_CALL.search(body)
    off = m.start()
    rows.append(_mk_row(
        rel, name, _line_of_offset(body, off) + decl_idx, lang,
        "N_FIXED_IV", "nonce-reuse",
        "AEAD encrypt/seal called with a fixed / zero / module-const nonce (IV) "
        "and no per-message rotation",
        _excerpt(body, off),
        f"`{name}` calls an AEAD encrypt/seal with a FIXED or zero IV/nonce and "
        f"no per-message rotation (no counter / RNG) - reusing an AEAD nonce "
        f"under one key breaks confidentiality (keystream reuse) and, for "
        f"Poly1305/GCM, forgeability (the one-time authenticator key repeats)."))


# ============================================================================
# row + summary
# ============================================================================
def _mk_row(rel, fn, line, lang, arm_id, arm, missing_guard, excerpt, why):
    return {
        "schema": HYP_SCHEMA,
        "capability": _CAPABILITY,
        "id": _stable_id(rel, fn, arm_id, missing_guard, line),
        "file": rel,
        "line": line,
        "function": fn,
        "context": fn,
        "lang": lang,
        "arm_id": arm_id,
        "arm": arm,
        "missing_guard": missing_guard,
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
    rows = []
    for name, decl_idx, sig, body in _functions(lines):
        if lang == "solidity":
            _scan_sol_fn(rel, name, decl_idx, sig, body, text, rows)
        else:
            _scan_rustgo_fn(rel, name, decl_idx, sig, body, lang, rows)
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
        "by_arm": _count(rows, "arm_id"),
        "by_lang": _count(rows, "lang"),
        "verdict": "needs-fuzz" if fired else "clean-advisory",
        "advisory": True,
        "auto_credit": False,
    }


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="GEN-EL4 crypto-preimage soundness census (Solidity "
                    "primary; Rust/Go AEAD-IV secondary; advisory)")
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
        return 1 if (strict and rows) else 0

    if args.source:
        rows = scan_tree(Path(args.source))
        print(json.dumps(rows, indent=2))
        return 1 if (strict and rows) else 0

    if not args.workspace:
        ap.error("one of --workspace / --source / --file is required")

    ws = Path(args.workspace)
    if not ws.is_absolute():
        for base in ("/Users/wolf/audits", "/Users/wolf/auditooor-worktrees"):
            cand = Path(base) / args.workspace
            if cand.exists():
                ws = cand
                break
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
