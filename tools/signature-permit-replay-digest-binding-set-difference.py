#!/usr/bin/env python3
"""signature-permit-replay-digest-binding-set-difference.py - the EIP-712 /
ECDSA permit-replay reasoning query (LOGIC ARSENAL, docs/LOGIC_ARSENAL_ROADMAP.md).

This is a SET / CLOSURE query over an OWNED dataflow backend, NOT a token detector.

CORPUS SOURCE (the mined logic class)
  reference/patterns.dsl/signature-missing-chainid-enables-cross-chain-replay.yaml,
  r74-auth-cross-contract-signature-replay.yaml, w68-approval-replay-missing-nonce.yaml,
  certora-nonce-strictly-monotonic.yaml, r94-loop-erc1271-replay-no-nonce.yaml,
  chain-id-hardcoded-eip712.yaml; detectors/fixtures/{bridge_replay_key_omits_chain_domain,
  eip_712_signature_replay_across_different_domains,
  batched_ecrecover_with_no_per_signer_tracking_replay_risk,
  w68_approval_replay_missing_nonce,
  perp_signature_missing_oracle_id_replay_across_feeds};
  detectors/go_wave1/{go-cosmos-signature-replay-scope-missing.py,
  go-signature-domain-replay-fire37.py}.

THE ASSUMPTION (what the protocol trusts)
  A recovered signer authorizes a SPECIFIC action, EXACTLY ONCE, on THIS chain,
  for THIS contract.

THE INVARIANT (set relation, transitive-closure)
  Let RECOVER = { fn F : F's forward call closure recovers a signer
                  (ecrecover / ECDSA.recover / ECDSA.tryRecover /
                   SignatureChecker.isValidSignatureNow / crypto.SigToPub /
                   secp256k1.RecoverPubkey) and USES the result to authorize a
                  state change }.
  For every F in RECOVER, the BACKWARD DefUse closure of the hashed DIGEST that
  is recovered against MUST bind ALL of:
      chainid              (block.chainid, or a domain separator that itself
                            binds chainid),
      verifyingContract    (address(this) / a verifyingContract field),
      consumed-nonce       (a nonce / used-hash slot that is BOTH read as a guard
                            AND WRITTEN by a state-write inside F -
                            nonces[user]++ / usedHash[h]=true),
      deadline             (an expiry compared against block.timestamp) [advisory].
  The binding is TRANSITIVE: chainid+verifyingContract commonly live in a
  _getDomainSeparator() helper reached through F's forward call closure, NOT in
  F's own body - so this is a CLOSURE relation, not a same-body scan.

THE FINDING = SET-DIFFERENCE
  For each F in RECOVER, MISSING(F) = REQUIRED \\ PRESENT(F), where
  REQUIRED = {chainid, verifyingContract, consumed-nonce}. Every F with
  MISSING(F) non-empty is a survivor: the signature bytes are attacker-replayable
  across chains (chainid absent), across sibling contracts (verifyingContract
  absent), or unlimited-times (the nonce slot is READ but never WRITTEN, so the
  replay guard never latches). deadline is reported but does not, by itself,
  produce a survivor.

WHY THIS IS LOGIC, NOT A SHAPE (guard-rail satisfied)
  A same-body regex ("block.chainid present? address(this) present?") FALSE-
  POSITIVES on every fn whose binding lives in a domain-separator helper, and
  cannot express the nonce read-vs-write relation. This query differs on three
  axes that make it a graph/def-use relation:
   (a) RECOVER membership is TRANSITIVE forward-closure reachability to a
       signer-recovery NODE - a recover call reached through an N-hop helper
       still places F in RECOVER (impossible for a body-scoped regex);
   (b) PRESENT(F) is computed over F's DIGEST-BINDING CLOSURE (F's body UNION the
       digest-builder helper fns reached through F's call closure), so chainid in
       _getDomainSeparart() two hops away correctly BINDS F - the answer is a
       SET-DIFFERENCE REQUIRED\\PRESENT, not a boolean over one body's text;
   (c) the consumed-nonce element is a DEF/USE relation (the used/nonce slot must
       be READ as a guard AND WRITTEN by a state-write in F); a slot that is
       read-only is a distinct survivor class (unlimited replay) that no token-
       present/absent test can express.

OWNED BACKEND CONSUMED (no new engine is built here)
  <ws>/.auditooor/dataflow_paths.jsonl (schema dataflow_path.v1) produced by the
  Slither statevar-defuse bridge (Solidity) and go-dataflow (Go). Each record
  ties an ENTRYPOINT to a sink and carries closure guard nodes. This reasoner
  reads it to (1) enumerate the candidate fns + their file:decl anchors and (2)
  build the same-file bare-name call map used to resolve digest-builder helpers.
  The signer-recovery NODE predicate and the four binding-element NODE predicates
  are per-node classifiers (exactly as callgraph-set-difference-hunter's
  solvency_guard_pred is a per-node predicate); the LOGIC is the transitive
  closure + set-difference wrapped around them.

OUTPUT
  <ws>/.auditooor/signature_replay_digest_binding_obligations.jsonl - one row per
  survivor, schema auditooor.signature_replay_digest_binding.v1, exploit_queue-
  ingest compatible (contract/function/source_refs/root_cause_hypothesis/
  attack_class/broken_invariant_ids/quality_gate_status='needs_source'). It is
  ingested by exploit-queue.py _gather_from_signature_replay_binding_obligations
  -> the queue -> per-fn-mimo-batch-gen OPEN-OBLIGATIONS block.
  A summary (|RECOVER|, KEPT (fully-bound, proving the subtraction is non-vacuous),
  survivors + their MISSING set) is printed / emitted (--json).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from pathlib import Path

_HERE = Path(__file__).resolve().parent

# ---------------------------------------------------------------------------
# scope OOS guard (single source of truth); degrade to a conservative default.
# ---------------------------------------------------------------------------
try:
    from tools.lib.scope_exclusion import is_oos  # type: ignore
except Exception:  # pragma: no cover
    _LIB = _HERE / "lib"
    if str(_LIB) not in sys.path:
        sys.path.insert(0, str(_LIB))
    try:
        from scope_exclusion import is_oos  # type: ignore
    except Exception:
        def is_oos(rel: str, **_) -> bool:  # type: ignore[misc]
            n = ("/" + str(rel).replace("\\", "/")).lower()
            return any(m in n for m in (
                "/test/", "/tests/", "_test.", ".t.sol", "/mock", "/vendor/",
                "/node_modules/", "/out/", "/build/", "/target/", "/.auditooor/",
            ))

_VENDOR_MARKERS = ("/pkg/mod/", "/go/pkg/", "/vendor/", "/node_modules/")
_CODEGEN_SUFFIXES = (".pb.go", ".pb.gw.go", ".gen.go", "_pb2.py")

# ---------------------------------------------------------------------------
# (A) signer-recovery NODE predicate. A recovery CALL - the digest+signature ->
# signer primitive - not the substring 'recover' (which appears in comments /
# names / unrelated fns). Anchored to a call form '<primitive>(' so a doc string
# or a variable named recoveredSigner does not match.
# ---------------------------------------------------------------------------
# Two forms: (1) a bare-identifier primitive (word-bounded so a variable named
# recoveredSigner / a comment never matches), and (2) a METHOD-call primitive
# `<x>.isValidSignatureNow(` / `ECDSA.recover(` where the '.' floats after any
# receiver expression.
_RECOVER_BARE_RE = re.compile(
    r"(?<![A-Za-z0-9_.])(ecrecover|Ecrecover)\s*\(")
_RECOVER_METHOD_RE = re.compile(
    r"\.\s*(recover|tryRecover|isValidSignatureNow|SigToPub|RecoverPubkey|"
    r"Ecrecover)\s*\(")


def has_recover_node(text: str) -> bool:
    t = text or ""
    return bool(_RECOVER_BARE_RE.search(t) or _RECOVER_METHOD_RE.search(t))


# ---------------------------------------------------------------------------
# (B) the four binding-element NODE predicates. Each classifies whether a
# binding element is BOUND anywhere in the digest-binding CLOSURE text. Pure node
# predicates; the closure/set logic lives in the caller.
# ---------------------------------------------------------------------------
_CHAINID_RE = re.compile(r"(?<![A-Za-z0-9_])(block\s*\.\s*chainid|chainid|chain_id)\b",
                         re.IGNORECASE)
_VERIFYING_RE = re.compile(
    r"address\s*\(\s*this\s*\)|(?<![A-Za-z0-9_])verifyingcontract\b",
    re.IGNORECASE)

# OpenZeppelin EIP712 domain-separator primitives bind chainid AND
# verifyingContract BY CONSTRUCTION: OZ EIP712._buildDomainSeparator feeds
# block.chainid + address(this) into the domain hash, and _hashTypedDataV4 /
# _domainSeparatorV4 / eip712Domain() consume it. Recognizing these is a cited
# construction fact (identical in spirit to the set-diff hunter's module-boundary
# bank-primitive credit), NOT a name-shape: a fn whose digest is computed via an
# OZ EIP712 primitive HAS the chainid+contract binding even though block.chainid
# / address(this) never appear in this workspace's own source (they live in the
# vendored OZ base, which the in-scope filter drops).
_OZ_EIP712_PRIMITIVE_RE = re.compile(
    r"(?<![A-Za-z0-9_])(_domainSeparatorV4|_hashTypedDataV4|_buildDomainSeparator|"
    r"eip712Domain|_EIP712NameHash|_INITIAL_DOMAIN_SEPARATOR)\s*[\(;]",
    re.IGNORECASE)


def _oz_eip712_domain(text: str) -> bool:
    return bool(_OZ_EIP712_PRIMITIVE_RE.search(_strip_strings(text or "")))
_DEADLINE_RE = re.compile(
    r"(?<![A-Za-z0-9_])deadline\b|block\s*\.\s*timestamp\s*[<>]=?|"
    r"expir(?:e|y|ation)|valid(?:until|before)",
    re.IGNORECASE)

# nonce / used-hash slot READ (a guard consulting the replay-tracking slot) and
# WRITE (the state-write that latches it). The consumed-nonce element requires
# BOTH (def/use relation): a slot READ but never WRITTEN is a distinct survivor.
# A replay-tracking slot: a used/nonce/consumed/authorization/... mapping. `\w*`
# tails match _authorizationStates, usedSignatures, isNonceUsed, etc.
_NONCE_SLOT = (r"\w*used\w*|\w*nonce\w*|\w*consumed\w*|\w*executed\w*|"
               r"\w*processed\w*|\w*seen\w*|\w*claimed\w*|\w*spent\w*|"
               r"\w*invalidated\w*|\w*filled\w*|\w*authorization\w*|\w*replay\w*")
# one or more index brackets (a NESTED mapping slot[a][b] is common for per-owner
# nonces / EIP-3009 _authorizationStates[authorizer][nonce]).
_IDX = r"(?:\s*\[[^\]]+\])+"
_SLOT = r"(?<![A-Za-z0-9_])(?:" + _NONCE_SLOT + r")" + _IDX
_NONCE_READ_RE = re.compile(
    _SLOT
    + r"|(?<![A-Za-z0-9_])nonces?\s*\[[^\]]+\]"
    + r"|(?<![A-Za-z0-9_])_usenonce\s*\(",
    re.IGNORECASE)
_NONCE_WRITE_RE = re.compile(
    _SLOT + r"\s*=\s*true"
    + r"|" + _SLOT + r"\s*=\s*[^=]"
    + r"|(?<![A-Za-z0-9_])nonces?\s*\[[^\]]+\]\s*(?:\+\+|\+=|=)"
    + r"|(?<![A-Za-z0-9_])_usenonce\s*\(",
    re.IGNORECASE)


# The EIP712Domain TYPE STRING literal ("EIP712Domain(string name,uint256
# chainId,address verifyingContract)") mentions the WORDS chainId /
# verifyingContract but is the SCHEMA, not the bound VALUE. Binding is asserted by
# the CODE that feeds block.chainid / address(this) into abi.encode, never by the
# type-hash string. So string literals are stripped before binding classification
# (block.chainid / address(this) are code and survive). This is what makes
# "drop address(this) but keep the typehash string" correctly flip to a survivor.
_STRLIT_RE = re.compile(r'"(?:\\.|[^"\\])*"' r"|'(?:\\.|[^'\\])*'"
                        r"|`[^`]*`")


def _strip_strings(text: str) -> str:
    return _STRLIT_RE.sub(" ", text or "")


def binding_chainid(text: str) -> bool:
    return bool(_CHAINID_RE.search(_strip_strings(text)))


def binding_verifying_contract(text: str) -> bool:
    return bool(_VERIFYING_RE.search(_strip_strings(text)))


def binding_deadline(text: str) -> bool:
    return bool(_DEADLINE_RE.search(_strip_strings(text)))


def nonce_read(text: str) -> bool:
    return bool(_NONCE_READ_RE.search(_strip_strings(text)))


def nonce_write(text: str) -> bool:
    return bool(_NONCE_WRITE_RE.search(_strip_strings(text)))


# ---------------------------------------------------------------------------
# source helpers (fn-body window anchored at the ENCLOSING decl).
# ---------------------------------------------------------------------------
_SRC_CACHE: dict = {}
# A REAL function declaration line - the keyword followed by a NAME (or a Go
# receiver then name). Requiring the name avoids matching the WORD 'function' in
# a prose comment ("uses the internal function provided by ..."), which would
# truncate a body window early and drop the digest-builder helper's binding.
_DECL_RE = re.compile(
    r"(?:^|\s)(?:function|func|fn)\s+(?:\([^)]*\)\s*)?[A-Za-z_]\w*\s*(?:\(|<)")
_LINE_COMMENT_RE = re.compile(r"//.*$|/\*.*?\*/|#.*$")


def _code_part(line: str) -> str:
    return _LINE_COMMENT_RE.sub("", line or "")


def _source_lines(path: str) -> list:
    if path in _SRC_CACHE:
        return _SRC_CACHE[path]
    try:
        lines = Path(path).read_text(encoding="utf-8",
                                     errors="replace").splitlines()
    except Exception:
        lines = []
    _SRC_CACHE[path] = lines
    return lines


def _enclosing_decl_line(path: str, hint_line: int) -> int:
    ls = _source_lines(path)
    if not ls or not hint_line:
        return hint_line or 0
    i = min(len(ls), int(hint_line)) - 1
    for k in range(i, max(0, i - 400) - 1, -1):
        if 0 <= k < len(ls) and _DECL_RE.search(_code_part(ls[k])):
            return k + 1
    return hint_line


def _fn_body_window(path: str, hint_line: int, cap: int = 120) -> str:
    """Text of the ENCLOSING fn's decl line + body up to the next decl (bounded
    by `cap`), so a binding read stays inside this one function."""
    decl = _enclosing_decl_line(path, hint_line)
    ls = _source_lines(path)
    if not ls or not decl:
        return ""
    start = int(decl) - 1
    if start >= len(ls):
        return ""
    out = [ls[start]]
    for k in range(start + 1, min(len(ls), start + cap)):
        if _DECL_RE.search(_code_part(ls[k])):
            break
        out.append(ls[k])
    return "\n".join(out)


def _short_fn(fn: str) -> str:
    s = (fn or "").strip()
    if ")." in s:
        s = s.rsplit(").", 1)[-1]
    s = s.split("(")[0].replace("*", "")
    return s.split(".")[-1].strip()


def _contract_of(fn: str) -> str:
    s = (fn or "").strip()
    if ")." in s:
        recv = s.rsplit(").", 1)[0].lstrip("(").lstrip("*")
        return recv.split(".")[-1]
    head = s.split("(")[0]
    parts = head.split(".")
    return parts[0] if len(parts) > 1 else ""


# ---------------------------------------------------------------------------
# per-fn Unit folded from the dataflow backend.
# ---------------------------------------------------------------------------
class Unit:
    __slots__ = ("fn", "file", "line", "lang", "node_texts", "n_records")

    def __init__(self, fn: str):
        self.fn = fn
        self.file = ""
        self.line = 0
        self.lang = ""
        # node exprs seen for this fn in the backend (guard exprs, sink callees,
        # source vars) - used ONLY to seed recovery detection cheaply; the
        # authoritative recovery + binding classification is over the fn body.
        self.node_texts: list[str] = []
        self.n_records = 0


def _iter_fn_anchors(rec: dict):
    """Yield (fn, file, line, lang, extra_text) for each fn anchor in a record."""
    lang = str(rec.get("language") or "")
    for sec in ("source", "sink"):
        d = rec.get(sec) or {}
        fn = d.get("fn")
        if not fn:
            continue
        extra = " ".join(str(d.get(k) or "") for k in ("callee", "var", "kind"))
        yield str(fn), str(d.get("file") or ""), int(d.get("line") or 0), lang, extra
    for g in rec.get("guard_nodes") or []:
        e = g.get("expr")
        # guard nodes are not fn-anchored; attach to no fn (skip) - they inform
        # nothing about recovery. (kept for future closure use)
        _ = e


def _in_scope_file(fpath: str, ws_root: Path, include_oos: bool) -> bool:
    if not fpath:
        return False
    low = fpath.replace("\\", "/").lower()
    if any(m in low for m in _VENDOR_MARKERS):
        return False
    if any(low.endswith(s) for s in _CODEGEN_SUFFIXES):
        return False
    try:
        rel = Path(fpath).resolve().relative_to(ws_root)
    except Exception:
        return False
    if not include_oos and is_oos(str(rel)):
        return False
    return True


def build_units(dataflow_path: Path, ws_root: Path,
                include_oos: bool = False) -> tuple[dict, list]:
    units: dict[str, Unit] = {}
    warnings: list[str] = []
    n_total = n_degraded = 0
    if not dataflow_path.is_file():
        warnings.append(f"dataflow_paths absent: {dataflow_path}")
        return units, warnings
    with dataflow_path.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except Exception:
                continue
            n_total += 1
            if rec.get("degraded"):
                n_degraded += 1
                continue
            for fn, fpath, fline, lang, extra in _iter_fn_anchors(rec):
                if not _in_scope_file(fpath, ws_root, include_oos):
                    continue
                u = units.get(fn)
                if u is None:
                    u = Unit(fn)
                    u.file = fpath
                    u.line = fline
                    u.lang = lang
                    units[fn] = u
                u.n_records += 1
                if not u.file and fpath:
                    u.file = fpath
                # keep the SMALLEST (enclosing-decl-closest) anchor line so the
                # body window starts at the fn decl, not a mid-body sink far down.
                if fline and (not u.line or fline < u.line):
                    u.line = fline
                if extra:
                    u.node_texts.append(extra)
    if n_total and n_degraded == n_total:
        warnings.append(
            f"ALL {n_total} dataflow records are DEGRADED (substrate-starved) - "
            f"RECOVER is vacuously empty because the def-use graph never "
            f"materialized, NOT because every signer-recovery fn is bound.")
    return units, warnings


# ---------------------------------------------------------------------------
# same-file bare-name call map -> resolve digest-builder helpers reached through
# a recover fn's forward call closure (transitive, bounded depth).
# ---------------------------------------------------------------------------
_CALL_ID_RE = re.compile(r"(?<![A-Za-z0-9_.])([A-Za-z_]\w*)\s*\(")


# a Solidity/Go/Rust function declaration with a capturable name. Used to
# AUGMENT the helper index with decls the dataflow backend never recorded (a
# trivial domain-separator getter override that appears in no def-use path but
# IS the concrete implementation of a virtual hook the recover fn calls).
_FN_DECL_NAME_RE = re.compile(
    r"(?:^|\s)(?:function|func|fn)\s+"
    r"(?:\([^)]*\)\s*)?"          # optional Go receiver
    r"([A-Za-z_]\w*)\s*\(")


def _scan_file_decls(fpath: str) -> list:
    """[(bare_name, line)] for every function declaration in a source file."""
    out: list = []
    for i, ln in enumerate(_source_lines(fpath), start=1):
        m = _FN_DECL_NAME_RE.search(_code_part(ln))
        if m:
            out.append((m.group(1), i))
    return out


def _build_name_index(units: dict, augment_source: bool = True) -> dict:
    """{ bare_name : [Unit, ...] } - resolves a helper CALL to its declaring
    Unit(s). Keyed on bare name so an INHERITED helper (a _getDomainSeparator /
    _domainSeparator defined in a base or derived contract in ANOTHER file,
    reached through the recover fn's forward call closure) is resolvable - the
    digest-binding closure is a cross-file/cross-inheritance call relation, not a
    same-file text scan. Augmented with a source-decl scan of every in-scope file
    the backend referenced, so a concrete virtual-hook OVERRIDE that appears in no
    def-use path is still resolvable."""
    idx: dict = {}
    for u in units.values():
        if not u.file:
            continue
        idx.setdefault(_short_fn(u.fn), []).append(u)
    if augment_source:
        seen_files = {u.file for u in units.values() if u.file}
        known = {(u.file, _short_fn(u.fn)) for u in units.values() if u.file}
        for f in seen_files:
            for name, line in _scan_file_decls(f):
                if (f, name) in known:
                    continue
                syn = Unit(f"{name}()")
                syn.file = f
                syn.line = line
                idx.setdefault(name, []).append(syn)
                known.add((f, name))
    return idx


def _is_abstract_decl(u: "Unit") -> bool:
    """A bodyless declaration (an abstract / virtual interface hook, e.g.
    `function _domainSeparator() internal view virtual returns (bytes32);`). Its
    binding lives in the concrete OVERRIDE elsewhere, so it must not be preferred
    over an implementing candidate."""
    body = _fn_body_window(u.file, u.line, cap=6)
    if not body:
        return False
    # the decl line + a few lines: abstract iff there is no '{' opening a body.
    return "{" not in body


def _resolve_helper(name: str, filelow: str, name_idx: dict):
    cands = name_idx.get(name)
    if not cands:
        return None
    # prefer a CONCRETE (bodyful) declaration - a virtual hook resolves to its
    # override, not the abstract stub. Among concrete, prefer same-file then the
    # smallest-line declaration.
    concrete = [c for c in cands if not _is_abstract_decl(c)]
    pool = concrete or cands
    same = [c for c in pool if (c.file or "").replace("\\", "/").lower() == filelow]
    pool = same or pool
    return min(pool, key=lambda c: c.line or 1 << 30)


def digest_binding_closure(u: Unit, name_idx: dict, max_depth: int = 3,
                           cap: int = 120) -> tuple[str, list]:
    """Concatenated text of u's body UNION the bodies of digest-builder helper
    fns reached through u's forward call closure (bounded depth, cross-file). This
    is the DIGEST-BINDING CLOSURE over which PRESENT(F) is computed - a chainid /
    address(this) bound inside a _getDomainSeparator helper N hops away (even in a
    base contract in another file) is correctly attributed to F. Returns
    (closure_text, visited_helper_fns)."""
    seen: set = {u.fn}
    visited: list = []
    texts: list = []

    def _walk(cur: Unit, depth: int):
        if depth > max_depth:
            return
        body = _fn_body_window(cur.file, cur.line, cap=cap)
        if not body:
            return
        texts.append(body)
        curfilelow = (cur.file or "").replace("\\", "/").lower()
        for m in _CALL_ID_RE.finditer(body):
            name = m.group(1)
            nxt = _resolve_helper(name, curfilelow, name_idx)
            if nxt is None or nxt.fn in seen:
                continue
            seen.add(nxt.fn)
            visited.append(nxt.fn)
            _walk(nxt, depth + 1)

    _walk(u, 0)
    return "\n".join(texts), visited


REQUIRED = ("chainid", "verifyingContract", "consumed-nonce")


def classify(units: dict) -> dict:
    name_idx = _build_name_index(units)
    recover: list = []
    results: dict = {}
    for fn, u in units.items():
        own_body = _fn_body_window(u.file, u.line, cap=140)
        # RECOVER membership: F is a signer-recovery fn iff the recovery NODE
        # (ecrecover / ECDSA.recover / isValidSignatureNow / ...) executes in F's
        # OWN body - F is the fn that recovers a signer and authorizes off the
        # result. A mere CALLER of F (a deposit entrypoint that calls _verifyAML)
        # is covered by F's obligation and is NOT re-emitted (else every caller
        # duplicates the survivor). The TRANSITIVE axis lives in the digest-
        # binding CLOSURE below (chainid bound in a _getDomainSeparator helper N
        # hops / files away), not in recovery detection.
        if not has_recover_node(own_body):
            continue
        closure_text, helpers = digest_binding_closure(u, name_idx)
        recover.append(fn)
        # PRESENT(F): over the DIGEST-BINDING CLOSURE (u body + digest-builder
        # helpers). nonce is a def/use relation evaluated over u's OWN body (the
        # slot must be consumed IN the authorizing fn).
        present: set = set()
        # an OZ EIP712 domain-separator primitive in the closure binds BOTH
        # chainid and verifyingContract by construction (the vendored OZ base
        # feeds block.chainid + address(this) into the domain hash).
        oz_domain = _oz_eip712_domain(closure_text)
        if binding_chainid(closure_text) or oz_domain:
            present.add("chainid")
        if binding_verifying_contract(closure_text) or oz_domain:
            present.add("verifyingContract")
        n_read = nonce_read(own_body)
        n_write = nonce_write(own_body)
        if n_write:
            present.add("consumed-nonce")
        has_deadline = binding_deadline(closure_text)
        missing = [e for e in REQUIRED if e not in present]
        # nonce read-but-not-written = unlimited replay (distinct survivor class)
        nonce_readonly = bool(n_read and not n_write)
        results[fn] = {
            "present": sorted(present),
            "missing": missing,
            "deadline": has_deadline,
            "nonce_read": n_read,
            "nonce_write": n_write,
            "nonce_readonly": nonce_readonly,
            "helpers": helpers,
            "is_survivor": bool(missing),
        }
    survivors = sorted(fn for fn, r in results.items() if r["is_survivor"])
    kept = sorted(fn for fn, r in results.items() if not r["is_survivor"])
    return {
        "recover": sorted(recover),
        "results": results,
        "survivors": survivors,
        "kept": kept,
    }


def make_obligation(u: Unit, r: dict, invariant_id: str) -> dict:
    short = _short_fn(u.fn)
    contract = _contract_of(u.fn)
    src_ref = u.file + (f":{u.line}" if u.line else "")
    missing = r["missing"]
    parts = []
    if "chainid" in missing:
        parts.append("chainid (cross-chain replay)")
    if "verifyingContract" in missing:
        parts.append("verifyingContract/address(this) (cross-contract replay)")
    if "consumed-nonce" in missing:
        if r.get("nonce_readonly"):
            parts.append("consumed-nonce: the replay slot is READ but never "
                         "WRITTEN (unlimited replay)")
        else:
            parts.append("consumed-nonce (unlimited replay)")
    root = (
        f"Signer-recovery fn '{u.fn}' authorizes a state change against a digest "
        f"whose binding closure is MISSING {{{', '.join(missing)}}}. The signed "
        f"preimage does not bind these elements, so the signature bytes are "
        f"replayable: " + "; ".join(parts) + "."
    )
    return {
        "schema": "auditooor.signature_replay_digest_binding.v1",
        "obligation_type": "signature-replay-digest-binding",
        "contract": contract,
        "function": short,
        "function_signature": u.fn,
        "language": u.lang,
        "source_refs": [src_ref] if src_ref else [],
        "file": u.file,
        "line": u.line,
        "missing_binding_elements": missing,
        "present_binding_elements": r["present"],
        "nonce_read_not_written": bool(r.get("nonce_readonly")),
        "deadline_present": bool(r.get("deadline")),
        "digest_helper_closure": r.get("helpers") or [],
        "attack_class": "signature-permit-replay-missing-digest-binding",
        "likely_severity": "high",
        "broken_invariant_ids": [invariant_id],
        "root_cause_hypothesis": root,
        "quality_gate_status": "needs_source",
        "proof_status": "needs_source",
        "advisory_only": True,
        "learning_route": "mine-source",
        "falsification_requirements": [
            "DIGEST_CLOSURE: prove the missing element is genuinely absent from "
            "the FULL digest preimage closure (a domain separator reached through "
            "a helper that DOES bind chainid/address(this) KILLS that arm).",
            "REPLAY_TARGET: identify the concrete replay surface - a sibling "
            "contract sharing the signer (verifyingContract absent), another "
            "chain (chainid absent), or a second submission of the same sig "
            "(nonce not consumed).",
            "STATE_EFFECT: confirm the recovered signer authorizes a value / "
            "authority state change (not a view), so a replay has impact.",
        ],
        "next_command": (
            "read the fn + its _getDomainSeparator/_hashTypedData helper closure; "
            "if the missing element is truly unbound, author the cross-chain / "
            "cross-contract / double-submit replay PoC."
        ),
    }


def run(argv=None):
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--workspace", required=True)
    ap.add_argument("--dataflow", default=None,
                    help="override dataflow_paths.jsonl path")
    ap.add_argument("--alt-dataflow", default=None,
                    help="additional dataflow jsonl to UNION")
    ap.add_argument("--include-oos", action="store_true")
    ap.add_argument("--invariant-id",
                    default="INV-SIGNATURE-DIGEST-BINDS-CHAINID-CONTRACT-NONCE")
    ap.add_argument("--emit", default=None)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--fail-closed", action="store_true",
                    help="exit non-zero if the dataflow substrate is fully "
                         "degraded (RECOVER could not be computed)")
    args = ap.parse_args(argv)

    ws = Path(args.workspace).expanduser().resolve()
    df = Path(args.dataflow).expanduser() if args.dataflow else \
        ws / ".auditooor" / "dataflow_paths.jsonl"
    units, warnings = build_units(df, ws, include_oos=args.include_oos)

    alt_paths: list = []
    if args.alt_dataflow:
        alt_paths.append(Path(args.alt_dataflow).expanduser())
    if not args.dataflow:
        for sib in sorted((ws / ".auditooor").glob("dataflow_paths.*.jsonl")):
            if sib.resolve() != df.resolve():
                alt_paths.append(sib)
    for alt in alt_paths:
        au, aw = build_units(alt, ws, include_oos=args.include_oos)
        warnings.extend(aw)
        for fn, u2 in au.items():
            u = units.get(fn)
            if u is None:
                units[fn] = u2
                continue
            u.n_records += u2.n_records
            u.node_texts.extend(u2.node_texts)
            if u2.line and (not u.line or u2.line < u.line):
                u.line = u2.line
            if not u.file:
                u.file = u2.file

    res = classify(units)

    obligations = []
    seen = set()
    for fn in res["survivors"]:
        u = units[fn]
        dk = (u.file, u.line, _short_fn(fn))
        if dk in seen:
            continue
        seen.add(dk)
        obligations.append(make_obligation(u, res["results"][fn], args.invariant_id))

    emit = Path(args.emit).expanduser() if args.emit else \
        ws / ".auditooor" / "signature_replay_digest_binding_obligations.jsonl"
    emit.parent.mkdir(parents=True, exist_ok=True)
    with emit.open("w", encoding="utf-8") as fh:
        for ob in obligations:
            fh.write(json.dumps(ob) + "\n")
        # Capability-vacuity-telltale: the digest-binding set-difference RAN over a
        # real recover surface (>=1 ecrecover/permit site) and every site was fully
        # bound (0 survivors). PERSIST an explicit cited-empty examined-record so the
        # reasoner-firing gate scores this FIRED_CLEAN (ran, examined, recorded 0)
        # instead of reading the empty ledger as VACUOUS.
        if not obligations and len(res["recover"]) > 0:
            fh.write(json.dumps({
                "schema": "auditooor.signature_replay_digest_binding.examined_record.v1",
                "note": ("cited-empty: digest-binding screen ran over the recover "
                         "surface, every signature site fully domain-bound, 0 survivors"),
                "survivors": [],
                "report": {
                    "reasoner": "signature-permit-replay-digest-binding",
                    "totals": {"examined": len(res["recover"]),
                               "kept_fully_bound": len(res["kept"])},
                },
            }) + "\n")

    substrate_degraded = any("DEGRADED" in w for w in warnings) and not units

    summary = {
        "schema": "auditooor.signature_replay_digest_binding.summary.v1",
        "workspace": str(ws),
        "dataflow": str(df),
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "n_units": len(units),
        "size_RECOVER": len(res["recover"]),
        "required_binding": list(REQUIRED),
        "size_KEPT_fully_bound": len(res["kept"]),
        "size_survivors": len(res["survivors"]),
        "kept_fully_bound": [_short_fn(f) for f in res["kept"]],
        "survivors": [
            {"fn": _short_fn(f), "signature": f,
             "file": units[f].file, "line": units[f].line,
             "missing": res["results"][f]["missing"],
             "present": res["results"][f]["present"],
             "nonce_read_not_written": res["results"][f]["nonce_readonly"],
             "digest_helpers": res["results"][f]["helpers"]}
            for f in res["survivors"]
        ],
        "obligations_written": len(obligations),
        "obligations_path": str(emit),
        "warnings": warnings,
        "substrate_degraded": substrate_degraded,
    }

    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print(f"[sig-replay-digest-binding] {ws.name}: "
              f"|RECOVER|={summary['size_RECOVER']} "
              f"KEPT(fully-bound)={summary['size_KEPT_fully_bound']} "
              f"survivors(missing binding)={summary['size_survivors']} "
              f"-> {len(obligations)} signature-replay obligation(s)")
        if res["kept"]:
            print("  KEPT (recovers a signer + digest binds all of "
                  "{chainid, verifyingContract, consumed-nonce}): "
                  + ", ".join(summary["kept_fully_bound"]))
        for s in summary["survivors"][:40]:
            tag = " [nonce READ-not-WRITTEN]" if s["nonce_read_not_written"] else ""
            print(f"  SURVIVOR {s['fn']}  MISSING={s['missing']}{tag}  "
                  f"{s['file']}:{s['line']}")
        for w in warnings:
            print(f"  WARN {w}", file=sys.stderr)
        print(f"  -> {emit}")

    if args.fail_closed and substrate_degraded:
        return 3
    return summary


if __name__ == "__main__":
    out = run()
    if out == 3:
        sys.exit(3)
