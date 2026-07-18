#!/usr/bin/env python3
"""inclusion-proof-positional-soundness.py  (E12) - inclusion-proof POSITION /
node-type soundness screen.

WHAT THIS TOOL DOES  (GENERAL enforcement / invariant screen - NOT a bug shape)
===============================================================================
A non-ZK inclusion proof (bridge / light-client Merkle or MPT membership proof)
carries a DELEGATED-AND-TRUSTED safety property:

    "recomputed_root == stored_root  =>  this leaf is a member of the tree AT
     THE CLAIMED POSITION, encoded as the CLAIMED node type."

That is a compound private invariant. The recompute has to UNIQUELY BIND three
things into the root it produces:

    (1) the leaf position / index (block, txindex, leaf-index), and
    (2) the leaf-vs-internal-node DOMAIN (a leaf preimage must not be
        re-interpretable as an internal node, and vice-versa - the classic MPT
        node-type / second-preimage ambiguity), so that
    (3) a single valid proof cannot REPLAY at a forged position or a different
        node type.

E12 is the north-star method (w8mv5mpcw) applied to that invariant: enumerate
every trusted inclusion-proof root-recompute site -> state its private binding
invariant -> attack the invariant (a proof accepted for one (position,node-type)
is accepted for another). It is a REUSABLE invariant screen over ANY positional
Merkle / MPT verifier, in any language - never keyed to one protocol's shape.

TWO POSITIONAL-SOUNDNESS AXES (each an advisory needs-fuzz row when unbound):

  - unbound-index        : the recompute forms root(leaf, siblings...) but the
                           per-level pair ORDERING is not selected by a position
                           bit (index >> h & 1 / index % 2 / a direction flag /
                           swapped hash-arg branches). Order-free combine over a
                           POSITIONAL proof lets the same siblings validate at a
                           forged index.
  - node-type-ambiguity  : the proof length / tree depth is UNBOUNDED and there
                           is no leaf-vs-node domain tag (0x00/0x01 prefix,
                           distinct hashLeaf/hashNode, or a fixed-depth tree), so
                           an internal 64-byte node preimage can be replayed as a
                           leaf (or a short proof truncated) - node-type collision.

DEDUP (disjoint axes; reuse, do not re-derive):
  - E3  (digest domain-binding) binds message DOMAIN / chainid into a signature
        digest - identity fields, NOT proof membership+position. E12 excludes
        identity/domain fields; it owns the index+node-type axes.
  - E10 (proof-leaf-to-message-TYPE) binds a leaf to ONE message class
        (deposit vs exit) via a leafType discriminator. E12 is orthogonal:
        internal-NODE-type ambiguity + unbound POSITION, not the message class.
  - E4  is ZK-gate EXISTENCE only. E12 is the non-ZK recompute.
  - Commutative / sorted-pair set-membership proofs (OZ MerkleProof, a<b?h(a,b))
        are ORDER-INDEPENDENT BY DESIGN (set membership, not positional) and are
        EXCLUDED - positional soundness does not apply to them (FP guard).

ADVISORY-FIRST (mandatory): every row carries verdict="needs-fuzz". This tool
NEVER credits a unit, NEVER flips a gate, NEVER fails closed. Off-by-default:
with no --emit / no AUDITOOOR_E12_EMIT it reports status only and writes nothing.
Hang emitted rows on the completeness-matrix inclusion/proof axis downstream.

Usage:
  python3 tools/inclusion-proof-positional-soundness.py --workspace <ws> [--emit] [--json]
  python3 tools/inclusion-proof-positional-soundness.py --file <path.sol> [--json]
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import sys

# ---------------------------------------------------------------------------
# Source enumeration
# ---------------------------------------------------------------------------
SRC_EXTS = (".sol", ".rs", ".go", ".vy")

# Skip vendored / test / mock trees - they are not the trusted enforcement.
_SKIP_DIR = re.compile(
    r"(^|/)(test|tests|mock|mocks|node_modules|forge-std|lib/openzeppelin|"
    r"target|out|artifacts|cache|\.git)(/|$)", re.IGNORECASE)

# A function header across brace languages: solidity `function f(`, rust `fn f(`,
# go `func f(` / `func (r R) f(`.
_FN_HEADER = re.compile(
    r"(?:^|\n)\s*(?:function|fn|func)\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)\s*"
    r"(?:<[^>]*>)?\s*\(", re.MULTILINE)

# Hash-combine primitives (a leaf/node folded with a sibling).
_HASH_CALL = re.compile(
    r"\b(keccak256|sha256|sha3|efficientKeccak256|commutativeKeccak256|"
    r"blake2|blake3|hash_pair|hashPair|_hashPair|poseidon|Hashes\.\w+)\s*\(",
    re.IGNORECASE)

# A proof / sibling / branch array term (the ordered path of siblings).
_PROOF_TERM = re.compile(
    r"\b(smtproof|proof|siblings?|branch|_branch|merklepath|merkle_path|"
    r"path|witness|coproof|authpath|auth_path)\b", re.IGNORECASE)

# The recompute compares to / returns a trusted root.
_ROOT_TERM = re.compile(r"\broot\b", re.IGNORECASE)

# Loop presence.
_LOOP = re.compile(r"\b(for|while|loop)\b")

# ---- positional-binding signals -------------------------------------------
# A position bit consumed to select ordering: index >> h & 1, index & 1,
# index % 2, i>>height, or a direction/side flag.
_INDEX_BIT = re.compile(
    r"\b(index|idx|_index|leafindex|leaf_index|position|pos|txindex|tx_index|"
    r"i|h|height|bitmap|path)\w*\b[^;\n{}]{0,48}?(>>|>>=|&\s*1\b|%\s*2\b)"
    r"|(>>|&\s*1\b|%\s*2\b)[^;\n{}]{0,48}?\b(index|idx|position|pos|txindex)\w*",
    re.IGNORECASE)
_DIRECTION_FLAG = re.compile(
    r"\b(isleft|is_left|isright|is_right|proofflags?|proof_flags?|leftright|"
    r"direction|side|goesleft|turn|bit)\b", re.IGNORECASE)

# ---- domain / node-type separation signals --------------------------------
# A leaf-vs-node domain tag byte, or distinct leaf/node hashers.
# NOTE: deliberately NOT a bare \bLEAF\b/\bNODE\b - the accumulator variable is
# ubiquitously named `node`, which would spuriously satisfy domain-separation.
_DOMAIN_TAG = re.compile(
    r"(0x00\b|0x01\b|hex\"0[01]\"|LEAF_PREFIX|NODE_PREFIX|LEAF_DOMAIN|"
    r"NODE_DOMAIN|hashleaf|hash_leaf|hashnode|hash_node|leaf_tag|node_tag|"
    r"leaf_domain|node_domain|domain_sep|leafPrefix|nodePrefix)", re.IGNORECASE)
# A compile-time-fixed tree depth binds the node type positionally: a constant /
# UPPER_SNAKE / numeric loop bound, or a fixed-size sol array `[NAME]`/`[12]`.
_FIXED_DEPTH = re.compile(
    r"<\s*(\d+|[_A-Z][_A-Z0-9]{2,})\b"          # for h < 12 / < TREE_DEPTH
    r"|\[\s*(\d+|[_A-Z][_A-Z0-9]{2,})\s*\]",     # bytes32[TREE_DEPTH]
    )
# A proof-length / depth bound folded into the check (guards truncation).
_LEN_BOUND = re.compile(
    r"\.length\s*(==|<=|>=|!=)|require\([^)]*length|assert[^;]*length|"
    r"\bdepth\b", re.IGNORECASE)

# Commutative / sorted-pair combine == SET membership (order-free BY DESIGN):
# EXCLUDE from positional soundness (FP guard).
_COMMUTATIVE = re.compile(
    r"commutativeKeccak256|_hashPair|hashPair|"
    r"([A-Za-z_]\w*)\s*<\s*([A-Za-z_]\w*)\s*\?"      # a < b ? h(a,b) : h(b,a)
    r"|sort\(|_efficientSortedHash|sortPair", re.IGNORECASE)


def _iter_sources(root: pathlib.Path):
    for p in root.rglob("*"):
        if not p.is_file() or p.suffix not in SRC_EXTS:
            continue
        rel = str(p.relative_to(root)) if root in p.parents or root == p.parent \
            else str(p)
        if _SKIP_DIR.search("/" + rel):
            continue
        yield p


def _extract_functions(src: str):
    """Yield (name, body, start_line) for each brace-delimited function."""
    out = []
    for m in _FN_HEADER.finditer(src):
        name = m.group(1)
        # find the first '{' after the header parens
        brace = src.find("{", m.end())
        if brace == -1:
            continue
        depth = 0
        i = brace
        n = len(src)
        while i < n:
            c = src[i]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        body = src[brace:i + 1]
        start_line = src.count("\n", 0, m.start()) + 1
        out.append((name, body, start_line))
    return out


def _hash_call_arglists(body: str):
    """Yield the (unwrapped) argument string of every hash-combine call - the
    inner abi.encodePacked(...) is peeled so the folded operands are visible."""
    for hm in _HASH_CALL.finditer(body):
        j = body.find("(", hm.start())
        if j == -1:
            continue
        depth, k = 0, j
        while k < len(body):
            if body[k] == "(":
                depth += 1
            elif body[k] == ")":
                depth -= 1
                if depth == 0:
                    break
            k += 1
        args = body[j + 1:k]
        ep = re.search(r"(?:abi\.)?encode\w*\(", args)
        if ep:
            inner_j = args.find("(", ep.start())
            d2, kk = 0, inner_j
            while kk < len(args):
                if args[kk] == "(":
                    d2 += 1
                elif args[kk] == ")":
                    d2 -= 1
                    if d2 == 0:
                        break
                kk += 1
            args = args[inner_j + 1:kk]
        yield args


# A proof/sibling element consumed inside a hash-combine: indexed (proof[h],
# smtProof[height], siblings[i]) or accessed (proof.get(i) / proof.at(i)).
_PROOF_INDEXED = re.compile(
    r"\b(smtproof|proof|siblings?|branch|_branch|merklepath|merkle_path|path|"
    r"witness|authpath|auth_path|coproof)\w*\s*(\[|\.get\(|\.at\(|\.index\()",
    re.IGNORECASE)
# A range-loop over a proof term binding a per-sibling loop variable.
_RANGE_OVER_PROOF = re.compile(
    r"\bfor\b[^\n{;]*?\b([A-Za-z_]\w*)\b[^\n{;]*?\bin\b[^\n{;]*?"
    r"\b(smtproof|proof|siblings?|branch|_branch|merklepath|merkle_path|path|"
    r"witness|authpath|auth_path|coproof)\w*", re.IGNORECASE)


def _folds_proof_through_hash(body: str) -> bool:
    """The defining Merkle/MPT recompute shape: a sibling drawn from the proof
    array is an OPERAND of a hash-combine call. Two fold forms:
      (A) indexed  - hash(.., proof[h], ..)          (Solidity / Go index loop)
      (B) iterator - for sib in proof { hash(.., sib, ..) }   (Rust / Go range)
    Requiring the proof element INSIDE the hash args is what rejects generic
    loop+keccak+"root" functions (e.g. batch sequencing) that merely mention a
    proof in a comment."""
    for args in _hash_call_arglists(body):
        if _PROOF_INDEXED.search(args):
            return True
    # iterator form: a proof-bound loop var folded through a hash
    for rm in _RANGE_OVER_PROOF.finditer(body):
        loopvar = rm.group(1)
        if loopvar.lower() in ("in", "let", "mut", "ref", "for"):
            continue
        pat = re.compile(r"\b" + re.escape(loopvar) + r"\b")
        for args in _hash_call_arglists(body):
            if pat.search(args):
                return True
    return False


def _accumulator_swapped(body: str) -> bool:
    """True if some variable appears BOTH as the leading and the trailing
    argument across the hash-combine calls in `body` (the two ordered branches
    of a positional Merkle fold). Position-independent proofs never swap."""
    lead, trail = set(), set()
    for args in _hash_call_arglists(body):
        parts = _split_top_commas(args)
        if len(parts) < 2:
            continue
        first = re.sub(r"\W", "", re.sub(r"\[[^\]]*\]", "", parts[0]).strip())
        last = re.sub(r"\W", "", re.sub(r"\[[^\]]*\]", "", parts[-1]).strip())
        if first:
            lead.add(first)
        if last:
            trail.add(last)
    return bool(lead & trail)


def _split_top_commas(s: str):
    parts, depth, cur = [], 0, []
    for c in s:
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        if c == "," and depth == 0:
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(c)
    parts.append("".join(cur))
    return [p.strip() for p in parts if p.strip()]


def is_inclusion_verifier(body: str) -> bool:
    """A positional inclusion-proof root RECOMPUTE site: a loop that folds a
    proof/sibling array THROUGH a hash into a root-shaped value. The proof
    element must be an actual OPERAND of the hash (rejects generic
    loop+keccak+"root" fns that only mention a proof in prose)."""
    if not _LOOP.search(body):
        return False
    if not _HASH_CALL.search(body):
        return False
    if not _ROOT_TERM.search(body):
        return False
    if not _folds_proof_through_hash(body):
        return False
    return True


def is_commutative_set_proof(body: str) -> bool:
    """Sorted / commutative pair == unordered SET membership, order-free by
    design -> positional soundness is N/A (FP guard)."""
    return bool(_COMMUTATIVE.search(body))


def check_position_binding(body: str) -> bool:
    """P_pos: the per-level pair ordering is selected by a position bit / a
    direction flag / swapped hash-arg branches."""
    if _INDEX_BIT.search(body):
        return True
    if _DIRECTION_FLAG.search(body):
        return True
    if _accumulator_swapped(body):
        return True
    return False


def check_domain_separation(body: str) -> bool:
    """P_dom: leaf-vs-node domain is bound - explicit domain tag, distinct
    leaf/node hashers, a FIXED tree depth, or a proof-length/depth bound."""
    if _DOMAIN_TAG.search(body):
        return True
    if _FIXED_DEPTH.search(body):
        return True
    if _LEN_BOUND.search(body):
        return True
    return False


_INV = ("recomputed_root==stored_root must uniquely bind (leaf position, "
        "leaf-vs-node encoding) to the root")


def screen_source(src: str, path: str):
    """Return advisory needs-fuzz rows for every unbound positional axis."""
    rows = []
    for name, body, line in _extract_functions(src):
        if not is_inclusion_verifier(body):
            continue
        if is_commutative_set_proof(body):
            continue  # order-free set membership - positional soundness N/A
        pos = check_position_binding(body)
        dom = check_domain_separation(body)
        base = {
            "capability": "E12",
            "tool": "inclusion-proof-positional-soundness",
            "file": path,
            "function": name,
            "line": line,
            "invariant": _INV,
            "delegated_trust": (
                "verifier trusts root-equality => membership at the CLAIMED "
                "position and node-type"),
            "verdict": "needs-fuzz",
            "evidence": {
                "position_bound": pos,
                "domain_bound": dom,
            },
            "dedup": {
                "E3": "domain/chainid identity fields - disjoint axis",
                "E10": "leaf message-TYPE discriminator - disjoint axis",
                "E4": "ZK-gate existence only",
            },
        }
        if not pos:
            r = dict(base)
            r["axis"] = "unbound-index"
            r["private_invariant"] = (
                "the leaf position/index must select the hash-pair ORDER at "
                "every level")
            r["attack"] = (
                "the same sibling set re-forms the root at a FORGED index -> a "
                "proof for leaf L at position i validates at position j; a "
                "membership proof is replayed to a spoofed txindex/leaf slot")
            rows.append(r)
        if not dom:
            r = dict(base)
            r["axis"] = "node-type-ambiguity"
            r["private_invariant"] = (
                "an internal-node preimage must not be re-interpretable as a "
                "leaf (unbounded depth + no leaf/node domain tag)")
            r["attack"] = (
                "a 64-byte internal-node value is presented as a leaf (or a "
                "short/long proof truncates depth) -> second-preimage / "
                "node-type collision accepts a non-member")
            rows.append(r)
    return rows


def run_workspace(ws_root: pathlib.Path):
    rows, scanned, verifiers = [], 0, 0
    for p in _iter_sources(ws_root):
        try:
            src = p.read_text(errors="ignore")
        except Exception:
            continue
        scanned += 1
        fns = _extract_functions(src)
        for _n, body, _l in fns:
            if is_inclusion_verifier(body) and not is_commutative_set_proof(body):
                verifiers += 1
        rel = str(p.relative_to(ws_root))
        rows.extend(screen_source(src, rel))
    return rows, scanned, verifiers


def main(argv=None):
    ap = argparse.ArgumentParser(description="E12 inclusion-proof positional soundness screen")
    ap.add_argument("--workspace", help="workspace name under AUDITS_ROOT")
    ap.add_argument("--file", help="single source file to screen")
    ap.add_argument("--audits-root", default=os.environ.get(
        "AUDITOOOR_AUDITS_ROOT", "/Users/wolf/audits"))
    ap.add_argument("--emit", action="store_true",
                    help="write hypotheses (default off; also AUDITOOOR_E12_EMIT=1)")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    emit = args.emit or os.environ.get("AUDITOOOR_E12_EMIT") == "1"

    if args.file:
        p = pathlib.Path(args.file)
        rows = screen_source(p.read_text(errors="ignore"), str(p))
        scanned, verifiers = 1, sum(
            1 for _n, b, _l in _extract_functions(p.read_text(errors="ignore"))
            if is_inclusion_verifier(b) and not is_commutative_set_proof(b))
        ws_root = None
    elif args.workspace:
        ws_root = pathlib.Path(args.audits_root) / args.workspace
        if not ws_root.is_dir():
            print(json.dumps({"status": "no-workspace", "workspace": args.workspace,
                              "rows": 0}))
            return 0
        rows, scanned, verifiers = run_workspace(ws_root)
    else:
        ap.error("one of --workspace / --file is required")
        return 2

    status = "emitted" if emit else "off-by-default"
    summary = {
        "capability": "E12",
        "status": status,
        "files_scanned": scanned,
        "positional_verifiers": verifiers,
        "advisory_rows": len(rows),
        "verdict": "needs-fuzz" if rows else "clean-or-na",
        "auto_credit": False,
        "fail_closed": False,
    }

    if emit and ws_root is not None:
        outdir = ws_root / ".auditooor"
        outdir.mkdir(exist_ok=True)
        with (outdir / "e12_inclusion_position_hypotheses.jsonl").open("w") as fh:
            for r in rows:
                fh.write(json.dumps(r) + "\n")
        (outdir / "e12_inclusion_position_accounting.json").write_text(
            json.dumps(summary, indent=2))

    if args.json:
        print(json.dumps({"summary": summary, "rows": rows}, indent=2))
    else:
        print(json.dumps(summary))
        if not emit and rows:
            print(f"# (off-by-default: {len(rows)} advisory rows suppressed; "
                  f"--emit to write)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
