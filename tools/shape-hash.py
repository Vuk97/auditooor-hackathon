#!/usr/bin/env python3
"""shape-hash — canonical adversarial-equivalence hash for function records.

Per BIG_PLAN_2026-05-11 sub-report 06 §"Shape-hash canonicalization": two
function signatures collapse to the same ``shape_hash`` iff they share the
same adversarially-equivalent attack surface. The hash is consumed by
``tools/ranker.py`` (Scorer S1 — shape-similarity nearest-neighbor) and the
new ``vault_function_signature_shape`` MCP callable.

Canonicalization (6 steps):

1. NORMALIZE TYPES via per-language alias map
   Go:        ``sdk.AccAddress`` / ``AccAddress`` → ``@address``
              ``context.Context`` / ``sdk.Context`` → ``@ctx``
              ``*types.MsgX`` / ``types.MsgX`` → ``@msg<X>`` (or just ``@msg`` for fine)
   Solidity:  ``address`` / ``address payable`` → ``@address``
   Rust:      ``T::AccountId`` / ``AccountId`` → ``@address``

2. PARAM-TYPE SEQUENCE (positional, comma-joined)

3. RETURN-TYPE SEQUENCE (comma-joined)

4. VISIBILITY/MODIFIER FLAGS bit-vector:
   ``{exported, has_authority_guard, has_pause_guard, has_reentrancy_guard,
      has_blocked_addr_guard, mutates_state}``

5. RECEIVER-TYPE FAMILY (coarse cluster):
   msgServer / Keeper / GovKeeper → ``msg-server-family``
   IBCModule → ``ibc-module``
   Hook / IPostHook → ``hook-family``
   Vault / Pool / Pair → ``amm-pool-family``
   ERC20 / ERC4626 / Bank → ``token-family``
   else → ``misc-family``

6. CONCATENATE + SHA-256 → first 16 hex chars

The function emits BOTH:
  * ``shape_hash``       — coarse (Msg payload type collapses to ``@msg``)
  * ``shape_hash_fine``  — preserves the exact ``@msg<X>`` payload-name

CLI usage:
    python3 tools/shape-hash.py --function-jsonl <path> [--out <path>]
    python3 tools/shape-hash.py --update-tags audit/corpus_tags/tags

If ``--out`` is omitted, prints to stdout. ``--update-tags`` re-walks each
verdict-tag YAML and adds shape_hash/shape_hash_fine to each ``sites[]``
entry that has a function_signature field (requires that the verdict-tag
extractor had earlier joined sites against a sig-extract).

This file is stdlib-only.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


# --------------------------------------------------------------------------- #
# Type-alias maps (per-language)                                              #
# --------------------------------------------------------------------------- #

GO_ADDRESS_TYPES = {
    "sdk.AccAddress", "AccAddress",
    "sdk.ValAddress", "ValAddress",
    "sdk.ConsAddress", "ConsAddress",
    "common.Address", "ethcommon.Address",
}
GO_CTX_TYPES = {
    "context.Context", "sdk.Context", "Context",
}

SOL_ADDRESS_TYPES = {
    "address", "addresspayable", "address_payable", "payableaddress",
}

RUST_ADDRESS_TYPES = {
    "T::AccountId", "AccountId", "Address", "Addr", "AccountId32",
    "Pubkey", "Principal",
}


# --------------------------------------------------------------------------- #
# Receiver-family classifier                                                  #
# --------------------------------------------------------------------------- #

# Note: matched against the receiver_type string after stripping pointer
# decoration and packages. Case-sensitive substring match on the bare type.
RECEIVER_FAMILY_RULES: List[Tuple[str, List[str]]] = [
    ("msg-server-family", ["msgServer", "MsgServer", "Keeper", "GovKeeper"]),
    ("ibc-module", ["IBCModule", "IBCMiddleware"]),
    ("hook-family", ["Hook", "IPostHook", "Hooks"]),
    ("amm-pool-family", ["Vault", "Pool", "Pair", "AMM"]),
    ("token-family", ["ERC20", "ERC4626", "Bank", "Token"]),
]


def receiver_family(receiver_type: Optional[str]) -> str:
    """Return the coarse receiver-family cluster name."""
    if not receiver_type:
        return "free-function"
    bare = receiver_type.lstrip("*").strip()
    # strip a `pkg.` prefix
    if "." in bare:
        bare = bare.split(".")[-1]
    for family, needles in RECEIVER_FAMILY_RULES:
        for needle in needles:
            if needle in bare:
                return family
    return "misc-family"


# --------------------------------------------------------------------------- #
# Type normalization                                                          #
# --------------------------------------------------------------------------- #

_RX_MSG_GO = re.compile(r"^\*?(?:types\.)?Msg([A-Za-z0-9_]+)$")
_RX_PTR = re.compile(r"^\*+")


def _strip_ptr(t: str) -> str:
    return _RX_PTR.sub("", t).strip()


def normalize_type(raw: str, language: str, fine: bool = False) -> str:
    """Normalize a single type token.

    ``fine`` preserves Msg-payload naming (``@msg<X>``); ``fine=False``
    collapses to ``@msg``.
    """
    t = (raw or "").strip()
    if not t:
        return ""
    # Drop leading/trailing whitespace and unify spaces inside.
    t = re.sub(r"\s+", " ", t)

    lang = (language or "unknown").lower()

    if lang == "go":
        bare = _strip_ptr(t)
        if bare in GO_ADDRESS_TYPES:
            return "@address"
        if bare in GO_CTX_TYPES:
            return "@ctx"
        m = _RX_MSG_GO.match(t)
        if m:
            return f"@msg<{m.group(1)}>" if fine else "@msg"
        # generic "*types.X" stripped
        if bare.startswith("types."):
            return f"@type<{bare[len('types.'):]}>" if fine else "@type"
        return bare
    if lang == "solidity":
        compact = re.sub(r"\s+", "", t).lower()
        if compact in SOL_ADDRESS_TYPES:
            return "@address"
        return compact
    if lang == "rust":
        bare = _strip_ptr(t)
        # Rust references are syntactic surface (`&` / `&mut`) and should not
        # split function-shape neighborhoods on their own.
        bare = re.sub(r"^&\s*(?:mut\s+)?", "", bare).strip()
        bare = re.sub(r"^mut\s+", "", bare).strip()
        if bare in RUST_ADDRESS_TYPES:
            return "@address"
        # `Vec<T>` style stays
        return bare
    return t


def normalize_param_sequence(
    params: List[Dict[str, str]], language: str, fine: bool = False
) -> List[str]:
    return [normalize_type(p.get("type", ""), language, fine=fine) for p in params or []]


def normalize_return_sequence(
    returns: List[str], language: str, fine: bool = False
) -> List[str]:
    return [normalize_type(r, language, fine=fine) for r in returns or []]


# --------------------------------------------------------------------------- #
# Guard-flag bit-vector                                                       #
# --------------------------------------------------------------------------- #

GUARD_FLAG_KEYS = [
    "exported",
    "has_authority_guard",
    "has_pause_guard",
    "has_reentrancy_guard",
    "has_blocked_addr_guard",
    "mutates_state",
]

# Map raw extractor-emitted labels → canonical guard-flag keys.
RAW_GUARD_TO_FLAG = {
    "authority-check": "has_authority_guard",
    "authority-mismatch-revert": "has_authority_guard",
    "only-owner": "has_authority_guard",
    "require-auth": "has_authority_guard",
    "blocked-addr-check": "has_blocked_addr_guard",
    "reentrancy-guard": "has_reentrancy_guard",
    "pause-check": "has_pause_guard",
    "write-store": "mutates_state",
    "delete-store": "mutates_state",
}


def compute_flag_vector(
    visibility: Optional[str], guards_detected: Optional[List[str]]
) -> Dict[str, int]:
    flags = {k: 0 for k in GUARD_FLAG_KEYS}
    if visibility in ("exported", "public", "pub", "external"):
        flags["exported"] = 1
    for g in guards_detected or []:
        flag_key = RAW_GUARD_TO_FLAG.get(g)
        if flag_key:
            flags[flag_key] = 1
    return flags


def flag_vector_to_string(flags: Dict[str, int]) -> str:
    return "".join(str(flags.get(k, 0)) for k in GUARD_FLAG_KEYS)


# --------------------------------------------------------------------------- #
# Top-level shape-hash                                                        #
# --------------------------------------------------------------------------- #

def _hash16(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()[:16]


def _solidity_fine_features_canonical(features: Dict[str, Any]) -> str:
    """Canonicalize the Wave-11 Solidity ``shape_features`` dict into a stable
    string suitable for hashing. Key ordering is fixed; missing keys are
    treated as zero/empty so older records hash deterministically.

    NOTE: this is a wire format — changing the key list / order / formatting
    invalidates every previously-computed shape_hash_fine for Solidity.
    """
    if not isinstance(features, dict):
        features = {}
    mods = features.get("modifiers_sorted") or []
    if not isinstance(mods, list):
        mods = []
    parts = [
        f"vis={features.get('visibility') or 'unknown'}",
        f"mut={features.get('state_mutability') or 'unknown'}",
        f"pc={int(features.get('param_count') or 0)}",
        f"rc={int(features.get('return_count') or 0)}",
        f"mods={','.join(sorted(str(m) for m in mods))}",
        f"auth={int(features.get('has_authority_modifier') or 0)}",
        f"reen={int(features.get('has_reentrancy_modifier') or 0)}",
        f"sw={int(features.get('storage_write_count') or 0)}",
        f"xc={int(features.get('external_call_count') or 0)}",
        f"req={int(features.get('has_require_or_revert') or 0)}",
        f"asm={int(features.get('has_assembly_block') or 0)}",
    ]
    return ";".join(parts)


_BODY_FEATURE_ORDER = (
    "line_bucket",
    "call_bucket",
    "map_op_count",
    "slice_op_count",
    "has_append",
    "has_len",
    "has_range",
    "has_goroutine",
    "has_defer",
    "returns_error",
    "return_count",
)


def _body_features_canonical(body_features: Optional[Dict[str, Any]]) -> str:
    """Render body_features into a stable canonical key-eq-val list.

    Wave-14: used ONLY by shape_hash_fine (fine=True) for Go records. The
    coarse shape_hash is unchanged so legacy sites[].shape_hash entries
    still match. Empty / missing features collapse to an empty marker so
    languages other than Go (which do not currently emit body_features)
    still produce the historical hash.
    """
    if not body_features:
        return ""
    parts: List[str] = []
    for k in _BODY_FEATURE_ORDER:
        if k in body_features:
            parts.append(f"{k}={body_features[k]}")
    return ",".join(parts)


def compute_shape_hash(
    *,
    language: str,
    params: Optional[List[Dict[str, str]]] = None,
    return_types: Optional[List[str]] = None,
    visibility: Optional[str] = None,
    guards_detected: Optional[List[str]] = None,
    receiver_type: Optional[str] = None,
    fine: bool = False,
    shape_features: Optional[Dict[str, Any]] = None,
    body_features: Optional[Dict[str, Any]] = None,
) -> str:
    """Return the 16-hex shape_hash for a function record.

    Set ``fine=True`` for shape_hash_fine (preserves Msg-payload names). When
    fine hashing is enabled, Solidity ``shape_features`` and Go
    ``body_features`` are mixed in if present. Coarse hash behavior is
    unchanged.
    """
    lang = (language or "unknown").lower()
    param_seq = normalize_param_sequence(params or [], lang, fine=fine)
    ret_seq = normalize_return_sequence(return_types or [], lang, fine=fine)
    flags = compute_flag_vector(visibility, guards_detected)
    family = receiver_family(receiver_type)
    canonical_parts = [
        f"lang={lang}",
        f"params={','.join(param_seq)}",
        f"returns={','.join(ret_seq)}",
        f"flags={flag_vector_to_string(flags)}",
        f"family={family}",
        f"fine={int(fine)}",
    ]
    # Wave-11: for Solidity, augment the fine-hash canonical string with
    # body-derived feature components when shape_features is supplied.
    # Coarse hash (`fine=False`) is intentionally unchanged so existing
    # corpus indexes remain stable.
    if fine and lang == "solidity" and shape_features:
        canonical_parts.append(
            "solfine=" + _solidity_fine_features_canonical(shape_features)
        )
    if fine and body_features:
        canonical_parts.append(f"body={_body_features_canonical(body_features)}")
    canonical = "|".join(canonical_parts)
    return _hash16(canonical)


def shape_components(
    *,
    language: str,
    params: Optional[List[Dict[str, str]]] = None,
    return_types: Optional[List[str]] = None,
    visibility: Optional[str] = None,
    guards_detected: Optional[List[str]] = None,
    receiver_type: Optional[str] = None,
) -> Dict[str, Any]:
    """Return the human-readable canonicalization components (debugging /
    MCP-introspection)."""
    lang = (language or "unknown").lower()
    return {
        "language": lang,
        "param_type_sequence": normalize_param_sequence(params or [], lang, fine=False),
        "param_type_sequence_fine": normalize_param_sequence(params or [], lang, fine=True),
        "return_type_sequence": normalize_return_sequence(return_types or [], lang, fine=False),
        "flag_vector": compute_flag_vector(visibility, guards_detected),
        "flag_vector_string": flag_vector_to_string(compute_flag_vector(visibility, guards_detected)),
        "receiver_family": receiver_family(receiver_type),
    }


# --------------------------------------------------------------------------- #
# JSONL pipeline                                                              #
# --------------------------------------------------------------------------- #

def add_shape_hashes_to_record(rec: Dict[str, Any]) -> Dict[str, Any]:
    """Mutate-and-return: add shape_hash + shape_hash_fine in-place."""
    rec["shape_hash"] = compute_shape_hash(
        language=rec.get("language", "unknown"),
        params=rec.get("params"),
        return_types=rec.get("return_types"),
        visibility=rec.get("visibility"),
        guards_detected=rec.get("guards_detected"),
        receiver_type=rec.get("receiver_type"),
        fine=False,
    )
    rec["shape_hash_fine"] = compute_shape_hash(
        language=rec.get("language", "unknown"),
        params=rec.get("params"),
        return_types=rec.get("return_types"),
        visibility=rec.get("visibility"),
        guards_detected=rec.get("guards_detected"),
        receiver_type=rec.get("receiver_type"),
        fine=True,
        # Wave-11: Solidity body-feature dict (no-op for other languages).
        shape_features=rec.get("shape_features"),
        body_features=rec.get("body_features"),
    )
    return rec


def process_jsonl(
    input_path: Path, output_path: Optional[Path] = None
) -> Tuple[int, Optional[Path]]:
    n = 0
    out_stream = None
    if output_path:
        out_stream = output_path.open("w", encoding="utf-8")
    try:
        with input_path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                rec = add_shape_hashes_to_record(rec)
                serialized = json.dumps(rec, sort_keys=False)
                if out_stream:
                    out_stream.write(serialized + "\n")
                else:
                    print(serialized)
                n += 1
    finally:
        if out_stream:
            out_stream.close()
    return n, output_path


# --------------------------------------------------------------------------- #
# YAML tag update (in-place, line-preserving)                                 #
# --------------------------------------------------------------------------- #

# We deliberately do not invoke a YAML library here. Tag files are written
# by tools/verdict-tag-extractor.py with a fixed shape — we surgically insert
# shape_hash / shape_hash_fine lines under each `sites[]` entry that already
# has function_signature. Sites without function_signature are skipped (we
# cannot derive shape from file_path alone).

_RX_SITE_ENTRY = re.compile(r"^(\s*-\s*)file_path:\s*(.+)$")


def update_tag_file_in_place(tag_file: Path, sig_index: Dict[str, Dict[str, Any]]) -> int:
    """Augment a verdict-tag YAML in-place by adding shape_hash to sites[]
    entries whose ``function_signature`` resolves via ``sig_index``.

    ``sig_index`` is keyed by ``"<file_path>:<line_start>"``.

    Returns the number of sites updated. Idempotent.
    """
    text = tag_file.read_text(encoding="utf-8")
    lines = text.splitlines(keepends=False)
    out_lines: List[str] = []
    i = 0
    n_updated = 0
    while i < len(lines):
        line = lines[i]
        m = _RX_SITE_ENTRY.match(line)
        if not m:
            out_lines.append(line)
            i += 1
            continue
        # We have a `- file_path: X` site entry. Scan its block (lines
        # starting with the same indentation prefix or deeper) until next
        # non-block line.
        prefix_match = re.match(r"^(\s*)-\s*", line)
        indent = prefix_match.group(1) if prefix_match else ""
        block_indent = indent + "  "
        block: List[str] = [line]
        i += 1
        while i < len(lines):
            nxt = lines[i]
            if not nxt.startswith(block_indent) and not nxt.startswith(indent + "- "):
                break
            if nxt.startswith(indent + "- "):
                # next entry in same list begins
                break
            block.append(nxt)
            i += 1
        # parse the block into a dict (best-effort)
        site_kv: Dict[str, str] = {}
        for bl in block:
            mm = re.match(r"^\s*-?\s*([A-Za-z_][A-Za-z0-9_]*):\s*(.+)$", bl)
            if mm:
                k = mm.group(1)
                v = mm.group(2).strip()
                # strip optional surrounding quotes
                if (v.startswith('"') and v.endswith('"')) or (
                    v.startswith("'") and v.endswith("'")
                ):
                    v = v[1:-1]
                site_kv[k] = v
        fp = site_kv.get("file_path", "")
        line_start = site_kv.get("line_start", "")
        key = f"{fp}:{line_start}" if line_start else fp
        match = sig_index.get(key) or sig_index.get(fp)
        if (
            match
            and "shape_hash" not in site_kv
            and match.get("function_signature")
        ):
            # build shape_hash records using extractor fields
            sh_coarse = compute_shape_hash(
                language=match.get("language", "go"),
                params=match.get("params"),
                return_types=match.get("return_types"),
                visibility=match.get("visibility"),
                guards_detected=match.get("guards_detected"),
                receiver_type=match.get("receiver_type"),
                fine=False,
            )
            sh_fine = compute_shape_hash(
                language=match.get("language", "go"),
                params=match.get("params"),
                return_types=match.get("return_types"),
                visibility=match.get("visibility"),
                guards_detected=match.get("guards_detected"),
                receiver_type=match.get("receiver_type"),
                fine=True,
                # Wave-11: pass through Solidity body-feature dict if present.
                shape_features=match.get("shape_features"),
            )
            extra_lines = [
                f"{block_indent}shape_hash: {sh_coarse}",
                f"{block_indent}shape_hash_fine: {sh_fine}",
            ]
            if "function_signature" not in site_kv:
                fs = match.get("function_signature", "")
                if fs:
                    # collapse newlines + multi-whitespace; escape quotes
                    fs_norm = re.sub(r"\s+", " ", fs).strip().replace('"', '\\"')
                    extra_lines.insert(0, f"{block_indent}function_signature: \"{fs_norm}\"")
            if "function_name" not in site_kv and match.get("function_name"):
                extra_lines.insert(0, f"{block_indent}function_name: {match['function_name']}")
            if "receiver_type" not in site_kv and match.get("receiver_type"):
                extra_lines.insert(0, f"{block_indent}receiver_type: {match['receiver_type']}")
            if "visibility" not in site_kv and match.get("visibility"):
                extra_lines.insert(0, f"{block_indent}visibility: {match['visibility']}")
            block.extend(extra_lines)
            n_updated += 1
        out_lines.extend(block)
    if n_updated > 0:
        tag_file.write_text("\n".join(out_lines) + "\n", encoding="utf-8")
    return n_updated


def load_sig_index(sig_jsonl: Path) -> Dict[str, Dict[str, Any]]:
    """Index function records by ``file_path:line_start`` and by ``file_path``
    (first match) for sloppy join. Additionally, the index keys each record
    by progressively-shorter trailing path-suffixes (e.g. ``msg_server.go``
    when fp is ``protocol/x/affiliates/keeper/msg_server.go``). Per-suffix
    keys are only set if not already present (longer wins on ambiguity)."""
    idx: Dict[str, Dict[str, Any]] = {}
    if not sig_jsonl.exists():
        return idx
    with sig_jsonl.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            fp = rec.get("file_path", "")
            ls = rec.get("line_start", "")
            if fp:
                idx.setdefault(fp, rec)
                if ls:
                    idx[f"{fp}:{ls}"] = rec
                # add progressive suffixes so tag-side `x/affiliates/keeper/msg_server.go`
                # matches against extract-side `protocol/x/affiliates/keeper/msg_server.go`.
                segments = fp.split("/")
                for i in range(1, len(segments)):
                    suffix = "/".join(segments[i:])
                    idx.setdefault(suffix, rec)
                    if ls:
                        idx.setdefault(f"{suffix}:{ls}", rec)
    return idx


# --------------------------------------------------------------------------- #
# CLI                                                                         #
# --------------------------------------------------------------------------- #

def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument(
        "--function-jsonl",
        type=Path,
        help="Path to function-signature-extractor JSONL input.",
    )
    ap.add_argument(
        "--out",
        type=Path,
        default=None,
        help="Output JSONL path (default: stdout).",
    )
    ap.add_argument(
        "--update-tags",
        type=Path,
        default=None,
        help="Directory of verdict-tag YAML files to update in-place.",
    )
    ap.add_argument(
        "--sig-index",
        type=Path,
        default=None,
        help="Sig-extract JSONL used as the index source for --update-tags.",
    )
    args = ap.parse_args(argv)

    if args.function_jsonl:
        if not args.function_jsonl.exists():
            print(f"error: input not found: {args.function_jsonl}", file=sys.stderr)
            return 2
        n, out_path = process_jsonl(args.function_jsonl, args.out)
        if args.out:
            print(f"wrote {n} records to {args.out}", file=sys.stderr)
        return 0

    if args.update_tags:
        if not args.sig_index or not args.sig_index.exists():
            print(
                "error: --update-tags requires --sig-index pointing to a sig-extract JSONL",
                file=sys.stderr,
            )
            return 2
        sig_index = load_sig_index(args.sig_index)
        tag_dir = args.update_tags
        total = 0
        files_changed = 0
        for tag_file in sorted(tag_dir.glob("*.yaml")):
            n = update_tag_file_in_place(tag_file, sig_index)
            if n:
                files_changed += 1
                total += n
        print(
            f"updated {total} site shapes across {files_changed} tag files in {tag_dir}",
            file=sys.stderr,
        )
        return 0

    ap.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
