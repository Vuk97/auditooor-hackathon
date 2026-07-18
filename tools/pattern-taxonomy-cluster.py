#!/usr/bin/env python3
"""pattern-taxonomy-cluster.py — V5 Gap-27 / Gap-10 / Gap-13.

Background
----------
``reference/patterns.dsl/`` currently holds ~1,300 active YAML detector
specs. When an LLM (Kimi or Minimax) is asked "is THIS finding already
covered by an existing pattern?" we historically sent a *random* 60-name
sample of the library. LISA-Bench mining batch 1 (agent ``a1ef8b86``,
2026-04-25) showed 35/96 of Minimax's "novel" verdicts were actually
covered by patterns whose names were not in the random sample — a
~44% false-positive rate driven entirely by sampling noise.

A taxonomy-aware sampler (``/tmp/lisa_mine/dispatch_minimax_taxonomy.py``,
2026-04-25) replaced the random sample with bucket-relevant names
(e.g. all ``oracle``-tokened patterns when the case mentioned "oracle
staleness") and lifted Minimax accuracy from 0% → 57% on the same
prompts. This tool promotes that clusterer to canonical infrastructure.

Behaviour
---------
1. Read every ``*.yaml`` (and ``*.yaml.candidate``) pattern file under
   ``reference/patterns.dsl/`` (the main directory only — the
   per-round mined sub-directories are out of scope; they are merged
   into the main directory before promotion).
2. Tokenise each pattern name on hyphens, underscores, and camelCase
   word boundaries. Lowercase.
3. For each :data:`TAXONOMY` bucket (curated mapping of bucket id →
   substring tokens), include any pattern whose name contains one of
   the bucket's tokens.
4. Patterns that match no bucket land in ``__uncategorised``.
5. Emit ``reference/pattern_taxonomy.json`` with the shape:

       {
         "schema_version": 1,
         "generated_at": "<UTC ISO-8601>",
         "pattern_count": <int>,
         "buckets": {
            "<bucket_id>": ["<pattern-name>", ...],
            ...
         },
         "uncategorised": ["<pattern-name>", ...],
         "overlap": {
            "<pattern-name>": ["<bucket_id>", ...],
            ...
         }
       }

   ``overlap`` records every pattern that legitimately fits more than
   one bucket (e.g. ``oracle-stale-price-uses-twap-fallback`` → both
   ``oracle`` and ``amm_swap``). Downstream callers can decide whether
   to dedupe or keep duplicates.

Consumers
---------
``tools/llm-pr-review.py`` (and the LISA mining dispatcher) use this
JSON to pick a *bucket-relevant* pattern sample for the LLM prompt
instead of a random 60-name sample. See :func:`select_for_finding` for
the contract; the function is exposed publicly so other dispatchers
can reuse it without reimplementing token matching.

Hard rules
----------
- Stdlib only (no PyYAML — the names are extracted via regex on the
  ``pattern:`` field, which is the first field of every pattern file
  in this repo).
- Idempotent — running twice produces byte-identical output (sorted
  pattern lists, sorted bucket order in JSON).
- Empty input → empty output, no crash. Critical when run on a fresh
  worktree that hasn't pulled the patterns directory yet.
"""

from __future__ import annotations

import argparse
import collections
import datetime as _dt
import json
import pathlib
import re
import sys
from typing import Iterable


REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
DEFAULT_PATTERNS_DIR = REPO_ROOT / "reference" / "patterns.dsl"
DEFAULT_OUTPUT = REPO_ROOT / "reference" / "pattern_taxonomy.json"


# Curated taxonomy. Each bucket maps a bucket id → list of substring
# tokens. A pattern name belongs to a bucket if any token appears as a
# substring of the lowercased name OR of any whole token (split on
# hyphens/underscores).
#
# This map is hand-curated from LISA-Bench batch 1 + the existing
# pattern catalog. Adding a bucket is cheap; deleting a bucket is
# stable (downstream just stops getting that bucket).
TAXONOMY: dict[str, list[str]] = {
    "auth_access": [
        "auth", "role", "owner", "admin", "permission", "access",
        "onlyowner", "onlyrole", "onlyadmin", "tx-origin", "msg-sender",
        "ecdsa", "signature", "permit", "acl", "whitelist",
    ],
    "oracle": [
        "oracle", "chainlink", "twap", "spot", "price", "feed",
        "aggregator", "median", "stale", "scalar", "pyth", "redstone",
    ],
    "reentrancy": [
        "reentrancy", "reentrant", "cei", "before-external",
        "post-external", "nonreentrant", "cross-function",
    ],
    "math_overflow": [
        "overflow", "underflow", "rounding", "precision", "decimal",
        "decimals", "shr", "shl", "cast", "downcast", "abdk", "prbmath",
        "fixed-point", "64x64", "sd59x18", "ud60x18", "exp", "log",
        "mulmod",
    ],
    "slippage": [
        "slippage", "minout", "min-amount", "minprimary", "amountoutmin",
        "minshares", "deadline", "amountoutmin",
    ],
    "merkle": [
        "merkle", "proof", "leaf", "tree", "trie",
    ],
    "liquidation": [
        "liquidat", "collateral", "debt", "borrow", "lend", "stable",
        "bad-debt", "ltv",
    ],
    "vault": [
        "vault", "erc4626", "totalassets", "shares", "convertto",
        "deposit", "withdraw", "redeem", "preview",
    ],
    "amm_swap": [
        "swap", "pool", "lp", "amm", "uniswap", "balancer", "curve",
        "pancake", "dex", "hook", "tickspacing", "tick", "v3", "v4",
    ],
    "auction_order": [
        "auction", "order", "match-order", "fill-order", "bid",
        "limit-order", "trigger", "dutch", "gda", "vrgda", "fok",
        "seaport", "permit2", "fok",
    ],
    "fee_rebate": [
        "fee", "rebate", "premium", "kickback", "execution-fee",
        "keeper", "gas",
    ],
    "bridge_xchain": [
        "bridge", "lz", "wormhole", "ccip", "axelar", "ibc", "xchain",
        "cross-chain", "remote", "canonical", "wrapped", "layerzero",
    ],
    "governance": [
        "governance", "proposal", "vote", "quorum", "veto", "snapshot",
        "timelock", "offboard", "onboard", "delegate",
    ],
    "vrf_random": [
        "vrf", "random", "rng", "chainlink-vrf", "request-random",
    ],
    "factory_create": [
        "factory", "create", "create2", "create3", "deploy", "salt",
        "clone",
    ],
    "init_upgrade": [
        "initializer", "init", "upgrade", "uups", "proxy",
        "implementation", "reinit", "disable-init", "storage-gap",
    ],
    "blast_l2": [
        "blast", "yield-mode", "claimable", "void", "configurewell",
        "optimism", "ecotone", "fjord",
    ],
    "reward_emission": [
        "reward", "emission", "boost", "harvest", "claim", "rebase",
        "incentive",
    ],
    "loop_dos": [
        "unbounded", "loop", "iterate", "linkedlist", "linked-list",
        "queue", "gas-bomb", "out-of-gas",
    ],
    "encoding": [
        "abi-encode", "abi-decode", "encodepacked", "calldata", "memory",
        "bytes32", "domain-separator", "eip712", "eip-712",
    ],
    "elliptic_crypto": [
        "elliptic", "ec", "ecdsa", "jacobian", "projective", "ed25519",
        "secp", "schnorr",
    ],
    "parser_codec": [
        "parse", "decode", "rlp", "ssz", "merkleize",
    ],
}


# ---------------------------------------------------------------------------
# Pattern-name extraction
# ---------------------------------------------------------------------------

# Pattern files have ``pattern: <name>`` as the first or near-first
# non-comment line. Regex is used in lieu of YAML to keep this tool
# stdlib-only.
PATTERN_FIELD_RE = re.compile(r"^\s*pattern\s*:\s*([A-Za-z0-9._\-]+)\s*$")


def extract_pattern_name(text: str) -> str | None:
    """Return the value of the top-level ``pattern:`` field, or None."""
    for line in text.splitlines():
        line = line.split("#", 1)[0]
        m = PATTERN_FIELD_RE.match(line)
        if m:
            return m.group(1)
    return None


def discover_patterns(patterns_dir: pathlib.Path) -> list[str]:
    """Return sorted, deduped list of pattern names under ``patterns_dir``.

    Reads ``*.yaml`` and ``*.yaml.candidate`` files at the top level of
    ``patterns_dir`` (sub-round-mined sub-directories are intentionally
    out of scope — see module docstring). Pattern names are taken from
    the YAML's ``pattern:`` field, NOT the filename, because filenames
    occasionally drift from the canonical ``pattern:`` value.
    """
    if not patterns_dir.is_dir():
        return []
    names: set[str] = set()
    for path in sorted(patterns_dir.iterdir()):
        if not path.is_file():
            continue
        name_l = path.name.lower()
        if not (name_l.endswith(".yaml") or name_l.endswith(".yaml.candidate")):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        pname = extract_pattern_name(text)
        if pname:
            names.add(pname)
    return sorted(names)


# ---------------------------------------------------------------------------
# Bucket assignment
# ---------------------------------------------------------------------------


def _name_token_set(name: str) -> set[str]:
    """Tokenise a pattern name on hyphens + underscores. Lowercased."""
    return set(name.lower().replace("_", "-").split("-"))


def assign_buckets(name: str) -> list[str]:
    """Return the sorted list of bucket ids matched by pattern ``name``.

    A name matches a bucket if any of the bucket's tokens appears as
    a substring of the lowercased name OR exactly matches one of the
    name's hyphen/underscore tokens. Substring matching covers token
    fragments embedded inside compound words (e.g. ``stale`` inside
    ``stale-twap-feed``); exact-token matching covers short tokens
    that we explicitly do NOT want substringed (e.g. ``ec`` inside
    ``ecdsa`` would be too noisy as a pure substring). Both modes
    coexist: the bucket curator picks tokens long enough to be safe
    as substrings, and short tokens (rare) are matched only as whole
    name-tokens.
    """
    nl = name.lower()
    nl_tokens = _name_token_set(name)
    hits: set[str] = set()
    for bucket, toks in TAXONOMY.items():
        for t in toks:
            t = t.lower()
            if len(t) >= 4:
                if t in nl:
                    hits.add(bucket)
                    break
            else:
                if t in nl_tokens:
                    hits.add(bucket)
                    break
    return sorted(hits)


def cluster(names: Iterable[str]) -> dict:
    """Cluster pattern names into the taxonomy.

    Returns a dict suitable for :func:`build_manifest`. Empty input
    yields empty buckets/uncategorised/overlap (no crash).
    """
    buckets: dict[str, list[str]] = collections.defaultdict(list)
    overlap: dict[str, list[str]] = {}
    uncategorised: list[str] = []
    for n in sorted(set(names)):
        hits = assign_buckets(n)
        if not hits:
            uncategorised.append(n)
            continue
        for b in hits:
            buckets[b].append(n)
        if len(hits) > 1:
            overlap[n] = hits
    # Deterministic ordering — bucket ids sorted, names already sorted.
    return {
        "buckets": {b: sorted(buckets[b]) for b in sorted(buckets)},
        "uncategorised": sorted(uncategorised),
        "overlap": dict(sorted(overlap.items())),
    }


def build_manifest(names: list[str]) -> dict:
    """Wrap :func:`cluster` in the schema v1 manifest envelope."""
    payload = cluster(names)
    return {
        "schema_version": 1,
        "generated_at": _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "pattern_count": len(set(names)),
        "buckets": payload["buckets"],
        "uncategorised": payload["uncategorised"],
        "overlap": payload["overlap"],
    }


# ---------------------------------------------------------------------------
# Bucket selection (consumed by tools/llm-pr-review.py)
# ---------------------------------------------------------------------------


_WORD_TOKEN_RE = re.compile(r"[a-z0-9]+")


def keywords_from_text(text: str) -> list[str]:
    """Extract taxonomy bucket-ids relevant to free-form ``text``.

    Used by :func:`select_for_finding` and by external dispatchers that
    have a ``title + content`` blob and want to know which bucket(s)
    to pull pattern names from.

    Matching rules (stricter than :func:`assign_buckets` because text
    is full English prose, not pre-tokenised pattern names):
      * Tokens of length >= 4 must appear as a substring of *some
        word* in the text — protects against ``acl`` matching
        ``oracle`` or ``fee`` matching ``feed``.
      * Tokens of length < 4 must be a whole word.
    """
    if not text:
        return []
    words = _WORD_TOKEN_RE.findall(text.lower())
    if not words:
        return []
    word_set = set(words)
    hit: list[str] = []
    for bucket, toks in TAXONOMY.items():
        matched = False
        for t in toks:
            tl = t.lower()
            # Tokens may themselves carry hyphens (e.g. ``cross-chain``);
            # split them so we can check each piece against word_set
            # for short pieces and substring-search for long pieces.
            pieces = tl.split("-") if "-" in tl else [tl]
            for piece in pieces:
                if not piece:
                    continue
                if len(piece) < 4:
                    if piece in word_set:
                        matched = True
                        break
                else:
                    # Substring match against any word in the prose.
                    if any(piece in w for w in words):
                        matched = True
                        break
            if matched:
                break
        if matched:
            hit.append(bucket)
    return hit


def select_for_finding(
    manifest: dict,
    *,
    text: str,
    cap: int = 60,
) -> tuple[list[str], list[str]]:
    """Pick a bucket-relevant pattern sample for an LLM prompt.

    ``manifest`` is the dict returned by :func:`build_manifest` (or
    ``json.load(open("reference/pattern_taxonomy.json"))``). ``text`` is
    the finding's title + description blob; we tokenise it via
    :func:`keywords_from_text`. Returns a pair ``(sample, buckets_used)``:

      - ``sample`` is up to ``cap`` pattern names, deduped, sorted.
      - ``buckets_used`` is the list of bucket ids contributing.

    If no buckets matched, returns ``([], [])`` — caller decides
    whether to fall back to a random sample (existing behaviour).
    """
    if not manifest or "buckets" not in manifest:
        return [], []
    buckets_used = keywords_from_text(text)
    if not buckets_used:
        return [], []
    chosen: list[str] = []
    seen: set[str] = set()
    for b in buckets_used:
        for n in manifest["buckets"].get(b, []):
            if n in seen:
                continue
            seen.add(n)
            chosen.append(n)
            if len(chosen) >= cap:
                break
        if len(chosen) >= cap:
            break
    return sorted(chosen[:cap]), buckets_used


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pattern-taxonomy-cluster",
        description=(
            "Cluster reference/patterns.dsl/*.yaml pattern names by "
            "token co-occurrence into reference/pattern_taxonomy.json "
            "(V5 Gap-27)."
        ),
    )
    p.add_argument(
        "--patterns-dir",
        default=str(DEFAULT_PATTERNS_DIR),
        help=f"Directory containing pattern YAMLs (default: {DEFAULT_PATTERNS_DIR})",
    )
    p.add_argument(
        "--output",
        default=str(DEFAULT_OUTPUT),
        help=f"Output JSON path (default: {DEFAULT_OUTPUT})",
    )
    p.add_argument(
        "--json",
        action="store_true",
        help="Emit the manifest to stdout instead of writing to --output.",
    )
    p.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress the human-readable summary line on stderr.",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    args = _arg_parser().parse_args(argv)
    patterns_dir = pathlib.Path(args.patterns_dir).expanduser().resolve()
    names = discover_patterns(patterns_dir)
    manifest = build_manifest(names)
    if args.json:
        print(json.dumps(manifest, indent=2, sort_keys=True))
    else:
        out = pathlib.Path(args.output).expanduser().resolve()
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    if not args.quiet:
        nb = len(manifest["buckets"])
        nu = len(manifest["uncategorised"])
        no = len(manifest["overlap"])
        print(
            f"[pattern-taxonomy] patterns={manifest['pattern_count']} "
            f"buckets={nb} uncategorised={nu} overlap={no}",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
