"""
rust_per_actor_cap_keyed_on_composite_addr.py

Flags HashMap / BTreeMap fields (or local variables) whose KEY type is
SocketAddr (or a composite tuple that includes an ephemeral port component)
and whose usage context implies a per-actor rate / slot / cap / dedup budget.

Bug class: CROSS-COMPONENT KEY-ASYMMETRY
A per-actor rate/cap/dedup map is keyed on a COMPOSITE / ephemeral-inclusive
identity (e.g. HashMap<SocketAddr, _> = IP + ephemeral port) instead of the
stable security identity (IpAddr). An attacker opens N connections from one
IP; each gets a distinct ephemeral port = a distinct map bucket, multiplying
their per-peer budget N-fold.

Real zebra anchor:
  zebrad/src/components/mempool/downloads.rs:206
    pending_per_peer: HashMap<SocketAddr, usize>
  The per-peer cap enforcing GHSA-4fc2-h7jh-287c keys on SocketAddr (IP+port).
  The sibling inbound/downloads.rs block-download cap keys on addr.ip() (IpAddr,
  correct). An attacker opens 100 connections from one IP, filling all 500 global
  slots from a single source IP.

Structural shape (class-invariant):
  - A struct field OR local `let` binding whose TYPE is HashMap<SocketAddr, _>
    (or BTreeMap<SocketAddr, _>, or HashMap<(SocketAddr, ...), _>).
  - The field / variable NAME or a nearby identifier (within the same block)
    contains a per-actor budget token (cap, limit, per_peer, pending, slot,
    quota, count, budget, seen, dedup, concurrency).
  - The KEY type is NOT IpAddr or a newtype / struct that plausibly contains
    only the IP (to avoid FP on clean keying).

Three structural signals required:
  1. HashMap / BTreeMap with SocketAddr key in a struct field declaration
     OR a local let-binding in non-test code.
  2. At least one per-actor budget identifier adjacent to the declaration.
  3. No evidence that the map is keyed only on the stable IP component
     (no .ip() extraction used as the map key in the same context).

Severity: HIGH
Rubric: Non-distributed DoS against an individual node; defeats a
  peer-rate-limit / cap mitigation and allows resource exhaustion from one
  source IP.
"""

from __future__ import annotations

import re

from _util import (
    body_text_nocomment,
    fn_body,
    in_test_cfg,
    line_col,
    snippet_of,
    text_of,
    walk,
    walk_no_nested_fn,
    IDENT,
)

# ---------------------------------------------------------------------------
# Signal 1a - HashMap or BTreeMap with a SocketAddr key (struct field)
#
# Matches:
#   HashMap<SocketAddr, usize>
#   BTreeMap<SocketAddr, ...>
#   HashMap<(SocketAddr, SomeOtherType), ...>   <- composite key including port
# Does NOT fire on:
#   HashMap<IpAddr, ...>  -- IpAddr alone is the stable identity
# ---------------------------------------------------------------------------
_COMPOSITE_KEY_TYPE_RE = re.compile(
    r"(?:HashMap|BTreeMap)\s*<\s*(?:"
    # plain SocketAddr key
    r"(?:\w+::)*SocketAddr"
    # OR a tuple key that contains SocketAddr  (IP+port is a common composite)
    r"|"
    r"\(\s*(?:\w+::)*SocketAddr[\s\S]{0,80}?\)"
    r")\s*,"
)

# ---------------------------------------------------------------------------
# Signal 2 - per-actor budget tokens
#
# At least one of these tokens must appear in the field's name, in a nearby
# comment, or in the surrounding block text.
#
# NOTE: in Rust identifier names (snake_case), these tokens appear as
# components joined by underscores, e.g. "pending_per_peer". Because `_` is
# a word character, `\bpending\b` does NOT match inside "pending_per_peer".
# We use a compound pattern that covers both bare `\b...\b` occurrences
# (comments, string literals) AND identifier-component occurrences
# (start-of-string, after `_`, before `_`, end-of-string).
# ---------------------------------------------------------------------------
_BUDGET_TOKEN_RE = re.compile(
    r"(?:"
    # standard word-boundary form (in comments, type names, strings)
    r"\b(?:cap|limit|per_peer|pending|slot|quota|count|budget|seen|dedup"
    r"|concurrency|rate|throttle|inflight|in_flight|inbound)\b"
    r"|"
    # snake_case component form: token at identifier start or after _
    r"(?:^|_)(?:cap|limit|per_peer|pending|slot|quota|count|budget|seen|dedup"
    r"|concurrency|rate|throttle|inflight|in_flight|inbound)(?:_|$|\s|:)"
    r")",
    re.IGNORECASE | re.MULTILINE,
)

# ---------------------------------------------------------------------------
# Guard - the map is keyed on IpAddr (stable identity) or the call site
# extracts .ip() to build the key.
# These indicate the developer DID use the stable IP, so we skip.
# ---------------------------------------------------------------------------
_STABLE_KEY_GUARD_RE = re.compile(
    r"(?:"
    r"HashMap\s*<\s*(?:\w+::)*IpAddr"      # HashMap<IpAddr, _>
    r"|BTreeMap\s*<\s*(?:\w+::)*IpAddr"    # BTreeMap<IpAddr, _>
    r"|HashSet\s*<\s*(?:\w+::)*IpAddr"     # HashSet<IpAddr>
    r"|\.ip\s*\(\s*\)"                      # .ip() extractor used as key
    r"|addr\.ip\b"                          # explicit addr.ip
    r")"
)

# ---------------------------------------------------------------------------
# Struct field extraction helpers
# ---------------------------------------------------------------------------

def _is_test_context(node) -> bool:
    """Walk up the tree; return True if inside a #[cfg(test)] mod or impl."""
    n = node.parent
    while n is not None:
        if n.type == "mod_item":
            # Try to detect cfg(test) via source text inspection
            n2 = n.prev_named_sibling
            while n2 is not None and n2.type == "attribute_item":
                return True  # any attribute on a parent mod is suspicious enough
            break
        n = n.parent
    return False


def _surrounding_text(node, source: bytes, radius: int = 300) -> str:
    """Return up to `radius` bytes of source around `node`, decoded."""
    start = max(0, node.start_byte - radius)
    end = min(len(source), node.end_byte + radius)
    return source[start:end].decode("utf-8", errors="replace")


def run(tree, source: bytes, filepath: str):
    hits = []
    seen_lines: set[int] = set()

    src_text = source.decode("utf-8", errors="replace")

    # ------------------------------------------------------------------
    # Pass 1: struct field declarations
    # Walk every `field_declaration` node whose type text matches.
    # ------------------------------------------------------------------
    for node in walk(tree.root_node):
        if node.type != "field_declaration":
            continue

        field_text = text_of(node, source)

        # Signal 1: SocketAddr-composite key type?
        if not _COMPOSITE_KEY_TYPE_RE.search(field_text):
            continue

        # Guard: IpAddr-keyed map already uses stable identity - skip
        if _STABLE_KEY_GUARD_RE.search(field_text):
            continue

        # Signal 2: per-actor budget token anywhere in field text or
        # surrounding ±300 bytes (captures comments + adjacent fields).
        surround = _surrounding_text(node, source, radius=400)
        if not _BUDGET_TOKEN_RE.search(field_text) and not _BUDGET_TOKEN_RE.search(surround):
            continue

        # Skip if inside test code
        if in_test_cfg(node, source):
            continue

        line, col = line_col(node)
        if line in seen_lines:
            continue
        seen_lines.add(line)

        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(node, source),
            "message": (
                "Per-actor cap/budget map keyed on `SocketAddr` (IP+port). "
                "An attacker opens N connections from one IP, each using a "
                "distinct ephemeral port, obtaining a separate budget bucket "
                "per connection and multiplying their allowed rate N-fold. "
                "Key on `IpAddr` (i.e. `addr.ip()`) instead of the full "
                "`SocketAddr` to enforce the cap per source IP."
            ),
        })

    # ------------------------------------------------------------------
    # Pass 2: local `let` bindings inside function bodies
    # e.g.:  let mut per_peer: HashMap<SocketAddr, usize> = HashMap::new();
    # ------------------------------------------------------------------
    for node in walk(tree.root_node):
        if node.type != "let_declaration":
            continue

        let_text = text_of(node, source)

        # Signal 1
        if not _COMPOSITE_KEY_TYPE_RE.search(let_text):
            continue

        # Guard
        if _STABLE_KEY_GUARD_RE.search(let_text):
            continue

        # Signal 2
        surround = _surrounding_text(node, source, radius=300)
        if not _BUDGET_TOKEN_RE.search(let_text) and not _BUDGET_TOKEN_RE.search(surround):
            continue

        # Skip test code: walk up to see if we are inside a #[test] fn
        fn_ancestor = None
        n = node.parent
        while n is not None:
            if n.type == "function_item":
                fn_ancestor = n
                break
            n = n.parent
        if fn_ancestor is not None and in_test_cfg(fn_ancestor, source):
            continue

        line, col = line_col(node)
        if line in seen_lines:
            continue
        seen_lines.add(line)

        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(node, source),
            "message": (
                "Local per-actor cap/budget map keyed on `SocketAddr` (IP+port). "
                "An attacker opens N connections from one IP, each using a "
                "distinct ephemeral port, bypassing the per-peer budget. "
                "Key on `IpAddr` (i.e. `addr.ip()`) to enforce the cap per "
                "source IP."
            ),
        })

    return hits
