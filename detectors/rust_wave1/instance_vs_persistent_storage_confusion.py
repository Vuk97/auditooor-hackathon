"""
instance_vs_persistent_storage_confusion.py

Flags Soroban storage-tier confusion: writing one tier and reading another
for the same DataKey variant, or per-user state put on instance() (capacity
cap risk, Halborn §7.7 class), or one-time-init config flags parked on
persistent() (wastes TTL cost).

Heuristics (any one is a hit):
  1. Same key variant (e.g. `DataKey::Balance`) appears with both `.instance()`
     and `.persistent()` (or either + `.temporary()`) access in the SAME file.
  2. `env.storage().instance().set(&Key::<Variant>(<Address-typed arg>,...))`
     — per-user data on instance storage.
  3. `env.storage().persistent().set(&Key::Config)` / `...::Admin`
     / `...::Initialized` / `...::Paused` — global singleton flags on
     persistent storage.

Heuristics are intentionally conservative (textual over the callee chain).
"""

from __future__ import annotations

import re

from _util import text_of, walk, line_col, snippet_of


# Key-variant name hints that strongly imply a global singleton (not per-user)
_SINGLETON_HINTS = {
    "Admin", "Config", "OracleConfig", "Initialized", "Paused", "PendingAdmin",
    "Owner", "Governance", "FallbackOracle", "ReflectorContract", "Registry",
    "Treasury", "Version", "ReflectorPrecision",
}

# Per-user / per-account variants — these should NOT live on instance()
_PERUSER_HINTS = {
    "Balance", "Allowance", "UserConfig", "UserConfiguration",
    "UserData", "Position", "User", "Account", "Nonce", "Stake",
}

# Match callee text like `env.storage().<TIER>()` possibly with preceding receiver
_TIER_RE = re.compile(
    r"storage\(\)\s*\.\s*(instance|persistent|temporary)\(\)"
)

# Match the first `Key::Variant` inside a set/get/has/remove call (the key path)
_KEY_VARIANT_RE = re.compile(
    r"(?:^|[^A-Za-z0-9_])([A-Z][A-Za-z0-9_]*)\s*::\s*([A-Z][A-Za-z0-9_]*)"
)


def _iter_storage_calls(root, source: bytes):
    """Yield (call_node, tier, method, args_text) for every
    env.storage().<tier>().<method>(...) call."""
    for n in walk(root):
        if n.type != "call_expression":
            continue
        callee = None
        args = None
        for c in n.children:
            if c.type == "field_expression" and callee is None:
                callee = c
            elif c.type == "arguments":
                args = c
        if callee is None or args is None:
            continue
        method = None
        for c in callee.children:
            if c.type == "field_identifier":
                method = text_of(c, source)
        if method not in ("set", "get", "has", "remove", "update",
                          "extend_ttl", "set_persistent"):
            continue
        ctxt = text_of(callee, source)
        m = _TIER_RE.search(ctxt)
        if not m:
            continue
        tier = m.group(1)
        args_text = text_of(args, source)
        yield n, tier, method, args_text


def _first_key_variant(args_text: str):
    """Return (enum_name, variant_name) for the first Key::Variant found."""
    m = _KEY_VARIANT_RE.search(args_text)
    if not m:
        return None
    return (m.group(1), m.group(2))


def _arg_looks_peruser(args_text: str) -> bool:
    """Heuristic: does the argument list contain an Address-like token after
    the key variant? We look for typical per-user markers."""
    # Common per-user arg shapes: `(Address,...)`, `(caller`, `(user`,
    # `(who`, `(owner`, `(account`.
    if re.search(r"\b(caller|user|who|owner|account|from|to|holder)\b",
                 args_text):
        return True
    # Variants explicitly tupling on Address
    if re.search(r"Address\b", args_text):
        return True
    return False


def run(tree, source: bytes, filepath: str):
    hits = []
    root = tree.root_node

    # Pass 1: collect all storage calls
    calls = list(_iter_storage_calls(root, source))

    # Map variant -> set of tiers seen
    variant_tiers: dict[tuple, set] = {}
    variant_first_node: dict[tuple, object] = {}
    for node, tier, method, args in calls:
        kv = _first_key_variant(args)
        if kv is None:
            continue
        variant_tiers.setdefault(kv, set()).add(tier)
        variant_first_node.setdefault(kv, node)

    # Hit type 1: same variant in multiple tiers
    reported_lines = set()
    for kv, tiers in variant_tiers.items():
        if len(tiers) < 2:
            continue
        node = variant_first_node[kv]
        line, col = line_col(node)
        reported_lines.add(line)
        hits.append({
            "severity": "med",
            "line": line,
            "col": col,
            "snippet": snippet_of(node, source),
            "message": (f"Key `{kv[0]}::{kv[1]}` is accessed across multiple "
                        f"storage tiers ({', '.join(sorted(tiers))}) in the "
                        f"same file — writes to one tier will not be visible "
                        f"through reads on the other."),
        })

    # Hit type 2 & 3: per-variant semantic mismatch
    for node, tier, method, args in calls:
        if method not in ("set", "update"):
            continue
        line, col = line_col(node)
        if line in reported_lines:
            continue
        kv = _first_key_variant(args)
        if kv is None:
            continue
        variant_name = kv[1]

        # Type 2: per-user variant on instance()
        if tier == "instance" and (
            variant_name in _PERUSER_HINTS or _arg_looks_peruser(args)
        ):
            hits.append({
                "severity": "med",
                "line": line,
                "col": col,
                "snippet": snippet_of(node, source),
                "message": (f"Per-user key `{kv[0]}::{variant_name}` written "
                            f"to instance() storage — instance state has a "
                            f"capacity cap and is copied on every invocation "
                            f"(Halborn §7.7 class). Use persistent() for "
                            f"per-user data."),
            })
            continue

        # Type 3: singleton-flag variant on persistent()
        if tier == "persistent" and variant_name in _SINGLETON_HINTS:
            hits.append({
                "severity": "low",
                "line": line,
                "col": col,
                "snippet": snippet_of(node, source),
                "message": (f"Singleton key `{kv[0]}::{variant_name}` written "
                            f"to persistent() storage — one-time-init / global "
                            f"config should live on instance() to avoid "
                            f"per-entry TTL archival cost."),
            })

    return hits
