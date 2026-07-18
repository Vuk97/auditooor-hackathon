"""
unwrap_or_zero_on_persistent_storage.py

Flags `.unwrap_or(0)` / `.unwrap_or(0i128)` / `.unwrap_or(0u128)` applied to a
persistent-storage get call — TTL archival makes a previously-written value
read back as default, silently erasing state. Pattern class: Volley V12
Criticals #44792/#44793.

Heuristic: find any call_expression where method = unwrap_or and the first
argument is an explicit-zero literal (0 / false / Address::default()); walk
up the receiver chain and confirm it contains `.persistent().get(` or
`.instance().get(`.

Tightening (wave1 batch 3):
  - Only flag when the storage key identifier looks like a BALANCE /
    DEBT / DEFICIT / reward / supply / allowance / principal / collateral
    — i.e. reads where the account holder would lose value if the key
    silently returned 0.
  - Skip when the key clearly resembles a COUNTER / NONCE / ID / rate
    constant / TTL / config where 0 is a safe initial value.
"""

from __future__ import annotations

from _util import text_of, walk, line_col, snippet_of


_ZERO_LITERALS = {"0", "0i128", "0u128", "0i64", "0u64", "0i32", "0u32",
                  "0_i128", "0_u128", "false"}

# Receiver-chain / fn name tokens that are SAFE to default to 0 — skip
_SAFE_KEY_TOKENS = (
    "counter", "count", "nonce", "next_id", "rate", "slope",
    "util", "ttl", "premium", "deploy", "ceiling",
    "total_liquidations", "reserve_count", "next_reserve",
    "var_rate", "base_rate", "opt_util", "treasury",
)

# Receiver-chain / fn name tokens that are SUSPICIOUS — keep flagging
_RISKY_KEY_TOKENS = (
    "balance", "scaled_balance", "debt", "deficit", "supply",
    "collateral", "shares", "allowance", "reward", "accrued",
    "liquidity", "principal", "deposit",
    "fee_accum", "pending_",
)


def _is_zero_arg(node, source):
    if node is None:
        return False
    t = text_of(node, source).strip()
    if t in _ZERO_LITERALS:
        return True
    # Address::default() / FooKey::default() of a key type
    if t.endswith("::default()"):
        return True
    return False


def _chain_reads_persistent(callee_node, source):
    """True if receiver chain contains `.persistent().get(` or
    `.instance().get(`."""
    txt = text_of(callee_node, source)
    if ".persistent()" in txt or ".instance()" in txt:
        if ".get(" in txt or ".get::" in txt:
            return True
    return False


def _classify(callee_text: str, fn_name_text: str, body_keys: str) -> str:
    """Return 'risky' / 'safe' / 'unknown'.
    Only look at:
      - receiver-chain text (callee_text) — the .get(&key) is there
      - function name (fn_name_text) — get_scaled_balance etc.
      - body_keys — only the `let key = ...` and `DataKey::` references,
        NOT the full body (avoids matching TTL_THRESHOLD noise).
    Safe tokens take precedence.
    """
    haystack = (callee_text + " " + fn_name_text + " " + body_keys).lower()
    for tok in _SAFE_KEY_TOKENS:
        if tok in haystack:
            return "safe"
    for tok in _RISKY_KEY_TOKENS:
        if tok in haystack:
            return "risky"
    return "unknown"


def _body_key_snippets(fn_text: str) -> str:
    """Extract only the lines that look like key declarations to classify
    on.  Keeps `let key = ...`, `DataKey::...`, `StorageKey::...`."""
    out = []
    for ln in fn_text.splitlines():
        s = ln.strip()
        if s.startswith("let key") or "DataKey::" in s or "StorageKey::" in s:
            out.append(s)
    return "\n".join(out)


def _enclosing_fn_text(node, source):
    n = node
    while n is not None:
        if n.type == "function_item":
            return text_of(n, source)
        n = n.parent
    return ""


def run(tree, source: bytes, filepath: str):
    hits = []
    for n in walk(tree.root_node):
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
        if method != "unwrap_or":
            continue
        # First positional argument
        first_arg = None
        for c in args.children:
            if c.type not in ("(", ")", ","):
                first_arg = c
                break
        if not _is_zero_arg(first_arg, source):
            continue
        if not _chain_reads_persistent(callee, source):
            continue

        # Tightening: classify by surrounding fn + receiver chain
        callee_text = text_of(callee, source)
        fn_text = _enclosing_fn_text(n, source)
        # Extract fn NAME (first identifier after `fn`)
        fn_name_text = ""
        nn = n
        while nn is not None:
            if nn.type == "function_item":
                for c in nn.children:
                    if c.type == "identifier":
                        fn_name_text = text_of(c, source)
                        break
                break
            nn = nn.parent
        body_keys = _body_key_snippets(fn_text)
        kind = _classify(callee_text, fn_name_text, body_keys)
        if kind != "risky":
            continue

        line, col = line_col(n)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(n, source),
            "message": ("`.unwrap_or(0)` on persistent/instance storage read "
                        "of a balance/debt/reward-like key — TTL archival "
                        "can silently erase user state (Volley V12 "
                        "#44792/#44793 class)."),
        })
    return hits
