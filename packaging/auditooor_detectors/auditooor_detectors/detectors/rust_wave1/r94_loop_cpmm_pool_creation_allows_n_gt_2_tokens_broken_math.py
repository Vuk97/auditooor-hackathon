"""
r94_loop_cpmm_pool_creation_allows_n_gt_2_tokens_broken_math.py

Flags factory / create-pool fns that accept a `PoolKind::CPMM`
variant (or constant-product) with an `assets.len()` or
`n_tokens` > 2 — Uniswap-style CPMM math only supports n=2.
The resulting pool is structurally broken; LPs deposit then
cannot exit cleanly.

Source: Solodit #54977 (Code4rena MANTRA pool-manager).
Class: cpmm-pool-creation-allows-n-gt-2-tokens-broken-math (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT, CALL

_FN_NAME_RE = re.compile(
    r"(?i)(create_pool|instantiate_pool|register_pool|"
    r"add_pool|factory_create_pool|new_pool|open_pool)"
)
# Touches CPMM branch / constant-product.
_CPMM_RE = re.compile(
    r"(?i)(PoolKind::CPMM|pool_kind::cpmm|"
    r"PoolType::CPMM|"
    r"ConstantProduct|CONSTANT_PRODUCT|"
    r"CpmmPool|constant_product_pool|"
    r"xyk_pool|XykPool)"
)
# Safe: asserts n_tokens == 2 for CPMM.
_N_CHECK_RE = re.compile(
    fr"(?i)(assert\w*\s*!?\s*\(\s*{IDENT}assets\.len\s*\(\s*\)\s*==\s*2|"
    fr"require\s*\(\s*{IDENT}assets\.length\s*==\s*2|"
    fr"assert\w*\s*!?\s*\(\s*{IDENT}tokens\.len\s*\(\s*\)\s*==\s*2|"
    fr"require\s*\(\s*{IDENT}n_tokens\s*==\s*2|"
    fr"if\s+{IDENT}assets\.len\s*\(\s*\)\s*!=\s*2\s*\{{\s*(return|panic|revert)|"
    fr"N_COINS\s*==\s*2|n_coins\s*==\s*2)"
)


def run(tree, source: bytes, filepath: str):
    hits = []
    for fn, _impl in functions_in_contractimpl(tree.root_node, source):
        if not is_pub(fn, source):
            continue
        name = fn_name(fn, source)
        if not _FN_NAME_RE.search(name):
            continue
        body = fn_body(fn)
        if body is None:
            continue
        body_nc = body_text_nocomment(body, source)
        if not _CPMM_RE.search(body_nc):
            continue
        if _N_CHECK_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` creates a `CPMM` / constant-product "
                f"pool without asserting `n_tokens == 2` — factory "
                f"can mint a structurally broken tri-crypto CPMM "
                f"whose math doesn't support n≥3, LPs lock funds "
                f"(cpmm-pool-creation-allows-n-gt-2-tokens-broken-math). "
                f"See Solodit #54977 (Code4rena MANTRA pool-manager)."
            ),
        })
    return hits
