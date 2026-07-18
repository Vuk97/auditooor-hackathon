"""
Detect reward accounting that binds claims to a token pair instead of the
full pool identity.

Confirmed source shape: a pool is registered from a full PoolKey
including fee, tick spacing, or hooks, but rewards are stored and claimed
through a HashMap keyed only by (token0, token1). A lookalike pool with
the same listed token pair can claim rewards intended for the canonical
pool.
"""

from __future__ import annotations

import re

from _util import source_nocomment


_POOL_KEY_RE = re.compile(r"struct\s+PoolKey\s*\{(?P<body>[\s\S]{0,1200}?)\}", re.IGNORECASE)
_EXTRA_IDENTITY_RE = re.compile(r"\b(fee|tick_spacing|tickSpacing|hooks?|pool_id|poolId)\b", re.IGNORECASE)
_PAIR_REWARD_MAP_RE = re.compile(
    r"\b(?P<name>\w*reward\w*)\s*:\s*HashMap\s*<\s*\("
    r"(?P<key>[\s\S]{0,180}?)\)\s*,",
    re.IGNORECASE,
)
_POOL_REGISTRY_RE = re.compile(
    r"fn\s+register_pool\s*\([^)]*\bpool_key\s*:\s*&?\s*PoolKey[\s\S]{0,700}?"
    r"(derive_pool_id\s*\(\s*pool_key\s*\)|pool_key\.hash\s*\(|PoolId)",
    re.IGNORECASE,
)
_CANONICAL_PAIR_GUARD_RE = re.compile(
    r"canonical_pools|canonical_pool_for_pair|registered_pool_for_pair|"
    r"whitelisted_pool|contains_key\s*\(\s*&\s*pair\s*\)|Pool already exists",
    re.IGNORECASE,
)
_PAIR_FROM_POOL_KEY_RE = re.compile(
    r"pool_key\s*\.\s*token0[\s\S]{0,260}?pool_key\s*\.\s*token1|"
    r"pool_key\s*\.\s*currency0[\s\S]{0,260}?pool_key\s*\.\s*currency1",
    re.IGNORECASE,
)


def _has_full_pool_key(text: str) -> bool:
    match = _POOL_KEY_RE.search(text)
    if not match:
        return False
    body = match.group("body")
    has_pair = re.search(r"\b(token0|currency0)\b", body, re.IGNORECASE) and re.search(
        r"\b(token1|currency1)\b", body, re.IGNORECASE
    )
    return bool(has_pair and _EXTRA_IDENTITY_RE.search(body))


def _reward_pair_maps(text: str) -> list[str]:
    names: list[str] = []
    for match in _PAIR_REWARD_MAP_RE.finditer(text):
        key = match.group("key")
        if "," not in key:
            continue
        if re.search(r"PoolId|pool_id|PoolKey|canonical", key, re.IGNORECASE):
            continue
        names.append(match.group("name"))
    return names


def _iter_pool_key_reward_fns(text: str):
    fn_re = re.compile(
        r"(?P<sig>(?:pub\s+)?fn\s+(?P<name>\w*reward\w*)\s*\("
        r"(?P<params>[\s\S]{0,500}?\bpool_key\s*:\s*&?\s*PoolKey[\s\S]{0,500}?)\)"
        r"\s*(?:->\s*[^{]+)?\{)",
        re.IGNORECASE,
    )
    for match in fn_re.finditer(text):
        start = match.end() - 1
        depth = 0
        end = start
        for idx in range(start, len(text)):
            ch = text[idx]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    end = idx + 1
                    break
        if end <= start:
            continue
        yield match.group("name"), match.start(), text[match.start() : end]


def _hit(filepath: str, text: str, fn_start: int, fn_name: str) -> dict[str, object]:
    line = text[:fn_start].count("\n") + 1
    snippet = text[fn_start : fn_start + 180].replace("\n", " ").strip()
    return {
        "severity": "high",
        "line": line,
        "col": 0,
        "snippet": snippet,
        "message": (
            f"{filepath}: reward function `{fn_name}` claims rewards by a "
            "token-pair key while pools are registered from a wider PoolKey. "
            "A duplicate pool with the same token pair can receive rewards "
            "intended for the canonical pool "
            "(rewards-distribution-duplicate-pool-fire12, "
            "rewards-distribution-skew)."
        ),
    }


def run(tree, source: bytes, filepath: str):  # noqa: ARG001
    text = source_nocomment(source)
    if not _has_full_pool_key(text):
        return []
    if not _POOL_REGISTRY_RE.search(text):
        return []

    reward_maps = _reward_pair_maps(text)
    if not reward_maps:
        return []

    hits = []
    for fn_name, fn_start, body in _iter_pool_key_reward_fns(text):
        if _CANONICAL_PAIR_GUARD_RE.search(body):
            continue
        if not _PAIR_FROM_POOL_KEY_RE.search(body):
            continue
        for reward_map in reward_maps:
            reward_lookup = re.compile(
                rf"\b{re.escape(reward_map)}\s*\.\s*(?:get|entry)\s*\(\s*&?\s*pair\s*\)",
                re.IGNORECASE,
            )
            if reward_lookup.search(body):
                hits.append(_hit(filepath, text, fn_start, fn_name))
                break
    return hits
