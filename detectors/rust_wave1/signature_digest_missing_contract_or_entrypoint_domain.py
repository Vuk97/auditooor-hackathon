"""
signature_digest_missing_contract_or_entrypoint_domain.py

Flags Rust signed-action flows where two or more public entrypoints share the
same digest helper, verify signatures against that helper's output, mutate
state, and the shared helper omits both contract-domain and entrypoint/action
binding. The same signature can then replay across sibling entrypoints on the
same deployment.

This detector is intentionally narrow:
  1. Find a helper fn whose name looks like a digest/hash builder.
  2. Require the helper body to build a hash/digest.
  3. Require the helper body to omit contract-domain and entrypoint/action
     tokens such as `current_contract_address`, `contract_id`,
     `verifying_contract`, `entry_point`, `selector`, or `action_tag`.
  4. Require at least two distinct public state-mutating fns to call the same
     helper and verify a signature in their own body.

This avoids flagging single-entrypoint helpers or generic chain-id-only
detectors that are already covered elsewhere.
"""

from __future__ import annotations

import re

from _util import (
    body_text_nocomment,
    fn_body,
    fn_name,
    function_items,
    in_test_cfg,
    is_pub,
    line_col,
    snippet_of,
)


_HASH_HELPER_NAME_RE = re.compile(
    r"(?i)^(?:"
    r"(?:build_|compute_)?(?:action_|signed_)?(?:digest|hash)"
    r"|hash_(?:action|message|payload|intent|user_?op)"
    r"|(?:action|message|payload|intent|user_?op)_(?:digest|hash)"
    r")$"
)

_HASH_BUILD_RE = re.compile(
    r"(?i)("
    r"keccak256\s*\(|"
    r"sha256\s*\(|"
    r"blake2(?:b|s)?\s*\(|"
    r"\.finalize\s*\(|"
    r"env\.crypto\(\)\.sha256\s*\(|"
    r"env\.crypto\(\)\.keccak256\s*\("
    r")"
)

_DOMAIN_BINDING_RE = re.compile(
    r"(?i)\b("
    r"current_contract_address|"
    r"env\.current_contract_address|"
    r"contract_id|"
    r"verifying_contract|"
    r"entry_?point|"
    r"selector|"
    r"function_selector|"
    r"action_tag|"
    r"action_type|"
    r"method_tag|"
    r"domain_separator"
    r")\b"
)

_SIG_VERIFY_RE = re.compile(
    r"(?i)("
    r"ed25519_verify|"
    r"secp256k1_recover|"
    r"secp256r1_verify|"
    r"\.verify_sig\b|"
    r"\.verify_signature\b"
    r")"
)

_STATE_MUTATION_RE = re.compile(
    r"(?i)("
    r"\.set\s*\(|"
    r"\.insert\s*\(|"
    r"\.transfer\s*\(|"
    r"\.mint\s*\(|"
    r"\.burn\s*\(|"
    r"\.invoke_contract\s*\(|"
    r"\.push_back\s*\(|"
    r"\.remove\s*\("
    r")"
)


def _called_hash_helpers(body_text: str) -> set[str]:
    return {
        match.group("name")
        for match in re.finditer(
            r"\b(?P<name>(?:build_|compute_)?(?:action_|signed_)?(?:digest|hash)"
            r"|hash_(?:action|message|payload|intent|user_?op)"
            r"|(?:action|message|payload|intent|user_?op)_(?:digest|hash))\s*\(",
            body_text,
            re.IGNORECASE,
        )
    }


def run(tree, source: bytes, filepath: str):
    helper_info: dict[str, dict[str, object]] = {}
    consumer_map: dict[str, list[dict[str, object]]] = {}

    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue
        name = fn_name(fn, source)
        body = fn_body(fn)
        if body is None:
            continue
        body_text = body_text_nocomment(body, source)

        if _HASH_HELPER_NAME_RE.search(name) and _HASH_BUILD_RE.search(body_text):
            helper_info[name] = {
                "node": fn,
                "body_text": body_text,
            }

        if not is_pub(fn, source):
            continue
        if not _SIG_VERIFY_RE.search(body_text):
            continue
        if not _STATE_MUTATION_RE.search(body_text):
            continue

        for helper_name in _called_hash_helpers(body_text):
            consumer_map.setdefault(helper_name, []).append(
                {
                    "fn_name": name,
                    "node": fn,
                }
            )

    hits = []
    for helper_name, consumers in consumer_map.items():
        info = helper_info.get(helper_name)
        if info is None:
            continue
        distinct_callers = {str(row["fn_name"]) for row in consumers}
        if len(distinct_callers) < 2:
            continue

        body_text = str(info["body_text"])
        if _DOMAIN_BINDING_RE.search(body_text):
            continue

        helper_node = info["node"]
        line, col = line_col(helper_node)
        hits.append(
            {
                "severity": "high",
                "line": line,
                "col": col,
                "snippet": snippet_of(helper_node, source),
                "message": (
                    f"shared digest helper `{helper_name}` is consumed by multiple "
                    f"public signature-verifying entrypoints "
                    f"({', '.join(sorted(distinct_callers))}) but the helper does "
                    f"not bind any contract or entrypoint domain token "
                    f"(`current_contract_address`, `contract_id`, "
                    f"`verifying_contract`, `entry_point`, `selector`, "
                    f"`action_tag`). A signature for one entrypoint can replay "
                    f"against its sibling."
                ),
            }
        )

    return hits
