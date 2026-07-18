"""
r94_loop_aa_limit_module_bypass_via_executor_entrypoint.py

Flags ERC-4337 / ERC-6900 spend-limit modules that track native
token / gas spend only inside a validateUserOp-style hook but do
NOT also track it in the execution-layer entrypoint
(execute / executeFromExecutor / executeBatch). An attacker invokes
the executor path directly, skipping the hook, and the limit is
never enforced.

Source: Solodit #58888 (Quantstamp Alchemy Modular Account V2
NativeTokenLimitModule).
Class: aa-limit-module-bypass-via-executor-entrypoint (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment

# Detector fires on the executor entrypoint fn that spends/transfers
# native value without a limit-module hook call.
_FN_NAME_RE = re.compile(
    r"(?i)(execute_from_executor|execute_batch|execute_user_op|"
    r"execute_call|execute|execute_single|execute_direct)"
)
_NATIVE_SPEND_RE = re.compile(
    r"(?i)(\btransfer\s*\(|\.\s*call\s*\{?\s*value|"
    r"\.\s*send\s*\(|native_transfer|send_native|"
    r"pay\s*\(|\.\s*transfer_native|pay_value)"
)
# Safe: module hook / pre-exec hook / limit check.
_HOOK_RE = re.compile(
    r"(?i)(nativeTokenLimit|native_token_limit|"
    r"preExecutionHook|pre_execution_hook|pre_exec_hook|"
    r"validate_limit|spend_limit_check|update_spend|"
    r"track_spend|record_spend|check_limit|"
    r"spending_limit|per_tx_limit)"
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
        if not _NATIVE_SPEND_RE.search(body_nc):
            continue
        if _HOOK_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` is an executor entrypoint that "
                f"transfers / sends native value without invoking a "
                f"spend-limit module hook — attacker bypasses the "
                f"validateUserOp-side NativeTokenLimitModule by "
                f"going through the executor path "
                f"(aa-limit-module-bypass-via-executor-entrypoint). "
                f"See Solodit #58888 (Quantstamp Alchemy Modular V2)."
            ),
        })
    return hits
