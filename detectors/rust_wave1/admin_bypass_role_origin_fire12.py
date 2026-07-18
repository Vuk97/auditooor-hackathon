"""
admin_bypass_role_origin_fire12.py

Flags Rust public functions that mutate admin, role, delegation, or
configuration state without a real caller, origin, signer, owner, or role
authorization guard.

Confirmed source fixtures:
  - admin_origin_or_role_guard_missing_positive.rs
  - boostcontroller_updateuserboost_lacks_access_control_delegation_overwrite_dos_positive.rs

This is a same-class companion detector. It intentionally distinguishes
missing role or origin authorization from generic zero-address validation
gaps by requiring a sensitive role/config/delegation write target.
"""

from __future__ import annotations

import os
import pathlib
import re
import sys

from _util import (
    body_text_nocomment,
    fn_body,
    fn_name,
    function_items,
    in_test_cfg,
    is_pub,
    line_col,
    snippet_of,
    text_of,
)


DETECTOR_ID = "rust_wave1.admin_bypass_role_origin_fire12"

_SKIP_DIRS = {"target", ".git", "node_modules", "vendor", "_archive"}

_MUTATOR_NAME_RE = re.compile(
    r"(?i)(^|_)(set|update|grant|revoke|transfer|assign|force|rotate|"
    r"change|pause|unpause|sudo|add|remove|enable|disable|register|"
    r"configure)(_|\b)|"
    r"(admin|owner|authority|operator|governance|governor|role|"
    r"permission|delegat|boost|config|params)"
)

_SENSITIVE_TARGET_RE = re.compile(
    r"(?i)(admin|owner|authority|operator|governance|governor|role|"
    r"roles|permission|permissions|delegat|delegations|boost|boosts|"
    r"user_boost|config|params|oracle|treasury|pause|paused|upgrade|"
    r"runtime|route|limit|fee|guardian|council)"
)

_WRITE_RE = re.compile(
    r"(?xs)"
    r"(?P<storage>[A-Za-z_][A-Za-z0-9_:]*)\s*::\s*"
    r"(?:<[^>]+>\s*::\s*)?"
    r"(?P<storage_method>put|insert|mutate|try_mutate|remove|kill|set)\s*\("
    r"|"
    r"(?:self|ctx\s*\.\s*accounts\s*\.\s*[A-Za-z_][A-Za-z0-9_]*)"
    r"\s*\.\s*(?P<field>[A-Za-z_][A-Za-z0-9_]*)\s*"
    r"(?:\.\s*(?P<field_method>insert|set|remove)\s*\(|=)"
    r"|"
    r"\b(?P<map>[A-Za-z_][A-Za-z0-9_]*)\s*\.\s*"
    r"(?P<map_method>insert|set|remove)\s*\("
)

_ROOT_OR_ROLE_GUARD_RE = re.compile(
    r"(?is)("
    r"ensure_root\s*\(|"
    r"ensure_origin\s*\(|"
    r"RawOrigin\s*::\s*Root|"
    r"(?:Admin|Governance|Council|Root|Sudo)Origin\s*::\s*ensure_origin|"
    r"T::(?:Admin|Governance|Council|Root|Sudo)Origin\s*::\s*ensure_origin|"
    r"\.require_auth\s*\(|"
    r"\bhas_role\s*\(|"
    r"\b(?:only|check|require|assert)_(?:admin|owner|governance|"
    r"authority|operator|role)\s*\(|"
    r"\b(?:admin|owner|authority|operator|governance|role)_guard\s*\(|"
    r"Signer\s*<|"
    r"has_one\s*=|"
    r"constraint\s*="
    r")"
)

_SIGNED_RE = re.compile(
    r"\blet\s+(?P<who>who|caller|sender|account|account_id|authority)\s*="
    r"\s*ensure_signed\s*\(\s*origin\s*\)\s*\?"
)

_SIGNED_ROLE_CHECK_RE = re.compile(
    r"(?is)("
    r"ensure!\s*\([^;]*(?:who|caller|sender|account|account_id|authority)"
    r"[^;]*(?:==|!=|has_role|contains|is_admin|is_owner|is_operator)"
    r"[^;]*(?:admin|owner|authority|operator|governance|role|user_id)|"
    r"(?:Admins|Owners|Authorities|Operators|Roles|Members)::\s*"
    r"(?:<[^>]+>\s*::\s*)?(?:contains_key|get)\s*\([^;]*"
    r"(?:who|caller|sender|account|account_id|authority)"
    r")"
)

_CALLER_ROLE_CHECK_RE = re.compile(
    r"(?is)("
    r"\bif\s+[^{};]*(?:caller|sender|authority|signer)[^{};]*"
    r"(?:==|!=)[^{};]*(?:owner|admin|authority|operator|governance|"
    r"role|user_id|account_id)|"
    r"ensure!\s*\([^;]*(?:caller|sender|authority|signer)[^;]*"
    r"(?:==|!=|has_role|contains|is_admin|is_owner|is_operator)[^;]*"
    r"(?:owner|admin|authority|operator|governance|role|user_id)|"
    r"(?:return\s+Err|Err\s*\()[^;]*(?:unauthorized|forbidden|badorigin)"
    r")"
)

_AUTH_CARRIER_RE = re.compile(
    r"(?i)\b(origin|caller|sender|signer|authority|admin|owner|ctx)\b"
)

_COMMENT_RE = re.compile(r"//[^\n]*|/\*.*?\*/", re.DOTALL)
_PUB_FN_RE = re.compile(r"\bpub\s+fn\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(")


def _signature_text(fn, source: bytes) -> str:
    return text_of(fn, source).split("{", 1)[0]


def _has_real_guard(signature: str, body_text: str) -> bool:
    joined = signature + "\n" + body_text
    if _ROOT_OR_ROLE_GUARD_RE.search(joined):
        return True
    if _CALLER_ROLE_CHECK_RE.search(body_text):
        return True
    if _SIGNED_RE.search(body_text) and _SIGNED_ROLE_CHECK_RE.search(body_text):
        return True
    return False


def _sensitive_write_sites(body_text: str) -> list[tuple[str, str]]:
    sites: list[tuple[str, str]] = []
    for match in _WRITE_RE.finditer(body_text):
        target = (
            match.group("storage")
            or match.group("field")
            or match.group("map")
            or ""
        )
        method = (
            match.group("storage_method")
            or match.group("field_method")
            or match.group("map_method")
            or "assign"
        )
        if _SENSITIVE_TARGET_RE.search(target):
            sites.append((target, method))
    return sites


def _looks_like_mutator(name: str, write_sites: list[tuple[str, str]]) -> bool:
    if not write_sites:
        return False
    if _MUTATOR_NAME_RE.search(name):
        return True
    return any(_SENSITIVE_TARGET_RE.search(target) for target, _method in write_sites)


def _guard_reason(signature: str) -> str:
    if _AUTH_CARRIER_RE.search(signature):
        return "authorization carrier is not checked before the sensitive write"
    return "no caller, origin, signer, owner, or role parameter reaches the sensitive write"


def _build_hit(
    *,
    filepath: str,
    line: int,
    col: int,
    name: str,
    target: str,
    method: str,
    reason: str,
    snippet: str,
) -> dict:
    return {
        "detector_id": DETECTOR_ID,
        "severity": "high",
        "file": filepath,
        "line": line,
        "col": col,
        "fn_name": name,
        "write_target": target,
        "write_method": method,
        "snippet": snippet,
        "message": (
            f"pub fn `{name}` mutates `{target}` via `{method}` without a "
            f"real role or origin guard: {reason}. This is an admin-bypass "
            f"class issue, not a generic zero-address validation check."
        ),
    }


def run(tree, source: bytes, filepath: str):
    hits = []

    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue
        if not is_pub(fn, source):
            continue

        body = fn_body(fn)
        if body is None:
            continue

        name = fn_name(fn, source)
        body_nc = body_text_nocomment(body, source)
        write_sites = _sensitive_write_sites(body_nc)
        if not _looks_like_mutator(name, write_sites):
            continue

        signature = _signature_text(fn, source)
        if _has_real_guard(signature, body_nc):
            continue

        target, method = write_sites[0]
        line, col = line_col(fn)
        hits.append(_build_hit(
            filepath=filepath,
            line=line,
            col=col,
            name=name,
            target=target,
            method=method,
            reason=_guard_reason(signature),
            snippet=snippet_of(fn, source, 220),
        ))

    return hits


def _strip_comments(text: str) -> str:
    return _COMMENT_RE.sub("", text)


def _find_matching_brace(text: str, open_idx: int) -> int:
    depth = 0
    for idx in range(open_idx, len(text)):
        ch = text[idx]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return idx
    return -1


def _snippet(text: str, start: int, end: int, max_len: int = 220) -> str:
    out = " ".join(text[start:end].split())
    if len(out) > max_len:
        out = out[:max_len] + "..."
    return out


def _scan_source_text(source_text: str, filepath: str) -> list[dict]:
    source_nc = _strip_comments(source_text)
    hits = []
    for match in _PUB_FN_RE.finditer(source_nc):
        name = match.group("name")
        brace = source_nc.find("{", match.end())
        if brace == -1:
            continue
        end = _find_matching_brace(source_nc, brace)
        if end == -1:
            continue

        signature = source_nc[match.start():brace]
        body_text = source_nc[brace + 1:end]
        write_sites = _sensitive_write_sites(body_text)
        if not _looks_like_mutator(name, write_sites):
            continue
        if _has_real_guard(signature, body_text):
            continue

        target, method = write_sites[0]
        line = source_nc[:match.start()].count("\n") + 1
        last_newline = source_nc.rfind("\n", 0, match.start())
        col = match.start() if last_newline == -1 else match.start() - last_newline - 1
        hits.append(_build_hit(
            filepath=filepath,
            line=line,
            col=col,
            name=name,
            target=target,
            method=method,
            reason=_guard_reason(signature),
            snippet=_snippet(source_nc, match.start(), end + 1),
        ))
    return hits


def _parse_rust(source: bytes):
    try:
        from tree_sitter_language_pack import get_parser
    except Exception:
        return None
    return get_parser("rust").parse(source)


def scan_file(filepath: str) -> list[dict]:
    try:
        source = pathlib.Path(filepath).read_bytes()
    except OSError:
        return []
    tree = _parse_rust(source)
    if tree is None:
        return _scan_source_text(source.decode("utf-8", errors="replace"), filepath)
    return run(tree, source, filepath)


def scan(root: str) -> list[tuple[str, int, str]]:
    results = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for filename in filenames:
            if not filename.endswith(".rs"):
                continue
            path = os.path.join(dirpath, filename)
            for hit in scan_file(path):
                results.append((hit["file"], hit["line"], hit["message"]))
    return results


if __name__ == "__main__":
    root = sys.argv[1] if len(sys.argv) > 1 else "."
    for file_path, line, message in scan(root):
        print(f"{file_path}:{line}:{DETECTOR_ID}:{message}")
