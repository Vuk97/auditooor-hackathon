"""
rust_substrate_origin_privileged_effect_missing_guard.py

Flags Substrate dispatchables that accept an OriginFor<T> argument, discard or
ignore that origin, then perform privileged runtime state changes.

This covers a narrower recall gap than admin_origin_or_role_guard_missing:
the function name may be routine, but the effect is privileged. Examples are
global bridge route toggles, outbound caps, runtime code changes, validator
limits, or other system-wide settings that are reachable from a public
dispatchable without ensure_root or ensure_signed plus an owner or role check.

Confirmed class: admin-bypass / origin-bypass.
Source memory: realworld recall admin-bypass packet and cross-language
access-control lift both point to missing authorization on privileged state
transitions as the invariant.
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
    source_nocomment,
    text_of,
)


DETECTOR_ID = "rust_wave1.rust_substrate_origin_privileged_effect_missing_guard"

_SKIP_DIRS = {"target", ".git", "node_modules", "vendor", "_archive"}

_SUBSTRATE_MARKER_RE = re.compile(
    r"(?s)(#\[\s*pallet::call\s*\]|OriginFor\s*<|frame_support|"
    r"DispatchResult|StorageValue\s*<|StorageMap\s*<)"
)

_ORIGIN_PARAM_RE = re.compile(
    r"\b_?origin\s*:\s*(?:T::)?OriginFor\s*<|\b_?origin\s*:\s*RawOrigin"
)

_ORIGIN_DISCARDED_RE = re.compile(
    r"(?s)(\blet\s+_\s*=\s*origin\s*;|\bdrop\s*\(\s*origin\s*\)|"
    r"\b_origin\s*:)"
)

_ROOT_GUARD_RE = re.compile(
    r"(?s)(ensure_root\s*\(\s*origin\s*\)|ensure_origin\s*\(|"
    r"RawOrigin\s*::\s*Root|EnsureRoot\s*<|"
    r"(?:Admin|Governance|Council|Root|Sudo)Origin\s*::\s*ensure_origin|"
    r"T::(?:Admin|Governance|Council|Root|Sudo)Origin\s*::\s*ensure_origin)"
)

_SIGNED_RE = re.compile(
    r"\blet\s+(?P<who>who|caller|sender|account|account_id)\s*=\s*"
    r"ensure_signed\s*\(\s*origin\s*\)\s*\?"
)

_SIGNED_ROLE_CHECK_RE = re.compile(
    r"(?s)("
    r"ensure!\s*\([^;]*(?:who|caller|sender|account|account_id)[^;]*"
    r"(?:admin|owner|authority|operator|governance|council|role)|"
    r"(?:owner|admin|authority|operator|governance)\s*=.*?::get\s*\(\s*\).*?"
    r"ensure!\s*\([^;]*(?:who|caller|sender|account|account_id)\s*==\s*"
    r"(?:owner|admin|authority|operator|governance)|"
    r"(?:Owners|Admins|Authorities|Operators|Council|Members)::\s*<[^>]+>\s*"
    r"::\s*(?:contains_key|get)\s*\(\s*&?(?:who|caller|sender|account|account_id)"
    r")"
)

_WRITE_RE = re.compile(
    r"(?P<target>[A-Za-z_][A-Za-z0-9_:]*)\s*::\s*"
    r"(?:<[^>]+>\s*::\s*)?"
    r"(?P<method>put|insert|mutate|try_mutate|remove|kill|set_code|"
    r"set_storage|force_set_balance|force_transfer)\s*\("
)

_PRIVILEGED_EFFECT_RE = re.compile(
    r"(?i)(admin|owner|authority|govern|root|sudo|force|bridge|egress|"
    r"ingress|route|global|runtime|parameter|params|limit|max|min|"
    r"threshold|fee|treasury|oracle|operator|validator|guardian|pause|"
    r"halt|frozen|freeze|enabled|disabled|allow|deny|upgrade|code|asset|"
    r"mode|emergency|withdraw|deposit|outbound|inbound)"
)

_LINE_COMMENT_RE = re.compile(r"//[^\n]*")
_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)
_PUB_FN_RE = re.compile(r"\bpub\s+fn\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(")


def _strip_comments(text: str) -> str:
    text = _LINE_COMMENT_RE.sub("", text)
    text = _BLOCK_COMMENT_RE.sub("", text)
    return text


def _signature_text(fn, source: bytes) -> str:
    return text_of(fn, source).split("{", 1)[0]


def _has_origin_param_text(signature: str) -> bool:
    return bool(_ORIGIN_PARAM_RE.search(signature))


def _has_origin_param(fn, source: bytes) -> bool:
    return _has_origin_param_text(_signature_text(fn, source))


def _origin_is_ignored_text(signature: str, body_text: str) -> bool:
    if "_origin" in signature:
        return True
    if _ORIGIN_DISCARDED_RE.search(body_text):
        return True
    return "origin" not in body_text


def _origin_is_ignored(fn, body_text: str, source: bytes) -> bool:
    return _origin_is_ignored_text(_signature_text(fn, source), body_text)


def _has_privileged_guard(body_text: str) -> bool:
    if _ROOT_GUARD_RE.search(body_text):
        return True
    if not _SIGNED_RE.search(body_text):
        return False
    return bool(_SIGNED_ROLE_CHECK_RE.search(body_text))


def _privileged_write_sites(body_text: str) -> list[tuple[str, str]]:
    sites: list[tuple[str, str]] = []
    for match in _WRITE_RE.finditer(body_text):
        target = match.group("target")
        method = match.group("method")
        if method.startswith("force_") or method in {"set_code", "set_storage"}:
            sites.append((target, method))
            continue
        if _PRIVILEGED_EFFECT_RE.search(target):
            sites.append((target, method))
    return sites


def _supported_surface(source_text: str) -> bool:
    return bool(_SUBSTRATE_MARKER_RE.search(source_text))


def _build_hit(
    *,
    filepath: str,
    line: int,
    col: int,
    name: str,
    target: str,
    method: str,
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
            f"Substrate dispatchable `{name}` ignores `origin` and writes "
            f"privileged runtime state via `{target}::{method}` without "
            f"ensure_root or ensure_signed plus an owner or role check."
        ),
    }


def run(tree, source: bytes, filepath: str):
    hits = []
    source_text = source_nocomment(source)
    if not _supported_surface(source_text):
        return hits

    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue
        if not is_pub(fn, source):
            continue
        if not _has_origin_param(fn, source):
            continue

        body = fn_body(fn)
        if body is None:
            continue

        body_nc = body_text_nocomment(body, source)
        if _has_privileged_guard(body_nc):
            continue

        write_sites = _privileged_write_sites(body_nc)
        if not write_sites:
            continue
        if not _origin_is_ignored(fn, body_nc, source):
            continue

        name = fn_name(fn, source)
        line, col = line_col(fn)
        target, method = write_sites[0]
        hits.append(_build_hit(
            filepath=filepath,
            line=line,
            col=col,
            name=name,
            target=target,
            method=method,
            snippet=snippet_of(fn, source, 220),
        ))

    return hits


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
    if not _supported_surface(source_nc):
        return []

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
        if not _has_origin_param_text(signature):
            continue
        if _has_privileged_guard(body_text):
            continue
        write_sites = _privileged_write_sites(body_text)
        if not write_sites:
            continue
        if not _origin_is_ignored_text(signature, body_text):
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
