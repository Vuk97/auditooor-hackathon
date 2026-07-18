"""
admin_privileged_effect_missing_guard_fire16.py

Rust admin-bypass lift from Solidity access-control failures.

Flags public Rust handlers that perform a privileged effect, such as an
upgrade/config write, whitelist mutation, or role grant, before any root,
owner, admin, authority, or role authorization guard appears.

The detector is intentionally source-shape based:
  - find public Rust functions
  - find sensitive mutation targets and write APIs
  - require privileged naming or privileged state vocabulary
  - require the authorization guard to appear before the first sensitive write

Detector hits are candidate evidence only and need normal R40/R76/R80 proof
discipline before any filing work.
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


DETECTOR_ID = "rust_wave1.admin_privileged_effect_missing_guard_fire16"

_SKIP_DIRS = {"target", ".git", "node_modules", "vendor", "_archive"}

_PRIVILEGED_NAME_RE = re.compile(
    r"(?i)(^|_)(set|update|configure|force|grant|revoke|rotate|change|"
    r"upgrade|migrate|pause|unpause|allow|deny|whitelist|blacklist|"
    r"add|remove|register|sudo)(_|\b)|"
    r"(admin|owner|authority|operator|governance|governor|role|"
    r"permission|access|whitelist|allowlist|denylist|blacklist|config|"
    r"params|upgrade|oracle|treasury|guardian|council)"
)

_SENSITIVE_TARGET_RE = re.compile(
    r"(?i)(admin|owner|authority|operator|governance|governor|role|"
    r"roles|permission|permissions|access|whitelist|allowlist|denylist|"
    r"blacklist|config|params|oracle|treasury|guardian|council|pause|"
    r"paused|upgrade|code_id|code_hash|runtime|route|fee|limit)"
)

_WRITE_RE = re.compile(
    r"(?xs)"
    r"(?P<assoc>[A-Za-z_][A-Za-z0-9_:]*)\s*::\s*"
    r"(?:<[^>]+>\s*::\s*)?"
    r"(?P<assoc_method>put|insert|mutate|try_mutate|remove|kill|set)\s*\("
    r"|"
    r"\b(?P<item>[A-Za-z_][A-Za-z0-9_]*)\s*\.\s*"
    r"(?P<item_method>save|update|insert|remove|replace|set)\s*\("
    r"|"
    r"\b(?P<receiver>self|ctx\s*\.\s*accounts\s*\.\s*[A-Za-z_][A-Za-z0-9_]*|"
    r"[A-Za-z_][A-Za-z0-9_]*)\s*\.\s*"
    r"(?P<field>[A-Za-z_][A-Za-z0-9_]*)\s*"
    r"(?:=|\.insert\s*\(|\.set\s*\(|\.remove\s*\(|\.push\s*\()"
)

_ROOT_OR_ROLE_GUARD_RE = re.compile(
    r"(?is)("
    r"ensure_root\s*\(|"
    r"ensure_origin\s*\(|"
    r"RawOrigin\s*::\s*Root|"
    r"(?:Admin|Governance|Council|Root|Sudo)Origin\s*::\s*ensure_origin|"
    r"T::(?:Admin|Governance|Council|Root|Sudo)Origin\s*::\s*ensure_origin|"
    r"\b(?:only|check|require|assert|ensure)_(?:admin|owner|governance|"
    r"authority|operator|role|root)\s*\(|"
    r"\b(?:admin|owner|authority|operator|governance|role)_guard\s*\(|"
    r"\bhas_role\s*\(|"
    r"\bis_(?:admin|owner|operator|governance|root)\s*\(|"
    r"(?:admin|owner|authority|operator|governance)\s*\.\s*require_auth\s*\("
    r")"
)

_COMPARE_GUARD_RE = re.compile(
    r"(?is)("
    r"(?:ensure|require|assert)(?:_eq|_ne)?!?\s*\([^;]{0,360}"
    r"(?:caller|sender|signer|authority|who|info\s*\.\s*sender|ctx\s*\.\s*accounts)"
    r"[^;]{0,360}(?:==|!=|has_role|contains|is_admin|is_owner|is_operator)"
    r"[^;]{0,360}(?:admin|owner|authority|operator|governance|role)|"
    r"\bif\s+[^{}]{0,320}"
    r"(?:caller|sender|signer|authority|who|info\s*\.\s*sender)"
    r"[^{}]{0,320}(?:==|!=)[^{}]{0,320}"
    r"(?:admin|owner|authority|operator|governance|role)[^{}]*\{"
    r"[^{}]{0,320}(?:return\s+Err|Err\s*\(|bail!\s*\()"
    r")"
)

_SIGNED_BINDING_RE = re.compile(
    r"\blet\s+(?P<who>who|caller|sender|account|account_id|authority)\s*="
    r"\s*ensure_signed\s*\(\s*origin\s*\)\s*\?"
)

_SIGNED_AUTH_RE = re.compile(
    r"(?is)("
    r"ensure!\s*\([^;]*(?:who|caller|sender|account|account_id|authority)"
    r"[^;]*(?:==|!=|has_role|contains|is_admin|is_owner|is_operator)"
    r"[^;]*(?:admin|owner|authority|operator|governance|role)|"
    r"(?:Admins|Owners|Authorities|Operators|Roles|Members)::\s*"
    r"(?:<[^>]+>\s*::\s*)?(?:contains_key|get)\s*\([^;]*"
    r"(?:who|caller|sender|account|account_id|authority)"
    r")"
)

_AUTH_CARRIER_RE = re.compile(
    r"(?i)\b(origin|caller|sender|signer|authority|admin|owner|ctx|info)\b"
)

_ANCHOR_CONTEXT_RE = re.compile(
    r"\bContext\s*<\s*([A-Za-z_][A-Za-z0-9_]*)\s*>"
)
_ANCHOR_AUTH_RE = re.compile(
    r"(?is)(Signer\s*<|has_one\s*=|constraint\s*=[^,\)]*"
    r"(?:admin|owner|authority|operator)|require_keys_eq!\s*\(|"
    r"assert_keys_eq!\s*\()"
)

_COMMENT_RE = re.compile(r"//[^\n]*|/\*.*?\*/", re.DOTALL)
_PUB_FN_RE = re.compile(r"\bpub\s+fn\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(")


def _signature_text(fn, source: bytes) -> str:
    return text_of(fn, source).split("{", 1)[0]


def _extract_braced_body(text: str, open_pos: int) -> str:
    depth = 0
    start = None
    for idx in range(open_pos, len(text)):
        ch = text[idx]
        if ch == "{":
            depth += 1
            if depth == 1:
                start = idx + 1
        elif ch == "}":
            depth -= 1
            if depth == 0 and start is not None:
                return text[start:idx]
    return ""


def _anchor_context_has_guard(signature: str, source_text: str) -> bool:
    for ctx_name in _ANCHOR_CONTEXT_RE.findall(signature):
        struct_match = re.search(r"\bstruct\s+" + re.escape(ctx_name) + r"\b", source_text)
        if struct_match is None:
            continue
        open_pos = source_text.find("{", struct_match.end())
        if open_pos == -1:
            continue
        if _ANCHOR_AUTH_RE.search(_extract_braced_body(source_text, open_pos)):
            return True
    return False


def _write_sites(body_text: str) -> list[tuple[int, str, str]]:
    sites: list[tuple[int, str, str]] = []
    for match in _WRITE_RE.finditer(body_text):
        target = (
            match.group("assoc")
            or match.group("item")
            or match.group("field")
            or ""
        )
        method = (
            match.group("assoc_method")
            or match.group("item_method")
            or "assign"
        )
        if _SENSITIVE_TARGET_RE.search(target):
            sites.append((match.start(), target, method))
    return sites


def _looks_privileged(name: str, body_text: str, sites: list[tuple[int, str, str]]) -> bool:
    if not sites:
        return False
    if _PRIVILEGED_NAME_RE.search(name):
        return True
    return bool(_SENSITIVE_TARGET_RE.search(body_text))


def _has_guard_before_write(
    *,
    prefix: str,
    signature: str,
    body_text: str,
    source_text: str,
) -> bool:
    joined_prefix = signature + "\n" + prefix
    if _ROOT_OR_ROLE_GUARD_RE.search(joined_prefix):
        return True
    if _COMPARE_GUARD_RE.search(prefix):
        return True
    if _SIGNED_BINDING_RE.search(prefix) and _SIGNED_AUTH_RE.search(prefix):
        return True
    if _anchor_context_has_guard(signature, source_text):
        return True
    if _ROOT_OR_ROLE_GUARD_RE.search(body_text):
        guard_match = _ROOT_OR_ROLE_GUARD_RE.search(body_text)
        return bool(guard_match and guard_match.start() < len(prefix))
    return False


def _guard_reason(signature: str) -> str:
    if _AUTH_CARRIER_RE.search(signature):
        return "authorization carrier exists but is not checked before the privileged effect"
    return "no caller, origin, signer, owner, authority, or role carrier reaches the privileged effect"


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
            f"pub fn `{name}` performs privileged `{target}` mutation via "
            f"`{method}` before any admin, owner, authority, root, or role "
            f"guard: {reason}. This is an admin-bypass candidate."
        ),
    }


def run(tree, source: bytes, filepath: str):
    hits = []
    source_text = _COMMENT_RE.sub("", source.decode("utf-8", errors="replace"))

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
        sites = _write_sites(body_nc)
        if not _looks_privileged(name, body_nc, sites):
            continue

        first_pos, target, method = sorted(sites, key=lambda item: item[0])[0]
        signature = _signature_text(fn, source)
        if _has_guard_before_write(
            prefix=body_nc[:first_pos],
            signature=signature,
            body_text=body_nc,
            source_text=source_text,
        ):
            continue

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
        sites = _write_sites(body_text)
        if not _looks_privileged(name, body_text, sites):
            continue

        first_pos, target, method = sorted(sites, key=lambda item: item[0])[0]
        if _has_guard_before_write(
            prefix=body_text[:first_pos],
            signature=signature,
            body_text=body_text,
            source_text=source_nc,
        ):
            continue

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
