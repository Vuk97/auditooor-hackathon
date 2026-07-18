"""
admin_auth_mutation_guard_fire17.py

Rust admin-bypass companion detector for Fire17 recall lift.

Flags public Rust entrypoints where a privileged mutation, replay path, or
cross-domain administrative effect executes before a caller, signer, endpoint,
owner, role, or nonce guard.

The detector is deliberately narrower than a generic "public setter" rule:
  - Soroban-style storage mutations must appear in admin/config/storage
    mutator entrypoints.
  - Cross-domain dispatches must carry message, nonce, endpoint, remote, or
    chain vocabulary and call an administrative effect or replay handler.
  - A clean fixture must include a real authorization guard before the effect.

Detector hits are candidate evidence only. They still require R40, R76, and
R80 proof discipline before any filing work.
"""

from __future__ import annotations

import os
import pathlib
import re
import sys
from typing import NamedTuple


DETECTOR_ID = "rust_wave1.admin_auth_mutation_guard_fire17"

_SKIP_DIRS = {"target", ".git", "node_modules", "vendor", "_archive"}

_COMMENT_RE = re.compile(r"//[^\n]*|/\*.*?\*/", re.DOTALL)
_PUB_FN_RE = re.compile(
    r"\bpub(?:\s*\([^)]*\))?\s+(?:async\s+)?fn\s+"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(",
    re.MULTILINE,
)

_PRIVILEGED_NAME_RE = re.compile(
    r"(?i)(^|_)(set|update|configure|force|grant|revoke|rotate|change|"
    r"upgrade|migrate|pause|unpause|allow|deny|whitelist|blacklist|"
    r"register|execute|dispatch|process|deliver|receive|retry|mint|burn|"
    r"release|sweep)(_|\b)|"
    r"(admin|owner|authority|operator|governance|governor|role|"
    r"permission|access|whitelist|allowlist|denylist|blacklist|config|"
    r"params|upgrade|oracle|treasury|guardian|endpoint|remote|nonce)"
)

_SENSITIVE_TARGET_RE = re.compile(
    r"(?i)(admin|owner|authority|operator|governance|governor|role|"
    r"roles|permission|permissions|access|whitelist|allowlist|denylist|"
    r"blacklist|config|params|oracle|treasury|guardian|council|pause|"
    r"paused|upgrade|code_id|code_hash|runtime|route|fee|limit|endpoint|"
    r"remote|nonce|message|bridge)"
)

_CROSS_DOMAIN_RE = re.compile(
    r"(?i)(src_chain|dst_chain|chain_id|nonce|payload|message|endpoint|"
    r"trusted_remote|remote|origin_chain|lz_|layerzero|bridge|proof)"
)

_SOROBAN_STORAGE_RE = re.compile(
    r"(?is)\benv\s*\.\s*storage\s*\(\)\s*\.\s*"
    r"(?:persistent|instance|temporary)\s*\(\)\s*\.\s*"
    r"(?P<method>set|update|remove|extend_ttl|extend_instance_ttl)\s*\("
)

_SENSITIVE_WRITE_RE = re.compile(
    r"(?xs)"
    r"(?P<assoc>[A-Za-z_][A-Za-z0-9_:]*)\s*::\s*"
    r"(?:<[^>]+>\s*::\s*)?"
    r"(?P<assoc_method>put|insert|mutate|try_mutate|remove|kill|set)\s*\("
    r"|"
    r"\b(?P<item>[A-Za-z_][A-Za-z0-9_]*)\s*\.\s*"
    r"(?P<item_method>save|update|insert|remove|replace|set)\s*\("
    r"|"
    r"\b(?P<receiver>self|ctx\s*\.\s*accounts\s*\.\s*"
    r"[A-Za-z_][A-Za-z0-9_]*|[A-Za-z_][A-Za-z0-9_]*)\s*\.\s*"
    r"(?P<field>[A-Za-z_][A-Za-z0-9_]*)\s*"
    r"(?:=|\.insert\s*\(|\.set\s*\(|\.remove\s*\(|\.push\s*\()"
)

_ADMIN_EFFECT_CALL_RE = re.compile(
    r"(?is)\b(?:self\s*\.\s*)?"
    r"(?P<method>"
    r"_?receive_?message|retry_?(?:failed|stuck)_?(?:message|msg)|"
    r"execute_?(?:admin_?)?(?:action|message|payload|command)|"
    r"dispatch_?(?:admin_?)?(?:action|message|payload|command)|"
    r"process_?(?:admin_?)?(?:action|message|payload|command)|"
    r"mint|burn|release_?funds|credit|debit|sweep"
    r")\s*\("
)

_AUTH_GUARD_RE = re.compile(
    r"(?is)("
    r"\.require_auth(?:_for_args)?\s*\(|"
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
    r"Signer\s*<|"
    r"has_one\s*=|"
    r"constraint\s*=|"
    r"require_keys_eq!\s*\(|"
    r"assert_keys_eq!\s*\("
    r")"
)

_COMPARE_GUARD_RE = re.compile(
    r"(?is)("
    r"(?:ensure|require|assert)(?:_eq|_ne)?!?\s*\([^;]{0,420}"
    r"(?:caller|sender|signer|authority|who|info\s*\.\s*sender|"
    r"ctx\s*\.\s*accounts)[^;]{0,420}"
    r"(?:==|!=|has_role|contains|is_admin|is_owner|is_operator)"
    r"[^;]{0,420}(?:admin|owner|authority|operator|governance|role|"
    r"endpoint|remote)|"
    r"\bif\s+[^{}]{0,360}"
    r"(?:caller|sender|signer|authority|who|info\s*\.\s*sender)"
    r"[^{}]{0,360}(?:==|!=)[^{}]{0,360}"
    r"(?:admin|owner|authority|operator|governance|role|endpoint|remote)"
    r"[^{}]*\{[^{}]{0,420}(?:return\s+Err|Err\s*\(|bail!\s*\()|"
    r"(?:processed_)?nonces?\s*\.\s*(?:get|contains_key)\s*\(|"
    r"MessageAlreadyProcessed|ReplayDetected|UnauthorizedEndpoint|"
    r"InvalidSender|trusted_remote|endpoint_address\s*\("
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
    r"(?i)\b(origin|caller|sender|signer|authority|admin|owner|ctx|info|from)\b"
)


class _Function(NamedTuple):
    name: str
    signature: str
    body: str
    full_source: str
    start: int
    end: int


class _Effect(NamedTuple):
    pos: int
    target: str
    method: str
    kind: str


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


def _iter_pub_functions(source_text: str):
    for match in _PUB_FN_RE.finditer(source_text):
        brace = source_text.find("{", match.end())
        if brace == -1:
            continue
        end = _find_matching_brace(source_text, brace)
        if end == -1:
            continue
        yield _Function(
            name=match.group("name"),
            signature=source_text[match.start():brace],
            body=source_text[brace + 1:end],
            full_source=source_text[match.start():end + 1],
            start=match.start(),
            end=end + 1,
        )


def _effect_sites(fn: _Function) -> list[_Effect]:
    body = fn.body
    sites: list[_Effect] = []

    for match in _SOROBAN_STORAGE_RE.finditer(body):
        sites.append(_Effect(
            pos=match.start(),
            target="env.storage",
            method=match.group("method"),
            kind="soroban-storage",
        ))

    for match in _SENSITIVE_WRITE_RE.finditer(body):
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
            sites.append(_Effect(
                pos=match.start(),
                target=target,
                method=method,
                kind="sensitive-write",
            ))

    domain_text = fn.signature + "\n" + fn.body + "\n" + fn.name
    if _CROSS_DOMAIN_RE.search(domain_text):
        for match in _ADMIN_EFFECT_CALL_RE.finditer(body):
            method = match.group("method")
            sites.append(_Effect(
                pos=match.start(),
                target=method,
                method="call",
                kind="cross-domain-effect",
            ))

    return sorted(sites, key=lambda item: item.pos)


def _looks_privileged(fn: _Function, effects: list[_Effect]) -> bool:
    if not effects:
        return False
    if _PRIVILEGED_NAME_RE.search(fn.name):
        return True
    text = fn.signature + "\n" + fn.body
    if any(effect.kind == "cross-domain-effect" for effect in effects):
        return bool(_CROSS_DOMAIN_RE.search(text))
    return bool(_SENSITIVE_TARGET_RE.search(text))


def _has_guard_before_effect(prefix: str, signature: str) -> bool:
    joined = signature + "\n" + prefix
    if _AUTH_GUARD_RE.search(joined):
        return True
    if _COMPARE_GUARD_RE.search(prefix):
        return True
    if _SIGNED_BINDING_RE.search(prefix) and _SIGNED_AUTH_RE.search(prefix):
        return True
    return False


def _guard_reason(signature: str) -> str:
    if _AUTH_CARRIER_RE.search(signature):
        return "authorization carrier exists but is not checked before the privileged effect"
    return "no caller, signer, origin, endpoint, owner, authority, or role carrier reaches the privileged effect"


def _line_col(source_text: str, pos: int) -> tuple[int, int]:
    line = source_text[:pos].count("\n") + 1
    last_newline = source_text.rfind("\n", 0, pos)
    col = pos if last_newline == -1 else pos - last_newline - 1
    return line, col


def _snippet(text: str, max_len: int = 220) -> str:
    out = " ".join(text.split())
    if len(out) > max_len:
        out = out[:max_len] + "..."
    return out


def _build_hit(
    *,
    filepath: str,
    line: int,
    col: int,
    fn: _Function,
    effect: _Effect,
) -> dict:
    return {
        "detector_id": DETECTOR_ID,
        "severity": "high",
        "file": filepath,
        "line": line,
        "col": col,
        "fn_name": fn.name,
        "effect_target": effect.target,
        "effect_method": effect.method,
        "effect_kind": effect.kind,
        "snippet": _snippet(fn.full_source),
        "message": (
            f"pub fn `{fn.name}` reaches privileged `{effect.target}` "
            f"{effect.kind} before a caller, signer, endpoint, owner, nonce, "
            f"or role guard: {_guard_reason(fn.signature)}. This is an "
            f"admin-bypass candidate."
        ),
    }


def _scan_source_text(source_text: str, filepath: str) -> list[dict]:
    hits = []
    clean_text = _strip_comments(source_text)
    for fn in _iter_pub_functions(clean_text):
        effects = _effect_sites(fn)
        if not _looks_privileged(fn, effects):
            continue
        first_effect = effects[0]
        if _has_guard_before_effect(fn.body[:first_effect.pos], fn.signature):
            continue
        line, col = _line_col(clean_text, fn.start)
        hits.append(_build_hit(
            filepath=filepath,
            line=line,
            col=col,
            fn=fn,
            effect=first_effect,
        ))
    return hits


def run(tree, source: bytes, filepath: str):  # noqa: ARG001
    return _scan_source_text(source.decode("utf-8", errors="replace"), filepath)


def scan_file(filepath: str) -> list[dict]:
    try:
        source_text = pathlib.Path(filepath).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    return _scan_source_text(source_text, filepath)


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
