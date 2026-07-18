"""
rust_bridge_conditional_auth_missing_fire29.py

Rust admin-bypass detector for bridge branch-asymmetry misses.

Flags public Rust bridge handlers where one receive, execute, route update,
signer swap, or relayer branch checks authority, while a sibling branch still
performs a privileged bridge effect without the same origin, relayer, signer,
admin, or authority guard.

Source refs:
  - reference/patterns.dsl/r94-loop-bridge-receive-message-conditional-auth-missing.yaml
  - reference/patterns.dsl/admin-bypass-umbrella.yaml
  - reference/big_loss_templates/bridge_proof_domain.json

Detector hits are candidate evidence only. They need normal R40, R76, and R80
proof discipline before filing work.
"""

from __future__ import annotations

import os
import pathlib
import re
import sys
from typing import NamedTuple


DETECTOR_ID = "rust_wave1.rust_bridge_conditional_auth_missing_fire29"

_SKIP_DIRS = {"target", ".git", "node_modules", "vendor", "_archive"}

_COMMENT_RE = re.compile(r"//[^\n]*|/\*.*?\*/", re.DOTALL)
_PUB_FN_RE = re.compile(
    r"\bpub(?:\s*\([^)]*\))?\s+(?:async\s+)?fn\s+"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(",
    re.MULTILINE,
)

_BRIDGE_NAME_RE = re.compile(
    r"(?i)(receive|handle|execute|process|relay|route|signer|relayer|"
    r"message|payload|packet|bridge)"
)

_BRIDGE_CONTEXT_RE = re.compile(
    r"(?i)\b(bridge|message|payload|packet|route|router|relayer|signer|"
    r"source_?chain|dest(?:ination)?_?chain|origin_?chain|remote|lane|"
    r"channel|proof|attestation|portal|withdrawal)\b"
)

_AUTH_GUARD_RE = re.compile(
    r"(?is)("
    r"\.require_auth(?:_for_args)?\s*\(|"
    r"\b(?:require|ensure|check|verify)_(?:bridge_?)?"
    r"(?:auth|authority|admin|owner|operator|relayer|signer|sender|origin)"
    r"\s*\(|"
    r"\bonly_(?:admin|owner|operator|relayer|signer|authority)\s*\(|"
    r"\bhas_role\s*\(|"
    r"\bis_(?:admin|owner|operator|relayer|signer|authority)\s*\(|"
    r"\bensure_root\s*\(|"
    r"\bensure_origin\s*\(|"
    r"\b(?:trusted_)?(?:relayers|signers|senders|origins)\s*\.\s*"
    r"(?:contains|contains_key|get)\s*\(|"
    r"\b(?:ensure|require|assert)(?:_eq|_ne)?!?\s*\([^;]{0,420}"
    r"(?:caller|sender|relayer|signer|authority|origin|who|info\s*\.\s*sender)"
    r"[^;]{0,420}(?:==|!=|has_role|contains|is_admin|is_owner|"
    r"is_operator|is_relayer|is_signer|is_authority|trusted)[^;]{0,420}"
    r"(?:admin|owner|operator|relayer|signer|authority|origin|role|trusted)"
    r")"
)

_PRIVILEGED_EFFECT_RE = re.compile(
    r"(?is)("
    r"\b(?:self\s*\.\s*)?(?:routes?|route_table|trusted_routes)\s*\.\s*"
    r"(?:insert|set|update|save|remove)\s*\(|"
    r"\b(?:Routes|RouteTable|TrustedRoutes|BridgeRoutes)::\s*"
    r"(?:<[^>]+>\s*::\s*)?(?:insert|put|mutate|try_mutate|set|remove)"
    r"\s*\(|"
    r"\b(?:self\s*\.\s*)?(?:trusted_)?(?:relayer|relayers|signer|signers|"
    r"authority|authorities|admin|admins|router|routers|operator|operators)"
    r"\s*(?:=|\.insert\s*\(|\.set\s*\(|\.remove\s*\(|\.push\s*\()|"
    r"\b(?:trusted_)?(?:relayers|signers|authorities|admins|operators)"
    r"\s*\.\s*(?:insert|set|remove|push)\s*\(|"
    r"\b(?:apply|update|replace|register|remove)_(?:route|relayer|signer|"
    r"authority|bridge_route)\s*\(|"
    r"\b(?:swap|rotate|set)_(?:signer|relayer|authority|router)\s*\(|"
    r"\b(?:execute|dispatch|process|apply)_(?:admin_?)?"
    r"(?:message|payload|packet|command|action|route_update)\s*\(|"
    r"\b(?:release_funds|mint_to|credit_recipient|finalize_withdrawal)"
    r"\s*\("
    r")"
)


class _Function(NamedTuple):
    name: str
    signature: str
    body: str
    full_source: str
    start: int
    end: int


class _Branch(NamedTuple):
    label: str
    text: str
    start: int
    end: int


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


def _branch_label(prefix: str) -> str:
    tail = prefix[-180:]
    if re.search(r"=>\s*$", tail):
        arm = re.search(
            r"([A-Za-z_][A-Za-z0-9_:]*(?:\s*\([^)]*\))?)\s*=>\s*$",
            tail,
        )
        if arm:
            return f"match-arm {arm.group(1)}"
        return "match-arm"
    if re.search(r"\belse\s*$", tail):
        return "else"
    if re.search(r"\bif\b[^{}]*$", tail):
        return "if"
    return ""


def _iter_branch_blocks(body: str) -> list[_Branch]:
    branches: list[_Branch] = []
    seen: set[tuple[int, int]] = set()
    search_pos = 0
    while True:
        open_idx = body.find("{", search_pos)
        if open_idx == -1:
            break
        close_idx = _find_matching_brace(body, open_idx)
        if close_idx == -1:
            break
        label = _branch_label(body[:open_idx])
        if label and (open_idx, close_idx) not in seen:
            branches.append(
                _Branch(
                    label=label,
                    text=body[open_idx + 1:close_idx],
                    start=open_idx,
                    end=close_idx + 1,
                )
            )
            seen.add((open_idx, close_idx))
        search_pos = open_idx + 1
    return branches


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


def _effect_terms(text: str) -> list[str]:
    terms: list[str] = []
    for match in _PRIVILEGED_EFFECT_RE.finditer(text):
        token = " ".join(match.group(0).strip().split())
        if len(token) > 60:
            token = token[:60] + "..."
        terms.append(token)
        if len(terms) == 3:
            break
    return terms


def _has_unconditional_guard(fn: _Function, branches: list[_Branch]) -> bool:
    first_branch = min((branch.start for branch in branches), default=len(fn.body))
    effect_match = _PRIVILEGED_EFFECT_RE.search(fn.body)
    first_effect = effect_match.start() if effect_match else len(fn.body)
    cutoff = min(first_branch, first_effect)
    prefix = fn.signature + "\n" + fn.body[:cutoff]
    return bool(_AUTH_GUARD_RE.search(prefix))


def _surface_matches(fn: _Function) -> bool:
    text = fn.signature + "\n" + fn.body
    return bool(_BRIDGE_NAME_RE.search(fn.name) or _BRIDGE_CONTEXT_RE.search(text))


def _scan_source_text(source_text: str, filepath: str) -> list[dict]:
    clean_text = _strip_comments(source_text)
    hits: list[dict] = []

    for fn in _iter_pub_functions(clean_text):
        if not _surface_matches(fn):
            continue

        branches = _iter_branch_blocks(fn.body)
        if len(branches) < 2:
            continue
        if _has_unconditional_guard(fn, branches):
            continue

        guarded: list[tuple[_Branch, list[str]]] = []
        unguarded: list[tuple[_Branch, list[str]]] = []
        for branch in branches:
            terms = _effect_terms(branch.text)
            if not terms:
                continue
            if _AUTH_GUARD_RE.search(branch.text):
                guarded.append((branch, terms))
            else:
                unguarded.append((branch, terms))

        if not guarded or not unguarded:
            continue

        line, col = _line_col(clean_text, fn.start)
        guarded_terms = ", ".join(guarded[0][1])
        unguarded_terms = ", ".join(unguarded[0][1])
        hits.append(
            {
                "detector_id": DETECTOR_ID,
                "severity": "high",
                "file": filepath,
                "line": line,
                "col": col,
                "fn_name": fn.name,
                "guarded_effect": guarded_terms,
                "unguarded_effect": unguarded_terms,
                "snippet": _snippet(fn.full_source),
                "message": (
                    f"pub fn `{fn.name}` has bridge authority checked only "
                    f"inside a {guarded[0][0].label} branch before "
                    f"`{guarded_terms}`, while sibling "
                    f"{unguarded[0][0].label} branch performs privileged "
                    f"`{unguarded_terms}` without the same relayer, signer, "
                    f"origin, admin, or authority guard."
                ),
            }
        )

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
    results: list[tuple[str, int, str]] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [dirname for dirname in dirnames if dirname not in _SKIP_DIRS]
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
