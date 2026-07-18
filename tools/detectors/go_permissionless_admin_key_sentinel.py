#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple


SCHEMA = "auditooor.go_permissionless_admin_key_sentinel.v1"


# Function declaration with optional receiver.
FUNC_DECL_RE = re.compile(
    r"^\s*func\s+(?:\((?P<recv>[^)]*)\)\s+)?(?P<name>[A-Za-z_][\w]*)\s*\("
)

COMMENT_LINE_RE = re.compile(r"^\s*(//|/\*|\*)")

# MsgServer-ish receiver type names (broad - default mode).
MSGSERVER_TYPE_RE = re.compile(
    r"(?i)(msgServer|MsgServer|Keeper|Server|Msg_Server)$"
)

# Genuine MsgServer entrypoint receiver: only the conventional Cosmos MsgServer
# struct name. Used by --entrypoints-only to EXCLUDE bare Keeper/Server receivers
# which are internal helpers guarded at the dispatch layer above.
ENTRYPOINT_RECEIVER_RE = re.compile(
    r"(?i)(msgServer|Msg_Server)$"
)

# State-write idioms found in cosmos-sdk modules.
STATE_WRITE_RE = re.compile(
    r"\b("
    r"[A-Za-z_][\w]*\.Set[A-Z][\w]*\(|"          # k.SetParams(, k.SetFoo(
    r"[A-Za-z_][\w]*\.Store[A-Z][\w]*\(|"        # k.StoreFoo(
    r"[A-Za-z_][\w]*\.Delete[A-Z][\w]*\(|"       # k.DeleteFoo(
    r"\bstore\.Set\(|"                            # store.Set(
    r"\bstore\.Delete\(|"                         # store.Delete(
    r"[A-Za-z_][\w]*\.Append\(|"                  # collection.Append(
    r"[A-Za-z_][\w]*\.Remove\(|"                  # collection.Remove(
    r"[A-Za-z_][\w]*\.Update[A-Z][\w]*\("         # k.UpdateFoo(
    r")"
)

# Authority-check idioms — any of these in the body means "guarded".
AUTHORITY_CHECK_RE = re.compile(
    r"\b("
    r"[A-Za-z_][\w]*\.authority\b|"
    r"[A-Za-z_][\w]*\.Authority\b|"
    r"GetAuthority\(|"
    r"Authenticate\(|"
    r"checkAuthority\(|"
    r"CheckAuthority\(|"
    r"requireAuthority\(|"
    r"RequireGovernance\(|"
    r"AssertAuthority\(|"
    r"AssertSigner\(|"
    r"sdk\.AccAddress\(.*authority|"
    r"govtypes\.[A-Za-z_][\w]*Authority\b|"
    r"ms\.k\.authority\b|"
    r"ms\.authority\b|"
    r"k\.authority\b|"
    r"msg\.Authority\s*!=|"
    r"msg\.Authority\s*=="
    r")"
)

# Admin-key field names (for Pattern B clustering).
ADMIN_FIELD_RE = re.compile(
    r"\b("
    r"[A-Za-z_][\w]*\.Authority\b|"
    r"[A-Za-z_][\w]*\.Admin\b|"
    r"[A-Za-z_][\w]*\.Owner\b|"
    r"[A-Za-z_][\w]*KeeperAuthority\b|"
    r"GetAuthority\(\)"
    r")"
)


@dataclass
class Sentinel:
    file: str
    line: int
    method: str
    pattern: str   # "A" or "B"
    evidence: str
    severity_hint: str
    receiver: str = ""  # receiver type name extracted at emit time (additive)


def _strip_strings_and_comments(line: str) -> str:
    out = []
    i = 0
    in_str = None
    while i < len(line):
        c = line[i]
        if in_str:
            if c == "\\" and i + 1 < len(line):
                i += 2
                continue
            if c == in_str:
                in_str = None
            i += 1
            continue
        if c == '"' or c == "'" or c == "`":
            in_str = c
            i += 1
            continue
        if c == "/" and i + 1 < len(line) and line[i + 1] == "/":
            break
        out.append(c)
        i += 1
    return "".join(out)


def _iter_funcs(lines: List[str]):
    """Yield (name, decl_line_idx, body_start_idx, body_end_idx, recv)."""
    i = 0
    n = len(lines)
    while i < n:
        m = FUNC_DECL_RE.match(lines[i])
        if not m:
            i += 1
            continue
        name = m.group("name")
        recv = m.group("recv") or ""
        depth = 0
        body_start = -1
        j = i
        opened = False
        while j < n:
            stripped = _strip_strings_and_comments(lines[j])
            advanced = False
            for ch in stripped:
                if ch == "{":
                    if not opened:
                        opened = True
                        body_start = j
                    depth += 1
                elif ch == "}":
                    depth -= 1
                    if opened and depth == 0:
                        yield name, i, body_start, j, recv
                        i = j + 1
                        advanced = True
                        break
            if advanced:
                break
            j += 1
        else:
            return
        if not advanced:
            return


def _is_msgserver_method(recv: str, *, entrypoints_only: bool = False) -> bool:
    """Receiver looks like msgServer / Keeper / Server.

    When entrypoints_only=True only the conventional Cosmos MsgServer struct
    receiver (`msgServer` / `Msg_Server`) is accepted.  Bare `Keeper` /
    `Server` receivers are EXCLUDED because those are internal state-writing
    helpers whose authorization is enforced at the registered Msg handler one
    layer above - not genuine public entrypoints.
    """
    if not recv:
        return False
    parts = recv.split()
    if not parts:
        return False
    tname = parts[-1].lstrip("*")
    pattern = ENTRYPOINT_RECEIVER_RE if entrypoints_only else MSGSERVER_TYPE_RE
    return bool(pattern.search(tname))


def _is_exported(name: str) -> bool:
    return bool(name) and name[0].isupper()


def _body_text(lines: List[str], body_start: int, body_end: int) -> List[Tuple[int, str]]:
    """Return (line_idx, stripped-line) tuples for body lines."""
    out: List[Tuple[int, str]] = []
    for k in range(body_start + 1, body_end):
        raw = lines[k]
        if COMMENT_LINE_RE.match(raw):
            continue
        out.append((k, _strip_strings_and_comments(raw)))
    return out


def _extract_receiver_type(recv: str) -> str:
    """Extract the bare receiver type name from a Go receiver declaration.

    E.g. ``ms *msgServer`` -> ``msgServer``, ``k Keeper`` -> ``Keeper``.
    """
    parts = recv.split()
    if not parts:
        return ""
    return parts[-1].lstrip("*")


def scan_file(path: Path, *, entrypoints_only: bool = False) -> List[Sentinel]:
    """Scan a single Go source file for permissionless admin / authority issues.

    Args:
        path: Path to the .go file to scan.
        entrypoints_only: When True, Pattern A fires ONLY when the receiver
            matches the genuine Cosmos MsgServer struct convention
            (``msgServer`` / ``Msg_Server``). Bare ``Keeper`` / ``Server``
            receivers are excluded in this mode because their authorization is
            enforced at the registered Msg handler one layer above.
            Default False preserves existing broad behavior.
    """
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except (OSError, UnicodeDecodeError):
        return []
    lines = text.splitlines()
    sentinels: List[Sentinel] = []

    # For Pattern B clustering: count msgServer methods referencing Authority/Admin/Owner.
    admin_refs: Dict[str, List[Tuple[str, int, str, str]]] = {}
    # key: field-name suffix ("Authority","Admin","Owner"),
    # value: list of (method, line, evidence, receiver_type)

    for name, decl_line, body_start, body_end, recv in _iter_funcs(lines):
        if not _is_msgserver_method(recv, entrypoints_only=entrypoints_only):
            continue
        if not _is_exported(name):
            continue
        recv_type = _extract_receiver_type(recv)
        body = _body_text(lines, body_start, body_end)

        # Pattern A: state write without authority check anywhere in body.
        write_hit: Optional[Tuple[int, str]] = None
        has_auth_check = False
        for idx, body_line in body:
            if AUTHORITY_CHECK_RE.search(body_line):
                has_auth_check = True
            if write_hit is None and STATE_WRITE_RE.search(body_line):
                write_hit = (idx, body_line)
        if write_hit and not has_auth_check:
            sentinels.append(
                Sentinel(
                    file=str(path),
                    line=write_hit[0] + 1,
                    method=name,
                    pattern="A",
                    evidence=write_hit[1].strip()[:240],
                    severity_hint="HIGH",
                    receiver=recv_type,
                )
            )

        # Pattern B: collect admin-field references per file.
        for idx, body_line in body:
            m = ADMIN_FIELD_RE.search(body_line)
            if not m:
                continue
            ref = m.group(0)
            # bucket by trailing field suffix
            if "Authority" in ref:
                key = "Authority"
            elif "Admin" in ref:
                key = "Admin"
            elif "Owner" in ref:
                key = "Owner"
            else:
                key = "Authority"
            admin_refs.setdefault(key, []).append((name, idx + 1, body_line.strip()[:240], recv_type))
            break  # one ref per method is enough to count it

    # Emit Pattern B sentinels: clusters with >=3 distinct methods.
    for key, refs in admin_refs.items():
        distinct_methods = {m for (m, _, _, _) in refs}
        if len(distinct_methods) < 3:
            continue
        # emit one sentinel per method in the cluster
        for method, line_no, ev, recv_type in refs:
            sentinels.append(
                Sentinel(
                    file=str(path),
                    line=line_no,
                    method=method,
                    pattern="B",
                    evidence=f"admin-field={key}; cluster_size={len(distinct_methods)}; ref={ev}",
                    severity_hint="MEDIUM",
                    receiver=recv_type,
                )
            )

    return sentinels


def walk_repo(root: Path) -> Iterable[Path]:
    for p in root.rglob("*.go"):
        parts = set(p.parts)
        if "vendor" in parts or "testdata" in parts:
            continue
        if p.name.endswith("_test.go"):
            continue
        if p.name.endswith(".pb.go") or p.name.endswith(".pb.gw.go"):
            continue
        yield p


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        description="Go detector: permissionless module + admin-key concentration sentinel"
    )
    ap.add_argument("repo", type=Path, help="repo root or single .go file to scan")
    ap.add_argument("--out", type=Path, default=None)
    ap.add_argument("--threshold", type=int, default=0, help="min sentinels to exit 0")
    ap.add_argument(
        "--entrypoints-only",
        action="store_true",
        default=False,
        help=(
            "Pattern A fires ONLY on genuine MsgServer entrypoint receivers "
            "(msgServer / Msg_Server). Bare Keeper/Server helpers are excluded "
            "because their authorization is enforced at the dispatch layer above. "
            "Default: False (broad behavior, all msgServer-ish receivers)."
        ),
    )
    args = ap.parse_args(argv)

    entrypoints_only: bool = args.entrypoints_only
    root = args.repo
    if not root.exists():
        print(f"error: {root} does not exist", file=sys.stderr)
        return 2

    sentinels: List[Sentinel] = []
    if root.is_file() and root.suffix == ".go":
        sentinels.extend(scan_file(root, entrypoints_only=entrypoints_only))
    else:
        for p in walk_repo(root):
            sentinels.extend(scan_file(p, entrypoints_only=entrypoints_only))

    payload = {
        "schema": SCHEMA,
        "root": str(root),
        "count": len(sentinels),
        "sentinels": [asdict(s) for s in sentinels],
    }
    out_text = json.dumps(payload, indent=2)
    if args.out:
        args.out.write_text(out_text, encoding="utf-8")
    else:
        print(out_text)
    if args.threshold and len(sentinels) < args.threshold:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
