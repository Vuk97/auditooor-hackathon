#!/usr/bin/env python3
"""Go detector for unprotected first-writer initialization.

Source-backed lift:
- solodit:20968 records a tier-2 public archive finding where initializers
  could be front-run and the recommendation is to initialize atomically.
- solodit:50827 records a tier-2 public archive deployment sequence where a
  proxy is deployed and then initialized in a later transaction.
- solodit:64726 records a tier-2 public archive first-caller initializer shape
  where the boss field is set by the first signer when no authority check runs.

RELATED TOOLS:
- tools/detectors/go_ast_fee_redirect_user_controlled_sink.py: same standalone
  JSON scanner style, different attack class.
- tools/go-detector-runner.py: broad Go regex runner, not used here because this
  lane owns a narrow cross-language lift with focused fixtures.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable


SCHEMA = "auditooor.go_initializer_front_run_unprotected_first_writer.v1"

FUNC_DECL_RE = re.compile(
    r"^\s*func\s+(?:\((?P<recv>[^)]*)\)\s+)?(?P<name>[A-Za-z_]\w*)\s*\("
)

ENTRYPOINT_NAME_RE = re.compile(
    r"(?i)^(initialize|init|setup|bootstrap|configure|register|create|add|set|migrate)"
    r".*(owner|admin|boss|authority|role|peer|remote|gateway|route|chain|endpoint)?$"
)

FIRST_WRITER_GUARD_RES = (
    re.compile(r"(?i)\bAlready(?:Initialized|Set)\b|BossAlreadySet|OwnerAlreadySet|RouteAlreadySet"),
    re.compile(r"(?i)\bif\s+[^{}\n]*(?:initialized|Initialized)\b[^{}\n]*\{"),
    re.compile(
        r"(?i)\bif\s+[^{}\n]*(?:Owner|Admin|Boss|Authority|Governor|Controller|Manager)"
        r"\s*(?:!=|==)(?:\s*(?:\"\"|nil|0|zero|Zero|[A-Za-z_][\w.]*Default))?[^{}\n]*\{"
    ),
    re.compile(
        r"(?i)\bif\s+[^{}\n]*(?:owner|admin|boss|authority|governor|controller|manager)"
        r"\s*(?:!=|==)(?:\s*(?:\"\"|nil|0|zero|Zero))?[^{}\n]*\{"
    ),
    re.compile(
        r"(?i)\bif\s+[^{}\n]*(?:routes?|gateways?|gatewayFor|chainGateways?|registeredChains?|"
        r"knownChains?|trustedRemotes?)[^{}\n]*(?:\bok\b|\bexists\b|!=|==|len\s*\()[^{}\n]*\{"
    ),
)

PROTECTED_WRITE_RE = re.compile(
    r"(?P<target>"
    r"(?:[A-Za-z_]\w*\.)?(?:Owner|Admin|Boss|Authority|Governor|Controller|Manager|"
    r"RemoteGateway|RemoteBridge|TrustedRemote|Endpoint|Gateway|Peer|Counterpart)"
    r"|(?:[A-Za-z_]\w*\.)*(?:routes?|gateways?|gatewayFor|chainGateways?|registeredChains?|knownChains?|trustedRemotes?)"
    r"\s*\[[^\n=]+\])\s*=\s*(?P<rhs>[^;\n]+)"
    r"|\.(?P<setter>Set(?:Owner|Admin|Boss|Authority|Governor|Controller|Manager|"
    r"RemoteGateway|RemoteBridge|TrustedRemote|Endpoint|Gateway|Peer|Counterpart|Route|Chain))\s*\(",
    re.IGNORECASE,
)

AUTH_GUARD_RE = re.compile(
    r"(?i)"
    r"(RequireAuth|RequireAuthorized|CheckAuth|CheckAuthority|EnsureAuthority|EnsureAdmin|"
    r"OnlyOwner|OnlyAdmin|OnlyGovernance|OnlyGovernor|OnlyFactory|OnlyDeployer|"
    r"ValidateSigner|VerifySigner|AuthorizeCaller|AuthorizeSetup|HasRole|hasRole|"
    r"IsAdmin|IsOwner|MustOwner|AssertOwner|AllowedInitializer|ValidateInitializer|"
    r"ctx\.MsgSender|ctx\.Signer|GetSigners|msg\.Signer|request\.Signer|req\.Signer|"
    r"caller\s*(?:==|!=)\s*[^{}\n]*(?:deployer|factory|owner|admin|authority|governance|governor|upgradeAuthority)|"
    r"(?:deployer|factory|owner|admin|authority|governance|governor|upgradeAuthority)[^{}\n]*(?:==|!=)\s*caller|"
    r"sender\s*(?:==|!=)\s*[^{}\n]*(?:deployer|factory|owner|admin|authority|governance|governor|upgradeAuthority)|"
    r"(?:deployer|factory|owner|admin|authority|governance|governor|upgradeAuthority)[^{}\n]*(?:==|!=)\s*sender)"
)

SKIP_DIR_RE = re.compile(r"(?i)\b(mock|fixture|testdata)\b")


@dataclass
class Candidate:
    file: str
    line: int
    function: str
    snippet: str
    severity_hint: str
    reason: str


def _strip_strings_and_comments(line: str) -> str:
    out: list[str] = []
    i = 0
    in_str: str | None = None
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
        if c in ('"', "'", "`"):
            in_str = c
            i += 1
            continue
        if c == "/" and i + 1 < len(line) and line[i + 1] == "/":
            break
        out.append(c)
        i += 1
    return "".join(out)


def _iter_funcs(lines: list[str]):
    i = 0
    n = len(lines)
    while i < n:
        match = FUNC_DECL_RE.match(lines[i])
        if not match:
            i += 1
            continue
        name = match.group("name")
        depth = 0
        body_start = -1
        opened = False
        j = i
        while j < n:
            stripped = _strip_strings_and_comments(lines[j])
            for ch in stripped:
                if ch == "{":
                    if not opened:
                        opened = True
                        body_start = j
                    depth += 1
                elif ch == "}":
                    depth -= 1
                    if opened and depth == 0:
                        yield name, i, body_start, j
                        i = j + 1
                        break
            else:
                j += 1
                continue
            break
        else:
            return


def _is_exported(name: str) -> bool:
    return bool(name) and name[0].isupper()


def _has_first_writer_guard(body_text: str) -> bool:
    return any(pattern.search(body_text) for pattern in FIRST_WRITER_GUARD_RES)


def _has_auth_guard(body_text: str) -> bool:
    return bool(AUTH_GUARD_RE.search(body_text))


def _protected_write(body_lines: list[str], first_line: int) -> tuple[int, str, str] | None:
    for offset, raw in enumerate(body_lines):
        stripped = _strip_strings_and_comments(raw)
        match = PROTECTED_WRITE_RE.search(stripped)
        if not match:
            continue
        target = match.group("target") or match.group("setter") or "privileged state"
        return first_line + offset, raw.strip()[:240], target.strip()
    return None


def scan_file(path: Path) -> list[Candidate]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except (OSError, UnicodeDecodeError):
        return []
    lines = text.splitlines()
    out: list[Candidate] = []
    for name, decl_line, body_start, body_end in _iter_funcs(lines):
        if not (_is_exported(name) and ENTRYPOINT_NAME_RE.search(name)):
            continue
        body_lines = lines[body_start + 1 : body_end]
        body_text = "\n".join(_strip_strings_and_comments(line) for line in body_lines)
        if not _has_first_writer_guard(body_text):
            continue
        if _has_auth_guard(body_text):
            continue
        protected_write = _protected_write(body_lines, body_start + 2)
        if protected_write is None:
            continue
        line_no, snippet, target = protected_write
        out.append(
            Candidate(
                file=str(path),
                line=line_no,
                function=name,
                snippet=snippet,
                severity_hint="HIGH",
                reason=(
                    f"{name} first-writes `{target}` behind only an unset or initialized "
                    "guard, with no deployer, factory, signer, or governance binding"
                ),
            )
        )
    return out


def walk_repo(root: Path) -> Iterable[Path]:
    for path in root.rglob("*.go"):
        parts = set(path.parts)
        if "vendor" in parts or "testdata" in parts or ".auditooor" in parts:
            continue
        if any(SKIP_DIR_RE.search(part) for part in parts):
            continue
        if path.name.endswith("_test.go"):
            continue
        if path.name.endswith(".pb.go") or path.name.endswith(".pb.gw.go"):
            continue
        yield path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Go detector: unprotected first-writer initializer takeover"
    )
    parser.add_argument("repo", type=Path, help="repo root or Go file to scan")
    parser.add_argument("--out", type=Path, default=None)
    parser.add_argument("--threshold", type=int, default=0, help="min candidates to exit 1")
    args = parser.parse_args(argv)

    root = args.repo
    if not root.exists():
        print(f"error: {root} does not exist", file=sys.stderr)
        return 2

    candidates: list[Candidate] = []
    if root.is_file() and root.suffix == ".go":
        candidates.extend(scan_file(root))
    else:
        for go_file in walk_repo(root):
            candidates.extend(scan_file(go_file))

    payload = {
        "schema": SCHEMA,
        "root": str(root),
        "count": len(candidates),
        "candidates": [asdict(candidate) for candidate in candidates],
    }
    out_text = json.dumps(payload, indent=2)
    if args.out:
        args.out.write_text(out_text, encoding="utf-8")
    else:
        print(out_text)
    if args.threshold and len(candidates) < args.threshold:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
