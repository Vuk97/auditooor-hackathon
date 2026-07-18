#!/usr/bin/env python3
"""Flag Rust RPC handlers that accept a trusted-forwarder sender without any
auth primitive shipped in the containing crate.

Base-Azul engagement-3 FN-B3 shape (``base/base@v0.8.0-rc.24:
crates/execution/txpool/src/builder/rpc.rs:72``). A Rust fn takes a ``sender:
Address`` argument and constructs a ``Recovered::new_unchecked(...)`` — i.e.
it treats the caller-supplied sender as authoritative. If the same crate ships
no JWT verify, no mTLS config, and no IP allowlist primitive, a public RPC
endpoint can forge the sender.

Scanner walks Rust sources (``*.rs``) under the crate root and reports per-fn
findings. Advisory by default; the severity becomes MEDIUM when the crate
ships ``Recovered::new_unchecked`` but NO auth primitive.
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any


FN_WITH_SENDER_RE = re.compile(
    r"\bfn\s+([A-Za-z_][A-Za-z0-9_]*)\s*[^{;]*?\bsender\s*:\s*[A-Za-z0-9_:]*Address\b",
    re.DOTALL,
)
UNCHECKED_RECOVERED_RE = re.compile(r"\bRecovered::new_unchecked\b")

# Strong auth-primitive tokens. Presence in the SAME FILE as the handler
# or in a router-mount file that wires the handler is treated as proof
# the request is authenticated before the unchecked sender flows in.
#
# Codex review #3: a bare ``rustls`` dep in Cargo.toml or a passing
# mention in an unrelated comment is NOT proof of mTLS client auth, so
# we tightened the evidence check to handler-file or router-mount scope
# (option a from the review).
AUTH_TOKENS = (
    "jwt::validate",
    "jwt::verify",
    "JwtSecret",
    "JwtAuth",
    "tower::auth",
    "tower_http::auth",
    "ip_allowlist",
    "IpAllowlist",
    "MtlsConfig",
    "with_client_cert_verifier",
    "client_cert_required",
    "bearer_token::verify",
    "authorize_request",
    "route_layer",
    ".layer(tower_http::auth",
    ".layer(tower::auth",
)


def _crate_root_for(path: Path) -> Path:
    """Walk up from a Rust file looking for the nearest Cargo.toml. If none,
    treat the file's parent as the scan root."""
    for ancestor in [path.parent, *path.parents][:10]:
        if (ancestor / "Cargo.toml").exists():
            return ancestor
    return path.parent


def _line_for_offset(source: str, offset: int) -> int:
    return source.count("\n", 0, offset) + 1


def _file_has_auth_token(text: str) -> list[str]:
    return [token for token in AUTH_TOKENS if token in text]


def _router_files_mounting(crate_root: Path, handler_file: Path, fn_names: list[str]) -> list[Path]:
    """Return the set of Rust files in ``crate_root`` that look like they
    mount one of ``fn_names`` onto a router (and therefore would carry the
    auth-layer wiring). Heuristic: the file is NOT the handler file itself
    AND mentions the handler name AND uses a router-style verb token
    (``.route(``, ``.method(``, ``.merge(``, ``.nest(``, ``register_method``,
    ``RpcModule``, ``rpc.register``).
    """
    router_verbs = (
        ".route(",
        ".method(",
        ".merge(",
        ".nest(",
        "register_method",
        "register_async_method",
        "RpcModule",
        "rpc.register",
    )
    out: list[Path] = []
    for rs in crate_root.rglob("*.rs"):
        if rs == handler_file:
            continue
        try:
            text = rs.read_text(errors="replace")
        except OSError:
            continue
        if not any(verb in text for verb in router_verbs):
            continue
        if not any(re.search(rf"\b{re.escape(name)}\b", text) for name in fn_names):
            continue
        out.append(rs)
    return out


def _scoped_auth_evidence(
    handler_source: str,
    handler_file: Path,
    crate_root: Path,
    fn_names: list[str],
) -> list[str]:
    """Auth evidence that actually defends THIS handler.

    Codex review #3: the previous implementation walked every ``*.rs``
    in the crate plus four Cargo.toml dep names, so a stray ``rustls``
    line or an unrelated comment suppressed legitimate findings. We now
    require:

    1. an auth token in the handler file itself, OR
    2. an auth token in a router-mount file that wires this handler.

    Cargo.toml dep names are NOT sufficient on their own — a dependency
    in the manifest does not prove the route is gated.
    """
    tokens: list[str] = []
    for token in _file_has_auth_token(handler_source):
        if token not in tokens:
            tokens.append(token)
    for router in _router_files_mounting(crate_root, handler_file, fn_names):
        try:
            text = router.read_text(errors="replace")
        except OSError:
            continue
        for token in _file_has_auth_token(text):
            tag = f"{router.name}:{token}"
            if tag not in tokens:
                tokens.append(tag)
    return tokens


def _candidate_handler_names(source: str) -> list[str]:
    """Return all fn names in ``source`` that take ``sender: Address`` and
    call ``Recovered::new_unchecked``. Used for router-mount lookup."""
    names: list[str] = []
    for fn_match in FN_WITH_SENDER_RE.finditer(source):
        fn_name = fn_match.group(1)
        if fn_name == "new_unchecked":
            continue
        body = _fn_body(source, fn_match.end())
        if body is None or "Recovered::new_unchecked" not in body:
            continue
        if fn_name not in names:
            names.append(fn_name)
    return names


def scan_file(path: Path) -> list[dict[str, Any]]:
    source = path.read_text(errors="replace")

    if "Recovered::new_unchecked" not in source:
        return []

    findings: list[dict[str, Any]] = []
    crate_root = _crate_root_for(path)
    handler_names = _candidate_handler_names(source)
    auth_tokens_hit = _scoped_auth_evidence(source, path, crate_root, handler_names)

    if auth_tokens_hit:
        return []

    for fn_match in FN_WITH_SENDER_RE.finditer(source):
        fn_name = fn_match.group(1)
        # Skip the Recovered::new_unchecked constructor definition itself.
        if fn_name == "new_unchecked":
            continue
        # Require the fn BODY (not just the file) to call
        # Recovered::new_unchecked — that is the "trust the caller" gadget.
        body = _fn_body(source, fn_match.end())
        if body is None or "Recovered::new_unchecked" not in body:
            continue
        findings.append(
            {
                "file": str(path),
                "crate_root": str(crate_root),
                "function": fn_name,
                "line": _line_for_offset(source, fn_match.start(1)),
                "auth_tokens_found": auth_tokens_hit,  # always empty here
                "pattern": "trusted_forwarder_rpc_without_auth_primitive",
                "severity": "advisory",
            }
        )
    return findings


def _fn_body(source: str, after_header: int) -> str | None:
    """Return the text between the first `{` after `after_header` and its
    matching `}`. None if braces don't balance."""
    brace = source.find("{", after_header)
    if brace < 0:
        return None
    depth = 0
    for idx in range(brace, len(source)):
        ch = source[idx]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return source[brace + 1 : idx]
    return None


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Advisory scanner for Rust RPC handlers that accept a trusted "
            "sender address without a crate-level auth primitive."
        )
    )
    parser.add_argument("paths", nargs="+", type=Path, help="Rust files or directories")
    parser.add_argument("--json", action="store_true", help="Emit JSON findings")
    args = parser.parse_args()

    files: list[Path] = []
    for path in args.paths:
        if path.is_dir():
            files.extend(sorted(path.rglob("*.rs")))
        elif path.suffix == ".rs":
            files.append(path)

    findings: list[dict[str, Any]] = []
    for file_path in files:
        findings.extend(scan_file(file_path))

    if args.json:
        print(json.dumps({"findings": findings}, indent=2))
    else:
        for finding in findings:
            print(
                "{file}:{line}: {pattern}: fn {function} in crate "
                "{crate_root} accepts a caller-supplied sender with no "
                "auth primitive".format(**finding)
            )

    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
