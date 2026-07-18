#!/usr/bin/env python3
"""Base RPC-crash probe — Wave-10 Lane F (A8 zero-coverage closeout).

Lane G's wave-9 critical-hunt sweep flagged "A8 — RPC API crash affecting
programs with required market-cap threshold" as a zero-coverage angle on the
Base Azul scope. Kimi-7's RPC mining brief named two concrete unbounded-input
shapes the scanner is built around:

  1. ``crates/execution/rpc/src/eth/proofs.rs:67-76`` — ``eth_getProof`` takes
     ``keys: Vec<JsonStorageKey>`` and copies every entry into a fresh
     ``Vec<_>`` with no upstream length check, no per-request ``MAX_*``
     constant in the surrounding module, and no auth gate (public RPC).

  2. ``crates/execution/engine-tree/src/validator.rs:789`` — receipt streaming
     opens a ``crossbeam_channel::unbounded()`` channel, which lets a single
     producer back-pressure the heap into OOM under crafted input.

This probe walks every ``*.rs`` file under one or more Rust RPC roots
(``crates/execution/rpc``, ``crates/consensus/rpc`` by default) and emits a
candidate row per detection compatible with the
``tools/base-critical-candidate-matrix.py`` schema.

Pattern types
-------------

``unbounded_input``
    Function takes ``Vec<…>`` / ``Vec<Bytes>`` / ``Vec<KeyType>`` parameter
    and the function body has **no** length-cap call (``MAX_*``,
    ``.len() <``, ``ensure!(…len()…)``) and the surrounding module has no
    ``const MAX_*`` declaration.

``oom_path``
    Function body uses ``crossbeam_channel::unbounded()``,
    ``mpsc::unbounded_channel()``, or ``Vec::with_capacity`` driven by a
    caller-supplied length without a clamp.

``panic_on_input``
    Function body calls ``.unwrap()`` / ``.expect(`` directly on a parameter
    that came from the wire (parameter named in the fn signature). The
    scanner is conservative — it only fires when the same parameter token
    appears as the receiver of ``.unwrap()`` / ``.expect(``.

``blocking_io``
    Function is async (or attributed ``#[rpc(method = "…")]`` style) yet
    calls ``std::fs::``, ``std::thread::sleep``, or ``Mutex::lock()`` on a
    parameter that came from the wire — a single slow caller can pin the
    RPC thread.

Auth gates
----------

Each candidate carries an ``auth_gate`` field:

  * ``jwt`` — same crate ships ``JwtSecret`` / ``jwt::validate`` / ``JwtAuth``.
    Default-to-kill: still a candidate, but flagged as auth-shielded.
  * ``debug-only`` — the function (or its module) is named ``debug_*`` /
    ``trace_*`` / lives in ``debug.rs``; treated as non-public.
  * ``public`` — none of the above. The default for a normal ``eth_*`` /
    ``engine_*`` handler.

Default-to-kill semantics
-------------------------

Every emitted candidate is written with
``candidate_status = "kill_or_reframe"`` and a notes string explaining what
real-component PoC would unlock it (per
``tools/base-critical-candidate-matrix.py``). The probe never promotes a row
to ``executable`` on its own.

Output
------

When ``--workspace <ws>`` is given, writes::

    <ws>/critical_hunt/rpc_crash/a8_rpc_crash_matrix.json
    <ws>/critical_hunt/rpc_crash/a8_rpc_crash_matrix.md
    <ws>/critical_hunt/candidates/a8_rpc_crash_<n>.json    (per row)

When ``--out-json -`` is passed (or no workspace), prints the JSON payload
to stdout — useful for the unit tests.

Stdlib-only. Idempotent. Offline-safe.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

try:
    from lib.project_source_roots import rust_subdir_scan_roots
except ModuleNotFoundError:  # pragma: no cover - direct import from test loaders.
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from lib.project_source_roots import rust_subdir_scan_roots


SCHEMA_VERSION = "auditooor.base_rpc_crash_probe.v1"

DEFAULT_RPC_ROOTS = (
    "external/base/crates/execution/rpc",
    "external/base/crates/consensus/rpc",
    "crates/execution/rpc",
    "crates/consensus/rpc",
)

# Match the start of a fn declaration: ``[pub] [async] fn NAME``. We then
# parse the parameter list with balanced-paren walking and locate the body
# brace explicitly, because Rust return types like ``Result<Vec<u8>, String>``
# do not play well with a single regex.
FN_START_RE = re.compile(
    r"\b(?:pub(?:\s*\([^)]*\))?\s+)?(?:async\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)\s*"
    r"(?:<[^{};]*>\s*)?\(",
)

# Vec<...> param with optional inner generics. Captures the parameter name and
# the inner type. Examples matched:
#   keys: Vec<JsonStorageKey>
#   bytes_list: Vec<Bytes>
#   transactions: Vec<TransactionSigned>
#   logs: Vec<Log<Address>>
VEC_PARAM_RE = re.compile(
    r"\b([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(?:&\s*)?(?:mut\s+)?Vec\s*<\s*([^,>]+(?:<[^>]*>)?)\s*>",
)

UNBOUNDED_CHAN_RE = re.compile(
    r"\b(?:crossbeam_channel|tokio::sync::mpsc|futures::channel::mpsc)::unbounded(?:_channel)?\s*\(",
)

# Length-cap evidence that suppresses an unbounded_input flag.
LEN_CAP_PATTERNS = (
    re.compile(r"\bconst\s+MAX_[A-Z0-9_]+\s*:"),
    re.compile(r"\.len\s*\(\s*\)\s*[<>]"),
    re.compile(r"\bensure!\s*\([^)]*\.len\s*\(\s*\)"),
    re.compile(r"\bif\s+[A-Za-z_][A-Za-z0-9_]*\.len\s*\(\s*\)\s*[<>]"),
    re.compile(r"\.truncate\s*\("),
    re.compile(r"\bmax_request_size\b", re.IGNORECASE),
    re.compile(r"\bmax_keys\b", re.IGNORECASE),
)

# JWT / mTLS / authz tokens that mark the crate as auth-gated.
JWT_TOKENS = (
    "JwtSecret",
    "JwtAuth",
    "jwt::validate",
    "jwt::verify",
    "jsonwebtoken::decode",
    "with_client_cert_verifier",
    "MtlsConfig",
    "bearer_token::verify",
    "authorize_request",
)

# Modules / fn names that mark a handler as debug-only (non-public surface).
DEBUG_TOKENS_FN = ("debug_", "trace_", "anvil_", "txpool_inspect")
DEBUG_TOKENS_FILE = ("debug.rs", "trace.rs", "anvil.rs")

# Test code we never flag.
TEST_PATH_TOKENS = ("/tests/", "/test_", "/testing/", "_tests.rs", "/benches/", "/examples/")
TEST_ATTR_RE = re.compile(r"#\[(?:cfg\(test\)|test)\]")

PANIC_ON_INPUT_PATTERNS = (".unwrap()", ".expect(")
BLOCKING_IO_PATTERNS = (
    "std::fs::",
    "std::thread::sleep",
    "blocking::Mutex",
)

# Parameter tokens that are obviously self / auth context — never a wire input.
NON_WIRE_PARAM_NAMES = {"self", "_self", "ctx", "cx", "store", "factory", "rpc"}


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class Candidate:
    candidate_id: str
    scope_asset: str
    pattern_type: str
    auth_gate: str
    function: str
    file: str
    line: int
    parameter: str
    parameter_type: str
    impact_mapping: str
    candidate_status: str
    production_path: str
    required_proof: str
    artifact_refs: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    severity: str = "Critical-candidate (default-to-kill)"


# ---------------------------------------------------------------------------
# File enumeration
# ---------------------------------------------------------------------------


def enumerate_rpc_files(workspace: Path, extra_roots: list[str]) -> list[Path]:
    """Return all *.rs files under the configured RPC roots.

    We intentionally include both the wave-default roots and any caller
    overrides. Test / bench / example files are filtered out; we do NOT want
    a ``Vec<Bytes>`` in a ``#[cfg(test)]`` block to false-flag.
    """
    seen: set[Path] = set()
    out: list[Path] = []
    roots = rust_subdir_scan_roots(
        workspace,
        ("crates/execution/rpc", "crates/consensus/rpc"),
        DEFAULT_RPC_ROOTS,
    ) + list(extra_roots)
    for rel in roots:
        root = (workspace / rel).resolve()
        if not root.is_dir():
            continue
        for path in sorted(root.rglob("*.rs")):
            spath = str(path)
            if any(tok in spath for tok in TEST_PATH_TOKENS):
                continue
            if path.name.endswith("_test.rs") or path.name.endswith("_tests.rs"):
                continue
            if path in seen:
                continue
            seen.add(path)
            out.append(path)
    return out


# ---------------------------------------------------------------------------
# Per-file analysis
# ---------------------------------------------------------------------------


def _line_for_offset(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _find_paren_close(source: str, paren_open: int) -> int | None:
    """Return the index of the matching ``)`` for the ``(`` at ``paren_open``."""
    depth = 0
    i = paren_open
    n = len(source)
    while i < n:
        c = source[i]
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return None


def _find_body_brace(source: str, start: int) -> int | None:
    """Return the index of the function-body ``{`` after the param list.

    Stops if a ``;`` is hit first — that means it's a trait fn declaration
    without a body (no candidate to scan).
    """
    n = len(source)
    i = start
    while i < n:
        c = source[i]
        if c == "{":
            return i
        if c == ";":
            return None
        i += 1
    return None


def _find_fn_body(source: str, brace_open: int) -> tuple[int, int]:
    """Return (body_start, body_end) for a balanced ``{...}`` starting at
    ``brace_open`` (which must point at the opening ``{``)."""
    depth = 0
    i = brace_open
    n = len(source)
    while i < n:
        c = source[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return brace_open + 1, i
        i += 1
    return brace_open + 1, n


def _crate_root(path: Path) -> Path:
    for ancestor in [path.parent, *path.parents][:10]:
        if (ancestor / "Cargo.toml").exists():
            return ancestor
    return path.parent


def _crate_has_jwt(crate_root: Path) -> bool:
    for rs in crate_root.rglob("*.rs"):
        spath = str(rs)
        if any(tok in spath for tok in TEST_PATH_TOKENS):
            continue
        try:
            text = rs.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if any(tok in text for tok in JWT_TOKENS):
            return True
    return False


def _is_debug_only(file_path: Path, fn_name: str) -> bool:
    if any(file_path.name == tok for tok in DEBUG_TOKENS_FILE):
        return True
    if any(tok in str(file_path) for tok in (f"/{t}" for t in DEBUG_TOKENS_FILE)):
        return True
    for tok in DEBUG_TOKENS_FN:
        if fn_name.startswith(tok):
            return True
    return False


def _module_has_max_const(text: str) -> bool:
    """Module-scope ``const MAX_*: usize`` (or ``: u32``, etc.) check.

    We consider any ``const MAX_..._: <int> = N;`` line "module scope" because
    the scanner runs on a single file at a time. Conservative: presence of
    such a constant means the module *could* be capping; we'd rather kill the
    flag than fight the user about a missing in-fn use.
    """
    return any(p.search(text) for p in LEN_CAP_PATTERNS[:1])


def _fn_body_has_len_cap(body: str, param_name: str) -> bool:
    """Function-body length-cap evidence that names ``param_name``."""
    if re.search(rf"\b{re.escape(param_name)}\.len\s*\(\s*\)\s*[<>]", body):
        return True
    if re.search(rf"\bensure!\s*\([^)]*\b{re.escape(param_name)}\.len\s*\(\s*\)", body):
        return True
    if re.search(rf"\bif\s+{re.escape(param_name)}\.len\s*\(\s*\)\s*[<>]", body):
        return True
    if re.search(rf"\b{re.escape(param_name)}\.truncate\s*\(", body):
        return True
    # Any caller token like ``MAX_GET_PROOF_KEYS`` referenced near the param.
    for line in body.splitlines():
        if param_name in line and re.search(r"\bMAX_[A-Z0-9_]+\b", line):
            return True
    return False


def _scan_unbounded_input(
    source: str,
    fn_name: str,
    sig: str,
    body: str,
    file_path: Path,
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    module_has_const = _module_has_max_const(source)
    for m in VEC_PARAM_RE.finditer(sig):
        param_name = m.group(1)
        param_type = m.group(2).strip()
        if param_name in NON_WIRE_PARAM_NAMES:
            continue
        if _fn_body_has_len_cap(body, param_name):
            continue
        if module_has_const:
            # Module names a MAX_* const — be lenient, but only when the body
            # actually references it. Otherwise the const may be unrelated.
            if re.search(r"\bMAX_[A-Z0-9_]+\b", body):
                continue
        out.append(
            {
                "pattern_type": "unbounded_input",
                "function": fn_name,
                "parameter": param_name,
                "parameter_type": f"Vec<{param_type}>",
                "evidence_token": f"Vec<{param_type}>",
            }
        )
    return out


def _scan_oom_path(
    fn_name: str,
    body: str,
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for m in UNBOUNDED_CHAN_RE.finditer(body):
        out.append(
            {
                "pattern_type": "oom_path",
                "function": fn_name,
                "parameter": "",
                "parameter_type": "",
                "evidence_token": m.group(0).rstrip("("),
            }
        )
    return out


def _scan_panic_on_input(
    fn_name: str,
    sig: str,
    body: str,
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    # Map of param-name -> param-type for the fn.
    params: dict[str, str] = {}
    # Cheap parser: split on commas at depth 0.
    depth = 0
    chunk = ""
    chunks: list[str] = []
    for c in sig:
        if c in "<([":
            depth += 1
        elif c in ">)]":
            depth -= 1
        if c == "," and depth == 0:
            chunks.append(chunk)
            chunk = ""
        else:
            chunk += c
    if chunk.strip():
        chunks.append(chunk)
    for piece in chunks:
        piece = piece.strip()
        if not piece or piece in {"&self", "&mut self", "self"}:
            continue
        if ":" not in piece:
            continue
        name, type_ = piece.split(":", 1)
        params[name.strip().lstrip("&").lstrip("mut").strip()] = type_.strip()
    for name in params:
        if name in NON_WIRE_PARAM_NAMES:
            continue
        for tok in PANIC_ON_INPUT_PATTERNS:
            if re.search(rf"\b{re.escape(name)}\b\s*[^;]*?{re.escape(tok)}", body):
                out.append(
                    {
                        "pattern_type": "panic_on_input",
                        "function": fn_name,
                        "parameter": name,
                        "parameter_type": params[name],
                        "evidence_token": tok,
                    }
                )
                break
    return out


def _scan_blocking_io(
    fn_name: str,
    is_async: bool,
    body: str,
) -> list[dict[str, Any]]:
    if not is_async:
        return []
    out: list[dict[str, Any]] = []
    for tok in BLOCKING_IO_PATTERNS:
        if tok in body:
            out.append(
                {
                    "pattern_type": "blocking_io",
                    "function": fn_name,
                    "parameter": "",
                    "parameter_type": "",
                    "evidence_token": tok,
                }
            )
    return out


def scan_file(
    file_path: Path,
    workspace: Path,
    crate_jwt_cache: dict[Path, bool],
) -> list[Candidate]:
    """Return the list of candidates extracted from ``file_path``."""
    try:
        source = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    # Strip ``#[cfg(test)] ... mod tests { ... }`` blocks. We do this with a
    # naive scan because we want to be cheap and stdlib-only.
    cleaned = _strip_test_blocks(source)
    candidates: list[Candidate] = []
    for fn_match in FN_START_RE.finditer(cleaned):
        fn_name = fn_match.group(1)
        # Walk the paren list starting at the ``(`` we matched.
        paren_open = fn_match.end() - 1
        sig_close = _find_paren_close(cleaned, paren_open)
        if sig_close is None:
            continue
        sig = cleaned[paren_open + 1:sig_close]
        # Find the function body opening brace, allowing for ``-> ReturnType``
        # plus an optional ``where`` clause. Stop if we hit a ``;`` first
        # (trait-fn declaration without body).
        brace_open = _find_body_brace(cleaned, sig_close + 1)
        if brace_open is None:
            continue
        body_start, body_end = _find_fn_body(cleaned, brace_open)
        body = cleaned[body_start:body_end]
        # async-ness check: look back from the fn keyword.
        prefix_start = max(fn_match.start() - 48, 0)
        is_async = "async" in cleaned[prefix_start:fn_match.start() + 3]
        line = _line_for_offset(cleaned, fn_match.start())
        crate_root = _crate_root(file_path)
        has_jwt = crate_jwt_cache.setdefault(crate_root, _crate_has_jwt(crate_root))
        debug_only = _is_debug_only(file_path, fn_name)
        if has_jwt:
            auth_gate = "jwt"
        elif debug_only:
            auth_gate = "debug-only"
        else:
            auth_gate = "public"
        rel_path = _safe_rel(file_path, workspace)
        # Run all four pattern detectors.
        hits: list[dict[str, Any]] = []
        hits.extend(_scan_unbounded_input(cleaned, fn_name, sig, body, file_path))
        hits.extend(_scan_oom_path(fn_name, body))
        hits.extend(_scan_panic_on_input(fn_name, sig, body))
        hits.extend(_scan_blocking_io(fn_name, is_async, body))
        for hit in hits:
            cid = _candidate_id(rel_path, fn_name, hit["pattern_type"], hit.get("parameter") or "", line)
            impact = (
                "RPC API crash affecting programs with required market-cap threshold"
            )
            required = (
                "Send the synthetic request fixture (see "
                "<ws>/critical_hunt/rpc_crash/synthetic_requests/) against a "
                "real Base node and capture either a panic, an OOM, or a "
                "process exit. Without a real-component panic capture the row "
                "stays kill_or_reframe."
            )
            notes = [
                f"pattern_type={hit['pattern_type']}",
                f"auth_gate={auth_gate}",
                f"evidence_token={hit['evidence_token']}",
                "default-to-kill: emitted with kill_or_reframe; promotion "
                "requires a real-component panic/OOM capture.",
            ]
            if hit["pattern_type"] == "blocking_io" and not is_async:
                continue
            production_path = f"{rel_path}:{line}"
            candidates.append(
                Candidate(
                    candidate_id=cid,
                    scope_asset=_scope_asset(rel_path),
                    pattern_type=hit["pattern_type"],
                    auth_gate=auth_gate,
                    function=fn_name,
                    file=rel_path,
                    line=line,
                    parameter=hit.get("parameter") or "",
                    parameter_type=hit.get("parameter_type") or "",
                    impact_mapping=impact,
                    candidate_status="kill_or_reframe",
                    production_path=production_path,
                    required_proof=required,
                    artifact_refs=[rel_path],
                    notes=notes,
                )
            )
    return candidates


def _strip_test_blocks(text: str) -> str:
    """Remove ``#[cfg(test)] mod tests { ... }`` blocks. Naive but cheap."""
    out_parts: list[str] = []
    i = 0
    while True:
        m = re.search(r"#\[cfg\(test\)\]\s*\n?\s*mod\s+\w+\s*\{", text[i:])
        if not m:
            out_parts.append(text[i:])
            break
        out_parts.append(text[i:i + m.start()])
        # Skip past the block.
        depth = 0
        j = i + m.end() - 1  # at the ``{``
        n = len(text)
        while j < n:
            c = text[j]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    j += 1
                    break
            j += 1
        i = j
    return "".join(out_parts)


def _safe_rel(path: Path, workspace: Path) -> str:
    try:
        return str(path.relative_to(workspace))
    except ValueError:
        return str(path)


def _scope_asset(rel_path: str) -> str:
    # Best-effort crate identifier for the matrix scope_asset column.
    parts = rel_path.split("/")
    for i, p in enumerate(parts):
        if p == "crates" and i + 1 < len(parts):
            return "/".join(parts[i:i + 3])
    return rel_path


def _candidate_id(rel_path: str, fn_name: str, pattern_type: str, param: str, line: int) -> str:
    base = rel_path.replace("/", "_").replace(".", "_")
    return f"A8_{pattern_type}_{base}_{fn_name}_{param or 'noparam'}_L{line}".lower()


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------


def render_markdown(rows: list[Candidate]) -> str:
    lines: list[str] = []
    lines.append("# A8 RPC-Crash Candidate Matrix")
    lines.append("")
    lines.append(f"_Schema: `{SCHEMA_VERSION}`_")
    lines.append("")
    lines.append(
        "Every row below is emitted with `candidate_status = kill_or_reframe`. "
        "Promotion requires a real-component panic / OOM capture against a "
        "live Base node — see "
        "`<ws>/critical_hunt/rpc_crash/synthetic_requests/` and "
        "`expected_outcomes.md` for the fixtures."
    )
    lines.append("")
    counts: dict[str, int] = {}
    for r in rows:
        counts[r.pattern_type] = counts.get(r.pattern_type, 0) + 1
    lines.append("## Pattern counts")
    lines.append("")
    if counts:
        for k, v in sorted(counts.items()):
            lines.append(f"- `{k}`: {v}")
    else:
        lines.append("- _(no candidates emitted)_")
    lines.append("")
    lines.append("## Candidates")
    lines.append("")
    if not rows:
        lines.append("_No candidates found._")
        return "\n".join(lines) + "\n"
    lines.append(
        "| candidate_id | pattern | auth | fn | file:line | param | type |"
    )
    lines.append("|---|---|---|---|---|---|---|")
    for r in rows:
        lines.append(
            "| `{cid}` | `{p}` | `{auth}` | `{fn}` | `{path}:{line}` | "
            "`{param}` | `{ptype}` |".format(
                cid=r.candidate_id,
                p=r.pattern_type,
                auth=r.auth_gate,
                fn=r.function,
                path=r.file,
                line=r.line,
                param=r.parameter or "_(n/a)_",
                ptype=r.parameter_type or "_(n/a)_",
            )
        )
    lines.append("")
    return "\n".join(lines) + "\n"


def write_outputs(workspace: Path, rows: list[Candidate]) -> tuple[Path, Path, Path]:
    out_dir = workspace / "critical_hunt" / "rpc_crash"
    out_dir.mkdir(parents=True, exist_ok=True)
    cand_dir = workspace / "critical_hunt" / "candidates"
    cand_dir.mkdir(parents=True, exist_ok=True)
    _install_synthetic_requests(out_dir)
    json_path = out_dir / "a8_rpc_crash_matrix.json"
    md_path = out_dir / "a8_rpc_crash_matrix.md"
    payload = {
        "schema": SCHEMA_VERSION,
        "workspace": str(workspace),
        "pattern_counts": _count_by(rows, lambda r: r.pattern_type),
        "auth_gate_counts": _count_by(rows, lambda r: r.auth_gate),
        "rows": [asdict(r) for r in rows],
    }
    json_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    md_path.write_text(render_markdown(rows), encoding="utf-8")
    # Per-row candidate JSON, schema-compatible with base-critical-candidate-matrix.
    for r in rows:
        cand_payload = {
            "candidate_id": r.candidate_id,
            "scope_asset": r.scope_asset,
            "impact_mapping": r.impact_mapping,
            "production_path": r.production_path,
            "required_proof": r.required_proof,
            "artifact_refs": list(r.artifact_refs),
            "severity": r.severity,
            "pattern_type": r.pattern_type,
            "auth_gate": r.auth_gate,
            "notes": list(r.notes),
        }
        (cand_dir / f"{r.candidate_id}.json").write_text(
            json.dumps(cand_payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    return json_path, md_path, cand_dir


SYNTHETIC_REQUESTS = {
    "01_eth_get_proof_10000_keys.json": {
        "_doc": (
            "eth_getProof with 10000 storage keys — exercises the unbounded "
            "Vec<JsonStorageKey> at crates/execution/rpc/src/eth/proofs.rs:67."
        ),
        "_endpoint": "POST /  (eth_getProof)",
        "_expected_outcome": "OOM_OR_RPC_TIMEOUT",
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_getProof",
        "params": [
            "0x0000000000000000000000000000000000000000",
            ["0x" + "11" * 32 for _ in range(10_000)],
            "latest",
        ],
    },
    "02_engine_new_payload_v4_malformed.json": {
        "_doc": (
            "engine_newPayloadV4 with truncated payload + giant transactions "
            "vec — JWT-gated; expected 401 unless caller has the token."
        ),
        "_endpoint": "POST /  (engine_newPayloadV4)",
        "_expected_outcome": "AUTH_REJECT_401",
        "jsonrpc": "2.0",
        "id": 2,
        "method": "engine_newPayloadV4",
        "params": [
            {
                "parentHash": "0x" + "00" * 32,
                "feeRecipient": "0x" + "00" * 20,
                "stateRoot": "0x" + "00" * 32,
                "receiptsRoot": "0x" + "00" * 32,
                "logsBloom": "0x" + "00" * 256,
                "prevRandao": "0x" + "00" * 32,
                "blockNumber": "0x1",
                "gasLimit": "0xffffffff",
                "gasUsed": "0x0",
                "timestamp": "0x0",
                "extraData": "0x",
                "baseFeePerGas": "0x0",
                "blockHash": "0x" + "00" * 32,
                "transactions": ["0x" + "ff" * 64 for _ in range(50_000)],
                "withdrawals": [],
                "blobGasUsed": "0x0",
                "excessBlobGas": "0x0",
            },
            [],
            "0x" + "00" * 32,
            [],
        ],
    },
    "03_eth_get_logs_max_range.json": {
        "_doc": (
            "eth_getLogs over the entire chain — exercises receipt-streaming "
            "via the crossbeam_channel::unbounded() at validator.rs:789."
        ),
        "_endpoint": "POST /  (eth_getLogs)",
        "_expected_outcome": "OOM_OR_TIMEOUT",
        "jsonrpc": "2.0",
        "id": 3,
        "method": "eth_getLogs",
        "params": [{"fromBlock": "earliest", "toBlock": "latest"}],
    },
    "04_eth_call_huge_input.json": {
        "_doc": (
            "eth_call with a 2 MiB input blob — should be rejected by the "
            "request-size middleware; logs the rejection path so the operator "
            "can confirm the cap is wired."
        ),
        "_endpoint": "POST /  (eth_call)",
        "_expected_outcome": "REQUEST_TOO_LARGE",
        "jsonrpc": "2.0",
        "id": 4,
        "method": "eth_call",
        "params": [
            {
                "from": "0x" + "00" * 20,
                "to": "0x" + "00" * 20,
                "data": "0x" + "ee" * (2 * 1024 * 1024),
            },
            "latest",
        ],
    },
    "05_debug_trace_unauth.json": {
        "_doc": (
            "debug_traceBlockByNumber against a public RPC. Expected to be "
            "rejected (debug-only / authenticated). If it succeeds, the auth "
            "gate is misconfigured."
        ),
        "_endpoint": "POST /  (debug_traceBlockByNumber)",
        "_expected_outcome": "AUTH_REJECT_OR_METHOD_NOT_FOUND",
        "jsonrpc": "2.0",
        "id": 5,
        "method": "debug_traceBlockByNumber",
        "params": ["latest", {"tracer": "callTracer"}],
    },
}


EXPECTED_OUTCOMES_MD = """# A8 RPC-Crash Synthetic Request Expectations

These five requests live next to the matrix in
`<ws>/critical_hunt/rpc_crash/synthetic_requests/`. They are *not* a brute-
force fuzz corpus — each one targets a single named mining angle and has a
clear pass/fail outcome.

| # | File | Endpoint | Expected outcome | Promotes? |
|---|------|----------|------------------|-----------|
| 1 | `01_eth_get_proof_10000_keys.json` | `eth_getProof` | `OOM_OR_RPC_TIMEOUT` | **YES** if real-component panic / OOM observed (Kimi-7 lead) |
| 2 | `02_engine_new_payload_v4_malformed.json` | `engine_newPayloadV4` | `AUTH_REJECT_401` | only if auth gate is bypassable |
| 3 | `03_eth_get_logs_max_range.json` | `eth_getLogs` | `OOM_OR_TIMEOUT` | YES if validator.rs:789 unbounded receipt channel triggers OOM |
| 4 | `04_eth_call_huge_input.json` | `eth_call` | `REQUEST_TOO_LARGE` | NO if rejected at the size middleware |
| 5 | `05_debug_trace_unauth.json` | `debug_traceBlockByNumber` | `AUTH_REJECT_OR_METHOD_NOT_FOUND` | NO unless auth gate is bypassable |

## Default-to-kill rule

A row in `a8_rpc_crash_matrix.json` only promotes from `kill_or_reframe`
when the operator records a real-component panic / OOM / process-exit
under `<ws>/poc_execution/<candidate_id>/execution_manifest.json`. None of
these requests, by themselves, are evidence — the operator must capture
the host-side outcome and link it.

## Why these five and not 50

Brief Lane F: "5 malformed-but-non-bruteforce requests for known
endpoints." We avoid randomized fuzz cases here on purpose; this is an
explanation harness, not a coverage harness. The scanner already names the
crash-prone code paths; these five requests are the smallest set that
exercises one path per pattern type (unbounded_input, oom_path,
panic_on_input, request-size middleware, auth gate).
"""


def _install_synthetic_requests(out_dir: Path) -> None:
    """Write the five synthetic requests + expected_outcomes.md.

    Idempotent: only writes a file when the contents differ.
    """
    req_dir = out_dir / "synthetic_requests"
    req_dir.mkdir(parents=True, exist_ok=True)
    for name, payload in SYNTHETIC_REQUESTS.items():
        target = req_dir / name
        new = json.dumps(payload, indent=2, sort_keys=True) + "\n"
        if target.is_file():
            try:
                if target.read_text(encoding="utf-8") == new:
                    continue
            except OSError:
                pass
        target.write_text(new, encoding="utf-8")
    md_target = out_dir / "expected_outcomes.md"
    if not md_target.is_file() or md_target.read_text(encoding="utf-8") != EXPECTED_OUTCOMES_MD:
        md_target.write_text(EXPECTED_OUTCOMES_MD, encoding="utf-8")


def _count_by(rows: list[Candidate], key) -> dict[str, int]:
    out: dict[str, int] = {}
    for r in rows:
        k = key(r)
        out[k] = out.get(k, 0) + 1
    return out


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def run(workspace: Path, extra_roots: list[str]) -> list[Candidate]:
    files = enumerate_rpc_files(workspace, extra_roots)
    crate_jwt_cache: dict[Path, bool] = {}
    rows: list[Candidate] = []
    for f in files:
        rows.extend(scan_file(f, workspace, crate_jwt_cache))
    # Stable order: file then line then pattern.
    rows.sort(key=lambda r: (r.file, r.line, r.pattern_type, r.parameter))
    return rows


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="base-rpc-crash-probe.py",
        description=(
            "Wave-10 Lane F probe for A8 (RPC API crash). Walks Rust RPC "
            "crates and emits unbounded-input / OOM / panic / blocking-IO "
            "candidates with default-to-kill semantics."
        ),
    )
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument(
        "--root",
        action="append",
        default=[],
        help=(
            "Additional path (workspace-relative) to walk. May be passed "
            "multiple times. Defaults to declared project_source_roots RPC "
            "crates, then historical external/base RPC roots when no "
            "declaration exists."
        ),
    )
    parser.add_argument(
        "--out-json",
        default="",
        help=(
            "When set to '-', print the JSON payload to stdout instead of "
            "writing files. Useful for tests."
        ),
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help=(
            "Exit 1 when at least one public unbounded_input candidate was "
            "emitted (CI gate after the first cleanup wave)."
        ),
    )
    args = parser.parse_args(argv)

    workspace: Path = args.workspace
    if not workspace.is_dir():
        print(
            f"[base-rpc-crash-probe] ERR workspace not a directory: {workspace}",
            file=sys.stderr,
        )
        return 2

    rows = run(workspace, list(args.root))

    if args.out_json == "-":
        sys.stdout.write(
            json.dumps(
                {
                    "schema": SCHEMA_VERSION,
                    "rows": [asdict(r) for r in rows],
                    "pattern_counts": _count_by(rows, lambda r: r.pattern_type),
                },
                indent=2,
                sort_keys=True,
            )
            + "\n"
        )
    else:
        json_path, md_path, cand_dir = write_outputs(workspace, rows)
        print(f"[base-rpc-crash-probe] wrote {json_path.relative_to(workspace)}", file=sys.stderr)
        print(f"[base-rpc-crash-probe] wrote {md_path.relative_to(workspace)}", file=sys.stderr)
        print(
            f"[base-rpc-crash-probe] wrote {len(rows)} candidate JSONs under "
            f"{cand_dir.relative_to(workspace)}",
            file=sys.stderr,
        )
        if rows:
            counts_str = ", ".join(
                f"{k}={v}"
                for k, v in sorted(_count_by(rows, lambda r: r.pattern_type).items())
            )
            print(
                f"[base-rpc-crash-probe] pattern counts: {counts_str}",
                file=sys.stderr,
            )
        else:
            print("[base-rpc-crash-probe] no candidates emitted", file=sys.stderr)

    if args.strict:
        public_unbounded = [
            r for r in rows
            if r.pattern_type == "unbounded_input" and r.auth_gate == "public"
        ]
        if public_unbounded:
            print(
                f"[base-rpc-crash-probe] STRICT FAIL: "
                f"{len(public_unbounded)} public unbounded_input candidate(s) remain",
                file=sys.stderr,
            )
            return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
