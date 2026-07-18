#!/usr/bin/env python3
"""Ground a finding's live precondition against real on-chain state.

Motivation (operator, 2026-07): agents claim "no RPC available" and then file
findings whose *impact tier* silently assumes a live on-chain state ("steal X
now") that was never checked.  This tool closes that gap generically:

  1. It reads the per-workspace, no-secrets access config
     ``<ws>/.auditooor/onchain_access.json`` (see ``tools/lib/onchain_access.py``).
  2. It reads one or more declarative PRECONDITION SPECS - "state field F at
     query Q must ``op`` value V" - from the draft (``<!-- live-precondition:
     {json} -->`` directives), a ``--spec-file``, and/or
     ``<ws>/.auditooor/live_precondition_specs.json``.
  3. For each spec it QUERIES the live chain over a public, read-only,
     unauthenticated endpoint - a cosmos LCD REST GET or an EVM ``eth_call``
     JSON-RPC POST - and compares the observed value with V.
  4. It emits a per-precondition verdict:
        live-verified        - chain confirms the precondition holds now
        contradicted-by-chain - chain contradicts it (config-gated downgrade)
        unverifiable         - no endpoint / no route / fetch error / unresolved

Verdicts are appended to ``<ws>/.auditooor/live_precondition_verdicts.jsonl``
(reviving the empty ``live_topology_proof_*`` convention; schema/field names are
reused where sensible).  A gate (pre-submit Check #149) reads these so a
severity claim that hinges on a live precondition without a ``live-verified``
verdict is downgraded to conditional/latent or flagged unverifiable.

Network safety: real HTTP is performed ONLY when ``--allow-network`` (or
``AUDITOOOR_ONCHAIN_ALLOW_NETWORK=1``) is set, or when ``--mock-responses`` is
supplied for hermetic tests.  Otherwise every route is ``unverifiable`` - the
tool never blocks on a network it was not told it could reach, and never sends
credentials (the config loader rejects secret-bearing endpoints).

Exit codes:
  0 = every spec live-verified (or no specs present)
  1 = at least one precondition contradicted by chain (downgrade signal)
  2 = at least one unverifiable and none contradicted
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent / "lib"))
from onchain_access import (  # noqa: E402
    load_onchain_access,
    resolve_address,
    VALID_KINDS,
)

SCHEMA = "auditooor.live_precondition_verdicts.v1"
VERDICTS_RELPATH = ".auditooor/live_precondition_verdicts.jsonl"
SPECS_RELPATH = ".auditooor/live_precondition_specs.json"
DIRECTIVE_RE = re.compile(
    r"<!--\s*live-precondition:\s*(\{.*?\})\s*-->", re.IGNORECASE | re.DOTALL
)
NUMERIC_OPS = {"<", "<=", ">", ">="}
ALL_OPS = {"==", "!=", "<", "<=", ">", ">="}

LIVE_VERIFIED = "live-verified"
CONTRADICTED = "contradicted-by-chain"
UNVERIFIABLE = "unverifiable"


# --------------------------------------------------------------------------- #
# keccak-256 (pure python) - only used to derive an EVM selector from a `sig`.
# Golden-vector checked in the test suite (paused() -> 0x5c975abb).
# --------------------------------------------------------------------------- #
_KECCAK_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
    0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]
_KECCAK_ROT = [
    [0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56], [27, 20, 39, 8, 14],
]
_MASK = (1 << 64) - 1


def _rotl(x: int, n: int) -> int:
    return ((x << n) | (x >> (64 - n))) & _MASK


def _keccak_f(state: list[list[int]]) -> None:
    for rnd in range(24):
        c = [state[x][0] ^ state[x][1] ^ state[x][2] ^ state[x][3] ^ state[x][4]
             for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rotl(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                state[x][y] ^= d[x]
        b = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                b[y][(2 * x + 3 * y) % 5] = _rotl(state[x][y], _KECCAK_ROT[x][y])
        for x in range(5):
            for y in range(5):
                state[x][y] = b[x][y] ^ ((~b[(x + 1) % 5][y]) & b[(x + 2) % 5][y])
        state[0][0] ^= _KECCAK_RC[rnd]


def keccak256(data: bytes) -> bytes:
    rate = 136  # 1088 bits for keccak-256
    state = [[0] * 5 for _ in range(5)]
    padded = bytearray(data)
    padded.append(0x01)
    while len(padded) % rate != 0:
        padded.append(0x00)
    padded[-1] ^= 0x80
    for off in range(0, len(padded), rate):
        block = padded[off:off + rate]
        for i in range(0, rate, 8):
            lane = int.from_bytes(block[i:i + 8], "little")
            state[(i // 8) % 5][(i // 8) // 5] ^= lane
        _keccak_f(state)
    out = bytearray()
    for y in range(5):
        for x in range(5):
            out += state[x][y].to_bytes(8, "little")
    return bytes(out[:32])


def selector_for(sig: str) -> str:
    """4-byte selector for a canonical signature like ``paused()``.

    Only the ``name(type,type)`` head is hashed, so ``paused()(bool)`` and
    ``paused()`` both work (the trailing return group is stripped).
    """
    head = sig.strip()
    # strip a trailing "(returns)" group if the cast-style form was passed
    m = re.match(r"^([A-Za-z_]\w*\([^)]*\))", head)
    canonical = m.group(1) if m else head
    return "0x" + keccak256(canonical.encode()).hex()[:8]


# --------------------------------------------------------------------------- #
# Spec loading
# --------------------------------------------------------------------------- #
def load_specs(
    *, submission: Optional[Path], spec_file: Optional[Path], workspace: Optional[Path]
) -> list[dict[str, Any]]:
    specs: list[dict[str, Any]] = []
    if submission and submission.is_file():
        text = submission.read_text(encoding="utf-8", errors="replace")
        for m in DIRECTIVE_RE.finditer(text):
            try:
                obj = json.loads(m.group(1))
                obj.setdefault("_origin", "draft-directive")
                specs.append(obj)
            except json.JSONDecodeError:
                specs.append({"_parse_error": m.group(1)[:200], "_origin": "draft-directive"})
    for path, origin in (
        (spec_file, "spec-file"),
        (workspace / SPECS_RELPATH if workspace else None, "ws-specs"),
    ):
        if path and path.is_file():
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            rows = payload if isinstance(payload, list) else payload.get("specs") or []
            for obj in rows:
                if isinstance(obj, dict):
                    obj.setdefault("_origin", origin)
                    specs.append(obj)
    return specs


# --------------------------------------------------------------------------- #
# Fetching
# --------------------------------------------------------------------------- #
class FetchResult:
    __slots__ = ("ok", "value", "reason", "raw")

    def __init__(self, ok: bool, value: Any = None, reason: str = "", raw: str = ""):
        self.ok = ok
        self.value = value
        self.reason = reason
        self.raw = raw


def _dotted(obj: Any, path: str) -> Any:
    cur = obj
    for part in path.split("."):
        if part == "":
            continue
        if isinstance(cur, list):
            cur = cur[int(part)]
        elif isinstance(cur, dict):
            cur = cur[part]
        else:
            raise KeyError(path)
    return cur


def _http_get_json(url: str, timeout: float) -> Any:
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (public no-auth)
        return json.loads(resp.read().decode("utf-8"))


def _http_post_json(url: str, body: dict, timeout: float) -> Any:
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (public no-auth)
        return json.loads(resp.read().decode("utf-8"))


def _decode_evm_output(hexval: str, abi_out: str) -> Any:
    raw = hexval[2:] if hexval.startswith("0x") else hexval
    if not raw:
        return None
    abi_out = (abi_out or "uint256").strip().lower()
    if abi_out == "bool":
        return int(raw, 16) != 0
    if abi_out == "address":
        return "0x" + raw[-40:]
    # default numeric
    return int(raw, 16)


def fetch_value(
    spec: dict[str, Any],
    cfg: dict[str, Any],
    *,
    kind: str,
    endpoint: str,
    allow_network: bool,
    mock: Optional[dict[str, Any]],
    timeout: float,
) -> FetchResult:
    query = spec.get("query") or {}
    if kind == "cosmos-lcd":
        path = str(query.get("path") or "")
        if not path:
            return FetchResult(False, reason="spec.query.path missing for cosmos-lcd")
        addr = ""
        if "{address}" in path:
            ref = spec.get("address_ref") or spec.get("address") or ""
            addr = resolve_address(cfg, str(ref))
            if not addr or addr == ref and ref not in (cfg.get("key_addresses") or {}):
                # ref did not resolve to a concrete address and is not itself an address
                if not re.match(r"^[a-z0-9]+1[a-z0-9]{6,}$", str(addr)) and not str(addr).startswith("0x"):
                    return FetchResult(False, reason=f"address_ref {ref!r} unresolved")
            path = path.replace("{address}", addr)
        url = endpoint.rstrip("/") + "/" + path.lstrip("/")
        key = url
        try:
            if mock is not None:
                if key not in mock:
                    return FetchResult(False, reason=f"no mock response for {key}")
                doc = mock[key]
            elif allow_network:
                doc = _http_get_json(url, timeout)
            else:
                return FetchResult(False, reason="network not allowed (pass --allow-network or --mock-responses)")
        except (urllib.error.URLError, OSError, ValueError) as exc:
            return FetchResult(False, reason=f"cosmos-lcd fetch error: {exc}")
        field = str(query.get("json_field") or "")
        try:
            value = _dotted(doc, field) if field else doc
        except (KeyError, IndexError, ValueError) as exc:
            return FetchResult(False, reason=f"json_field {field!r} not found: {exc}", raw=json.dumps(doc)[:200])
        return FetchResult(True, value=value, raw=json.dumps(doc)[:200])

    if kind == "evm-rpc":
        to_ref = spec.get("to_ref") or spec.get("address_ref") or query.get("to") or query.get("to_ref") or ""
        to = resolve_address(cfg, str(to_ref))
        if not to.startswith("0x"):
            return FetchResult(False, reason=f"evm 'to' address unresolved: {to_ref!r}")
        data = query.get("data")
        if not data:
            sig = query.get("sig") or ""
            if not sig:
                return FetchResult(False, reason="evm spec needs query.data or query.sig")
            args = query.get("args") or []
            if args:
                return FetchResult(
                    False,
                    reason="evm sig with args needs precomputed query.data (ABI-encoded)",
                )
            data = selector_for(str(sig))
        body = {
            "jsonrpc": "2.0", "id": 1, "method": "eth_call",
            "params": [{"to": to, "data": data}, "latest"],
        }
        key = f"{to}|{data}"
        try:
            if mock is not None:
                if key not in mock:
                    return FetchResult(False, reason=f"no mock response for {key}")
                doc = mock[key]
            elif allow_network:
                doc = _http_post_json(endpoint, body, timeout)
            else:
                return FetchResult(False, reason="network not allowed (pass --allow-network or --mock-responses)")
        except (urllib.error.URLError, OSError, ValueError) as exc:
            return FetchResult(False, reason=f"evm-rpc fetch error: {exc}")
        if isinstance(doc, dict) and doc.get("error"):
            return FetchResult(False, reason=f"evm-rpc error: {doc['error']}")
        result_hex = doc.get("result") if isinstance(doc, dict) else doc
        try:
            value = _decode_evm_output(str(result_hex), str(query.get("abi_out") or "uint256"))
        except (ValueError, TypeError) as exc:
            return FetchResult(False, reason=f"evm decode error: {exc}", raw=str(result_hex)[:200])
        return FetchResult(True, value=value, raw=str(result_hex)[:200])

    return FetchResult(False, reason=f"unsupported kind {kind!r}")


# --------------------------------------------------------------------------- #
# Comparison
# --------------------------------------------------------------------------- #
def _norm(v: Any) -> Any:
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return v
    s = str(v).strip().strip("`").strip('"').strip("'")
    low = s.lower()
    if low in ("true", "false"):
        return low == "true"
    if re.fullmatch(r"-?\d+", s):
        return int(s)
    if re.fullmatch(r"0x[0-9a-fA-F]+", s):
        return s.lower()
    return low


def compare(observed: Any, op: str, expected: Any) -> tuple[bool, str]:
    o = _norm(observed)
    e = _norm(expected)
    if op in NUMERIC_OPS:
        try:
            of = int(o) if not isinstance(o, bool) else int(o)
            ef = int(e) if not isinstance(e, bool) else int(e)
        except (ValueError, TypeError):
            return False, f"non-numeric operands for {op}: {observed!r} {expected!r}"
        holds = {
            "<": of < ef, "<=": of <= ef, ">": of > ef, ">=": of >= ef,
        }[op]
        return holds, f"{of} {op} {ef}"
    if op == "==":
        return o == e, f"{o!r} == {e!r}"
    if op == "!=":
        return o != e, f"{o!r} != {e!r}"
    return False, f"unknown op {op!r}"


# --------------------------------------------------------------------------- #
# Driver
# --------------------------------------------------------------------------- #
def evaluate_spec(
    spec: dict[str, Any],
    cfg: Optional[dict[str, Any]],
    *,
    allow_network: bool,
    mock: Optional[dict[str, Any]],
    timeout: float,
) -> dict[str, Any]:
    sid = spec.get("id") or spec.get("finding_id") or "LP-?"
    finding_id = spec.get("finding_id") or ""
    op = spec.get("op") or "=="
    expected = spec.get("expected")
    severity_dependent = bool(spec.get("severity_dependent", True))
    base = {
        "id": sid,
        "finding_id": finding_id,
        "description": spec.get("description") or "",
        "op": op,
        "expected": expected,
        "severity_dependent": severity_dependent,
        "source_refs": spec.get("source_refs") or spec.get("source_ref") or [],
        "origin": spec.get("_origin") or "",
    }
    if spec.get("_parse_error"):
        base.update(verdict=UNVERIFIABLE, reason=f"unparseable directive: {spec['_parse_error']}")
        return base
    if op not in ALL_OPS:
        base.update(verdict=UNVERIFIABLE, reason=f"unsupported op {op!r}")
        return base
    if cfg is None:
        base.update(verdict=UNVERIFIABLE, reason="no onchain_access.json configured for workspace")
        return base
    if cfg.get("_problems"):
        base.update(verdict=UNVERIFIABLE, reason="onchain_access.json invalid: " + "; ".join(cfg["_problems"]))
        return base
    kind = spec.get("kind") or cfg.get("kind")
    if kind not in VALID_KINDS:
        base.update(verdict=UNVERIFIABLE, reason=f"unknown/unsupported kind {kind!r}")
        return base
    endpoint = str(cfg.get("endpoint") or "")
    res = fetch_value(
        spec, cfg, kind=kind, endpoint=endpoint,
        allow_network=allow_network, mock=mock, timeout=timeout,
    )
    base["kind"] = kind
    base["endpoint"] = endpoint
    if not res.ok:
        base.update(verdict=UNVERIFIABLE, reason=res.reason)
        return base
    base["observed"] = res.value
    holds, detail = compare(res.value, op, expected)
    base["comparison"] = detail
    if holds:
        base.update(verdict=LIVE_VERIFIED, reason=f"chain confirms precondition ({detail})")
    else:
        base.update(verdict=CONTRADICTED, reason=f"chain contradicts precondition ({detail})")
    return base


def _coverage_fields(verdict: str) -> dict[str, Any]:
    if verdict == LIVE_VERIFIED:
        return {"coverage_claim": "live_precondition_verified_onchain", "promotion_allowed": True, "advisory_only": False}
    if verdict == CONTRADICTED:
        return {"coverage_claim": "live_precondition_contradicted_onchain", "promotion_allowed": False, "advisory_only": False}
    return {"coverage_claim": "live_precondition_unverified", "promotion_allowed": False, "advisory_only": True}


# Rank so a persisted stronger verdict wins over a weaker current one.
_VERDICT_RANK = {UNVERIFIABLE: 0, LIVE_VERIFIED: 1, CONTRADICTED: 2}


def load_persisted_verdicts(ws: Path) -> dict[str, dict[str, Any]]:
    """Map precondition id -> the strongest persisted verdict row.

    Used by ``--gate`` so a pre-submit run that cannot reach the network still
    honours a ``live-verified`` (or ``contradicted``) verdict written earlier by
    an authoring run that DID query the chain.  A contradiction always wins; a
    live-verified beats an unverifiable.
    """
    out: dict[str, dict[str, Any]] = {}
    path = ws / VERDICTS_RELPATH
    if not path.is_file():
        return out
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        sid = row.get("id")
        verdict = row.get("verdict")
        if not sid or verdict not in _VERDICT_RANK:
            continue
        prior = out.get(sid)
        if prior is None or _VERDICT_RANK[verdict] >= _VERDICT_RANK[prior.get("verdict", UNVERIFIABLE)]:
            out[sid] = row
    return out


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Ground finding preconditions on live chain state")
    ap.add_argument("--workspace", required=True, help="workspace root (holds .auditooor/onchain_access.json)")
    ap.add_argument("--submission", help="draft .md to scan for <!-- live-precondition: {...} --> directives")
    ap.add_argument("--spec-file", help="JSON file: list of precondition specs")
    ap.add_argument("--allow-network", action="store_true", help="permit real read-only HTTP to the public endpoint")
    ap.add_argument("--mock-responses", help="JSON map (request-key -> response) for hermetic runs/tests")
    ap.add_argument("--timeout", type=float, default=8.0, help="per-request timeout seconds")
    ap.add_argument("--no-emit", action="store_true", help="do not append to live_precondition_verdicts.jsonl")
    ap.add_argument("--json", action="store_true", help="emit machine-readable JSON to stdout")
    ap.add_argument(
        "--gate",
        action="store_true",
        help="filing-gate mode: merge persisted verdicts, score only "
        "severity-dependent specs, never emit. N/A (rc 0) when no config or no specs.",
    )
    args = ap.parse_args(argv)

    ws = Path(args.workspace)
    cfg = load_onchain_access(ws, strict=False)
    allow_network = args.allow_network or os.environ.get("AUDITOOOR_ONCHAIN_ALLOW_NETWORK") == "1"
    if args.gate:
        args.no_emit = True

    mock = None
    if args.mock_responses:
        mock = json.loads(Path(args.mock_responses).read_text(encoding="utf-8"))

    specs = load_specs(
        submission=Path(args.submission) if args.submission else None,
        spec_file=Path(args.spec_file) if args.spec_file else None,
        workspace=ws,
    )

    verdicts = [
        evaluate_spec(s, cfg, allow_network=allow_network, mock=mock, timeout=args.timeout)
        for s in specs
    ]

    if args.gate:
        # Adopt a stronger persisted verdict (from an authoring run that queried
        # the chain) when the current run could not reach it.
        persisted = load_persisted_verdicts(ws)
        for v in verdicts:
            prior = persisted.get(v.get("id"))
            if prior and _VERDICT_RANK.get(prior.get("verdict"), 0) > _VERDICT_RANK.get(v["verdict"], 0):
                v["verdict"] = prior["verdict"]
                v["reason"] = f"adopted persisted verdict ({prior.get('reason','')})"
                v["adopted_from_persisted"] = True

    generated_at = datetime.now(timezone.utc).isoformat()
    if not args.no_emit and specs:
        out_path = ws / VERDICTS_RELPATH
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with out_path.open("a", encoding="utf-8") as fh:
            for v in verdicts:
                row = {"schema": SCHEMA, "generated_at": generated_at, **v, **_coverage_fields(v["verdict"])}
                fh.write(json.dumps(row, sort_keys=True) + "\n")

    # In gate mode only severity-dependent preconditions decide the rc: a
    # latent/conditional precondition that does not drive the impact tier must
    # not block filing.
    scored = [v for v in verdicts if v.get("severity_dependent", True)] if args.gate else verdicts

    n_live = sum(1 for v in scored if v["verdict"] == LIVE_VERIFIED)
    n_contra = sum(1 for v in scored if v["verdict"] == CONTRADICTED)
    n_unver = sum(1 for v in scored if v["verdict"] == UNVERIFIABLE)

    if n_contra:
        overall, rc = CONTRADICTED, 1
    elif n_unver:
        overall, rc = UNVERIFIABLE, 2
    else:
        overall, rc = LIVE_VERIFIED, 0

    summary = {
        "schema": SCHEMA,
        "workspace": str(ws),
        "generated_at": generated_at,
        "has_config": cfg is not None and not cfg.get("_problems"),
        "chain": (cfg or {}).get("chain") if cfg else None,
        "kind": (cfg or {}).get("kind") if cfg else None,
        "total": len(verdicts),
        "scored": len(scored),
        "gate_mode": bool(args.gate),
        "live_verified": n_live,
        "contradicted": n_contra,
        "unverifiable": n_unver,
        "verdict": overall if scored else LIVE_VERIFIED,
        "verdicts": verdicts,
    }

    if args.json:
        print(json.dumps(summary, indent=2, sort_keys=True))
    else:
        if not scored:
            print("live-precondition: no severity-dependent precondition specs to ground")
        else:
            print(f"live-precondition: {overall} - {n_live} live-verified, {n_contra} contradicted, {n_unver} unverifiable")
            for v in verdicts:
                print(f"  [{v['verdict']}] {v['id']}: {v.get('reason','')}")
    return rc if scored else 0


if __name__ == "__main__":
    raise SystemExit(main())
