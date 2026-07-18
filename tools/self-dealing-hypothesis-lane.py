#!/usr/bin/env python3
"""self-dealing-hypothesis-lane.py  (SADL) - Self-Dealing / Identity-Collapse
Hypothesis Lane.

WHAT THIS TOOL DOES
===================
For every value-moving function in <ws>/.auditooor/value_moving_functions.json,
SADL enumerates the address-typed parameters AND the storage-derived counterparty
slots present in the function signature (payer, receiver, maker, taker, buyer,
seller, from, to, beneficiary, owner, spender, liquidator, borrower, sender,
recipient), then emits one identity-collapse hypothesis per distinct address-pair
- the exact class behind the morpho self-settled-take (payer==receiver nets a
settlement transfer to a no-op while the ledger still mints credit).

WHY THIS MATTERS
================
SelfTake-style guards check only ONE pair (e.g. maker != taker). SADL enumerates
the OTHER collapses no existing guard addresses. A function with params
(payer, receiver, beneficiary) has three collapse hypotheses:
  - payer == receiver
  - payer == beneficiary
  - receiver == beneficiary
Each deserves independent fuzz investigation.

HYPOTHESIS SCHEMA (per emitted record)
=======================================
{
  "workspace":       "<abs-path>",
  "file":            "<rel-path>",
  "function":        "<name>",
  "language":        "sol|go|rs|move|cairo",
  "param_a":         "<addr-param-name>",
  "param_b":         "<addr-param-name>",
  "collapse_expr":   "<param_a> == <param_b>",
  "note":            "<human-readable description>",
  "attack_class":    "self-dealing-identity-collapse",
  "source":          "SADL",
  "verdict":         "needs-fuzz",
  "vcis_oracle_hint": "<suggested conservation property to pair with>",
  "selftake_guard_note": "<whether a guard on another pair still leaves this open>"
}

NO FALSE-GREEN RULE
===================
SADL NEVER auto-credits a gate. Every emitted hypothesis carries
verdict="needs-fuzz". The caller (VCIS + medusa/echidna actor pool) must
independently verify whether the collapse is exploitable.

COMPOSE WITH VCIS
=================
The collapse pair is the INPUT REGION for the fuzz campaign. The VCIS
conservation property (solvency floor: balanceOf >= sum(credit fields)) is the
ORACLE. A self-dealing collapse is confirmed when the oracle property fails while
the actors in the actor pool include the collapsed identity pair.

LANGUAGE COVERAGE
=================
- Solidity (.sol, .vy): address / address payable typed params + counterparty-
  name heuristic on untyped params.
- Go/Cosmos (.go): sdk.AccAddress / Addr typed params + counterparty-name
  heuristic on string / interface{} params.
- Rust/CosmWasm (.rs): Addr / &Addr / &mut Addr / AccountId + implicit
  MessageInfo.sender counterparty slot + counterparty-name heuristic.
- Move (.move): address / &signer typed params + counterparty-name heuristic.
- Cairo (.cairo, .nr): ContractAddress typed params + counterparty-name heuristic.

EMIT TARGETS
============
1. <ws>/.auditooor/self_dealing_hypotheses.jsonl - one JSON object per line,
   one record per collapsed pair per function.
2. Per-function hunt corpus injection (stdout summary for operator review).

CLI
===
  python3 tools/self-dealing-hypothesis-lane.py <workspace> [--out <path>]
  --out: override the .jsonl output path (default: <ws>/.auditooor/self_dealing_hypotheses.jsonl)
  --vmf-json: override value_moving_functions.json path (default: <ws>/.auditooor/value_moving_functions.json)
  --regen-vmf: re-run value-moving-functions.py even if the JSON already exists

Returns rc=0 on success (even if 0 hypotheses emitted), rc=1 on error.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import re
import sys
from datetime import datetime, timezone
from itertools import combinations
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Compose with scope_exclusion (OOS guard, single source of truth).
# ---------------------------------------------------------------------------
try:
    from tools.lib.scope_exclusion import is_oos  # type: ignore
except Exception:
    _HERE = Path(__file__).resolve().parent
    _LIB = _HERE / "lib"
    if str(_LIB) not in sys.path:
        sys.path.insert(0, str(_LIB))
    try:
        from scope_exclusion import is_oos  # type: ignore
    except Exception:
        def is_oos(rel: str, **_) -> bool:  # type: ignore[misc]
            n = ("/" + rel.replace("\\", "/")).lower()
            for marker in (
                "/test/", "/tests/", "_test.", ".t.sol", "/vendor/", "/lib/",
                "/node_modules/", "/out/", "/build/", "/target/",
            ):
                if marker in n:
                    return True
            return False

# ---------------------------------------------------------------------------
# Counterparty lexicon - ROLE-GROUPED for opposing-pair filtering.
#
# Roles are split into two camps:
#   ORIGIN_ROLES  - the "from" side of a value flow (payer, sender, maker, ...)
#   DEST_ROLES    - the "to"   side of a value flow (receiver, recipient, taker, ...)
#
# A self-dealing hypothesis is ONLY meaningful when:
#   (a) both params are in opposing camps (origin vs dest), OR
#   (b) one param is a known CALLER slot (msg.sender / implicit) and the
#       other is any dest-role param.
#
# Pairs where BOTH params are in the same camp, or where at least one param
# is a NON-ROLE address (token contract, config, mode-enum, well address, etc.)
# are DROPPED - they are not self-dealing collapse candidates.
# ---------------------------------------------------------------------------

# Origin-side roles (the party who gives / pays / provides / acts on behalf of)
# "onBehalf" = the subject whose account is being acted on (share-owner /
# position-holder); they are the SOURCE of the authorisation, not the destination.
# "owner" in ERC-4626 = the share-holder providing shares (source side).
_ORIGIN_KEYWORDS: frozenset[str] = frozenset([
    "payer", "sender", "from", "frm", "src", "source",
    "maker", "seller", "debtor", "borrower", "depositor",
    "liquidator", "liquidatoraddr",
    "owner", "onwer",      # ERC-4626 owner provides shares (origin)
    "onbehalf",            # subject whose account is debited / repaid (origin)
    "account",             # generic "account being acted on" = origin slot
])

# Destination-side roles (the party who receives / benefits)
_DEST_KEYWORDS: frozenset[str] = frozenset([
    "receiver", "recv", "recipient",
    "to", "dst", "dest", "destination", "target",
    "beneficiary", "benefactor", "bene",
    "taker", "buyer", "creditor",
    "spender",
])

# Combined flat list for name-matching, longest first.
_ALL_CP_KEYWORDS: list[str] = sorted(
    _ORIGIN_KEYWORDS | _DEST_KEYWORDS,
    key=len, reverse=True,
)

# Non-role address names that look like addresses but are NOT counterparty roles.
# Params whose lowercased name CONTAINS any of these tokens are excluded even
# if they accidentally match a role keyword via substring.
_NON_ROLE_TOKENS: frozenset[str] = frozenset([
    "token", "asset", "vault", "well", "pool", "pair", "market",
    "contract", "factory", "registry", "oracle", "router", "module",
    "mode", "flag", "type", "kind", "class", "config", "param",
    "augustus", "instance", "ctoken", "urd", "bean", "lp",
])


def _role_of(name: str) -> str | None:
    """Return 'origin', 'dest', or None (= not a role-meaningful counterparty).

    The check is:
    1. If the lowercased name contains a NON_ROLE_TOKEN fragment -> None.
    2. If the lowercased name matches (whole-word / starts-with / ends-with)
       an ORIGIN keyword -> 'origin'.
    3. Same for DEST keywords -> 'dest'.
    4. Otherwise -> None (unrecognised / non-role address param).
    """
    nl = name.lower()
    # Reject non-role addresses first.
    for bad in _NON_ROLE_TOKENS:
        if bad in nl:
            return None
    for kw in _ALL_CP_KEYWORDS:
        if kw == nl or nl.startswith(kw) or nl.endswith(kw):
            if kw in _ORIGIN_KEYWORDS:
                return "origin"
            if kw in _DEST_KEYWORDS:
                return "dest"
    return None


def _is_counterparty_name(name: str) -> bool:
    """Return True if ``name`` is ANY recognised counterparty keyword.

    Preserved for the heuristic address-extraction step; the
    opposing-role filter is applied later in ``emit_hypotheses_for_fn``.
    """
    return _role_of(name) is not None


# ---------------------------------------------------------------------------
# Per-language address-param extraction patterns.
# Each returns the list of address-typed parameter NAMES found in a function
# signature string (text between the opening and closing parentheses of the
# function declaration, NOT the body).
# ---------------------------------------------------------------------------

# Solidity: address [payable] <name>
_SOL_ADDR_RE = re.compile(
    r"\baddress\s+(?:payable\s+)?([A-Za-z_]\w*)\b"
)

# Go/Cosmos: sdk.AccAddress <name> or plain Addr <name> or ValAddress <name>
_GO_ADDR_RE = re.compile(
    r"\b(?:sdk\.)?(?:AccAddress|ValAddress|Addr)\s+([A-Za-z_]\w*)\b"
)

# Rust/CosmWasm: Addr / &Addr / &mut Addr / AccountId
_RS_ADDR_RE = re.compile(
    r"\b(?:&\s*(?:mut\s+)?)?(?:Addr|AccountId)\s+([A-Za-z_]\w*)\b"
)

# Move: address <name> (signer is a capability, not an identity address)
_MOVE_ADDR_RE = re.compile(
    r"\baddress\s+([A-Za-z_]\w*)\b"
)

# Cairo / Noir: ContractAddress <name>
_CAIRO_ADDR_RE = re.compile(
    r"\bContractAddress\s+([A-Za-z_]\w*)\b"
)

_ADDR_RE_BY_LANG: dict[str, re.Pattern] = {
    "sol":   _SOL_ADDR_RE,
    "go":    _GO_ADDR_RE,
    "rs":    _RS_ADDR_RE,
    "move":  _MOVE_ADDR_RE,
    "cairo": _CAIRO_ADDR_RE,
}


def _extract_signature_text(source: str, fn_match: re.Match) -> str:
    """Extract the text between the opening and closing parentheses of the
    function declaration matched by ``fn_match``.

    The match is expected to end at or just past the opening '(' of the
    parameter list.  We scan forward to find the balanced closing ')'.
    """
    # The _FN_RES patterns end after the function name + optional '<' or '('.
    # Find the '(' that starts the param list.
    text = source
    start = fn_match.end()
    # Seek to the opening '(' (may already be at start if the regex ended there)
    i = text.find("(", start - 1)
    if i < 0:
        return ""
    depth = 0
    for j in range(i, len(text)):
        c = text[j]
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return text[i + 1: j]
    return text[i + 1:]


# Import _FN_RES from value-moving-functions for signature detection reuse.
# We load it dynamically so the module name (with hyphens) doesn't block import.
_VMF_MOD_NAME = "value_moving_functions_sadl_import"
_VMF_PATH = Path(__file__).resolve().parent / "value-moving-functions.py"


def _load_vmf_module():
    """Load tools/value-moving-functions.py as a module (hyphen-safe)."""
    spec = importlib.util.spec_from_file_location(_VMF_MOD_NAME, _VMF_PATH)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[_VMF_MOD_NAME] = mod
    spec.loader.exec_module(mod)
    return mod


_VMF: Any = None  # lazy-load on first use


def _vmf() -> Any:
    global _VMF
    if _VMF is None:
        _VMF = _load_vmf_module()
    return _VMF


# ---------------------------------------------------------------------------
# Per-function address-param extraction.
# ---------------------------------------------------------------------------
def _extract_addr_params(source: str, fn_match: re.Match, lang: str) -> list[str]:
    """Return the list of address-typed parameter names for the matched function.

    Strategy:
    1. Extract the signature text (between the function's '(' and ')').
    2. Apply the language-specific typed-address regex to capture typed names.
    3. Also scan for untyped counterparty-role names (heuristic: a bare param
       whose identifier alone matches the counterparty lexicon is included
       regardless of its declared type, because many codebases pass addresses
       as 'string', 'interface{}', or 'felt252' with semantic names like
       'sender', 'receiver', etc.).
    4. Deduplicate while preserving order.
    """
    sig_text = _extract_signature_text(source, fn_match)
    if not sig_text:
        return []

    addr_re = _ADDR_RE_BY_LANG.get(lang)
    found: list[str] = []
    seen: set[str] = set()

    # Step 1: typed address params
    if addr_re:
        for m in addr_re.finditer(sig_text):
            name = m.group(1)
            if name not in seen:
                found.append(name)
                seen.add(name)

    # Step 2: counterparty-name heuristic on any identifier in the signature
    # that is not already captured.  We tokenize the signature into identifiers
    # and check each against the counterparty lexicon.
    for word in re.findall(r"[A-Za-z_]\w*", sig_text):
        if word in seen:
            continue
        if _is_counterparty_name(word):
            found.append(word)
            seen.add(word)

    return found


# ---------------------------------------------------------------------------
# Implicit counterparty slots injected per language.
# Some languages have well-known implicit counterparties not present in the
# signature text (e.g. Rust/CosmWasm MessageInfo.sender).
# ---------------------------------------------------------------------------
_IMPLICIT_COUNTERPARTIES: dict[str, list[str]] = {
    # Rust CosmWasm: info.sender is always the implicit caller
    "rs": ["sender"],
}


# ---------------------------------------------------------------------------
# Core hypothesis emitter.
# ---------------------------------------------------------------------------
_SELFTAKE_NOTE = (
    "A present guard on one address pair (e.g. require(maker != taker)) does "
    "NOT cover this pair. Each collapse must be independently guarded."
)

_VCIS_ORACLE_HINT = (
    "Pair with the VCIS solvency-floor property: after calling the function with "
    "{param_a} set equal to {param_b}, verify balanceOf(protocol) >= sum(credit fields)."
)


def _build_note(fn_name: str, param_a: str, param_b: str) -> str:
    return (
        f"Set {param_a} == {param_b} and re-check the value-conservation invariant: "
        f"does the ledger still mint/credit while the net transfer is a no-op? "
        f"(function: {fn_name})"
    )


def emit_hypotheses_for_fn(
    ws_abs: str,
    fn_rec: dict[str, Any],
    source: str,
    fn_match: re.Match,
) -> list[dict[str, Any]]:
    """Return one hypothesis record per ROLE-MEANINGFUL opposing-role address-param pair.

    ``fn_rec`` is a record from value_moving_functions.json.
    ``source`` is the full source text of the file.
    ``fn_match`` is the regex match object for the function signature.

    TIGHTENING vs naive N-choose-2:
    - Only params whose name maps to a known counterparty role (origin OR dest)
      are considered.  Token-address, config, mode-enum, and other non-role
      address params are silently dropped.
    - A pair is emitted ONLY when the two params are in OPPOSING role camps
      (one origin + one dest).  Same-camp pairs (sender==from, receiver==to)
      are dropped - they are redundant or config-level collapses, not
      self-dealing value-flow attacks.
    - Exception: implicit caller slots (e.g. Rust 'sender' from MessageInfo)
      are treated as origin-role and paired with any dest-role param.
    """
    lang = fn_rec["language"]
    addr_params = _extract_addr_params(source, fn_match, lang)

    # Inject implicit counterparties for the language.
    implicit = _IMPLICIT_COUNTERPARTIES.get(lang, [])
    for imp in implicit:
        if imp not in addr_params:
            addr_params.append(imp)

    # Filter to role-meaningful params only, recording each param's role camp.
    role_params: list[tuple[str, str]] = []  # (name, "origin"|"dest")
    for name in addr_params:
        role = _role_of(name)
        if role is not None:
            role_params.append((name, role))

    # Need at least 2 role-meaningful params to form an opposing pair.
    if len(role_params) < 2:
        return []

    # Emit one hypothesis per distinct OPPOSING-role pair (order-insensitive).
    hypotheses: list[dict[str, Any]] = []
    seen_pairs: set[frozenset[str]] = set()
    for (a, role_a), (b, role_b) in combinations(role_params, 2):
        # Only emit when roles are OPPOSING.
        if role_a == role_b:
            continue
        key = frozenset({a, b})
        if key in seen_pairs:
            continue
        seen_pairs.add(key)
        vcis_hint = _VCIS_ORACLE_HINT.format(param_a=a, param_b=b)
        hypotheses.append({
            "workspace":          ws_abs,
            "file":               fn_rec["file"],
            "function":           fn_rec["function"],
            "language":           lang,
            "param_a":            a,
            "param_b":            b,
            "collapse_expr":      f"{a} == {b}",
            "note":               _build_note(fn_rec["function"], a, b),
            "attack_class":       "self-dealing-identity-collapse",
            "source":             "SADL",
            "verdict":            "needs-fuzz",
            "vcis_oracle_hint":   vcis_hint,
            "selftake_guard_note": _SELFTAKE_NOTE,
        })
    return hypotheses


# ---------------------------------------------------------------------------
# Source-file -> function-match resolver.
# Reuses _FN_RES from value-moving-functions to locate each function in source.
# ---------------------------------------------------------------------------
def _find_fn_match(source: str, fn_name: str, lang: str) -> re.Match | None:
    """Return the first regex match for ``fn_name`` in ``source``."""
    fn_re = _vmf()._FN_RES.get(lang)
    if fn_re is None:
        return None
    for m in fn_re.finditer(source):
        if m.group(1) == fn_name:
            return m
    return None


# ---------------------------------------------------------------------------
# Workspace-level runner.
# ---------------------------------------------------------------------------
def run_sadl(
    workspace: str | Path,
    vmf_json_path: str | Path | None = None,
    out_path: str | Path | None = None,
    regen_vmf: bool = False,
) -> list[dict[str, Any]]:
    """Run SADL over ``workspace`` and return the list of hypothesis records.

    Also writes the .jsonl sidecar.
    """
    ws = Path(workspace).resolve()
    ws_abs = str(ws)

    # Resolve the value_moving_functions.json path.
    vmf_json = (
        Path(vmf_json_path)
        if vmf_json_path is not None
        else ws / ".auditooor" / "value_moving_functions.json"
    )

    # Run value-moving-functions.py if absent or regen requested.
    if regen_vmf or not vmf_json.exists():
        vmf_mod = _vmf()
        out_vmf = vmf_mod.run(ws, vmf_json)
        vmf_json = out_vmf

    if not vmf_json.exists():
        print(
            f"ERROR: value_moving_functions.json not found at {vmf_json}",
            file=sys.stderr,
        )
        return []

    payload = json.loads(vmf_json.read_text(encoding="utf-8"))
    fn_records: list[dict[str, Any]] = payload.get("functions", [])

    # Group records by file so we load each source file only once.
    by_file: dict[str, list[dict[str, Any]]] = {}
    for rec in fn_records:
        by_file.setdefault(rec["file"], []).append(rec)

    all_hypotheses: list[dict[str, Any]] = []

    for rel_path, recs in by_file.items():
        abs_path = ws / rel_path
        if not abs_path.exists():
            continue
        if is_oos(rel_path):
            continue
        try:
            source = abs_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        for fn_rec in recs:
            fn_name = fn_rec["function"]
            lang = fn_rec["language"]
            fn_match = _find_fn_match(source, fn_name, lang)
            if fn_match is None:
                continue
            hyps = emit_hypotheses_for_fn(ws_abs, fn_rec, source, fn_match)
            all_hypotheses.extend(hyps)

    # Write .jsonl sidecar.
    out_jsonl = (
        Path(out_path)
        if out_path is not None
        else ws / ".auditooor" / "self_dealing_hypotheses.jsonl"
    )
    out_jsonl.parent.mkdir(parents=True, exist_ok=True)
    with out_jsonl.open("w", encoding="utf-8") as fh:
        for hyp in all_hypotheses:
            fh.write(json.dumps(hyp) + "\n")

    return all_hypotheses


# ---------------------------------------------------------------------------
# Public API: used directly in tests (no file-system workspace needed).
# ---------------------------------------------------------------------------
def hypotheses_from_source(
    source: str,
    language: str,
    fn_name: str,
    file_rel: str = "fixture.sol",
    ws_abs: str = "/tmp/sadl_fixture_ws",
) -> list[dict[str, Any]]:
    """Return SADL hypotheses for a single function in ``source``.

    Convenience wrapper for unit tests: no workspace directory required.
    ``source`` must contain the full function definition (signature + body).
    """
    fn_re = _vmf()._FN_RES.get(language)
    if fn_re is None:
        return []

    # Build a minimal vmf record.
    fn_match = None
    for m in fn_re.finditer(source):
        if m.group(1) == fn_name:
            fn_match = m
            break
    if fn_match is None:
        return []

    # Detect transfer/ledger evidence (needed for a valid vmf record shape).
    fn_rec: dict[str, Any] = {
        "file":                fn_name if not file_rel else file_rel,
        "function":            fn_name,
        "language":            language,
        "transfer_hit":        True,
        "ledger_write_hit":    False,
        "transfer_evidence":   [],
        "ledger_write_evidence": [],
    }
    return emit_hypotheses_for_fn(ws_abs, fn_rec, source, fn_match)


# ---------------------------------------------------------------------------
# CLI entry-point.
# ---------------------------------------------------------------------------
def _main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="SADL: enumerate self-dealing / identity-collapse hypotheses."
    )
    parser.add_argument("workspace", help="Workspace root path")
    parser.add_argument("--out", default=None, help="Override .jsonl output path")
    parser.add_argument(
        "--vmf-json", default=None,
        help="Override value_moving_functions.json path",
    )
    parser.add_argument(
        "--regen-vmf", action="store_true",
        help="Re-run value-moving-functions.py even if JSON exists",
    )
    args = parser.parse_args(argv)

    ws = Path(args.workspace)
    if not ws.is_dir():
        print(f"ERROR: workspace not found: {ws}", file=sys.stderr)
        return 1

    hyps = run_sadl(
        workspace=ws,
        vmf_json_path=args.vmf_json,
        out_path=args.out,
        regen_vmf=args.regen_vmf,
    )

    out_path = (
        Path(args.out)
        if args.out
        else ws / ".auditooor" / "self_dealing_hypotheses.jsonl"
    )
    print(
        f"SADL: {len(hyps)} identity-collapse hypotheses -> {out_path}"
    )
    by_fn: dict[str, list[dict[str, Any]]] = {}
    for h in hyps:
        key = f"{h['file']}::{h['function']}"
        by_fn.setdefault(key, []).append(h)
    for fn_key, fn_hyps in sorted(by_fn.items()):
        print(f"  {fn_key}:")
        for h in fn_hyps:
            print(f"    [{h['verdict']}] {h['collapse_expr']}")
    return 0


if __name__ == "__main__":
    sys.exit(_main())
