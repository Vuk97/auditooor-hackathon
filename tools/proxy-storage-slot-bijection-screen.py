#!/usr/bin/env python3
"""proxy-storage-slot-bijection-screen.py - A10 upgradeable storage-slot
bijection enforcement screen (GENERAL invariant / trust-enforcement class).

NORTH-STAR METHOD (w8mv5mpcw) applied inside this capability:

  TRUSTED ENFORCEMENT (delegated + trusted):
      an upgradeable proxy trusts that EVERY future implementation preserves
      the storage-slot BIJECTION - i.e. that the byte living at storage slot k
      means the same thing in impl vN and impl vN+1.

  PRIVATE INVARIANT that makes that trust sound:
      for an upgradeable contract, the storage layout is APPEND-ONLY *and* a
      reserved-space enforcer absorbs future additions so no already-occupied
      slot ever shifts:
        - a `__gap` reserved array (OZ-4.x inheritance-storage-gap idiom), OR
        - an ERC-7201 NAMESPACED storage struct (`@custom:storage-location
          erc7201:...` / `assembly { $.slot := <Location> }`), which pins each
          module's state to a hashed, collision-free slot region.
      Absent BOTH, appending a variable in a future impl (or reordering an
      inheritance base) silently repacks lower slots -> derived-contract /
      proxy state corrupts across vN->vN+1 with NO revert and NO upstream
      visibility. No single module OWNS this invariant (the proxy trusts the
      impl; the impl trusts its bases), which is exactly the un-owned
      whole-system dimension this screen enumerates.

  ATTACK THE INVARIANT:
      find a contract that IS upgradeable-relevant (Initializable / *Upgradeable
      base / initialize()/reinitializer / _authorizeUpgrade) AND declares raw
      mutable storage (occupies slots) AND has NEITHER a `__gap` NOR ERC-7201
      namespacing. That is the append-safety enforcement absent at a delegated,
      type-erased, silent-fail boundary.

GENERALITY: this is a reusable ENFORCEMENT class (append-safety of the
storage-slot bijection across impl versions), NOT a specific bug shape or an
impact-specific detector. It flags the ABSENCE of the enforcement mechanism
that would make ANY future upgrade slot-safe - the confirming vN->vN+1 layout
diff is delegated to `tools/storage-layout.py --compare-dir`.

ADVISORY-FIRST: every row carries verdict='needs-fuzz' and auto_credit=False.
The screen NEVER fail-closes by default (rc 0). A dedicated env
`AUDITOOOR_A10_STORAGE_BIJECTION_STRICT` opts into a non-zero exit ONLY for an
operator who explicitly wants a hard gate; it is NOT wired under the L37
umbrella.

Usage:
    python3 tools/proxy-storage-slot-bijection-screen.py <workspace-or-file>
    python3 tools/proxy-storage-slot-bijection-screen.py <ws> --json
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Tuple, Union

SCHEMA = "auditooor.a10_storage_slot_bijection_screen.v1"
CANONICAL_CLASS = "proxy-storage-slot-bijection"
_A10_ENV = "AUDITOOOR_A10_STORAGE_BIJECTION_STRICT"

TRUSTED_INVARIANT = (
    "an upgradeable proxy trusts that every future implementation preserves "
    "the storage-slot bijection (slot k means the same in impl vN and vN+1)"
)
PRIVATE_INVARIANT = (
    "storage layout is append-only AND a reserved __gap OR an ERC-7201 "
    "namespace absorbs future additions so no occupied slot ever shifts"
)

# ---- load-bearing predicates (monkeypatchable in tests to prove non-vacuity) #

# A contract is upgradeable-relevant if it inherits an upgradeable base ...
_A10_UPGRADEABLE_INHERIT_RE = re.compile(
    r"\b("
    r"Initializable"
    r"|UUPSUpgradeable"
    r"|[A-Za-z0-9_]*Upgradeable"     # OwnableUpgradeable, ERC20Upgradeable, ...
    r"|ERC1967[A-Za-z0-9_]*"
    r"|VersionedInitializable"
    r")\b"
)
# ... or it carries an initializer / upgrade-authorizer in its own body.
_A10_UPGRADEABLE_BODY_RE = re.compile(
    r"\b("
    r"onlyInitializing"
    r"|initializer\b"
    r"|reinitializer\s*\("
    r"|_authorizeUpgrade\b"
    r"|function\s+initialize\s*\("     # exact initialize( - not initializeFoo(
    r"|function\s+__[A-Za-z0-9_]+_init\b"
    r")"
)
# Reserved-storage-gap enforcer (OZ-4.x inheritance-gap idiom). Any identifier
# named __gap counts; the canonical form is `uint256[N] private __gap;`.
_A10_GAP_RE = re.compile(r"\b__gap\b")
# ERC-7201 namespaced-storage enforcer: the annotation (raw text) or the
# assembly slot-getter that pins the struct to a hashed location.
_A10_NAMESPACE_RE = re.compile(
    r"(erc7201\s*:"                       # @custom:storage-location erc7201:...
    r"|@custom:storage-location"
    r"|\.slot\s*:="                       # assembly { $.slot := <Location> }
    r"|StorageLocation\s*=\s*0x[0-9a-fA-F]+"  # bytes32 ... constant ...Location = 0x..
    r")"
)

# Members that are NOT storage-occupying state variables.
_NON_STATE_LEADING = (
    "function", "modifier", "event", "error", "using", "constructor",
    "receive", "fallback", "import", "pragma", "type ", "struct", "enum",
)
_STATE_EXCLUDE_TOKEN_RE = re.compile(r"\b(constant|immutable)\b")

# --------------------------------------------------------------------------- #
# comment / string stripping (best-effort, dependency-free)
# --------------------------------------------------------------------------- #


def _strip_comments(src: str) -> str:
    """Remove // and /* */ comments. String literals are left intact (they do
    not contain unbalanced contract-level braces in practice)."""
    out = []
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        nxt = src[i + 1] if i + 1 < n else ""
        if c == "/" and nxt == "/":
            j = src.find("\n", i)
            if j == -1:
                break
            i = j
            continue
        if c == "/" and nxt == "*":
            j = src.find("*/", i + 2)
            i = (j + 2) if j != -1 else n
            continue
        out.append(c)
        i += 1
    return "".join(out)


# --------------------------------------------------------------------------- #
# contract extraction
# --------------------------------------------------------------------------- #

_CONTRACT_HEADER_RE = re.compile(
    r"\b(abstract\s+)?(contract|library|interface)\s+"
    r"([A-Za-z_$][A-Za-z0-9_$]*)"
    r"([^{;]*)\{",
    re.DOTALL,
)


def _iter_contracts(stripped: str) -> Iterable[Dict[str, Any]]:
    """Yield {name, kind, is_abstract, inherits, body, header_start} for every
    top-level contract/library/interface. Bodies are brace-balanced slices."""
    for m in _CONTRACT_HEADER_RE.finditer(stripped):
        is_abstract = bool(m.group(1))
        kind = m.group(2)
        name = m.group(3)
        header_tail = m.group(4) or ""
        open_brace = m.end() - 1
        depth = 0
        i = open_brace
        n = len(stripped)
        while i < n:
            ch = stripped[i]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        body = stripped[open_brace + 1:i]
        inherits = ""
        mi = re.search(r"\bis\b(.*)$", header_tail, re.DOTALL)
        if mi:
            inherits = mi.group(1)
        yield {
            "name": name,
            "kind": kind,
            "is_abstract": is_abstract,
            "inherits": inherits.strip(),
            "body": body,
            "header_start": m.start(),
        }


def _iter_members(body: str) -> Iterable[Tuple[str, str]]:
    """Yield (header_text, kind) for each direct member of a contract body,
    where kind is 'block' (a `{...}` member: function/struct/enum/...) or
    'stmt' (a `;`-terminated member: state var / using / abstract fn)."""
    buf: List[str] = []
    i, n = 0, len(body)
    while i < n:
        c = body[i]
        if c == "{":
            yield ("".join(buf).strip(), "block")
            buf = []
            depth = 1
            i += 1
            while i < n and depth > 0:
                if body[i] == "{":
                    depth += 1
                elif body[i] == "}":
                    depth -= 1
                i += 1
            continue
        if c == ";":
            yield ("".join(buf).strip(), "stmt")
            buf = []
            i += 1
            continue
        buf.append(c)
        i += 1
    tail = "".join(buf).strip()
    if tail:
        yield (tail, "stmt")


def _is_state_var(header: str) -> bool:
    """True iff a `;`-terminated contract member declares raw storage."""
    h = header.strip()
    if not h:
        return False
    low = h.lstrip()
    for kw in _NON_STATE_LEADING:
        if low.startswith(kw):
            return False
    if "__gap" in h:
        return False
    if _STATE_EXCLUDE_TOKEN_RE.search(h):
        return False
    # Must look like `<type> ... <name>` : at least two identifier-ish tokens.
    if not re.search(r"[A-Za-z_$][A-Za-z0-9_$]*", h):
        return False
    tokens = re.findall(r"[A-Za-z_$][A-Za-z0-9_$]*", h)
    if len(tokens) < 2 and "mapping" not in h and "[" not in h:
        return False
    return True


def _state_vars(body: str) -> List[str]:
    """Collect raw-storage variable names declared directly in a contract."""
    names: List[str] = []
    for header, kind in _iter_members(body):
        if kind != "stmt":
            continue
        if not _is_state_var(header):
            continue
        toks = re.findall(r"[A-Za-z_$][A-Za-z0-9_$]*", header)
        # Heuristic name = last identifier before an initializer / end.
        rhs = header.split("=", 1)[0]
        rtoks = re.findall(r"[A-Za-z_$][A-Za-z0-9_$]*", rhs) or toks
        names.append(rtoks[-1])
    return names


# --------------------------------------------------------------------------- #
# core screen
# --------------------------------------------------------------------------- #

CoveredArg = Optional[Union[Set, Callable[[Tuple[str, str]], bool]]]


def _is_covered(key: Tuple[str, str], covered: CoveredArg) -> bool:
    """A1/dedup boundary: consume a covering set/predicate, never re-derive."""
    if covered is None:
        return False
    if callable(covered):
        try:
            return bool(covered(key))
        except Exception:
            return False
    contract, name = key
    return (key in covered) or (name in covered) or (contract in covered)


def _upgradeable_signal(contract: Dict[str, Any]) -> Optional[str]:
    inh = contract.get("inherits") or ""
    if _A10_UPGRADEABLE_INHERIT_RE.search(inh):
        return "inheritance"
    if _A10_UPGRADEABLE_BODY_RE.search(contract.get("body") or ""):
        return "initializer-in-body"
    return None


def screen_source(
    text: str,
    path: Optional[str] = None,
    covered: CoveredArg = None,
) -> List[Dict[str, Any]]:
    """Screen one Solidity source string. Returns advisory hypothesis rows for
    every upgradeable contract whose storage-slot bijection is UNENFORCED
    (raw mutable storage, no __gap, no ERC-7201 namespace)."""
    stripped = _strip_comments(text)
    rows: List[Dict[str, Any]] = []

    for contract in _iter_contracts(stripped):
        if contract["kind"] in ("library", "interface"):
            continue
        signal = _upgradeable_signal(contract)
        if signal is None:
            continue
        body = contract["body"]
        state_vars = _state_vars(body)
        if not state_vars:
            # nothing occupies a slot -> no bijection to corrupt.
            continue
        has_gap = bool(_A10_GAP_RE.search(body))
        # Namespacing is detected on the RAW text region (the erc7201
        # annotation lives in a comment that _strip_comments removed).
        raw_region = text
        namespaced = bool(_A10_NAMESPACE_RE.search(raw_region)) or bool(
            _A10_NAMESPACE_RE.search(body)
        )
        if has_gap or namespaced:
            continue  # enforcement present -> silent

        # line number of the contract header
        line = stripped[: contract["header_start"]].count("\n") + 1

        key = (contract["name"], state_vars[0])
        rows.append({
            "canonical_class": CANONICAL_CLASS,
            "contract": contract["name"],
            "file": path,
            "line": line,
            "is_abstract": contract["is_abstract"],
            "upgradeable_signal": signal,
            "state_var_count": len(state_vars),
            "state_var_sample": state_vars[:8],
            "trusted_invariant": TRUSTED_INVARIANT,
            "private_invariant": PRIVATE_INVARIANT,
            "enforcement_absent": ["reserved-storage-gap", "erc7201-namespace"],
            "reason": (
                f"upgradeable contract `{contract['name']}` declares "
                f"{len(state_vars)} raw storage slot(s) but has NEITHER a "
                f"__gap reserved array NOR ERC-7201 namespacing; a future "
                f"impl that appends a var (or reorders an inheritance base) "
                f"silently shifts every derived/proxy slot -> storage-slot "
                f"bijection unenforced across vN->vN+1"
            ),
            "next_step": (
                "diff storage layout vs the prior impl "
                "(tools/storage-layout.py --compare-dir) OR add a "
                "`uint256[N] __gap` / ERC-7201 namespaced-storage struct"
            ),
            "verdict": "needs-fuzz",
            "auto_credit": False,
            "covered_by": _is_covered(key, covered),
        })
    return rows


def screen_path(target: Union[str, Path], covered: CoveredArg = None) -> List[Dict[str, Any]]:
    """Screen a file or (recursively) a directory of .sol files."""
    p = Path(target)
    rows: List[Dict[str, Any]] = []
    if p.is_file():
        files = [p]
    else:
        files = sorted(
            f for f in p.rglob("*.sol")
            if f.is_file() and "/node_modules/" not in str(f)
        )
    for f in files:
        try:
            txt = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rows.extend(screen_source(txt, path=str(f), covered=covered))
    return rows


def _a10_advisory_enabled() -> bool:
    return os.environ.get(_A10_ENV, "").strip() not in ("", "0", "false", "False")


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("target", help="workspace dir or single .sol file")
    ap.add_argument("--json", action="store_true", help="emit JSON pack")
    ap.add_argument(
        "--strict",
        action="store_true",
        help=(
            "opt into a non-zero exit when rows are emitted AND the dedicated "
            f"env {_A10_ENV} is set. Advisory-first: never fail-closed by "
            "default."
        ),
    )
    args = ap.parse_args(argv)

    target = Path(args.target).expanduser()
    if not target.exists():
        print(f"[err] not found: {target}", file=sys.stderr)
        return 2
    rows = screen_path(target)
    # Advisory sidecar for the hunt corpus (folded by auto-coverage-closer's
    # NETNEW_ADVISORY list) when run over a workspace directory: JSONL, one
    # needs-fuzz / no-auto-credit row per hypothesis, under <ws>/.auditooor/.
    if target.is_dir():
        _sd = target / ".auditooor"
        _sd.mkdir(parents=True, exist_ok=True)
        with open(_sd / "storage_slot_bijection_hypotheses.jsonl", "w", encoding="utf-8") as _sf:
            for _r in rows:
                _sf.write(json.dumps({
                    **_r, "capability": "A10",
                    "verdict": "needs-fuzz", "advisory": True, "auto_credit": False,
                }) + "\n")
    pack = {
        "schema": SCHEMA,
        "canonical_class": CANONICAL_CLASS,
        "target": str(target),
        "advisory": True,
        "advisory_enabled": _a10_advisory_enabled(),
        "trusted_invariant": TRUSTED_INVARIANT,
        "private_invariant": PRIVATE_INVARIANT,
        "row_count": len(rows),
        "rows": rows,
    }
    if args.json:
        json.dump(pack, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
    else:
        print(f"# A10 storage-slot-bijection screen: {target}")
        print(f"advisory-first (verdict=needs-fuzz, no auto-credit); rows={len(rows)}")
        for r in rows:
            print(f"  [{r['upgradeable_signal']}] {r['contract']} "
                  f"(slots={r['state_var_count']}) L{r['line']} :: {r['file']}")
            print(f"      -> {r['reason']}")
    # Advisory-first: fail-closed ONLY when the operator both passes --strict
    # AND has set the dedicated opt-in env. Otherwise always rc 0.
    if args.strict and _a10_advisory_enabled() and rows:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
