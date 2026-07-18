#!/usr/bin/env python3
"""mock-reference-divergence-check.py - flag a harness/PoC that ROLLS ITS OWN mock
of an external dependency the workspace ALREADY ships a reference mock for.

MOTIVATION (Strata 2026-07-07, a 55-minute waste + a false-positive Medium):
A step-4b lane built its own `contract MockDepositVault is IDepositVault` inside
chimera_harnesses/MidasStrategyConservation/ and made it pull the RAW 18-decimal
amount via transferFrom. But the workspace SHIPS an authoritative reference at
src/contracts/contracts/test/midas/MockDepositVault.sol whose depositInstant
CONVERTS base18 -> native decimals before the pull. The lane never imported the
reference, its rolled-own mock diverged in the exact spot the "bug" lived, and the
result was a plausible-but-invalid finding (killed) after a full 1.2M-call medusa
campaign on an unfaithful harness.

THE RULE (generalized): when a workspace ships a reference/mock for an external
dependency (the protocol team's own model of that dependency's behavior), THAT is
the ground truth. A harness/PoC that DEFINES its own mock of the same dependency,
instead of importing the shipped reference, is presumptively unfaithful - and if
the "finding" or the invariant result depends on that mock's behavior, it may be
vacuous. This gate catches the structural precondition (rolled-own when a
reference exists) BEFORE a campaign burns an hour / a finding is filed.

NEVER-FALSE-POSITIVE: flag ONLY when ALL hold - (a) a harness/PoC/submission file
DEFINES a mock-shaped contract (name Mock*/Fake*/Stub*/Dummy* or *Mock, OR a
contract implementing an interface named I<X> in a harness/PoC file), (b) the
workspace ships a DIFFERENT file (under test/** / mocks/**) that defines a mock of
the SAME subject (same contract name, or a mock implementing the same interface),
and (c) the harness file does NOT import that reference file (by basename). It
does NOT claim the mock is wrong - it flags that a reference exists and should be
reused or the divergence justified.

ADVISORY-FIRST + rebuttal: WARN by default; hard-fail only under the dedicated
AUDITOOOR_MOCK_REFERENCE_STRICT (or AUDITOOOR_L37_STRICT). An inline
`mock-reference-divergence-rebuttal` marker in the harness/finding clears an entry
(reference is abstract / lacks a needed hook / genuinely unusable - justified).
Pure stdlib, offline, Solidity-focused (regex, no full parser).
"""
from __future__ import annotations

import argparse
import json
import os
import re
from pathlib import Path

# A contract name is "mock-shaped" if it looks like a test double.
_MOCK_NAME_RE = re.compile(r"^(?:Mock|Fake|Stub|Dummy|Harness)\w+|\w+(?:Mock|Stub|Fake)$")
_CONTRACT_RE = re.compile(
    r"\bcontract\s+(\w+)\s+is\s+([^{]+)\{|\bcontract\s+(\w+)\s*\{", re.S)
_IMPORT_RE = re.compile(r"""import\s+(?:\{[^}]*\}\s+from\s+)?["']([^"']+)["']""")
_REBUTTAL = "mock-reference-divergence-rebuttal"

# Where the workspace's OWN reference mocks live vs where harness/PoC mocks live.
_REF_GLOBS = ("**/test/**/*.sol", "**/mocks/**/*.sol", "**/mock/**/*.sol")
_HARNESS_GLOBS = ("chimera_harnesses/**/*.sol", "harnesses/**/*.sol",
                  "submissions/**/*.sol", "**/*_PoC*.sol", "**/*Conservation*.sol")
# never descend into build/dep noise
_SKIP = {"node_modules", "lib", "out", "cache", ".git", "artifacts", "typechain"}
# A "reference" must be the PROTOCOL's own shipped model, NOT one of our audit
# artifacts. A mock defined inside our own PoC/harness tree is not ground truth,
# so it is excluded from the reference set (else harnesses match each other = noise).
_ARTIFACT_MARKERS = ("audit_pocs", "poc-tests", "poc_tests", "submissions",
                     "chimera_harnesses", "/harnesses/", "engine-harness")
# Standard primitives have CANONICAL semantics - re-implementing a plain ERC20 /
# ERC4626 mock is harmless (no protocol-specific behavior to diverge on). The gate
# targets mocks of PROTOCOL-SPECIFIC external dependencies (non-standard behavior).
_STANDARD_MOCK_NAMES = {"mockerc20", "mocktoken", "mockweth", "mockweth9",
                        "mockerc721", "mockerc1155", "mockerc4626", "mockerc20metadata",
                        "mockusdc", "mockdai", "mockerc20decimals", "erc20mock"}
_STANDARD_IFACES = {"IERC20", "IERC20Metadata", "IERC4626", "IERC721", "IERC1155",
                    "IERC165", "IERC20Permit"}


def _is_artifact(p: Path) -> bool:
    s = str(p).lower()
    return any(m in s for m in _ARTIFACT_MARKERS)


def _is_standard(name: str, ifaces: set[str]) -> bool:
    if name.lower() in _STANDARD_MOCK_NAMES:
        return True
    return bool(ifaces) and ifaces.issubset(_STANDARD_IFACES)


def _skip(p: Path) -> bool:
    return any(part in _SKIP for part in p.parts)


def _read(p: Path) -> str:
    try:
        return p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _interfaces(bases: str) -> set[str]:
    # only I-prefixed base names (interfaces); ignore ERC20/OZ base contracts.
    return {b.strip().split("(")[0] for b in bases.split(",")
            if re.match(r"\s*I[A-Z]\w*", b.strip())}


def _contracts(text: str) -> list[tuple[str, set[str]]]:
    out = []
    for m in _CONTRACT_RE.finditer(text):
        name = m.group(1) or m.group(3)
        bases = m.group(2) or ""
        if name:
            out.append((name, _interfaces(bases)))
    return out


def _mock_shaped(name: str, ifaces: set[str]) -> bool:
    return bool(_MOCK_NAME_RE.match(name)) or bool(ifaces)


def _collect(ws: Path, globs) -> list[dict]:
    files = {}
    for g in globs:
        for p in ws.glob(g):
            if p.is_file() and not _skip(p):
                files[str(p.resolve())] = p
    out = []
    for p in files.values():
        txt = _read(p)
        if not txt:
            continue
        imports = {Path(i).name for i in _IMPORT_RE.findall(txt)}
        has_rebuttal = _REBUTTAL in txt
        for name, ifaces in _contracts(txt):
            if _mock_shaped(name, ifaces):
                out.append({"file": p, "name": name, "ifaces": ifaces,
                            "imports": imports, "rebuttal": has_rebuttal})
    return out


def check(ws: Path) -> dict:
    ws = ws.expanduser().resolve()
    # references = the protocol's OWN shipped test-tree mocks, never our artifacts.
    refs = [r for r in _collect(ws, _REF_GLOBS) if not _is_artifact(r["file"])]
    harnesses = _collect(ws, _HARNESS_GLOBS)
    ref_files = {str(r["file"].resolve()) for r in refs}
    # index references by mock name and by implemented interface
    ref_by_name: dict[str, list[dict]] = {}
    ref_by_iface: dict[str, list[dict]] = {}
    for r in refs:
        ref_by_name.setdefault(r["name"], []).append(r)
        for i in r["ifaces"]:
            ref_by_iface.setdefault(i, []).append(r)

    findings = []
    for h in harnesses:
        # a harness file that IS the reference file itself is not a rolled-own mock
        if str(h["file"].resolve()) in ref_files:
            continue
        # a standard-primitive mock (plain ERC20/ERC4626) has canonical semantics -
        # re-implementing it is harmless, so it is not a divergence risk.
        if _is_standard(h["name"], h["ifaces"]):
            continue
        # match a shipped reference for the SAME subject (name first, then interface)
        matches = [r for r in ref_by_name.get(h["name"], [])
                   if str(r["file"].resolve()) != str(h["file"].resolve())]
        match_kind = "same-mock-name"
        if not matches:
            for i in h["ifaces"]:
                cand = [r for r in ref_by_iface.get(i, [])
                        if str(r["file"].resolve()) != str(h["file"].resolve())]
                if cand:
                    matches = cand
                    match_kind = f"same-interface:{i}"
                    break
        if not matches:
            continue
        # did the harness import the reference (by basename)? then it's REUSING it.
        ref_basenames = {r["file"].name for r in matches}
        if h["imports"] & ref_basenames:
            continue
        if h["rebuttal"]:
            findings.append({"status": "rebutted", "harness_mock": h["name"],
                             "harness_file": str(h["file"].relative_to(ws))})
            continue
        findings.append({
            "status": "divergence-risk",
            "harness_mock": h["name"],
            "harness_file": str(h["file"].relative_to(ws)),
            "match_kind": match_kind,
            "reference_mock": matches[0]["name"],
            "reference_file": str(matches[0]["file"].relative_to(ws)),
            "detail": (f"harness defines its own {h['name']} ({match_kind}) but the workspace "
                       f"ships a reference at {matches[0]['file'].relative_to(ws)} that it does "
                       "not import - reuse the reference or justify the divergence "
                       f"(<!-- {_REBUTTAL}: ... -->)"),
        })

    risky = [f for f in findings if f["status"] == "divergence-risk"]
    strict = (os.environ.get("AUDITOOOR_MOCK_REFERENCE_STRICT", "").strip().lower()
              not in ("", "0", "false", "no")) or \
             (os.environ.get("AUDITOOOR_L37_STRICT", "").strip().lower()
              not in ("", "0", "false", "no"))
    if not risky:
        verdict = "pass-no-mock-divergence"
    elif strict:
        verdict = "fail-mock-reference-divergence"
    else:
        verdict = "warn-mock-reference-divergence"
    return {"workspace": str(ws), "verdict": verdict, "strict": strict,
            "reference_mocks": len(refs), "harness_mocks": len(harnesses),
            "divergence_risks": len(risky), "findings": findings}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--workspace", required=True, type=Path)
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    r = check(a.workspace)
    if a.json:
        print(json.dumps(r, indent=2))
    else:
        print(f"mock-reference-divergence: {r['verdict']} "
              f"({r['divergence_risks']} risk(s); {r['reference_mocks']} ref / "
              f"{r['harness_mocks']} harness mocks)")
        for f in r["findings"]:
            if f["status"] == "divergence-risk":
                print(f"  <-- {f['harness_file']}: {f['detail']}")
    return 1 if r["verdict"] == "fail-mock-reference-divergence" else 0


if __name__ == "__main__":
    raise SystemExit(main())
