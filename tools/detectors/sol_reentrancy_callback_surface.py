"""G-4 (enforcement-gap 2026-07-03): reentrancy-callback SURFACE applicability detector.

The reentrancy/callback vuln class was silently un-hunted while audit-complete
reported 0 reentrancy findings - a harness can kill a value-conservation mutant
WITHOUT ever exercising a reentrant callback (the surface is usually hardcoded away,
e.g. takerCallback=address(0)). This detector makes the class VISIBLE: it FIRES when
the workspace has a real external-call / callback surface to which reentrancy is
APPLICABLE, so the `reentrancy-callback-surface` mechanism cell becomes an OPEN
obligation the operator must DISPOSITION (covered-by-fuzz with a reentryFired
non-vacuity marker / source-cited rule-out / finding). A workspace with NO such
surface -> 0 findings (mechanism enumerated-clean). Low-FP: keyed on real
external-call / known-callback tokens, one finding per bearing file.

scan_root(root) -> {"schema","mechanism","impact","findings":[...]} (mechanism-scan contract).
"""
import os
import re

SCHEMA = "auditooor.mechanism_scan.v1"
MECHANISM = "reentrancy-callback-surface"
IMPACT = "direct-theft"

# Real value-moving external-call primitives (not a pure view .staticcall).
_CALL_RE = re.compile(r"\.\s*call\s*\{|\.\s*call\s*\(|\.\s*delegatecall\s*\(|"
                      r"\.\s*transfer\s*\(|\.\s*send\s*\(|\bsafeTransfer(?:From)?\s*\(")
# Known reentrancy-relevant callback entrypoints + a generic *Callback( token.
_CB_RE = re.compile(r"\b(?:onFlashLoan|receiveFlashLoan|executeOperation|tokensReceived|"
                    r"tokensToSend|onERC721Received|onERC1155Received|onERC1155BatchReceived|"
                    r"uniswapV2Call|uniswapV3SwapCallback|pancakeCall|[A-Za-z0-9_]+Callback)\s*\(")
_NONREENT_RE = re.compile(r"\bnonReentrant\b")
# A harness/proof marker that a reentrant callback was actually EXERCISED.
_REENTRY_FIRED_RE = re.compile(r"\breentryFired\b|\breentrancyFired\b")


def _sol_files(root):
    for dp, dns, fns in os.walk(root):
        dns[:] = [d for d in dns if d not in
                  ("node_modules", "lib", "out", "artifacts", "cache", "vendor")
                  and not d.startswith(".")]
        for fn in fns:
            if fn.endswith(".sol") and not fn.endswith(".t.sol"):
                yield os.path.join(dp, fn)


def scan_root(root: str) -> dict:
    findings = []
    for p in _sol_files(root):
        try:
            t = open(p, encoding="utf-8", errors="replace").read()
        except OSError:
            continue
        has_call = bool(_CALL_RE.search(t))
        has_cb = bool(_CB_RE.search(t))
        if not (has_call or has_cb):
            continue
        rel = os.path.relpath(p, root) if os.path.isdir(root) else p
        findings.append({
            "schema": SCHEMA, "mechanism": MECHANISM, "impact": IMPACT,
            "file": rel, "line": 1,
            "detail": ("external-call/callback surface present; reentrancy mechanism "
                       "APPLICABLE - disposition required (covered-by-fuzz with a reentryFired "
                       "non-vacuity marker / source-cited rule-out / finding). A nonReentrant "
                       "guard on some fns is NOT proof the callback was exercised."),
            "has_external_call": has_call,
            "has_callback": has_cb,
            "has_nonreentrant_guard": bool(_NONREENT_RE.search(t)),
            "has_reentry_fired_marker": bool(_REENTRY_FIRED_RE.search(t)),
        })
    findings.sort(key=lambda f: f["file"])
    return {"schema": SCHEMA, "mechanism": MECHANISM, "impact": IMPACT, "findings": findings}
