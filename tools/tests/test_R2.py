#!/usr/bin/env python3
"""R2 arch-invariant-suspension-window regression (non-vacuous).

The INVARIANT plane of read-only / cross-function reentrancy: a coupled storage
set S={A,B} whose writer updates A, YIELDS the trust boundary (external call /
transfer / ERC receiver hook), then updates B; while the writer is mid-window S
is temporarily FALSE, and a reachable observer (a view or sibling external
entrypoint) that reads S consumes the false invariant.

Non-vacuity (each predicate is load-bearing):
  1. VULNERABLE: coupled write (A before yield, B after) + an unguarded view
     reading S -> exactly one open suspension-window row (view reader, promotable).
  2. GREEN (CEI): move BOTH writes before the yield -> set settled at the yield
     -> SILENT.
  3. GREEN (shared lock): writer AND reader both nonReentrant -> the reader
     cannot execute in the window -> SILENT.
  4. GREEN (single member): only ONE storage cell written in the window -> not a
     coupled SET -> SILENT (dedup vs single-var reentrancy / A7).
  5. GREEN (no reader): the suspended set is read by no external/view fn -> SILENT.
  6. NEUTRALIZE THE CORE PREDICATE: monkeypatch find_yields -> [] so no yield is
     seen; the VULNERABLE fixture must then FIRE NOTHING (proves the yield-JOIN
     is the load-bearing predicate, not the coupled-write pattern alone).
  7. Advisory-first: rows are verdict=needs-fuzz / advisory / no auto-credit, and
     accounting NEVER blocks by default; it blocks ONLY under
     AUDITOOOR_YIELD_WINDOW_ENFORCE + AUDITOOOR_L37_STRICT.
"""
import contextlib
import importlib.util
import io
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

_T = Path(__file__).resolve().parent.parent


def _load(name, fname):
    s = importlib.util.spec_from_file_location(name, _T / fname)
    m = importlib.util.module_from_spec(s)
    sys.modules[name] = m
    s.loader.exec_module(m)
    return m


R2 = _load("arch_invariant_suspension_window", "arch-invariant-suspension-window.py")


def _mk_ws(files: dict) -> Path:
    ws = Path(tempfile.mkdtemp())
    (ws / ".auditooor").mkdir(parents=True)
    lines = []
    for rel, src in files.items():
        fp = ws / rel
        fp.parent.mkdir(parents=True, exist_ok=True)
        fp.write_text(src, encoding="utf-8")
        lines.append(json.dumps({"file": rel, "unit": f"{rel}::c"}))
    (ws / ".auditooor" / "inscope_units.jsonl").write_text("\n".join(lines) + "\n")
    return ws


def _run(ws):
    findings, acc = R2.analyze(ws)
    return findings, acc


# ---------------------------------------------------------------------------
# Fixtures. A 4626-style vault: totalAssets + totalShares must move together;
# pricePerShare() view reads both.
# ---------------------------------------------------------------------------
_VULN = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IToken { function transfer(address to, uint256 a) external returns (bool); }

contract Vault {
    IToken public token;
    uint256 public totalAssets;
    uint256 public totalShares;
    mapping(address => uint256) public sharesOf;

    // WRITER: updates totalAssets, YIELDS to an external transfer, THEN updates
    // totalShares. Between the two the invariant assets:shares is SUSPENDED.
    function withdraw(uint256 shares) external {
        totalAssets = totalAssets - shares;             // member A written (pre-yield)
        token.transfer(msg.sender, shares);             // YIELD point (external call)
        totalShares = totalShares - shares;             // member B written (post-yield)
        sharesOf[msg.sender] -= shares;
    }

    // READER: a view that reads the SUSPENDED coupled set -> read-only reentrancy.
    function pricePerShare() external view returns (uint256) {
        if (totalShares == 0) return 1e18;
        return (totalAssets * 1e18) / totalShares;
    }
}
"""

# GREEN: CEI - ALL members settled BEFORE the yield.
_GREEN_CEI = _VULN.replace(
    "        totalAssets = totalAssets - shares;             // member A written (pre-yield)\n"
    "        token.transfer(msg.sender, shares);             // YIELD point (external call)\n"
    "        totalShares = totalShares - shares;             // member B written (post-yield)\n"
    "        sharesOf[msg.sender] -= shares;\n",
    "        totalAssets = totalAssets - shares;\n"
    "        totalShares = totalShares - shares;\n"
    "        sharesOf[msg.sender] -= shares;\n"
    "        token.transfer(msg.sender, shares);             // yield AFTER all writes settle\n")

# GREEN: writer AND reader share a reentrancy lock (nonReentrant on both).
_GREEN_LOCK = _VULN.replace(
    "    function withdraw(uint256 shares) external {",
    "    function withdraw(uint256 shares) external nonReentrant {").replace(
    "    function pricePerShare() external view returns (uint256) {",
    "    function pricePerShare() external view nonReentrant returns (uint256) {")

# GREEN: only ONE storage member written in the window (single-var reentrancy =
# A7's turf, not a coupled-invariant suspension).
_GREEN_SINGLE = _VULN.replace(
    "        totalShares = totalShares - shares;             // member B written (post-yield)\n",
    "").replace(
    "        sharesOf[msg.sender] -= shares;\n", "")

# GREEN: nobody reads the suspended set (view removed, no other reader).
_GREEN_NOREADER = _VULN.replace(
    "    // READER: a view that reads the SUSPENDED coupled set -> read-only reentrancy.\n"
    "    function pricePerShare() external view returns (uint256) {\n"
    "        if (totalShares == 0) return 1e18;\n"
    "        return (totalAssets * 1e18) / totalShares;\n"
    "    }\n", "")


class SuspensionWindow(unittest.TestCase):

    def test_vulnerable_fires_once(self):
        ws = _mk_ws({"src/Vault.sol": _VULN})
        f, acc = _run(ws)
        self.assertEqual(len(f), 1, "one coupled invariant suspended at one yield with one reader")
        e = f[0]
        self.assertEqual(e["contract"], "Vault")
        self.assertEqual(e["writer_fn"], "withdraw")
        self.assertIn("totalAssets", e["suspended_invariant_set"])
        self.assertIn("totalShares", e["suspended_invariant_set"])
        self.assertIn("totalAssets", e["members_updated_at_yield"])
        self.assertIn("totalShares", e["members_pending_at_yield"])
        self.assertEqual([r["fn"] for r in e["readers"]], ["pricePerShare"])
        self.assertEqual(e["readers"][0]["kind"], "view")
        self.assertEqual(e["verdict"], "needs-fuzz")
        self.assertTrue(e["advisory"])
        self.assertFalse(e["auto_credit"])
        self.assertTrue(e["promotable"])
        self.assertEqual(acc["status"], "ok")
        self.assertEqual(acc["hypotheses"], 1)
        shutil.rmtree(ws, ignore_errors=True)

    def test_cei_is_green(self):
        ws = _mk_ws({"src/Vault.sol": _GREEN_CEI})
        f, _ = _run(ws)
        self.assertEqual(f, [], "checks-effects-interactions (settled before yield) must be GREEN")
        shutil.rmtree(ws, ignore_errors=True)

    def test_shared_lock_is_green(self):
        ws = _mk_ws({"src/Vault.sol": _GREEN_LOCK})
        f, _ = _run(ws)
        self.assertEqual(f, [], "writer+reader sharing a nonReentrant lock must be GREEN")
        shutil.rmtree(ws, ignore_errors=True)

    def test_single_member_is_green(self):
        ws = _mk_ws({"src/Vault.sol": _GREEN_SINGLE})
        f, _ = _run(ws)
        self.assertEqual(f, [], "a single storage cell in the window is single-var reentrancy (A7), "
                                "not a coupled-invariant suspension")
        shutil.rmtree(ws, ignore_errors=True)

    def test_no_reader_is_green(self):
        ws = _mk_ws({"src/Vault.sol": _GREEN_NOREADER})
        f, _ = _run(ws)
        self.assertEqual(f, [], "no reachable observer of the suspended set -> GREEN")
        shutil.rmtree(ws, ignore_errors=True)

    def test_neutralizing_core_predicate_makes_positive_fail(self):
        # Remove the YIELD-JOIN (the load-bearing predicate): with no yield seen,
        # the coupled-write pattern alone must produce ZERO findings.
        ws = _mk_ws({"src/Vault.sol": _VULN})
        orig = R2.find_yields
        try:
            R2.find_yields = lambda body: []
            f, _ = _run(ws)
            self.assertEqual(f, [], "with the yield predicate neutralized the vulnerable fixture "
                                    "must FIRE NOTHING (the yield-JOIN is load-bearing)")
        finally:
            R2.find_yields = orig
        # sanity: restored predicate re-fires (the neutralization did real work)
        f2, _ = _run(ws)
        self.assertEqual(len(f2), 1)
        shutil.rmtree(ws, ignore_errors=True)


class _EnvGuard:
    _KEYS = ("AUDITOOOR_YIELD_WINDOW_ENFORCE", "AUDITOOOR_L37_STRICT")

    def __init__(self, env):
        self.env = env
        self.saved = {}

    def __enter__(self):
        self.saved = {k: os.environ.get(k) for k in self._KEYS}
        for k in self._KEYS:
            os.environ.pop(k, None)
        os.environ.update(self.env)
        return self

    def __exit__(self, *a):
        for k in self._KEYS:
            os.environ.pop(k, None)
        for k, v in self.saved.items():
            if v is not None:
                os.environ[k] = v


class Gating(unittest.TestCase):

    def test_advisory_by_default_never_blocks(self):
        with _EnvGuard({}):
            ws = _mk_ws({"src/Vault.sol": _VULN})
            with contextlib.redirect_stdout(io.StringIO()):
                rc = R2.main(["--workspace", str(ws)])
            _, acc = _run(ws)
            self.assertEqual(rc, 0, "advisory-first: never fail-closes by default")
            self.assertFalse(acc["blocking"])
            self.assertEqual(acc["verdict"], "pass-invariant-suspension-window")
            self.assertGreaterEqual(acc["hypotheses"], 1)
            shutil.rmtree(ws, ignore_errors=True)

    def test_plain_strict_alone_does_not_block(self):
        with _EnvGuard({"AUDITOOOR_L37_STRICT": "1"}):
            ws = _mk_ws({"src/Vault.sol": _VULN})
            _, acc = _run(ws)
            self.assertFalse(acc["blocking"], "plain L37 strict without the dedicated env stays advisory")
            shutil.rmtree(ws, ignore_errors=True)

    def test_enforce_plus_strict_blocks(self):
        with _EnvGuard({"AUDITOOOR_YIELD_WINDOW_ENFORCE": "1", "AUDITOOOR_L37_STRICT": "1"}):
            ws = _mk_ws({"src/Vault.sol": _VULN})
            with contextlib.redirect_stdout(io.StringIO()):
                rc = R2.main(["--workspace", str(ws)])
            _, acc = _run(ws)
            self.assertEqual(rc, 1, "open suspension-window row must fail-closed under enforce+strict")
            self.assertTrue(acc["blocking"])
            self.assertEqual(acc["verdict"], "fail-invariant-suspension-open")
            shutil.rmtree(ws, ignore_errors=True)

    def test_enforce_plus_strict_but_clean_is_green(self):
        with _EnvGuard({"AUDITOOOR_YIELD_WINDOW_ENFORCE": "1", "AUDITOOOR_L37_STRICT": "1"}):
            ws = _mk_ws({"src/Vault.sol": _GREEN_CEI})
            with contextlib.redirect_stdout(io.StringIO()):
                rc = R2.main(["--workspace", str(ws)])
            _, acc = _run(ws)
            self.assertEqual(rc, 0, "no open row -> passes even under enforce+strict")
            self.assertFalse(acc["blocking"])
            shutil.rmtree(ws, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
