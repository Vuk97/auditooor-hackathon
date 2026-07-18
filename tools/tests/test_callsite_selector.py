#!/usr/bin/env python3
"""AST-exact name/signature-filtered CALL-SITE selector - regression + grep-delta.

Pins the Glider gap #4 capability added in ``tools/slither_predicates.py``
(``callsites_of``) + ``tools/callsite-selector.py`` + the AST wiring in
``tools/missing-guard-callsite-enumerator.sh``.

Honesty (R80): the AST cases require a real Slither compile of the in-tree
fixture; if Slither is not importable they SKIP (no faked pass). The DEGRADE /
grep-fallback path runs WITHOUT Slither.

Proof-the-upgrade-is-real (the brief's core assertion):
  - ``test_ast_finds_all_five_dispatch_shapes`` - the AST selector returns the
    direct, alias, overload, virtual-override, AND interface call sites (5).
  - ``test_grep_misses_alias_overload_dispatch`` - a name-canonical grep
    (``ExitLib.validateExit``, the grep enumerator's keying) MISSES the alias,
    the interface, and the virtual-override sites that the AST catches.
  - ``test_ast_is_superset_or_equal_of_grep`` - every grep-found site is also in
    the AST set; the AST set is strictly larger (never fewer genuine sites).
  - ``test_signature_filter_excludes_other_overload`` - a signature target
    ``validateExit(uint256)`` excludes the ``(uint256,address)`` overload.
  - ``test_degrade_on_non_navigable`` / ``test_cli_degrades_on_uncompilable``
    - R80 fallback: no crash, sentinel rc, callers fall back to grep.
"""
from __future__ import annotations

import importlib.util
import os
import pathlib
import re
import subprocess
import sys
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
TOOLS = ROOT / "tools"
FX = ROOT / "tests" / "fixtures" / "callsite_selector"
FX_ENTRY = FX / "Callers.sol"
SELECTOR = TOOLS / "callsite-selector.py"

if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))


def _load_sp():
    spec = importlib.util.spec_from_file_location(
        "slither_predicates_cs_test", TOOLS / "slither_predicates.py"
    )
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


sp = _load_sp()


def _slither_available() -> bool:
    try:
        import slither  # noqa: F401

        return True
    except Exception:
        return False


SKIP_NO_SLITHER = unittest.skipUnless(
    _slither_available(),
    "slither-analyzer not importable; AST call-site tests need a real compile",
)


def _compile_entry():
    from slither import Slither

    return Slither(str(FX_ENTRY))


def _grep_canonical_sites(target_owner: str):
    """The grep enumerator's keying: name-canonical grep over the source text.
    Returns the set of (line) for non-comment matches of ``<owner>.<name>``."""
    text = FX_ENTRY.read_text(encoding="utf-8").splitlines()
    rx = re.compile(re.escape(target_owner))
    hits = set()
    for i, line in enumerate(text, start=1):
        stripped = line.strip()
        if stripped.startswith("//"):
            continue
        if rx.search(line):
            hits.add(i)
    return hits


# ─── DEGRADE / fallback (no Slither needed) ──────────────────────────────────


class DegradeTest(unittest.TestCase):
    def test_degrade_on_non_navigable(self):
        self.assertTrue(sp.is_degraded(sp.callsites_of("x", ["not a contract"])))

    def test_degrade_on_empty_scope(self):
        self.assertTrue(sp.is_degraded(sp.callsites_of("x", [])))

    def test_degrade_on_none(self):
        self.assertTrue(sp.is_degraded(sp.callsites_of("x", None)))

    def test_cli_degrades_on_uncompilable(self):
        """R80: CLI on an uncompilable path emits degraded + rc=3 (the sentinel
        the bash enumerator keys on to fall back to grep) - never crashes."""
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            (pathlib.Path(td) / "readme.txt").write_text("not solidity")
            cp = subprocess.run(
                [sys.executable, str(SELECTOR), "--target", "x",
                 "--path", td, "--json"],
                capture_output=True, text=True,
            )
            self.assertEqual(cp.returncode, 3, cp.stderr)
            self.assertIn('"degraded": true', cp.stdout)

    def test_cli_usage_error_on_missing_path(self):
        cp = subprocess.run(
            [sys.executable, str(SELECTOR), "--target", "x",
             "--path", "/no/such/path/here"],
            capture_output=True, text=True,
        )
        self.assertEqual(cp.returncode, 2, cp.stderr)


# ─── AST-exact semantics (require a real Slither compile) ─────────────────────


@SKIP_NO_SLITHER
class AstSelectorTest(unittest.TestCase):
    def setUp(self):
        self.sl = _compile_entry()
        self.rows = sp.callsites_of("validateExit", self.sl.contracts)
        self.assertFalse(sp.is_degraded(self.rows))

    def test_ast_finds_all_five_dispatch_shapes(self):
        # 5 call sites: direct(lib), alias(lib), overload(lib),
        # virtual-override, interface.
        lines = sorted(r["line"] for r in self.rows)
        self.assertEqual(len(self.rows), 5, self.rows)
        kinds = set(r["dispatch_kind"] for r in self.rows)
        # library covers the direct/alias/overload (using-for resolution);
        # virtual-override + interface are distinct dispatch kinds.
        self.assertIn("virtual-override", kinds)
        self.assertIn("interface", kinds)
        self.assertIn("library", kinds)
        # The five distinct source lines (34 direct, 40 alias, 46 overload,
        # 53 virtual-override, 59 interface).
        self.assertEqual(lines, [34, 40, 46, 53, 59], self.rows)

    def test_ast_catches_alias_site(self):
        # The alias call (Checks.validateExit, L40) resolves to ExitLib.
        alias = [r for r in self.rows if r["line"] == 40]
        self.assertEqual(len(alias), 1)
        self.assertEqual(alias[0]["callee"], "ExitLib.validateExit(uint256)")

    def test_ast_catches_interface_site_resolved(self):
        iface = [r for r in self.rows if r["dispatch_kind"] == "interface"]
        self.assertEqual(len(iface), 1)
        self.assertEqual(iface[0]["line"], 59)

    def test_ast_catches_virtual_override_site(self):
        vo = [r for r in self.rows if r["dispatch_kind"] == "virtual-override"]
        self.assertEqual(len(vo), 1)
        self.assertEqual(vo[0]["line"], 53)
        self.assertEqual(vo[0]["callee"], "Vault.validateExit(uint256)")

    def test_grep_misses_alias_overload_dispatch(self):
        # The grep enumerator keys on the canonical owner 'ExitLib.validateExit'.
        grep_lines = _grep_canonical_sites("ExitLib.validateExit")
        # Grep finds only the two literal ExitLib.validateExit sites (34 direct,
        # 46 overload). It cannot resolve the alias / interface / virtual sites.
        self.assertIn(34, grep_lines)
        self.assertIn(46, grep_lines)
        # The three sites grep MISSES (alias 40, virtual 53, interface 59):
        for missed in (40, 53, 59):
            self.assertNotIn(missed, grep_lines,
                             f"grep unexpectedly found line {missed}")
        ast_lines = set(r["line"] for r in self.rows)
        for missed in (40, 53, 59):
            self.assertIn(missed, ast_lines,
                          f"AST failed to catch grep-missed line {missed}")

    def test_ast_is_superset_or_equal_of_grep(self):
        # Never-fewer-sites-than-grep: every grep-found site is in the AST set.
        grep_lines = _grep_canonical_sites("ExitLib.validateExit")
        ast_lines = set(r["line"] for r in self.rows)
        self.assertTrue(grep_lines.issubset(ast_lines),
                        f"AST {ast_lines} is NOT a superset of grep {grep_lines}")
        # And strictly larger (the upgrade is real, not a no-op).
        self.assertGreater(len(ast_lines), len(grep_lines))

    def test_signature_filter_excludes_other_overload(self):
        # A signature target matches ONLY that overload.
        sig_rows = sp.callsites_of("validateExit(uint256)", self.sl.contracts)
        self.assertFalse(sp.is_degraded(sig_rows))
        sigs = set(r["callee_sig"] for r in sig_rows)
        self.assertIn("validateExit(uint256)", sigs)
        self.assertNotIn("validateExit(uint256,address)", sigs)
        # The (uint256,address) overload site (L46) is excluded.
        self.assertNotIn(46, set(r["line"] for r in sig_rows))

    def test_cli_ast_path_emits_five(self):
        # The standalone CLI (AST path) emits the 5 sites.
        cp = subprocess.run(
            [sys.executable, str(SELECTOR), "--target", "validateExit",
             "--path", str(FX_ENTRY), "--json"],
            capture_output=True, text=True,
        )
        self.assertEqual(cp.returncode, 0, cp.stderr)
        import json

        data = json.loads(cp.stdout)
        self.assertFalse(data["degraded"])
        self.assertEqual(len(data["callsites"]), 5)


# ─── Enumerator wiring: AST block is additive + falls back (R80) ─────────────


@SKIP_NO_SLITHER
class EnumeratorWiringTest(unittest.TestCase):
    ENUM = TOOLS / "missing-guard-callsite-enumerator.sh"

    def test_enumerator_emits_ast_block_for_sol(self):
        # Running the enumerator over the fixture dir surfaces the AST-EXACT
        # block: the selector's per-file union fallback compiles the entry file
        # standalone so the 5 dispatch sites are resolved even on a config-less
        # tree. The AST block is ADDITIVE - the grep path still runs after it.
        env = dict(os.environ)
        env["AUDITOOOR_SLITHER_PYTHON"] = sys.executable
        cp = subprocess.run(
            [str(self.ENUM), str(FX), "validateExit", "validateExit",
             "--language", "sol"],
            capture_output=True, text=True, env=env,
        )
        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertIn("AST-EXACT GUARDED call sites", cp.stdout)
        # The alias (L40), virtual-override (L53), interface (L59) sites the
        # grep path misses appear in the AST block.
        ast_block = cp.stdout.split("AST-EXACT GUARDED call sites")[1].split(
            "GUARDED sites (call")[0]
        for marker in ("Callers.sol:40", "Callers.sol:53", "Callers.sol:59",
                       "virtual-override", "interface"):
            self.assertIn(marker, ast_block, ast_block[:2000])
        # The grep path still ran (additive, never-regress).
        self.assertIn("GUARDED sites (call validateExit)", cp.stdout)

    def test_enumerator_falls_back_when_selector_degrades(self):
        # R80: when the selector cannot run (no slither in the chosen python),
        # the enumerator prints the fallback note and continues with grep -
        # never crashes.
        env = dict(os.environ)
        # Point at a python that definitely cannot import slither: use a bogus
        # interpreter so the selector subprocess fails -> rc != 0 -> fallback.
        env["AUDITOOOR_SLITHER_PYTHON"] = "/usr/bin/false"
        cp = subprocess.run(
            [str(self.ENUM), str(FX), "validateExit", "validateExit",
             "--language", "sol"],
            capture_output=True, text=True, env=env,
        )
        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertIn("R80 fallback", cp.stdout)
        self.assertIn("GUARDED sites (call validateExit)", cp.stdout)


if __name__ == "__main__":
    unittest.main()
