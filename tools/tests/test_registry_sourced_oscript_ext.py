#!/usr/bin/env python3
"""Guard: exploit-class-coverage._SRC_EXTS and
unhunted-surface-followthrough-gate._UNIT_SRC_EXTS are REGISTRY-SOURCED
(lib.source_extensions.SOURCE_EXTS), so an LLM-hunt-only language - Oscript
(.oscript/.aa) - is recognized without a per-tool ext-list edit.

Obyte 2026-07-09 gap (readiness-map):
  * exploit-class-coverage._SRC_EXTS lacked .oscript/.aa/.js, so a
    not-applicable disposition could NOT cite an Oscript source file as
    proof-of-absence (it failed evidence-binding "not a source file").
  * unhunted-surface-followthrough-gate._UNIT_SRC_EXTS lacked oscript/aa, so
    the value-moving fc cross-credit + universe-pruning parsed every Oscript
    surface to None and kept it conservatively: an LLM-hunt sidecar could
    never credit an Oscript surface, and a still-open one was never surfaced.

Both ext lists now derive from SOURCE_EXTS. Solidity (.sol) behavior must stay
byte-identical.
"""
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

_TOOLS = Path(__file__).resolve().parent.parent


def _load(name, fn):
    spec = importlib.util.spec_from_file_location(name, str(_TOOLS / fn))
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m


ecc = _load("ecc_reg", "exploit-class-coverage.py")
ug = _load("ug_reg", "unhunted-surface-followthrough-gate.py")

# The canonical registry (same import path the tools use).
sys.path.insert(0, str(_TOOLS))
from lib.source_extensions import SOURCE_EXTS  # noqa: E402


class TestRegistrySourced(unittest.TestCase):
    def test_ecc_src_exts_is_registry_superset(self):
        # every registry ext (incl .oscript/.aa/.js) is an accepted N/A source ext
        for e in SOURCE_EXTS:
            self.assertIn(e, ecc._SRC_EXTS, f"{e} missing from exploit-class _SRC_EXTS")
        # legacy non-registry exts preserved (no language regresses)
        for e in (".cpp", ".c", ".huff"):
            self.assertIn(e, ecc._SRC_EXTS)
        # Oscript specifically
        self.assertIn(".oscript", ecc._SRC_EXTS)
        self.assertIn(".aa", ecc._SRC_EXTS)

    def test_unhunted_unit_exts_is_registry_dotstripped(self):
        # _UNIT_SRC_EXTS is the dot-stripped registry (regex-alternation form)
        for e in SOURCE_EXTS:
            self.assertIn(e[1:], ug._UNIT_SRC_EXTS, f"{e} missing from _UNIT_SRC_EXTS")
        self.assertIn("oscript", ug._UNIT_SRC_EXTS)
        self.assertIn("aa", ug._UNIT_SRC_EXTS)

    def test_no_registry_ext_is_prefix_of_another(self):
        # order-safety of the regex alternation: no ext is a prefix of another,
        # so alternation order never truncates a longer ext.
        bare = [e[1:] for e in SOURCE_EXTS]
        for a in bare:
            for b in bare:
                if a != b:
                    self.assertFalse(
                        b.startswith(a),
                        f"ext {a!r} is a prefix of {b!r}: regex alternation is order-sensitive",
                    )


class TestExploitClassOscriptNA(unittest.TestCase):
    """A not-applicable disposition may cite an Oscript source file as
    proof-of-absence; Solidity behavior is unchanged."""

    def setUp(self):
        self.ws = Path(tempfile.mkdtemp()).resolve()
        (self.ws / "src").mkdir(parents=True)
        (self.ws / "src" / "agent.aa").write_text('{ "cases": [ { "if": "1" } ] }')
        (self.ws / "src" / "lib.oscript").write_text("$f = 1;")
        (self.ws / "src" / "Core.sol").write_text("contract Core { constructor() {} }")
        (self.ws / "notes.md").write_text("prose, not a source file, no scope/severity")

    def test_oscript_and_aa_na_evidence_accepted(self):
        ok_aa, _ = ecc._evidence_ok(self.ws, "src/agent.aa", "not-applicable")
        ok_os, _ = ecc._evidence_ok(self.ws, "src/lib.oscript", "not-applicable")
        self.assertTrue(ok_aa, ".aa N/A source must be accepted")
        self.assertTrue(ok_os, ".oscript N/A source must be accepted")

    def test_solidity_na_unchanged(self):
        ok, why = ecc._evidence_ok(self.ws, "src/Core.sol", "not-applicable")
        self.assertTrue(ok, f".sol N/A source must stay accepted: {why}")

    def test_non_source_na_still_rejected(self):
        # a prose .md with no scope/severity marker is still NOT a valid N/A basis
        ok, _ = ecc._evidence_ok(self.ws, "notes.md", "not-applicable")
        self.assertFalse(ok, "a non-source prose file must not back a not-applicable")


class TestUnhuntedOscriptRecognitionAndCredit(unittest.TestCase):
    def test_oscript_surface_recognized(self):
        self.assertEqual(
            ug._parse_unit_target("unhunted-surface target: agent.aa::distribute"),
            ("agent.aa", "distribute"),
        )
        self.assertEqual(
            ug._parse_unit_target("unhunted-surface target: token.oscript::vote"),
            ("token.oscript", "vote"),
        )

    def test_solidity_surface_unchanged(self):
        self.assertEqual(ug._parse_unit_target("Vault.sol::deposit"), ("vault.sol", "deposit"))

    def test_unknown_ext_still_none(self):
        # fail-safe: a non-source ext still yields None (kept conservatively)
        self.assertIsNone(ug._parse_unit_target("notes.txt::foo"))

    def test_oscript_with_sidecar_credited_without_stays_uncovered(self):
        # Grounded in the real obyte sidecar anchor agent.aa::distribute
        # (aa-sweep-cascading-donations-negative.json). WITH a matching sidecar =>
        # fc-terminal (hunted to a verdict) => credited/dropped. WITHOUT => fc
        # non-terminal => KEPT (still an uncovered value-moving gap). No over-credit.
        universe = {("agent.aa", "distribute"), ("token.oscript", "vote")}
        terminal = {("agent.aa", "distribute")}
        rows = [
            {"title": "unhunted-surface target: agent.aa::distribute", "id": "WITH", "source": "eq"},
            {"title": "unhunted-surface target: token.oscript::vote", "id": "NO", "source": "eq"},
        ]
        kept, dropped_term, dropped_oou = ug._fc_credit_filter(
            [dict(r) for r in rows], universe, terminal, None
        )
        kept_ids = [r["id"] for r in kept]
        self.assertEqual(kept_ids, ["NO"], "the without-sidecar surface must stay uncovered")
        self.assertEqual(dropped_term, 1, "the with-sidecar (hunted) surface must be credited")
        self.assertEqual(dropped_oou, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
