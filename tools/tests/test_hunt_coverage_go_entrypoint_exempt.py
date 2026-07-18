#!/usr/bin/env python3
"""Regression: hunt-coverage-gate must align its STRICT queued-not-scanned
obligation with function-coverage-completeness' Go entry-point surface.

Axelar-DLT field run 2026-07-12: fcc narrowed the Cosmos/Go-L1 coverage
denominator to true external entry points (go_entry_surface.applied=True,
internal helpers excluded), but hunt-coverage-gate's queued_units_strict was
drawn on the every-exported source-unit basis, so it demanded hunting 445
exported-yet-non-entrypoint keeper helpers (baseKeeper.CreateChain,
ABIInflationGuard.walk) that fcc already treats as covered - a permanent
fail-queued-not-scanned false-red. The fix exempts a queued `<file>.go::<fn>`
unit that is NOT one of fcc's enumerated entry points, while KEEPING the entry
points themselves obligated (never a false-pass), and restricting the exemption
to .go units (Rust/tofn helpers keep their own obligation).
"""
import importlib.util
import unittest
from pathlib import Path

_MOD = Path(__file__).resolve().parent.parent / "hunt-coverage-gate.py"
_spec = importlib.util.spec_from_file_location("hcg", _MOD)
g = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(g)


class TestGoEntrypointExempt(unittest.TestCase):
    def setUp(self):
        # entry-point set: one msg-server handler (basename + relpath spellings)
        self.ep_base = {"msg_server.go::AddCosmosBasedChain"}
        self.ep_rel = {"src/x/axelarnet/keeper/msg_server.go::AddCosmosBasedChain"}

    def test_exported_non_entrypoint_go_helper_is_exempt(self):
        # baseKeeper.CreateChain is exported but NOT an entry point => helper => exempt
        self.assertTrue(
            g._unit_is_go_nonentrypoint_helper(
                "baseKeeper.go::CreateChain", self.ep_base, self.ep_rel))

    def test_entry_point_stays_obligated(self):
        # the enumerated entry point (basename spelling) is NOT exempt
        self.assertFalse(
            g._unit_is_go_nonentrypoint_helper(
                "msg_server.go::AddCosmosBasedChain", self.ep_base, self.ep_rel))

    def test_entry_point_relpath_spelling_stays_obligated(self):
        self.assertFalse(
            g._unit_is_go_nonentrypoint_helper(
                "src/x/axelarnet/keeper/msg_server.go::AddCosmosBasedChain",
                self.ep_base, self.ep_rel))

    def test_rust_helper_never_exempted_here(self):
        # a Rust/tofn helper absent from the Go entry-point set must NOT be exempt
        # (its obligation is carried by the Rust coverage basis, not go_entry_surface)
        self.assertFalse(
            g._unit_is_go_nonentrypoint_helper(
                "k256_serde.rs::from_bytes", self.ep_base, self.ep_rel))

    def test_file_only_unit_never_exempted(self):
        self.assertFalse(
            g._unit_is_go_nonentrypoint_helper(
                "baseKeeper.go", self.ep_base, self.ep_rel))

    def test_loader_fail_closed_without_artifact(self):
        import tempfile
        ws = Path(tempfile.mkdtemp())
        applied, base, rel = g._load_fcc_go_entrypoint_keys(ws)
        self.assertFalse(applied)
        self.assertEqual(base, set())
        self.assertEqual(rel, set())

    def test_loader_requires_go_entry_surface_applied(self):
        import json
        import tempfile
        ws = Path(tempfile.mkdtemp())
        (ws / ".auditooor").mkdir(parents=True)
        # go_entry_surface NOT applied => loader must report applied=False (fail-closed)
        (ws / ".auditooor" / "function_coverage_completeness.json").write_text(
            json.dumps({
                "go_entry_surface": {"applied": False},
                "functions": [{"name": "Foo", "file": "src/x.go"}],
            }))
        applied, _, _ = g._load_fcc_go_entrypoint_keys(ws)
        self.assertFalse(applied)

    def test_loader_builds_keys_when_applied(self):
        import json
        import tempfile
        ws = Path(tempfile.mkdtemp())
        (ws / ".auditooor").mkdir(parents=True)
        (ws / ".auditooor" / "function_coverage_completeness.json").write_text(
            json.dumps({
                "go_entry_surface": {"applied": True},
                "functions": [
                    {"name": "AddCosmosBasedChain",
                     "file": "src/x/axelarnet/keeper/msg_server.go"},
                ],
            }))
        applied, base, rel = g._load_fcc_go_entrypoint_keys(ws)
        self.assertTrue(applied)
        self.assertIn("msg_server.go::AddCosmosBasedChain", base)
        self.assertIn("src/x/axelarnet/keeper/msg_server.go::AddCosmosBasedChain", rel)
        # a helper in the same file but not enumerated is a non-entrypoint
        self.assertTrue(
            g._unit_is_go_nonentrypoint_helper("msg_server.go::internalHelper", base, rel))


if __name__ == "__main__":
    unittest.main()
