"""test_f4_quarantine.py

Guards F4-safe (spec section F4, items E4.3 + E4.4) in
tools/dispatch-agent-with-prebriefing.py - the safe halves that INCREASE recall
and never red a workspace.

E4.3 - an unable-to-anchor finding must be routed to a quarantine sink
       (.auditooor/hunt_quarantine.jsonl), a re-dispatch-with-full-source queue,
       instead of being silently set applies_to_target='no' (which fcc miscounts
       as "examined + ruled out"). A quarantined row is UNRESOLVED, NEVER
       ruled_out.

E4.4 - the source-read mandate gains a mode flag:
         verify-strict (default) = current R76 anchor-or-quarantine
         generate-broad          = recall-first: confidence field, kill-rubric
                                   prior OFF, uncertain allowed -> quarantine
       The R76 SOURCE-READ requirement is present in BOTH modes; only the
       negative default differs. Selected via the AUDITOOOR_DISPATCH_HUNT_MODE
       env var or the --hunt-mode CLI flag (flag wins).

These are recall-INCREASING / never-red changes (Wave A), so the test asserts the
quarantine path and the mode scaffolding, NOT a gate failure.
"""

from __future__ import annotations

import importlib.util
import json
import os
import pathlib
import sys
import tempfile
import unittest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "dispatch-agent-with-prebriefing.py"


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "dispatch_agent_with_prebriefing_f4", TOOL_PATH
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load module at {TOOL_PATH}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["dispatch_agent_with_prebriefing_f4"] = mod
    spec.loader.exec_module(mod)  # type: ignore[attr-defined]
    return mod


prebriefing = _load_module()


class TestQuarantineSinkE43(unittest.TestCase):
    """E4.3 - unable-to-anchor lands in hunt_quarantine.jsonl, NOT ruled-out."""

    def test_quarantine_row_written_and_not_ruled_out(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            ws = pathlib.Path(tmpdir)
            sink = prebriefing.quarantine_unable_to_anchor(
                ws,
                unit="Vault.withdraw",
                source_ref="src/Vault.sol:88",
            )
            self.assertIsNotNone(sink)
            # The sink must be the canonical re-dispatch queue path.
            self.assertEqual(sink.name, "hunt_quarantine.jsonl")
            self.assertEqual(sink.parent.name, ".auditooor")
            self.assertTrue(sink.exists())
            lines = [
                ln for ln in sink.read_text(encoding="utf-8").splitlines() if ln.strip()
            ]
            self.assertEqual(len(lines), 1)
            row = json.loads(lines[0])
            # The load-bearing assertion: a quarantined unit is NOT ruled out.
            self.assertIs(row["ruled_out"], False)
            self.assertEqual(row["status"], "quarantined")
            self.assertIs(row["needs_full_source"], True)
            self.assertEqual(row["reason"], "unable-to-anchor")
            self.assertEqual(row["unit"], "Vault.withdraw")
            self.assertEqual(row["source_ref"], "src/Vault.sol:88")
            # applies_to_target='no' (the OLD silent-drop default) must NOT be
            # what a quarantined row carries.
            self.assertNotEqual(row.get("applies_to_target"), "no")

    def test_quarantine_appends_not_truncates(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            ws = pathlib.Path(tmpdir)
            prebriefing.quarantine_unable_to_anchor(ws, unit="A.f1")
            prebriefing.quarantine_unable_to_anchor(ws, unit="B.f2")
            sink = prebriefing.hunt_quarantine_path(ws)
            lines = [
                ln for ln in sink.read_text(encoding="utf-8").splitlines() if ln.strip()
            ]
            self.assertEqual(len(lines), 2)
            units = {json.loads(ln)["unit"] for ln in lines}
            self.assertEqual(units, {"A.f1", "B.f2"})

    def test_extra_cannot_override_ruled_out_invariant(self):
        """A caller-supplied 'ruled_out': True must NOT win - the row stays
        UNRESOLVED. This is the un-fakeable invariant."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ws = pathlib.Path(tmpdir)
            sink = prebriefing.quarantine_unable_to_anchor(
                ws,
                unit="C.f3",
                extra={
                    "ruled_out": True,
                    "status": "dismissed",
                    "needs_full_source": False,
                    "note": "kept",
                },
            )
            row = json.loads(sink.read_text(encoding="utf-8").splitlines()[0])
            self.assertIs(row["ruled_out"], False)
            self.assertEqual(row["status"], "quarantined")
            self.assertIs(row["needs_full_source"], True)
            # A non-conflicting extra field IS preserved.
            self.assertEqual(row["note"], "kept")

    def test_confidence_recorded_when_supplied(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            ws = pathlib.Path(tmpdir)
            sink = prebriefing.quarantine_unable_to_anchor(
                ws, unit="D.f4", confidence=0.35
            )
            row = json.loads(sink.read_text(encoding="utf-8").splitlines()[0])
            self.assertEqual(row["confidence"], 0.35)


class TestHuntModeE44(unittest.TestCase):
    """E4.4 - mode-gated source-read mandate; R76 in BOTH modes."""

    def setUp(self):
        self._saved = os.environ.pop(prebriefing.DISPATCH_HUNT_MODE_ENV_VAR, None)

    def tearDown(self):
        if self._saved is not None:
            os.environ[prebriefing.DISPATCH_HUNT_MODE_ENV_VAR] = self._saved
        else:
            os.environ.pop(prebriefing.DISPATCH_HUNT_MODE_ENV_VAR, None)

    def test_default_mode_is_verify_strict(self):
        self.assertEqual(
            prebriefing.resolve_hunt_mode(), prebriefing.HUNT_MODE_VERIFY_STRICT
        )

    def test_cli_arg_wins_over_env(self):
        os.environ[prebriefing.DISPATCH_HUNT_MODE_ENV_VAR] = "verify-strict"
        self.assertEqual(
            prebriefing.resolve_hunt_mode("generate-broad"),
            prebriefing.HUNT_MODE_GENERATE_BROAD,
        )

    def test_env_selects_mode(self):
        os.environ[prebriefing.DISPATCH_HUNT_MODE_ENV_VAR] = "generate-broad"
        self.assertEqual(
            prebriefing.resolve_hunt_mode(), prebriefing.HUNT_MODE_GENERATE_BROAD
        )

    def test_unknown_mode_falls_back_to_verify_strict(self):
        os.environ[prebriefing.DISPATCH_HUNT_MODE_ENV_VAR] = "nonsense"
        self.assertEqual(
            prebriefing.resolve_hunt_mode(), prebriefing.HUNT_MODE_VERIFY_STRICT
        )
        self.assertEqual(
            prebriefing.resolve_hunt_mode("garbage"),
            prebriefing.HUNT_MODE_VERIFY_STRICT,
        )

    def test_source_read_mandate_present_in_both_modes(self):
        vs = prebriefing.pack_source_read_mandate("verify-strict")
        gb = prebriefing.pack_source_read_mandate("generate-broad")
        for text in (vs, gb):
            self.assertIn("SOURCE-READ MANDATE", text)
            self.assertIn("R76", text)
            self.assertIn("read the real source", text)
            # Both route to the quarantine queue, never silent ruled-out.
            self.assertIn("hunt_quarantine.jsonl", text)
            self.assertIn("unable-to-anchor", text)

    def test_verify_strict_does_not_silently_drop(self):
        vs = prebriefing.pack_source_read_mandate("verify-strict")
        # The OLD silent-drop instruction must be replaced by quarantine
        # routing: it must explicitly tell the agent NOT to set
        # applies_to_target='no'.
        self.assertIn("do NOT set", vs)
        self.assertIn("applies_to_target='no'", vs)
        self.assertIn("never ruled out", vs.lower())

    def test_generate_broad_recall_first_scaffolding(self):
        gb = prebriefing.pack_source_read_mandate("generate-broad")
        vs = prebriefing.pack_source_read_mandate("verify-strict")
        # confidence field + kill-rubric-prior-OFF + uncertain-allowed are
        # exclusive to generate-broad.
        self.assertIn("confidence", gb.lower())
        self.assertIn("kill-rubric prior is OFF", gb)
        self.assertIn("UNCERTAIN", gb.upper())
        self.assertNotIn("confidence", vs.lower())

    def test_default_alias_is_verify_strict(self):
        self.assertEqual(
            prebriefing._PACK_SOURCE_READ_MANDATE,
            prebriefing.pack_source_read_mandate("verify-strict"),
        )

    def test_emitted_pack_section_honors_env_mode(self):
        """The matched-pack section emits the generate-broad mandate when the
        env mode is set - proving the flag is load-bearing end-to-end."""
        ctx = {
            "schema": "auditooor.pre_flight_pack_context.v1",
            "status": "matched",
            "matched": True,
            "path": "",
            "reason": "f4 fixture",
            "pack_count": 1,
            "excerpt": '{"function": "foo", "source_ref": ""}',
        }
        os.environ[prebriefing.DISPATCH_HUNT_MODE_ENV_VAR] = "generate-broad"
        out_broad = "\n".join(
            prebriefing._format_pre_flight_pack_section(ctx, workspace_path=None)
        )
        self.assertIn("kill-rubric prior is OFF", out_broad)
        self.assertIn("SOURCE-READ MANDATE", out_broad)

        os.environ[prebriefing.DISPATCH_HUNT_MODE_ENV_VAR] = "verify-strict"
        out_strict = "\n".join(
            prebriefing._format_pre_flight_pack_section(ctx, workspace_path=None)
        )
        self.assertNotIn("kill-rubric prior is OFF", out_strict)
        self.assertIn("SOURCE-READ MANDATE", out_strict)


class TestHuntModeCliFlag(unittest.TestCase):
    """The --hunt-mode flag parses and is accepted."""

    def test_parser_accepts_hunt_mode(self):
        parser = prebriefing._build_parser()
        args = parser.parse_args(["--hunt-mode", "generate-broad"])
        self.assertEqual(args.hunt_mode, "generate-broad")

    def test_parser_rejects_bad_hunt_mode(self):
        parser = prebriefing._build_parser()
        with self.assertRaises(SystemExit):
            parser.parse_args(["--hunt-mode", "bogus"])


if __name__ == "__main__":
    unittest.main()
