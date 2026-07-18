#!/usr/bin/env python3
"""Unit tests for tools/go_toolchain_env.py (stdlib-only).

Regression for the recurring "GOTOOLCHAIN suspected" class: a Go ws that pins a toolchain
in go.mod/go.work must have GOTOOLCHAIN set in the subprocess env so a dep that only compiles
under the pin is not a silent build_failed on the host default; a ws with NO toolchain
directive must leave the env BYTE-IDENTICAL (no accidental hardcode / no key added)."""
from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path


def _load():
    spec = importlib.util.spec_from_file_location(
        "go_toolchain_env",
        Path(__file__).parent.parent / "go_toolchain_env.py",
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


gte = _load()


class TestWorkspaceToolchain(unittest.TestCase):
    def test_toolchain_directive_pinned(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "go.mod").write_text(
                "module example.com/x\n\ngo 1.25\n\ntoolchain go1.25.8\n", encoding="utf-8")
            self.assertEqual(gte.workspace_go_toolchain(d), "go1.25.8")

    def test_three_part_go_directive_pins(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "go.mod").write_text(
                "module example.com/x\n\ngo 1.24.1\n", encoding="utf-8")
            self.assertEqual(gte.workspace_go_toolchain(d), "go1.24.1")

    def test_two_part_go_directive_is_not_a_pin(self):
        # `go 1.24` is a language minimum, not a toolchain pin -> '' (goX.Y is malformed).
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "go.mod").write_text(
                "module example.com/x\n\ngo 1.24\n", encoding="utf-8")
            self.assertEqual(gte.workspace_go_toolchain(d), "")

    def test_no_go_mod_no_pin(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(gte.workspace_go_toolchain(d), "")

    def test_go_work_toolchain_wins(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "go.work").write_text(
                "go 1.25\n\ntoolchain go1.25.8\n\nuse ./mod\n", encoding="utf-8")
            self.assertEqual(gte.workspace_go_toolchain(d), "go1.25.8")


class TestApplyGoToolchain(unittest.TestCase):
    def test_pinned_sets_gotoolchain(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "go.mod").write_text(
                "module example.com/x\n\ngo 1.25\n\ntoolchain go1.25.8\n", encoding="utf-8")
            env = {"PATH": "/usr/bin"}
            got = gte.apply_go_toolchain(env, d, loosen_goproxy_if_needed=False)
            self.assertEqual(got, "go1.25.8")
            self.assertEqual(env["GOTOOLCHAIN"], "go1.25.8")

    def test_no_directive_leaves_env_byte_identical(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "go.mod").write_text(
                "module example.com/x\n\ngo 1.24\n", encoding="utf-8")
            env = {"PATH": "/usr/bin", "GOFLAGS": "-mod=mod"}
            before = dict(env)
            got = gte.apply_go_toolchain(env, d, loosen_goproxy_if_needed=False)
            self.assertEqual(got, "")
            self.assertEqual(env, before)  # byte-identical, no GOTOOLCHAIN key added
            self.assertNotIn("GOTOOLCHAIN", env)

    def test_no_go_mod_leaves_env_byte_identical(self):
        with tempfile.TemporaryDirectory() as d:
            env = {"PATH": "/usr/bin"}
            before = dict(env)
            self.assertEqual(gte.apply_go_toolchain(env, d), "")
            self.assertEqual(env, before)

    def test_already_set_gotoolchain_respected(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "go.mod").write_text(
                "module example.com/x\n\ntoolchain go1.25.8\n", encoding="utf-8")
            env = {"GOTOOLCHAIN": "go1.24.1"}  # explicit caller/operator choice
            got = gte.apply_go_toolchain(env, d)
            self.assertEqual(got, "go1.24.1")
            self.assertEqual(env["GOTOOLCHAIN"], "go1.24.1")


if __name__ == "__main__":
    unittest.main()
