#!/usr/bin/env python3
"""Regression: the calibration vault emitter must render dict-shaped mitigation
rows without a TypeError.

tools/calibration/routing_manifest.yaml carries single-key {label: detail} dicts
(e.g. {"See INC-001": "..."}) mixed with plain strings under `mitigations`;
emit_task_type_note did a raw ', '.join(mits) which raised
`TypeError: sequence item N: expected str instance, dict found` for the
fixture-synthesis / fp-repair-yaml / missing-path-evidence task types.

Non-vacuous: a dict must render as 'label: detail'; and a join over a mixed
list must never raise (the last test proves the RAW join the bug used DOES raise,
so the helper is load-bearing).
"""
from __future__ import annotations

import importlib.util
import pathlib
import sys
import unittest

TOOLS = pathlib.Path(__file__).resolve().parents[1]
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))


def _load():
    spec = importlib.util.spec_from_file_location(
        "agent_calibration_vault_emit", TOOLS / "agent-calibration-vault-emit.py")
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(mod)  # type: ignore
    return mod


M = _load()


class FmtMitigationTest(unittest.TestCase):
    def test_plain_string_passthrough(self):
        self.assertEqual(M._fmt_mitigation("run smoke-tests"), "run smoke-tests")

    def test_single_key_dict_label_detail(self):
        self.assertEqual(
            M._fmt_mitigation({"See INC-001": "91 fake fixtures"}),
            "See INC-001: 91 fake fixtures")

    def test_multi_key_dict_joined(self):
        out = M._fmt_mitigation({"a": "1", "b": "2"})
        self.assertIn("a: 1", out)
        self.assertIn("b: 2", out)

    def test_mixed_list_join_never_raises(self):
        # Exactly the shape emit_task_type_note renders (fixture-synthesis).
        mits = ["Run smoke-tests on every generated fixture before use",
                {"See INC-001": "minimax generated 91 fake passing fixtures"}]
        rendered = ", ".join(M._fmt_mitigation(m) for m in mits)
        self.assertIn("smoke-tests", rendered)
        self.assertIn(
            "See INC-001: minimax generated 91 fake passing fixtures", rendered)

    def test_raw_join_would_raise_without_helper(self):
        # Proves the bug: the raw join the emitter used raises on a dict element.
        with self.assertRaises(TypeError):
            ", ".join(["ok", {"k": "v"}])  # type: ignore[list-item]


if __name__ == "__main__":
    unittest.main()
