"""test_sidecar_slug_frame_key.py

Brick 1 of the (unit x frame) coverage substrate: _sidecar_slug frame-keys on an
optional task `impact` field so a freeze-frame hunt of a function does NOT overwrite
its theft-frame hunt (the strata MIN_SHARES near-miss - latest-wins clobbered the
other impact's verdict). ADDITIVE + backward-compatible: a task with no impact field
yields the byte-identical legacy slug (no regression to existing per-function hunts).
"""
from __future__ import annotations

import importlib.util
import pathlib
import sys
import unittest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "haiku-fanout-dispatcher.py"


def _load():
    spec = importlib.util.spec_from_file_location("haiku_fanout_dispatcher_slug", TOOL_PATH)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["haiku_fanout_dispatcher_slug"] = mod
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


HFD = _load()
_ANC = {"file": "src/tranches/Tranche.sol", "fn": "withdraw", "start_line": 282}


class TestSidecarSlugFrameKey(unittest.TestCase):
    def test_no_impact_is_legacy_slug(self):
        """Backward-compat: a task without an impact field yields the exact legacy
        (file,fn,pathhash,line) slug - no `__I-` suffix, no regression."""
        s = HFD._sidecar_slug({"function_anchor": _ANC}, "t1")
        self.assertNotIn("__I-", s)
        self.assertTrue(s.startswith("hunt__Tranche.sol__withdraw__"))

    def test_frames_are_distinct(self):
        theft = HFD._sidecar_slug({"function_anchor": _ANC, "impact": "direct-theft"}, "t1")
        freeze = HFD._sidecar_slug({"function_anchor": _ANC, "impact": "permanent-freeze"}, "t1")
        self.assertNotEqual(theft, freeze)
        self.assertIn("__I-direct-theft", theft)
        self.assertIn("__I-permanent-freeze", freeze)

    def test_same_frame_is_idempotent(self):
        """Same fn + same frame -> same slug (a genuine re-hunt correctly overwrites
        ITS OWN cell, not a different frame's)."""
        a = HFD._sidecar_slug({"function_anchor": _ANC, "impact": "permanent-freeze"}, "tA")
        b = HFD._sidecar_slug({"function_anchor": _ANC, "impact": "permanent-freeze"}, "tB")
        self.assertEqual(a, b)

    def test_impact_readable_from_anchor_or_task(self):
        a = HFD._sidecar_slug({"function_anchor": dict(_ANC, impact="insolvency")}, "t")
        b = HFD._sidecar_slug({"function_anchor": _ANC, "impact": "insolvency"}, "t")
        self.assertEqual(a, b)

    def test_impact_sanitized(self):
        s = HFD._sidecar_slug({"function_anchor": _ANC, "impact": "Direct Theft / funds!"}, "t")
        self.assertIn("__I-direct-theft-funds", s)
        # no unsafe filename chars leaked
        self.assertNotIn("/", s.split("__I-")[-1])
        self.assertNotIn(" ", s)

    def test_different_functions_still_distinct(self):
        a = HFD._sidecar_slug({"function_anchor": _ANC, "impact": "x"}, "t")
        b = HFD._sidecar_slug({"function_anchor": dict(_ANC, fn="redeem"), "impact": "x"}, "t")
        self.assertNotEqual(a, b)


if __name__ == "__main__":
    unittest.main()
