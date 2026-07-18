from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from io import StringIO
from pathlib import Path
from contextlib import redirect_stdout


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "detectors" / "go_permissionless_admin_key_sentinel.py"
FIX_DIR = REPO_ROOT / "tools" / "detectors" / "fixtures" / "d8_admin_sentinel"


def _load():
    spec = importlib.util.spec_from_file_location(
        "go_permissionless_admin_key_sentinel", TOOL_PATH
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load detector")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["go_permissionless_admin_key_sentinel"] = mod
    spec.loader.exec_module(mod)
    return mod


detector = _load()


KEEPER_HELPER_FIXTURE = REPO_ROOT / "tools" / "detectors" / "fixtures" / "d8_admin_sentinel" / "keeper_helper_no_auth.go"


def _run(root: Path, *, entrypoints_only: bool = False) -> dict:
    args = [str(root)]
    if entrypoints_only:
        args.append("--entrypoints-only")
    buf = StringIO()
    with redirect_stdout(buf):
        rc = detector.main(args)
    payload = json.loads(buf.getvalue())
    payload["_rc"] = rc
    return payload


class TestD8AdminSentinel(unittest.TestCase):
    def test_pattern_a_fires_on_unguarded_write(self):
        payload = _run(FIX_DIR / "positive")
        self.assertEqual(payload["_rc"], 0)
        a_hits = [s for s in payload["sentinels"] if s["pattern"] == "A"]
        # Pattern A fires on SetParams in permissionless_write_no_auth.go
        a_methods = {s["method"] for s in a_hits}
        self.assertIn("SetParams", a_methods)
        for s in a_hits:
            self.assertEqual(s["severity_hint"], "HIGH")

    def test_pattern_b_fires_on_admin_key_concentration(self):
        payload = _run(FIX_DIR / "positive")
        b_hits = [s for s in payload["sentinels"] if s["pattern"] == "B"]
        b_methods = {s["method"] for s in b_hits}
        # All three msgServer methods read k.Authority
        self.assertIn("UpdateFee", b_methods)
        self.assertIn("UpdateOracle", b_methods)
        self.assertIn("UpdateMarket", b_methods)
        for s in b_hits:
            self.assertEqual(s["severity_hint"], "MEDIUM")
            self.assertIn("cluster_size=3", s["evidence"])

    def test_negative_fixtures_do_not_fire(self):
        payload = _run(FIX_DIR / "negative")
        self.assertEqual(payload["_rc"], 0)
        self.assertEqual(payload["count"], 0)
        self.assertEqual(payload["sentinels"], [])

    def test_schema_field_present(self):
        payload = _run(FIX_DIR / "positive")
        self.assertEqual(
            payload["schema"],
            "auditooor.go_permissionless_admin_key_sentinel.v1",
        )
        self.assertGreater(payload["count"], 0)

    def test_receiver_field_populated(self):
        """Every emitted sentinel must carry a non-empty receiver field."""
        payload = _run(FIX_DIR / "positive")
        a_hits = [s for s in payload["sentinels"] if s["pattern"] == "A"]
        self.assertGreater(len(a_hits), 0, "expected Pattern A hits in positive fixture")
        for s in a_hits:
            self.assertIn("receiver", s, f"sentinel missing receiver field: {s}")
            self.assertNotEqual(s["receiver"], "", f"sentinel has empty receiver: {s}")

    def test_entrypoints_only_excludes_keeper_helper_default_includes(self):
        """--entrypoints-only excludes a *Keeper helper that default mode includes.

        The keeper_helper_no_auth.go fixture has a bare *KeeperHelper receiver
        (matches MSGSERVER_TYPE_RE in default mode, excluded by
        ENTRYPOINT_RECEIVER_RE in --entrypoints-only mode).
        """
        self.assertTrue(KEEPER_HELPER_FIXTURE.is_file(),
                        f"keeper_helper fixture missing: {KEEPER_HELPER_FIXTURE}")

        # Default mode: KeeperHelper matches Keeper-ish regex - Pattern A fires.
        default_payload = _run(KEEPER_HELPER_FIXTURE)
        default_a_hits = [s for s in default_payload["sentinels"] if s["pattern"] == "A"]
        self.assertGreater(
            len(default_a_hits), 0,
            "default mode should fire on KeeperHelper receiver (it matches MSGSERVER_TYPE_RE)"
        )

        # --entrypoints-only mode: KeeperHelper is NOT a genuine MsgServer - no hit.
        ep_payload = _run(KEEPER_HELPER_FIXTURE, entrypoints_only=True)
        ep_a_hits = [s for s in ep_payload["sentinels"] if s["pattern"] == "A"]
        self.assertEqual(
            len(ep_a_hits), 0,
            f"--entrypoints-only should NOT fire on KeeperHelper receiver; got: {ep_a_hits}"
        )

    def test_entrypoints_only_still_fires_on_real_msgserver(self):
        """--entrypoints-only still catches genuine msgServer Pattern A hits."""
        payload = _run(FIX_DIR / "positive", entrypoints_only=True)
        a_hits = [s for s in payload["sentinels"] if s["pattern"] == "A"]
        # permissionless_write_no_auth.go has a genuine msgServer receiver
        a_methods = {s["method"] for s in a_hits}
        self.assertIn(
            "SetParams", a_methods,
            f"--entrypoints-only must still fire on genuine msgServer.SetParams; got methods: {a_methods}"
        )

    def test_default_mode_fixtures_unchanged(self):
        """Existing positive + negative fixtures behave the same in default mode
        (regression guard: --entrypoints-only=False is the default)."""
        pos = _run(FIX_DIR / "positive")
        self.assertGreater(pos["count"], 0, "positive fixtures must still fire in default mode")
        neg = _run(FIX_DIR / "negative")
        self.assertEqual(neg["count"], 0, "negative fixtures must still be silent in default mode")


if __name__ == "__main__":
    unittest.main()
