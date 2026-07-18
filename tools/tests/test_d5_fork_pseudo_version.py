from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "fork-pseudo-version-mislabel.py"
FIX_DIR = REPO_ROOT / "tools" / "detectors" / "fixtures" / "d5_pseudo_version"


def _load():
    spec = importlib.util.spec_from_file_location("fork_pseudo_version_mislabel", TOOL_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load detector")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["fork_pseudo_version_mislabel"] = mod
    spec.loader.exec_module(mod)
    return mod


detector = _load()


def _run(*args: str) -> dict:
    buf = StringIO()
    with redirect_stdout(buf):
        rc = detector.main(list(args))
    payload = json.loads(buf.getvalue())
    payload["_rc"] = rc
    return payload


class TestD5ForkPseudoVersion(unittest.TestCase):
    def test_fork_gomod_offline_emits_pseudo_versions(self):
        payload = _run(str(FIX_DIR / "go.mod.fork"))
        self.assertEqual(payload["_rc"], 0)
        self.assertEqual(payload["schema"], "auditooor.fork_pseudo_version_mislabel.v1")
        self.assertEqual(payload["stage"], "offline")
        # 4 replace entries total: 3 in block (1 non-pseudo) + 1 single-line pseudo.
        self.assertEqual(payload["count_replace_entries"], 4)
        # 3 of them are pseudo-version shape.
        self.assertEqual(payload["count_pseudo_versions"], 3)
        # No flags in offline stage.
        self.assertEqual(payload["count_flagged"], 0)
        for e in payload["entries"]:
            if e["pseudo"]:
                self.assertTrue(e["needs_verification"])
                self.assertIsNotNone(e["sha"])
                self.assertIsNotNone(e["claimed_lineage"])
                self.assertTrue(e["claimed_lineage"].startswith("v"))

    def test_specific_claimed_lineages_extracted(self):
        payload = _run(str(FIX_DIR / "go.mod.fork"))
        by_version = {e["version"]: e for e in payload["entries"]}
        ibc = by_version.get("v8.5.2-0.20260428182857-8733b3edf43a")
        self.assertIsNotNone(ibc)
        self.assertEqual(ibc["claimed_lineage"], "v8.5.2")
        self.assertEqual(ibc["sha"], "8733b3edf43a")
        single = by_version.get("v1.2.3-0.20251231235959-deadbeefcafe")
        self.assertIsNotNone(single)
        self.assertEqual(single["claimed_lineage"], "v1.2.3")
        self.assertEqual(single["sha"], "deadbeefcafe")

    def test_clean_gomod_has_zero_pseudo(self):
        payload = _run(str(FIX_DIR / "go.mod.clean"))
        self.assertEqual(payload["_rc"], 0)
        # 2 replace entries, both fixed semver — zero pseudos.
        self.assertEqual(payload["count_replace_entries"], 2)
        self.assertEqual(payload["count_pseudo_versions"], 0)
        self.assertEqual(payload["count_flagged"], 0)

    def test_missing_gomod_returns_2(self):
        buf = StringIO()
        with redirect_stdout(buf):
            rc = detector.main([str(FIX_DIR / "no_such_file_xyzzy.mod")])
        self.assertEqual(rc, 2)

    def test_verify_without_clone_returns_2(self):
        buf = StringIO()
        with redirect_stdout(buf):
            rc = detector.main([str(FIX_DIR / "go.mod.fork"), "--verify"])
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
