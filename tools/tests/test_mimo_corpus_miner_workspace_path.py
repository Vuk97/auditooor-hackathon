"""Guard test - mimo-corpus-miner normalizes a workspace PATH to its basename
when building the harness-dir glob.

Root cause this guards (2026-06-13): the miner built the glob
`mimo_harness_{args.workspace}*/*.json`, but `make mimo-corpus-mine WS=<path>`
and the canonical audit loops pass the FULL workspace path
(e.g. /Users/wolf/audits/monero-oxide). The glob then became
`mimo_harness_/Users/wolf/audits/monero-oxide*` which matches nothing, so the
per-workspace mine silently scanned 0 sidecars on every loop.

Contract:
  - `--workspace <full/path/to/ws>` scans the same sidecars as `--workspace <ws>`;
  - a trailing slash is tolerated;
  - a non-matching workspace still scans 0 (no over-broad match).
"""
from __future__ import annotations

import contextlib
import importlib.util
import io
import re
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock


REPO = Path(__file__).resolve().parents[2]
MINER = REPO / "tools" / "mimo-corpus-miner.py"


def _load() -> types.ModuleType:
    tools_dir = str(REPO / "tools")
    if tools_dir not in sys.path:
        sys.path.insert(0, tools_dir)
    spec = importlib.util.spec_from_file_location("mimo_corpus_miner", MINER)
    assert spec is not None and spec.loader is not None
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def _scanned(stderr: str) -> int:
    mm = re.search(r"scanning (\d+) sidecars", stderr)
    return int(mm.group(1)) if mm else -1


class MimoMinerWorkspacePathTest(unittest.TestCase):
    def setUp(self) -> None:
        self.m = _load()
        self.tmp = Path(tempfile.mkdtemp())
        # canonical workflow-drill harness dir for workspace "testws"
        hdir = self.tmp / "mimo_harness_testws_workflow"
        hdir.mkdir(parents=True)
        (hdir / "sc.json").write_text("{}")  # content irrelevant to the glob count
        self._patch = mock.patch.object(self.m, "DERIVED", self.tmp)
        self._patch.start()

    def tearDown(self) -> None:
        self._patch.stop()

    def _run(self, workspace: str) -> int:
        # The "scanning N sidecars" line is emitted right after globbing, before
        # main() writes any derived corpora. With DERIVED redirected to a temp
        # dir outside the repo, the later relative_to(AUDITOOOR_ROOT) output step
        # raises - which is irrelevant to the glob-count contract under test.
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            try:
                self.m.main(["--workspace", workspace])
            except Exception:
                pass
        return _scanned(buf.getvalue())

    def test_full_path_matches_basename(self) -> None:
        by_path = self._run("/Users/wolf/audits/testws")
        by_name = self._run("testws")
        self.assertEqual(by_name, 1, "basename should match the one fixture sidecar")
        self.assertEqual(by_path, by_name, "full path must normalize to basename")

    def test_trailing_slash_tolerated(self) -> None:
        self.assertEqual(self._run("/Users/wolf/audits/testws/"), 1)

    def test_non_matching_workspace_scans_zero(self) -> None:
        self.assertEqual(self._run("/Users/wolf/audits/otherws"), 0)


class SafeWsFilenameTest(unittest.TestCase):
    """Guards the brain_prime_priors OUTPUT-FILENAME basename fix (2026-06-13).

    The per-workspace brain_prime_priors emitter wrote
    `brain_prime_priors_{ws}.json`, but `ws` is read from a sidecar's
    `workspace` field which is a FULL PATH (e.g. /Users/wolf/audits/mezo) on
    every canonical loop. The raw path produced an embedded-slash filename ->
    the write resolved into a nested non-existent dir -> FileNotFoundError,
    silently aborting the learning step. `_safe_ws_filename` must basename it."""

    def setUp(self) -> None:
        self.m = _load()

    def test_full_path_basenamed(self) -> None:
        self.assertEqual(self.m._safe_ws_filename("/Users/wolf/audits/mezo"), "mezo")

    def test_trailing_slash_basenamed(self) -> None:
        self.assertEqual(self.m._safe_ws_filename("/Users/wolf/audits/beanstalk/"), "beanstalk")

    def test_bare_name_unchanged(self) -> None:
        self.assertEqual(self.m._safe_ws_filename("mezo"), "mezo")

    def test_empty_falls_back_to_unknown(self) -> None:
        self.assertEqual(self.m._safe_ws_filename(""), "unknown")
        self.assertEqual(self.m._safe_ws_filename("/"), "unknown")

    def test_result_never_contains_slash(self) -> None:
        for ws in ("/Users/wolf/audits/mezo", "a/b/c", "mezo", "/", ""):
            self.assertNotIn("/", self.m._safe_ws_filename(ws))


if __name__ == "__main__":
    unittest.main()
