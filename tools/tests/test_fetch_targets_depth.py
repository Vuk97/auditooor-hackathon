"""Tests for the fetch-targets.sh deep-clone fix (commit-mining no-op).

tools/fetch-targets.sh used to `git fetch --depth 1` the pinned commit.
Tier-6 commit-mining (R47 dedup + fork-base discovery) then silently
pivoted to snapshot-only because the fetched commit_count (1) is below the
30-commit FLATTENED_SNAPSHOT_THRESHOLD -> mining became a no-op that still
scored ok.

The fix fetches with `--depth "${AUDITOOOR_CLONE_DEPTH:-300}"` (300 > 30)
so there is real history to walk, while staying overridable for
ultra-large repos / bandwidth-constrained hosts.

These tests are hermetic (no real network / real git clone):

- The fetch command in the script uses the env-defaulted depth, not a
  hardcoded `--depth 1`.
- The default depth is >= 300 (above the FLATTENED_SNAPSHOT_THRESHOLD).
- The depth is overridable via AUDITOOOR_CLONE_DEPTH. This is proven at
  runtime by stubbing `git` so the actual `git fetch ... --depth N ...`
  argv is captured without touching the network.
"""
from __future__ import annotations

import os
import re
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "tools" / "fetch-targets.sh"

# The threshold below which commit-mining degrades to flattened-snapshot mode.
FLATTENED_SNAPSHOT_THRESHOLD = 30


class TestFetchTargetsDepthStatic(unittest.TestCase):
    """Source-level assertions on the fetch depth (R76: grep the real code)."""

    def setUp(self) -> None:
        self.assertTrue(SCRIPT.exists(), f"missing {SCRIPT}")
        self.src = SCRIPT.read_text()

    def test_no_hardcoded_depth_1_fetch(self) -> None:
        # The pin-fetch must not use the no-op `--depth 1`.
        self.assertNotRegex(
            self.src,
            r"git fetch --depth 1\b",
            "pin-fetch still uses --depth 1 -> commit-mining no-op",
        )

    def test_fetch_uses_env_defaulted_depth(self) -> None:
        self.assertRegex(
            self.src,
            r'git fetch --depth "\$\{AUDITOOOR_CLONE_DEPTH:-(\d+)\}"',
            "pin-fetch does not use the AUDITOOOR_CLONE_DEPTH-defaulted depth",
        )

    def test_default_depth_above_threshold(self) -> None:
        m = re.search(
            r'git fetch --depth "\$\{AUDITOOOR_CLONE_DEPTH:-(\d+)\}"', self.src
        )
        self.assertIsNotNone(m, "could not find env-defaulted depth in fetch cmd")
        default_depth = int(m.group(1))
        self.assertGreaterEqual(
            default_depth,
            FLATTENED_SNAPSHOT_THRESHOLD,
            f"default depth {default_depth} not > FLATTENED_SNAPSHOT_THRESHOLD "
            f"({FLATTENED_SNAPSHOT_THRESHOLD}); commit-mining would degrade",
        )
        # Spec target is 300.
        self.assertEqual(default_depth, 300)


class TestFetchTargetsDepthRuntime(unittest.TestCase):
    """Hermetic runtime: stub git + forge so the fetch argv is captured
    without any real clone / network access."""

    def _run(self, depth_env: str | None):
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            ws = tdp / "ws"
            ws.mkdir()
            bindir = tdp / "bin"
            bindir.mkdir()
            argv_log = tdp / "git_argv.log"

            # Stub `git`: log every invocation's argv; for `clone <url> <dest>`
            # create a fake .git dir so the script proceeds to the fetch step.
            git_stub = bindir / "git"
            git_stub.write_text(
                "#!/usr/bin/env bash\n"
                f'echo "$@" >> "{argv_log}"\n'
                'if [ "$1" = "clone" ]; then\n'
                '  dest="${@: -1}"\n'
                '  mkdir -p "$dest/.git"\n'
                "fi\n"
                "exit 0\n"
            )
            git_stub.chmod(git_stub.stat().st_mode | stat.S_IEXEC)

            # targets.tsv with a non-main pinned commit so the fetch path runs.
            (ws / "targets.tsv").write_text(
                "https://github.com/example/repo.git\tdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef\trepo\n"
            )

            env = dict(os.environ)
            # Prepend our stub dir so the stub git wins; keep real bash tools.
            env["PATH"] = f"{bindir}:{env.get('PATH', '')}"
            # Point HOME away so the forge-bin probe finds nothing real.
            env["HOME"] = str(tdp / "home")
            (tdp / "home").mkdir()
            if depth_env is not None:
                env["AUDITOOOR_CLONE_DEPTH"] = depth_env
            else:
                env.pop("AUDITOOOR_CLONE_DEPTH", None)

            subprocess.run(
                ["bash", str(SCRIPT), str(ws)],
                env=env,
                capture_output=True,
                text=True,
                timeout=60,
            )
            return argv_log.read_text() if argv_log.exists() else ""

    def _fetch_depth(self, argv_log: str) -> int:
        for line in argv_log.splitlines():
            m = re.match(r"fetch --depth (\d+) origin ", line)
            if m:
                return int(m.group(1))
        self.fail(f"no `git fetch --depth N origin` call captured:\n{argv_log}")

    def test_default_depth_runtime(self) -> None:
        log = self._run(depth_env=None)
        self.assertEqual(self._fetch_depth(log), 300)

    def test_override_depth_runtime(self) -> None:
        log = self._run(depth_env="777")
        self.assertEqual(self._fetch_depth(log), 777)


if __name__ == "__main__":
    unittest.main()
