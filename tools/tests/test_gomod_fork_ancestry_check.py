"""Tests for gomod-fork-ancestry-check.py (PR #658 commit 5)."""
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

REPO = pathlib.Path(__file__).resolve().parents[2]
TOOL = REPO / "tools" / "gomod-fork-ancestry-check.py"
sys.path.insert(0, str(REPO / "tools"))

import importlib.util
spec = importlib.util.spec_from_file_location("gomod_fork_ancestry_check", TOOL)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


SAMPLE_GOMOD = """\
module github.com/dydxprotocol/v4-chain/protocol

go 1.21

require (
    github.com/cometbft/cometbft v0.38.6
    github.com/cosmos/cosmos-sdk v0.50.6
)

replace (
    github.com/cometbft/cometbft => github.com/dydxprotocol/cometbft v0.38.6-0.20260428184537-904204b11c9e
    github.com/cosmos/cosmos-sdk => github.com/dydxprotocol/cosmos-sdk v0.50.6-0.20260428191449-a212821dc2c3
    github.com/cosmos/iavl => github.com/dydxprotocol/iavl v1.1.1-0.20240509161911-1c8b8e787e85
)

replace github.com/cosmos/ibc-go/v8 => github.com/dydxprotocol/ibc-go/v8 v8.0.0-rc.0.0.20250312180215-8733b3edf43a
"""


class TestParseGomod(unittest.TestCase):
    def test_parses_in_replace_block(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".mod", delete=False) as fh:
            fh.write(SAMPLE_GOMOD)
            path = fh.name
        try:
            replaces = mod.parse_gomod(path)
            tos = [r["to"] for r in replaces]
            self.assertIn("github.com/dydxprotocol/cometbft", tos)
            self.assertIn("github.com/dydxprotocol/cosmos-sdk", tos)
            self.assertIn("github.com/dydxprotocol/iavl", tos)
            self.assertIn("github.com/dydxprotocol/ibc-go/v8", tos)
        finally:
            os.unlink(path)

    def test_filter_org_controlled(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".mod", delete=False) as fh:
            fh.write(SAMPLE_GOMOD)
            path = fh.name
        try:
            replaces = mod.parse_gomod(path)
            forks = [r for r in replaces if mod.is_org_controlled_fork(r, "dydxprotocol")]
            # 4 forks expected (cometbft + cosmos-sdk + iavl + ibc-go)
            self.assertEqual(len(forks), 4)
        finally:
            os.unlink(path)


class TestParsePseudoVersion(unittest.TestCase):
    def test_cometbft_pseudo_version(self):
        v = "v0.38.6-0.20260428184537-904204b11c9e"
        parsed = mod.parse_pseudo_version(v)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["fork_sha"], "904204b11c9e")
        self.assertEqual(parsed["fork_date"], "20260428")
        self.assertEqual(parsed["base_version"], "v0.38.6")

    def test_cosmos_sdk_pseudo_version(self):
        v = "v0.50.6-0.20260428191449-a212821dc2c3"
        parsed = mod.parse_pseudo_version(v)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["fork_sha"], "a212821dc2c3")
        self.assertEqual(parsed["fork_date"], "20260428")

    def test_iavl_pseudo_version(self):
        v = "v1.1.1-0.20240509161911-1c8b8e787e85"
        parsed = mod.parse_pseudo_version(v)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["fork_sha"], "1c8b8e787e85")
        self.assertEqual(parsed["fork_date"], "20240509")

    def test_invalid_version_returns_none(self):
        self.assertIsNone(mod.parse_pseudo_version("v1.2.3"))
        self.assertIsNone(mod.parse_pseudo_version(""))


class TestIsOrgControlled(unittest.TestCase):
    def test_dydx_fork_recognized(self):
        replace = {"to": "github.com/dydxprotocol/cometbft", "version": "v0.38.6"}
        self.assertTrue(mod.is_org_controlled_fork(replace, "dydxprotocol"))

    def test_other_org_not_dydx(self):
        replace = {"to": "github.com/skip-mev/slinky", "version": "v1.0.0"}
        self.assertFalse(mod.is_org_controlled_fork(replace, "dydxprotocol"))


class TestUpstreamUrlFor(unittest.TestCase):
    def test_known_overrides(self):
        url = mod.upstream_url_for("github.com/cometbft/cometbft")
        self.assertEqual(url, "https://github.com/cometbft/cometbft.git")

    def test_ibc_go_v8_handles_module_suffix(self):
        url = mod.upstream_url_for("github.com/cosmos/ibc-go/v8")
        self.assertEqual(url, "https://github.com/cosmos/ibc-go.git")

    def test_unknown_falls_back_to_github(self):
        url = mod.upstream_url_for("github.com/example/repo")
        self.assertEqual(url, "https://github.com/example/repo.git")


class TestSecurityKeywordsRegex(unittest.TestCase):
    def test_security_keywords_match(self):
        for subject in [
            "fix(blocksync): use full commit verification",
            "feat: add additional evidence validation",
            "consensus: hardening for vote extension",
            "fix nil pointer in iavl",
        ]:
            self.assertIsNotNone(mod.SECURITY_KEYWORDS.search(subject), subject)

    def test_non_security_subjects_skipped(self):
        for subject in [
            "chore: bump version",
            "docs: update README",
            "refactor: rename variables",
        ]:
            self.assertIsNone(mod.SECURITY_KEYWORDS.search(subject), subject)


class TestCLI(unittest.TestCase):
    def test_cli_no_forks(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".mod", delete=False) as fh:
            fh.write("module foo\n\ngo 1.21\n")
            path = fh.name
        try:
            proc = subprocess.run(
                ["python3", str(TOOL), path, "--fork-org", "dydxprotocol", "--skip-clone"],
                capture_output=True, text=True,
            )
            self.assertEqual(proc.returncode, 0)
            self.assertIn("no dydxprotocol-controlled forks", proc.stdout)
        finally:
            os.unlink(path)

    def test_cli_json_mode_no_forks(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".mod", delete=False) as fh:
            fh.write("module foo\n\ngo 1.21\n")
            path = fh.name
        try:
            proc = subprocess.run(
                ["python3", str(TOOL), path, "--fork-org", "dydxprotocol", "--skip-clone", "--json"],
                capture_output=True, text=True,
            )
            self.assertEqual(proc.returncode, 0)
            data = json.loads(proc.stdout)
            self.assertEqual(data["schema"], "auditooor.gomod_fork_ancestry.v1")
            self.assertEqual(data["forks"], [])
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
