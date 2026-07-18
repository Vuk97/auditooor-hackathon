"""Loop-fix 2026-06-22 (etherfi step-1): load_targets_tsv crashed the WHOLE `make audit`
when targets.tsv had a header row ("repo<TAB>url<TAB>pinned_commit"). The header row
constructed a Target OK (col2 'pinned_commit' satisfied local_name, so repo_url_to_owner_repo
was not called during construction), then `target.owner_repo` (a property that re-parses
repo_url='repo') raised ValueError OUTSIDE the try/except -> ValueError propagated ->
audit-target-commit-mining.py rc=2 -> step-1 aborted before any audit work. A stray/header/
non-GitHub row must be SKIPPED, never fatal. Fix moved the owner_repo key computation inside
the try. Valid rows must still load.
"""
import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

_TOOLS = Path(__file__).resolve().parent.parent


def _load():
    spec = importlib.util.spec_from_file_location(
        "atcm", str(_TOOLS / "audit-target-commit-mining.py"))
    mod = importlib.util.module_from_spec(spec)
    sys.modules["atcm"] = mod
    spec.loader.exec_module(mod)
    return mod


class TestTargetsTsvHeaderRobustness(unittest.TestCase):
    def setUp(self):
        self.m = _load()

    def _ws(self, body: str):
        ws = Path(tempfile.mkdtemp()).resolve()
        (ws / "targets.tsv").write_text(body)
        return ws

    def test_header_row_skipped_not_fatal(self):
        ws = self._ws(
            "repo\turl\tpinned_commit\n"
            "https://github.com/etherfi-protocol/smart-contracts\ta816695\tsmart-contracts\n"
            "https://github.com/etherfi-protocol/cash-v3\t8c58005\tcash-v3\n"
        )
        targets = self.m.load_targets_tsv(ws)  # must NOT raise
        owner_repos = sorted(t.owner_repo for t in targets)
        self.assertEqual(owner_repos,
                         ["etherfi-protocol/cash-v3", "etherfi-protocol/smart-contracts"])

    def test_garbage_row_skipped(self):
        ws = self._ws(
            "not-a-url\tx\ty\n"
            "https://github.com/etherfi-protocol/cash-v3\t8c58005\tcash-v3\n"
        )
        targets = self.m.load_targets_tsv(ws)
        self.assertEqual([t.owner_repo for t in targets], ["etherfi-protocol/cash-v3"])

    def test_clean_no_header_still_works(self):
        ws = self._ws("https://github.com/etherfi-protocol/smart-contracts\ta816695\n")
        targets = self.m.load_targets_tsv(ws)
        self.assertEqual(len(targets), 1)
        self.assertEqual(targets[0].owner_repo, "etherfi-protocol/smart-contracts")


if __name__ == "__main__":
    unittest.main(verbosity=2)
