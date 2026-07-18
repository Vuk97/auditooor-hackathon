# <!-- r36-rebuttal: lane fcc-multicomponent-enum-fix registered in .auditooor/agent_pathspec.json -->
"""Regression test for the GENERIC multi-component / Solidity in-scope coverage
gap in tools/workspace-coverage-heatmap.py.

THE BUG (observed on /Users/wolf/audits/near-intents):
  A prose SCOPE.md lists in-scope repos as HTTPS-URL rows in a markdown table.
  The path-token harvester ignores URLs and picks up only the few incidental
  ``foo/bar`` path tokens that appear in prose notes, then treats THOSE as the
  whole scope. The coverage walk is silently confined to a couple of sub-trees,
  dropping ENTIRE in-scope repos (a nested multi-component omni-bridge with
  near/ + evm/ + solana/ siblings; a btc-light-client repo) and EVERY Solidity
  component, producing a false-green coverage denominator.

THE FIX (generic, additive):
  ``targets.tsv`` (the machine scope: one ``<repo_url>\t<pin>\t<local_name>`` row
  per in-scope repo) is consulted as the AUTHORITATIVE in-scope source. Each
  ``local_name`` with a real ``src/<local_name>`` directory becomes a
  ``src/<local_name>/`` glob, so the WHOLE tree of EVERY in-scope repo (all
  nested components, all supported languages incl Solidity) is walked. Unioned
  with the prose/json globs so nothing previously emitted is dropped.

This fixture reproduces the near-intents shape in a tmpdir: a SCOPE.md whose
only path tokens are a couple of sub-tree notes, a targets.tsv that names all
the repos, and a nested multi-component repo carrying both a .sol and a .rs.
"""
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

TOOL = Path(__file__).resolve().parents[1] / "workspace-coverage-heatmap.py"


def _load_mod():
    spec = importlib.util.spec_from_file_location(
        "_inscope_targets_tsv_under_test", TOOL
    )
    mod = importlib.util.module_from_spec(spec)
    sys.modules["_inscope_targets_tsv_under_test"] = mod
    spec.loader.exec_module(mod)
    return mod


_MOD = _load_mod()


def _write(p: Path, txt: str) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(txt, encoding="utf-8")


def _make_ws(tmp: Path) -> Path:
    """A workspace mirroring the near-intents shape:

    src/
      mpc/crates/threshold-signatures/lib.rs   <- the prose-token sub-tree
      omni-bridge/                              <- nested multi-component repo
        near/contracts/bridge.rs                  - rust component
        evm/src/OmniBridge.sol                    - solidity component
        evm/node_modules/dep/Junk.sol             - MUST be excluded (vendored)
        evm/test/OmniBridge.t.sol                 - MUST be excluded (test)
        solana/programs/bridge/src/lib.rs         - rust component
      btc-light-client-contract/src/lib.rs      <- a whole repo with NO prose token

    SCOPE.md lists the repos as URLs (ignored by the harvester) plus one
    incidental ``mpc/crates/threshold-signatures`` prose token; targets.tsv
    names ALL repos by local_name.
    """
    ws = tmp / "ws"
    src = ws / "src"

    # The ONLY path token a naive prose harvest would catch.
    _write(src / "mpc" / "crates" / "threshold-signatures" / "lib.rs", (
        "pub fn sign() {}\n"
    ))

    # Nested multi-component repo: near/ (rust) + evm/ (solidity) + solana/ (rust).
    _write(src / "omni-bridge" / "near" / "contracts" / "bridge.rs", (
        "pub fn deposit() {}\n"
    ))
    _write(src / "omni-bridge" / "evm" / "src" / "OmniBridge.sol", (
        "// SPDX-License-Identifier: MIT\n"
        "pragma solidity ^0.8.0;\n"
        "contract OmniBridge {\n"
        "    function finTransfer(uint256 amount) external {}\n"
        "    function claimNativeFee() external {}\n"
        "}\n"
    ))
    # vendored + test .sol that MUST be excluded by the existing prune rules.
    _write(src / "omni-bridge" / "evm" / "node_modules" / "dep" / "Junk.sol", (
        "pragma solidity ^0.8.0;\ncontract Junk { function x() public {} }\n"
    ))
    _write(src / "omni-bridge" / "evm" / "test" / "OmniBridge.t.sol", (
        "pragma solidity ^0.8.0;\ncontract OmniBridgeTest { function t() public {} }\n"
    ))
    _write(src / "omni-bridge" / "solana" / "programs" / "bridge" / "src" / "lib.rs", (
        "pub fn process() {}\n"
    ))

    # A whole in-scope repo that NO prose token references at all.
    _write(src / "btc-light-client-contract" / "src" / "lib.rs", (
        "pub fn submit_block_header() {}\n"
    ))

    # SCOPE.md: repos as URLs (NOT path tokens) + ONE incidental prose sub-tree
    # token. This is the shape that mis-scopes without the targets.tsv fix.
    _write(ws / "SCOPE.md", (
        "# SCOPE\n\n"
        "## IN-SCOPE TARGETS\n\n"
        "| # | Repo URL | Branch |\n"
        "|---|---|---|\n"
        "| 1 | https://github.com/near/mpc | main |\n"
        "| 2 | https://github.com/Near-One/omni-bridge | main |\n"
        "| 3 | https://github.com/Near-One/btc-light-client-contract | main |\n\n"
        "Note: mpc/crates/threshold-signatures diverges and is hunted "
        "separately.\n"
    ))

    # targets.tsv: the authoritative machine scope (tab-separated;
    # <repo_url>\t<pin>\t<local_name>; with a leading comment line).
    _write(ws / "targets.tsv", (
        "# targets - columns: <repo_url>\t<pin>\t<local_name>\n"
        "https://github.com/near/mpc\tabc123\tmpc\n"
        "https://github.com/Near-One/omni-bridge\tdef456\tomni-bridge\n"
        "https://github.com/Near-One/btc-light-client-contract\tghi789"
        "\tbtc-light-client-contract\n"
    ))
    return ws


class TestInscopeTargetsTsvMultiComponent(unittest.TestCase):
    def _rows(self, ws: Path) -> list[dict]:
        return _MOD.build_inscope_manifest_rows(ws)

    def test_scope_globs_cover_every_targets_tsv_repo(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _make_ws(Path(td))
            scope = _MOD.resolve_scope(ws)
            self.assertEqual(scope["scope_mode"], "scope-file")
            globs = scope.get("scope_globs", [])
            for repo in ("mpc", "omni-bridge", "btc-light-client-contract"):
                self.assertIn(
                    f"src/{repo}/", globs,
                    f"targets.tsv repo {repo} missing from scope_globs: {globs}",
                )

    def test_nested_multicomponent_all_languages_present(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _make_ws(Path(td))
            rows = self._rows(ws)
            files = {r["file"] for r in rows}
            langs = {r["lang"] for r in rows}

            # Solidity component is present (function-granularity).
            self.assertIn("solidity", langs)
            sol_fns = {
                r["function"] for r in rows
                if r["lang"] == "solidity"
                and r["file"].endswith("OmniBridge.sol")
            }
            self.assertIn("finTransfer", sol_fns)
            self.assertIn("claimNativeFee", sol_fns)

            # ALL three nested components of the multi-component repo are walked.
            self.assertTrue(
                any(f.endswith("omni-bridge/near/contracts/bridge.rs")
                    for f in files),
                f"omni-bridge near/ rust component missing: {sorted(files)}",
            )
            self.assertTrue(
                any(f.endswith("omni-bridge/evm/src/OmniBridge.sol")
                    for f in files),
                f"omni-bridge evm/ solidity component missing: {sorted(files)}",
            )
            self.assertTrue(
                any(f.endswith(
                    "omni-bridge/solana/programs/bridge/src/lib.rs")
                    for f in files),
                f"omni-bridge solana/ rust component missing: {sorted(files)}",
            )

    def test_repo_with_no_prose_token_is_still_covered(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _make_ws(Path(td))
            files = {r["file"] for r in self._rows(ws)}
            self.assertTrue(
                any(f.endswith("btc-light-client-contract/src/lib.rs")
                    for f in files),
                "a whole in-scope repo with no prose token was dropped: "
                f"{sorted(files)}",
            )

    def test_vendored_and_test_sol_still_excluded(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _make_ws(Path(td))
            files = {r["file"] for r in self._rows(ws)}
            self.assertFalse(
                any("node_modules" in f for f in files),
                "vendored node_modules .sol leaked into the manifest",
            )
            self.assertFalse(
                any(f.endswith(".t.sol") or "/test/" in f for f in files),
                "test .sol leaked into the manifest",
            )

    def test_additive_never_drops_prose_token_units(self):
        # The prose sub-tree token (mpc/crates/threshold-signatures) must STILL
        # be covered after the fix (additive / never-reduce).
        with tempfile.TemporaryDirectory() as td:
            ws = _make_ws(Path(td))
            files = {r["file"] for r in self._rows(ws)}
            self.assertTrue(
                any(f.endswith(
                    "mpc/crates/threshold-signatures/lib.rs")
                    for f in files),
                "previously-emitted prose-token unit was dropped (not additive)",
            )

    def test_targets_tsv_globs_helper_skips_missing_dirs_and_comments(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _make_ws(Path(td))
            # add a row whose src/<local_name> does NOT exist -> must be skipped.
            tsv = ws / "targets.tsv"
            tsv.write_text(
                tsv.read_text(encoding="utf-8")
                + "https://github.com/x/ghost\tzzz\tghost-repo\n",
                encoding="utf-8",
            )
            globs = _MOD._targets_tsv_inscope_globs(ws)
            self.assertNotIn("src/ghost-repo/", globs)
            self.assertIn("src/mpc/", globs)
            self.assertIn("src/omni-bridge/", globs)

    def test_no_targets_tsv_preserves_prior_behaviour(self):
        # Without targets.tsv, the helper returns [] and resolve_scope falls
        # back to the prose/json/unscoped path (no regression for non-tsv ws).
        with tempfile.TemporaryDirectory() as td:
            ws = _make_ws(Path(td))
            (ws / "targets.tsv").unlink()
            self.assertEqual(_MOD._targets_tsv_inscope_globs(ws), [])
            # resolve_scope still returns a valid dict (prose-token mode here).
            scope = _MOD.resolve_scope(ws)
            self.assertIn("scope_mode", scope)


if __name__ == "__main__":
    unittest.main()
