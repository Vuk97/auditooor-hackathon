"""test_orient_scope_coverage_check.py - unit tests for
tools/orient-scope-coverage-check.py (Capability Gap 24 fix, 2026-05-25).

Test coverage:
  - REAL Hyperbridge anchor fixture (SCOPE.md + hunt_orient.json on disk):
    must verdict fail-asset-uncovered with assets_uncovered including
    'Solidity Merkle Trees' (the operator-caught scope-coverage gap).
  - Positive control: synthetic orient with candidates covering both
    assets -> pass-full-coverage.
  - Empty-asset case: SCOPE.md lists an asset whose local_path has no
    source files in the synthetic workspace -> pass-empty-only (warn-
    grade) or warn-partial-coverage when a sibling asset is covered.
  - Mocked Morpho fixture (multi-asset with partial coverage) ->
    fail-asset-uncovered (uncovered count > 0 still trumps empty).
  - SCOPE.md missing -> error verdict, exit 2.
  - Orient JSON missing -> error verdict, exit 2.
  - Malformed orient JSON -> error verdict, exit 2.
  - drill_candidates with files=[] -> uncovered for any non-empty asset.
  - drill_candidate {file: "x"} single-file shape parsed.
  - --json output is valid and contains the schema field.
  - --strict mode promotes warn-partial-coverage to exit-1.
  - Path-matching: asset-slug as middle path token matches (e.g.
    'hyperbridge/evm/src/...' matches asset local_path 'src/hyperbridge').
  - parse_scope_assets ignores assets without 'Local path after fetch'.
  - parse_scope_assets bounds parsing to '## In-Scope Assets' section
    (later '## In-Scope Vulnerabilities' headers not consumed).
"""
from __future__ import annotations

import importlib.util
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import textwrap
import unittest


REPO = pathlib.Path(__file__).resolve().parents[2]
TOOL_PATH = REPO / "tools" / "orient-scope-coverage-check.py"

REAL_HYPERBRIDGE_ORIENT = pathlib.Path(
    "/Users/wolf/auditooor-mcp/reports/v3_iter_2026-05-25/"
    "lane_HYPERBRIDGE_FULL_HUNT_ORIENT/hunt_orient.json"
)
REAL_HYPERBRIDGE_WORKSPACE = pathlib.Path("/Users/wolf/audits/hyperbridge")


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "orient_scope_coverage_check", TOOL_PATH
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


CHK = _load_module()


def _scope_md(assets):
    """Build a minimal SCOPE.md with the given asset rows.

    assets: list of dicts {name, repo, local_path}.
    """
    blocks = []
    for a in assets:
        blocks.append(textwrap.dedent(f"""\
            ### {a['name']}

            - Type: {a.get('type', 'Smart Contract')}
            - Repository: {a['repo']}
            - Local path after fetch: `{a['local_path']}`
            - Asset class: code
        """))
    body = "\n".join(blocks)
    return textwrap.dedent("""\
        # Workspace - Scope

        ## In-Scope Assets

        """) + body + textwrap.dedent("""\

            ## In-Scope Vulnerabilities

            - placeholder
            """)


def _orient(candidates):
    """Build minimal hunt_orient.json with the given drill_candidates."""
    return {
        "schema": "auditooor.hunt_orient.v1",
        "workspace": "test",
        "drill_candidates": candidates,
    }


def _make_workspace(tmp, scope_md, asset_dirs_with_files):
    """Materialize a workspace dir: SCOPE.md + src/<asset>/<files...>.

    asset_dirs_with_files: list of (rel_dir, [filenames]).
    """
    (pathlib.Path(tmp) / "SCOPE.md").write_text(scope_md, encoding="utf-8")
    for rel_dir, files in asset_dirs_with_files:
        full = pathlib.Path(tmp) / rel_dir
        full.mkdir(parents=True, exist_ok=True)
        for fn in files:
            (full / fn).write_text("// stub", encoding="utf-8")


def _run_cli(orient_path, workspace, extra=None):
    cmd = [
        sys.executable, str(TOOL_PATH),
        "--orient", str(orient_path),
        "--workspace", str(workspace),
        "--json",
    ]
    if extra:
        cmd.extend(extra)
    proc = subprocess.run(cmd, capture_output=True, text=True)
    return proc


class TestRealHyperbridgeAnchor(unittest.TestCase):
    """The REAL operator-caught scope-coverage gap from 2026-05-25."""

    @unittest.skipUnless(
        REAL_HYPERBRIDGE_ORIENT.exists() and REAL_HYPERBRIDGE_WORKSPACE.exists(),
        "real Hyperbridge fixture not available on this host",
    )
    def test_real_hyperbridge_fixture_fails_for_solidity_merkle_trees(self):
        proc = _run_cli(REAL_HYPERBRIDGE_ORIENT, REAL_HYPERBRIDGE_WORKSPACE)
        self.assertEqual(proc.returncode, 1, msg=proc.stderr)
        report = json.loads(proc.stdout)
        self.assertEqual(report["schema"], "auditooor.orient_scope_coverage_check.v1")
        self.assertEqual(report["top_verdict"], "fail-asset-uncovered")
        self.assertIn("Solidity Merkle Trees", report["assets_uncovered"])
        self.assertIn("Hyperbridge", report["assets_covered"])
        # 8 drill candidates (DRILL-1..DRILL-8), 14 cited files.
        self.assertGreaterEqual(report["drill_candidate_file_count"], 8)


class TestPositiveControl(unittest.TestCase):

    def test_full_coverage_when_every_asset_has_candidate(self):
        with tempfile.TemporaryDirectory() as tmp:
            scope = _scope_md([
                {"name": "Alpha", "repo": "https://x/alpha", "local_path": "src/alpha"},
                {"name": "Beta", "repo": "https://x/beta", "local_path": "src/beta"},
            ])
            _make_workspace(tmp, scope, [
                ("src/alpha", ["A.sol"]),
                ("src/beta", ["B.sol"]),
            ])
            orient = _orient([
                {"id": "D1", "files": ["alpha/contracts/A.sol"]},
                {"id": "D2", "files": ["beta/src/B.sol"]},
            ])
            orient_path = pathlib.Path(tmp) / "orient.json"
            orient_path.write_text(json.dumps(orient), encoding="utf-8")
            proc = _run_cli(orient_path, tmp)
            self.assertEqual(proc.returncode, 0, msg=proc.stderr + proc.stdout)
            report = json.loads(proc.stdout)
            self.assertEqual(report["top_verdict"], "pass-full-coverage")
            self.assertEqual(set(report["assets_covered"]), {"Alpha", "Beta"})
            self.assertEqual(report["assets_uncovered"], [])


class TestEmptyAsset(unittest.TestCase):

    def test_empty_only_when_no_source_files_present(self):
        with tempfile.TemporaryDirectory() as tmp:
            scope = _scope_md([
                {"name": "Empty", "repo": "https://x/empty", "local_path": "src/empty"},
            ])
            # SCOPE.md says src/empty, but we do NOT materialize that dir.
            (pathlib.Path(tmp) / "SCOPE.md").write_text(scope, encoding="utf-8")
            orient = _orient([])
            orient_path = pathlib.Path(tmp) / "orient.json"
            orient_path.write_text(json.dumps(orient), encoding="utf-8")
            proc = _run_cli(orient_path, tmp)
            self.assertEqual(proc.returncode, 0, msg=proc.stderr + proc.stdout)
            report = json.loads(proc.stdout)
            self.assertEqual(report["top_verdict"], "pass-empty-only")
            self.assertEqual(report["assets_empty"], ["Empty"])

    def test_warn_partial_when_one_empty_one_covered(self):
        with tempfile.TemporaryDirectory() as tmp:
            scope = _scope_md([
                {"name": "Real", "repo": "https://x/real", "local_path": "src/real"},
                {"name": "Pending", "repo": "https://x/pending", "local_path": "src/pending"},
            ])
            _make_workspace(tmp, scope, [
                ("src/real", ["R.sol"]),
            ])  # src/pending intentionally missing.
            orient = _orient([
                {"id": "D1", "files": ["real/contracts/R.sol"]},
            ])
            orient_path = pathlib.Path(tmp) / "orient.json"
            orient_path.write_text(json.dumps(orient), encoding="utf-8")
            proc = _run_cli(orient_path, tmp)
            self.assertEqual(proc.returncode, 0, msg=proc.stderr + proc.stdout)
            report = json.loads(proc.stdout)
            self.assertEqual(report["top_verdict"], "warn-partial-coverage")
            self.assertIn("Real", report["assets_covered"])
            self.assertIn("Pending", report["assets_empty"])


class TestMockedMorphoFixture(unittest.TestCase):

    def test_partial_coverage_with_uncovered_asset_fails(self):
        # Synthesize a multi-asset workspace mirroring Morpho-style scope:
        # 6 in-scope assets, drill_candidates covers only 4. The remaining 2
        # have source files but no drill_candidates -> fail-asset-uncovered.
        with tempfile.TemporaryDirectory() as tmp:
            assets = [
                {"name": f"Module{i}", "repo": f"https://x/m{i}", "local_path": f"src/module{i}"}
                for i in range(6)
            ]
            scope = _scope_md(assets)
            _make_workspace(
                tmp, scope,
                [(f"src/module{i}", [f"M{i}.sol"]) for i in range(6)],
            )
            # Candidates for module0..module3 only.
            orient = _orient([
                {"id": f"D{i}", "files": [f"module{i}/contracts/M{i}.sol"]}
                for i in range(4)
            ])
            orient_path = pathlib.Path(tmp) / "orient.json"
            orient_path.write_text(json.dumps(orient), encoding="utf-8")
            proc = _run_cli(orient_path, tmp)
            self.assertEqual(proc.returncode, 1, msg=proc.stderr + proc.stdout)
            report = json.loads(proc.stdout)
            self.assertEqual(report["top_verdict"], "fail-asset-uncovered")
            self.assertEqual(set(report["assets_uncovered"]), {"Module4", "Module5"})
            self.assertEqual(set(report["assets_covered"]),
                             {"Module0", "Module1", "Module2", "Module3"})


class TestErrorModes(unittest.TestCase):

    def test_missing_orient_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            scope = _scope_md([
                {"name": "A", "repo": "https://x/a", "local_path": "src/a"},
            ])
            (pathlib.Path(tmp) / "SCOPE.md").write_text(scope, encoding="utf-8")
            proc = _run_cli(
                pathlib.Path(tmp) / "missing.json", tmp,
            )
            self.assertEqual(proc.returncode, 2)
            report = json.loads(proc.stdout)
            self.assertEqual(report["top_verdict"], "error")
            self.assertEqual(report["error"], "orient_file_missing")

    def test_missing_scope_md(self):
        with tempfile.TemporaryDirectory() as tmp:
            orient_path = pathlib.Path(tmp) / "orient.json"
            orient_path.write_text(json.dumps(_orient([])), encoding="utf-8")
            proc = _run_cli(orient_path, tmp)
            self.assertEqual(proc.returncode, 2)
            report = json.loads(proc.stdout)
            self.assertEqual(report["top_verdict"], "error")
            self.assertEqual(report["error"], "scope_md_missing")

    def test_malformed_orient_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            scope = _scope_md([
                {"name": "A", "repo": "https://x/a", "local_path": "src/a"},
            ])
            (pathlib.Path(tmp) / "SCOPE.md").write_text(scope, encoding="utf-8")
            orient_path = pathlib.Path(tmp) / "orient.json"
            orient_path.write_text("{not json", encoding="utf-8")
            proc = _run_cli(orient_path, tmp)
            self.assertEqual(proc.returncode, 2)
            report = json.loads(proc.stdout)
            self.assertEqual(report["top_verdict"], "error")
            self.assertEqual(report["error"], "orient_json_decode_failed")


class TestCandidateFileShapes(unittest.TestCase):

    def test_empty_drill_candidates_uncovered(self):
        with tempfile.TemporaryDirectory() as tmp:
            scope = _scope_md([
                {"name": "Solo", "repo": "https://x/solo", "local_path": "src/solo"},
            ])
            _make_workspace(tmp, scope, [("src/solo", ["S.sol"])])
            orient = _orient([])
            orient_path = pathlib.Path(tmp) / "orient.json"
            orient_path.write_text(json.dumps(orient), encoding="utf-8")
            proc = _run_cli(orient_path, tmp)
            self.assertEqual(proc.returncode, 1)
            report = json.loads(proc.stdout)
            self.assertEqual(report["top_verdict"], "fail-asset-uncovered")
            self.assertIn("Solo", report["assets_uncovered"])

    def test_single_file_shape_parsed(self):
        # candidate uses {"file": "..."} instead of {"files": [...]}.
        with tempfile.TemporaryDirectory() as tmp:
            scope = _scope_md([
                {"name": "Alpha", "repo": "https://x/alpha", "local_path": "src/alpha"},
            ])
            _make_workspace(tmp, scope, [("src/alpha", ["A.sol"])])
            orient = _orient([{"id": "D1", "file": "alpha/contracts/A.sol"}])
            orient_path = pathlib.Path(tmp) / "orient.json"
            orient_path.write_text(json.dumps(orient), encoding="utf-8")
            proc = _run_cli(orient_path, tmp)
            self.assertEqual(proc.returncode, 0, msg=proc.stderr + proc.stdout)
            report = json.loads(proc.stdout)
            self.assertEqual(report["top_verdict"], "pass-full-coverage")


class TestStrictMode(unittest.TestCase):

    def test_strict_promotes_warn_to_exit1(self):
        with tempfile.TemporaryDirectory() as tmp:
            scope = _scope_md([
                {"name": "Real", "repo": "https://x/real", "local_path": "src/real"},
                {"name": "Pending", "repo": "https://x/pending", "local_path": "src/pending"},
            ])
            _make_workspace(tmp, scope, [("src/real", ["R.sol"])])  # pending empty
            orient = _orient([{"id": "D1", "files": ["real/contracts/R.sol"]}])
            orient_path = pathlib.Path(tmp) / "orient.json"
            orient_path.write_text(json.dumps(orient), encoding="utf-8")
            proc = _run_cli(orient_path, tmp, extra=["--strict"])
            self.assertEqual(proc.returncode, 1, msg=proc.stderr + proc.stdout)
            report = json.loads(proc.stdout)
            self.assertEqual(report["top_verdict"], "warn-partial-coverage")


class TestPathMatching(unittest.TestCase):

    def test_asset_slug_middle_token_matches(self):
        # candidate cites 'hyperbridge/evm/src/foo.sol'; asset local_path
        # is 'src/hyperbridge' -> asset slug 'hyperbridge' is a token in
        # candidate path -> matches.
        self.assertTrue(CHK._candidate_matches_asset(
            "hyperbridge/evm/src/foo.sol", "src/hyperbridge"
        ))

    def test_unrelated_path_does_not_match(self):
        self.assertFalse(CHK._candidate_matches_asset(
            "hyperbridge/evm/src/foo.sol", "src/solidity-merkle-trees"
        ))

    def test_asset_slug_top_token_matches(self):
        self.assertTrue(CHK._candidate_matches_asset(
            "src/solidity-merkle-trees/EthereumTrie.sol", "src/solidity-merkle-trees"
        ))

    def test_empty_inputs_do_not_match(self):
        self.assertFalse(CHK._candidate_matches_asset("", "src/foo"))
        self.assertFalse(CHK._candidate_matches_asset("foo.sol", ""))


class TestScopeMdParser(unittest.TestCase):

    def test_skips_asset_without_local_path(self):
        scope = textwrap.dedent("""\
            # Workspace

            ## In-Scope Assets

            ### NoPath

            - Repository: https://x/nopath
            - Asset class: code

            ### HasPath

            - Repository: https://x/haspath
            - Local path after fetch: `src/haspath`
            - Asset class: code

            ## In-Scope Vulnerabilities

            - x
            """)
        assets = CHK.parse_scope_assets(scope)
        self.assertEqual(len(assets), 1)
        self.assertEqual(assets[0]["name"], "HasPath")

    def test_bounds_parsing_to_in_scope_assets_section(self):
        # An asset header AFTER the In-Scope Assets section ends must be ignored.
        scope = textwrap.dedent("""\
            # Workspace

            ## In-Scope Assets

            ### Real

            - Repository: https://x/real
            - Local path after fetch: `src/real`

            ## Out-Of-Scope Vulnerabilities

            ### Theoretical Class

            - Local path after fetch: `src/never`
            """)
        assets = CHK.parse_scope_assets(scope)
        self.assertEqual([a["name"] for a in assets], ["Real"])

    def test_missing_in_scope_assets_section_returns_empty(self):
        scope = "# Doc\n\nNo assets section here.\n"
        assets = CHK.parse_scope_assets(scope)
        self.assertEqual(assets, [])


class TestJsonOutputShape(unittest.TestCase):

    def test_json_output_has_schema_and_required_keys(self):
        with tempfile.TemporaryDirectory() as tmp:
            scope = _scope_md([
                {"name": "Alpha", "repo": "https://x/a", "local_path": "src/alpha"},
            ])
            _make_workspace(tmp, scope, [("src/alpha", ["A.sol"])])
            orient = _orient([{"id": "D1", "files": ["alpha/A.sol"]}])
            orient_path = pathlib.Path(tmp) / "orient.json"
            orient_path.write_text(json.dumps(orient), encoding="utf-8")
            proc = _run_cli(orient_path, tmp)
            report = json.loads(proc.stdout)
            for key in (
                "schema", "inputs", "drill_candidate_file_count",
                "drill_candidate_file_samples", "assets_in_scope",
                "assets_covered", "assets_uncovered", "assets_empty",
                "asset_rows", "top_verdict",
            ):
                self.assertIn(key, report, msg=f"missing key {key}")
            self.assertEqual(report["schema"], "auditooor.orient_scope_coverage_check.v1")


if __name__ == "__main__":
    unittest.main()
