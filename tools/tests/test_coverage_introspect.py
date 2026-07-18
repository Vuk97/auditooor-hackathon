#!/usr/bin/env python3
"""V5 Gap-46 / Codex P0 #3 — tests for tools/coverage-introspect.py.

Hermetic, stdlib only. Each test scaffolds its own temp workspace + (when
relevant) a temp pattern library, so they never touch the real
`reference/patterns.dsl/` corpus or `~/audits/...`. LLM dispatch is mocked
through the dependency-injected ``dispatcher`` callable that
``phase3_llm_surface`` accepts — no network, no subprocess.

Covered (from spec, plus a few defensive cases):

  1. Surface enumeration: synthetic .sol with known imports → expected
     categories present.
  2. Library cross-check (empty library + workspace with categories):
     all UNCOVERED.
  3. Library cross-check (rich library matching all): all WELL_COVERED.
  4. LLM-dispatch mock: returns canned JSON, parser correctly classifies
     survivors via phase-4 ranking.
  5. M14-trap: Kimi-novel claim that Minimax flagged covered → REJECTED.
  6. Manifest output is well-formed JSON.

Plus:
  7. CLI: --no-llm path runs phase 1+2, writes both JSONs, manifest is
     well-formed.
  8. audit-deep.sh `--profile coverage-gaps` is wired and accepts that
     value (DRY_RUN path).

Stdlib only.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "coverage-introspect.py"
AUDIT_DEEP = ROOT / "tools" / "audit-deep.sh"

# Add the tools/ directory to sys.path so we can import the module by name
# despite its dash-bearing filename. (Mirrors what test_math_invariant_miner
# would do if it imported the miner — we chose subprocess for the CLI test
# but use direct import for the unit-level pieces.)
sys.path.insert(0, str(ROOT / "tools"))

import importlib.util


def _import_tool():
    spec = importlib.util.spec_from_file_location("coverage_introspect", str(TOOL))
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


CI = _import_tool()


# Synthetic .sol fixtures — chosen to fire 1+ category each.
# Keep these small; their job is to exercise the regex engine, not to be
# realistic contracts.

ERC20_SOL = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract Vault {
    IERC20 public asset;
    function deposit(address from, uint256 amount) external {
        asset.transferFrom(from, address(this), amount);
    }
}
"""

PYTH_SOL = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import {IPyth} from "@pythnetwork/pyth-sdk-solidity/IPyth.sol";

contract OracleConsumer {
    IPyth public pyth;
    function priceNow(bytes32 id) external view returns (int64) {
        // Stale-price classic
        return pyth.getPriceUnsafe(id).price;
    }
}
"""

LZ_SOL = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import { OFTV2 } from "@layerzero/contracts/OFTV2.sol";

contract MyOFT is OFTV2 {
    function _lzReceive(uint16, bytes memory, uint64, bytes memory) internal {}
}
"""

ASM_SOL = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Trampoline {
    function tload_demo() external view returns (uint256 v) {
        assembly {
            v := tload(0)
        }
    }
    function dc(address t, bytes memory cd) external returns (bytes memory) {
        (bool ok, bytes memory r) = t.delegatecall(cd);
        require(ok);
        return r;
    }
}
"""

# Test files that should be SKIPPED (under lib/, test/, mock/).
TEST_FILE_SOL = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
contract Foo { IERC20 public x; }
"""


def _scaffold_ws(tmp: Path, files: dict[str, str]) -> Path:
    """Write {relpath: contents} under tmp/<rel>; return tmp."""
    for rel, body in files.items():
        p = tmp / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, encoding="utf-8")
    return tmp


def _scaffold_patterns(dir_: Path, patterns: list[dict[str, str]]) -> Path:
    dir_.mkdir(parents=True, exist_ok=True)
    for i, p in enumerate(patterns):
        name = p.get("name", f"synthetic-pattern-{i}")
        body = (
            f"pattern: {name}\n"
            f"severity: MEDIUM\n"
            f"confidence: MEDIUM\n"
            f"help: \"{p.get('help', '')}\"\n"
            f"wiki_description: \"{p.get('wiki_description', '')}\"\n"
            "match:\n"
            f"  - function.body_contains_regex: '{p.get('regex', 'noop')}'\n"
        )
        (dir_ / f"{name}.yaml").write_text(body, encoding="utf-8")
    return dir_


class Phase1SurfaceTests(unittest.TestCase):
    """Test 1: surface enumeration with known imports → expected categories."""

    def test_finds_erc20_pyth_lz_asm(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _scaffold_ws(ws, {
                "src/Vault.sol": ERC20_SOL,
                "src/OracleConsumer.sol": PYTH_SOL,
                "src/MyOFT.sol": LZ_SOL,
                "src/Trampoline.sol": ASM_SOL,
            })
            surf = CI.phase1_surface(ws)
            cats = set(surf["categories_present"])
            self.assertIn("erc20", cats)
            self.assertIn("oracle-pyth", cats)
            self.assertIn("bridge-layerzero", cats)
            self.assertIn("asm-assembly", cats)
            self.assertIn("asm-tload-tstore", cats)
            self.assertIn("asm-delegatecall", cats)
            # by_file for Vault.sol should include erc20 hits
            self.assertIn("src/Vault.sol", surf["by_file"])
            self.assertIn("erc20", surf["by_file"]["src/Vault.sol"])

    def test_skips_lib_test_mock_dirs(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _scaffold_ws(ws, {
                "src/Real.sol": ERC20_SOL,
                "lib/openzeppelin/IERC20.sol": ERC20_SOL,
                "test/MockToken.sol": TEST_FILE_SOL,
                "src/mocks/Fake.sol": TEST_FILE_SOL,
            })
            surf = CI.phase1_surface(ws)
            self.assertIn("src/Real.sol", surf["by_file"])
            for skipped in (
                "lib/openzeppelin/IERC20.sol",
                "test/MockToken.sol",
                "src/mocks/Fake.sol",
            ):
                self.assertNotIn(skipped, surf["by_file"], f"should skip {skipped}")

    def test_no_solidity_files_yields_empty_surface(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            (ws / "src").mkdir()
            surf = CI.phase1_surface(ws)
            self.assertEqual(surf["scanned_files"], 0)
            self.assertEqual(surf["categories_present"], [])


class Phase2LibraryCrosscheckTests(unittest.TestCase):
    """Tests 2 + 3: empty library → UNCOVERED; rich library → WELL_COVERED."""

    def test_empty_library_yields_uncovered(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            patterns_dir = ws / "patterns_dsl_empty"
            patterns_dir.mkdir()
            _scaffold_ws(ws, {
                "src/Vault.sol": ERC20_SOL,
                "src/OracleConsumer.sol": PYTH_SOL,
                "src/MyOFT.sol": LZ_SOL,
                "src/Trampoline.sol": ASM_SOL,
            })
            surf = CI.phase1_surface(ws)
            cov = CI.phase2_library_crosscheck(surf, patterns_dir=patterns_dir)
            self.assertGreater(len(cov["categories"]), 0)
            for cat, info in cov["categories"].items():
                self.assertEqual(
                    info["status"],
                    "UNCOVERED",
                    f"empty library should leave {cat} UNCOVERED, got {info['status']}",
                )

    def test_rich_library_yields_well_covered(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _scaffold_ws(ws, {
                "src/Vault.sol": ERC20_SOL,
                "src/OracleConsumer.sol": PYTH_SOL,
            })
            patterns_dir = ws / "patterns_dsl_rich"
            # Synthesize >= WELL_COVERED_ABS patterns mentioning each category
            # keyword set, so the ratio gate also clears.
            pats: list[dict[str, str]] = []
            for i in range(CI.WELL_COVERED_ABS + 2):
                pats.append({
                    "name": f"erc20-allowance-bug-{i}",
                    "help": "ERC20 transferFrom with stale allowance, ierc20 approve",
                    "wiki_description": "erc20 transfer transferFrom approve allowance",
                    "regex": "transferFrom",
                })
            for i in range(CI.WELL_COVERED_ABS + 2):
                pats.append({
                    "name": f"oracle-pyth-stale-{i}",
                    "help": "pyth getPriceUnsafe getPriceNoOlderThan ipyth",
                    "wiki_description": "pyth oracle getPriceUnsafe stale check",
                    "regex": "getPriceUnsafe",
                })
            _scaffold_patterns(patterns_dir, pats)

            surf = CI.phase1_surface(ws)
            cov = CI.phase2_library_crosscheck(surf, patterns_dir=patterns_dir)
            self.assertEqual(cov["categories"]["erc20"]["status"], "WELL_COVERED")
            self.assertEqual(cov["categories"]["oracle-pyth"]["status"], "WELL_COVERED")


class Phase3MockDispatchTests(unittest.TestCase):
    """Test 4: dispatcher mock returns canned JSON; survivors classified."""

    def test_mock_dispatcher_yields_survivors(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            patterns_dir = ws / "patterns_empty"
            patterns_dir.mkdir()
            _scaffold_ws(ws, {"src/OracleConsumer.sol": PYTH_SOL})
            surf = CI.phase1_surface(ws)
            cov = CI.phase2_library_crosscheck(surf, patterns_dir=patterns_dir)

            # Mock dispatcher: when provider=='kimi', return a single
            # JSON-line claim; when 'minimax', return a JSON-line verdict
            # that does NOT mark it covered.
            def fake(prompt: str, provider: str, **kw):
                if provider == "kimi":
                    return 0, json.dumps({
                        "bug_class": "pyth getPriceUnsafe consumed without max-age check",
                        "regex_positive": "getPriceUnsafe",
                        "regex_negative": "getPriceNoOlderThan",
                        "fixture_signature": "function f() returns (int64)",
                        "exhibited_in_workspace": True,
                        "severity": "HIGH",
                    }) + "\n", ""
                if provider == "minimax":
                    return 0, json.dumps({
                        "id": 0,
                        "false_positive_in_supplied_excerpts": False,
                        "actually_covered_by_existing_pattern": None,
                        "single_protocol_only": False,
                    }) + "\n", ""
                return 1, "", "unknown provider"

            llm = CI.phase3_llm_surface(
                surf, cov, ws,
                providers=("kimi", "minimax"),
                dispatcher=fake,
            )
            self.assertGreaterEqual(llm["calls"], 2)
            self.assertIn("oracle-pyth", llm["per_category"])
            kimi_claims = llm["per_category"]["oracle-pyth"]["kimi_claims"]
            self.assertEqual(len(kimi_claims), 1)

            m14 = CI.phase4_m14_rank(surf, cov, llm, patterns_dir=patterns_dir)
            self.assertEqual(m14["ranked_count"], 1)
            self.assertEqual(m14["rejected_count"], 0)
            self.assertEqual(m14["ranked"][0]["status"], "SURVIVOR_immediate")


class Phase4M14TrapTests(unittest.TestCase):
    """Test 5: Minimax flagged covered → claim REJECTED."""

    def test_minimax_covered_rejects_claim(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            patterns_dir = ws / "patterns_empty"
            patterns_dir.mkdir()
            _scaffold_ws(ws, {"src/OracleConsumer.sol": PYTH_SOL})
            surf = CI.phase1_surface(ws)
            cov = CI.phase2_library_crosscheck(surf, patterns_dir=patterns_dir)

            def fake(prompt: str, provider: str, **kw):
                if provider == "kimi":
                    return 0, json.dumps({
                        "bug_class": "pyth getPriceUnsafe consumed without max-age check",
                        "regex_positive": "getPriceUnsafe",
                        "regex_negative": "getPriceNoOlderThan",
                        "fixture_signature": "function f()",
                        "exhibited_in_workspace": True,
                        "severity": "HIGH",
                    }) + "\n", ""
                # Minimax says the claim IS covered by an existing pattern.
                return 0, json.dumps({
                    "id": 0,
                    "false_positive_in_supplied_excerpts": False,
                    "actually_covered_by_existing_pattern": "pyth-stale-existing",
                    "single_protocol_only": False,
                }) + "\n", ""

            llm = CI.phase3_llm_surface(
                surf, cov, ws,
                providers=("kimi", "minimax"),
                dispatcher=fake,
            )
            m14 = CI.phase4_m14_rank(surf, cov, llm, patterns_dir=patterns_dir)
            self.assertEqual(m14["ranked_count"], 0)
            self.assertEqual(m14["rejected_count"], 1)
            self.assertEqual(
                m14["rejected"][0]["status"], "REJECTED_minimax_covered_by"
            )

    def test_independent_match_rejects_claim(self):
        # Even if Minimax misses, Phase 4 itself re-greps the corpus and
        # rejects when ≥2 keyword tokens match an existing pattern blob.
        # Build a 100-pattern library where exactly ONE pattern matches pyth
        # — that keeps the category SPARSE (so phase 3 targets it) while
        # giving phase 4 a covering pattern to find on independent re-grep.
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _scaffold_ws(ws, {"src/OracleConsumer.sol": PYTH_SOL})
            patterns_dir = ws / "patterns_with_pyth"
            pats = [
                {
                    "name": "pyth-stale-getpriceunsafe-no-maxage",
                    "help": "pyth getPriceUnsafe consumed without max-age",
                    "wiki_description": "pyth getPriceUnsafe getPriceNoOlderThan stale",
                    "regex": "getPriceUnsafe",
                },
            ]
            for i in range(100):
                pats.append({
                    "name": f"unrelated-pattern-{i}",
                    "help": "unrelated reentrancy storage write after external call",
                    "wiki_description": "no overlap with any monitored category",
                    "regex": "noop",
                })
            _scaffold_patterns(patterns_dir, pats)
            surf = CI.phase1_surface(ws)
            cov = CI.phase2_library_crosscheck(surf, patterns_dir=patterns_dir)
            # Sanity: SPARSE or UNCOVERED both fire phase 3 — we only need
            # to be sure we're NOT classified WELL_COVERED.
            self.assertNotEqual(
                cov["categories"]["oracle-pyth"]["status"], "WELL_COVERED"
            )

            def fake(prompt: str, provider: str, **kw):
                if provider == "kimi":
                    return 0, json.dumps({
                        "bug_class": "pyth getPriceUnsafe consumed without max-age check",
                        "regex_positive": "getPriceUnsafe",
                        "regex_negative": "getPriceNoOlderThan",
                        "fixture_signature": "function f()",
                        "exhibited_in_workspace": True,
                        "severity": "HIGH",
                    }) + "\n", ""
                # Minimax MISSES it.
                return 0, json.dumps({
                    "id": 0,
                    "false_positive_in_supplied_excerpts": False,
                    "actually_covered_by_existing_pattern": None,
                    "single_protocol_only": False,
                }) + "\n", ""

            llm = CI.phase3_llm_surface(
                surf, cov, ws,
                providers=("kimi", "minimax"),
                dispatcher=fake,
            )
            m14 = CI.phase4_m14_rank(surf, cov, llm, patterns_dir=patterns_dir)
            self.assertEqual(m14["ranked_count"], 0)
            self.assertEqual(m14["rejected_count"], 1)
            self.assertEqual(
                m14["rejected"][0]["status"], "REJECTED_independent_match"
            )


class ManifestShapeTests(unittest.TestCase):
    """Test 6: manifest is well-formed JSON with required keys."""

    def test_manifest_keys_and_jsonability(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            patterns_dir = ws / "patterns_empty"
            patterns_dir.mkdir()
            _scaffold_ws(ws, {"src/Vault.sol": ERC20_SOL})
            surf = CI.phase1_surface(ws)
            cov = CI.phase2_library_crosscheck(surf, patterns_dir=patterns_dir)
            llm = CI.phase3_llm_surface(
                surf, cov, ws,
                providers=("kimi", "minimax"),
                dry_run=True,
            )
            m14 = CI.phase4_m14_rank(surf, cov, llm, patterns_dir=patterns_dir)

            import time
            mp = CI.write_manifest(
                workspace=ws,
                started_at=time.time() - 1.0,
                surface_path=ws / "coverage_surface.json",
                coverage_path=ws / "coverage_by_category.json",
                kimi_md_path=ws / "coverage_gaps_kimi.md",
                minimax_md_path=ws / "coverage_gaps_minimax.md",
                ranked_md_path=ws / "coverage_gaps_ranked.md",
                llm=llm,
                m14=m14,
                coverage=cov,
            )
            self.assertTrue(mp.is_file())
            data = json.loads(mp.read_text(encoding="utf-8"))
            for k in (
                "schema", "tier", "workspace", "elapsed_seconds",
                "outputs", "llm_calls_used", "llm_calls_max",
                "llm_providers", "llm_dry_run", "category_counts",
                "categories_targeted_for_llm", "ranked_survivor_count",
                "rejected_count", "guardrails",
            ):
                self.assertIn(k, data, f"missing manifest key: {k}")
            self.assertEqual(data["tier"], "B")
            self.assertTrue(data["llm_dry_run"])
            # category_counts buckets must exist
            self.assertIn("UNCOVERED", data["category_counts"])


class CLINoLLMTests(unittest.TestCase):
    """Test 7: CLI --no-llm path produces all required artifacts."""

    def test_cli_no_llm_runs_to_completion(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _scaffold_ws(ws, {
                "src/Vault.sol": ERC20_SOL,
                "src/OracleConsumer.sol": PYTH_SOL,
            })
            patterns_dir = ws / "patterns_empty"
            patterns_dir.mkdir()
            proc = subprocess.run(
                [
                    sys.executable, str(TOOL),
                    str(ws),
                    "--no-llm",
                    "--patterns-dir", str(patterns_dir),
                ],
                capture_output=True, text=True, timeout=60,
            )
            self.assertEqual(proc.returncode, 0, msg=proc.stderr)
            for rel in (
                "coverage_surface.json",
                "coverage_by_category.json",
                "coverage_gaps_kimi.md",
                "coverage_gaps_minimax.md",
                "coverage_gaps_ranked.md",
                ".audit_logs/coverage_introspect_manifest.json",
            ):
                self.assertTrue((ws / rel).is_file(), f"missing artifact: {rel}")
            manifest = json.loads((ws / ".audit_logs" / "coverage_introspect_manifest.json").read_text())
            self.assertEqual(manifest["llm_calls_used"], 0)
            self.assertTrue(manifest["llm_dry_run"])


class AuditDeepProfileWiringTests(unittest.TestCase):
    """Test 8: audit-deep.sh accepts --profile coverage-gaps (DRY_RUN)."""

    def test_audit_deep_coverage_gaps_dry_run(self):
        if not AUDIT_DEEP.is_file():
            self.skipTest("audit-deep.sh not present")
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            (ws / "src").mkdir()
            env = os.environ.copy()
            env["AUDIT_DEEP_DRY_RUN"] = "1"
            proc = subprocess.run(
                ["bash", str(AUDIT_DEEP), "--profile", "coverage-gaps", str(ws)],
                env=env, capture_output=True, text=True, timeout=60,
            )
            self.assertEqual(proc.returncode, 0, msg=proc.stderr)
            report = ws / ".audit_logs" / "audit_deep_report.md"
            self.assertTrue(report.is_file())
            text = report.read_text(encoding="utf-8")
            self.assertIn("coverage-gaps", text)
            # Dry-run path notes the planned invocation rather than running it.
            self.assertIn("dry-run", text.lower())


if __name__ == "__main__":
    unittest.main()
