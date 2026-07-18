from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "attack-class-ranker.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location("attack_class_ranker", TOOL)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load attack-class-ranker.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class AttackClassRankerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self.tmp.name)
        (self.repo / "reference" / "patterns.dsl").mkdir(parents=True)
        (self.repo / "defihacklabs").mkdir()
        (self.repo / "reference" / "patterns.dsl" / "zero-amountoutmin-in-router.yaml").write_text(
            textwrap.dedent(
                """
                pattern: zero-amountoutmin-in-router
                source: local-test
                severity: HIGH
                confidence: HIGH
                match:
                  - function.name_matches: '(?i)swap|route'
                  - function.body_contains_regex: '(?i)amountOutMin\\s*[:=]\\s*0'
                  - function.body_not_contains_regex: '(?i)deadline'
                help: "Router swap accepts zero amountOutMin and no deadline, exposing users to slippage and sandwich MEV."
                wiki_title: "Swap route has no slippage floor"
                """
            ).strip()
            + "\n",
            encoding="utf-8",
        )
        (self.repo / "reference" / "patterns.dsl" / "manager-write-no-auth.yaml").write_text(
            textwrap.dedent(
                """
                pattern: manager-write-no-auth
                source: local-test
                severity: MEDIUM
                confidence: MEDIUM
                match:
                  - function.name_matches: '(?i)addManager|removeManager'
                  - function.body_not_contains_regex: '(?i)onlyOwner|hasRole|admin'
                help: "Manager mapping mutation has no visible caller authorization guard."
                """
            ).strip()
            + "\n",
            encoding="utf-8",
        )
        (self.repo / "defihacklabs" / "catalog.yaml").write_text(
            textwrap.dedent(
                """
                ---
                rows:
                  - id: dhl-001
                    attack_class: spot-lp-oracle-manipulation
                    dollar_lost: "~$60M"
                    example_poc: "src/test/Woofi_exp.sol"
                    mechanism: >
                      Protocol reads instantaneous AMM spot price from slot0 or getReserves
                      as a collateral oracle without TWAP.
                    grep_predicates:
                      - 'getReserves\\(\\)'
                      - 'slot0\\(\\)'
                      - 'latestRoundData'
                    detector_status: gap
                    wave_candidate: W8-4
                  - id: dhl-002
                    attack_class: flashloan-callback-initiator-unchecked
                    mechanism: >
                      Flashloan callback does not verify msg.sender is the pool.
                    grep_predicates:
                      - 'onFlashLoan|executeOperation'
                      - 'msg\\.sender'
                    detector_status: covered
                """
            ).strip()
            + "\n",
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_ranks_pattern_attack_class_from_detector_context(self) -> None:
        tool = _load_tool()

        payload = tool.run(
            [
                "--repo-root",
                str(self.repo),
                "--detector-slug",
                "zero-amountoutmin-in-router",
                "--file-path",
                "src/Router.sol",
                "--function-name",
                "swapExactTokensForTokens",
                "--language",
                "solidity",
                "--context",
                "router swap sets amountOutMin to 0 and omits deadline slippage protection",
            ]
        )

        self.assertTrue(payload["advisory_only"])
        self.assertRegex(payload["context_pack_hash"], r"^[0-9a-f]{64}$")
        self.assertTrue(payload["context_pack_id"].startswith("auditooor.attack_class_ranker.v1:"))
        top = payload["ranked_attack_classes"][0]
        self.assertEqual(top["attack_class"], "slippage-mev")
        self.assertIn("zero-amountoutmin-in-router", top["pattern_ids"])
        self.assertTrue(top["advisory_only"])
        self.assertEqual(top["claim_scope"], "hypothesis_prioritization_only")
        self.assertEqual(top["evidence_refs"][0]["source_kind"], "patterns.dsl")

    def test_defihack_catalog_rows_are_ranked_when_present(self) -> None:
        tool = _load_tool()

        payload = tool.run(
            [
                "--repo-root",
                str(self.repo),
                "--function-name",
                "getCollateralPrice",
                "--context",
                "collateral oracle reads slot0 getReserves latestRoundData spot price with no twap before borrow",
                "--top-n",
                "3",
            ]
        )

        attack_classes = [row["attack_class"] for row in payload["ranked_attack_classes"]]
        self.assertIn("spot-lp-oracle-manipulation", attack_classes)
        oracle = next(row for row in payload["ranked_attack_classes"] if row["attack_class"] == "spot-lp-oracle-manipulation")
        self.assertTrue(any(ref["source_kind"] == "defihacklabs" for ref in oracle["evidence_refs"]))
        self.assertTrue(any(ref["source_kind"] == "defihacklabs" for ref in oracle["analogue_refs"]))

    def test_external_corpus_rows_become_analogue_refs(self) -> None:
        tool = _load_tool()
        external_dir = self.repo / "reference" / "patterns.dsl.r94_solodit_rust"
        external_dir.mkdir(parents=True)
        (external_dir / "spl-token-mint-mismatch.yaml").write_text(
            textwrap.dedent(
                """
                id: spl-token-mint-mismatch
                title: "SPL token deposit accepts wrong mint"
                severity: High
                language: rust
                platform: solana
                bug_class: bridge-message-validation
                real_world_example: |
                  Bridge deposit instruction accepts a token account whose mint does not match the configured whitelist mint.
                suggested_remediation: "Require token_account.mint == configured_mint before minting wrapped assets."
                """
            ).strip()
            + "\n",
            encoding="utf-8",
        )

        payload = tool.run(
            [
                "--repo-root",
                str(self.repo),
                "--context",
                "solana bridge deposit accepts wrong spl token mint configured whitelist token account",
                "--top-n",
                "3",
                "--external-corpus-limit",
                "20",
            ]
        )

        self.assertGreater(payload["sources"]["source_counts"].get("external_corpus:rust", 0), 0)
        bridge = next(row for row in payload["ranked_attack_classes"] if row["attack_class"] == "bridge-message-validation")
        self.assertTrue(bridge["analogue_refs"])
        self.assertTrue(any(ref["source_kind"] == "external_corpus:rust" for ref in bridge["analogue_refs"]))
        self.assertTrue(any("spl-token-mint-mismatch" in ref["source_ref"] for ref in bridge["analogue_refs"]))

    def test_case_study_frontmatter_rows_become_analogue_refs(self) -> None:
        tool = _load_tool()
        case_dir = self.repo / "case_study"
        case_dir.mkdir(parents=True)
        (case_dir / "engagement_3_gap_b_composition_fuzz.md").write_text(
            textwrap.dedent(
                """
                ---
                case_id: engagement-3-composition-fuzz-2026
                mechanism: blacklistDisputeGame non-cascade through isGameClaimValid for resolved descendants
                class: bridge
                severity_class: CRIT
                applicable_workspace_classes:
                  - bridge
                  - consensus
                grep_predicates:
                  - "blacklistDisputeGame|isGameClaimValid"
                  - "finalizeWithdrawalTransaction|proveWithdrawalTransaction"
                runtime_predicates:
                  - "halmos counter-example plus forge fuzz reachability"
                extracted_lesson: >
                  Cross-contract invariants between AnchorStateRegistry and OptimismPortal2 require
                  composition fuzzing; Critical requires both SMT witness and permissionless reachability.
                ---
                # Case Study

                Anchor poisoning bridge finalization case study.
                """
            ).strip()
            + "\n",
            encoding="utf-8",
        )

        payload = tool.run(
            [
                "--repo-root",
                str(self.repo),
                "--context",
                "bridge AnchorStateRegistry blacklistDisputeGame isGameClaimValid finalizeWithdrawalTransaction composition fuzz",
                "--top-n",
                "3",
                "--external-corpus-limit",
                "20",
            ]
        )

        self.assertGreater(payload["sources"]["source_counts"].get("external_corpus:case-study", 0), 0)
        bridge = next(row for row in payload["ranked_attack_classes"] if row["attack_class"] == "bridge-message-validation")
        self.assertTrue(any(ref["source_kind"] == "external_corpus:case-study" for ref in bridge["analogue_refs"]))
        self.assertTrue(
            any("engagement_3_gap_b_composition_fuzz" in ref["source_ref"] for ref in bridge["analogue_refs"])
        )
        case_ref = next(ref for ref in bridge["analogue_refs"] if ref["source_kind"] == "external_corpus:case-study")
        self.assertIn("blacklistDisputeGame|isGameClaimValid", case_ref["grep_predicates"])
        self.assertIn("halmos counter-example plus forge fuzz reachability", case_ref["runtime_predicates"])
        self.assertIn("blacklistDisputeGame non-cascade", case_ref["mechanism"])

    def test_top_n_bounds_output_and_keeps_limitations(self) -> None:
        tool = _load_tool()

        payload = tool.run(
            [
                "--repo-root",
                str(self.repo),
                "--context",
                "swap amountOutMin zero manager addManager no auth slot0 oracle getReserves",
                "--top-n",
                "1",
            ]
        )

        self.assertEqual(len(payload["ranked_attack_classes"]), 1)
        self.assertIn("Advisory ranking only", payload["limitations"][0])
        serialized = json.dumps(payload).lower()
        self.assertNotIn("confirmed exploit", serialized)
        self.assertNotIn("submit-ready", serialized)

    def test_cli_emits_json(self) -> None:
        out = subprocess.run(
            [
                sys.executable,
                str(TOOL),
                "--repo-root",
                str(self.repo),
                "--context",
                "executeOperation callback msg.sender pool flashloan",
                "--top-n",
                "2",
            ],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            check=True,
        )

        payload = json.loads(out.stdout)
        self.assertEqual(payload["schema"], "auditooor.attack_class_ranker.v1")
        self.assertGreaterEqual(payload["summary"]["ranked_count"], 1)
        self.assertRegex(payload["context_pack_hash"], r"^[0-9a-f]{64}$")

    def test_make_attack_class_rank_dry_run_wires_local_cli_inputs(self) -> None:
        proc = subprocess.run(
            [
                "make",
                "-n",
                "attack-class-rank",
                "DETECTOR=zero-amountoutmin-in-router",
                "FILE=src/Router.sol",
                "FUNC=swapExactTokensForTokens",
                "LANGUAGE=solidity",
                "CONTEXT=router amountOutMin zero",
                "TOP_N=3",
                "PRETTY=1",
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=True,
        )

        self.assertIn("tools/attack-class-ranker.py", proc.stdout)
        self.assertIn('--detector-slug "zero-amountoutmin-in-router"', proc.stdout)
        self.assertIn('--file-path "src/Router.sol"', proc.stdout)
        self.assertIn('--function-name "swapExactTokensForTokens"', proc.stdout)
        self.assertIn('--language "solidity"', proc.stdout)
        self.assertIn('--context "router amountOutMin zero"', proc.stdout)
        self.assertIn('--top-n "3"', proc.stdout)
        self.assertIn("--pretty", proc.stdout)

    def test_make_attack_class_rank_writes_out_file_from_local_corpus(self) -> None:
        out_path = self.repo / "ranker-output.json"
        proc = subprocess.run(
            [
                "make",
                "attack-class-rank",
                f"PATTERNS_DIR={self.repo / 'reference' / 'patterns.dsl'}",
                f"DEFIHACK_CATALOG={self.repo / 'defihacklabs' / 'catalog.yaml'}",
                "DETECTOR=zero-amountoutmin-in-router",
                "FILE=src/Router.sol",
                "FUNC=swapExactTokensForTokens",
                "LANGUAGE=solidity",
                "CONTEXT=router swap amountOutMin zero deadline slippage",
                "TOP_N=2",
                f"OUT={out_path}",
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=True,
        )

        self.assertIn(f"[make attack-class-rank] wrote {out_path}", proc.stdout)
        payload = json.loads(out_path.read_text(encoding="utf-8"))
        self.assertEqual(payload["schema"], "auditooor.attack_class_ranker.v1")
        self.assertTrue(payload["advisory_only"])
        self.assertLessEqual(len(payload["ranked_attack_classes"]), 2)
        self.assertEqual(payload["ranked_attack_classes"][0]["attack_class"], "slippage-mev")

    def test_out_of_repo_sources_are_redacted_and_confidence_basis_is_present(self) -> None:
        tool = _load_tool()
        with tempfile.TemporaryDirectory() as ext_tmp:
            ext_root = Path(ext_tmp)
            patterns_dir = ext_root / "patterns"
            patterns_dir.mkdir()
            (patterns_dir / "callback-no-sender-check.yaml").write_text(
                textwrap.dedent(
                    """
                    pattern: callback-no-sender-check
                    severity: HIGH
                    confidence: MEDIUM
                    help: "Callback path skips sender validation and permits arbitrary callback entry."
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )
            catalog_path = ext_root / "catalog.yaml"
            catalog_path.write_text(
                textwrap.dedent(
                    """
                    ---
                    rows:
                      - id: dhl-ext-001
                        attack_class: flashloan-callback-initiator-unchecked
                        mechanism: >
                          Flashloan callback does not verify msg.sender is the pool.
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )

            payload = tool.run(
                [
                    "--repo-root",
                    str(self.repo),
                    "--patterns-dir",
                    str(patterns_dir),
                    "--defihack-catalog",
                    str(catalog_path),
                    "--context",
                    "flashloan callback msg.sender pool validation missing",
                ]
            )
            again = tool.run(
                [
                    "--repo-root",
                    str(self.repo),
                    "--patterns-dir",
                    str(patterns_dir),
                    "--defihack-catalog",
                    str(catalog_path),
                    "--context",
                    "flashloan callback msg.sender pool validation missing",
                ]
            )

        self.assertEqual(payload["sources"]["patterns_dir"], "<external-input>")
        self.assertEqual(payload["sources"]["defihack_catalog"], "<external-input>")
        self.assertEqual(payload["context_pack_hash"], again["context_pack_hash"])
        for row in payload["ranked_attack_classes"]:
            self.assertEqual(row["confidence_basis"], "uncalibrated_corpus_similarity")
            for ref in row["evidence_refs"]:
                self.assertFalse(ref["source_ref"].startswith(str(ext_root)))
                self.assertTrue(ref["source_ref"].startswith("<external-input>"))


    def test_real_corpus_items_surface_in_evidence_refs_before_patterns_dsl(self) -> None:
        """Regression test for cap-before-source-kind-filter bug.

        When a bucket has many high-scoring patterns.dsl items and a few lower-scoring
        real-corpus (solodit) items, the evidence_refs[:5] slice MUST NOT be saturated
        by patterns.dsl items.  Real corpus items must sort before patterns.dsl items
        even when their raw token-overlap score is lower.
        """
        tool = _load_tool()

        # Build 10 patterns.dsl CorpusItems whose text matches ALL 8 query tokens
        # (token overlap score = 8 + 8*0.4 = 11.2).  Then 2 solodit items whose text
        # matches only 1 query token (score = 1 + 1*0.4 = 1.4).  Without the fix the
        # first [:5] slice is entirely patterns.dsl.
        query_text = "reentrancy callback external call balance update order"
        shared_attack_class = "reentrancy"

        patterns_dsl_items = [
            tool.CorpusItem(
                source_kind="patterns.dsl",
                source_ref=f"reference/patterns.dsl/reentrancy-guard-{i}.yaml",
                item_id=f"reentrancy-guard-{i}",
                attack_class=shared_attack_class,
                text="reentrancy callback external call balance update order check effects interactions",
                pattern_id=f"reentrancy-guard-{i}",
                severity="HIGH",
                corpus_confidence="HIGH",
            )
            for i in range(10)
        ]

        solodit_items = [
            tool.CorpusItem(
                source_kind="solodit",
                source_ref=f"solodit/finding-{j}.json",
                item_id=f"solodit-finding-{j}",
                attack_class=shared_attack_class,
                text="reentrancy real world exploit ETH stolen cross-function re-entrance",
                severity="CRITICAL",
                corpus_confidence="HIGH",
            )
            for j in range(2)
        ]

        all_items = patterns_dsl_items + solodit_items

        result = tool.rank_attack_classes(
            query_text=query_text,
            items=all_items,
            top_n=5,
        )

        self.assertTrue(result, "expected at least one ranked attack class")
        reentrancy_row = next(
            (row for row in result if row["attack_class"] == shared_attack_class), None
        )
        self.assertIsNotNone(reentrancy_row, "reentrancy bucket must appear in results")

        evidence_refs = reentrancy_row["evidence_refs"]
        self.assertTrue(evidence_refs, "evidence_refs must not be empty")

        # Core assertion: at least one real corpus (solodit) item must appear in evidence_refs
        solodit_in_evidence = [r for r in evidence_refs if r["source_kind"] == "solodit"]
        self.assertTrue(
            solodit_in_evidence,
            f"no solodit item in evidence_refs[:5]; all are: "
            f"{[r['source_kind'] for r in evidence_refs]}",
        )

        # First slot must NOT be a patterns.dsl item (real corpus item sorts first)
        self.assertNotEqual(
            evidence_refs[0]["source_kind"],
            "patterns.dsl",
            f"evidence_refs[0] is patterns.dsl (auto-gen dominates); "
            f"full list: {[r['source_kind'] for r in evidence_refs]}",
        )


if __name__ == "__main__":
    unittest.main()
