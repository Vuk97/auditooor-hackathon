"""Tests for tools/hackerman-stratify-verification-tier.py.

The stratifier scans a directory of hackerman v1 YAML records and emits a
JSONL of per-record verification_tier candidates. These tests exercise the
classifier directly (so they are fast and deterministic) plus a small
integration test against a synthesised tags directory.
"""
from __future__ import annotations

import importlib.util
import json
import tempfile
import textwrap
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "hackerman-stratify-verification-tier.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location(
        "_hackerman_stratify_verification_tier", str(TOOL_PATH)
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


class ClassifierTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = _load_tool()
        self.classify = self.tool.classify

    def test_tier_5_quarantine_wave_3b_substring(self) -> None:
        tier, reason = self.classify(
            {
                "record_id": "legacy:dsl_pattern_vyper-reentrancy-lock-slot-drift-across-function-variants:abc",
                "source_audit_ref": "dsl_pattern/vyper-reentrancy-lock-slot-drift-across-function-variants",
                "target_repo": "unknown/dsl-synthetic",
                "source_extraction_method": "dsl-synthetic",
            }
        )
        self.assertEqual(tier, "tier-5-quarantine")
        self.assertIn("wave3b", reason)

    def test_tier_5_quarantine_path_marker(self) -> None:
        tier, reason = self.classify(
            {
                "record_id": "synthetic:foo",
                "source_audit_ref": "_QUARANTINE_FABRICATED_CVE/vyper/cve-2023-xxxxx",
            }
        )
        self.assertEqual(tier, "tier-5-quarantine")
        self.assertIn("quarantine-path-marker", reason)

    def test_tier_1_git_mining_sha(self) -> None:
        tier, reason = self.classify(
            {
                "record_id": "git-mining:makerdao-dss:b9736422072c:96b614c72e",
                "source_audit_ref": "git-mining:reports/git_commits_mining_MakerDAO-dss.json@b9736422072c",
            }
        )
        self.assertEqual(tier, "tier-1-verified-realtime-api")
        self.assertEqual(reason, "git-mining-with-sha")

    def test_tier_1_canonical_cve_id(self) -> None:
        tier, _ = self.classify(
            {
                "record_id": "cve_db:CVE-2023-12345",
                "source_audit_ref": "cve_db:CVE-2023-12345:body",
            }
        )
        self.assertEqual(tier, "tier-1-verified-realtime-api")

    def test_tier_1_ghsa(self) -> None:
        tier, _ = self.classify(
            {
                "record_id": "advisory:ghsa-xxxx-yyyy-zzzz",
                "source_audit_ref": "https://api.github.com/repos/owner/repo/security-advisories",
            }
        )
        self.assertEqual(tier, "tier-1-verified-realtime-api")

    def test_tier_2_prior_audit(self) -> None:
        tier, reason = self.classify(
            {
                "record_id": "prior-audit:monetrix:digest:abc",
                "source_audit_ref": "prior-audit:monetrix:prior_audits/DIGEST_oz.md:L93:S10",
                "source_extraction_method": "human-curated",
            }
        )
        self.assertEqual(tier, "tier-2-verified-public-archive")
        self.assertIn("prior-audit", reason)

    def test_tier_2_findings_go(self) -> None:
        tier, _ = self.classify(
            {
                "record_id": "findings-go:swival-go-crypto-008:abcd",
                "source_audit_ref": "findings-go:reference/findings_go_swival.jsonl:swival-go-crypto-008",
            }
        )
        self.assertEqual(tier, "tier-2-verified-public-archive")

    def test_tier_2_solodit_numeric_id(self) -> None:
        tier, _ = self.classify(
            {
                "record_id": "solodit-spec:20232:9c5adb86c501",
                "source_audit_ref": "solodit-spec:detectors/_specs/drafts_solodit/h-09-foo.yaml:20232",
            }
        )
        self.assertEqual(tier, "tier-2-verified-public-archive")

    def test_tier_2_solodit_named_draft_fallback(self) -> None:
        tier, _ = self.classify(
            {
                "record_id": "solodit-spec:drafts_rust_soroban:misnamed-debt:abc",
                "source_audit_ref": "solodit-spec:detectors/_specs/drafts_rust_soroban/misnamed-debt-token-views.yaml:misnamed-debt-token-views",
            }
        )
        self.assertEqual(tier, "tier-2-verified-public-archive")

    def test_tier_2_local_workspace_overrides_regex_derived(self) -> None:
        # local-workspace records often carry extraction_method=regex-derived
        # but are real workspace artifacts, not synthetic taxonomies.
        tier, reason = self.classify(
            {
                "record_id": "legacy:2026-05-08-worker-a_verdict.md:abc",
                "source_audit_ref": "2026-05-08-worker-A/VERDICT.md",
                "record_tier": "local-workspace",
                "source_extraction_method": "regex-derived",
            }
        )
        self.assertEqual(tier, "tier-2-verified-public-archive")
        self.assertIn("record-tier", reason)

    # ----------------------------------------------------------------- #
    # Tier-2 contest-platform + audit-firm prefix coverage (Wave-2 W2.3).
    # These were previously classified as tier-3 fallback-unknown-prefix.
    # ----------------------------------------------------------------- #

    def test_tier_2_code4rena_prefix(self) -> None:
        tier, reason = self.classify(
            {
                "record_id": "code4rena:2022-05-rubicon-findings:1:31a587298909",
                "source_audit_ref": "code4rena:2022-05-rubicon-findings:1",
                "source_extraction_method": "corpus-etl",
            }
        )
        self.assertEqual(tier, "tier-2-verified-public-archive")
        self.assertIn("code4rena:", reason)

    def test_tier_2_sherlock_prefix(self) -> None:
        tier, reason = self.classify(
            {
                "record_id": "sherlock:2023-01-optimism-judging:001:6aac6203806f",
                "source_audit_ref": "sherlock:2023-01-optimism-judging:001",
                "source_extraction_method": "corpus-etl",
            }
        )
        self.assertEqual(tier, "tier-2-verified-public-archive")
        self.assertIn("sherlock:", reason)

    def test_tier_2_spearbit_prefix(self) -> None:
        tier, reason = self.classify(
            {
                "record_id": "spearbit:morpho-blue:M-01:abcd1234efef",
                "source_audit_ref": "spearbit:morpho-blue:M-01",
            }
        )
        self.assertEqual(tier, "tier-2-verified-public-archive")
        self.assertIn("spearbit:", reason)

    def test_tier_2_cantina_prefix(self) -> None:
        tier, reason = self.classify(
            {
                "record_id": "cantina:dydx-v4:213:01234abcd567",
                "source_audit_ref": "cantina:dydx-v4:213",
            }
        )
        self.assertEqual(tier, "tier-2-verified-public-archive")
        self.assertIn("cantina:", reason)

    def test_tier_2_cyfrin_prefix(self) -> None:
        tier, reason = self.classify(
            {
                "record_id": "cyfrin:beanstalk:H-03:fedcba987654",
                "source_audit_ref": "cyfrin:beanstalk:H-03",
            }
        )
        self.assertEqual(tier, "tier-2-verified-public-archive")
        self.assertIn("cyfrin:", reason)

    def test_tier_2_hats_prefix(self) -> None:
        tier, reason = self.classify(
            {
                "record_id": "hats:gmx:C-04:a1b2c3d4e5f6",
                "source_audit_ref": "hats:gmx:C-04",
            }
        )
        self.assertEqual(tier, "tier-2-verified-public-archive")
        self.assertIn("hats:", reason)

    def test_tier_2_pashov_prefix(self) -> None:
        tier, reason = self.classify(
            {
                "record_id": "pashov:ethena:medium-02:abcdef012345",
                "source_audit_ref": "pashov:ethena:medium-02",
            }
        )
        self.assertEqual(tier, "tier-2-verified-public-archive")
        self.assertIn("pashov:", reason)

    def test_tier_2_chainsecurity_prefix(self) -> None:
        tier, reason = self.classify(
            {
                "record_id": "chainsecurity:lido-v2:high-01:1234567890ab",
                "source_audit_ref": "chainsecurity:lido-v2:high-01",
            }
        )
        self.assertEqual(tier, "tier-2-verified-public-archive")
        self.assertIn("chainsecurity:", reason)

    def test_tier_2_trailofbits_prefix(self) -> None:
        tier, reason = self.classify(
            {
                "record_id": "trailofbits:aptos:2024-10-franklintempleton-aptos-securityreview:6ca2e5980925",
                "source_audit_ref": "trailofbits:aptos:franklintempleton-securityreview",
            }
        )
        self.assertEqual(tier, "tier-2-verified-public-archive")
        self.assertIn("trailofbits:", reason)

    def test_tier_2_zellic_prefix(self) -> None:
        tier, reason = self.classify(
            {
                "record_id": "zellic:aptos:pancakeswap-aptos-zellic-audit-report:3a1ed9505aad",
                "source_audit_ref": "zellic:aptos:pancakeswap-audit",
            }
        )
        self.assertEqual(tier, "tier-2-verified-public-archive")
        self.assertIn("zellic:", reason)

    def test_tier_2_openzeppelin_prefix(self) -> None:
        tier, reason = self.classify(
            {
                "record_id": "openzeppelin:compound-iii:H-02:abc1239876ef",
                "source_audit_ref": "openzeppelin:compound-iii:H-02",
            }
        )
        self.assertEqual(tier, "tier-2-verified-public-archive")
        self.assertIn("openzeppelin:", reason)

    def test_tier_2_immunefi_plain_prefix(self) -> None:
        # `immunefi-public:` / `immunefi-live:` already match tier-1; the bare
        # `immunefi:` prefix should fall to tier-2 (verified-public-archive)
        # rather than tier-3 fallback.
        tier, reason = self.classify(
            {
                "record_id": "immunefi:archive:bug-7654:a987654321bc",
                "source_audit_ref": "immunefi:archive:bug-7654",
            }
        )
        self.assertEqual(tier, "tier-2-verified-public-archive")
        self.assertIn("immunefi:", reason)

    def test_tier_2_audit_firm_umbrella_prefix(self) -> None:
        tier, reason = self.classify(
            {
                "record_id": "audit-firm:trailofbits-publications:reviews_compound:6e5a3f1c0d2e",
                "source_audit_ref": "audit-firm:trailofbits-publications:reviews_compound",
            }
        )
        self.assertEqual(tier, "tier-2-verified-public-archive")
        self.assertIn("audit-firm:", reason)

    def test_tier_2_audit_firm_pashov_subprefix(self) -> None:
        tier, _ = self.classify(
            {
                "record_id": "audit-firm:pashov-audits:ethena-2024-02:b1c2d3e4f5a6",
                "source_audit_ref": "audit-firm:pashov-audits:ethena-2024-02",
            }
        )
        self.assertEqual(tier, "tier-2-verified-public-archive")

    def test_tier_2_solc_bugs_json_prefix(self) -> None:
        # Canonical ethereum/solidity docs/bugs.json taxonomy records cite the
        # verbatim Solidity-team disclosure (real `blog.soliditylang.org`
        # writeup + real `github.com/ethereum/solidity/blob/develop/docs/bugs.json`
        # anchor). They are structurally a verified-public-archive source,
        # equivalent to `findings-go:` / `audit-firm:` records.
        tier, reason = self.classify(
            {
                "record_id": "solc-compiler:sol-2022-1:abiencodecallliteralasfixedbytesbug:b3a6ee83be1b",
                "source_audit_ref": "solc-bugs-json:SOL-2022-1:AbiEncodeCallLiteralAsFixedBytesBug",
            }
        )
        self.assertEqual(tier, "tier-2-verified-public-archive")
        self.assertIn("solc-bugs-json:", reason)

    def test_tier_2_w23_residual_zk_auditor(self) -> None:
        # W2.3-residual (PR #728). ZK audit-firm reports (asymmetric-research,
        # trail-of-bits, veridise, zellic) - each record cites a real public
        # PDF or github URL under fix_pattern / source_audit_ref.
        tier, reason = self.classify(
            {
                "record_id": "zk-auditor:trail-of-bits:aztec-plonk-verifier:S7:abcd1234",
                "source_audit_ref": "zk-auditor:trail-of-bits:aztec-plonk-verifier:verifier-domain-separation-missing:S7",
            }
        )
        self.assertEqual(tier, "tier-2-verified-public-archive")
        self.assertIn("zk-auditor:", reason)

    def test_tier_2_w23_residual_zk_contest(self) -> None:
        # Cantina / code4rena zk-targeted contests.
        tier, reason = self.classify(
            {
                "record_id": "zk-contest:sherlock:linea-zkrollup:S7:abcd",
                "source_audit_ref": "zk-contest:sherlock:linea-zkrollup:verifier-stale-key:S7",
            }
        )
        self.assertEqual(tier, "tier-2-verified-public-archive")
        self.assertIn("zk-contest:", reason)

    def test_tier_2_w23_residual_zkbugs(self) -> None:
        # zksecurity/zkbugs dataset; real github URLs under source_audit_ref.
        tier, reason = self.classify(
            {
                "record_id": "zkbugs:0xpolygonhermez/zkevm-proverjs:hexens-missing-constraint:c0d94dbc07ab",
                "source_audit_ref": "zkbugs:0xpolygonhermez/zkevm-proverjs/hexens_missing_constraint_in_pil",
            }
        )
        self.assertEqual(tier, "tier-2-verified-public-archive")
        self.assertIn("zkbugs:", reason)

    def test_tier_2_w23_residual_zkbugs_catalog(self) -> None:
        # zksecurity/zkbugs catalog - circuit-aliased-witness taxonomy.
        tier, reason = self.classify(
            {
                "record_id": "zkbugs-catalog:circuit-aliased-witness:aztec-note-merge:S10",
                "source_audit_ref": "zkbugs-catalog:proof-malleability:taiko-block-prover:S12",
            }
        )
        self.assertEqual(tier, "tier-2-verified-public-archive")
        self.assertIn("zkbugs-catalog:", reason)

    def test_tier_2_w23_residual_zkbugtracker(self) -> None:
        # 0xPARC zk-bug-tracker - canonical public-tracker entries.
        tier, reason = self.classify(
            {
                "record_id": "zkbugtracker:pse-zkevm-2:abcd",
                "source_audit_ref": "zkbugtracker:0xPARC/zk-bug-tracker:pse-zkevm-2",
            }
        )
        self.assertEqual(tier, "tier-2-verified-public-archive")
        self.assertIn("zkbugtracker:", reason)

    def test_tier_2_w23_residual_l2_zkrollup(self) -> None:
        # L2 zkrollup incident references - consensys-diligence / aztec.
        tier, reason = self.classify(
            {
                "record_id": "l2-zkrollup:consensys-diligence-linea:S1:abcd",
                "source_audit_ref": "l2-zkrollup:consensys-diligence-linea-rollup-2023-07-sequencer-finality:linearollup-finalizeblocks",
            }
        )
        self.assertEqual(tier, "tier-2-verified-public-archive")
        self.assertIn("l2-zkrollup:", reason)

    def test_tier_2_w23_residual_mev_exploits(self) -> None:
        # Flashbots / blocknative MEV write-ups - real
        # https://writings.flashbots.net / blocknative blog URLs.
        tier, reason = self.classify(
            {
                "record_id": "mev-exploits:flashbots-sitemap:order-flow-auctions:2b2a2bce0ed0",
                "source_audit_ref": "https://writings.flashbots.net/order-flow-auctions-and-centralisation-II",
            }
        )
        self.assertEqual(tier, "tier-2-verified-public-archive")
        self.assertIn("mev-exploits:", reason)

    def test_tier_2_w23_residual_mev_flashloan(self) -> None:
        # Flash-loan canonical attack classes.
        tier, reason = self.classify(
            {
                "record_id": "mev-flashloan:aave-v2-collateral-donation-class:pre-fix:abc",
                "source_audit_ref": "mev-flashloan:flashbots-pga-class:uniswap-v2-arb-router-class:pre-fix",
            }
        )
        self.assertEqual(tier, "tier-2-verified-public-archive")
        self.assertIn("mev-flashloan:", reason)

    def test_tier_2_w23_residual_bridge_incident(self) -> None:
        # Bridge-incident post-mortems - real https://rekt.news URLs.
        tier, reason = self.classify(
            {
                "record_id": "bridge-incident:harmony-horizon-2022-06:af52dd81c86c",
                "source_audit_ref": "https://rekt.news/harmony-rekt",
            }
        )
        self.assertEqual(tier, "tier-2-verified-public-archive")
        self.assertIn("bridge-incident:", reason)

    def test_tier_2_w23_residual_starknet_cairo_corpus(self) -> None:
        # Starknet / Cairo audit PDFs - real raw.githubusercontent.com URLs.
        tier, reason = self.classify(
            {
                "record_id": "starknet-cairo-corpus:argentlabs__argent-contracts-starknet:S1",
                "source_audit_ref": "https://raw.githubusercontent.com/OpenZeppelin/cairo-contracts/main/audits/2025-11-v3.0.0.pdf",
            }
        )
        self.assertEqual(tier, "tier-2-verified-public-archive")
        self.assertIn("starknet-cairo-corpus:", reason)

    def test_tier_2_w23_residual_movebit(self) -> None:
        # Movebit audit reports - real github.com/movebit/Sampled-Audit-Reports URLs.
        tier, reason = self.classify(
            {
                "record_id": "movebit:aptos:movedid-aptos-contracts-audit-report:abcd",
                "source_audit_ref": "https://github.com/movebit/Sampled-Audit-Reports/blob/main/reports/MoveDID-Aptos-Contracts-Audit-Report.pdf",
            }
        )
        self.assertEqual(tier, "tier-2-verified-public-archive")
        self.assertIn("movebit:", reason)

    def test_tier_2_w23_residual_solana_svm(self) -> None:
        # Solana SVM write-ups - Neodyme breakpoint, Sec3 sealevel categories.
        tier, reason = self.classify(
            {
                "record_id": "solana-svm:sealevel:sealevel-category-10-sysvar-address:aa4f4826562e",
                "source_audit_ref": "solana-svm:sealevel:category:10-sysvar-address",
            }
        )
        self.assertEqual(tier, "tier-2-verified-public-archive")
        self.assertIn("solana-svm:", reason)

    def test_tier_2_w23_residual_vyper_39363(self) -> None:
        # CVE-2023-39363 Vyper compiler bug family - real CVE id + on-chain contract.
        tier, reason = self.classify(
            {
                "record_id": "vyper-39363:cve-2023-39363:curve-crv-eth-crypto-pool:post-fix-not-migrated:abc",
                "source_audit_ref": "vyper-39363:cve-2023-39363:curve-aleth-eth-pool:0xc4c319e2d4d66cca4464c0c2b32c9bd23ebe784e:pre-fix",
            }
        )
        self.assertEqual(tier, "tier-2-verified-public-archive")
        self.assertIn("vyper-39363:", reason)

    def test_tier_2_w23_residual_cve_db(self) -> None:
        # cve-db: canonical NIST/MITRE CVE entries. Distinct from tier-1
        # `cve_db:` (underscore form lives in TIER1_SUBSTRINGS).
        tier, reason = self.classify(
            {
                "record_id": "cve-db:cve-2018-10299:pre-fix:0efbe82b9a53",
                "source_audit_ref": "cve-db:cve-2018-10299:pre-fix",
            }
        )
        self.assertEqual(tier, "tier-2-verified-public-archive")
        self.assertIn("cve-db:", reason)

    def test_tier_1_git_mining_solc_still_wins_over_tier_2_bugs_json(self) -> None:
        # Real upstream solc fix-commit SHA records remain tier-1; the new
        # tier-2 `solc-bugs-json:` prefix must NOT downgrade them.
        tier, _ = self.classify(
            {
                "record_id": "git-mining:ethereum-solidity:47c83613b40dc0efd767d70047255ed68e1cb017:fe58ff80eedd",
                "source_audit_ref": "git-mining:ethereum/solidity@47c83613b40dc0efd767d70047255ed68e1cb017",
            }
        )
        self.assertEqual(tier, "tier-1-verified-realtime-api")

    def test_tier_1_immunefi_public_still_wins_over_tier_2_bare(self) -> None:
        # Ensure adding `immunefi:` to tier-2 prefixes does NOT regress the
        # tier-1 substring match for `immunefi-public:` / `immunefi-live:`.
        tier, _ = self.classify(
            {
                "record_id": "immunefi-public:bug-7654:a987654321bc",
                "source_audit_ref": "immunefi-public:bug-7654",
            }
        )
        self.assertEqual(tier, "tier-1-verified-realtime-api")

    def test_tier_1_cantina_live_still_wins_over_tier_2_bare(self) -> None:
        # `cantina-live:` is a tier-1 substring; bare `cantina:` is tier-2.
        # Confirm tier-1 priority for live records.
        tier, _ = self.classify(
            {
                "record_id": "cantina-live:dydx:213:01234abcd567",
                "source_audit_ref": "cantina-live:dydx:213",
            }
        )
        self.assertEqual(tier, "tier-1-verified-realtime-api")

    def test_tier_3_corpus_mined_slice(self) -> None:
        tier, _ = self.classify(
            {
                "record_id": "corpus-mined:slice_ah.md:L37:S16:d6715fca62fc",
                "source_audit_ref": "corpus-mined:slice_ah.md:L37:S16",
                "source_extraction_method": "regex-derived",
            }
        )
        self.assertEqual(tier, "tier-3-synthetic-taxonomy-anchored")

    def test_tier_3_fallback_regex_derived_no_anchor(self) -> None:
        tier, reason = self.classify(
            {
                "record_id": "unknown-prefix:foo:abc",
                "source_audit_ref": "unknown-prefix:foo",
                "source_extraction_method": "regex-derived",
            }
        )
        self.assertEqual(tier, "tier-3-synthetic-taxonomy-anchored")
        self.assertIn("regex-derived", reason)

    def test_tier_4_dsl_synthetic_target_repo(self) -> None:
        tier, _ = self.classify(
            {
                "record_id": "synthpattern:abc",
                "source_audit_ref": "some-ref:abc",
                "source_extraction_method": "dsl-synthetic",
                "target_repo": "unknown/dsl-synthetic",
            }
        )
        self.assertEqual(tier, "tier-4-bundled-fixture")

    def test_tier_4_solidity_fork_pattern(self) -> None:
        tier, _ = self.classify(
            {
                "record_id": "solidity-fork-pattern:finding_29984:abc",
                "source_audit_ref": "solidity-fork-pattern:patterns/fixtures/auto/finding_29984__README.md.vuln.md:unknown",
            }
        )
        self.assertEqual(tier, "tier-4-bundled-fixture")

    def test_tier_5_priority_over_tier_4(self) -> None:
        # Even though the record has dsl-synthetic target_repo, the Wave-3b
        # substring must override and place it in tier-5.
        tier, _ = self.classify(
            {
                "record_id": "legacy:dsl_pattern_vyper-reentrancy-lock-slot-drift:abc",
                "target_repo": "unknown/dsl-synthetic",
                "source_extraction_method": "dsl-synthetic",
            }
        )
        self.assertEqual(tier, "tier-5-quarantine")

    def test_fallback_unknown_prefix(self) -> None:
        tier, reason = self.classify(
            {
                "record_id": "weird:zzz:abc",
                "source_audit_ref": "weird:zzz",
            }
        )
        self.assertEqual(tier, "tier-3-synthetic-taxonomy-anchored")
        self.assertEqual(reason, "fallback-unknown-prefix")


class StratifyDirectoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = _load_tool()
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.tags_dir = root / "tags"
        self.tags_dir.mkdir()
        self.output = root / "candidates.jsonl"

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _write(self, name: str, body: str) -> Path:
        p = self.tags_dir / name
        p.write_text(textwrap.dedent(body).lstrip(), encoding="utf-8")
        return p

    def _minimal_record(
        self,
        *,
        record_id: str,
        source_audit_ref: str,
        extraction_method: str = "corpus-etl",
        target_repo: str = "owner/repo",
    ) -> str:
        return f"""
            schema_version: auditooor.hackerman_record.v1
            record_id: {record_id}
            source_audit_ref: {source_audit_ref}
            source_extraction_method: "{extraction_method}"
            target_repo: {target_repo}
            target_language: solidity
            target_component: SomeFunc
            function_shape:
              raw_signature: function someFunc()
              shape_tags:
                - language:solidity
            bug_class: x
            attack_class: y
            attacker_role: unprivileged
            attacker_action_sequence: zzz
            required_preconditions: []
            impact_class: theft
            impact_actor: protocol-treasury
            impact_dollar_class: "<$100k"
            fix_pattern: add guard
            fix_anti_pattern_avoided: rely on caller
            severity_at_finding: medium
            year: 2025
            cross_language_analogues: []
            related_records: []
            """

    def test_dry_run_classifies_all_tiers(self) -> None:
        self._write(
            "tier1.yaml",
            self._minimal_record(
                record_id="git-mining:foo:abc:def",
                source_audit_ref="git-mining:reports/foo.json@abcd1234ef",
            ),
        )
        self._write(
            "tier2.yaml",
            self._minimal_record(
                record_id="prior-audit:monetrix:digest:abc",
                source_audit_ref="prior-audit:monetrix:DIGEST.md:L1:S1",
            ),
        )
        self._write(
            "tier3.yaml",
            self._minimal_record(
                record_id="corpus-mined:slice_ah.md:L37:S16:abc",
                source_audit_ref="corpus-mined:slice_ah.md:L37:S16",
                extraction_method="regex-derived",
            ),
        )
        self._write(
            "tier4.yaml",
            self._minimal_record(
                record_id="solidity-fork-pattern:finding_29984:abc",
                source_audit_ref="solidity-fork-pattern:patterns/fixtures/auto/finding_29984.md.vuln.md:unknown",
                target_repo="unknown",
            ),
        )
        self._write(
            "tier5.yaml",
            self._minimal_record(
                record_id="legacy:dsl_pattern_vyper-reentrancy-lock-slot-drift:abc",
                source_audit_ref="dsl_pattern/vyper-reentrancy-lock-slot-drift",
                extraction_method="dsl-synthetic",
                target_repo="unknown/dsl-synthetic",
            ),
        )
        # Add a non-v1 record that must be skipped.
        self._write(
            "skip.yaml",
            """
            verdict_id: dsl_pattern/foo
            schema_version: auditooor.verdict_tag.v2
            """,
        )

        summary = self.tool.stratify(self.tags_dir, self.output, write=False)
        self.assertEqual(summary["scanned"], 6)
        self.assertEqual(summary["skipped_non_hackerman_v1"], 1)
        self.assertEqual(summary["classified"], 5)
        self.assertEqual(summary["distribution"]["tier-1-verified-realtime-api"], 1)
        self.assertEqual(summary["distribution"]["tier-2-verified-public-archive"], 1)
        self.assertEqual(summary["distribution"]["tier-3-synthetic-taxonomy-anchored"], 1)
        self.assertEqual(summary["distribution"]["tier-4-bundled-fixture"], 1)
        self.assertEqual(summary["distribution"]["tier-5-quarantine"], 1)
        self.assertFalse(self.output.exists(), "dry-run must NOT write the JSONL")

    def test_accept_hackerman_v1_1_record(self) -> None:
        """Wave-2 Phase-3 schema migration: v1.1 records must be classified,
        NOT skipped. Regression-guard for the exact-match → prefix-match
        migration on the schema_version check at the stratify scan loop."""
        body = self._minimal_record(
            record_id="prior-audit:v1_1:abc",
            source_audit_ref="prior-audit:v1_1:DIGEST.md:L1:S1",
        ).replace(
            "schema_version: auditooor.hackerman_record.v1",
            "schema_version: auditooor.hackerman_record.v1.1",
        )
        self._write("v1_1.yaml", body)
        summary = self.tool.stratify(self.tags_dir, self.output, write=False)
        self.assertEqual(summary["scanned"], 1)
        self.assertEqual(summary["skipped_non_hackerman_v1"], 0)
        self.assertEqual(summary["classified"], 1)
        self.assertEqual(
            summary["distribution"]["tier-2-verified-public-archive"], 1
        )

    def test_write_persists_jsonl(self) -> None:
        self._write(
            "rec.yaml",
            self._minimal_record(
                record_id="prior-audit:foo:abc",
                source_audit_ref="prior-audit:foo:DIGEST.md:L1:S1",
            ),
        )
        summary = self.tool.stratify(self.tags_dir, self.output, write=True)
        self.assertTrue(self.output.exists())
        lines = [
            json.loads(l) for l in self.output.read_text(encoding="utf-8").splitlines() if l
        ]
        self.assertEqual(len(lines), 1)
        self.assertEqual(lines[0]["verification_tier"], "tier-2-verified-public-archive")
        self.assertEqual(summary["candidates_written"], 1)


if __name__ == "__main__":
    unittest.main()
