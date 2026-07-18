from __future__ import annotations

import importlib.util
import json
import tempfile
import textwrap
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "hackerman-nvd-verification-sweep.py"


def _load_tool():
    import sys
    name = "_hackerman_nvd_verification_sweep"
    spec = importlib.util.spec_from_file_location(name, str(TOOL_PATH))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


SAMPLE_RECORD_WITH_GHSA = textwrap.dedent(
    """\
    schema_version: auditooor.hackerman_record.v1
    record_id: findings-go:lnd-ghsa-9gxx-58q6-42p7:11b937f1fc0d
    source_audit_ref: findings-go:reference/findings_go.jsonl:lnd-GHSA-9gxx-58q6-42p7
    target_repo: lightningnetwork/lnd
    target_component: lnd
    attacker_action_sequence: "CVE-2024-38359 (LND Onion Bomb): onion-routing packet processing allows a remote peer ..."
    severity_at_finding: high
    """
)


SAMPLE_RECORD_NO_CLAIM = textwrap.dedent(
    """\
    schema_version: auditooor.hackerman_record.v1
    record_id: critical:cantina:40209:49fab722dfc4
    target_repo: some-protocol/contracts
    attacker_action_sequence: "Reentrancy in withdraw path."
    severity_at_finding: critical
    """
)


SAMPLE_RECORD_ALREADY_FLAGGED = textwrap.dedent(
    """\
    schema_version: auditooor.hackerman_record.v1
    record_id: vyper_cve:fake-1
    target_repo: vyperlang/vyper
    attribution_verdict: UNVERIFIED-FABRICATED-WAVE-3B
    attacker_action_sequence: "CVE-2022-37937 vyper saturating ..."
    severity_at_finding: critical
    """
)


SAMPLE_RECORD_MISMATCH_REPO = textwrap.dedent(
    """\
    schema_version: auditooor.hackerman_record.v1
    record_id: findings-go:wrong-repo-attribution:abcdef
    target_repo: ethereum/go-ethereum
    attacker_action_sequence: "GHSA-9gxx-58q6-42p7 LND onion bomb is alleged to affect go-ethereum."
    severity_at_finding: high
    """
)


class HackermanNvdVerificationSweepTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = _load_tool()
        self.tmp = tempfile.TemporaryDirectory()
        self.workspace = Path(self.tmp.name)
        self.tags = self.workspace / "audit" / "corpus_tags" / "tags"
        self.tags.mkdir(parents=True)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    # --- regex extraction ---

    def test_id_claim_extraction_cve(self):
        fields = self.tool.parse_simple_yaml_fields(SAMPLE_RECORD_WITH_GHSA)
        claims = self.tool.extract_id_claims(SAMPLE_RECORD_WITH_GHSA, fields)
        kinds = {c.kind: c.id for c in claims}
        self.assertEqual(kinds.get("CVE"), "CVE-2024-38359")
        self.assertEqual(kinds.get("GHSA"), "GHSA-9gxx-58q6-42p7")

    def test_id_claim_extraction_none(self):
        fields = self.tool.parse_simple_yaml_fields(SAMPLE_RECORD_NO_CLAIM)
        claims = self.tool.extract_id_claims(SAMPLE_RECORD_NO_CLAIM, fields)
        self.assertEqual(claims, [])

    def test_simple_yaml_parser(self):
        fields = self.tool.parse_simple_yaml_fields(SAMPLE_RECORD_WITH_GHSA)
        self.assertEqual(fields["record_id"], "findings-go:lnd-ghsa-9gxx-58q6-42p7:11b937f1fc0d")
        self.assertEqual(fields["target_repo"], "lightningnetwork/lnd")

    # --- product matching ---

    def test_repo_token_overlap_match(self):
        evidence = {"descriptions": ["LND lightning network node onion bomb"]}
        ok, reason = self.tool.evidence_repo_match(evidence, "lightningnetwork/lnd")
        self.assertTrue(ok, reason)
        self.assertTrue(reason.startswith("match:"))

    def test_repo_token_overlap_mismatch(self):
        evidence = {"descriptions": ["vyper compiler reentrancy"]}
        ok, reason = self.tool.evidence_repo_match(evidence, "lightningnetwork/lnd")
        self.assertFalse(ok)
        self.assertEqual(reason, "no-token-overlap")

    def test_repo_token_overlap_empty(self):
        ok, reason = self.tool.evidence_repo_match({"descriptions": ["anything"]}, "")
        self.assertFalse(ok)
        self.assertEqual(reason, "empty-target-repo")

    def test_repo_token_overlap_weak_tokens_only(self):
        # btcd advisory description does not name "coredao" specifically -
        # only the common tokens "chain" and "org" appear.
        evidence = {
            "descriptions": [
                "btcd before 0.24.0 does not correctly implement BIP 68 chain consensus rules; org-x ate the apple"
            ],
        }
        ok, reason = self.tool.evidence_repo_match(evidence, "coredao-org/core-chain")
        self.assertFalse(ok, reason)
        self.assertTrue(reason.startswith("weak-match-only:"), reason)

    # --- skip rules ---

    def test_already_flagged_record_skipped(self):
        (self.tags / "vyper_cve:fake-1.yaml").write_text(SAMPLE_RECORD_ALREADY_FLAGGED)
        out_path = self.workspace / ".auditooor" / "out.jsonl"
        rc = self.tool.main([
            "--workspace", str(self.workspace),
            "--out", str(out_path),
            "--dry-run",
        ])
        self.assertEqual(rc, 0)
        lines = out_path.read_text().splitlines()
        header = json.loads(lines[0])
        self.assertTrue(header["_header"])
        self.assertEqual(header["totals"]["candidates_emitted"], 0)
        self.assertEqual(header["totals"]["skipped_already_flagged"], 1)

    def test_no_claim_record_skipped(self):
        (self.tags / "critical:cantina:40209:49fab722dfc4_49fab722dfc4.yaml").write_text(SAMPLE_RECORD_NO_CLAIM)
        out_path = self.workspace / ".auditooor" / "out.jsonl"
        rc = self.tool.main([
            "--workspace", str(self.workspace),
            "--out", str(out_path),
            "--dry-run",
        ])
        self.assertEqual(rc, 0)
        header = json.loads(out_path.read_text().splitlines()[0])
        self.assertEqual(header["totals"]["candidates_emitted"], 0)
        self.assertEqual(header["totals"]["skipped_no_claim"], 1)

    def test_dry_run_emits_blocked_verdict(self):
        (self.tags / "findings-go:lnd-ghsa.yaml").write_text(SAMPLE_RECORD_WITH_GHSA)
        out_path = self.workspace / ".auditooor" / "out.jsonl"
        rc = self.tool.main([
            "--workspace", str(self.workspace),
            "--out", str(out_path),
            "--dry-run",
        ])
        self.assertEqual(rc, 0)
        lines = out_path.read_text().splitlines()
        header = json.loads(lines[0])
        self.assertEqual(header["totals"]["candidates_emitted"], 1)
        cand = json.loads(lines[1])
        self.assertIn(cand["verdict"], ("NEEDS-MANUAL-REVIEW",))
        # all claim lookups skipped in dry-run
        for claim in cand["id_claims"]:
            self.assertTrue(str(claim["lookup"]).startswith("skipped:"))

    def test_miner_prefix_extraction(self):
        self.assertEqual(self.tool.miner_prefix_of("findings-go:x.yaml"), "findings-go")
        self.assertEqual(self.tool.miner_prefix_of("critical:cantina:40209:abc_abc.yaml"), "critical:cantina")
        self.assertEqual(self.tool.miner_prefix_of("vyper_cve:x.yaml"), "vyper_cve")
        self.assertEqual(self.tool.miner_prefix_of("mev_flashloan_x.yaml"), "mev_flashloan")
        self.assertEqual(self.tool.miner_prefix_of("historic:slither:1.yaml"), "historic")

    def test_scope_prefix_filtering(self):
        # finding-go is in default scope; cantina is too; out-of-scope prefix is rejected
        (self.tags / "findings-go:x.yaml").write_text(SAMPLE_RECORD_WITH_GHSA)
        (self.tags / "dsl_pattern_x.yaml").write_text(SAMPLE_RECORD_WITH_GHSA)
        out_path = self.workspace / ".auditooor" / "out.jsonl"
        rc = self.tool.main([
            "--workspace", str(self.workspace),
            "--out", str(out_path),
            "--dry-run",
        ])
        self.assertEqual(rc, 0)
        header = json.loads(out_path.read_text().splitlines()[0])
        # only the findings-go record is scanned (dsl_pattern_ is out of scope)
        self.assertEqual(header["totals"]["scanned"], 1)


if __name__ == "__main__":
    unittest.main()
