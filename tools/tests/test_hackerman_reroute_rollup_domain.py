"""Tests for tools/hackerman-reroute-rollup-domain.py."""
from __future__ import annotations

import importlib.util
import json
import tempfile
import textwrap
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "hackerman-reroute-rollup-domain.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location(
        "_hackerman_reroute_rollup_domain", str(TOOL_PATH)
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


def _record(target_repo: str, target_domain: str, body_extra: str = "") -> str:
    return textwrap.dedent(
        f"""
        schema_version: auditooor.hackerman_record.v1
        record_id: rec-{abs(hash(target_repo + target_domain + body_extra)) % 100000}
        source_audit_ref: test
        target_repo: {target_repo}
        target_domain: {target_domain}
        target_language: solidity
        target_component: T
        function_shape:
          raw_signature: foo()
          shape_tags: [t]
        bug_class: x
        attack_class: y
        attacker_role: unprivileged
        attacker_action_sequence: "{body_extra}"
        required_preconditions: [tbd]
        impact_class: theft
        impact_actor: arbitrary-user
        impact_dollar_class: "$10K-$100K"
        fix_pattern: f
        fix_anti_pattern_avoided: g
        severity_at_finding: medium
        year: 2024
        cross_language_analogues: []
        related_records: []
        """
    ).lstrip()


# 30 L2-stack records: 27 reroutable + 3 control cases (already rollup,
# non-reroutable domain like zk-proof, no L2 signal).
L2_RECORDS = [
    # op-stack (5)
    ("op_01.yaml", "ethereum-optimism/optimism", "bridge", "", "op-stack"),
    ("op_02.yaml", "sherlock/optimism", "bridge", "", "op-stack"),
    ("op_03.yaml", "code4rena/optimism", "vault", "", "op-stack"),
    ("op_04.yaml", "openzeppelin/optimism", "governance", "", "op-stack"),
    ("op_05.yaml", "spearbit/optimism", "lending", "", "op-stack"),
    # arbitrum (3)
    ("arb_01.yaml", "code4rena/arbitrum", "dex", "", "arbitrum-nitro"),
    ("arb_02.yaml", "OffchainLabs/arbitrum-stylus", "vault", "", "arbitrum-nitro"),
    ("arb_03.yaml", "trailofbits/arbitrum", "consensus", "", "arbitrum-nitro"),
    # zksync (4)
    ("zks_01.yaml", "code4rena/zksync", "governance", "", "zksync-era"),
    ("zks_02.yaml", "openzeppelin/zksync", "vault", "", "zksync-era"),
    ("zks_03.yaml", "matterlabs/era-contracts", "bridge", "", "zksync-era"),
    ("zks_04.yaml", "unknown", "vault", "Boojum zk circuit", "zksync-era"),
    # scroll (3)
    ("scr_01.yaml", "openzeppelin/scroll", "bridge", "", "scroll-zkevm"),
    ("scr_02.yaml", "scroll-tech/go-ethereum", "l1-client", "", "scroll-zkevm"),
    ("scr_03.yaml", "openzeppelin/scrollowner", "governance", "", "scroll-zkevm"),
    # linea (3)
    ("lin_01.yaml", "consensys/linea", "bridge", "", "linea-zkevm"),
    ("lin_02.yaml", "openzeppelin/linea", "vault", "", "linea-zkevm"),
    ("lin_03.yaml", "cyfrin/linea", "dex", "", "linea-zkevm"),
    # polygon zkevm (2)
    ("pol_01.yaml", "hexens/polygonzkevm", "bridge", "", "polygon-zkevm"),
    ("pol_02.yaml", "sigmaprime/polygon", "governance", "", "polygon-pos"),
    # starknet (2)
    ("stk_01.yaml", "consensys/starbase", "governance", "starknet-cairo", "starknet-cairo"),
    ("stk_02.yaml", "unknown", "vault", "starkware cairo verifier", "starknet-cairo"),
    # base (2)
    ("base_01.yaml", "base-org/azul", "vault", "", "base-l2"),
    ("base_02.yaml", "spearbit/base", "governance", "", "base-l2"),
    # mantle (1)
    ("mnt_01.yaml", "mantlenetworkio/mantle-v2", "consensus", "", "mantle-l2"),
    # taiko (1)
    ("tko_01.yaml", "taikoxyz/taiko-mono", "bridge", "", "taiko-l2"),
    # blast (1)
    ("bls_01.yaml", "zokyo/blastoff", "vault", "", "blast-l2"),
    # CONTROL: already rollup -> skipped
    ("ctrl_01.yaml", "ethereum-optimism/optimism", "rollup", "", "skip-already-rollup"),
    # CONTROL: zk-proof preserved -> skipped
    ("ctrl_02.yaml", "consensys/linea", "zk-proof", "", "skip-zk-proof"),
    # CONTROL: no L2 signal -> not a candidate
    ("ctrl_03.yaml", "code4rena/notional", "lending", "", "skip-no-signal"),
]


class HackermanRerouteRollupDomainTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = _load_tool()
        self.tmp = tempfile.TemporaryDirectory()
        self.tag_dir = Path(self.tmp.name) / "tags"
        self.tag_dir.mkdir(parents=True)
        self.ledger = Path(self.tmp.name) / "ledger.jsonl"

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _write_fixtures(self) -> None:
        for name, repo, domain, extra, _ in L2_RECORDS:
            (self.tag_dir / name).write_text(
                _record(repo, domain, extra), encoding="utf-8"
            )

    def test_thirty_record_dry_run_yields_27_candidates(self) -> None:
        self._write_fixtures()
        candidates, summary = self.tool.scan(self.tag_dir, apply=False)
        self.assertEqual(summary["scanned"], 30)
        self.assertEqual(summary["candidate_count"], 27)
        self.assertEqual(summary["already_rollup_or_zkproof_skipped"], 2)
        # ctrl_03 falls out via "no L2 signal" (never matched detect_stack).

    def test_detect_stack_per_bucket(self) -> None:
        expected_buckets = {
            entry[0]: entry[4]
            for entry in L2_RECORDS
            if not entry[4].startswith("skip-")
        }
        # detect_stack receives target_repo + body; build a tiny stub of body
        # text per fixture.
        for name, repo, _domain, extra, exp_bucket in L2_RECORDS:
            if exp_bucket.startswith("skip-"):
                continue
            body = (
                f"target_repo: {repo}\nattacker_action_sequence: {extra}\n"
            )
            sub_bucket, source = self.tool.detect_stack(repo, body)
            self.assertEqual(
                sub_bucket,
                exp_bucket,
                msg=f"{name}: expected {exp_bucket} got {sub_bucket}",
            )
            self.assertIn(source, ("target_repo", "body"))

    def test_apply_rewrites_target_domain_to_rollup(self) -> None:
        self._write_fixtures()
        candidates, summary = self.tool.scan(self.tag_dir, apply=True)
        self.assertEqual(summary["applied"], True)
        # Pick a known reroutable fixture and verify its body now says rollup.
        text = (self.tag_dir / "op_01.yaml").read_text(encoding="utf-8")
        self.assertIn("target_domain: rollup", text)
        # Control: zk-proof file MUST remain untouched.
        text2 = (self.tag_dir / "ctrl_02.yaml").read_text(encoding="utf-8")
        self.assertIn("target_domain: zk-proof", text2)
        self.assertNotIn("target_domain: rollup", text2)

    def test_ledger_round_trip(self) -> None:
        self._write_fixtures()
        candidates, summary = self.tool.scan(self.tag_dir, apply=False)
        self.tool.write_ledger(candidates, self.ledger)
        rows = [json.loads(line) for line in self.ledger.read_text(encoding="utf-8").splitlines() if line.strip()]
        self.assertEqual(len(rows), summary["candidate_count"])
        # Every row carries the required surface for rollback.
        for row in rows:
            self.assertIn("target_domain_original", row)
            self.assertEqual(row["target_domain_new"], "rollup")
            self.assertTrue(row["rollup_sub_bucket"])
            self.assertIn("tag_file", row)

    def test_apply_and_dry_run_mutually_exclusive(self) -> None:
        rc = self.tool.main(["--apply", "--dry-run", "--tag-dir", str(self.tag_dir)])
        self.assertEqual(rc, 2)

    def test_main_json_summary(self) -> None:
        self._write_fixtures()
        import contextlib
        import io
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = self.tool.main([
                "--dry-run",
                "--tag-dir", str(self.tag_dir),
                "--ledger", str(self.ledger),
                "--json-summary",
            ])
        self.assertEqual(rc, 0)
        out = json.loads(buf.getvalue().strip())
        self.assertEqual(out["candidate_count"], 27)
        self.assertEqual(out["scanned"], 30)


if __name__ == "__main__":
    unittest.main()
