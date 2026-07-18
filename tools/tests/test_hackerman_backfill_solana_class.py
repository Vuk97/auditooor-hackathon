"""Tests for tools/hackerman-backfill-solana-class.py."""
from __future__ import annotations

import importlib.util
import json
import tempfile
import textwrap
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "hackerman-backfill-solana-class.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location(
        "_hackerman_backfill_solana_class", str(TOOL_PATH)
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


def _record(
    target_repo: str,
    target_language: str,
    body_extra: str,
    attack_class: str = "unknown-bug-class",
) -> str:
    return textwrap.dedent(
        f"""
        schema_version: auditooor.hackerman_record.v1
        record_id: rec-{abs(hash(target_repo + body_extra + attack_class)) % 100000}
        source_audit_ref: test
        target_repo: {target_repo}
        target_domain: lending
        target_language: {target_language}
        target_component: T
        function_shape:
          raw_signature: foo()
          shape_tags: [t]
        bug_class: x
        attack_class: {attack_class}
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


# 30 records: 22 Solana-ecosystem-eligible + classifiable, 4 Solana but
# unclassifiable, 2 non-Solana controls, 2 already-native skip controls.
SOLANA_RECORDS = [
    # 14 indicators (one per native class)
    ("sol_signer.yaml",      "ottersec/solana",  "rust",  "missing signer check on transfer ix",       "unknown-bug-class", "missing-signer-check"),
    ("sol_pda.yaml",         "ottersec/solana",  "rust",  "find_program_address collides with seed",   "unknown-bug-class", "pda-collision"),
    ("sol_pda_seed.yaml",    "ottersec/solana",  "rust",  "seed confusion enables impersonation",      "unknown-bug-class", "pda-seed-confusion"),
    ("sol_acct_conf.yaml",   "ottersec/solana",  "rust",  "wrong account type passed via AccountInfo<", "unknown-bug-class", "account-confusion"),
    ("sol_reinit.yaml",      "ottersec/solana",  "rust",  "reinitialization allows resetting state",   "unknown-bug-class", "account-reinitialization"),
    ("sol_cpi.yaml",         "ottersec/solana",  "rust",  "arbitrary cpi target with invoke_signed",   "unknown-bug-class", "cpi-arbitrary-target"),
    ("sol_sysvar.yaml",      "ottersec/solana",  "rust",  "sysvar spoof via fake sysvar account",      "unknown-bug-class", "sysvar-spoof"),
    ("sol_t22.yaml",         "ottersec/solana",  "rust",  "token-2022 transfer hook bypass",           "unknown-bug-class", "token-2022-extension-confusion"),
    ("sol_anchor.yaml",      "ottersec/solana",  "rust",  "ctx.accounts is mis-typed against Anchor context", "unknown-bug-class", "anchor-context-misuse"),
    ("sol_realloc.yaml",     "ottersec/solana",  "rust",  "account.realloc allows attacker resize",    "unknown-bug-class", "realloc-attack"),
    ("sol_close.yaml",       "ottersec/solana",  "rust",  "close=destination drains lamports",          "unknown-bug-class", "close-attack"),
    ("sol_init_if.yaml",     "ottersec/solana",  "rust",  "init_if_needed bypass on token account",    "unknown-bug-class", "init-if-needed-bypass"),
    ("sol_disc.yaml",        "ottersec/solana",  "rust",  "anchor discriminator collision",            "unknown-bug-class", "account-discriminator-spoof"),
    ("sol_alt.yaml",         "ottersec/solana",  "rust",  "address lookup table poisoning at runtime", "unknown-bug-class", "lookup-table-poisoning"),
    # 8 more "duplicate-class" rows so we cross the >=20 reclassification bar
    ("sol_signer_b.yaml",    "ottersec/solana",  "rust",  "is_signer not checked on PDA owner",         "unknown-bug-class", "missing-signer-check"),
    ("sol_pda_b.yaml",       "ottersec/solana",  "rust",  "program_derived_address mismatch",          "unknown-bug-class", "pda-collision"),
    ("sol_cpi_b.yaml",       "drift-labs/protocol-v2", "rust", "unchecked program id in cross-program invocation", "unknown-bug-class", "cpi-arbitrary-target"),
    ("sol_close_b.yaml",     "metaplex-foundation/mpl-core", "rust", "close_account allows lamports drain", "unknown-bug-class", "close-attack"),
    ("sol_disc_b.yaml",      "raydium/raydium-amm-v3", "rust", "8-byte discriminator forged",          "unknown-bug-class", "account-discriminator-spoof"),
    ("sol_realloc_b.yaml",   "marinade-finance/liquid-staking", "rust", "resize account via realloc",  "unknown-bug-class", "realloc-attack"),
    ("sol_anchor_b.yaml",    "jet-protocol/v2-fixed-term", "rust", "#[derive(Accounts)] missing has_one", "unknown-bug-class", "anchor-context-misuse"),
    ("sol_t22_b.yaml",       "openbook-dex/program", "rust", "permanent delegate extension confusion", "unknown-bug-class", "token-2022-extension-confusion"),
    # 4 Solana-ecosystem-eligible but no class indicator (no-class-match)
    ("sol_nocls_01.yaml",    "ottersec/solana",  "rust",  "generic accounting drift",                  "unknown-bug-class", "no-class-match"),
    ("sol_nocls_02.yaml",    "ottersec/solana",  "rust",  "share inflation on vault",                  "unknown-bug-class", "no-class-match"),
    ("sol_nocls_03.yaml",    "solana_program",   "rust",  "logic error in fee math",                   "unknown-bug-class", "no-class-match"),
    ("sol_nocls_04.yaml",    "anchor_lang",      "rust",  "rounding error in computation",             "unknown-bug-class", "no-class-match"),
    # 2 controls: non-Solana ecosystem (Solidity EVM)
    ("ctrl_evm_01.yaml",     "code4rena/notional", "solidity", "missing access control on borrow",     "unknown-bug-class", "skip-non-solana"),
    ("ctrl_evm_02.yaml",     "sherlock/derby",     "solidity", "reentrancy in deposit",                "unknown-bug-class", "skip-non-solana"),
    # 2 controls: already-native attack_class (skip)
    ("ctrl_already_01.yaml", "ottersec/solana",  "rust",  "missing signer check",                      "missing-signer-check", "skip-already-native"),
    ("ctrl_already_02.yaml", "ottersec/solana",  "rust",  "pda collision exploit",                     "pda-collision",        "skip-already-native"),
]


class HackermanBackfillSolanaClassTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = _load_tool()
        self.tmp = tempfile.TemporaryDirectory()
        self.tag_dir = Path(self.tmp.name) / "tags"
        self.tag_dir.mkdir(parents=True)
        self.ledger = Path(self.tmp.name) / "ledger.jsonl"

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _write_fixtures(self) -> None:
        for entry in SOLANA_RECORDS:
            name, repo, lang, body, attack_class, _expected = entry
            (self.tag_dir / name).write_text(
                _record(repo, lang, body, attack_class), encoding="utf-8"
            )

    def test_thirty_record_dry_run_yields_at_least_20_reclassified(self) -> None:
        self._write_fixtures()
        candidates, summary = self.tool.scan(self.tag_dir, apply=False)
        self.assertEqual(summary["scanned"], 30)
        self.assertGreaterEqual(summary["classified"], 20)
        self.assertEqual(summary["candidate_count"], summary["classified"])
        # 4 Solana-eligible but no class indicator -> bucket "no_class_match"
        self.assertEqual(summary["no_class_match"], 4)
        # 2 already-native rows are skipped after eligibility check
        self.assertEqual(summary["already_native_class_skipped"], 2)
        # Solana eligible = 22 classified + 4 no_class_match + 2 already_native
        # = 28 (the 2 EVM controls fall out of eligibility).
        self.assertEqual(summary["solana_eligible"], 28)
        # Each native class shows up at least once.
        expected_classes = {
            entry[5]
            for entry in SOLANA_RECORDS
            if not entry[5].startswith("skip-") and entry[5] != "no-class-match"
        }
        for cls in expected_classes:
            self.assertGreaterEqual(
                summary["class_counts"].get(cls, 0),
                1,
                msg=f"class {cls} not seen in dry-run summary",
            )

    def test_classifier_assigns_expected_class_per_fixture(self) -> None:
        for entry in SOLANA_RECORDS:
            name, _repo, _lang, body, _attack_class, expected = entry
            if expected.startswith("skip-") or expected == "no-class-match":
                continue
            cls, _matched = self.tool.classify(body)
            self.assertEqual(
                cls, expected, msg=f"{name}: expected {expected} got {cls}"
            )

    def test_is_solana_record_eligibility_filter(self) -> None:
        for entry in SOLANA_RECORDS:
            _name, repo, lang, body, _attack_class, expected = entry
            eligible = self.tool.is_solana_record(repo, lang, body)
            if expected == "skip-non-solana":
                self.assertFalse(eligible, msg=f"{repo} unexpectedly eligible")
            else:
                self.assertTrue(eligible, msg=f"{repo} not eligible")

    def test_apply_rewrites_attack_class(self) -> None:
        self._write_fixtures()
        candidates, summary = self.tool.scan(self.tag_dir, apply=True)
        self.assertTrue(summary["applied"])
        text = (self.tag_dir / "sol_signer.yaml").read_text(encoding="utf-8")
        self.assertIn("attack_class: missing-signer-check", text)
        # Control: EVM file should still carry original attack_class.
        text2 = (self.tag_dir / "ctrl_evm_01.yaml").read_text(encoding="utf-8")
        self.assertIn("attack_class: unknown-bug-class", text2)

    def test_ledger_round_trip(self) -> None:
        self._write_fixtures()
        candidates, summary = self.tool.scan(self.tag_dir, apply=False)
        self.tool.write_ledger(candidates, self.ledger)
        rows = [
            json.loads(line)
            for line in self.ledger.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        self.assertEqual(len(rows), summary["candidate_count"])
        for row in rows:
            self.assertIn("attack_class_original", row)
            self.assertIn("attack_class_new", row)
            self.assertIn("matched_indicator", row)
            self.assertIn("tag_file", row)

    def test_apply_and_dry_run_mutually_exclusive(self) -> None:
        rc = self.tool.main([
            "--apply", "--dry-run", "--tag-dir", str(self.tag_dir),
        ])
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
        self.assertEqual(out["scanned"], 30)
        self.assertGreaterEqual(out["classified"], 20)


if __name__ == "__main__":
    unittest.main()
