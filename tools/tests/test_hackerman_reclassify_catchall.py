from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "hackerman-reclassify-catchall.py"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


def _make_record_yaml(
    *,
    attack_class: str,
    target_component: str,
    attacker_action: str = "",
    fix_pattern: str = "",
    extra_tags: tuple[str, ...] = (),
    bug_class: str = "logic-error",
    source_audit_ref: str = "corpus-mined:slice.md:L1:S1",
    record_id: str = "corpus-mined:slice.md:L1:S1:deadbeef",
) -> str:
    tags = "\n".join(f"    - {tag}" for tag in extra_tags) or "    - protocol-invariant-bypass"
    return (
        f"schema_version: auditooor.hackerman_record.v1\n"
        f"record_id: {record_id}\n"
        f"source_audit_ref: {source_audit_ref}\n"
        f"target_domain: vault\n"
        f"target_language: solidity\n"
        f"target_repo: unknown\n"
        f'target_component: "{target_component}"\n'
        f"function_shape:\n"
        f'  raw_signature: "function {target_component}"\n'
        f"  shape_tags:\n"
        f"{tags}\n"
        f"bug_class: {bug_class}\n"
        f"attack_class: {attack_class}\n"
        f"attacker_role: unprivileged\n"
        f'attacker_action_sequence: "{attacker_action}"\n'
        f"required_preconditions:\n"
        f"  - placeholder\n"
        f"impact_class: theft\n"
        f"impact_actor: depositor-class\n"
        f'impact_dollar_class: "$100K-$1M"\n'
        f'fix_pattern: "{fix_pattern}"\n'
        f'fix_anti_pattern_avoided: "placeholder"\n'
        f"severity_at_finding: high\n"
        f"year: 2024\n"
    )


# 50 synthetic records: 30 should reclassify, 20 should NOT.
# Each tuple => (descriptor, attack_class, target_component, action, fix_pattern, expected_new_class_or_None)
SYNTHETIC_CASES: tuple[tuple[str, str, str, str, str, str | None], ...] = (
    # Reward theft family (10) - all should reclassify
    ("reward-1", "state-accounting-drift", "stealing-rewards-via-lastRewardTime-mismatch", "lastRewardTime mismatch lets the user steal reward; accRewardPerShare drift; harvest", "", "staking-reward-theft"),
    ("reward-2", "state-accounting-drift", "MasterChef-reward-debt-drift", "Reward debt accumulates; pendingReward inflated; userInfo.amount stale; harvest twice", "", "staking-reward-theft"),
    ("reward-3", "protocol-invariant-bypass", "drain-reward-pool-via-deposit-withdraw", "Front-run reward distribution to drain the reward pool; rewardPerToken not updated; harvest", "", "staking-reward-theft"),
    ("reward-4", "state-accounting-drift", "manipulate-reward-distribution", "Manipulate reward, then claim. Reward pool drained.", "", "reward-theft"),
    ("reward-5", "protocol-invariant-bypass", "lp-reward-double-claim-bug", "lp reward double claim because user.lastClaim not updated and claim reward triggers; double claim", "", "lp-reward-double-claim"),
    ("reward-6", "state-accounting-drift", "stake-reward-frontrun", "front-run reward update; stake briefly to capture; rewardPerShare drift; harvest", "", "staking-reward-theft"),
    ("reward-7", "protocol-invariant-bypass", "yield-incentive-redirect", "Reward token redirected; reward share inflated for attacker; rewardDebt set to 0", "", "reward-theft"),
    ("reward-8", "state-accounting-drift", "reward-theft-via-stale-balance", "Steal reward via stale balance read; pendingReward incorrect", "", "reward-theft"),
    ("reward-9", "protocol-invariant-bypass", "staker-deposit-withdraw-sandwich", "Stake reward sandwich: deposit, harvest, withdraw; rewardPerShare drift; earn reward", "", "staking-reward-theft"),
    ("reward-10", "state-accounting-drift", "claim-reward-twice-bug", "claim reward twice; user.lastClaim not updated; double-claim", "", "lp-reward-double-claim"),
    # Fee family (8)
    ("fee-1", "state-accounting-drift", "fee-rounding-asymmetry-on-deposit", "fee rounds in favor of the user; rounding direction; mulwad; ceil; fee favor asymmetric", "", "fee-rounding-asymmetry"),
    ("fee-2", "state-accounting-drift", "FeeOnTransfer-token-mismatch", "fee-on-transfer; deflationary token; balanceOf delta; received != amount; tax token", "", "fee-on-transfer-accounting-drift"),
    ("fee-3", "protocol-invariant-bypass", "manipulate-distribution-avoid-DAO-fee", "Manipulate distribution to avoid DAO fee. Bypass protocol fee. evade fee. feeCollector skipped.", "", "protocol-fee-theft"),
    ("fee-4", "state-accounting-drift", "performance-fee-skim", "Skim performance fee. Drain protocol fee. Treasury fee theft. feeCollector bypass fee.", "", "protocol-fee-theft"),
    ("fee-5", "state-accounting-drift", "fee-rounding-favor-attacker", "Fee rounding favors attacker; round down; mulwad; rounding direction mismatch; truncation; asymmetry", "", "fee-rounding-asymmetry"),
    ("fee-6", "protocol-invariant-bypass", "tax-token-accounting-mismatch", "tax token mismatch; deflationary token; balance delta; transfer tax", "", "fee-on-transfer-accounting-drift"),
    ("fee-7", "state-accounting-drift", "evade-management-fee", "evade management fee; treasury fee; performance fee; bypass fee; fee distribution", "", "protocol-fee-theft"),
    ("fee-8", "protocol-invariant-bypass", "round-up-fee-bug", "fee rounding asymmetry; fee rounds favorable; round up; mulwad; ceil; truncation", "", "fee-rounding-asymmetry"),
    # Vault share family (5)
    ("share-1", "state-accounting-drift", "first-deposit-share-inflation", "first depositor share inflation; totalSupply == 0; donation; balanceOf(address(this))", "", "share-accounting"),
    ("share-2", "protocol-invariant-bypass", "ERC4626-share-inflation", "shares dilution via donation; totalSupply == 0; balanceOf(vault); erc-4626", "", "share-accounting"),
    ("share-3", "state-accounting-drift", "mintShares-rounds-up", "mint shares rounds favorable; rounding; previewDeposit; convertToShares; mulwad; round up", "", "vault-share-mint-rounding"),
    ("share-4", "protocol-invariant-bypass", "redeemShares-rounds-down", "redeem shares rounds favorable; previewRedeem; convertToAssets; rounding; round down", "", "vault-share-redemption-rounding"),
    ("share-5", "state-accounting-drift", "shares-accounting-drift-vault", "shares mis-accounted; totalShares; share supply; share price drift", "", "share-accounting"),
    # Vesting / unlock family (3)
    ("unlock-1", "protocol-invariant-bypass", "vesting-cliff-bypass", "bypass vesting cliff; vesting schedule skipped; early vesting release", "", "vesting-bypass"),
    ("unlock-2", "state-accounting-drift", "unlock-before-period", "unlock before period; unlock shares early; lock release; lockup ignored", "", "unlock-shares"),
    ("unlock-3", "protocol-invariant-bypass", "lock-release-frontrun", "frontrun lock release; sandwich unlock; race the unlock; release queue", "", "lock-release-front-run"),
    # Slippage (2)
    ("slip-1", "protocol-invariant-bypass", "missing-slippage-on-swap", "missing slippage; minAmountOut=0; amountOutMin not enforced; deadline; sandwich; front-run swap", "", "slippage-bypass"),
    ("slip-2", "state-accounting-drift", "slippage-ignored-vault", "slippage ignored; min output; user supplies min ignored", "", "slippage-bypass"),
    # Liquidation (2)
    ("liq-1", "state-accounting-drift", "self-liquidate-for-bonus", "self-liquidate to claim liquidation bonus; liquidator bonus inflated; liquidation reward", "", "liquidation-bonus-theft"),
    ("liq-2", "protocol-invariant-bypass", "stale-price-liquidation", "stale price liquidation; liquidation price wrong; health factor mis-calc; LTV; collateral price; oracle price; liquidate", "", "liquidation-mispricing"),
    # ---- Negative cases (should NOT reclassify): 20 ----
    ("neg-1", "protocol-invariant-bypass", "logic-error-foo", "generic logic error in a state machine transition", "", None),
    ("neg-2", "state-accounting-drift", "dirty-flag-not-updated", "state-stale after move; some transition; not enough indicators here", "", None),
    ("neg-3", "protocol-invariant-bypass", "unknown-component-1", "some text without finance keywords", "", None),
    ("neg-4", "state-accounting-drift", "init-state-missing", "init-state-missing in a constructor", "", None),
    ("neg-5", "protocol-invariant-bypass", "consensus-fork-issue", "Consensus fork; cosmos-sdk; validator", "", None),
    ("neg-6", "protocol-invariant-bypass", "lone-fee-mention", "the protocol charges a fee but nothing else", "", None),  # only 1 indicator
    ("neg-7", "state-accounting-drift", "lone-reward-mention", "user gets a reward later", "", None),  # only 1 indicator
    ("neg-8", "protocol-invariant-bypass", "consensus-block-issue", "block proposer; sequencer; validator set", "", None),
    ("neg-9", "state-accounting-drift", "rebase-token-issue", "rebase token causes balance to change", "", None),
    ("neg-10", "protocol-invariant-bypass", "governance-snapshot-bug", "castVote uses current balance not snapshot id", "", None),  # vetoed by 'snapshot id' on lp-reward
    ("neg-11", "state-accounting-drift", "permission-leak", "missing permission check on admin", "", None),
    ("neg-12", "protocol-invariant-bypass", "oracle-stale-feed", "oracle reports stale price; some text", "", None),
    ("neg-13", "state-accounting-drift", "race-condition", "race condition without specific finance domain", "", None),
    ("neg-14", "protocol-invariant-bypass", "merkle-proof-replay", "merkle proof replay across roots", "", None),
    ("neg-15", "state-accounting-drift", "queue-overflow", "queue overflow under high load", "", None),
    ("neg-16", "protocol-invariant-bypass", "signature-malleability", "signature malleability via s-value", "", None),
    ("neg-17", "state-accounting-drift", "compression-bug", "compression library miscalibrated", "", None),
    ("neg-18", "protocol-invariant-bypass", "gas-griefing", "gas griefing during withdrawal loop", "", None),
    ("neg-19", "state-accounting-drift", "init-double-call", "init function called twice", "", None),
    ("neg-20", "protocol-invariant-bypass", "epoch-skipped", "epoch skipped via timestamp manipulation", "", None),
)


class HackermanReclassifyCatchallTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = _load(TOOL_PATH, "_hackerman_reclassify_catchall_test")

    def _populate(self, tag_dir: Path) -> None:
        for descriptor, attack_class, component, action, fix, _expected in SYNTHETIC_CASES:
            path = tag_dir / f"{descriptor}.yaml"
            path.write_text(
                _make_record_yaml(
                    attack_class=attack_class,
                    target_component=component,
                    attacker_action=action,
                    fix_pattern=fix,
                    record_id=f"corpus-mined:slice.md:L1:S{descriptor}:dead",
                ),
                encoding="utf-8",
            )

    def test_dry_run_reclassifies_at_least_30(self) -> None:
        with tempfile.TemporaryDirectory(prefix="reclassify-", dir=str(REPO_ROOT)) as tmp:
            root = Path(tmp)
            tag_dir = root / "tags"
            tag_dir.mkdir()
            self._populate(tag_dir)
            candidates_path = root / "candidates.jsonl"
            summary = self.tool.run(tag_dir, candidates_path, apply=False)
            self.assertGreaterEqual(
                summary["matched_candidates"],
                30,
                f"expected >=30 reclassifications, got {summary['matched_candidates']}",
            )
            self.assertEqual(summary["applied_writes"], 0)
            # spot-check candidate file has at least matched rows
            rows = [json.loads(line) for line in candidates_path.read_text(encoding="utf-8").splitlines() if line.strip()]
            self.assertEqual(len(rows), summary["matched_candidates"])
            for row in rows:
                self.assertIn(row["new_attack_class"], {
                    "reward-theft", "staking-reward-theft", "lp-reward-double-claim",
                    "fee-rounding-asymmetry", "fee-on-transfer-accounting-drift", "protocol-fee-theft",
                    "vault-share-mint-rounding", "vault-share-redemption-rounding", "share-accounting",
                    "vesting-bypass", "unlock-shares", "lock-release-front-run",
                    "slippage-bypass", "min-output-bypass",
                    "liquidation-mispricing", "liquidation-bonus-theft",
                    "cross-margin-position-confusion", "funding-rate-theft", "funding-rate-rounding",
                    "auction-bidding-bypass",
                })
                self.assertIn(row["old_attack_class"], {"protocol-invariant-bypass", "state-accounting-drift"})

    def test_apply_writes_attack_class_and_emits_rollback_sidecar(self) -> None:
        with tempfile.TemporaryDirectory(prefix="reclassify-apply-", dir=str(REPO_ROOT)) as tmp:
            root = Path(tmp)
            tag_dir = root / "tags"
            tag_dir.mkdir()
            self._populate(tag_dir)
            candidates_path = root / "candidates.jsonl"
            rollback_path = root / "rollback.jsonl"
            summary = self.tool.run(
                tag_dir, candidates_path, apply=True, rollback_path=rollback_path,
            )
            self.assertGreater(summary["applied_writes"], 0)
            # Sidecar contains the rollback entry.
            rb_rows = [
                json.loads(line)
                for line in rollback_path.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
            self.assertGreater(len(rb_rows), 0)
            for row in rb_rows:
                self.assertIn("attack_class_original", row)
                self.assertIn("attack_class_applied", row)
            # Re-apply: second pass should rewrite zero (every applied row is no longer in a catch-all).
            summary2 = self.tool.run(tag_dir, candidates_path, apply=True, rollback_path=root / "rollback2.jsonl")
            self.assertEqual(summary2["applied_writes"], 0)
            # Spot-check one applied row: attack_class flipped; no inline original (rollback lives in sidecar).
            sample_path = tag_dir / "reward-1.yaml"
            text = sample_path.read_text(encoding="utf-8")
            self.assertNotIn("attack_class_original:", text)
            self.assertIn("attack_class: staking-reward-theft", text)

    def test_classify_no_signal_returns_none(self) -> None:
        record = {
            "schema_version": "auditooor.hackerman_record.v1",
            "attack_class": "protocol-invariant-bypass",
            "target_component": "irrelevant-component",
            "attacker_action_sequence": "generic flow with no class indicators",
        }
        cls, conf, hits = self.tool.classify(record)
        self.assertIsNone(cls)
        self.assertEqual(conf, 0.0)
        self.assertEqual(hits, [])

    def test_classify_exact_phrase_match_is_high_confidence(self) -> None:
        record = {
            "schema_version": "auditooor.hackerman_record.v1",
            "attack_class": "state-accounting-drift",
            "target_component": "exploit",
            "attacker_action_sequence": "this is a clear staking reward theft scenario",
        }
        cls, conf, hits = self.tool.classify(record)
        self.assertEqual(cls, "staking-reward-theft")
        self.assertEqual(conf, 1.0)
        self.assertTrue(hits and hits[0].startswith("exact:"))

    def test_cli_dry_run_default(self) -> None:
        with tempfile.TemporaryDirectory(prefix="reclassify-cli-", dir=str(REPO_ROOT)) as tmp:
            root = Path(tmp)
            tag_dir = root / "tags"
            tag_dir.mkdir()
            self._populate(tag_dir)
            candidates_path = root / "candidates.jsonl"
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = self.tool.main(
                    [
                        "--tag-dir", str(tag_dir),
                        "--candidates-path", str(candidates_path),
                        "--json-summary",
                    ]
                )
            self.assertEqual(rc, 0)
            data = json.loads(buf.getvalue().strip())
            self.assertEqual(data["applied_writes"], 0)
            self.assertGreaterEqual(data["matched_candidates"], 30)

    def test_apply_and_dry_run_are_mutually_exclusive(self) -> None:
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            rc = self.tool.main(["--apply", "--dry-run"])
        self.assertEqual(rc, 2)

    # ------------------------------------------------------------------
    # Corpus-drift regression guards (Wave-2 #2).
    # The corpus migrated from flat `tags/*.yaml` to nested
    # `tags/<subtree>/<slug>/record.yaml`, and newer records carry v1.1/v1.2
    # schema_version. The original non-recursive glob + exact-v1 filter
    # silently scanned ~0 records. These three tests fail pre-fix.
    # ------------------------------------------------------------------

    _DRIFT_NESTED_RECORD = (
        "schema_version: auditooor.hackerman_record.v1.1\n"
        "record_id: corpus-mined:nested.md:L9:S9:cafef00d\n"
        "source_audit_ref: corpus-mined:nested.md:L9:S9\n"
        "target_domain: vault\n"
        "target_language: solidity\n"
        "target_repo: unknown\n"
        'target_component: "stealing-rewards-via-lastRewardTime-mismatch"\n'
        "function_shape:\n"
        '  raw_signature: "function harvest"\n'
        "  shape_tags:\n"
        "    - protocol-invariant-bypass\n"
        "bug_class: logic-error\n"
        "attack_class: protocol-invariant-bypass\n"
        "attacker_role: unprivileged\n"
        'attacker_action_sequence: "lastRewardTime mismatch lets the user steal reward; accRewardPerShare drift; harvest twice; pendingReward inflated"\n'
        "required_preconditions:\n"
        "  - placeholder\n"
        "impact_class: theft\n"
        "impact_actor: depositor-class\n"
        'impact_dollar_class: "$100K-$1M"\n'
        'fix_pattern: ""\n'
        'fix_anti_pattern_avoided: "placeholder"\n'
        "severity_at_finding: high\n"
        "year: 2024\n"
    )

    def test_recursive_discovery_finds_nested_v1_1_record(self) -> None:
        """Nested record.yaml with schema v1.1 must be scanned + matched.

        Pre-fix: non-recursive glob('*.yaml') misses the nested path AND the
        exact-v1 filter rejects v1.1 -> scanned_catchall_records == 0.
        """
        with tempfile.TemporaryDirectory(prefix="reclassify-nested-", dir=str(REPO_ROOT)) as tmp:
            root = Path(tmp)
            tag_dir = root / "tags"
            nested = tag_dir / "evm-vault" / "reward-drift-slug"
            nested.mkdir(parents=True)
            (nested / "record.yaml").write_text(self._DRIFT_NESTED_RECORD, encoding="utf-8")
            candidates_path = root / "candidates.jsonl"
            summary = self.tool.run(tag_dir, candidates_path, apply=False)
            self.assertGreaterEqual(
                summary["scanned_catchall_records"],
                1,
                "nested record.yaml (v1.1) was not discovered - recursive glob fix missing",
            )
            self.assertGreaterEqual(
                summary["matched_candidates"],
                1,
                "nested v1.1 catch-all record produced no reclassify candidate",
            )

    def test_schema_family_v1_2_is_scanned(self) -> None:
        """A v1.2 schema record must be scanned (prefix family filter)."""
        with tempfile.TemporaryDirectory(prefix="reclassify-v12-", dir=str(REPO_ROOT)) as tmp:
            root = Path(tmp)
            tag_dir = root / "tags"
            nested = tag_dir / "evm-vault" / "reward-drift-v12"
            nested.mkdir(parents=True)
            rec = self._DRIFT_NESTED_RECORD.replace(
                "schema_version: auditooor.hackerman_record.v1.1\n",
                "schema_version: auditooor.hackerman_record.v1.2\n",
            )
            (nested / "record.yaml").write_text(rec, encoding="utf-8")
            candidates_path = root / "candidates.jsonl"
            summary = self.tool.run(tag_dir, candidates_path, apply=False)
            self.assertGreaterEqual(
                summary["scanned_catchall_records"],
                1,
                "v1.2 schema record was rejected - exact-v1 filter not relaxed to family",
            )

    def test_flat_shape_v1_record_still_discovered(self) -> None:
        """Flat tags/foo.yaml v1 record must still be discovered (compat)."""
        with tempfile.TemporaryDirectory(prefix="reclassify-flat-", dir=str(REPO_ROOT)) as tmp:
            root = Path(tmp)
            tag_dir = root / "tags"
            tag_dir.mkdir()
            (tag_dir / "foo.yaml").write_text(
                _make_record_yaml(
                    attack_class="state-accounting-drift",
                    target_component="stealing-rewards-via-lastRewardTime-mismatch",
                    attacker_action="lastRewardTime mismatch lets the user steal reward; accRewardPerShare drift; harvest twice; pendingReward inflated",
                ),
                encoding="utf-8",
            )
            candidates_path = root / "candidates.jsonl"
            summary = self.tool.run(tag_dir, candidates_path, apply=False)
            self.assertGreaterEqual(summary["scanned_catchall_records"], 1)
            self.assertGreaterEqual(summary["matched_candidates"], 1)

    def test_recursive_discovery_dedupes_by_resolved_path(self) -> None:
        """A nested record.yaml must be counted once, not twice.

        It matches both rglob('record.yaml') and rglob('*.yaml'); the
        resolved-path de-dup must collapse them to a single scan.
        """
        with tempfile.TemporaryDirectory(prefix="reclassify-dedupe-", dir=str(REPO_ROOT)) as tmp:
            root = Path(tmp)
            tag_dir = root / "tags"
            nested = tag_dir / "evm-vault" / "dedupe-slug"
            nested.mkdir(parents=True)
            (nested / "record.yaml").write_text(self._DRIFT_NESTED_RECORD, encoding="utf-8")
            candidates_path = root / "candidates.jsonl"
            summary = self.tool.run(tag_dir, candidates_path, apply=False)
            self.assertEqual(
                summary["scanned_catchall_records"],
                1,
                "record.yaml counted more than once - resolved-path de-dup failed",
            )


if __name__ == "__main__":
    unittest.main()
