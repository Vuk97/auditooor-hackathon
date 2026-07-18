"""Tests for the ``vault_severity_calibration`` MCP callable.

Wave-2 hackerman capability lift (W2.8). Exercises:

- envelope shape (schema / context_pack_id / context_pack_hash);
- attack-class match (substring, case-insensitive);
- attack-class not in corpus -> empty result, non-degraded;
- missing attack_class -> degraded envelope;
- tags_dir missing -> degraded envelope;
- domain filter (vault, dex, lending);
- tier filter (min_verification_tier default 2; explicit 4 widens);
- quarantine (tier-5) always dropped;
- severity histogram correctness across all 5 buckets;
- top-5 ranking critical -> info (tier tiebreaker);
- top-5 capped at 5 even when total_records > 5;
- idempotent / deterministic context_pack_hash;
- dispatch routing via ``_dispatch``.
"""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "tools" / "vault-mcp-server.py"


def _load_module() -> Any:
    spec = importlib.util.spec_from_file_location(
        "vault_mcp_server_severity_calibration_test", MODULE_PATH
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


vault_mcp_server = _load_module()


def _record_yaml(
    record_id: str,
    attack_class: str,
    severity: str,
    *,
    target_domain: str = "vault",
    target_language: str = "solidity",
    target_repo: str = "owner/repo",
    source_audit_ref: str = "",
    shape_tags: list[str] | None = None,
) -> str:
    tags = shape_tags or ["verification_tier:tier-1-verified-realtime-api"]
    tag_lines = "\n".join(f"    - {t}" for t in tags)
    source_ref = source_audit_ref or f"https://example.com/audits/{record_id}"
    return (
        "schema_version: auditooor.hackerman_record.v1\n"
        f"record_id: {record_id}\n"
        f"target_domain: {target_domain}\n"
        f"target_language: {target_language}\n"
        f"target_repo: {target_repo}\n"
        f"target_component: synthetic-{record_id}\n"
        "function_shape:\n"
        "  raw_signature: synthetic\n"
        "  shape_tags:\n"
        f"{tag_lines}\n"
        f"bug_class: {attack_class}\n"
        f"attack_class: {attack_class}\n"
        f"severity_at_finding: {severity}\n"
        f"source_audit_ref: {source_ref}\n"
        "year: 2024\n"
    )


class SeverityCalibrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="severity-calibration-test-")
        self.root = Path(self.tmp.name)
        # Layout matches the corpus walker contract: ``tags_dir`` is the
        # ``audit/corpus_tags/tags`` root and per-record dirs live under
        # ``<subtree>/<record-slug>/record.yaml``. The walker also picks up
        # flat ``tags_dir/*.yaml`` records at one level deep.
        self.tags_dir = self.root / "audit" / "corpus_tags" / "tags"
        self.tags_dir.mkdir(parents=True)
        self.vault_dir = self.root / "obsidian-vault"
        self.vault_dir.mkdir()
        self.workspace = self.root / "workspace"
        self.workspace.mkdir()

        # Eight reentrancy records spread across severities + tiers + domains
        # plus a few off-class records to verify the attack-class filter.
        # severity, tier-shape-tag, domain
        records = [
            ("rec-crit-vault-t1", "reentrancy", "critical",
             "vault", "verification_tier:tier-1-verified-realtime-api"),
            ("rec-high-vault-t1", "reentrancy", "high",
             "vault", "verification_tier:tier-1-verified-realtime-api"),
            ("rec-high-dex-t2", "reentrancy", "high",
             "dex", "verification_tier:tier-2-verified-public-archive"),
            ("rec-med-vault-t2", "reentrancy", "medium",
             "vault", "verification_tier:tier-2-verified-public-archive"),
            ("rec-low-lending-t1", "reentrancy", "low",
             "lending", "verification_tier:tier-1-verified-realtime-api"),
            ("rec-info-vault-t3", "reentrancy", "info",
             "vault", "verification_tier:tier-3-synthetic-taxonomy-anchored"),
            ("rec-crit-vault-t4", "reentrancy", "critical",
             "vault", "verification_tier:tier-4-bundled-fixture"),
            ("rec-crit-vault-t5", "reentrancy", "critical",
             "vault", "verification_tier:tier-5-quarantine"),
            # Off-class records (must be excluded from reentrancy queries).
            ("rec-off-admin", "admin-bypass", "critical",
             "vault", "verification_tier:tier-1-verified-realtime-api"),
            ("rec-off-replay", "signature-replay", "high",
             "dex", "verification_tier:tier-2-verified-public-archive"),
        ]
        for rid, ac, sev, domain, tier_tag in records:
            rec_dir = self.tags_dir / "synthetic" / rid
            rec_dir.mkdir(parents=True)
            (rec_dir / "record.yaml").write_text(
                _record_yaml(
                    rid,
                    ac,
                    sev,
                    target_domain=domain,
                    shape_tags=[tier_tag],
                ),
                encoding="utf-8",
            )
        self.tags_root = self.tags_dir  # canonical tags root
        self.vault = vault_mcp_server.VaultQuery(self.vault_dir, self.root)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _call(self, **overrides: Any) -> dict[str, Any]:
        base = {
            "workspace_path": str(self.workspace),
            "attack_class": "reentrancy",
            "tags_dir": str(self.tags_root),
        }
        base.update(overrides)
        return self.vault.vault_severity_calibration(**base)

    # 1.
    def test_envelope_shape(self):
        result = self._call()
        self.assertEqual(
            result["schema"], vault_mcp_server.SEVERITY_CALIBRATION_SCHEMA
        )
        self.assertTrue(
            result["context_pack_id"].startswith(
                vault_mcp_server.SEVERITY_CALIBRATION_SCHEMA + ":"
            )
        )
        self.assertEqual(len(result["context_pack_hash"]), 64)
        self.assertFalse(result["degraded"])
        for key in ("critical", "high", "medium", "low", "info"):
            self.assertIn(key, result["severity_distribution"])

    # 2.
    def test_attack_class_match_default_tier_floor(self):
        # Default min_verification_tier=2. tier-3/4 excluded; tier-5 always
        # excluded. So we keep:
        #   tier-1: rec-crit-vault-t1, rec-high-vault-t1, rec-low-lending-t1
        #   tier-2: rec-high-dex-t2, rec-med-vault-t2
        # = 5 records, severities: 1 critical, 2 high, 1 medium, 1 low.
        result = self._call()
        self.assertEqual(result["total_records"], 5)
        self.assertEqual(
            result["severity_distribution"],
            {"critical": 1, "high": 2, "medium": 1, "low": 1, "info": 0},
        )

    # 3.
    def test_attack_class_not_in_corpus(self):
        result = self._call(attack_class="nonexistent-class")
        self.assertFalse(result["degraded"])
        self.assertEqual(result["total_records"], 0)
        self.assertEqual(
            result["severity_distribution"],
            {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        )
        self.assertEqual(result["top_5_examples"], [])

    # 4.
    def test_missing_attack_class_degrades(self):
        result = self.vault.vault_severity_calibration(
            workspace_path=str(self.workspace),
            attack_class="",
            tags_dir=str(self.tags_root),
        )
        self.assertTrue(result["degraded"])
        self.assertEqual(result["reason"], "missing_attack_class")
        self.assertEqual(result["top_5_examples"], [])

    # 5.
    def test_tags_dir_missing_degrades(self):
        bogus = self.root / "does-not-exist"
        result = self.vault.vault_severity_calibration(
            workspace_path=str(self.workspace),
            attack_class="reentrancy",
            tags_dir=str(bogus),
        )
        self.assertTrue(result["degraded"])
        self.assertEqual(result["reason"], "tags_dir_missing")

    # 6.
    def test_target_domain_vault_filter(self):
        # Domain=vault under default tier floor: tier-1 vault (crit, high)
        # + tier-2 vault (medium). dex/lending dropped. tier-3/4/5 dropped.
        result = self._call(target_domain="vault")
        self.assertEqual(result["total_records"], 3)
        self.assertEqual(
            result["severity_distribution"],
            {"critical": 1, "high": 1, "medium": 1, "low": 0, "info": 0},
        )

    # 7.
    def test_target_domain_dex_filter(self):
        result = self._call(target_domain="dex")
        self.assertEqual(result["total_records"], 1)
        self.assertEqual(result["severity_distribution"]["high"], 1)

    # 8.
    def test_target_domain_lending_filter(self):
        result = self._call(target_domain="lending")
        self.assertEqual(result["total_records"], 1)
        self.assertEqual(result["severity_distribution"]["low"], 1)

    # 9.
    def test_min_verification_tier_widen_to_4(self):
        # Floor=4 keeps tier-1..4 (rec-crit-vault-t4 + rec-info-vault-t3
        # now included). tier-5 still dropped.
        result = self._call(min_verification_tier=4)
        # Expect tier-1+2+3+4 across all domains:
        #   crit: t1 vault + t4 vault = 2
        #   high: t1 vault + t2 dex = 2
        #   medium: t2 vault = 1
        #   low: t1 lending = 1
        #   info: t3 vault = 1
        self.assertEqual(result["total_records"], 7)
        self.assertEqual(
            result["severity_distribution"],
            {"critical": 2, "high": 2, "medium": 1, "low": 1, "info": 1},
        )

    # 10.
    def test_quarantine_always_dropped(self):
        # Even with floor=4 (which doesn't formally allow 5), the t5 record
        # (rec-crit-vault-t5) must never appear in totals.
        result = self._call(min_verification_tier=4)
        ids = {ex["record_id"] for ex in result["top_5_examples"]}
        self.assertNotIn("rec-crit-vault-t5", ids)
        # Even when caller passes min_verification_tier=5 (the valid upper
        # bound), the quarantine record (tier-5) MUST still be excluded
        # because the callable filters tier-5 separately from the floor.
        result5 = self._call(min_verification_tier=5)
        ids = {ex["record_id"] for ex in result5["top_5_examples"]}
        self.assertNotIn("rec-crit-vault-t5", ids)

    # 11.
    def test_top_5_ranking_critical_first_then_tier(self):
        # With floor=4 the corpus exposes both a tier-1 critical and a
        # tier-4 critical. Critical-tier1 must precede critical-tier4 in
        # top-5 ordering.
        result = self._call(min_verification_tier=4)
        ranked = result["top_5_examples"]
        self.assertEqual(len(ranked), 5)
        # First example must be critical.
        self.assertEqual(ranked[0]["severity"], "critical")
        # Among criticals, tier-1 record precedes tier-4 record.
        crit_ids_in_order = [r["record_id"] for r in ranked if r["severity"] == "critical"]
        self.assertEqual(
            crit_ids_in_order, ["rec-crit-vault-t1", "rec-crit-vault-t4"]
        )
        # Severity rank is non-decreasing across the ranked list.
        sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        ranks = [sev_rank[r["severity"]] for r in ranked]
        self.assertEqual(ranks, sorted(ranks))

    # 12.
    def test_top_5_capped_at_5(self):
        # With floor=4 we have 7 eligible records; top_5_examples must
        # be exactly 5 entries.
        result = self._call(min_verification_tier=4)
        self.assertEqual(len(result["top_5_examples"]), 5)
        # Each entry has the required keys.
        for ex in result["top_5_examples"]:
            self.assertIn("record_id", ex)
            self.assertIn("severity", ex)
            self.assertIn("source_url", ex)
            self.assertIn("slug", ex)

    # 13.
    def test_deterministic_context_pack_hash(self):
        r1 = self._call()
        r2 = self._call()
        self.assertEqual(r1["context_pack_hash"], r2["context_pack_hash"])
        self.assertEqual(r1["context_pack_id"], r2["context_pack_id"])

    # 14.
    def test_dispatch_routing(self):
        result = self.vault._dispatch(
            "vault_severity_calibration",
            {
                "workspace_path": str(self.workspace),
                "attack_class": "reentrancy",
                "tags_dir": str(self.tags_root),
            },
        )
        self.assertEqual(
            result["schema"], vault_mcp_server.SEVERITY_CALIBRATION_SCHEMA
        )
        self.assertFalse(result["degraded"])
        self.assertEqual(result["total_records"], 5)

    # 15.
    def test_source_refs_envelope_present(self):
        # source_refs is part of the envelope contract. Synthetic test
        # tags_dirs live outside the repo, so _safe_hackerman_source_refs
        # may return an empty list (single-segment names are dropped) -
        # the key itself must always exist as a list.
        result = self._call()
        self.assertIn("source_refs", result)
        self.assertIsInstance(result["source_refs"], list)

    # 16.
    def test_top_5_examples_carry_source_url_and_slug(self):
        result = self._call()
        self.assertTrue(result["top_5_examples"])
        first = result["top_5_examples"][0]
        # source_url and slug must be non-empty for our synthetic records.
        self.assertTrue(first["source_url"])
        self.assertTrue(first["slug"])
        # slug is the relative tag-file path.
        self.assertTrue(first["slug"].endswith("record.yaml"))


if __name__ == "__main__":
    unittest.main()
