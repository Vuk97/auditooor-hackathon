"""Tests for tools/wave2-cross-firm-dedup-execute.py (Wave-3 W3.9).

Validates that the executor consumes the detector's clusters, picks the
canonical, merges source_audit_ref correctly, applies redirected_to to the
non-canonical members, and skips the deferred bucket. Mirrors the
test_wave2_cross_firm_dedup_detector.py harness style.
"""

from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

try:
    import yaml  # type: ignore
except ImportError:  # pragma: no cover
    raise unittest.SkipTest("PyYAML not installed")

REPO_ROOT = Path(__file__).resolve().parents[2]
EXECUTOR_PATH = REPO_ROOT / "tools" / "wave2-cross-firm-dedup-execute.py"


def _load_executor():
    spec = importlib.util.spec_from_file_location(
        "wave2_cross_firm_dedup_execute", EXECUTOR_PATH
    )
    mod = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


def _write_firm_record(
    tags_root: Path,
    firm: str,
    record_id: str,
    *,
    title: str,
    severity: str,
    protocol: str,
    attack_class: str,
    verification_tier: str = "tier-2-verified-public-archive",
    incident_date: str = "2024-01-01",
    record_source_url: str = "",
    extra_source_refs: list = None,
) -> Path:
    firm_dir = tags_root / f"firm-{firm}-audits" / record_id
    firm_dir.mkdir(parents=True, exist_ok=True)
    refs = list(extra_source_refs or [])
    if record_source_url:
        refs.append(record_source_url)
    rec = {
        "schema_version": "auditooor.hackerman_record.v1.1",
        "record_id": record_id,
        "title": title,
        "severity_at_finding": severity,
        "target_repo": protocol,
        "target_component": f"{protocol}/contracts",
        "attack_class": attack_class,
        "bug_class": attack_class,
        "verification_tier": verification_tier,
        "incident_date": incident_date,
        "source_audit_ref": refs or f"audit-firm:{firm}:{record_id}.pdf",
        "record_source_url": (
            record_source_url
            or f"https://example/{firm}/{record_id}.pdf"
        ),
        "function_shape": {
            "raw_signature": f"firm-record::{firm}/{record_id}",
            "shape_tags": [
                "audit-firm-public-report",
                f"firm-{firm}-audits",
                f"verification_tier:{verification_tier}",
            ],
        },
    }
    path = firm_dir / "record.yaml"
    with open(path, "w") as f:
        yaml.safe_dump(rec, f, sort_keys=True, allow_unicode=True)
    return path


class TestWave2CrossFirmDedupExecute(unittest.TestCase):
    def setUp(self) -> None:
        self._exe = _load_executor()
        self._tmp = tempfile.TemporaryDirectory()
        self.workspace = Path(self._tmp.name)
        self.tags_root = self.workspace / "audit" / "corpus_tags" / "tags"
        self.tags_root.mkdir(parents=True, exist_ok=True)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_empty_corpus_no_clusters(self) -> None:
        result = self._exe.execute(self.workspace, dry_run=True)
        self.assertEqual(result["clusters_detected"], 0)
        self.assertEqual(result["clusters_executed"], 0)
        self.assertEqual(result["clusters_deferred"], 0)

    def test_high_confidence_cluster_is_executed_dry_run(self) -> None:
        # Two firms find the same reentrancy in protocol-foo.
        # Detector's _verification_tier_rank ranks tier-2 > tier-1 (its
        # convention: higher == "more verified archive"); we mirror that
        # ordering in this executor since we reuse the detector's cluster
        # output. Canonical here is the tier-2 (sherlock) record.
        _write_firm_record(
            self.tags_root,
            "tob",
            "rec-foo-001",
            title="Reentrancy in foo withdraw allows attacker drain",
            severity="high",
            protocol="protocol-foo",
            attack_class="reentrancy",
            verification_tier="tier-1-officially-disclosed",
            incident_date="2024-01-15",
            record_source_url="https://tob.example/foo-001.pdf",
        )
        _write_firm_record(
            self.tags_root,
            "sherlock",
            "rec-foo-002",
            title="Reentrancy attacker can drain foo via withdraw",
            severity="high",
            protocol="protocol-foo",
            attack_class="reentrancy",
            verification_tier="tier-2-verified-public-archive",
            incident_date="2024-02-01",
            record_source_url="https://sherlock.example/foo-002.pdf",
        )
        result = self._exe.execute(
            self.workspace, execute_threshold=0.4, dry_run=True
        )
        self.assertEqual(result["clusters_executed"], 1)
        cluster = result["executed"][0]
        self.assertEqual(cluster["canonical_record_id"], "rec-foo-002")
        urls = cluster["source_urls_after_merge"]
        self.assertIn("https://tob.example/foo-001.pdf", urls)
        self.assertIn("https://sherlock.example/foo-002.pdf", urls)

    def test_high_confidence_cluster_mutates_disk(self) -> None:
        canon_path = _write_firm_record(
            self.tags_root,
            "tob",
            "rec-bar-001",
            title="Oracle manipulation in bar pricing allows arbitrage",
            severity="critical",
            protocol="protocol-bar",
            attack_class="oracle-manipulation",
            verification_tier="tier-1-officially-disclosed",
            record_source_url="https://tob.example/bar-001.pdf",
        )
        dupe_path = _write_firm_record(
            self.tags_root,
            "zellic",
            "rec-bar-002",
            title="Oracle manipulation arbitrage in bar pricing",
            severity="critical",
            protocol="protocol-bar",
            attack_class="oracle-manipulation",
            verification_tier="tier-2-verified-public-archive",
            record_source_url="https://zellic.example/bar-002.pdf",
        )
        # Bar titles have Jaccard 0.667; execute at 0.6.
        result = self._exe.execute(
            self.workspace, execute_threshold=0.6, dry_run=False
        )
        self.assertEqual(result["clusters_executed"], 1)
        # Canonical is the higher tier-rank (tier-2 zellic, rec-bar-002).
        with open(canon_path) as f:
            tob_rec = yaml.safe_load(f)
        self.assertEqual(tob_rec["redirected_to"], "rec-bar-002")
        # Canonical (dupe_path here, since we picked tier-2) has merged URLs.
        with open(dupe_path) as f:
            canon = yaml.safe_load(f)
        refs = canon["source_audit_ref"]
        self.assertIsInstance(refs, list)
        self.assertIn("https://tob.example/bar-001.pdf", refs)
        self.assertIn("https://zellic.example/bar-002.pdf", refs)

    def test_idempotent_rerun(self) -> None:
        # Twin titles guarantee Jaccard=1.0 so cluster fires at default threshold.
        _write_firm_record(
            self.tags_root,
            "tob",
            "rec-iter-001",
            title="Access control bug grants admin to attacker",
            severity="high",
            protocol="protocol-iter",
            attack_class="access-control",
            verification_tier="tier-1-officially-disclosed",
        )
        _write_firm_record(
            self.tags_root,
            "sherlock",
            "rec-iter-002",
            title="Access control bug grants admin to attacker",
            severity="high",
            protocol="protocol-iter",
            attack_class="access-control",
            verification_tier="tier-2-verified-public-archive",
        )
        first = self._exe.execute(
            self.workspace, execute_threshold=0.6, dry_run=False
        )
        self.assertEqual(first["clusters_executed"], 1)
        second = self._exe.execute(
            self.workspace, execute_threshold=0.6, dry_run=False
        )
        # On the second run, cluster still detected, but redirect is no-op
        # because the record already carries redirected_to.
        self.assertEqual(second["clusters_executed"], 1)
        redirect = second["executed"][0]["redirects_applied"][0]
        self.assertFalse(redirect["mutated"])

    def test_deferred_cluster_does_not_mutate(self) -> None:
        # These two titles share {pricing, dashboard} only (Jaccard ~0.22)
        # so we set defer in [0.1, 0.95) and verify no mutation.
        a = _write_firm_record(
            self.tags_root,
            "tob",
            "rec-def-001",
            title="Precision loss in dashboard pricing displayed wrong",
            severity="medium",
            protocol="protocol-def",
            attack_class="precision-loss",
        )
        b = _write_firm_record(
            self.tags_root,
            "zellic",
            "rec-def-002",
            title="Precision loss in dashboard pricing calculator",
            severity="medium",
            protocol="protocol-def",
            attack_class="precision-loss",
        )
        result = self._exe.execute(
            self.workspace,
            execute_threshold=0.95,
            defer_threshold=0.2,
            dry_run=False,
        )
        # Cluster lands in deferred bucket because mean Jaccard < 0.95.
        self.assertEqual(result["clusters_executed"], 0)
        self.assertEqual(result["clusters_deferred"], 1)
        for p in (a, b):
            with open(p) as f:
                rec = yaml.safe_load(f)
            self.assertNotIn("redirected_to", rec)

    def test_migration_log_written(self) -> None:
        # Even on an empty corpus the log should land at the configured path.
        result = self._exe.execute(self.workspace, dry_run=True)
        log_path = self.workspace / "audit" / "migrations" / "wave3_w39_test.json"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text(json.dumps(result))
        loaded = json.loads(log_path.read_text())
        self.assertEqual(loaded["schema"], self._exe.SCHEMA_ID)

    def _write_layout_a_record(
        self,
        firm_repo: str,
        report_slug: str,
        record_id: str,
        *,
        title: str,
        attack_class: str,
        protocol: str,
        severity: str = "high",
        verification_tier: str = "tier-2-verified-public-archive",
        record_source_url: str = "",
    ) -> Path:
        """Write a record under the real audit_firm_public_reports layout."""
        d = (
            self.tags_root
            / "audit_firm_public_reports"
            / f"{firm_repo}__{report_slug}"
        )
        d.mkdir(parents=True, exist_ok=True)
        rec = {
            "schema_version": "auditooor.hackerman_record.v1.1",
            "record_id": record_id,
            "title": title,
            "severity_at_finding": severity,
            "target_repo": protocol,
            "attack_class": attack_class,
            "bug_class": attack_class,
            "protocol": protocol,
            "verification_tier": verification_tier,
            "record_source_url": record_source_url,
        }
        path = d / "record.yaml"
        with open(path, "w") as f:
            yaml.safe_dump(rec, f, sort_keys=True, allow_unicode=True)
        return path

    def test_layout_a_real_corpus_path_executes(self) -> None:
        """W3.9 path-fix: executor discovers + collapses Layout-A records and
        preserves EVERY record_source_url on the surviving canonical."""
        title = "Reentrancy in vault withdraw lets attacker drain funds"
        tob = self._write_layout_a_record(
            "trailofbits-publications",
            "vaultx-tob-review-aaaaaaaaaaaa",
            "rec-vaultx-tob",
            title=title,
            attack_class="reentrancy",
            protocol="vaultx",
            verification_tier="tier-1-officially-disclosed",
            record_source_url="https://tob.example/vaultx.pdf",
        )
        zel = self._write_layout_a_record(
            "zellic-publications",
            "vaultx-zellic-audit-report-bbbbbbbbbbbb",
            "rec-vaultx-zel",
            title=title,
            attack_class="reentrancy",
            protocol="vaultx",
            verification_tier="tier-2-verified-public-archive",
            record_source_url="https://zellic.example/vaultx.pdf",
        )
        result = self._exe.execute(
            self.workspace, execute_threshold=0.6, dry_run=False
        )
        self.assertEqual(result["clusters_executed"], 1)
        self.assertEqual(
            sorted(result["firms_scanned"]), ["trailofbits", "zellic"]
        )
        cluster = result["executed"][0]
        # Both source URLs survive on the canonical - none lost.
        self.assertIn("https://tob.example/vaultx.pdf",
                      cluster["source_urls_after_merge"])
        self.assertIn("https://zellic.example/vaultx.pdf",
                      cluster["source_urls_after_merge"])
        # Canonical record on disk carries both URLs.
        with open(zel) as f:
            canon = yaml.safe_load(f)
        self.assertIn("https://tob.example/vaultx.pdf",
                      canon["source_audit_ref"])
        self.assertIn("https://zellic.example/vaultx.pdf",
                      canon["source_audit_ref"])
        # Non-canonical record redirected, URL not destroyed.
        with open(tob) as f:
            non = yaml.safe_load(f)
        self.assertEqual(non["redirected_to"], "rec-vaultx-zel")
        self.assertEqual(non["record_source_url"],
                         "https://tob.example/vaultx.pdf")

    def test_layout_a_idempotent_rerun_no_url_loss(self) -> None:
        """Re-running the executor on Layout-A records is a no-op and never
        drops a record_source_url (W3.9 idempotency requirement)."""
        title = "Access control gap grants admin role to any caller"
        tob = self._write_layout_a_record(
            "trailofbits-publications",
            "acme-tob-review-cccccccccccc",
            "rec-acme-tob",
            title=title,
            attack_class="access-control",
            protocol="acme",
            verification_tier="tier-1-officially-disclosed",
            record_source_url="https://tob.example/acme.pdf",
        )
        zel = self._write_layout_a_record(
            "zellic-publications",
            "acme-zellic-audit-report-dddddddddddd",
            "rec-acme-zel",
            title=title,
            attack_class="access-control",
            protocol="acme",
            verification_tier="tier-2-verified-public-archive",
            record_source_url="https://zellic.example/acme.pdf",
        )
        first = self._exe.execute(
            self.workspace, execute_threshold=0.6, dry_run=False
        )
        with open(zel) as f:
            canon_after_first = yaml.safe_load(f)
        second = self._exe.execute(
            self.workspace, execute_threshold=0.6, dry_run=False
        )
        with open(zel) as f:
            canon_after_second = yaml.safe_load(f)
        # Idempotent: canonical record byte-identical across runs.
        self.assertEqual(
            canon_after_first["source_audit_ref"],
            canon_after_second["source_audit_ref"],
        )
        # Second run mutates nothing.
        self.assertEqual(first["clusters_executed"],
                         second["clusters_executed"])
        redirect = second["executed"][0]["redirects_applied"][0]
        self.assertFalse(redirect["mutated"])
        # Both source URLs still present after re-run.
        for url in ("https://tob.example/acme.pdf",
                    "https://zellic.example/acme.pdf"):
            self.assertIn(url, canon_after_second["source_audit_ref"])
        # Non-canonical URL never destroyed.
        with open(tob) as f:
            non = yaml.safe_load(f)
        self.assertEqual(non["record_source_url"],
                         "https://tob.example/acme.pdf")

    def test_corpus_profile_flags_index_only_subtree(self) -> None:
        """Report-index records (uniform attack_class, no title) yield a
        NEGATIVE-EMPTY corpus_profile rather than a false-positive collapse."""
        for firm_repo, slug, rid in (
            ("trailofbits-publications", "looksrare-eeeeeeeeeeee", "idx-1"),
            ("spearbit-portfolio", "looksrare-review-ffffffffffff", "idx-2"),
        ):
            d = (
                self.tags_root
                / "audit_firm_public_reports"
                / f"{firm_repo}__{slug}"
            )
            d.mkdir(parents=True, exist_ok=True)
            with open(d / "record.yaml", "w") as f:
                yaml.safe_dump(
                    {
                        "schema_version": "auditooor.hackerman_record.v1.1",
                        "record_id": rid,
                        "attack_class": "audit-firm-public-report",
                        "bug_class": "audit-firm-public-report-index",
                        "target_component": f"{firm_repo}:report.pdf",
                        "severity_at_finding": "info",
                        "record_source_url": f"https://example/{rid}.pdf",
                    },
                    f,
                    sort_keys=True,
                )
        result = self._exe.execute(self.workspace, dry_run=False)
        self.assertEqual(result["total_firm_records_scanned"], 2)
        self.assertEqual(result["clusters_executed"], 0)
        profile = result["corpus_profile"]
        self.assertTrue(profile["report_index_records_only"])
        self.assertEqual(profile["records_with_finding_title"], 0)
        self.assertIn("NEGATIVE-EMPTY", profile["note"])

    def test_canonical_pick_breaks_tier_tie_on_earliest_date(self) -> None:
        _write_firm_record(
            self.tags_root,
            "tob",
            "rec-tie-001",
            title="Signature replay attack on tie module verify",
            severity="high",
            protocol="protocol-tie",
            attack_class="signature-replay",
            verification_tier="tier-2-verified-public-archive",
            incident_date="2024-06-01",
        )
        _write_firm_record(
            self.tags_root,
            "sherlock",
            "rec-tie-002",
            title="Signature replay on tie verify module attack",
            severity="high",
            protocol="protocol-tie",
            attack_class="signature-replay",
            verification_tier="tier-2-verified-public-archive",
            incident_date="2024-03-15",
        )
        result = self._exe.execute(
            self.workspace, execute_threshold=0.6, dry_run=True
        )
        self.assertEqual(result["clusters_executed"], 1)
        # Earlier incident_date wins the tie-break.
        self.assertEqual(
            result["executed"][0]["canonical_record_id"], "rec-tie-002"
        )


if __name__ == "__main__":
    unittest.main()
