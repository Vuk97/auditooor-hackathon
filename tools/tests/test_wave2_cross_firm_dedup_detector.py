"""Tests for ``tools/wave2-cross-firm-dedup-detector.py``.

Coverage (>=6 cases per task brief):

1.  PASS: no overlapping records -> cluster_count=0, status PASS.
2.  INFO: two records same firm-pair high Jaccard -> 1 cluster of 2.
3.  INFO: three records same firm-trio (multi-firm cluster) -> 1 cluster
    of 3, firms_involved has 3 entries.
4.  Below-threshold (Jaccard 0.55 < 0.6) does NOT cluster.
5.  Different attack_class blocks clustering even if titles similar.
6.  Records with severity mismatch are blocked from clustering.
7.  Synthetic-fixture records mark the cluster as
    ``synthetic_fixture_only`` so downstream consumers can filter.
8.  recommended_canonical picks highest verification_tier and breaks
    ties by earliest incident_date.
9.  ``--firms`` filter restricts scan to listed firms (records from
    other firms are excluded from clustering).
10. CLI ``--json`` end-to-end run on a synthetic fixture tree emits a
    well-formed payload with the expected schema id.
"""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, Dict

try:
    import yaml  # type: ignore
except ImportError:  # pragma: no cover
    raise SystemExit("PyYAML required for the cross-firm dedup detector tests")


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "wave2-cross-firm-dedup-detector.py"


def _load_tool() -> Any:
    spec = importlib.util.spec_from_file_location(
        "_wave2_cross_firm_dedup_detector_test_mod", str(TOOL_PATH)
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules["_wave2_cross_firm_dedup_detector_test_mod"] = mod
    spec.loader.exec_module(mod)
    return mod


tool = _load_tool()


def _write_record(
    tags_root: Path,
    firm: str,
    protocol_slug: str,
    finding_id: str,
    body: Dict[str, Any],
) -> Path:
    rec_dir = (
        tags_root / f"firm-{firm}-audits" / protocol_slug
    )
    rec_dir.mkdir(parents=True, exist_ok=True)
    path = rec_dir / f"{finding_id}.yaml"
    path.write_text(yaml.safe_dump(body, sort_keys=True), encoding="utf-8")
    return path


def _make_record(
    *,
    record_id: str,
    title: str,
    attack_class: str = "reentrancy",
    severity: str = "high",
    protocol: str = "morpho-v1",
    verification_tier: str = "tier-2-verified-public-archive",
    incident_date: str = "2024-06-01",
    synthetic: bool = True,
) -> Dict[str, Any]:
    return {
        "schema_version": "auditooor.hackerman_record.v1",
        "record_id": record_id,
        "title": title,
        "attack_class": attack_class,
        "bug_family": "reentrancy",
        "severity_at_finding": severity,
        "protocol": protocol,
        "verification_tier": verification_tier,
        "incident_date": incident_date,
        "record_source_url": f"https://example/{record_id}.pdf",
        "record_extensions": {"synthetic_fixture": synthetic},
    }


class TitleKeywordsTest(unittest.TestCase):
    def test_strips_stopwords_and_punct(self) -> None:
        toks = tool._title_keywords(
            "Reentrancy in the supply hook of MorphoVault, allowing draining."
        )
        # Lowercased, stopwords removed, top-5 unique.
        self.assertEqual(
            toks[:3],
            ("reentrancy", "supply", "hook"),
        )
        self.assertLessEqual(len(toks), 5)
        self.assertNotIn("the", toks)
        self.assertNotIn("in", toks)

    def test_empty_title(self) -> None:
        self.assertEqual(tool._title_keywords(""), ())
        self.assertEqual(tool._title_keywords(None), ())


class SeverityNormaliseTest(unittest.TestCase):
    def test_variants(self) -> None:
        self.assertEqual(tool._normalise_severity("Critical"), "critical")
        self.assertEqual(tool._normalise_severity("crit"), "critical")
        self.assertEqual(tool._normalise_severity("HIGH"), "high")
        self.assertEqual(tool._normalise_severity("Medium"), "medium")
        self.assertEqual(tool._normalise_severity("med"), "medium")
        self.assertEqual(tool._normalise_severity("informational"), "informational")
        self.assertEqual(tool._normalise_severity("Info"), "informational")
        self.assertEqual(tool._normalise_severity(""), "")
        self.assertEqual(tool._normalise_severity(None), "")


class DetectorTest(unittest.TestCase):
    def _run(
        self,
        records: list,
        *,
        min_similarity: float = 0.6,
        min_cluster_size: int = 2,
        firms_filter=None,
    ) -> Dict[str, Any]:
        with tempfile.TemporaryDirectory() as td:
            workspace = Path(td)
            tags_root = workspace / "audit" / "corpus_tags" / "tags"
            tags_root.mkdir(parents=True)
            for firm, slug, fid, body in records:
                _write_record(tags_root, firm, slug, fid, body)
            return tool.run_detect(
                workspace,
                min_similarity=min_similarity,
                min_cluster_size=min_cluster_size,
                firms_filter=firms_filter,
            )

    def test_case_01_pass_no_overlap(self) -> None:
        """No overlapping records -> cluster_count=0, status PASS."""
        records = [
            (
                "cyfrin",
                "morpho-v1",
                "C-1",
                _make_record(
                    record_id="cy-1",
                    title="Reentrancy in supply hook of MorphoVault",
                ),
            ),
            (
                "tob",
                "polygon-zkevm",
                "TOB-2",
                _make_record(
                    record_id="tob-1",
                    title="Integer overflow in fee collector",
                    attack_class="integer-overflow",
                    protocol="polygon-zkevm",
                ),
            ),
        ]
        out = self._run(records)
        self.assertEqual(out["cluster_count"], 0)
        self.assertEqual(out["overall_status"], "PASS")
        self.assertEqual(out["total_firm_records_scanned"], 2)
        self.assertEqual(out["firms_scanned"], ["cyfrin", "tob"])

    def test_case_02_info_two_firms_high_jaccard(self) -> None:
        """Two records same firm-pair high Jaccard -> 1 cluster of 2."""
        # Title keywords identical -> Jaccard 1.0.
        rec_a = _make_record(
            record_id="cy-1",
            title="Reentrancy in supply hook of MorphoVault allowing draining",
        )
        rec_b = _make_record(
            record_id="tob-1",
            title="Reentrancy in supply hook of MorphoVault allowing draining",
        )
        out = self._run(
            [
                ("cyfrin", "morpho-v1", "C-1", rec_a),
                ("tob", "morpho-v1", "TOB-1", rec_b),
            ]
        )
        self.assertEqual(out["cluster_count"], 1)
        self.assertEqual(out["overall_status"], "INFO")
        c = out["clusters"][0]
        self.assertEqual(c["cluster_size"], 2)
        self.assertEqual(c["firms_involved"], ["cyfrin", "tob"])
        self.assertGreaterEqual(c["similarity_score"], 0.99)
        # firm_intersection_matrix has the pair.
        self.assertIn("cyfrin__x__tob", out["firm_intersection_matrix"])
        self.assertEqual(out["firm_intersection_matrix"]["cyfrin__x__tob"], 1)
        # total_estimated_dupes = cluster_size - 1.
        self.assertEqual(out["total_estimated_dupes"], 1)

    def test_case_03_info_three_firms_trio_cluster(self) -> None:
        """Three records same firm-trio -> 1 cluster of 3, 3 firms."""
        title = "Reentrancy in supply hook of MorphoVault allowing draining"
        recs = [
            ("cyfrin", "morpho-v1", "C-1", _make_record(record_id="cy-1", title=title)),
            ("tob", "morpho-v1", "TOB-1", _make_record(record_id="tob-1", title=title)),
            (
                "spearbit",
                "morpho-v1",
                "SP-1",
                _make_record(record_id="sp-1", title=title),
            ),
        ]
        out = self._run(recs)
        self.assertEqual(out["cluster_count"], 1)
        c = out["clusters"][0]
        self.assertEqual(c["cluster_size"], 3)
        self.assertEqual(c["firms_involved"], ["cyfrin", "spearbit", "tob"])
        self.assertEqual(out["total_estimated_dupes"], 2)

    def test_case_04_below_threshold_does_not_cluster(self) -> None:
        """Jaccard ~0.5 with default 0.6 threshold -> no cluster."""
        # Token sets: {alpha, beta} vs {alpha, gamma} -> Jaccard 1/3 ~ 0.33.
        rec_a = _make_record(record_id="cy-1", title="alpha beta finding")
        rec_b = _make_record(record_id="tob-1", title="alpha gamma finding")
        out = self._run(
            [
                ("cyfrin", "morpho-v1", "C-1", rec_a),
                ("tob", "morpho-v1", "TOB-1", rec_b),
            ]
        )
        self.assertEqual(out["cluster_count"], 0)
        self.assertEqual(out["overall_status"], "PASS")

    def test_case_05_diff_attack_class_blocks_clustering(self) -> None:
        """Same titles, same protocol, but different attack_class -> no cluster."""
        rec_a = _make_record(
            record_id="cy-1",
            title="Reentrancy in supply hook of MorphoVault",
            attack_class="reentrancy",
        )
        rec_b = _make_record(
            record_id="tob-1",
            title="Reentrancy in supply hook of MorphoVault",
            attack_class="oracle-manipulation",
        )
        out = self._run(
            [
                ("cyfrin", "morpho-v1", "C-1", rec_a),
                ("tob", "morpho-v1", "TOB-1", rec_b),
            ]
        )
        self.assertEqual(out["cluster_count"], 0)

    def test_case_06_severity_mismatch_blocks_clustering(self) -> None:
        """Same titles + attack_class + protocol but different severity -> no cluster."""
        title = "Reentrancy in supply hook of MorphoVault allowing draining"
        rec_a = _make_record(record_id="cy-1", title=title, severity="critical")
        rec_b = _make_record(record_id="tob-1", title=title, severity="medium")
        out = self._run(
            [
                ("cyfrin", "morpho-v1", "C-1", rec_a),
                ("tob", "morpho-v1", "TOB-1", rec_b),
            ]
        )
        self.assertEqual(out["cluster_count"], 0)

    def test_case_07_synthetic_only_cluster_flagged(self) -> None:
        title = "Reentrancy in supply hook of MorphoVault allowing draining"
        rec_a = _make_record(record_id="cy-1", title=title, synthetic=True)
        rec_b = _make_record(record_id="tob-1", title=title, synthetic=True)
        out = self._run(
            [
                ("cyfrin", "morpho-v1", "C-1", rec_a),
                ("tob", "morpho-v1", "TOB-1", rec_b),
            ]
        )
        self.assertEqual(out["cluster_count"], 1)
        self.assertTrue(out["clusters"][0]["synthetic_fixture_only"])

    def test_case_08_canonical_highest_tier_then_earliest_date(self) -> None:
        title = "Reentrancy in supply hook of MorphoVault allowing draining"
        # rec_a: tier-1, rec_b: tier-2, rec_c: tier-2 earlier date.
        rec_a = _make_record(
            record_id="cy-1",
            title=title,
            verification_tier="tier-1-public-archive",
            incident_date="2023-01-01",
        )
        rec_b = _make_record(
            record_id="tob-1",
            title=title,
            verification_tier="tier-2-verified-public-archive",
            incident_date="2024-06-01",
        )
        rec_c = _make_record(
            record_id="sp-1",
            title=title,
            verification_tier="tier-2-verified-public-archive",
            incident_date="2024-01-01",
        )
        out = self._run(
            [
                ("cyfrin", "morpho-v1", "C-1", rec_a),
                ("tob", "morpho-v1", "TOB-1", rec_b),
                ("spearbit", "morpho-v1", "SP-1", rec_c),
            ]
        )
        self.assertEqual(out["cluster_count"], 1)
        canon = out["clusters"][0]["recommended_canonical"]
        # Tier-2 wins over tier-1; earliest date (2024-01-01) wins among tier-2.
        self.assertEqual(canon["record_id"], "sp-1")
        self.assertEqual(canon["firm"], "spearbit")

    def test_case_09_firms_filter_restricts_scan(self) -> None:
        title = "Reentrancy in supply hook of MorphoVault allowing draining"
        recs = [
            ("cyfrin", "morpho-v1", "C-1", _make_record(record_id="cy-1", title=title)),
            ("tob", "morpho-v1", "TOB-1", _make_record(record_id="tob-1", title=title)),
            (
                "spearbit",
                "morpho-v1",
                "SP-1",
                _make_record(record_id="sp-1", title=title),
            ),
        ]
        # Filter to {cyfrin, tob}; spearbit must be excluded.
        out = self._run(recs, firms_filter={"cyfrin", "tob"})
        self.assertEqual(out["firms_scanned"], ["cyfrin", "tob"])
        self.assertEqual(out["cluster_count"], 1)
        c = out["clusters"][0]
        self.assertEqual(c["cluster_size"], 2)
        self.assertEqual(c["firms_involved"], ["cyfrin", "tob"])

    def test_case_10_cli_end_to_end_json(self) -> None:
        title = "Reentrancy in supply hook of MorphoVault allowing draining"
        with tempfile.TemporaryDirectory() as td:
            workspace = Path(td)
            tags_root = workspace / "audit" / "corpus_tags" / "tags"
            tags_root.mkdir(parents=True)
            _write_record(
                tags_root,
                "cyfrin",
                "morpho-v1",
                "C-1",
                _make_record(record_id="cy-1", title=title),
            )
            _write_record(
                tags_root,
                "tob",
                "morpho-v1",
                "TOB-1",
                _make_record(record_id="tob-1", title=title),
            )
            result = subprocess.run(
                [
                    sys.executable,
                    str(TOOL_PATH),
                    "--workspace",
                    str(workspace),
                    "--json",
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            payload = json.loads(result.stdout)
            self.assertEqual(
                payload["schema"], "auditooor.wave2_cross_firm_dedup_detector.v1"
            )
            self.assertEqual(payload["cluster_count"], 1)
            self.assertEqual(payload["overall_status"], "INFO")
            self.assertEqual(payload["total_firm_records_scanned"], 2)
            self.assertEqual(payload["firms_scanned"], ["cyfrin", "tob"])

    def test_case_11_empty_corpus_pass(self) -> None:
        """Live-corpus-style: 0 firm records on disk -> PASS."""
        with tempfile.TemporaryDirectory() as td:
            workspace = Path(td)
            # No audit/corpus_tags/tags at all.
            out = tool.run_detect(workspace)
            self.assertEqual(out["cluster_count"], 0)
            self.assertEqual(out["total_firm_records_scanned"], 0)
            self.assertEqual(out["firms_scanned"], [])
            self.assertEqual(out["overall_status"], "PASS")

    def test_case_13_real_corpus_layout_a_discovered(self) -> None:
        """W3.9 path-fix: records under audit_firm_public_reports/<firm>__<slug>/
        record.yaml are discovered (legacy firm-*-audits/ glob missed them)."""
        title = "Reentrancy in supply hook of MorphoVault allowing draining"
        with tempfile.TemporaryDirectory() as td:
            workspace = Path(td)
            tags_root = workspace / "audit" / "corpus_tags" / "tags"
            reports = tags_root / "audit_firm_public_reports"
            for firm_dir, rid in (
                ("trailofbits-publications__morpho-tob-review-aaaaaaaaaaaa",
                 "tob-1"),
                ("pashov-audits__morpho-security-review-bbbbbbbbbbbb",
                 "pa-1"),
            ):
                d = reports / firm_dir
                d.mkdir(parents=True)
                (d / "record.yaml").write_text(
                    yaml.safe_dump(
                        _make_record(record_id=rid, title=title),
                        sort_keys=True,
                    ),
                    encoding="utf-8",
                )
            out = tool.run_detect(workspace)
            # Both records discovered; firm slugs canonicalised.
            self.assertEqual(out["total_firm_records_scanned"], 2)
            self.assertEqual(out["firms_scanned"], ["pashov", "trailofbits"])
            # Same protocol + attack_class + title -> 1 cross-firm cluster.
            self.assertEqual(out["cluster_count"], 1)
            self.assertEqual(
                out["clusters"][0]["firms_involved"],
                ["pashov", "trailofbits"],
            )

    def test_case_14_firm_slug_canonicalised(self) -> None:
        """Firm-publication-repo suffixes collapse to canonical slugs."""
        self.assertEqual(
            tool._canonical_firm_slug("trailofbits-publications"),
            "trailofbits",
        )
        self.assertEqual(
            tool._canonical_firm_slug("cyfrin-audit-reports"), "cyfrin"
        )
        self.assertEqual(
            tool._canonical_firm_slug("openzeppelin-contracts-audits"),
            "openzeppelin",
        )
        self.assertEqual(tool._canonical_firm_slug("pashov-audits"), "pashov")
        self.assertEqual(
            tool._canonical_firm_slug("spearbit-portfolio"), "spearbit"
        )

    def test_case_15_firm_from_path_layout_a(self) -> None:
        """_firm_from_path extracts firm from audit_firm_public_reports layout."""
        p = Path(
            "audit/corpus_tags/tags/audit_firm_public_reports/"
            "zellic-publications__chainflip-solana-zellic-audit-report-deadbeef/"
            "record.yaml"
        )
        self.assertEqual(tool._firm_from_path(p), "zellic")

    def test_case_12_warning_status_above_ten_clusters(self) -> None:
        """>10 clusters -> WARNING."""
        records = []
        for i in range(12):
            title = f"reentrancy supply hook morpho dup{i}"
            # Each pair shares 3 tokens (reentrancy / supply / hook); 5 token cap
            # set including dupN gives Jaccard >= 0.6 within the pair.
            rec_a = _make_record(
                record_id=f"cy-{i}",
                title=title,
                protocol=f"morpho-v1-{i}",  # different protocol per pair
            )
            rec_b = _make_record(
                record_id=f"tob-{i}",
                title=title,
                protocol=f"morpho-v1-{i}",
            )
            records.append(("cyfrin", f"proto-{i}", f"C-{i}", rec_a))
            records.append(("tob", f"proto-{i}", f"TOB-{i}", rec_b))
        out = self._run(records)
        self.assertGreater(out["cluster_count"], 10)
        self.assertEqual(out["overall_status"], "WARNING")


if __name__ == "__main__":
    unittest.main()
