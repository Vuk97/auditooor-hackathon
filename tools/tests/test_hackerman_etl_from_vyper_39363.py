"""Tests for tools/hackerman-etl-from-vyper-39363.py.

This miner is the NVD/GHSA-anchored rebuild that replaces the quarantined
Wave-3b Vyper-CVE miner. The tests below pin the verified facts (advisory
ID, affected versions, fix version, absence of the six known-fabricated
CVE IDs) so the rebuild can not silently regress to the Wave-3b
fabrication pattern.
"""
from __future__ import annotations

import importlib.util
import json
import re
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "hackerman-etl-from-vyper-39363.py"
VALIDATOR_PATH = REPO_ROOT / "tools" / "hackerman-record-validate.py"


# Six CVE IDs the Wave-3b miner fabricated. Re-asserted here so no
# record in the rebuild references any of them.
FABRICATED_CVE_IDS_SHOULD_NOT_APPEAR = (
    "CVE-2022-37937",
    "CVE-2023-32674",
    "CVE-2023-30547",
    "CVE-2024-22417",
    "CVE-2024-24563",
    "CVE-2023-46247",
)

# Real verified facts (NVD + GHSA queries on 2026-05-15).
REAL_ADVISORY_CVE = "CVE-2023-39363"
REAL_ADVISORY_GHSA = "GHSA-5824-cm3x-3c38"
REAL_AFFECTED_VERSIONS = ["0.2.15", "0.2.16", "0.3.0"]
REAL_FIX_VERSION = "0.3.1"

# GHSA summary keyword set (sourced verbatim from
# https://api.github.com/advisories/GHSA-5824-cm3x-3c38 summary field).
REAL_GHSA_SUMMARY_KEYWORDS = (
    "named",
    "re-entrancy",
    "lock",
    "allocated",
)


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


class HackermanEtlFromVyper39363Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tool = _load(TOOL_PATH, "_hackerman_etl_from_vyper_39363")
        cls.validator = _load(VALIDATOR_PATH, "_validator_for_vyper_39363")

    # ------------------------------------------------------------------
    # Verified-source pinning.
    # ------------------------------------------------------------------
    def test_attack_class_matches_real_ghsa_advisory(self) -> None:
        """Attack class text must align with the real GHSA-5824-cm3x-3c38 summary
        ("Vyper has incorrectly allocated named re-entrancy locks"),
        not the fabricated Wave-3b
        "vyper-compiler-saturating-arithmetic-reentrancy" narrative.
        """
        attack_class = self.tool.ATTACK_CLASS.lower()
        self.assertIn("reentrancy", attack_class)
        self.assertIn("lock", attack_class)
        self.assertIn("vyper", attack_class)
        self.assertIn("named", attack_class)
        # The Wave-3b fabricated bug-class narrative must NOT appear.
        self.assertNotIn("saturating", attack_class)
        self.assertNotIn("arithmetic", attack_class)

        # Records must individually carry the real attack class.
        records = self.tool.build_all_records()
        self.assertGreater(len(records), 0)
        for rec in records:
            self.assertEqual(rec["attack_class"], self.tool.ATTACK_CLASS)

        # The advisory summary must appear verbatim somewhere in the
        # module's comment / docstring so manual reviewers can re-verify
        # the source attribution.
        source = TOOL_PATH.read_text(encoding="utf-8")
        for keyword in REAL_GHSA_SUMMARY_KEYWORDS:
            self.assertIn(
                keyword, source.lower(),
                f"miner source missing GHSA summary keyword {keyword!r}",
            )

    def test_affected_versions_match_nvd(self) -> None:
        """Affected versions list must be EXACTLY the three NVD CPE entries."""
        self.assertEqual(
            self.tool.AFFECTED_VERSIONS,
            REAL_AFFECTED_VERSIONS,
        )
        # Records must record one of the three affected versions in their
        # preconditions / shape tags.
        records = self.tool.build_all_records()
        version_strs = set(REAL_AFFECTED_VERSIONS)
        for rec in records:
            text_blob = " ".join(
                str(p) for p in rec["required_preconditions"]
            ) + " " + " ".join(rec["function_shape"]["shape_tags"])
            self.assertTrue(
                any(v in text_blob for v in version_strs),
                f"record {rec['record_id']} does not mention any of "
                f"the real affected versions {version_strs}",
            )

    def test_fix_version_matches_real_release(self) -> None:
        """Fix version must be exactly Vyper 0.3.1 (verbatim from GHSA
        first_patched_version)."""
        self.assertEqual(self.tool.FIX_VERSION, REAL_FIX_VERSION)
        records = self.tool.build_all_records()
        for rec in records:
            # Either the preconditions or the fix_pattern must cite
            # the real fix version.
            text_blob = (
                " ".join(str(p) for p in rec["required_preconditions"])
                + " "
                + str(rec.get("fix_pattern", ""))
            )
            self.assertIn(
                REAL_FIX_VERSION,
                text_blob,
                f"record {rec['record_id']} does not cite fix version "
                f"{REAL_FIX_VERSION}",
            )

    def test_no_fabricated_cve_ids(self) -> None:
        """No record may reference any of the six known-fabricated CVE IDs."""
        records = self.tool.build_all_records()
        for rec in records:
            blob = json.dumps(rec, sort_keys=True)
            for bad_id in FABRICATED_CVE_IDS_SHOULD_NOT_APPEAR:
                self.assertNotIn(
                    bad_id,
                    blob,
                    f"record {rec['record_id']} references fabricated "
                    f"CVE ID {bad_id}",
                )
        # Tool module itself must not reference any of the six in a
        # record-emitting code path. Two intentional source mentions are
        # allowed per id: (a) the module docstring that explains the
        # quarantine context, and (b) the FABRICATED_CVE_IDS sentinel
        # tuple so this test module can import it. Anything beyond two
        # is a regression risk (e.g. a record field referencing the bad
        # ID by accident).
        source = TOOL_PATH.read_text(encoding="utf-8")
        for bad_id in FABRICATED_CVE_IDS_SHOULD_NOT_APPEAR:
            occurrences = source.count(bad_id)
            self.assertLessEqual(
                occurrences,
                2,
                f"miner source references {bad_id} {occurrences}x "
                f"(expected <=2: docstring + FABRICATED_CVE_IDS sentinel)",
            )

    # ------------------------------------------------------------------
    # Record-shape / structural correctness.
    # ------------------------------------------------------------------
    def test_three_mitigation_states_per_component(self) -> None:
        records = self.tool.build_all_records()
        # 5 pools + 4 downstream protocols = 9 components, each with 3
        # mitigation states = 27 records.
        pools = len(self.tool.CURVE_POOLS_AFFECTED)
        downstream = len(self.tool.DOWNSTREAM_PROTOCOLS_AFFECTED)
        self.assertEqual(len(records), 3 * (pools + downstream))

        states_seen_per_component: dict = {}
        for rec in records:
            parts = rec["source_audit_ref"].split(":")
            # parts[1] = advisory_slug, parts[-1] = state_slug,
            # everything in between identifies the component.
            comp_key = ":".join(parts[2:-1])
            states_seen_per_component.setdefault(comp_key, set()).add(parts[-1])
        for comp_key, states in states_seen_per_component.items():
            self.assertEqual(
                states,
                {"pre-fix", "post-fix-not-migrated", "post-fix-released"},
                f"component {comp_key} missing one of the three states",
            )

    def test_records_validate_against_v1_schema(self) -> None:
        records = self.tool.build_all_records()
        errors = self.tool.validate_records(records)
        self.assertEqual(errors, [], f"schema validation errors: {errors[:5]}")

    def test_record_ids_unique_and_pattern_safe(self) -> None:
        records = self.tool.build_all_records()
        ids = [rec["record_id"] for rec in records]
        self.assertEqual(len(ids), len(set(ids)), "record_ids must be unique")
        for rid in ids:
            self.assertRegex(rid, r"^[A-Za-z0-9._:/-]{8,160}$")

    def test_emitted_count_within_target_range(self) -> None:
        """Brief target: ~30-50 records. We emit 27 (5 pools + 4 protocols)
        x 3 states, which is the closest-honest-fit to that range given the
        verified-pool count from the Curve July 2023 incident. Test pins
        the count to the expected value so accidental seed-list growth is
        caught."""
        records = self.tool.build_all_records()
        # Allow >= 27 in case operator extends the seed in a future patch
        # but pin a hard upper bound that catches runaway fabrication.
        self.assertGreaterEqual(len(records), 27)
        self.assertLessEqual(len(records), 60)

    def test_reference_urls_all_https_and_canonical(self) -> None:
        # Every emitted record must indirectly trace back to the canonical
        # advisory; we assert the miner-level REFERENCE_URLS tuple includes
        # the NVD entry and the GHSA entry.
        self.assertIn(
            f"https://nvd.nist.gov/vuln/detail/{REAL_ADVISORY_CVE}",
            self.tool.REFERENCE_URLS,
        )
        self.assertIn(
            f"https://github.com/vyperlang/vyper/security/advisories/{REAL_ADVISORY_GHSA}",
            self.tool.REFERENCE_URLS,
        )
        for url in self.tool.REFERENCE_URLS:
            self.assertTrue(
                url.startswith("https://"),
                f"non-https reference url {url!r}",
            )

    def test_pre_fix_severity_critical_post_fix_walkback_only_on_released(self) -> None:
        """Severity discipline: pre-fix critical for the direct-pool records;
        post-fix-not-migrated keeps the same severity (live exposure
        persists); post-fix-released walks back one tier."""
        records = self.tool.build_all_records()
        by_ref = {rec["source_audit_ref"]: rec for rec in records}
        for pool in self.tool.CURVE_POOLS_AFFECTED:
            advisory_slug = self.tool.slugify(REAL_ADVISORY_CVE, max_len=24)
            pool_slug = self.tool.slugify(pool["pool_name"], max_len=60)
            addr_slug = self.tool.slugify(pool["pool_address"].lower(), max_len=42)
            prefix = f"vyper-39363:{advisory_slug}:{pool_slug}:{addr_slug}"
            pre = by_ref[f"{prefix}:pre-fix"]
            not_migrated = by_ref[f"{prefix}:post-fix-not-migrated"]
            released = by_ref[f"{prefix}:post-fix-released"]
            self.assertEqual(pre["severity_at_finding"], "critical")
            self.assertEqual(
                not_migrated["severity_at_finding"], "critical",
                "deployed-not-migrated still has live exposure",
            )
            self.assertEqual(released["severity_at_finding"], "high")

    def test_emits_files_to_dedicated_subdir(self) -> None:
        records = self.tool.build_all_records()
        with tempfile.TemporaryDirectory() as tmpdir:
            paths = self.tool.write_records(
                records, Path(tmpdir), dry_run=False
            )
            self.assertEqual(len(paths), len(records))
            for path in paths:
                self.assertTrue(path.exists())
                self.assertTrue(path.name.endswith(".yaml"))
                self.assertGreater(path.stat().st_size, 100)

    def test_output_dir_is_vyper_cve_2023_39363(self) -> None:
        """The miner emits into a dedicated tag dir distinct from the
        quarantined Wave-3b output dir (so the rebuild does not silently
        contaminate the quarantine boundary)."""
        out_dir = self.tool.DEFAULT_OUT_DIR
        self.assertTrue(str(out_dir).endswith("vyper_cve_2023_39363"))
        self.assertNotIn("_QUARANTINE_", str(out_dir))


if __name__ == "__main__":
    unittest.main()
