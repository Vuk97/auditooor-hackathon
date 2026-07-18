"""Tests for tools/hackerman-etl-from-l2-rollup-advisories.py.

These tests exercise the miner against a synthetic GHSA-shape cache so the
suite is hermetic (no live ``gh api`` calls). The cache mirrors the JSON
shape returned by ``gh api /repos/<owner>/<repo>/security-advisories`` for
real upstream L2/rollup repos -- field names match the live REST payload.
"""
from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from typing import Any, Dict, List


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "hackerman-etl-from-l2-rollup-advisories.py"
VALIDATOR_PATH = REPO_ROOT / "tools" / "hackerman-record-validate.py"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


def _synthetic_advisory(
    *,
    ghsa: str,
    severity: str = "medium",
    summary: str = "Test advisory summary",
    description: str = "Test advisory description.",
    cve: str = "",
    pkg: str = "test-pkg",
    patched: str = ">= 1.2.3",
    published: str = "2025-01-15T12:00:00Z",
    cwe: str = "",
) -> Dict[str, Any]:
    vulns: List[Dict[str, Any]] = [
        {
            "package": {"name": pkg, "ecosystem": "rust"},
            "vulnerable_version_range": "< 1.2.3",
            "patched_versions": patched,
        }
    ]
    payload: Dict[str, Any] = {
        "ghsa_id": ghsa,
        "cve_id": cve or None,
        "url": f"https://api.github.com/advisories/{ghsa}",
        "html_url": f"https://github.com/example/repo/security/advisories/{ghsa}",
        "summary": summary,
        "description": description,
        "severity": severity,
        "state": "published",
        "published_at": published,
        "updated_at": published,
        "vulnerabilities": vulns,
        "cwes": ([{"cwe_id": cwe, "name": cwe}] if cwe else []),
    }
    return payload


class HackermanEtlFromL2RollupAdvisoriesTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = _load(TOOL_PATH, "_hackerman_etl_from_l2_rollup_advisories")
        self.validator = _load(
            VALIDATOR_PATH, "_hackerman_record_validate_for_l2_rollup_advisories"
        )

    # ------------------------------------------------------------------
    # Target repo list is well-formed and covers all required orgs.
    # ------------------------------------------------------------------
    def test_target_repos_cover_required_orgs(self) -> None:
        repos = {repo for repo, _l, _d in self.tool.TARGET_REPOS}
        required_owners = {
            "ethereum-optimism",
            "OffchainLabs",
            "matter-labs",
            "base-org",
            "polygon-edge",
            "0xPolygonZero",
            "scroll-tech",
            "LineaXYZ",
            "starkware-libs",
            "taikoxyz",
        }
        owners = {r.split("/")[0] for r in repos}
        missing = required_owners - owners
        self.assertFalse(missing, f"missing required orgs: {missing}")

    def test_target_repos_have_valid_language_and_domain(self) -> None:
        schema = self.validator.load_schema()
        lang_enum = set(schema["properties"]["target_language"]["enum"])
        domain_enum = set(schema["properties"]["target_domain"]["enum"])
        for repo, lang, domain in self.tool.TARGET_REPOS:
            self.assertIn(lang, lang_enum, f"{repo}: bad language {lang}")
            self.assertIn(domain, domain_enum, f"{repo}: bad domain {domain}")

    # ------------------------------------------------------------------
    # Slug shape matches PR #726 task spec: <owner>__<repo>__<ghsa>.
    # ------------------------------------------------------------------
    def test_slug_shape_owner_repo_ghsa(self) -> None:
        advisory = _synthetic_advisory(ghsa="GHSA-abcd-efgh-ijkl")
        record = self.tool.advisory_to_record(
            "ethereum-optimism/optimism",
            "solidity",
            "rollup",
            advisory,
            "tier-1-ghsa-cache",
        )
        slug = self.tool.slug_for_record(record)
        self.assertIn("__", slug)
        parts = slug.split("__")
        self.assertEqual(len(parts), 3, slug)
        self.assertEqual(parts[0], "ethereum-optimism")
        self.assertEqual(parts[1], "optimism")
        self.assertTrue(parts[2].startswith("ghsa-"), parts[2])

    # ------------------------------------------------------------------
    # Cache replay: end-to-end with synthetic advisories per org.
    # ------------------------------------------------------------------
    def _write_cache(self, tmp: Path) -> Path:
        cache_payload: Dict[str, List[Dict[str, Any]]] = {
            "ethereum-optimism/optimism": [
                _synthetic_advisory(
                    ghsa="GHSA-0000-0000-op01",
                    severity="high",
                    summary="Withdrawal proof verification bypass",
                    description="Forged withdrawal merkle proof accepted by L1 portal.",
                    cve="CVE-2099-99991",
                    pkg="@eth-optimism/contracts-bedrock",
                ),
            ],
            "OffchainLabs/nitro": [
                _synthetic_advisory(
                    ghsa="GHSA-0000-0000-nit01",
                    severity="critical",
                    summary="Sequencer censorship via reorg",
                    description="Reorg attack drains bridge.",
                    pkg="nitro",
                ),
            ],
            "matter-labs/era-compiler-solidity": [
                _synthetic_advisory(
                    ghsa="GHSA-0000-0000-zks01",
                    severity="medium",
                    summary="`fold (xor)` misoptimization soundness gap",
                    description="Compiler emits unsound bytecode for shifted xor pattern.",
                    pkg="zksolc",
                    cwe="CWE-682",
                ),
            ],
            "scroll-tech/scroll": [],  # honest-zero
            "taikoxyz/taiko-mono": [
                _synthetic_advisory(
                    ghsa="GHSA-0000-0000-tk01",
                    severity="low",
                    summary="Prover marketplace griefing",
                    description="Griefing attack against prover selection.",
                    pkg="@taiko/protocol",
                ),
            ],
        }
        cache_path = tmp / "cache.json"
        cache_path.write_text(json.dumps(cache_payload), encoding="utf-8")
        return cache_path

    def test_convert_writes_records_and_emits_summary(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            cache_path = self._write_cache(tmp)
            out_dir = tmp / "out"

            # Restrict to repos in cache so honest-zero noise stays bounded.
            repos = [
                r for r in self.tool.TARGET_REPOS
                if r[0] in {
                    "ethereum-optimism/optimism",
                    "OffchainLabs/nitro",
                    "matter-labs/era-compiler-solidity",
                    "scroll-tech/scroll",
                    "taikoxyz/taiko-mono",
                }
            ]
            summary = self.tool.convert(
                out_dir, repos=repos, cache_file=cache_path
            )

            self.assertEqual(summary["errors"], [])
            self.assertEqual(summary["records_emitted"], 4)
            self.assertEqual(summary["verification_tier"], "tier-1-ghsa-cache")
            self.assertIn("scroll-tech/scroll", summary["repos_with_zero_advisories"])

            # Verify each record file exists with the expected slug shape.
            yaml_files = list(out_dir.glob("*/record.yaml"))
            json_files = list(out_dir.glob("*/record.json"))
            self.assertEqual(len(yaml_files), 4)
            self.assertEqual(len(json_files), 4)
            for jf in json_files:
                slug = jf.parent.name
                self.assertEqual(slug.count("__"), 2, slug)

    def test_emitted_records_validate_against_schema(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            cache_path = self._write_cache(tmp)
            out_dir = tmp / "out"
            self.tool.convert(out_dir, cache_file=cache_path)

            schema = self.validator.load_schema()
            for jf in out_dir.glob("*/record.json"):
                record = json.loads(jf.read_text(encoding="utf-8"))
                errs = self.validator.validate_doc(record, schema)
                self.assertEqual(errs, [], f"{jf}: {errs}")

    # ------------------------------------------------------------------
    # Severity / impact / mitigation extraction.
    # ------------------------------------------------------------------
    def test_severity_normalization_maps_moderate_to_medium(self) -> None:
        advisory = _synthetic_advisory(ghsa="GHSA-test-mod", severity="moderate")
        record = self.tool.advisory_to_record(
            "matter-labs/era-compiler-solidity", "rust", "zk-proof",
            advisory, "tier-1-ghsa-cache",
        )
        self.assertEqual(record["severity_at_finding"], "medium")
        self.assertEqual(record["impact_dollar_class"], "$10K-$100K")

    def test_mitigation_state_is_mitigated_when_patched_versions_set(self) -> None:
        advisory = _synthetic_advisory(ghsa="GHSA-test-mit", patched=">= 1.2.3")
        record = self.tool.advisory_to_record(
            "ethereum-optimism/optimism", "solidity", "rollup",
            advisory, "tier-1-ghsa-cache",
        )
        self.assertIn("mitigation-state=mitigated", record["attacker_action_sequence"])

    def test_mitigation_state_is_proposed_when_no_patched_versions(self) -> None:
        advisory = _synthetic_advisory(ghsa="GHSA-test-prop", patched="")
        record = self.tool.advisory_to_record(
            "ethereum-optimism/optimism", "solidity", "rollup",
            advisory, "tier-1-ghsa-cache",
        )
        self.assertIn("mitigation-state=proposed", record["attacker_action_sequence"])

    def test_required_preconditions_contain_verification_tier(self) -> None:
        advisory = _synthetic_advisory(ghsa="GHSA-test-tier")
        record = self.tool.advisory_to_record(
            "ethereum-optimism/optimism", "solidity", "rollup",
            advisory, "tier-1-ghsa-rest-api",
        )
        joined = " | ".join(record["required_preconditions"])
        self.assertIn("verification_tier=tier-1-ghsa-rest-api", joined)
        # Source URL surfaces in the precondition rows for offline resolvability.
        self.assertIn("https://github.com/example/repo/security/advisories/GHSA-test-tier", joined)
        # Affected repo is captured.
        self.assertIn("ethereum-optimism/optimism", joined)

    def test_required_preconditions_capture_affected_packages_and_fix_versions(self) -> None:
        advisory = _synthetic_advisory(
            ghsa="GHSA-test-pkg", pkg="zksolc", patched=">= 1.5.7",
        )
        record = self.tool.advisory_to_record(
            "matter-labs/era-compiler-solidity", "rust", "zk-proof",
            advisory, "tier-1-ghsa-cache",
        )
        joined = " | ".join(record["required_preconditions"])
        self.assertIn("zksolc", joined)
        self.assertIn(">= 1.5.7", joined)

    # ------------------------------------------------------------------
    # Hard rule: no fabrication. A repo returning [] yields zero records.
    # ------------------------------------------------------------------
    def test_honest_zero_for_empty_repo(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            cache_path = tmp / "cache.json"
            cache_path.write_text(
                json.dumps({"ethereum-optimism/optimism": []}),
                encoding="utf-8",
            )
            out_dir = tmp / "out"
            repos = [
                r for r in self.tool.TARGET_REPOS
                if r[0] == "ethereum-optimism/optimism"
            ]
            summary = self.tool.convert(out_dir, repos=repos, cache_file=cache_path)
            self.assertEqual(summary["records_emitted"], 0)
            self.assertEqual(summary["errors"], [])
            self.assertEqual(
                summary["repos_with_zero_advisories"],
                ["ethereum-optimism/optimism"],
            )
            # No record files created.
            self.assertEqual(list(out_dir.glob("*/record.yaml")), [])

    def test_record_id_is_stable_for_same_repo_and_ghsa(self) -> None:
        advisory = _synthetic_advisory(ghsa="GHSA-stable-id")
        r1 = self.tool.advisory_to_record(
            "OffchainLabs/nitro", "go", "rollup",
            advisory, "tier-1-ghsa-cache",
        )
        r2 = self.tool.advisory_to_record(
            "OffchainLabs/nitro", "go", "rollup",
            advisory, "tier-1-ghsa-cache",
        )
        self.assertEqual(r1["record_id"], r2["record_id"])
        self.assertTrue(r1["record_id"].startswith("l2-rollup-advisories:"))

    def test_source_audit_ref_is_resolvable_https_url(self) -> None:
        advisory = _synthetic_advisory(ghsa="GHSA-https-url")
        record = self.tool.advisory_to_record(
            "OffchainLabs/nitro", "go", "rollup",
            advisory, "tier-1-ghsa-cache",
        )
        self.assertTrue(
            record["source_audit_ref"].startswith("https://"),
            record["source_audit_ref"],
        )

    def test_bug_class_routes_per_language(self) -> None:
        cases = [
            ("solidity", "rollup", "smart-contract-vulnerability"),
            ("rust", "zk-proof", "zk-circuit-or-prover-vulnerability"),
            ("rust", "rollup", "client-or-vm-vulnerability"),
            ("go", "rollup", "consensus-or-rpc-vulnerability"),
            ("cairo", "zk-proof", "cairo-contract-vulnerability"),
            ("typescript-onchain", "rollup", "client-or-vm-vulnerability"),
        ]
        for lang, domain, expected in cases:
            advisory = _synthetic_advisory(ghsa=f"GHSA-bug-class-{lang}")
            rec = self.tool.advisory_to_record(
                "example/repo", lang, domain, advisory, "tier-1-ghsa-cache"
            )
            self.assertEqual(rec["bug_class"], expected, f"lang={lang}")


if __name__ == "__main__":
    unittest.main()
