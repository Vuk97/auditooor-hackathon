"""Tests for tools/hackerman-etl-from-oracle-advisories.py.

Synthetic GHSA-shape cache so the suite is hermetic (no live ``gh api``
calls). The cache mirrors the JSON shape returned by
``gh api /repos/<owner>/<repo>/security-advisories`` for real upstream
oracle-ecosystem repos -- field names match the live REST payload.
"""
from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from typing import Any, Dict, List


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "hackerman-etl-from-oracle-advisories.py"
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
    ecosystem: str = "npm",
    patched: str = ">= 1.2.3",
    published: str = "2025-01-15T12:00:00Z",
    cwe: str = "",
    state: str = "published",
) -> Dict[str, Any]:
    vulns: List[Dict[str, Any]] = [
        {
            "package": {"name": pkg, "ecosystem": ecosystem},
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
        "state": state,
        "published_at": published,
        "updated_at": published,
        "vulnerabilities": vulns,
        "cwes": ([{"cwe_id": cwe, "name": cwe}] if cwe else []),
    }
    return payload


class HackermanEtlFromOracleAdvisoriesTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = _load(TOOL_PATH, "_hackerman_etl_from_oracle_advisories")
        self.validator = _load(
            VALIDATOR_PATH, "_hackerman_record_validate_for_oracle_advisories"
        )

    # ------------------------------------------------------------------
    # Target repo list is well-formed and covers all required oracle orgs.
    # ------------------------------------------------------------------
    def test_target_repos_cover_required_oracle_orgs(self) -> None:
        repos = {repo for repo, _l, _d in self.tool.TARGET_REPOS}
        required_owners = {
            "smartcontractkit",  # Chainlink
            "pyth-network",
            "api3dao",
            "tellor-io",
            "redstone-finance",
            "UMAprotocol",
            "chronicle-protocol",
            "supra-platform",
        }
        owners = {r.split("/")[0] for r in repos}
        missing = required_owners - owners
        self.assertFalse(missing, f"missing required oracle orgs: {missing}")

    def test_target_repos_include_explicit_repo_list(self) -> None:
        """Every repo from the PR #726 spec must appear in TARGET_REPOS."""
        required_repos = {
            "smartcontractkit/chainlink",
            "smartcontractkit/ccip",
            "smartcontractkit/chainlink-evm",
            "smartcontractkit/external-adapters-js",
            "smartcontractkit/chainlink-fhe-evm",
            "pyth-network/pyth-client-js",
            "pyth-network/pythnet-sdk",
            "pyth-network/pyth-crosschain",
            "pyth-network/pyth-sdk-rs",
            "pyth-network/pyth-sdk-solidity",
            "api3dao/airnode",
            "api3dao/contracts",
            "api3dao/data-feed-reader-examples",
            "tellor-io/tellorflex-contracts",
            "tellor-io/tellor360",
            "redstone-finance/redstone-oracles-monorepo",
            "UMAprotocol/protocol",
            "chronicle-protocol/chronicle-std",
            "supra-platform/supra-evm-contracts",
        }
        repos = {repo for repo, _l, _d in self.tool.TARGET_REPOS}
        missing = required_repos - repos
        self.assertFalse(missing, f"missing required repos: {missing}")

    def test_target_repos_have_valid_language_and_domain(self) -> None:
        schema = self.validator.load_schema()
        lang_enum = set(schema["properties"]["target_language"]["enum"])
        domain_enum = set(schema["properties"]["target_domain"]["enum"])
        for repo, lang, domain in self.tool.TARGET_REPOS:
            self.assertIn(lang, lang_enum, f"{repo}: bad language {lang}")
            self.assertIn(domain, domain_enum, f"{repo}: bad domain {domain}")
            # Every repo in this miner targets the oracle domain by definition.
            self.assertEqual(domain, "oracle", f"{repo}: expected domain=oracle")

    # ------------------------------------------------------------------
    # Slug shape matches PR #726 task spec: <owner>__<repo>__<ghsa>.
    # ------------------------------------------------------------------
    def test_slug_shape_owner_repo_ghsa(self) -> None:
        advisory = _synthetic_advisory(ghsa="GHSA-abcd-efgh-ijkl")
        record = self.tool.advisory_to_record(
            "smartcontractkit/chainlink",
            "go",
            "oracle",
            advisory,
            "tier-1-ghsa-cache",
        )
        slug = self.tool.slug_for_record(record)
        self.assertIn("__", slug)
        parts = slug.split("__")
        self.assertEqual(len(parts), 3, slug)
        self.assertEqual(parts[0], "smartcontractkit")
        self.assertEqual(parts[1], "chainlink")
        self.assertTrue(parts[2].startswith("ghsa-"), parts[2])

    # ------------------------------------------------------------------
    # Cache replay: end-to-end with synthetic advisories per ecosystem.
    # ------------------------------------------------------------------
    def _write_cache(self, tmp: Path) -> Path:
        cache_payload: Dict[str, List[Dict[str, Any]]] = {
            "smartcontractkit/chainlink": [
                _synthetic_advisory(
                    ghsa="GHSA-0000-0000-cl01",
                    severity="high",
                    summary="OCR2 transmitter signature replay",
                    description="Stale OCR2 signed report can be replayed; price manipulation possible.",
                    cve="CVE-2099-99991",
                    pkg="chainlink",
                    ecosystem="go",
                ),
            ],
            "pyth-network/pyth-crosschain": [
                _synthetic_advisory(
                    ghsa="GHSA-0000-0000-py01",
                    severity="critical",
                    summary="Stale price acceptance in Wormhole VAA verifier",
                    description="Forged signature passes consumer freshness check; drain via stale data.",
                    pkg="pyth-crosschain",
                    ecosystem="rust",
                ),
            ],
            "api3dao/airnode": [
                _synthetic_advisory(
                    ghsa="GHSA-0000-0000-a301",
                    severity="medium",
                    summary="dAPI dispute-bond griefing",
                    description="Griefing attack against beacon update flow.",
                    pkg="@api3/airnode-protocol",
                    ecosystem="npm",
                    cwe="CWE-841",
                ),
            ],
            "redstone-finance/redstone-oracles-monorepo": [],  # honest-zero
            "UMAprotocol/protocol": [
                _synthetic_advisory(
                    ghsa="GHSA-0000-0000-uma01",
                    severity="low",
                    summary="Optimistic oracle frontrun on dispute",
                    description="Front-run on dispute resolution causes precision-loss rounding mismatch.",
                    pkg="@uma/contracts-node",
                    ecosystem="npm",
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
                    "smartcontractkit/chainlink",
                    "pyth-network/pyth-crosschain",
                    "api3dao/airnode",
                    "redstone-finance/redstone-oracles-monorepo",
                    "UMAprotocol/protocol",
                }
            ]
            summary = self.tool.convert(
                out_dir, repos=repos, cache_file=cache_path
            )

            self.assertEqual(summary["errors"], [])
            self.assertEqual(summary["records_emitted"], 4)
            self.assertEqual(summary["verification_tier"], "tier-1-ghsa-cache")
            self.assertIn(
                "redstone-finance/redstone-oracles-monorepo",
                summary["repos_with_zero_advisories"],
            )

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
            "pyth-network/pyth-crosschain", "rust", "oracle",
            advisory, "tier-1-ghsa-cache",
        )
        self.assertEqual(record["severity_at_finding"], "medium")
        self.assertEqual(record["impact_dollar_class"], "$10K-$100K")

    def test_mitigation_state_is_mitigated_when_patched_versions_set(self) -> None:
        advisory = _synthetic_advisory(ghsa="GHSA-test-mit", patched=">= 1.2.3")
        record = self.tool.advisory_to_record(
            "smartcontractkit/chainlink", "go", "oracle",
            advisory, "tier-1-ghsa-cache",
        )
        self.assertIn("mitigation-state=mitigated", record["attacker_action_sequence"])

    def test_mitigation_state_is_proposed_when_no_patched_versions(self) -> None:
        advisory = _synthetic_advisory(ghsa="GHSA-test-prop", patched="")
        record = self.tool.advisory_to_record(
            "smartcontractkit/chainlink", "go", "oracle",
            advisory, "tier-1-ghsa-cache",
        )
        self.assertIn("mitigation-state=proposed", record["attacker_action_sequence"])

    def test_required_preconditions_contain_verification_tier(self) -> None:
        advisory = _synthetic_advisory(ghsa="GHSA-test-tier")
        record = self.tool.advisory_to_record(
            "smartcontractkit/chainlink", "go", "oracle",
            advisory, "tier-1-ghsa-rest-api",
        )
        joined = " | ".join(record["required_preconditions"])
        self.assertIn("verification_tier=tier-1-ghsa-rest-api", joined)
        # Source URL surfaces in the precondition rows for offline resolvability.
        self.assertIn(
            "https://github.com/example/repo/security/advisories/GHSA-test-tier",
            joined,
        )
        # Affected repo is captured.
        self.assertIn("smartcontractkit/chainlink", joined)

    def test_required_preconditions_capture_affected_packages_and_fix_versions(
        self,
    ) -> None:
        advisory = _synthetic_advisory(
            ghsa="GHSA-test-pkg", pkg="@chainlink/contracts", patched=">= 0.8.0",
            ecosystem="npm",
        )
        record = self.tool.advisory_to_record(
            "smartcontractkit/chainlink-evm", "solidity", "oracle",
            advisory, "tier-1-ghsa-cache",
        )
        joined = " | ".join(record["required_preconditions"])
        self.assertIn("@chainlink/contracts", joined)
        self.assertIn(">= 0.8.0", joined)

    # ------------------------------------------------------------------
    # Hard rule: no fabrication. A repo returning [] yields zero records.
    # ------------------------------------------------------------------
    def test_honest_zero_for_empty_repo(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            cache_path = tmp / "cache.json"
            cache_path.write_text(
                json.dumps({"smartcontractkit/chainlink": []}),
                encoding="utf-8",
            )
            out_dir = tmp / "out"
            repos = [
                r for r in self.tool.TARGET_REPOS
                if r[0] == "smartcontractkit/chainlink"
            ]
            summary = self.tool.convert(out_dir, repos=repos, cache_file=cache_path)
            self.assertEqual(summary["records_emitted"], 0)
            self.assertEqual(summary["errors"], [])
            self.assertEqual(
                summary["repos_with_zero_advisories"],
                ["smartcontractkit/chainlink"],
            )
            # No record files created.
            self.assertEqual(list(out_dir.glob("*/record.yaml")), [])

    def test_unpublished_advisories_are_filtered(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            cache_path = tmp / "cache.json"
            cache_path.write_text(
                json.dumps(
                    {
                        "smartcontractkit/chainlink": [
                            _synthetic_advisory(
                                ghsa="GHSA-draft-test", state="draft"
                            ),
                            _synthetic_advisory(
                                ghsa="GHSA-pub-test", state="published"
                            ),
                        ]
                    }
                ),
                encoding="utf-8",
            )
            out_dir = tmp / "out"
            repos = [
                r for r in self.tool.TARGET_REPOS
                if r[0] == "smartcontractkit/chainlink"
            ]
            summary = self.tool.convert(out_dir, repos=repos, cache_file=cache_path)
            self.assertEqual(summary["records_emitted"], 1)
            self.assertEqual(summary["errors"], [])

    def test_record_id_is_stable_for_same_repo_and_ghsa(self) -> None:
        advisory = _synthetic_advisory(ghsa="GHSA-stable-id")
        r1 = self.tool.advisory_to_record(
            "pyth-network/pyth-crosschain", "rust", "oracle",
            advisory, "tier-1-ghsa-cache",
        )
        r2 = self.tool.advisory_to_record(
            "pyth-network/pyth-crosschain", "rust", "oracle",
            advisory, "tier-1-ghsa-cache",
        )
        self.assertEqual(r1["record_id"], r2["record_id"])
        self.assertTrue(r1["record_id"].startswith("oracle-advisories:"))

    def test_source_audit_ref_is_resolvable_https_url(self) -> None:
        advisory = _synthetic_advisory(ghsa="GHSA-https-url")
        record = self.tool.advisory_to_record(
            "UMAprotocol/protocol", "solidity", "oracle",
            advisory, "tier-1-ghsa-cache",
        )
        self.assertTrue(
            record["source_audit_ref"].startswith("https://"),
            record["source_audit_ref"],
        )

    def test_bug_class_routes_per_language(self) -> None:
        cases = [
            ("solidity", "oracle", "smart-contract-vulnerability"),
            ("rust", "oracle", "client-or-vm-vulnerability"),
            ("go", "oracle", "consensus-or-rpc-vulnerability"),
            ("typescript-onchain", "oracle", "off-chain-adapter-vulnerability"),
        ]
        for lang, domain, expected in cases:
            advisory = _synthetic_advisory(ghsa=f"GHSA-bug-class-{lang}")
            rec = self.tool.advisory_to_record(
                "example/repo", lang, domain, advisory, "tier-1-ghsa-cache"
            )
            self.assertEqual(rec["bug_class"], expected, f"lang={lang}")

    # ------------------------------------------------------------------
    # Impact-class inference is oracle-tuned: price-manipulation routes to
    # theft, "stale data" routes to theft, signature forgery to theft,
    # "halt" to dos.
    # ------------------------------------------------------------------
    def test_impact_class_routes_oracle_keywords(self) -> None:
        cases: List[Tuple[str, str]] = [
            ("Price manipulation in OCR2", "theft"),
            ("Stale price acceptance bug", "theft"),
            ("Signature forgery in VAA verifier", "theft"),
            ("Adapter crash causing feed outage", "dos"),
            ("Griefing on dispute bond", "griefing"),
            ("Rounding error in updateFee", "precision-loss"),
            ("Governance takeover via vote dilution", "governance-takeover"),
        ]
        for summary, expected in cases:
            advisory = _synthetic_advisory(
                ghsa=f"GHSA-impact-{slug_safe(summary)}", summary=summary,
                description=summary,
            )
            rec = self.tool.advisory_to_record(
                "example/repo", "solidity", "oracle",
                advisory, "tier-1-ghsa-cache",
            )
            self.assertEqual(
                rec["impact_class"], expected,
                f"summary={summary!r} expected={expected} got={rec['impact_class']}",
            )

    def test_default_impact_class_is_theft_for_oracle_domain(self) -> None:
        """Oracle advisories with no matched keyword default to theft (not dos)."""
        advisory = _synthetic_advisory(
            ghsa="GHSA-default-impact",
            summary="Unrelated text without keyword matches.",
            description="Body has no impact keyword.",
        )
        rec = self.tool.advisory_to_record(
            "example/repo", "solidity", "oracle",
            advisory, "tier-1-ghsa-cache",
        )
        self.assertEqual(rec["impact_class"], "theft")


def slug_safe(s: str) -> str:
    import re

    return re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")[:32]


if __name__ == "__main__":
    unittest.main()
