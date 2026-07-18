"""Unit tests for ``tools/hackerman-etl-from-restaking-avs-deep.py``.

The deep miner is complementary to the sibling
``tools/hackerman-etl-from-restaking-lrt-advisories.py``. Where the
sibling miner was authored against an early operator brief whose
TARGET_REPOS contained mis-named (404) repos, this miner uses the
CANONICAL org / repo names enumerated live from
``gh api /orgs/<org>/repos`` on 2026-05-16.

These tests never call ``gh api``. They drive the miner through its
``cache_file`` path with synthetic GHSA-shaped payloads and assert that:

* The TARGET_REPOS list covers the CORRECTED ecosystem (Layr-Labs,
  symbioticfi, karak-network, etherfi-protocol, Renzo-Protocol,
  SwellNetwork, Kelp-DAO, PufferFinance, Pier-Two).
* No mis-named legacy org/repo names from the sibling miner leak into
  the deep miner's TARGET_REPOS.
* Records validate against the v1 schema.
* GHSA URL is preserved verbatim in ``source_audit_ref`` and
  ``required_preconditions``.
* ``verification_tier=tier-1-ghsa-cache`` (or rest-api) lands in
  ``required_preconditions``.
* Severity / impact / actor are routed correctly for restaking / AVS /
  LRT / EigenDA / TEE-attestation findings.
* Honest zeros are reported truthfully, not invented.
"""
from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "hackerman-etl-from-restaking-avs-deep.py"
VALIDATOR_PATH = REPO_ROOT / "tools" / "hackerman-record-validate.py"


def _load_tool():
    name = "_hackerman_etl_from_restaking_avs_deep"
    spec = importlib.util.spec_from_file_location(name, str(TOOL_PATH))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def _load_validator():
    name = "_hackerman_record_validate_for_restaking_avs_deep_test"
    spec = importlib.util.spec_from_file_location(name, str(VALIDATOR_PATH))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def _sample_advisory(
    *,
    ghsa_id: str = "GHSA-deep-aaaa-bbbb",
    severity: str = "high",
    summary: str = "Reentrancy in EigenPod withdrawal allows restaker fund theft",
    description: str = (
        "A reentrancy in the EigenPod withdrawal path lets an unprivileged "
        "attacker drain restaker collateral via the partial withdrawal "
        "credentials check."
    ),
    cve_id: str = "CVE-2025-99999",
    package_name: str = "@eigenlayer/contracts",
    patched_versions: str = ">=1.5.0",
    html_url: str = (
        "https://github.com/Layr-Labs/eigenlayer-contracts/security/"
        "advisories/GHSA-deep-aaaa-bbbb"
    ),
    published_at: str = "2025-04-12T12:00:00Z",
):
    return {
        "ghsa_id": ghsa_id,
        "cve_id": cve_id,
        "summary": summary,
        "description": description,
        "severity": severity,
        "state": "published",
        "html_url": html_url,
        "published_at": published_at,
        "updated_at": published_at,
        "vulnerabilities": [
            {
                "package": {"name": package_name, "ecosystem": "npm"},
                "patched_versions": patched_versions,
            }
        ],
        "cwes": [
            {"cwe_id": "CWE-841",
             "name": "Improper Enforcement of Behavioral Workflow"}
        ],
    }


def _build_cache(extra=None, repos=None):
    repos = repos or (
        "Layr-Labs/eigenlayer-contracts",
        "etherfi-protocol/smart-contracts",
        "Renzo-Protocol/contracts-public",
    )
    out = {}
    for i, repo in enumerate(repos):
        out[repo] = [
            _sample_advisory(
                ghsa_id=f"GHSA-deep-{i:02d}aa-bbcc",
                html_url=(
                    f"https://github.com/{repo}/security/advisories/"
                    f"GHSA-deep-{i:02d}aa-bbcc"
                ),
                summary=f"Advisory {i} in {repo}",
            )
        ]
    if extra:
        for repo, advs in extra.items():
            out.setdefault(repo, [])
            out[repo].extend(advs)
    return out


class HackermanEtlFromRestakingAvsDeepTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tool = _load_tool()
        cls.validator = _load_validator()

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.tmp.name)
        self.out_dir = self.tmp_path / "out"
        self.cache_path = self.tmp_path / "cache.json"

    def tearDown(self) -> None:
        self.tmp.cleanup()

    # -- helpers -----------------------------------------------------------

    def _write_cache(self, payload) -> Path:
        self.cache_path.write_text(json.dumps(payload), encoding="utf-8")
        return self.cache_path

    def _run(self, payload, **kwargs):
        cache = self._write_cache(payload)
        return self.tool.convert(
            self.out_dir, cache_file=cache, **kwargs
        )

    # -- TARGET_REPOS coverage --------------------------------------------

    def test_target_repos_covers_corrected_canonical_orgs(self) -> None:
        """All canonical org names enumerated via ``gh api`` must appear.

        The original miner used several mis-named repos that 404 on live
        REST calls (``karak-network/contracts``,
        ``etherfi-protocol/smart-contract-v2``, ``ether-fi/king-protocol``,
        ``renzoprotocol/contracts-public``, ``swell-network/v3``,
        ``kelpdao/contracts``, ``puffer-finance/puffer-pool``, etc.). The
        deep miner replaces those with corrected names.
        """
        required = {
            # EigenLayer
            "Layr-Labs/eigenlayer-contracts",
            "Layr-Labs/eigensdk-go",
            "Layr-Labs/eigenlayer-middleware",
            "Layr-Labs/eigensdk-rs",
            "Layr-Labs/eigenda",
            # Symbiotic
            "symbioticfi/core",
            "symbioticfi/relay",
            # Karak (CORRECTED: was karak-network/contracts which 404s)
            "karak-network/v1-contracts-public",
            "karak-network/v2-contracts",
            # ether.fi (CORRECTED: was etherfi-protocol/smart-contract-v2 which 404s)
            "etherfi-protocol/smart-contracts",
            "etherfi-protocol/etherfi-avs-operator",
            # Renzo (CORRECTED: PascalCase org)
            "Renzo-Protocol/contracts-public",
            # Swell (CORRECTED: PascalCase org, v3-core-public not v3)
            "SwellNetwork/v3-core-public",
            # Kelp (CORRECTED: Kelp-DAO + LRT-rsETH not kelpdao/contracts)
            "Kelp-DAO/LRT-rsETH",
            # Puffer (CORRECTED: PufferFinance + puffer-contracts not puffer-finance/puffer-pool)
            "PufferFinance/puffer-contracts",
            "PufferFinance/pufETH",
            # Pier-Two
            "Pier-Two/eigenlayer",
        }
        repos = {r[0] for r in self.tool.TARGET_REPOS}
        missing = required - repos
        self.assertEqual(missing, set(), msg=f"missing canonical repos: {missing}")

    def test_target_repos_excludes_known_misnamed_404_repos(self) -> None:
        """None of the legacy 404 repo names from the sibling miner leak in."""
        misnamed = {
            "karak-network/contracts",
            "etherfi-protocol/smart-contract-v2",
            "ether-fi/king-protocol",
            "renzoprotocol/contracts-public",
            "swell-network/v3",
            "kelpdao/contracts",
            "restake-finance/contracts",
            "inception-finance/inception-restaking-pool",
            "bedrock-defi/uniBTC-contracts",
            "puffer-finance/puffer-pool",
        }
        repos = {r[0] for r in self.tool.TARGET_REPOS}
        leaks = misnamed & repos
        self.assertEqual(leaks, set(),
                         msg=f"deep miner still references 404 repos: {leaks}")

    def test_target_repos_have_valid_schema_enums(self) -> None:
        valid_langs = {"solidity", "go", "rust", "typescript-onchain"}
        valid_domains = {"staking", "vault", "rollup", "zk-proof",
                         "consensus", "bridge"}
        for repo, lang, domain in self.tool.TARGET_REPOS:
            self.assertIn(lang, valid_langs, msg=f"{repo}: lang={lang}")
            self.assertIn(domain, valid_domains, msg=f"{repo}: domain={domain}")

    def test_target_repos_size_is_at_least_60(self) -> None:
        """Deep miner expanded surface to at least 60 canonical repos."""
        self.assertGreaterEqual(len(self.tool.TARGET_REPOS), 60)

    # -- verification_tier ------------------------------------------------

    def test_cache_path_emits_tier1_ghsa_cache(self) -> None:
        cache = self._write_cache(_build_cache())
        summary = self.tool.convert(self.out_dir, cache_file=cache, dry_run=True)
        self.assertEqual(summary["verification_tier"], "tier-1-ghsa-cache")

    # -- schema validation ------------------------------------------------

    def test_records_validate_against_schema(self) -> None:
        summary = self._run(_build_cache())
        self.assertEqual(summary["errors"], [])
        self.assertGreater(summary["records_emitted"], 0)
        schema = self.validator.load_schema()
        for sub in self.out_dir.iterdir():
            if not sub.is_dir():
                continue
            yaml_path = sub / "record.yaml"
            self.assertTrue(yaml_path.exists())
            status, errs = self.validator.validate_file(yaml_path, schema)
            self.assertEqual((status, errs), ("valid", []),
                             msg=f"{yaml_path}: {errs}")

    def test_source_audit_ref_is_ghsa_url(self) -> None:
        self._run(_build_cache())
        for sub in self.out_dir.iterdir():
            if not sub.is_dir():
                continue
            rec = json.loads((sub / "record.json").read_text())
            self.assertTrue(
                rec["source_audit_ref"].startswith("https://github.com/"),
                msg=f"non-GHSA url: {rec['source_audit_ref']}",
            )
            self.assertIn("/security/advisories/", rec["source_audit_ref"])

    def test_required_preconditions_contain_verification_tier(self) -> None:
        self._run(_build_cache())
        found = False
        for sub in self.out_dir.iterdir():
            if not sub.is_dir():
                continue
            rec = json.loads((sub / "record.json").read_text())
            tier_lines = [p for p in rec["required_preconditions"]
                          if p.startswith("verification_tier=")]
            self.assertEqual(len(tier_lines), 1)
            self.assertIn(tier_lines[0],
                          {"verification_tier=tier-1-ghsa-rest-api",
                           "verification_tier=tier-1-ghsa-cache"})
            ref_lines = [p for p in rec["required_preconditions"]
                         if p.startswith("Reference advisory at https://")]
            self.assertEqual(len(ref_lines), 1)
            found = True
        self.assertTrue(found)

    # -- impact routing ---------------------------------------------------

    def test_critical_eigenpod_maps_to_theft_depositor_class(self) -> None:
        adv = _sample_advisory(severity="critical")
        self._run({"Layr-Labs/eigenlayer-contracts": [adv]})
        sub = next(p for p in self.out_dir.iterdir() if p.is_dir())
        rec = json.loads((sub / "record.json").read_text())
        self.assertEqual(rec["severity_at_finding"], "critical")
        self.assertEqual(rec["impact_dollar_class"], ">=$1M")
        self.assertEqual(rec["impact_class"], "theft")
        self.assertEqual(rec["impact_actor"], "depositor-class")
        self.assertEqual(rec["target_domain"], "staking")

    def test_eigenda_blob_keyword_maps_to_freeze(self) -> None:
        adv = _sample_advisory(
            severity="high",
            summary="EigenDA blob dispersal failure",
            description=(
                "Blob dispersal in EigenDA stalls indefinitely when the "
                "quorum threshold can't be reached, freezing rollup data."
            ),
            html_url=(
                "https://github.com/Layr-Labs/eigenda/security/advisories/"
                "GHSA-deep-blob-aaaa-bbbb"
            ),
        )
        self._run({"Layr-Labs/eigenda": [adv]})
        sub = next(p for p in self.out_dir.iterdir() if p.is_dir())
        rec = json.loads((sub / "record.json").read_text())
        self.assertEqual(rec["impact_class"], "freeze")
        self.assertEqual(rec["target_domain"], "rollup")
        self.assertEqual(rec["impact_actor"], "depositor-class")

    def test_tee_attestation_keyword_maps_to_privilege_escalation(self) -> None:
        adv = _sample_advisory(
            severity="critical",
            summary="SGX attestation bypass in Puffer secure-signer",
            description=(
                "A flaw in the DCAP attestation chain lets an attacker "
                "submit forged TEE attestations and impersonate validators."
            ),
            html_url=(
                "https://github.com/PufferFinance/secure-signer/security/"
                "advisories/GHSA-deep-tee-aaaa-bbbb"
            ),
        )
        self._run({"PufferFinance/secure-signer": [adv]})
        sub = next(p for p in self.out_dir.iterdir() if p.is_dir())
        rec = json.loads((sub / "record.json").read_text())
        self.assertEqual(rec["impact_class"], "privilege-escalation")
        self.assertEqual(rec["impact_actor"], "protocol-treasury")
        self.assertEqual(rec["target_domain"], "zk-proof")
        self.assertEqual(rec["target_language"], "rust")

    def test_eigensdk_go_language_routing(self) -> None:
        adv = _sample_advisory(
            severity="high",
            summary="Goroutine leak in eigensdk-go AVS client",
            description=(
                "Goroutine leak in the AVS client leads to denial of service "
                "on long-running restaking operator nodes."
            ),
            html_url=(
                "https://github.com/Layr-Labs/eigensdk-go/security/advisories/"
                "GHSA-deep-gosdk-aaaa-bbbb"
            ),
        )
        self._run({"Layr-Labs/eigensdk-go": [adv]})
        sub = next(p for p in self.out_dir.iterdir() if p.is_dir())
        rec = json.loads((sub / "record.json").read_text())
        self.assertEqual(rec["target_language"], "go")
        self.assertEqual(rec["impact_class"], "dos")
        self.assertEqual(
            rec["attack_class"],
            "ghsa-public-advisory-go-restaking-avs-deep",
        )

    # -- honest zero ------------------------------------------------------

    def test_honest_zero_repos_reported_not_fabricated(self) -> None:
        cache = {"Layr-Labs/eigenlayer-contracts": [_sample_advisory()]}
        self._write_cache(cache)
        summary = self.tool.convert(
            self.out_dir, cache_file=self.cache_path, dry_run=True
        )
        self.assertEqual(summary["records_emitted"], 1)
        self.assertEqual(
            len(summary["repos_with_zero_advisories"]),
            len(self.tool.TARGET_REPOS) - 1,
        )
        self.assertNotIn(
            "Layr-Labs/eigenlayer-contracts",
            summary["repos_with_zero_advisories"],
        )

    def test_empty_cache_records_all_repos_as_zero(self) -> None:
        summary = self._run({})
        self.assertEqual(summary["records_emitted"], 0)
        self.assertEqual(summary["errors"], [])
        self.assertEqual(
            len(summary["repos_with_zero_advisories"]),
            len(self.tool.TARGET_REPOS),
        )

    # -- determinism / slug / id -----------------------------------------

    def test_record_id_namespace_prefix(self) -> None:
        import re as _re
        self._run(_build_cache())
        pattern = _re.compile(r"^[A-Za-z0-9._:/-]{8,160}$")
        seen = 0
        for sub in self.out_dir.iterdir():
            if not sub.is_dir():
                continue
            rec = json.loads((sub / "record.json").read_text())
            self.assertRegex(rec["record_id"], pattern)
            self.assertTrue(
                rec["record_id"].startswith("restaking-avs-deep:"),
                msg=f"unexpected prefix: {rec['record_id']}",
            )
            seen += 1
        self.assertGreater(seen, 0)

    def test_slug_uses_double_underscore_separator(self) -> None:
        self._run({
            "Layr-Labs/eigenlayer-contracts": [
                _sample_advisory(ghsa_id="GHSA-deep-slug-aaaa"),
            ]
        })
        subs = [p.name for p in self.out_dir.iterdir() if p.is_dir()]
        self.assertEqual(len(subs), 1)
        self.assertTrue(
            subs[0].startswith("layr-labs__eigenlayer-contracts__"),
            msg=f"unexpected slug: {subs[0]}",
        )
        self.assertIn("ghsa-deep-slug-aaaa", subs[0])

    def test_output_is_deterministic(self) -> None:
        cache = _build_cache()
        self._run(cache)
        first = sorted(
            (p.name, (p / "record.yaml").read_text())
            for p in self.out_dir.iterdir() if p.is_dir()
        )
        for sub in list(self.out_dir.iterdir()):
            if sub.is_dir():
                for f in sub.iterdir():
                    f.unlink()
                sub.rmdir()
        self._run(cache)
        second = sorted(
            (p.name, (p / "record.yaml").read_text())
            for p in self.out_dir.iterdir() if p.is_dir()
        )
        self.assertEqual(first, second)

    def test_state_filter_skips_unpublished_advisories(self) -> None:
        published = _sample_advisory(ghsa_id="GHSA-deep-pub-aaaa")
        draft = _sample_advisory(ghsa_id="GHSA-deep-drf-aaaa")
        draft["state"] = "draft"
        self._run({"Layr-Labs/eigenlayer-contracts": [published, draft]})
        sub_ids = [
            json.loads((p / "record.json").read_text())["record_id"]
            for p in self.out_dir.iterdir() if p.is_dir()
        ]
        self.assertEqual(len(sub_ids), 1)
        self.assertIn("ghsa-deep-pub-aaaa", sub_ids[0])

    def test_dedupe_collapses_same_ghsa(self) -> None:
        adv = _sample_advisory(ghsa_id="GHSA-deep-dup-aaaa")
        summary = self._run({"Layr-Labs/eigenlayer-contracts": [adv, adv]})
        self.assertEqual(summary["records_emitted"], 1)
        self.assertEqual(summary["errors"], [])

    def test_filter_repo_restricts_output(self) -> None:
        cache = _build_cache(
            repos=("Layr-Labs/eigenlayer-contracts", "PufferFinance/pufETH"),
        )
        self._write_cache(cache)
        summary = self.tool.convert(
            self.out_dir,
            cache_file=self.cache_path,
            filter_repo="PufferFinance/pufETH",
            dry_run=True,
        )
        self.assertEqual(summary["repos_queried"], 1)
        self.assertEqual(summary["records_emitted"], 1)
        self.assertEqual(list(summary["by_repo"].keys()),
                         ["PufferFinance/pufETH"])

    # -- CLI --------------------------------------------------------------

    def test_cli_json_summary(self) -> None:
        cache = self._write_cache(_build_cache())
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            rc = self.tool.main([
                "--out-dir", str(self.out_dir),
                "--cache-file", str(cache),
                "--dry-run",
                "--json-summary",
            ])
        self.assertEqual(rc, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["schema_version"], self.tool.SUMMARY_SCHEMA)
        self.assertEqual(payload["verification_tier"], "tier-1-ghsa-cache")
        self.assertGreater(payload["records_emitted"], 0)
        self.assertEqual(payload["errors"], [])


if __name__ == "__main__":
    unittest.main()
