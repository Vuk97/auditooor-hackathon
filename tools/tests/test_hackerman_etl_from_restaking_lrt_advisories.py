"""Unit tests for ``tools/hackerman-etl-from-restaking-lrt-advisories.py``.

These tests never call ``gh api``. They drive the miner through its
``cache_file`` path with synthetic GHSA-shaped payloads (modeled on real
fields returned by GitHub's REST endpoint) and assert that the records
that come out:

* Validate against the v1 schema.
* Preserve the GHSA URL verbatim in ``source_audit_ref`` and
  ``required_preconditions``.
* Encode ``verification_tier`` into ``required_preconditions``.
* Map severity / impact / actor correctly for restaking / LRT domains.
* Route restaking-specific keywords (slashing, withdrawal-queue,
  delegation-manager, beacon-proof, LRT share inflation).
* Are deterministic across reruns.
* Track honest zeros in ``repos_with_zero_advisories``.
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
TOOL_PATH = REPO_ROOT / "tools" / "hackerman-etl-from-restaking-lrt-advisories.py"
VALIDATOR_PATH = REPO_ROOT / "tools" / "hackerman-record-validate.py"


def _load_tool():
    name = "_hackerman_etl_from_restaking_lrt"
    spec = importlib.util.spec_from_file_location(name, str(TOOL_PATH))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def _load_validator():
    name = "_hackerman_record_validate_for_restaking_lrt_test"
    spec = importlib.util.spec_from_file_location(name, str(VALIDATOR_PATH))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def _sample_advisory(
    *,
    ghsa_id: str = "GHSA-aaaa-bbbb-cccc",
    severity: str = "high",
    summary: str = "Reentrancy in EigenPod withdrawal allows restaker fund theft",
    description: str = (
        "A reentrancy in the EigenPod withdrawal path allows an "
        "unprivileged attacker to drain restaker collateral by abusing "
        "the partial withdrawal credentials check."
    ),
    cve_id: str = "CVE-2024-99999",
    package_name: str = "@eigenlayer/contracts",
    patched_versions: str = ">=1.5.0",
    html_url: str = (
        "https://github.com/Layr-Labs/eigenlayer-contracts/security/"
        "advisories/GHSA-aaaa-bbbb-cccc"
    ),
    published_at: str = "2024-06-15T12:00:00Z",
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
    """Build a fully populated cache mapping for a small subset of repos."""
    repos = repos or (
        "Layr-Labs/eigenlayer-contracts",
        "etherfi-protocol/smart-contract-v2",
        "renzoprotocol/contracts-public",
    )
    out = {}
    for i, repo in enumerate(repos):
        out[repo] = [
            _sample_advisory(
                ghsa_id=f"GHSA-test-{i:02d}aa-bbcc",
                html_url=(
                    f"https://github.com/{repo}/security/advisories/"
                    f"GHSA-test-{i:02d}aa-bbcc"
                ),
                summary=f"Advisory {i} in {repo}",
            )
        ]
    if extra:
        for repo, advs in extra.items():
            out.setdefault(repo, [])
            out[repo].extend(advs)
    return out


class HackermanEtlFromRestakingLrtTests(unittest.TestCase):
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

    # -- tests -------------------------------------------------------------

    def test_target_repos_cover_required_set(self) -> None:
        """Every repo the operator named in the brief is in TARGET_REPOS.

        Pendle is intentionally excluded (already covered by AMM miner).
        """
        required = {
            "Layr-Labs/eigenlayer-contracts",
            "Layr-Labs/eigensdk-go",
            "Layr-Labs/eigenlayer-middleware",
            "symbioticfi/core",
            "symbioticfi/relay",
            "karak-network/contracts",
            "etherfi-protocol/smart-contract-v2",
            "renzoprotocol/contracts-public",
            "swell-network/v3",
            "kelpdao/contracts",
            "ether-fi/king-protocol",
            "restake-finance/contracts",
            "inception-finance/inception-restaking-pool",
            "bedrock-defi/uniBTC-contracts",
            "puffer-finance/puffer-pool",
        }
        repos = {r[0] for r in self.tool.TARGET_REPOS}
        self.assertEqual(required - repos, set(),
                         msg=f"missing repos in TARGET_REPOS: {required - repos}")
        # Pendle deliberately NOT in this miner.
        self.assertNotIn("pendle-finance/pendle-core-v2-public", repos)
        # Schema enum sanity: every (lang, domain) must be valid for the schema.
        valid_langs = {"solidity", "go", "rust"}
        valid_domains = {"staking", "vault"}
        for repo, lang, domain in self.tool.TARGET_REPOS:
            self.assertIn(lang, valid_langs, msg=f"{repo} unknown lang {lang}")
            self.assertIn(domain, valid_domains, msg=f"{repo} unknown domain {domain}")

    def test_cache_path_emits_tier1_ghsa_cache(self) -> None:
        cache = self._write_cache(_build_cache())
        summary = self.tool.convert(self.out_dir, cache_file=cache, dry_run=True)
        self.assertEqual(summary["verification_tier"], "tier-1-ghsa-cache")

    def test_records_validate_against_schema(self) -> None:
        summary = self._run(_build_cache())
        self.assertEqual(summary["errors"], [])
        self.assertGreater(summary["records_emitted"], 0)
        schema = self.validator.load_schema()
        for sub in self.out_dir.iterdir():
            if not sub.is_dir():
                continue
            yaml_path = sub / "record.yaml"
            self.assertTrue(yaml_path.exists(), msg=f"missing yaml: {sub}")
            status, errs = self.validator.validate_file(yaml_path, schema)
            self.assertEqual((status, errs), ("valid", []),
                             msg=f"{yaml_path}: {errs}")

    def test_source_audit_ref_is_ghsa_url(self) -> None:
        cache = _build_cache()
        self._run(cache)
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
        found_marker = False
        for sub in self.out_dir.iterdir():
            if not sub.is_dir():
                continue
            rec = json.loads((sub / "record.json").read_text())
            tier_lines = [
                p for p in rec["required_preconditions"]
                if p.startswith("verification_tier=")
            ]
            self.assertEqual(
                len(tier_lines), 1,
                msg=f"expected exactly one tier line: {rec['required_preconditions']}"
            )
            self.assertIn(tier_lines[0],
                          {"verification_tier=tier-1-ghsa-rest-api",
                           "verification_tier=tier-1-ghsa-cache"})
            ref_lines = [p for p in rec["required_preconditions"]
                         if p.startswith("Reference advisory at https://")]
            self.assertEqual(len(ref_lines), 1)
            found_marker = True
        self.assertTrue(found_marker)

    def test_critical_severity_maps_dollar_class_and_impact_actor(self) -> None:
        adv = _sample_advisory(severity="critical")
        summary = self._run({"Layr-Labs/eigenlayer-contracts": [adv]})
        self.assertEqual(summary["records_emitted"], 1)
        sub = next(p for p in self.out_dir.iterdir() if p.is_dir())
        rec = json.loads((sub / "record.json").read_text())
        self.assertEqual(rec["severity_at_finding"], "critical")
        self.assertEqual(rec["impact_dollar_class"], ">=$1M")
        # The EigenPod-flavored sample summary routes via "eigenpod" -> theft.
        self.assertEqual(rec["impact_class"], "theft")
        # Theft on staking domain -> depositor-class (restakers).
        self.assertEqual(rec["impact_actor"], "depositor-class")
        self.assertEqual(rec["target_domain"], "staking")
        self.assertEqual(rec["target_language"], "solidity")

    def test_withdrawal_queue_keyword_maps_to_freeze(self) -> None:
        adv = _sample_advisory(
            severity="high",
            summary="Withdrawal queue accounting bug locks restaker funds",
            description=(
                "An off-by-one in the queued withdrawal accounting "
                "prevents restakers from completing undelegation; funds "
                "remain stuck in the withdrawal queue indefinitely."
            ),
        )
        self._run({"Layr-Labs/eigenlayer-contracts": [adv]})
        sub = next(p for p in self.out_dir.iterdir() if p.is_dir())
        rec = json.loads((sub / "record.json").read_text())
        self.assertEqual(rec["impact_class"], "freeze")
        # Freeze on staking domain -> depositor-class.
        self.assertEqual(rec["impact_actor"], "depositor-class")

    def test_restaking_reward_keyword_maps_yield_redistribution(self) -> None:
        adv = _sample_advisory(
            severity="high",
            summary="Restaking reward distribution miscalculation",
            description=(
                "A miscalculation in the restaking reward distribution "
                "path redirects yield away from honest restakers."
            ),
        )
        self._run({"symbioticfi/core": [adv]})
        sub = next(p for p in self.out_dir.iterdir() if p.is_dir())
        rec = json.loads((sub / "record.json").read_text())
        self.assertEqual(rec["impact_class"], "yield-redistribution")
        self.assertEqual(rec["impact_actor"], "yield-recipient")
        self.assertEqual(rec["target_domain"], "staking")

    def test_lrt_share_inflation_maps_to_precision_loss(self) -> None:
        adv = _sample_advisory(
            severity="moderate",
            summary="LRT share inflation via first depositor donation attack",
            description=(
                "A first-depositor donation attack against the LRT "
                "vault inflates share price and steals later-depositor "
                "value via rounding."
            ),
        )
        self._run({"etherfi-protocol/smart-contract-v2": [adv]})
        sub = next(p for p in self.out_dir.iterdir() if p.is_dir())
        rec = json.loads((sub / "record.json").read_text())
        self.assertEqual(rec["severity_at_finding"], "medium")
        self.assertEqual(rec["impact_class"], "precision-loss")
        # Vault domain -> depositor-class.
        self.assertEqual(rec["impact_actor"], "depositor-class")
        self.assertEqual(rec["target_domain"], "vault")

    def test_delegation_manager_keyword_maps_privilege_escalation(self) -> None:
        adv = _sample_advisory(
            severity="high",
            summary="Delegation manager access-control bypass",
            description=(
                "Missing access-control check on the delegation manager "
                "allows an unprivileged caller to bind operators to "
                "victim stakers."
            ),
        )
        self._run({"Layr-Labs/eigenlayer-contracts": [adv]})
        sub = next(p for p in self.out_dir.iterdir() if p.is_dir())
        rec = json.loads((sub / "record.json").read_text())
        self.assertEqual(rec["impact_class"], "privilege-escalation")
        self.assertEqual(rec["impact_actor"], "protocol-treasury")

    def test_eigensdk_go_language_routing(self) -> None:
        """eigensdk-go should be tagged as Go language."""
        adv = _sample_advisory(
            severity="high",
            summary="Goroutine leak in eigensdk-go AVS client",
            description=(
                "Goroutine leak in the AVS client leads to denial of "
                "service on long-running restaking operator nodes."
            ),
            html_url=(
                "https://github.com/Layr-Labs/eigensdk-go/security/"
                "advisories/GHSA-go-aaaa-bbbb-cccc"
            ),
        )
        self._run({"Layr-Labs/eigensdk-go": [adv]})
        sub = next(p for p in self.out_dir.iterdir() if p.is_dir())
        rec = json.loads((sub / "record.json").read_text())
        self.assertEqual(rec["target_language"], "go")
        self.assertEqual(rec["target_domain"], "staking")
        self.assertEqual(rec["impact_class"], "dos")
        self.assertEqual(rec["attack_class"],
                         "ghsa-public-advisory-go-restaking-lrt")

    def test_honest_zero_repos_reported_not_fabricated(self) -> None:
        cache = {"Layr-Labs/eigenlayer-contracts": [_sample_advisory()]}
        self._write_cache(cache)
        summary = self.tool.convert(
            self.out_dir, cache_file=self.cache_path, dry_run=True
        )
        self.assertEqual(summary["records_emitted"], 1)
        # All TARGET_REPOS minus the one with data == honest-zero list.
        self.assertEqual(len(summary["repos_with_zero_advisories"]),
                         len(self.tool.TARGET_REPOS) - 1)
        self.assertNotIn("Layr-Labs/eigenlayer-contracts",
                         summary["repos_with_zero_advisories"])

    def test_filter_repo_restricts_output(self) -> None:
        cache = _build_cache(
            repos=("Layr-Labs/eigenlayer-contracts", "etherfi-protocol/smart-contract-v2"),
        )
        self._write_cache(cache)
        summary = self.tool.convert(
            self.out_dir,
            cache_file=self.cache_path,
            filter_repo="Layr-Labs/eigenlayer-contracts",
            dry_run=True,
        )
        self.assertEqual(summary["repos_queried"], 1)
        self.assertEqual(summary["records_emitted"], 1)
        self.assertEqual(list(summary["by_repo"].keys()),
                         ["Layr-Labs/eigenlayer-contracts"])

    def test_state_filter_skips_unpublished_advisories(self) -> None:
        published = _sample_advisory(ghsa_id="GHSA-pub-aa11-aaaa")
        draft = _sample_advisory(ghsa_id="GHSA-drf-aa11-aaaa")
        draft["state"] = "draft"
        self._run({"Layr-Labs/eigenlayer-contracts": [published, draft]})
        sub_ids = [
            json.loads((p / "record.json").read_text())["record_id"]
            for p in self.out_dir.iterdir() if p.is_dir()
        ]
        self.assertEqual(len(sub_ids), 1)
        self.assertIn("ghsa-pub-aa11-aaaa", sub_ids[0])

    def test_record_id_matches_schema_pattern(self) -> None:
        import re as _re
        self._run(_build_cache())
        pattern = _re.compile(r"^[A-Za-z0-9._:/-]{8,160}$")
        seen = 0
        for sub in self.out_dir.iterdir():
            if not sub.is_dir():
                continue
            rec = json.loads((sub / "record.json").read_text())
            self.assertRegex(rec["record_id"], pattern)
            # Namespace prefix is restaking-lrt.
            self.assertTrue(rec["record_id"].startswith("restaking-lrt:"),
                            msg=f"unexpected prefix: {rec['record_id']}")
            seen += 1
        self.assertGreater(seen, 0)

    def test_slug_uses_double_underscore_separator(self) -> None:
        self._run({
            "Layr-Labs/eigenlayer-contracts": [
                _sample_advisory(ghsa_id="GHSA-slug-aaaa-bbbb"),
            ]
        })
        subs = [p.name for p in self.out_dir.iterdir() if p.is_dir()]
        self.assertEqual(len(subs), 1)
        # "Layr-Labs" lowercased by slugify in the slug-component.
        self.assertTrue(
            subs[0].startswith("layr-labs__eigenlayer-contracts__"),
            msg=f"unexpected slug: {subs[0]}",
        )
        self.assertIn("ghsa-slug-aaaa-bbbb", subs[0])

    def test_output_is_deterministic(self) -> None:
        cache = _build_cache()
        summary1 = self._run(cache)
        first = sorted(
            (p.name, (p / "record.yaml").read_text())
            for p in self.out_dir.iterdir() if p.is_dir()
        )
        for sub in list(self.out_dir.iterdir()):
            if sub.is_dir():
                for f in sub.iterdir():
                    f.unlink()
                sub.rmdir()
        summary2 = self._run(cache)
        second = sorted(
            (p.name, (p / "record.yaml").read_text())
            for p in self.out_dir.iterdir() if p.is_dir()
        )
        self.assertEqual(summary1["records_emitted"], summary2["records_emitted"])
        self.assertEqual(first, second)

    def test_cli_json_summary(self) -> None:
        cache = self._write_cache(_build_cache())
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            rc = self.tool.main(
                [
                    "--out-dir",
                    str(self.out_dir),
                    "--cache-file",
                    str(cache),
                    "--dry-run",
                    "--json-summary",
                ]
            )
        self.assertEqual(rc, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["schema_version"], self.tool.SUMMARY_SCHEMA)
        self.assertEqual(payload["verification_tier"], "tier-1-ghsa-cache")
        self.assertGreater(payload["records_emitted"], 0)
        self.assertEqual(payload["errors"], [])

    def test_dedupe_collapses_same_ghsa(self) -> None:
        adv = _sample_advisory(ghsa_id="GHSA-dup-aaaa-aaaa")
        summary = self._run({"Layr-Labs/eigenlayer-contracts": [adv, adv]})
        self.assertEqual(summary["records_emitted"], 1)
        self.assertEqual(summary["errors"], [])

    def test_empty_cache_emits_zero_records_no_errors(self) -> None:
        summary = self._run({})
        self.assertEqual(summary["records_emitted"], 0)
        self.assertEqual(summary["errors"], [])
        self.assertEqual(len(summary["repos_with_zero_advisories"]),
                         len(self.tool.TARGET_REPOS))


if __name__ == "__main__":
    unittest.main()
