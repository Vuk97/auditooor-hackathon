"""Unit tests for ``tools/hackerman-etl-from-substrate-cosmwasm.py``.

These tests never call ``gh api``. They drive the miner through its
``cache_file`` path with synthetic GHSA-shaped payloads (modeled on real
fields returned by GitHub's REST endpoint) and assert that the records
that come out:

* Validate against the v1 schema.
* Preserve the GHSA URL verbatim in ``source_audit_ref`` and
  ``required_preconditions``.
* Encode ``verification_tier`` into ``required_preconditions``.
* Map severity / impact / actor correctly across Substrate / Polkadot /
  parachain / CosmWasm domains (consensus / dex / lending / bridge /
  staking / l1-client).
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
TOOL_PATH = REPO_ROOT / "tools" / "hackerman-etl-from-substrate-cosmwasm.py"
VALIDATOR_PATH = REPO_ROOT / "tools" / "hackerman-record-validate.py"


def _load_tool():
    name = "_hackerman_etl_from_substrate_cosmwasm"
    spec = importlib.util.spec_from_file_location(name, str(TOOL_PATH))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def _load_validator():
    name = "_hackerman_record_validate_for_substrate_cosmwasm_test"
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
    summary: str = "Missing origin check in XCM module allows unauthorized transfer",
    description: str = (
        "An XCM execution path skips the origin-check decorator allowing an "
        "unprivileged attacker to drain bridged assets across the channel."
    ),
    cve_id: str = "CVE-2024-99999",
    package_name: str = "polkadot-sdk",
    patched_versions: str = ">=1.7.0",
    html_url: str = "https://github.com/paritytech/polkadot-sdk/security/advisories/GHSA-aaaa-bbbb-cccc",
    published_at: str = "2024-08-15T12:00:00Z",
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
                "package": {"name": package_name, "ecosystem": "cargo"},
                "patched_versions": patched_versions,
            }
        ],
        "cwes": [{"cwe_id": "CWE-863", "name": "Incorrect Authorization"}],
    }


def _build_cache(extra=None, repos=None):
    """Build a fully populated cache mapping for a small subset of repos."""
    repos = repos or (
        "paritytech/polkadot-sdk",
        "CosmWasm/wasmd",
        "AcalaNetwork/Acala",
    )
    out = {}
    for i, repo in enumerate(repos):
        out[repo] = [
            _sample_advisory(
                ghsa_id=f"GHSA-test-{i:02d}aa-bbcc",
                html_url=f"https://github.com/{repo}/security/advisories/GHSA-test-{i:02d}aa-bbcc",
                summary=f"Advisory {i} in {repo}",
            )
        ]
    if extra:
        for repo, advs in extra.items():
            out.setdefault(repo, [])
            out[repo].extend(advs)
    return out


class HackermanEtlFromSubstrateCosmwasmTests(unittest.TestCase):
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
        """Every repo the operator named in the brief is in TARGET_REPOS."""
        required = {
            # Substrate / Polkadot
            "paritytech/polkadot-sdk",
            "paritytech/polkadot",
            "paritytech/substrate",
            "paritytech/cumulus",
            "paritytech/parity-bridges-common",
            # Parachain ecosystem
            "moonbeam-foundation/moonbeam",
            "centrifuge/centrifuge-chain",
            "centrifuge/centrifuge-pallets",
            "AcalaNetwork/Acala",
            "AcalaNetwork/karura",
            "bifrost-finance/bifrost",
            "galacticcouncil/HydraDX-node",
            "kintsugi-network/interbtc",
            "AstarNetwork/Astar",
            # CosmWasm
            "CosmWasm/wasmd",
            "CosmWasm/cosmwasm",
            "CosmWasm/cosmwasm-plus",
            "CosmWasm/cw-storage-plus",
            "CosmWasm/cw-template",
            "mars-protocol/red-bank",
            "mars-protocol/contracts",
            "white-whale-defi-platform/white-whale-core",
            "terraswap/terraswap",
            "astroport-fi/astroport-core",
        }
        repos = {r[0] for r in self.tool.TARGET_REPOS}
        self.assertEqual(
            required - repos, set(),
            msg=f"missing repos in TARGET_REPOS: {required - repos}"
        )
        # All entries must use language=rust and a schema-enum domain.
        valid_domains = {
            "lending", "dex", "bridge", "oracle", "governance", "staking",
            "vault", "rollup", "zk-proof", "consensus", "rpc-infra", "dao",
            "escrow", "nft", "gaming", "l1-client",
        }
        for repo, lang, domain in self.tool.TARGET_REPOS:
            self.assertEqual(lang, "rust",
                             msg=f"{repo} language wrong: {lang!r}")
            self.assertIn(domain, valid_domains,
                          msg=f"{repo} domain not in schema enum: {domain!r}")

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
                msg=f"expected exactly one tier line: {rec['required_preconditions']}",
            )
            self.assertIn(
                tier_lines[0],
                {"verification_tier=tier-1-ghsa-rest-api",
                 "verification_tier=tier-1-ghsa-cache"},
            )
            ref_lines = [
                p for p in rec["required_preconditions"]
                if p.startswith("Reference advisory at https://")
            ]
            self.assertEqual(len(ref_lines), 1)
            found_marker = True
        self.assertTrue(found_marker)

    def test_consensus_domain_dos_maps_validator_set(self) -> None:
        adv = _sample_advisory(
            severity="critical",
            summary="Consensus halt via panic in finality vote",
            description=(
                "An unprivileged peer can trigger a panic in the consensus "
                "vote-aggregation path causing a chain halt across the "
                "validator set."
            ),
        )
        summary = self._run({"paritytech/polkadot-sdk": [adv]})
        self.assertEqual(summary["records_emitted"], 1)
        sub = next(p for p in self.out_dir.iterdir() if p.is_dir())
        rec = json.loads((sub / "record.json").read_text())
        self.assertEqual(rec["severity_at_finding"], "critical")
        self.assertEqual(rec["impact_dollar_class"], ">=$1M")
        self.assertEqual(rec["impact_class"], "dos")
        # consensus-domain DoS hits validator-set, not arbitrary-user.
        self.assertEqual(rec["impact_actor"], "validator-set")
        self.assertEqual(rec["target_domain"], "consensus")
        self.assertEqual(rec["target_language"], "rust")

    def test_dex_theft_routes_arbitrary_user(self) -> None:
        adv = _sample_advisory(
            severity="high",
            summary="Price manipulation in AMM pool allows drain of LP funds",
            description=(
                "Oracle manipulation on the AMM curve lets an attacker drain "
                "LP balances from the pool."
            ),
        )
        self._run({"AcalaNetwork/Acala": [adv]})
        sub = next(p for p in self.out_dir.iterdir() if p.is_dir())
        rec = json.loads((sub / "record.json").read_text())
        self.assertEqual(rec["impact_class"], "theft")
        # dex domain theft -> arbitrary-user (not depositor-class, which is
        # reserved for lending/vault).
        self.assertEqual(rec["impact_actor"], "arbitrary-user")
        self.assertEqual(rec["target_domain"], "dex")

    def test_lending_theft_routes_depositor_class(self) -> None:
        adv = _sample_advisory(
            severity="critical",
            summary="Liquidation flow allows collateral drain on lending pool",
            description=(
                "A reentrancy in the liquidation path drains depositor "
                "collateral on the lending pool."
            ),
        )
        self._run({"mars-protocol/red-bank": [adv]})
        sub = next(p for p in self.out_dir.iterdir() if p.is_dir())
        rec = json.loads((sub / "record.json").read_text())
        self.assertEqual(rec["impact_class"], "theft")
        # lending domain theft -> depositor-class
        self.assertEqual(rec["impact_actor"], "depositor-class")
        self.assertEqual(rec["target_domain"], "lending")

    def test_moderate_severity_maps_medium_precision(self) -> None:
        adv = _sample_advisory(
            severity="moderate",
            summary="Precision rounding error in share math",
            description=(
                "Rounding in the share-accounting math produces off-by-one "
                "errors when computing pool share balances."
            ),
        )
        self._run({"CosmWasm/cw-storage-plus": [adv]})
        sub = next(p for p in self.out_dir.iterdir() if p.is_dir())
        rec = json.loads((sub / "record.json").read_text())
        self.assertEqual(rec["severity_at_finding"], "medium")
        self.assertEqual(rec["impact_dollar_class"], "$10K-$100K")
        self.assertEqual(rec["impact_class"], "precision-loss")

    def test_honest_zero_repos_reported_not_fabricated(self) -> None:
        # Only 1 repo with an advisory; the others in TARGET_REPOS are
        # honest zeros and should NOT appear as records.
        cache = {"paritytech/polkadot-sdk": [_sample_advisory()]}
        self._write_cache(cache)
        summary = self.tool.convert(
            self.out_dir, cache_file=self.cache_path, dry_run=True
        )
        self.assertEqual(summary["records_emitted"], 1)
        # N repos in TARGET_REPOS, 1 with data, N-1 honest zeros.
        self.assertEqual(
            len(summary["repos_with_zero_advisories"]),
            len(self.tool.TARGET_REPOS) - 1,
        )
        self.assertNotIn(
            "paritytech/polkadot-sdk",
            summary["repos_with_zero_advisories"],
        )

    def test_filter_repo_restricts_output(self) -> None:
        cache = _build_cache(
            repos=("paritytech/polkadot-sdk", "CosmWasm/wasmd"),
        )
        self._write_cache(cache)
        summary = self.tool.convert(
            self.out_dir,
            cache_file=self.cache_path,
            filter_repo="CosmWasm/wasmd",
            dry_run=True,
        )
        self.assertEqual(summary["repos_queried"], 1)
        self.assertEqual(summary["records_emitted"], 1)
        self.assertEqual(list(summary["by_repo"].keys()), ["CosmWasm/wasmd"])

    def test_state_filter_skips_unpublished_advisories(self) -> None:
        published = _sample_advisory(ghsa_id="GHSA-pub-aa11-aaaa")
        draft = _sample_advisory(ghsa_id="GHSA-drf-aa11-aaaa")
        draft["state"] = "draft"
        self._run({"paritytech/polkadot-sdk": [published, draft]})
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
            seen += 1
        self.assertGreater(seen, 0)

    def test_slug_uses_double_underscore_separator(self) -> None:
        self._run({
            "paritytech/polkadot-sdk": [
                _sample_advisory(ghsa_id="GHSA-slug-aaaa-bbbb"),
            ]
        })
        subs = [p.name for p in self.out_dir.iterdir() if p.is_dir()]
        self.assertEqual(len(subs), 1)
        # owner lowercased + double-underscore + repo lowercased
        self.assertTrue(subs[0].startswith("paritytech__polkadot-sdk__"),
                        msg=f"unexpected slug: {subs[0]}")
        self.assertIn("ghsa-slug-aaaa-bbbb", subs[0])

    def test_slug_handles_mixed_case_owner(self) -> None:
        # AcalaNetwork and CosmWasm have mixed-case owners; slug must
        # normalize to lowercase and still preserve the double-underscore
        # separator.
        self._run({
            "AcalaNetwork/Acala": [
                _sample_advisory(ghsa_id="GHSA-mcase-bbbb-cccc"),
            ],
            "CosmWasm/wasmd": [
                _sample_advisory(ghsa_id="GHSA-cwasm-dddd-eeee"),
            ],
        })
        subs = sorted(p.name for p in self.out_dir.iterdir() if p.is_dir())
        self.assertEqual(len(subs), 2)
        joined = " ".join(subs)
        self.assertIn("acalanetwork__acala__", joined)
        self.assertIn("cosmwasm__wasmd__", joined)

    def test_output_is_deterministic(self) -> None:
        cache = _build_cache()
        summary1 = self._run(cache)
        first = sorted(
            (p.name, (p / "record.yaml").read_text())
            for p in self.out_dir.iterdir() if p.is_dir()
        )
        # Reset and rebuild from the same cache.
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
        # Same advisory listed twice in one repo -> dedupe yields 1 record.
        summary = self._run({"paritytech/polkadot-sdk": [adv, adv]})
        self.assertEqual(summary["records_emitted"], 1)
        self.assertEqual(summary["errors"], [])

    def test_required_repo_count_matches_brief(self) -> None:
        # Operator brief enumerated 24 repos; sanity-check the count.
        self.assertEqual(len(self.tool.TARGET_REPOS), 24)

    def test_governance_takeover_maps_protocol_treasury(self) -> None:
        adv = _sample_advisory(
            severity="critical",
            summary="Governance takeover via sudo origin spoof",
            description="An attacker injects a sudo takeover via a forged root origin.",
        )
        self._run({"paritytech/polkadot": [adv]})
        sub = next(p for p in self.out_dir.iterdir() if p.is_dir())
        rec = json.loads((sub / "record.json").read_text())
        self.assertEqual(rec["impact_class"], "governance-takeover")
        self.assertEqual(rec["impact_actor"], "protocol-treasury")


if __name__ == "__main__":
    unittest.main()
