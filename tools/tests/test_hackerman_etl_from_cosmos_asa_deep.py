"""Unit tests for ``tools/hackerman-etl-from-cosmos-asa-deep.py``.

These tests never call ``gh api``. They drive the miner through its
``cache_file`` path with synthetic GHSA-shaped payloads and assert:

* Records validate against the v1 schema.
* GHSA URL is preserved verbatim in ``source_audit_ref`` and
  ``required_preconditions``.
* ``verification_tier`` is encoded into ``required_preconditions``.
* Severity / impact / actor mapping is correct.
* Output is deterministic across reruns.
* Honest zeros are tracked, not fabricated.
* Cross-reference logic skips advisories already covered by sibling miner's
  on-disk records (no double-emission).
* ASA / ISA tracker IDs extracted from advisory text are preserved verbatim.
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
TOOL_PATH = REPO_ROOT / "tools" / "hackerman-etl-from-cosmos-asa-deep.py"
VALIDATOR_PATH = REPO_ROOT / "tools" / "hackerman-record-validate.py"


def _load_tool():
    name = "_hackerman_etl_from_cosmos_asa_deep"
    spec = importlib.util.spec_from_file_location(name, str(TOOL_PATH))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def _load_validator():
    name = "_hackerman_record_validate_for_cosmos_asa_deep_test"
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
    summary: str = "Chain halt via malformed proposal in gaia x/staking module",
    description: str = (
        "An unprivileged proposer can submit a malformed governance proposal "
        "that triggers a panic during BeginBlock, causing a chain halt and "
        "consensus liveness failure across the validator set."
    ),
    cve_id: str = "CVE-2024-99999",
    package_name: str = "github.com/cosmos/gaia",
    patched_versions: str = ">=18.0.0",
    html_url: str = "https://github.com/cosmos/gaia/security/advisories/GHSA-aaaa-bbbb-cccc",
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
                "package": {"name": package_name, "ecosystem": "go"},
                "patched_versions": patched_versions,
            }
        ],
        "cwes": [{"cwe_id": "CWE-754", "name": "Improper Check for Unusual or Exceptional Conditions"}],
    }


def _build_cache(extra=None, repos=None):
    repos = repos or (
        "cosmos/gaia",
        "cosmwasm/wasmd",
        "evmos/evmos",
    )
    out = {}
    for i, repo in enumerate(repos):
        out[repo] = [
            _sample_advisory(
                ghsa_id=f"GHSA-test-{i:02d}aa-bbcc",
                html_url=f"https://github.com/{repo}/security/advisories/GHSA-test-{i:02d}aa-bbcc",
                summary=f"Chain halt advisory {i} in {repo}",
            )
        ]
    if extra:
        for repo, advs in extra.items():
            out.setdefault(repo, [])
            out[repo].extend(advs)
    return out


class HackermanEtlFromCosmosAsaDeepTests(unittest.TestCase):
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
        return self.tool.convert(self.out_dir, cache_file=cache, **kwargs)

    # -- tests -------------------------------------------------------------

    def test_target_repos_cover_net_new_set(self) -> None:
        """The repos this deep miner mines are NOT in the sibling miner's set."""
        required = {
            "cosmos/gaia",
            "cosmos/interchain-security",
            "cosmwasm/wasmd",
            "cosmwasm/wasmvm",
            "evmos/evmos",
            "strangelove-ventures/horcrux",
        }
        repos = {r[0] for r in self.tool.TARGET_REPOS}
        missing = required - repos
        self.assertEqual(missing, set(), msg=f"missing repos: {missing}")
        # Schema enum sanity on every (lang, domain).
        valid_langs = {
            "solidity", "vyper", "go", "rust", "move", "cairo", "huff",
            "assembly", "typescript-onchain", "python-onchain", "circom",
            "noir", "leo", "cairo-zk",
        }
        valid_domains = {
            "lending", "dex", "bridge", "oracle", "governance", "staking",
            "vault", "rollup", "zk-proof", "consensus", "rpc-infra", "dao",
            "escrow", "nft", "gaming", "l1-client",
        }
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
            self.assertEqual((status, errs), ("valid", []), msg=f"{yaml_path}: {errs}")

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
            self.assertEqual(len(tier_lines), 1)
            self.assertEqual(tier_lines[0], "verification_tier=tier-1-ghsa-cache")
            ref_lines = [p for p in rec["required_preconditions"]
                         if p.startswith("Reference advisory at https://")]
            self.assertEqual(len(ref_lines), 1)
            found_marker = True
        self.assertTrue(found_marker)

    def test_critical_severity_maps_dollar_class_and_dos_actor(self) -> None:
        adv = _sample_advisory(severity="critical")
        summary = self._run({"cosmos/gaia": [adv]})
        self.assertEqual(summary["records_emitted"], 1)
        sub = next(p for p in self.out_dir.iterdir() if p.is_dir())
        rec = json.loads((sub / "record.json").read_text())
        self.assertEqual(rec["severity_at_finding"], "critical")
        self.assertEqual(rec["impact_dollar_class"], ">=$1M")
        # "chain halt" + "liveness" routes to dos.
        self.assertEqual(rec["impact_class"], "dos")
        # DoS on consensus chains hits the validator set.
        self.assertEqual(rec["impact_actor"], "validator-set")
        self.assertEqual(rec["target_domain"], "consensus")
        self.assertEqual(rec["target_language"], "go")

    def test_asa_id_extracted_verbatim_from_advisory_text(self) -> None:
        adv = _sample_advisory(
            severity="high",
            summary="ASA-2024-0042 chain halt in interchain-security",
            description=(
                "ASA-2024-0042 reports an unprivileged liveness failure "
                "in the provider module."
            ),
            html_url=(
                "https://github.com/cosmos/interchain-security/"
                "security/advisories/GHSA-aaaa-bbbb-cccc"
            ),
        )
        self._run({"cosmos/interchain-security": [adv]})
        sub = next(p for p in self.out_dir.iterdir() if p.is_dir())
        rec = json.loads((sub / "record.json").read_text())
        self.assertIn(
            "Tracker identifier ASA-2024-0042",
            rec["required_preconditions"],
        )
        self.assertIn("asa-2024-0042", rec["function_shape"]["shape_tags"])

    def test_honest_zero_repos_reported_not_fabricated(self) -> None:
        cache = {"cosmos/gaia": [_sample_advisory()]}
        self._write_cache(cache)
        summary = self.tool.convert(
            self.out_dir, cache_file=self.cache_path, dry_run=True
        )
        self.assertEqual(summary["records_emitted"], 1)
        self.assertEqual(
            len(summary["repos_with_zero_advisories"]),
            len(self.tool.TARGET_REPOS) - 1,
        )
        self.assertNotIn("cosmos/gaia", summary["repos_with_zero_advisories"])

    def test_filter_repo_restricts_output(self) -> None:
        cache = _build_cache(
            repos=("cosmos/gaia", "cosmwasm/wasmd"),
        )
        self._write_cache(cache)
        summary = self.tool.convert(
            self.out_dir,
            cache_file=self.cache_path,
            filter_repo="cosmos/gaia",
            dry_run=True,
        )
        self.assertEqual(summary["repos_queried"], 1)
        self.assertEqual(summary["records_emitted"], 1)
        self.assertEqual(list(summary["by_repo"].keys()), ["cosmos/gaia"])

    def test_state_filter_skips_unpublished_advisories(self) -> None:
        published = _sample_advisory(ghsa_id="GHSA-pub-aa11-aaaa")
        draft = _sample_advisory(ghsa_id="GHSA-drf-aa11-aaaa")
        draft["state"] = "draft"
        self._run({"cosmos/gaia": [published, draft]})
        sub_ids = [
            json.loads((p / "record.json").read_text())["record_id"]
            for p in self.out_dir.iterdir() if p.is_dir()
        ]
        self.assertEqual(len(sub_ids), 1)
        self.assertIn("ghsa-pub-aa11-aaaa", sub_ids[0])

    def test_cross_reference_skips_existing_records(self) -> None:
        """Pre-existing slug under out_dir prevents re-emission of that GHSA."""
        adv_existing = _sample_advisory(ghsa_id="GHSA-zzzz-yyyy-xxxx")
        adv_new = _sample_advisory(
            ghsa_id="GHSA-newr-aaaa-bbbb",
            html_url=(
                "https://github.com/cosmos/gaia/security/advisories/"
                "GHSA-newr-aaaa-bbbb"
            ),
            summary="Different advisory in gaia",
        )
        # Manually seed an existing slug matching the sibling miner's shape.
        seed_slug = "cosmos-gaia-ghsa-zzzz-yyyy-xxxx"
        seed_dir = self.out_dir / seed_slug
        seed_dir.mkdir(parents=True)
        (seed_dir / "record.json").write_text("{}", encoding="utf-8")
        summary = self._run({"cosmos/gaia": [adv_existing, adv_new]})
        # Only the NEW one becomes a record; the existing-slug one is skipped.
        self.assertEqual(summary["records_emitted"], 1)
        self.assertEqual(len(summary["skipped_already_covered"]), 1)
        sk = summary["skipped_already_covered"][0]
        self.assertEqual(sk["ghsa_id"], "GHSA-zzzz-yyyy-xxxx")
        self.assertEqual(sk["existing_slug"], seed_slug)

    def test_record_id_namespaced_to_cosmos_asa_deep(self) -> None:
        self._run(_build_cache())
        seen = 0
        for sub in self.out_dir.iterdir():
            if not sub.is_dir():
                continue
            rec = json.loads((sub / "record.json").read_text())
            self.assertTrue(
                rec["record_id"].startswith("cosmos-asa-deep:"),
                msg=f"unexpected record_id: {rec['record_id']}",
            )
            seen += 1
        self.assertGreater(seen, 0)

    def test_slug_matches_sibling_shape(self) -> None:
        """Slug uses ``<owner>-<repo>-<ghsa-id>`` (hyphen, not double-underscore)."""
        self._run({
            "cosmos/gaia": [
                _sample_advisory(ghsa_id="GHSA-slug-aaaa-bbbb"),
            ]
        })
        subs = [p.name for p in self.out_dir.iterdir() if p.is_dir()]
        self.assertEqual(len(subs), 1)
        self.assertEqual(subs[0], "cosmos-gaia-ghsa-slug-aaaa-bbbb")

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

    def test_cli_json_summary_includes_cross_reference_keys(self) -> None:
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
        self.assertIn("skipped_already_covered", payload)
        self.assertIn("evidence_sources", payload)
        # The evidence-sources manifest cites cosmos/security ADVISORIES.md.
        self.assertTrue(
            any("cosmos/security" in s for s in payload["evidence_sources"]),
            msg=f"missing cosmos/security evidence source: {payload['evidence_sources']}",
        )

    def test_dedupe_collapses_same_ghsa(self) -> None:
        adv = _sample_advisory(ghsa_id="GHSA-dup-aaaa-aaaa")
        summary = self._run({"cosmos/gaia": [adv, adv]})
        self.assertEqual(summary["records_emitted"], 1)
        self.assertEqual(summary["errors"], [])

    def test_empty_cache_emits_zero_records_no_errors(self) -> None:
        summary = self._run({})
        self.assertEqual(summary["records_emitted"], 0)
        self.assertEqual(summary["errors"], [])
        self.assertEqual(
            len(summary["repos_with_zero_advisories"]),
            len(self.tool.TARGET_REPOS),
        )

    def test_governance_keyword_routes_to_governance_takeover(self) -> None:
        adv = _sample_advisory(
            severity="high",
            summary="Governance proposal can bypass parameter validation",
            description=(
                "A malicious gov proposal can update consensus params without "
                "passing the standard governance ratification flow."
            ),
        )
        self._run({"cosmos/gaia": [adv]})
        sub = next(p for p in self.out_dir.iterdir() if p.is_dir())
        rec = json.loads((sub / "record.json").read_text())
        self.assertEqual(rec["impact_class"], "governance-takeover")
        self.assertEqual(rec["impact_actor"], "validator-set")


if __name__ == "__main__":
    unittest.main()
