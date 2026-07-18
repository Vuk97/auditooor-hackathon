"""Unit tests for ``tools/hackerman-etl-from-stablecoin-cdp-advisories.py``.

These tests never call ``gh api``. They drive the miner through its
``cache_file`` path with synthetic GHSA-shaped payloads (modeled on real
fields returned by GitHub's REST endpoint) and assert that the records
that come out:

* Validate against the v1 schema.
* Preserve the GHSA URL verbatim in ``source_audit_ref`` and
  ``required_preconditions``.
* Encode ``verification_tier`` into ``required_preconditions``.
* Map severity / impact / actor correctly for stablecoin / CDP domains
  (lending / oracle / governance).
* Are deterministic across reruns.
* Track honest zeros in ``repos_with_zero_advisories``.
"""
from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import re as _re
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "hackerman-etl-from-stablecoin-cdp-advisories.py"
VALIDATOR_PATH = REPO_ROOT / "tools" / "hackerman-record-validate.py"


def _load_tool():
    name = "_hackerman_etl_from_stablecoin_cdp_advisories"
    spec = importlib.util.spec_from_file_location(name, str(TOOL_PATH))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def _load_validator():
    name = "_hackerman_record_validate_for_stablecoin_cdp_test"
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
    summary: str = "Unauthorized mint via oracle manipulation in CDP",
    description: str = (
        "An unprivileged attacker can manipulate the oracle price feed to "
        "trigger an unauthorized mint of stablecoin debt against an "
        "under-collateralized CDP."
    ),
    cve_id: str = "CVE-2024-99999",
    package_name: str = "@makerdao/dss",
    patched_versions: str = ">=2.0.0",
    html_url: str = (
        "https://github.com/makerdao/dss/security/advisories/GHSA-aaaa-bbbb-cccc"
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
        "cwes": [{"cwe_id": "CWE-682", "name": "Incorrect Calculation"}],
    }


def _build_cache(extra=None, repos=None):
    """Build a fully populated cache mapping for a small subset of repos."""
    repos = repos or (
        "makerdao/dss",
        "ethena-labs/contracts",
        "frax-finance/fraxlend",
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


class HackermanEtlFromStablecoinCdpAdvisoriesTests(unittest.TestCase):
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
            "makerdao/dss",
            "makerdao/dss-deploy",
            "makerdao/spark",
            "makerdao/sky-core",
            "makerdao/community",
            "ethena-labs/contracts",
            "usual-money/protocol-v1",
            "frax-finance/frax-cpi-oracle",
            "frax-finance/fraxlend",
            "alchemix-finance/alchemix-v2-dao",
            "alchemix-finance/v3-contracts",
            "ondo-finance/ondo-protocol-v3",
            "dolomite-protocol/dolomite-margin",
            "abracadabra-money-contracts/abracadabra-money-contracts",
            "prisma-fi/prisma-contracts",
            "raft-fi/raft-contracts",
            "gravita-protocol/gravita-protocol",
            "inverse-finance/dola-fed-contracts",
        }
        repos = {r[0] for r in self.tool.TARGET_REPOS}
        self.assertEqual(
            required - repos,
            set(),
            msg=f"missing repos in TARGET_REPOS: {required - repos}",
        )
        # Schema enum sanity: every (lang, domain) must be valid.
        valid_langs = {"solidity"}
        valid_domains = {"lending", "oracle", "governance"}
        for repo, lang, domain in self.tool.TARGET_REPOS:
            self.assertIn(lang, valid_langs, msg=f"{repo} unknown lang {lang}")
            self.assertIn(domain, valid_domains, msg=f"{repo} unknown domain {domain}")
        # Brief specifies liquity/dev and liquity/liquity2 are dups; both
        # MUST NOT be in TARGET_REPOS to avoid duplicate record_ids with
        # the lending miner.
        self.assertNotIn("liquity/dev", repos)
        self.assertNotIn("liquity/liquity2", repos)

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
            self.assertEqual(
                (status, errs), ("valid", []), msg=f"{yaml_path}: {errs}"
            )

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
            ref_lines = [p for p in rec["required_preconditions"]
                         if p.startswith("Reference advisory at https://")]
            self.assertEqual(len(ref_lines), 1)
            found_marker = True
        self.assertTrue(found_marker)

    def test_oracle_manipulation_maps_theft(self) -> None:
        adv = _sample_advisory(
            severity="critical",
            summary="Oracle manipulation drains MakerDAO debt ceiling",
            description=(
                "An unprivileged attacker manipulates the medianizer "
                "price feed to mint stablecoin debt at undercollateralized "
                "ratio, draining the protocol."
            ),
        )
        summary = self._run({"makerdao/dss": [adv]})
        self.assertEqual(summary["records_emitted"], 1)
        sub = next(p for p in self.out_dir.iterdir() if p.is_dir())
        rec = json.loads((sub / "record.json").read_text())
        self.assertEqual(rec["severity_at_finding"], "critical")
        self.assertEqual(rec["impact_dollar_class"], ">=$1M")
        self.assertEqual(rec["impact_class"], "theft")
        # lending + theft -> depositor-class.
        self.assertEqual(rec["impact_actor"], "depositor-class")
        self.assertEqual(rec["target_domain"], "lending")
        self.assertEqual(rec["target_language"], "solidity")

    def test_governance_takeover_routes_to_treasury(self) -> None:
        adv = _sample_advisory(
            severity="high",
            summary="Admin takeover via governance proxy hijack",
            description=(
                "The admin proxy hijack allows a malicious proposer to "
                "execute an upgrade hijack on the core stablecoin issuer."
            ),
            html_url=(
                "https://github.com/makerdao/community/security/advisories/"
                "GHSA-gov-aaaa-bbbb"
            ),
        )
        self._run({"makerdao/community": [adv]})
        sub = next(p for p in self.out_dir.iterdir() if p.is_dir())
        rec = json.loads((sub / "record.json").read_text())
        self.assertEqual(rec["impact_class"], "governance-takeover")
        self.assertEqual(rec["impact_actor"], "protocol-treasury")
        self.assertEqual(rec["target_domain"], "governance")

    def test_oracle_repo_domain_routing(self) -> None:
        adv = _sample_advisory(
            severity="medium",
            summary="Stale price feed allows skewed CPI quote",
            description=(
                "Stale oracle response on frax-cpi-oracle allows skewed "
                "CPI quote causing rounding-based precision loss."
            ),
            html_url=(
                "https://github.com/frax-finance/frax-cpi-oracle/"
                "security/advisories/GHSA-orc-aaaa-bbbb"
            ),
        )
        self._run({"frax-finance/frax-cpi-oracle": [adv]})
        sub = next(p for p in self.out_dir.iterdir() if p.is_dir())
        rec = json.loads((sub / "record.json").read_text())
        self.assertEqual(rec["target_domain"], "oracle")
        # "stale oracle" wins over "rounding" by ordering -> theft.
        self.assertEqual(rec["impact_class"], "theft")
        # oracle + theft -> arbitrary-user.
        self.assertEqual(rec["impact_actor"], "arbitrary-user")

    def test_share_inflation_maps_precision_loss(self) -> None:
        adv = _sample_advisory(
            severity="medium",
            summary="Share inflation in stability-pool deposit accounting",
            description=(
                "An attacker pre-mints shares and inflates the share price "
                "so subsequent depositors round down to zero shares."
            ),
        )
        self._run({"makerdao/dss": [adv]})
        sub = next(p for p in self.out_dir.iterdir() if p.is_dir())
        rec = json.loads((sub / "record.json").read_text())
        self.assertEqual(rec["impact_class"], "precision-loss")
        self.assertEqual(rec["impact_actor"], "depositor-class")
        self.assertEqual(rec["severity_at_finding"], "medium")
        self.assertEqual(rec["impact_dollar_class"], "$10K-$100K")

    def test_honest_zero_repos_reported_not_fabricated(self) -> None:
        # Only 1 repo with an advisory; the others in TARGET_REPOS are
        # honest zeros and should NOT appear as records.
        cache = {"makerdao/dss": [_sample_advisory()]}
        self._write_cache(cache)
        summary = self.tool.convert(
            self.out_dir, cache_file=self.cache_path, dry_run=True
        )
        self.assertEqual(summary["records_emitted"], 1)
        # All except the one repo with data are honest zeros.
        self.assertEqual(
            len(summary["repos_with_zero_advisories"]),
            len(self.tool.TARGET_REPOS) - 1,
        )
        self.assertNotIn("makerdao/dss", summary["repos_with_zero_advisories"])

    def test_filter_repo_restricts_output(self) -> None:
        cache = _build_cache(
            repos=("makerdao/dss", "ethena-labs/contracts"),
        )
        self._write_cache(cache)
        summary = self.tool.convert(
            self.out_dir,
            cache_file=self.cache_path,
            filter_repo="makerdao/dss",
            dry_run=True,
        )
        self.assertEqual(summary["repos_queried"], 1)
        self.assertEqual(summary["records_emitted"], 1)
        self.assertEqual(list(summary["by_repo"].keys()), ["makerdao/dss"])

    def test_state_filter_skips_unpublished_advisories(self) -> None:
        published = _sample_advisory(ghsa_id="GHSA-pub-aa11-aaaa")
        draft = _sample_advisory(ghsa_id="GHSA-drf-aa11-aaaa")
        draft["state"] = "draft"
        self._run({"makerdao/dss": [published, draft]})
        sub_ids = [
            json.loads((p / "record.json").read_text())["record_id"]
            for p in self.out_dir.iterdir() if p.is_dir()
        ]
        self.assertEqual(len(sub_ids), 1)
        # The published advisory's ghsa id appears verbatim in the record id.
        self.assertIn("ghsa-pub-aa11-aaaa", sub_ids[0])

    def test_record_id_matches_schema_pattern(self) -> None:
        self._run(_build_cache())
        pattern = _re.compile(r"^[A-Za-z0-9._:/-]{8,160}$")
        seen = 0
        for sub in self.out_dir.iterdir():
            if not sub.is_dir():
                continue
            rec = json.loads((sub / "record.json").read_text())
            self.assertRegex(rec["record_id"], pattern)
            self.assertTrue(rec["record_id"].startswith("stablecoin-cdp:"))
            seen += 1
        self.assertGreater(seen, 0)

    def test_slug_uses_double_underscore_separator(self) -> None:
        self._run({
            "makerdao/dss": [
                _sample_advisory(ghsa_id="GHSA-slug-aaaa-bbbb"),
            ]
        })
        subs = [p.name for p in self.out_dir.iterdir() if p.is_dir()]
        self.assertEqual(len(subs), 1)
        self.assertTrue(
            subs[0].startswith("makerdao__dss__"),
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
        summary = self._run({"makerdao/dss": [adv, adv]})
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

    def test_default_impact_falls_back_to_theft(self) -> None:
        """Stablecoin/CDP default falls back to ``theft`` (not
        privilege-escalation) for advisories whose summary/description
        do not match any keyword."""
        adv = _sample_advisory(
            severity="low",
            summary="Misc issue",
            description="An anomaly was observed in the contract state machine.",
        )
        self._run({"makerdao/dss": [adv]})
        sub = next(p for p in self.out_dir.iterdir() if p.is_dir())
        rec = json.loads((sub / "record.json").read_text())
        self.assertEqual(rec["impact_class"], "theft")
        self.assertEqual(rec["impact_actor"], "depositor-class")


if __name__ == "__main__":
    unittest.main()
