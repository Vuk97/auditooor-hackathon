"""Unit tests for ``tools/hackerman-etl-from-orderbook-rfq-advisories.py``.

These tests never call ``gh api``. They drive the miner through its
``cache_file`` path with synthetic GHSA-shaped payloads (modeled on real
fields returned by GitHub's REST endpoint) and assert that the records
that come out:

* Validate against the v1 schema.
* Preserve the GHSA URL verbatim in ``source_audit_ref`` and
  ``required_preconditions``.
* Encode ``verification_tier`` into ``required_preconditions``.
* Map severity / impact / actor correctly for orderbook / RFQ / perp-DEX
  domains.
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
TOOL_PATH = REPO_ROOT / "tools" / "hackerman-etl-from-orderbook-rfq-advisories.py"
VALIDATOR_PATH = REPO_ROOT / "tools" / "hackerman-record-validate.py"


def _load_tool():
    name = "_hackerman_etl_from_orderbook_rfq_advisories"
    spec = importlib.util.spec_from_file_location(name, str(TOOL_PATH))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def _load_validator():
    name = "_hackerman_record_validate_for_orderbook_rfq_test"
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
    summary: str = "Signature replay on RFQ quote allows unauthorized fill",
    description: str = (
        "An unprivileged attacker replays an EIP-712 signed RFQ quote to "
        "settle a fill against a market-maker beyond the intended nonce."
    ),
    cve_id: str = "CVE-2024-99999",
    package_name: str = "@cowprotocol/contracts",
    patched_versions: str = ">=2.0.0",
    html_url: str = (
        "https://github.com/cowprotocol/contracts/security/advisories/"
        "GHSA-aaaa-bbbb-cccc"
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
        "cwes": [{"cwe_id": "CWE-294", "name": "Authentication Bypass by Capture-replay"}],
    }


def _build_cache(extra=None, repos=None):
    """Build a fully populated cache mapping for a small subset of repos."""
    repos = repos or (
        "cowprotocol/contracts",
        "0xProject/protocol",
        "hashflow-finance/hashflow-evm",
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


class HackermanEtlFromOrderbookRfqAdvisoriesTests(unittest.TestCase):
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
            "gnosis/cow-amm",
            "gnosis/conditional-tokens-contracts",
            "gnosis/safe-contracts",
            "cowprotocol/contracts",
            "cowprotocol/services",
            "0xProject/protocol",
            "0xProject/0x-monorepo",
            "airswap-protocol/airswap-protocols-v3",
            "airswap-protocol/airswap-protocols",
            "hashflow-finance/hashflow-evm",
            "bebop-fi/bebop-contracts",
            "dydxprotocol/v4-chain",
            "dydxprotocol/perpetual",
            "vertex-protocol/clearinghouse",
            "aevo-exchange/contracts",
            "gmx-io/gmx-contracts",
            "gmx-io/gmx-synthetics",
            "elixir-protocol/elixir",
            "paragon-trade/paragon",
            "ggprotocol/ggp",
            "gns-protocol/contracts",
        }
        repos = {r[0] for r in self.tool.TARGET_REPOS}
        self.assertEqual(
            required - repos,
            set(),
            msg=f"missing repos in TARGET_REPOS: {required - repos}",
        )
        # Schema enum sanity: every (lang, domain) must be valid.
        valid_langs = {"solidity", "go", "rust"}
        valid_domains = {"dex", "governance", "oracle"}
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

    def test_signature_replay_maps_privilege_escalation(self) -> None:
        adv = _sample_advisory(
            severity="critical",
            summary="EIP-712 signature replay on RFQ quote",
            description=(
                "An unprivileged attacker replays a previously-signed "
                "RFQ quote against the settlement contract because the "
                "nonce reuse check is missing."
            ),
        )
        summary = self._run({"cowprotocol/contracts": [adv]})
        self.assertEqual(summary["records_emitted"], 1)
        sub = next(p for p in self.out_dir.iterdir() if p.is_dir())
        rec = json.loads((sub / "record.json").read_text())
        self.assertEqual(rec["severity_at_finding"], "critical")
        self.assertEqual(rec["impact_dollar_class"], ">=$1M")
        self.assertEqual(rec["impact_class"], "privilege-escalation")
        # dex + privilege-escalation -> specific-user (per-trader RFQ replay)
        self.assertEqual(rec["impact_actor"], "specific-user")
        self.assertEqual(rec["target_domain"], "dex")
        self.assertEqual(rec["target_language"], "solidity")

    def test_surplus_drain_maps_theft_depositor_class(self) -> None:
        adv = _sample_advisory(
            severity="high",
            summary="Solver surplus drain in batch auction settlement",
            description=(
                "A malicious solver can drain batch-auction surplus from "
                "users by manipulating the clearing-price calculation."
            ),
            html_url=(
                "https://github.com/cowprotocol/contracts/security/advisories/"
                "GHSA-cow-aaaa-bbbb"
            ),
        )
        self._run({"cowprotocol/contracts": [adv]})
        sub = next(p for p in self.out_dir.iterdir() if p.is_dir())
        rec = json.loads((sub / "record.json").read_text())
        self.assertEqual(rec["impact_class"], "theft")
        # dex + theft -> depositor-class
        self.assertEqual(rec["impact_actor"], "depositor-class")
        self.assertEqual(rec["target_domain"], "dex")

    def test_governance_takeover_routes_to_treasury(self) -> None:
        adv = _sample_advisory(
            severity="high",
            summary="Admin takeover via Safe proxy hijack",
            description=(
                "The admin proxy hijack allows a malicious proposer to "
                "execute an upgrade hijack on the core Safe contract."
            ),
            html_url=(
                "https://github.com/gnosis/safe-contracts/security/advisories/"
                "GHSA-gov-aaaa-bbbb"
            ),
        )
        self._run({"gnosis/safe-contracts": [adv]})
        sub = next(p for p in self.out_dir.iterdir() if p.is_dir())
        rec = json.loads((sub / "record.json").read_text())
        self.assertEqual(rec["impact_class"], "governance-takeover")
        self.assertEqual(rec["impact_actor"], "protocol-treasury")
        self.assertEqual(rec["target_domain"], "governance")

    def test_dydx_v4_go_chain_halt_dos(self) -> None:
        """dYdX v4-chain is Go domain dex; chain-halt keyword routes to dos."""
        adv = _sample_advisory(
            severity="high",
            summary="Block production halt via crafted MsgPlaceOrder",
            description=(
                "A crafted MsgPlaceOrder triggers consensus halt across "
                "all validators, causing chain-halt for an extended period."
            ),
            html_url=(
                "https://github.com/dydxprotocol/v4-chain/security/advisories/"
                "GHSA-dydx-aaaa-bbbb"
            ),
        )
        self._run({"dydxprotocol/v4-chain": [adv]})
        sub = next(p for p in self.out_dir.iterdir() if p.is_dir())
        rec = json.loads((sub / "record.json").read_text())
        self.assertEqual(rec["target_language"], "go")
        self.assertEqual(rec["target_domain"], "dex")
        self.assertEqual(rec["impact_class"], "dos")
        # dos -> arbitrary-user (any user impaired by chain halt)
        self.assertEqual(rec["impact_actor"], "arbitrary-user")

    def test_cowprotocol_services_rust_lang(self) -> None:
        """cowprotocol/services is Rust (solver backend); lang must be 'rust'."""
        lang_map = {
            repo: lang for repo, lang, _ in self.tool.TARGET_REPOS
        }
        self.assertEqual(lang_map["cowprotocol/services"], "rust")
        self.assertEqual(lang_map["dydxprotocol/v4-chain"], "go")

    def test_oracle_manipulation_perp_dex(self) -> None:
        adv = _sample_advisory(
            severity="critical",
            summary="Mark-price oracle manipulation on perp-DEX",
            description=(
                "An attacker manipulates the mark-price oracle feed to "
                "force a profitable funding-rate payment on perpetual positions."
            ),
            html_url=(
                "https://github.com/gmx-io/gmx-synthetics/security/advisories/"
                "GHSA-gmx-aaaa-bbbb"
            ),
        )
        self._run({"gmx-io/gmx-synthetics": [adv]})
        sub = next(p for p in self.out_dir.iterdir() if p.is_dir())
        rec = json.loads((sub / "record.json").read_text())
        self.assertEqual(rec["impact_class"], "theft")
        self.assertEqual(rec["target_domain"], "dex")
        self.assertEqual(rec["severity_at_finding"], "critical")

    def test_honest_zero_repos_reported_not_fabricated(self) -> None:
        cache = {"cowprotocol/contracts": [_sample_advisory()]}
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
            "cowprotocol/contracts", summary["repos_with_zero_advisories"]
        )

    def test_filter_repo_restricts_output(self) -> None:
        cache = _build_cache(
            repos=("cowprotocol/contracts", "0xProject/protocol"),
        )
        self._write_cache(cache)
        summary = self.tool.convert(
            self.out_dir,
            cache_file=self.cache_path,
            filter_repo="cowprotocol/contracts",
            dry_run=True,
        )
        self.assertEqual(summary["repos_queried"], 1)
        self.assertEqual(summary["records_emitted"], 1)
        self.assertEqual(list(summary["by_repo"].keys()), ["cowprotocol/contracts"])

    def test_state_filter_skips_unpublished_advisories(self) -> None:
        published = _sample_advisory(ghsa_id="GHSA-pub-aa11-aaaa")
        draft = _sample_advisory(ghsa_id="GHSA-drf-aa11-aaaa")
        draft["state"] = "draft"
        self._run({"cowprotocol/contracts": [published, draft]})
        sub_ids = [
            json.loads((p / "record.json").read_text())["record_id"]
            for p in self.out_dir.iterdir() if p.is_dir()
        ]
        self.assertEqual(len(sub_ids), 1)
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
            self.assertTrue(rec["record_id"].startswith("orderbook-rfq:"))
            seen += 1
        self.assertGreater(seen, 0)

    def test_slug_uses_double_underscore_separator(self) -> None:
        self._run({
            "cowprotocol/contracts": [
                _sample_advisory(ghsa_id="GHSA-slug-aaaa-bbbb"),
            ]
        })
        subs = [p.name for p in self.out_dir.iterdir() if p.is_dir()]
        self.assertEqual(len(subs), 1)
        self.assertTrue(
            subs[0].startswith("cowprotocol__contracts__"),
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
        summary = self._run({"cowprotocol/contracts": [adv, adv]})
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
        """Orderbook/RFQ default falls back to ``theft`` for advisories
        whose summary/description do not match any keyword."""
        adv = _sample_advisory(
            severity="low",
            summary="Misc issue",
            description="An anomaly was observed in the contract state machine.",
        )
        self._run({"cowprotocol/contracts": [adv]})
        sub = next(p for p in self.out_dir.iterdir() if p.is_dir())
        rec = json.loads((sub / "record.json").read_text())
        self.assertEqual(rec["impact_class"], "theft")
        self.assertEqual(rec["impact_actor"], "depositor-class")

    def test_mev_sandwich_routes_to_theft(self) -> None:
        adv = _sample_advisory(
            severity="medium",
            summary="MEV sandwich attack on AirSwap RFQ trades",
            description=(
                "A searcher can sandwich an RFQ-routed trade before the "
                "quote is settled by frontrunning the settlement tx."
            ),
        )
        self._run({"airswap-protocol/airswap-protocols": [adv]})
        sub = next(p for p in self.out_dir.iterdir() if p.is_dir())
        rec = json.loads((sub / "record.json").read_text())
        self.assertEqual(rec["impact_class"], "theft")
        self.assertEqual(rec["impact_actor"], "depositor-class")


if __name__ == "__main__":
    unittest.main()
