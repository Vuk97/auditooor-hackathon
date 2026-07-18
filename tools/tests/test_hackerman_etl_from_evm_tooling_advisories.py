"""Unit tests for ``tools/hackerman-etl-from-evm-tooling-advisories.py``.

These tests never call ``gh api``. They drive the miner through its
``cache_file`` path with synthetic GHSA-shaped payloads (modeled on real
fields returned by GitHub's REST endpoint) and assert that the records
that come out:

* Validate against the v1 schema.
* Preserve the GHSA URL verbatim in ``source_audit_ref`` and
  ``required_preconditions``.
* Encode ``verification_tier`` into ``required_preconditions``.
* Map severity / impact / actor correctly for EVM-tooling domains
  (compiler, fuzzer, analyzer, framework, RPC library).
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
TOOL_PATH = REPO_ROOT / "tools" / "hackerman-etl-from-evm-tooling-advisories.py"
VALIDATOR_PATH = REPO_ROOT / "tools" / "hackerman-record-validate.py"


def _load_tool():
    name = "_hackerman_etl_from_evm_tooling_advisories"
    spec = importlib.util.spec_from_file_location(name, str(TOOL_PATH))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def _load_validator():
    name = "_hackerman_record_validate_for_evm_tooling_test"
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
    summary: str = "Compiler bug in Solidity codegen leads to miscompile",
    description: str = (
        "A miscompilation in the optimizer pipeline emits incorrect "
        "storage-layout bytecode for a specific Yul pattern, leading to "
        "subtle on-chain accounting bugs."
    ),
    cve_id: str = "CVE-2024-99999",
    package_name: str = "solc",
    patched_versions: str = ">=0.8.20",
    html_url: str = (
        "https://github.com/ethereum/solidity/security/advisories/GHSA-aaaa-bbbb-cccc"
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
        "ethereum/solidity",
        "foundry-rs/foundry",
        "crytic/slither",
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


class HackermanEtlFromEvmToolingAdvisoriesTests(unittest.TestCase):
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
            "foundry-rs/foundry",
            "foundry-rs/foundry-rs.github.io",
            "argotorg/solidity",
            "ethereum/solidity",
            "ethereum/solc-bin",
            "vyperlang/vyper",
            "vyperlang/titanoboa",
            "crytic/slither",
            "crytic/echidna",
            "crytic/medusa",
            "crytic/crytic-compile",
            "crytic/eth-security-toolbox",
            "a16z/halmos",
            "runtimeverification/k",
            "runtimeverification/evm-semantics",
            "ConsenSys/mythril",
            "nikolaij/manticore",
            "trailofbits/manticore",
            "ralexstokes/ethereum-helpers",
            "NomicFoundation/hardhat",
            "NomicFoundation/edr",
            "ApeWorX/ape",
            "OpenZeppelin/openzeppelin-foundry-upgrades",
            "safe-global/safe-cli",
            "wagmi-dev/viem",
            "wagmi-dev/wagmi",
            "ethers-io/ethers.js",
        }
        repos = {r[0] for r in self.tool.TARGET_REPOS}
        self.assertEqual(
            required - repos,
            set(),
            msg=f"missing repos in TARGET_REPOS: {required - repos}",
        )
        # Schema enum sanity: every (lang, domain) must be valid.
        valid_langs = {
            "solidity",
            "vyper",
            "rust",
            "python-onchain",
            "typescript-onchain",
        }
        valid_domains = {"rpc-infra"}
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

    def test_compiler_miscompile_maps_theft(self) -> None:
        adv = _sample_advisory(
            severity="critical",
            summary="solc optimizer miscompilation corrupts storage layout",
            description=(
                "A miscompile in the optimizer pipeline emits incorrect "
                "yul codegen for a common storage layout pattern; deployed "
                "contracts can leak funds to attacker via miscalculated "
                "slots."
            ),
        )
        summary = self._run({"ethereum/solidity": [adv]})
        self.assertEqual(summary["records_emitted"], 1)
        sub = next(p for p in self.out_dir.iterdir() if p.is_dir())
        rec = json.loads((sub / "record.json").read_text())
        self.assertEqual(rec["severity_at_finding"], "critical")
        self.assertEqual(rec["impact_dollar_class"], ">=$1M")
        self.assertEqual(rec["impact_class"], "theft")
        # rpc-infra + theft -> arbitrary-user (developer using the tool)
        self.assertEqual(rec["impact_actor"], "arbitrary-user")
        self.assertEqual(rec["target_domain"], "rpc-infra")
        self.assertEqual(rec["target_language"], "solidity")

    def test_key_leak_maps_privilege_escalation(self) -> None:
        adv = _sample_advisory(
            severity="high",
            summary="Private key exposure in safe-cli when importing wallet",
            description=(
                "The safe-cli import path inadvertently logs the private "
                "key to stderr under a specific verbose flag; key leak "
                "allows attacker to drain the affected wallet."
            ),
            html_url=(
                "https://github.com/safe-global/safe-cli/security/advisories/"
                "GHSA-key-aaaa-bbbb"
            ),
        )
        self._run({"safe-global/safe-cli": [adv]})
        sub = next(p for p in self.out_dir.iterdir() if p.is_dir())
        rec = json.loads((sub / "record.json").read_text())
        self.assertEqual(rec["impact_class"], "privilege-escalation")
        self.assertEqual(rec["impact_actor"], "specific-user")

    def test_compiler_crash_maps_dos(self) -> None:
        adv = _sample_advisory(
            severity="medium",
            summary="solc crash on malformed input",
            description=(
                "Specially crafted input causes solc to panic with an "
                "out of memory error; the compiler hangs indefinitely on "
                "downstream tooling pipelines."
            ),
        )
        self._run({"ethereum/solidity": [adv]})
        sub = next(p for p in self.out_dir.iterdir() if p.is_dir())
        rec = json.loads((sub / "record.json").read_text())
        self.assertEqual(rec["impact_class"], "dos")
        self.assertEqual(rec["impact_actor"], "arbitrary-user")
        self.assertEqual(rec["severity_at_finding"], "medium")
        self.assertEqual(rec["impact_dollar_class"], "$10K-$100K")

    def test_supply_chain_maps_theft(self) -> None:
        adv = _sample_advisory(
            severity="critical",
            summary="malicious dependency typosquat ships wallet exfil payload",
            description=(
                "A typosquatted npm package mimicking ethers.js shipped a "
                "supply chain backdoor that exfiltrates wallet seeds."
            ),
            html_url=(
                "https://github.com/ethers-io/ethers.js/security/advisories/"
                "GHSA-sup-aaaa-bbbb"
            ),
        )
        self._run({"ethers-io/ethers.js": [adv]})
        sub = next(p for p in self.out_dir.iterdir() if p.is_dir())
        rec = json.loads((sub / "record.json").read_text())
        self.assertEqual(rec["impact_class"], "theft")
        self.assertEqual(rec["target_language"], "typescript-onchain")
        self.assertEqual(rec["impact_actor"], "arbitrary-user")

    def test_workflow_takeover_routes_to_treasury(self) -> None:
        adv = _sample_advisory(
            severity="high",
            summary="GitHub workflow takeover via workflow injection",
            description=(
                "An attacker can inject malicious yaml into a CI workflow "
                "and achieve admin takeover of the release pipeline."
            ),
            html_url=(
                "https://github.com/foundry-rs/foundry/security/advisories/"
                "GHSA-wfl-aaaa-bbbb"
            ),
        )
        self._run({"foundry-rs/foundry": [adv]})
        sub = next(p for p in self.out_dir.iterdir() if p.is_dir())
        rec = json.loads((sub / "record.json").read_text())
        self.assertEqual(rec["impact_class"], "governance-takeover")
        self.assertEqual(rec["impact_actor"], "protocol-treasury")

    def test_honest_zero_repos_reported_not_fabricated(self) -> None:
        # Only 1 repo with an advisory; the others in TARGET_REPOS are
        # honest zeros and should NOT appear as records.
        cache = {"ethereum/solidity": [_sample_advisory()]}
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
        self.assertNotIn(
            "ethereum/solidity", summary["repos_with_zero_advisories"]
        )

    def test_filter_repo_restricts_output(self) -> None:
        cache = _build_cache(
            repos=("ethereum/solidity", "foundry-rs/foundry"),
        )
        self._write_cache(cache)
        summary = self.tool.convert(
            self.out_dir,
            cache_file=self.cache_path,
            filter_repo="ethereum/solidity",
            dry_run=True,
        )
        self.assertEqual(summary["repos_queried"], 1)
        self.assertEqual(summary["records_emitted"], 1)
        self.assertEqual(list(summary["by_repo"].keys()), ["ethereum/solidity"])

    def test_state_filter_skips_unpublished_advisories(self) -> None:
        published = _sample_advisory(ghsa_id="GHSA-pub-aa11-aaaa")
        draft = _sample_advisory(ghsa_id="GHSA-drf-aa11-aaaa")
        draft["state"] = "draft"
        self._run({"ethereum/solidity": [published, draft]})
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
            self.assertTrue(rec["record_id"].startswith("evm-tooling:"))
            seen += 1
        self.assertGreater(seen, 0)

    def test_slug_uses_double_underscore_separator(self) -> None:
        self._run({
            "foundry-rs/foundry": [
                _sample_advisory(ghsa_id="GHSA-slug-aaaa-bbbb"),
            ]
        })
        subs = [p.name for p in self.out_dir.iterdir() if p.is_dir()]
        self.assertEqual(len(subs), 1)
        self.assertTrue(
            subs[0].startswith("foundry-rs__foundry__"),
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
        summary = self._run({"ethereum/solidity": [adv, adv]})
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

    def test_default_impact_falls_back_to_dos(self) -> None:
        """EVM-tooling default falls back to ``dos`` (not theft) for
        advisories whose summary/description do not match any keyword.
        Tooling bugs default to reliability impact, not financial.
        """
        adv = _sample_advisory(
            severity="low",
            summary="Misc issue",
            description="An anomaly was observed in the toolchain state machine.",
        )
        self._run({"ethereum/solidity": [adv]})
        sub = next(p for p in self.out_dir.iterdir() if p.is_dir())
        rec = json.loads((sub / "record.json").read_text())
        self.assertEqual(rec["impact_class"], "dos")
        self.assertEqual(rec["impact_actor"], "arbitrary-user")


if __name__ == "__main__":
    unittest.main()
