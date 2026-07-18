"""Unit tests for ``tools/hackerman-etl-from-privacy-mixer-advisories.py``.

These tests never call ``gh api``. They drive the miner through its
``cache_file`` path with synthetic GHSA-shaped payloads (modeled on real
fields returned by GitHub's REST endpoint) and assert that the records
that come out:

* Validate against the v1 schema.
* Preserve the GHSA URL verbatim in ``source_audit_ref`` and
  ``required_preconditions``.
* Encode ``verification_tier`` into ``required_preconditions``.
* Map severity / impact / actor correctly across the two privacy-protocol
  domain families (``zk-proof`` mixer / rollup vs ``rpc-infra`` mixnet /
  relay).
* Capture the real upstream implementation language in
  ``function_shape.shape_tags`` even when the schema-enum compromise
  forces ``target_language`` to a coarser bucket (e.g. nwaku Nim
  collapsed to typescript-onchain).
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
TOOL_PATH = REPO_ROOT / "tools" / "hackerman-etl-from-privacy-mixer-advisories.py"
VALIDATOR_PATH = REPO_ROOT / "tools" / "hackerman-record-validate.py"


def _load_tool():
    name = "_hackerman_etl_from_privacy_mixer_advisories"
    spec = importlib.util.spec_from_file_location(name, str(TOOL_PATH))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def _load_validator():
    name = "_hackerman_record_validate_for_privacy_mixer_test"
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
    summary: str = "Nullifier reuse in mixer withdrawal allows double-spend",
    description: str = (
        "A nullifier-reuse bug in the mixer withdrawal path allows an "
        "attacker to spend the same shielded note twice, draining the "
        "anonymity-pool of the corresponding deposit value."
    ),
    cve_id: str = "CVE-2024-77777",
    package_name: str = "tornado-core",
    patched_versions: str = ">=1.0.5",
    html_url: str = "https://github.com/tornado-cash/tornado-core/security/advisories/GHSA-aaaa-bbbb-cccc",
    published_at: str = "2024-09-21T12:00:00Z",
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
        "cwes": [{"cwe_id": "CWE-345", "name": "Insufficient Verification of Data Authenticity"}],
    }


def _build_cache(extra=None, repos=None):
    """Build a fully populated cache mapping for a small subset of repos."""
    repos = repos or (
        "tornado-cash/tornado-core",
        "privacy-scaling-explorations/semaphore",
        "aztecprotocol/aztec-packages",
        "nymtech/nym",
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


class HackermanEtlFromPrivacyMixerAdvisoriesTests(unittest.TestCase):
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
            "tornado-cash/tornado-core",
            "privacy-scaling-explorations/semaphore",
            "privacy-scaling-explorations/semaphore-protocol",
            "privacy-scaling-explorations/maci",
            "privacy-scaling-explorations/zkevm-circuits",
            "privacy-scaling-explorations/snark-artifacts",
            "aztecprotocol/aztec-packages",
            "aztecprotocol/aztec-connect",
            "railgun-privacy/contract",
            "railgun-privacy/cookbook",
            "railgun-privacy/engine",
            "nymtech/nym",
            "penumbra-zone/penumbra",
            "WalletConnect/WalletConnectV2-monorepo",
            "waku-org/go-waku",
            "waku-org/nwaku",
            "ammen99/wireless-tools",
        }
        repos = {r[0] for r in self.tool.TARGET_REPOS}
        self.assertEqual(
            required - repos, set(),
            msg=f"missing repos in TARGET_REPOS: {required - repos}"
        )
        # All entries must use a schema-enum language and domain.
        valid_langs = {
            "solidity", "go", "rust", "vyper", "move", "cairo", "huff",
            "assembly", "typescript-onchain", "python-onchain", "circom",
            "noir", "leo", "cairo-zk",
        }
        valid_domains = {
            "lending", "dex", "bridge", "oracle", "governance", "staking",
            "vault", "rollup", "zk-proof", "consensus", "rpc-infra", "dao",
            "escrow", "nft", "gaming", "l1-client",
        }
        for repo, lang, domain, real_lang in self.tool.TARGET_REPOS:
            self.assertIn(lang, valid_langs,
                          msg=f"{repo} language not in schema enum: {lang!r}")
            self.assertIn(domain, valid_domains,
                          msg=f"{repo} domain not in schema enum: {domain!r}")
            self.assertTrue(real_lang and isinstance(real_lang, str),
                            msg=f"{repo} missing real_lang tag")

    def test_required_repo_count_matches_brief(self) -> None:
        # Brief enumerated 17 repos.
        self.assertEqual(len(self.tool.TARGET_REPOS), 17)

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

    def test_nullifier_reuse_maps_theft_depositor_class(self) -> None:
        """zk-proof + theft -> depositor-class (note holders)."""
        adv = _sample_advisory(
            severity="critical",
            summary="Nullifier reuse allows double-spend of shielded notes",
            description=(
                "Missing nullifier-set check allows the same shielded note "
                "to be spent twice, draining the mixer pool."
            ),
        )
        summary = self._run({"tornado-cash/tornado-core": [adv]})
        self.assertEqual(summary["records_emitted"], 1)
        sub = next(p for p in self.out_dir.iterdir() if p.is_dir())
        rec = json.loads((sub / "record.json").read_text())
        self.assertEqual(rec["severity_at_finding"], "critical")
        self.assertEqual(rec["impact_dollar_class"], ">=$1M")
        self.assertEqual(rec["impact_class"], "theft")
        self.assertEqual(rec["impact_actor"], "depositor-class")
        self.assertEqual(rec["target_domain"], "zk-proof")
        self.assertEqual(rec["target_language"], "solidity")

    def test_deanonymization_maps_privilege_escalation(self) -> None:
        """Privacy bug (deanonymization) -> privilege-escalation /
        protocol-treasury (modeling anonymity-set compromise)."""
        adv = _sample_advisory(
            severity="high",
            summary="Deanonymization via metadata leak in semaphore proof generation",
            description=(
                "A side-channel in the proof-generation path leaks group "
                "membership metadata, enabling linkability of signals to "
                "their authors and breaking anonymity-set guarantees."
            ),
        )
        self._run({"privacy-scaling-explorations/semaphore": [adv]})
        sub = next(p for p in self.out_dir.iterdir() if p.is_dir())
        rec = json.loads((sub / "record.json").read_text())
        self.assertEqual(rec["impact_class"], "privilege-escalation")
        self.assertEqual(rec["impact_actor"], "protocol-treasury")
        self.assertEqual(rec["target_domain"], "zk-proof")

    def test_mixnet_dos_maps_arbitrary_user(self) -> None:
        """rpc-infra (mixnet) + DoS -> arbitrary-user."""
        adv = _sample_advisory(
            severity="moderate",
            summary="Panic on malformed sphinx packet causes node crash",
            description=(
                "A malformed sphinx packet causes the nym mixnode to panic "
                "and exit. An attacker can deliver the panic remotely "
                "(denial of service against the mixnode operator)."
            ),
        )
        self._run({"nymtech/nym": [adv]})
        sub = next(p for p in self.out_dir.iterdir() if p.is_dir())
        rec = json.loads((sub / "record.json").read_text())
        self.assertEqual(rec["impact_class"], "dos")
        self.assertEqual(rec["impact_actor"], "arbitrary-user")
        self.assertEqual(rec["target_domain"], "rpc-infra")
        self.assertEqual(rec["target_language"], "rust")

    def test_zk_proof_dos_maps_depositor_class(self) -> None:
        """zk-proof DoS hits depositor-class (note holders cannot withdraw)."""
        adv = _sample_advisory(
            severity="high",
            summary="Infinite loop in withdrawal proof verification",
            description=(
                "A malformed proof input triggers an infinite loop in the "
                "verifier, denying service to all note holders attempting "
                "to withdraw from the mixer."
            ),
        )
        self._run({"aztecprotocol/aztec-connect": [adv]})
        sub = next(p for p in self.out_dir.iterdir() if p.is_dir())
        rec = json.loads((sub / "record.json").read_text())
        self.assertEqual(rec["impact_class"], "dos")
        # zk-proof + dos -> depositor-class (not arbitrary-user).
        self.assertEqual(rec["impact_actor"], "depositor-class")
        self.assertEqual(rec["target_domain"], "zk-proof")

    def test_moderate_severity_maps_medium_precision(self) -> None:
        """Moderate -> medium, with under-constrained -> precision-loss."""
        adv = _sample_advisory(
            severity="moderate",
            summary="Under-constrained circuit allows fee math drift",
            description=(
                "A missing constraint in the fee-math sub-circuit allows "
                "off-by-one drift between prover and verifier accounting."
            ),
        )
        self._run({"privacy-scaling-explorations/maci": [adv]})
        sub = next(p for p in self.out_dir.iterdir() if p.is_dir())
        rec = json.loads((sub / "record.json").read_text())
        self.assertEqual(rec["severity_at_finding"], "medium")
        self.assertEqual(rec["impact_dollar_class"], "$10K-$100K")
        self.assertEqual(rec["impact_class"], "precision-loss")

    def test_real_language_tag_preserved_in_shape_tags(self) -> None:
        """Schema enum compromise must not lose the real upstream language
        (nwaku is Nim but mapped to typescript-onchain for schema)."""
        adv = _sample_advisory()
        self._run({"waku-org/nwaku": [adv]})
        sub = next(p for p in self.out_dir.iterdir() if p.is_dir())
        rec = json.loads((sub / "record.json").read_text())
        self.assertEqual(rec["target_language"], "typescript-onchain")
        self.assertIn("lang-nim", rec["function_shape"]["shape_tags"])

    def test_noir_language_for_aztec_packages(self) -> None:
        """aztec-packages should map to target_language=noir verbatim."""
        adv = _sample_advisory()
        self._run({"aztecprotocol/aztec-packages": [adv]})
        sub = next(p for p in self.out_dir.iterdir() if p.is_dir())
        rec = json.loads((sub / "record.json").read_text())
        self.assertEqual(rec["target_language"], "noir")
        self.assertIn("lang-noir", rec["function_shape"]["shape_tags"])

    def test_honest_zero_repos_reported_not_fabricated(self) -> None:
        cache = {"tornado-cash/tornado-core": [_sample_advisory()]}
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
            "tornado-cash/tornado-core",
            summary["repos_with_zero_advisories"],
        )

    def test_filter_repo_restricts_output(self) -> None:
        cache = _build_cache(
            repos=("tornado-cash/tornado-core", "penumbra-zone/penumbra"),
        )
        self._write_cache(cache)
        summary = self.tool.convert(
            self.out_dir,
            cache_file=self.cache_path,
            filter_repo="penumbra-zone/penumbra",
            dry_run=True,
        )
        self.assertEqual(summary["repos_queried"], 1)
        self.assertEqual(summary["records_emitted"], 1)
        self.assertEqual(list(summary["by_repo"].keys()), ["penumbra-zone/penumbra"])

    def test_state_filter_skips_unpublished_advisories(self) -> None:
        published = _sample_advisory(ghsa_id="GHSA-pub-aa11-aaaa")
        draft = _sample_advisory(ghsa_id="GHSA-drf-aa11-aaaa")
        draft["state"] = "draft"
        self._run({"tornado-cash/tornado-core": [published, draft]})
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
            self.assertTrue(
                rec["record_id"].startswith("privacy-mixer:"),
                msg=f"record_id missing namespace: {rec['record_id']}",
            )
            seen += 1
        self.assertGreater(seen, 0)

    def test_slug_uses_double_underscore_separator(self) -> None:
        self._run({
            "tornado-cash/tornado-core": [
                _sample_advisory(ghsa_id="GHSA-slug-aaaa-bbbb"),
            ]
        })
        subs = [p.name for p in self.out_dir.iterdir() if p.is_dir()]
        self.assertEqual(len(subs), 1)
        self.assertTrue(subs[0].startswith("tornado-cash__tornado-core__"),
                        msg=f"unexpected slug: {subs[0]}")
        self.assertIn("ghsa-slug-aaaa-bbbb", subs[0])

    def test_slug_handles_mixed_case_owner(self) -> None:
        # WalletConnect is mixed-case; slugify should lowercase it.
        self._run({
            "WalletConnect/WalletConnectV2-monorepo": [
                _sample_advisory(ghsa_id="GHSA-wc02-aaaa-bbbb"),
            ],
        })
        subs = [p.name for p in self.out_dir.iterdir() if p.is_dir()]
        self.assertEqual(len(subs), 1)
        self.assertIn("walletconnect__walletconnectv2-monorepo__", subs[0])

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
        summary = self._run({"tornado-cash/tornado-core": [adv, adv]})
        self.assertEqual(summary["records_emitted"], 1)
        self.assertEqual(summary["errors"], [])

    def test_trusted_setup_maps_governance_takeover(self) -> None:
        adv = _sample_advisory(
            severity="critical",
            summary="Trusted setup ceremony bypass on zkevm-circuits",
            description=(
                "An attacker can submit forged contributions to the trusted "
                "setup ceremony, compromising the system's soundness "
                "assumption and enabling proof forgery."
            ),
        )
        self._run({"privacy-scaling-explorations/zkevm-circuits": [adv]})
        sub = next(p for p in self.out_dir.iterdir() if p.is_dir())
        rec = json.loads((sub / "record.json").read_text())
        # "trusted setup" matches before generic "proof forgery"
        self.assertEqual(rec["impact_class"], "governance-takeover")
        self.assertEqual(rec["impact_actor"], "protocol-treasury")

    def test_no_keyword_match_default_privilege_escalation(self) -> None:
        """Privacy advisories without a keyword match default to
        privilege-escalation (anonymity-set compromise null shape)."""
        adv = _sample_advisory(
            severity="medium",
            summary="Internal refactor of helper module",
            description="Updates an internal helper module.",
        )
        self._run({"railgun-privacy/engine": [adv]})
        sub = next(p for p in self.out_dir.iterdir() if p.is_dir())
        rec = json.loads((sub / "record.json").read_text())
        self.assertEqual(rec["impact_class"], "privilege-escalation")
        self.assertEqual(rec["impact_actor"], "protocol-treasury")

    def test_mitigation_state_inferred_from_patched_versions(self) -> None:
        adv = _sample_advisory()
        self._run({"tornado-cash/tornado-core": [adv]})
        sub = next(p for p in self.out_dir.iterdir() if p.is_dir())
        rec = json.loads((sub / "record.json").read_text())
        self.assertIn("mitigation-state=mitigated", rec["attacker_action_sequence"])

        for sub in list(self.out_dir.iterdir()):
            if sub.is_dir():
                for f in sub.iterdir():
                    f.unlink()
                sub.rmdir()
        adv2 = _sample_advisory(ghsa_id="GHSA-prop-aaaa-aaaa", patched_versions="")
        adv2["vulnerabilities"] = [
            {"package": {"name": "tornado-core", "ecosystem": "npm"}}
        ]
        self._run({"tornado-cash/tornado-core": [adv2]})
        sub = next(p for p in self.out_dir.iterdir() if p.is_dir())
        rec = json.loads((sub / "record.json").read_text())
        self.assertIn("mitigation-state=proposed", rec["attacker_action_sequence"])


if __name__ == "__main__":
    unittest.main()
