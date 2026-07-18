# r36-rebuttal: lane advisory-generic-miner registered in .auditooor/agent_pathspec.json
"""Tests for tools/hackerman-etl-from-advisories.py (generic repo-agnostic miner).

Covers (offline, deterministic - no live gh api):
  * record + GENERALIZED invariant + detector_seed triple emitted per advisory
  * Rule 37: every emitted record/invariant/detector carries tier-1-officially-disclosed
  * CWE-anchored generalization is target-agnostic (no repo/package name leaks
    into the invariant_text)
  * no-CWE fallback generalization (impact-keyword derived)
  * verbatim transcription: advisory summary preserved on the record + invariant
  * --extra-cve verified vs unverified (R37: unverified reported, never baked)
  * dedupe by source_audit_ref
  * record validates against auditooor.hackerman_record.v1 schema
  * invariant validates against auditooor.invariant.v1 schema
  * zebra entrypoint delegation (--delegate-generic path) over a cache fixture
"""
import importlib.util
import json
import re
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


def _load(name: str, rel: str):
    spec = importlib.util.spec_from_file_location(name, str(REPO_ROOT / rel))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


M = _load("hackerman_etl_advisories", "tools/hackerman-etl-from-advisories.py")
ZEBRA = _load("hackerman_etl_zebra_deleg", "tools/hackerman-etl-from-zebra-advisories.py")


# A deterministic offline fixture in the GitHub Security Advisories REST shape.
# Mix of CWEs (memory-leak / panic / consensus-divergence) + a no-CWE advisory.
SAMPLE_ADVISORIES = [
    {
        "ghsa_id": "GHSA-test-leak-0001",
        "summary": "Unbounded memory leak in mempool cancel_handles map on timeout.",
        "description": "The cancel_handles map fails to clean up on the timeout path.",
        "severity": "medium",
        "cve_id": "CVE-2099-0001",
        "html_url": "https://github.com/acme/widget/security/advisories/GHSA-test-leak-0001",
        "published_at": "2099-01-15T00:00:00Z",
        "state": "published",
        "cwes": [{"cwe_id": "CWE-401", "name": "Missing Release of Memory"}],
        "vulnerabilities": [
            {"package": {"name": "widget-net"}, "vulnerable_version_range": "<5.0.0", "patched_versions": "5.0.0"},
        ],
    },
    {
        "ghsa_id": "GHSA-test-panic-0002",
        "summary": "RPC handler panics via .expect() on a crafted Sapling receiver.",
        "description": "Under panic=abort this terminates the node.",
        "severity": "high",
        "cve_id": None,
        "html_url": "https://github.com/acme/widget/security/advisories/GHSA-test-panic-0002",
        "published_at": "2099-02-01T00:00:00Z",
        "state": "published",
        "cwes": [{"cwe_id": "CWE-617", "name": "Reachable Assertion"}],
        "vulnerabilities": [
            {"package": {"name": "widget-rpc"}, "vulnerable_version_range": "<=7.0.0", "patched_versions": "8.0.0"},
        ],
    },
    {
        "ghsa_id": "GHSA-test-consensus-0003",
        "summary": "Consensus divergence via sigop undercount on disabled opcodes.",
        "description": "Reference impl counts through disabled opcodes; this one stops early.",
        "severity": "critical",
        "cve_id": "CVE-2099-0003",
        "html_url": "https://github.com/acme/widget/security/advisories/GHSA-test-consensus-0003",
        "published_at": "2099-03-01T00:00:00Z",
        "state": "published",
        "cwes": [{"cwe_id": "CWE-684", "name": "Incorrect Provision of Specified Functionality"}],
        "vulnerabilities": [
            {"package": {"name": "widget-script"}, "vulnerable_version_range": "<6.0.0", "patched_versions": "6.0.0"},
        ],
    },
    {
        "ghsa_id": "GHSA-test-nocwe-0004",
        "summary": "Denial of service via interrupted request causing process abort.",
        "description": "No first-class CWE published for this advisory.",
        "severity": "medium",
        "cve_id": None,
        "html_url": "https://github.com/acme/widget/security/advisories/GHSA-test-nocwe-0004",
        "published_at": "2099-04-01T00:00:00Z",
        "state": "published",
        "cwes": [],
        "vulnerabilities": [
            {"package": {"name": "widget-rpc"}, "vulnerable_version_range": "<4.3.1", "patched_versions": "4.3.1"},
        ],
    },
]

REPO = "acme/widget"


def _convert(td, **kw):
    defaults = dict(
        repo=REPO,
        records_dir=Path(td) / "rec",
        invariants_out=Path(td) / "inv.jsonl",
        detector_seeds_out=Path(td) / "det.jsonl",
        corpus_dir=None,
        dry_run=False,
        ecosystem="crates.io",
        target_domain="l1-client",
        advisories=SAMPLE_ADVISORIES,
    )
    defaults.update(kw)
    return M.convert(**defaults)


class TestGenericAdvisoryETL(unittest.TestCase):
    def test_triple_emitted_per_advisory(self):
        with tempfile.TemporaryDirectory() as td:
            s = _convert(td)
            self.assertEqual(s["errors"], [])
            self.assertEqual(s["records_emitted"], len(SAMPLE_ADVISORIES))
            self.assertEqual(s["invariants_emitted"], len(SAMPLE_ADVISORIES))
            self.assertEqual(s["detector_seeds_emitted"], len(SAMPLE_ADVISORIES))

    def test_rule37_tier_on_every_artifact(self):
        for adv in SAMPLE_ADVISORIES:
            rec = M.build_record(adv, repo=REPO, target_domain="l1-client", target_language="rust")
            self.assertEqual(rec["record_tier"], "tier-1-officially-disclosed")
            tier_tags = [t for t in rec["function_shape"]["shape_tags"] if t.startswith("verification_tier=")]
            self.assertEqual(tier_tags, ["verification_tier=tier-1-officially-disclosed"])

            inv = M.build_invariant(adv, repo=REPO, target_language="rust")
            self.assertEqual(inv["verification_tier"], "tier-1-officially-disclosed")
            self.assertTrue(inv["content"]["invariant_id"].startswith("INV-"))

            det = M.build_detector_seed(adv, repo=REPO, target_language="rust")
            self.assertEqual(det["verification_tier"], "tier-1-officially-disclosed")
            self.assertEqual(det["kind"], "detector_seed")

        # JSONL lines carry the tier too
        with tempfile.TemporaryDirectory() as td:
            _convert(td)
            for line in (Path(td) / "inv.jsonl").read_text().splitlines():
                self.assertEqual(json.loads(line)["verification_tier"], "tier-1-officially-disclosed")
            for line in (Path(td) / "det.jsonl").read_text().splitlines():
                self.assertEqual(json.loads(line)["verification_tier"], "tier-1-officially-disclosed")

    def test_generalized_invariant_is_target_agnostic(self):
        # The GENERALIZED invariant_text must NOT leak the repo / package /
        # GHSA-id specificity - it is a reusable hunt hypothesis.
        leaky = ["acme", "widget", "widget-net", "widget-rpc", "widget-script", "ghsa-test"]
        for adv in SAMPLE_ADVISORIES:
            inv = M.build_invariant(adv, repo=REPO, target_language="rust")
            text = inv["content"]["invariant_text"].lower()
            for token in leaky:
                self.assertNotIn(token, text, f"{adv['ghsa_id']}: invariant leaked '{token}'")
            self.assertTrue(inv["content"]["reusable_as_hunt_hypothesis"])
            # provenance: verbatim summary preserved on the invariant
            self.assertIn(adv["summary"][:20], inv["content"]["source_advisory_summary_verbatim"])

    def test_cwe_drives_generalization(self):
        # CWE-401 advisory -> memory-leak generalization; CWE-684 -> consensus.
        leak = M.build_invariant(SAMPLE_ADVISORIES[0], repo=REPO, target_language="rust")
        self.assertIn("removed on ALL exit paths", leak["content"]["invariant_text"])
        self.assertIn("CWE-401", leak["content"]["generalization_basis"])

        consensus = M.build_invariant(SAMPLE_ADVISORIES[2], repo=REPO, target_language="rust")
        self.assertIn("reference", consensus["content"]["invariant_text"].lower())
        self.assertIn("CWE-684", consensus["content"]["generalization_basis"])

    def test_no_cwe_fallback(self):
        # The no-CWE advisory still emits a valid triple via the impact-keyword
        # fallback generalization (marked as such in the basis).
        adv = SAMPLE_ADVISORIES[3]
        inv = M.build_invariant(adv, repo=REPO, target_language="rust")
        self.assertIn("no first-class CWE", inv["content"]["generalization_basis"])
        rec = M.build_record(adv, repo=REPO, target_domain="l1-client", target_language="rust")
        self.assertEqual(rec["impact_class"], "dos")

    def test_verbatim_summary_preserved_on_record(self):
        for adv in SAMPLE_ADVISORIES:
            rec = M.build_record(adv, repo=REPO, target_domain="l1-client", target_language="rust")
            self.assertIn(adv["summary"][:20], rec["attacker_action_sequence"])
            # provenance markers
            self.assertIn(adv["ghsa_id"], rec["source_audit_ref"])
            self.assertIn("source=github-security-advisory", rec["attacker_action_sequence"])

    def test_record_validates_against_schema(self):
        v = M._RECORD_VALIDATOR
        schema = v.load_schema()
        for adv in SAMPLE_ADVISORIES:
            rec = M.build_record(adv, repo=REPO, target_domain="l1-client", target_language="rust")
            errs = v.validate_doc(rec, schema)
            self.assertEqual(errs, [], f"{adv['ghsa_id']}: {errs}")

    def test_invariant_validates_against_schema(self):
        try:
            import jsonschema
        except ImportError:
            self.skipTest("jsonschema not installed")
        schema = M._load_invariant_schema()
        v = jsonschema.Draft202012Validator(schema)
        for adv in SAMPLE_ADVISORIES:
            inv = M.build_invariant(adv, repo=REPO, target_language="rust")
            errs = sorted(v.iter_errors(inv), key=lambda e: list(e.path))
            self.assertEqual(errs, [], f"{adv['ghsa_id']}: {[e.message for e in errs]}")

    def test_invariant_id_pattern(self):
        pat = re.compile(r"^INV-[A-Za-z0-9_.-]{1,80}$")
        for adv in SAMPLE_ADVISORIES:
            inv_id = M._invariant_id(REPO, adv["ghsa_id"])
            self.assertRegex(inv_id, pat)

    def test_extra_cve_verified_vs_unverified(self):
        # CVE-2099-0001 is referenced by advisory 0; CVE-9999-9999 is not.
        with tempfile.TemporaryDirectory() as td:
            s = _convert(td, extra_cves=["CVE-2099-0001", "CVE-9999-9999"])
            self.assertIn("CVE-2099-0001", s["verified_extra_cves"])
            self.assertIn("CVE-9999-9999", s["unverified_extra_cves"])
            # R37: the unverified CVE is reported, never baked into a record.
            self.assertNotIn("CVE-9999-9999", json.dumps(s["files"]))

    def test_dedupe_by_source_ref(self):
        with tempfile.TemporaryDirectory() as td:
            corpus = Path(td) / "corpus"
            sub = corpus / "existing"
            sub.mkdir(parents=True)
            first = SAMPLE_ADVISORIES[0]
            (sub / "record.json").write_text(
                json.dumps({"source_audit_ref": first["html_url"]}), encoding="utf-8"
            )
            s = _convert(td, corpus_dir=corpus)
            self.assertEqual(s["deduped"], 1)
            self.assertEqual(s["records_emitted"], len(SAMPLE_ADVISORIES) - 1)
            self.assertEqual(s["errors"], [])

    def test_honest_zero_on_empty_repo(self):
        with tempfile.TemporaryDirectory() as td:
            s = _convert(td, advisories=[])
            self.assertEqual(s["records_emitted"], 0)
            self.assertEqual(s["invariants_emitted"], 0)
            self.assertEqual(s["errors"], [])

    def test_cache_file_list_and_mapping_shapes(self):
        with tempfile.TemporaryDirectory() as td:
            # bare list shape
            lst = Path(td) / "list.json"
            lst.write_text(json.dumps(SAMPLE_ADVISORIES), encoding="utf-8")
            self.assertEqual(len(M.load_advisories(REPO, cache_file=lst)), len(SAMPLE_ADVISORIES))
            # {repo: [...]} mapping shape
            mp = Path(td) / "map.json"
            mp.write_text(json.dumps({REPO: SAMPLE_ADVISORIES}), encoding="utf-8")
            self.assertEqual(len(M.load_advisories(REPO, cache_file=mp)), len(SAMPLE_ADVISORIES))
            # repo absent from mapping -> honest empty
            self.assertEqual(M.load_advisories("other/repo", cache_file=mp), [])

    def test_skips_non_published(self):
        adv = dict(SAMPLE_ADVISORIES[0])
        adv["state"] = "draft"
        with tempfile.TemporaryDirectory() as td:
            s = _convert(td, advisories=[adv])
            self.assertEqual(s["records_emitted"], 0)
            self.assertEqual(s["skipped_non_published"], 1)

    def test_ecosystem_sets_language(self):
        with tempfile.TemporaryDirectory() as td:
            s = _convert(td, ecosystem="npm", advisories=[SAMPLE_ADVISORIES[0]])
            self.assertEqual(s["target_language"], "typescript-onchain")
            self.assertEqual(s["errors"], [])


class TestZebraDelegation(unittest.TestCase):
    def test_zebra_delegates_to_generic_over_cache(self):
        # The zebra entrypoint's delegate path runs the generic engine with
        # repo=ZcashFoundation/zebra over a deterministic cache fixture.
        with tempfile.TemporaryDirectory() as td:
            cache = Path(td) / "zebra-cache.json"
            cache.write_text(json.dumps({ZEBRA.ZEBRA_REPO: SAMPLE_ADVISORIES}), encoding="utf-8")
            s = ZEBRA.delegate_to_generic(
                records_dir=Path(td) / "rec",
                invariants_out=Path(td) / "inv.jsonl",
                detector_seeds_out=Path(td) / "det.jsonl",
                corpus_dir=None,
                dry_run=False,
                cache_file=cache,
            )
            self.assertEqual(s["repo"], "ZcashFoundation/zebra")
            self.assertEqual(s["records_emitted"], len(SAMPLE_ADVISORIES))
            self.assertEqual(s["errors"], [])
            # invariant ids are owner-tokened (INV-ZCASHFOUNDATION-...)
            for line in (Path(td) / "inv.jsonl").read_text().splitlines():
                self.assertTrue(json.loads(line)["content"]["invariant_id"].startswith("INV-ZCASHFOUNDATION-"))

    def test_zebra_baked_path_still_works(self):
        # The baked ZEBRA_ADVISORIES convert() path is untouched by delegation.
        with tempfile.TemporaryDirectory() as td:
            s = ZEBRA.convert(
                records_dir=Path(td) / "rec",
                invariants_out=Path(td) / "inv.jsonl",
                detector_seeds_out=Path(td) / "det.jsonl",
                corpus_dir=None,
                dry_run=False,
            )
            self.assertEqual(s["errors"], [])
            self.assertEqual(s["records_emitted"], len(ZEBRA.ZEBRA_ADVISORIES))


if __name__ == "__main__":
    unittest.main()
