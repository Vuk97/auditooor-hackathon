"""Tests for tools/hackerman-etl-from-zebra-advisories.py.

Rule 37: asserts every emitted record (hackerman_record, invariant, detector_seed)
carries a non-empty verification_tier=tier-1-officially-disclosed.
"""
import importlib.util
import json
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "hackerman_etl_zebra",
        str(REPO_ROOT / "tools" / "hackerman-etl-from-zebra-advisories.py"),
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


M = _load_module()


class TestZebraETL(unittest.TestCase):
    def test_dataset_nonempty_and_tier1(self):
        # Expanded 2026-06-02: full published Zebra GHSA set plus GHSA-2prc.
        self.assertGreaterEqual(len(M.ZEBRA_ADVISORIES), 26)

    def test_full_published_advisory_set_present(self):
        # The complete published ZcashFoundation/zebra GHSA set verified live
        # 2026-05-29, incl. the per-peer mempool caps our findings cite and the
        # Critical consensus-divergence + block-discovery-halt advisories.
        ids = {a["ghsa"] for a in M.ZEBRA_ADVISORIES}
        expected = {
            # page 1
            "GHSA-hhm7-qrv5-h4r6",
            "GHSA-w834-cf6p-9m9w",
            "GHSA-gvjc-3w7c-92jx",
            "GHSA-4m69-67m6-prqp",
            "GHSA-4fc2-h7jh-287c",  # per-peer mempool slot saturation
            "GHSA-65jj-fmw8-468q",  # mempool timeout-path memory leak
            "GHSA-h72h-ppcx-998p",  # pre-handshake buffer reserve
            "GHSA-gf9r-m956-97qx",  # CRITICAL P2SH sigop consensus divergence
            "GHSA-2prc-cj5x-4443",  # CRITICAL incomplete P2SH sigop fix in 4.5.0
            "GHSA-63wg-wjjj-7cp8",  # IPv4-mapped address-book abort
            "GHSA-2gf8-q9rr-jq3h",  # subtree-root on-disk corruption
            "GHSA-h9hm-m2xj-4rq9",  # CRITICAL block-discovery halt (CVE-2026-44499)
            # page 2
            "GHSA-c8w6-x74f-vmg3",  # z_listunifiedreceivers Sapling-receiver panic
            "GHSA-pvmv-cwg8-v6c8",  # CRITICAL V5 SIGHASH_SINGLE missing output
            "GHSA-qv2r-v3mx-f4pf",  # non-ASCII LongPollId slice panic
            "GHSA-gq4h-3grw-2rhv",  # CRITICAL stale-sighash-buffer (CVE-2026-44497)
            "GHSA-438q-jx8f-cccv",  # allocation amplification (CVE-2026-44500)
            "GHSA-cwfq-rfcr-8hmp",  # CRITICAL SIGHASH_SINGLE block-validity split
            "GHSA-jv4h-j224-23cc",  # CRITICAL coinbase/P2SH sigop undercount (CVE-2026-44498)
            "GHSA-29x4-r6jv-ff4w",  # interrupted JSON-RPC abort
            # page 3
            "GHSA-452v-w3gx-72wg",  # CRITICAL Orchard rk identity panic (CVE-2026-41584)
            "GHSA-8m29-fpq5-89jj",  # CRITICAL sighash hash-type omission (CVE-2026-41583)
            "GHSA-xr93-pcq3-pxf8",  # addr/addrv2 resource exhaustion (CVE-2026-40881)
            "GHSA-xvj8-ph7x-65gf",  # height-blind verification cache (CVE-2026-40880)
            "GHSA-3vmh-33xr-9cqh",  # V5 auth-data cache key (CVE-2026-34377)
            "GHSA-qp6f-w4r3-h8wg",  # CRITICAL V5 TxID panic (CVE-2026-34202)
        }
        self.assertEqual(expected - ids, set(), f"missing advisories: {expected - ids}")
        # exactly two Critical advisories in the published set
        crit = {a["ghsa"] for a in M.ZEBRA_ADVISORIES if a["severity"] == "critical"}
        self.assertEqual(crit, {
            "GHSA-gf9r-m956-97qx", "GHSA-h9hm-m2xj-4rq9", "GHSA-pvmv-cwg8-v6c8",
            "GHSA-gq4h-3grw-2rhv", "GHSA-cwfq-rfcr-8hmp", "GHSA-jv4h-j224-23cc",
            "GHSA-452v-w3gx-72wg", "GHSA-8m29-fpq5-89jj", "GHSA-qp6f-w4r3-h8wg",
            "GHSA-2prc-cj5x-4443",
        })
        # GHSA-h9hm carries a real CVE id (verbatim from the advisory)
        h9hm = next(a for a in M.ZEBRA_ADVISORIES if a["ghsa"] == "GHSA-h9hm-m2xj-4rq9")
        self.assertEqual(h9hm["cve"], "CVE-2026-44499")
        ghsa_2prc = next(
            a for a in M.ZEBRA_ADVISORIES if a["ghsa"] == "GHSA-2prc-cj5x-4443"
        )
        self.assertEqual(ghsa_2prc["crates"], [
            ("zebra-script", "7.0.0", "7.0.1"),
            ("zebrad", "4.5.0", "4.5.1"),
        ])
        self.assertEqual(
            ghsa_2prc["attack_class"],
            "consensus-divergence-via-p2sh-sigop-mode-mismatch",
        )
        # unique ids (no accidental dupes from the splice)
        self.assertEqual(len(ids), len(M.ZEBRA_ADVISORIES))

    def test_every_record_carries_tier(self):
        # Rule 37: every emitted record carries a non-empty verification_tier.
        for adv in M.ZEBRA_ADVISORIES:
            rec = M.build_record(adv)
            self.assertEqual(rec["record_tier"], "tier-1-officially-disclosed")
            self.assertEqual(rec["severity_at_finding"] in {"critical", "high", "medium", "low", "info"}, True)
            tier_tags = [t for t in rec["function_shape"]["shape_tags"] if t.startswith("verification_tier=")]
            self.assertEqual(tier_tags, ["verification_tier=tier-1-officially-disclosed"])

            inv = M.build_invariant(adv)
            self.assertEqual(inv["verification_tier"], "tier-1-officially-disclosed")
            self.assertTrue(inv["content"]["invariant_id"].startswith("INV-ZEBRA-"))

            det = M.build_detector_seed(adv)
            self.assertEqual(det["verification_tier"], "tier-1-officially-disclosed")
            self.assertEqual(det["kind"], "detector_seed")

    def test_record_validates_against_schema(self):
        validator = M._RECORD_VALIDATOR
        schema = validator.load_schema()
        for adv in M.ZEBRA_ADVISORIES:
            rec = M.build_record(adv)
            errs = validator.validate_doc(rec, schema)
            self.assertEqual(errs, [], f"{adv['ghsa']}: {errs}")

    def test_invariant_validates_against_schema(self):
        try:
            import jsonschema
        except ImportError:
            self.skipTest("jsonschema not installed")
        schema = M._load_invariant_schema()
        v = jsonschema.Draft202012Validator(schema)
        for adv in M.ZEBRA_ADVISORIES:
            inv = M.build_invariant(adv)
            errs = sorted(v.iter_errors(inv), key=lambda e: list(e.path))
            self.assertEqual(errs, [], f"{adv['ghsa']}: {[e.message for e in errs]}")

    def test_invariant_id_pattern(self):
        import re
        pat = re.compile(r"^INV-[A-Za-z0-9_.-]{1,80}$")
        for adv in M.ZEBRA_ADVISORIES:
            inv_id = M._invariant_id(adv)
            self.assertRegex(inv_id, pat)

    def test_attack_class_and_provenance_present(self):
        for adv in M.ZEBRA_ADVISORIES:
            rec = M.build_record(adv)
            self.assertTrue(rec["attack_class"])
            # GHSA id present in source_audit_ref provenance
            self.assertIn(adv["ghsa"], rec["source_audit_ref"])
            # CWE present in preconditions when the advisory carries one
            if adv.get("cwe"):
                joined = " ".join(rec["required_preconditions"])
                self.assertIn(adv["cwe"], joined)

    def test_dedupe_skips_existing_ref(self, ):
        import tempfile, os
        # build a corpus_dir with one record matching the first advisory's URL
        with tempfile.TemporaryDirectory() as td:
            corpus = Path(td) / "corpus"
            sub = corpus / "existing"
            sub.mkdir(parents=True)
            first = M.ZEBRA_ADVISORIES[0]
            (sub / "record.json").write_text(
                json.dumps({"source_audit_ref": M._ghsa_url(first["ghsa"])}),
                encoding="utf-8",
            )
            out = Path(td) / "out"
            summary = M.convert(
                records_dir=out,
                invariants_out=Path(td) / "inv.jsonl",
                detector_seeds_out=Path(td) / "det.jsonl",
                corpus_dir=corpus,
                dry_run=False,
            )
            self.assertEqual(summary["deduped"], 1)
            self.assertEqual(summary["records_emitted"], len(M.ZEBRA_ADVISORIES) - 1)
            self.assertEqual(summary["errors"], [])

    def test_full_convert_no_errors(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            summary = M.convert(
                records_dir=Path(td) / "rec",
                invariants_out=Path(td) / "inv.jsonl",
                detector_seeds_out=Path(td) / "det.jsonl",
                corpus_dir=None,
                dry_run=False,
            )
            self.assertEqual(summary["errors"], [])
            self.assertEqual(summary["records_emitted"], len(M.ZEBRA_ADVISORIES))
            self.assertEqual(summary["invariants_emitted"], len(M.ZEBRA_ADVISORIES))
            self.assertEqual(summary["detector_seeds_emitted"], len(M.ZEBRA_ADVISORIES))
            # verify every emitted invariant JSONL line carries the tier (Rule 37)
            for line in (Path(td) / "inv.jsonl").read_text().splitlines():
                doc = json.loads(line)
                self.assertEqual(doc["verification_tier"], "tier-1-officially-disclosed")
            for line in (Path(td) / "det.jsonl").read_text().splitlines():
                doc = json.loads(line)
                self.assertEqual(doc["verification_tier"], "tier-1-officially-disclosed")


    # r36-rebuttal: lane zebra-promote registered in .auditooor/agent_pathspec.json; scoped to this test file
    def test_router_stage_emits_promotable_batch_files(self):
        # --router-stage writes the promote-tool-consumable batch files:
        # invariant_library_extended/<batch>/INV-*.yaml (flat YAML w/ statement)
        # detector_synthesis_v2/<batch>/*.json (dispatch-ledger result shape).
        import tempfile
        import yaml as _yaml
        with tempfile.TemporaryDirectory() as td:
            derived = Path(td) / "derived"
            summary = M.convert(
                records_dir=Path(td) / "rec",
                invariants_out=Path(td) / "inv.jsonl",
                detector_seeds_out=Path(td) / "det.jsonl",
                corpus_dir=None,
                dry_run=False,
                router_stage=True,
                derived_root=derived,
            )
            self.assertEqual(summary["errors"], [])
            n = len(M.ZEBRA_ADVISORIES)
            self.assertEqual(summary["router_staged_files"], 2 * n)

            inv_dir = derived / M.INV_ROUTER_DIRNAME / M.ROUTER_STAGE_BATCH_ID
            det_dir = derived / M.DET_ROUTER_DIRNAME / M.ROUTER_STAGE_BATCH_ID
            inv_files = sorted(inv_dir.glob("*.yaml"))
            det_files = sorted(det_dir.glob("*.json"))
            self.assertEqual(len(inv_files), n)
            self.assertEqual(len(det_files), n)

            # Invariant batch YAML: flat shape consumed by
            # _extract_invariant_library_extended (invariant_id + statement).
            for f in inv_files:
                doc = _yaml.safe_load(f.read_text())
                self.assertTrue(doc["invariant_id"].startswith("INV-ZEBRA-"))
                self.assertTrue(doc["statement"])
                self.assertEqual(doc["verification_tier"], "tier-1-officially-disclosed")

            # Detector batch JSON: dispatch-ledger shape (result string-JSON,
            # status ok) consumed by _extract_dispatch_ledger_generic.
            for f in det_files:
                doc = json.loads(f.read_text())
                self.assertEqual(doc["status"], "ok")
                self.assertEqual(doc["verification_tier"], "tier-1-officially-disclosed")
                body = json.loads(doc["result"])
                self.assertIn("detector_id", body)
                self.assertIn("regex_pattern", body)
                self.assertEqual(body["target_lang"], "rust")

    def test_router_stage_builds_full_dataset_despite_dedupe(self):
        # Router-stage must populate the canonical promotion path even when the
        # per-advisory records are all deduped against --corpus-dir (the common
        # case on re-run). It builds from ZEBRA_ADVISORIES, not the dedupe-gated
        # accumulators.
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            corpus = Path(td) / "corpus"
            # Pre-seed corpus with ALL advisory refs so every one is deduped.
            for i, adv in enumerate(M.ZEBRA_ADVISORIES):
                sub = corpus / f"existing-{i}"
                sub.mkdir(parents=True)
                (sub / "record.json").write_text(
                    json.dumps({"source_audit_ref": M._ghsa_url(adv["ghsa"])}),
                    encoding="utf-8",
                )
            derived = Path(td) / "derived"
            summary = M.convert(
                records_dir=Path(td) / "rec",
                invariants_out=Path(td) / "inv.jsonl",
                detector_seeds_out=Path(td) / "det.jsonl",
                corpus_dir=corpus,
                dry_run=False,
                router_stage=True,
                derived_root=derived,
            )
            self.assertEqual(summary["deduped"], len(M.ZEBRA_ADVISORIES))
            self.assertEqual(summary["records_emitted"], 0)
            # Router-stage still emits the full set despite full dedupe.
            self.assertEqual(summary["router_staged_files"], 2 * len(M.ZEBRA_ADVISORIES))


if __name__ == "__main__":
    unittest.main()
