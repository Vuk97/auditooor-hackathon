"""Tests for tools/external-findings-miner.py.

M14 discipline: fixtures are derived VERBATIM from real Solodit MCP output
(see tools/tests/fixtures/external_findings_miner/reentrancy_solodit.md).
No fabricated finding text. A backtest miss is asserted as a miss.
"""
import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
TOOL = ROOT / "tools" / "external-findings-miner.py"
FIX = ROOT / "tools" / "tests" / "fixtures" / "external_findings_miner"
SCHEMAS = ROOT / "audit" / "corpus_tags" / "schemas"

spec = importlib.util.spec_from_file_location("efm", TOOL)
efm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(efm)


def _findings(*objs):
    out = []
    for o in objs:
        n = efm._norm_finding(o)
        assert n is not None
        out.append(n)
    return out


class TestParsing(unittest.TestCase):
    def test_md_fixture_parses_three_findings(self):
        text = (FIX / "reentrancy_solodit.md").read_text()
        fs = efm.parse_findings_md(text)
        self.assertEqual(len(fs), 3)
        ids = {f["id"] for f in fs}
        self.assertEqual(ids, {"30447", "35121", "21040"})

    def test_md_extracts_source_url_and_firm(self):
        text = (FIX / "reentrancy_solodit.md").read_text()
        fs = {f["id"]: f for f in efm.parse_findings_md(text)}
        self.assertTrue(fs["30447"]["source_url"].startswith("https://github.com/sherlock-audit"))
        self.assertEqual(fs["30447"]["firm"], "Sherlock")
        self.assertEqual(fs["30447"]["protocol"], "Arcadia")

    def test_finding_without_source_url_is_dropped(self):
        # tier-2 honesty: no URL -> no record
        n = efm._norm_finding({"id": "1", "title": "x", "content": "y"})
        self.assertIsNone(n)

    def test_json_list_and_wrapped_dict(self):
        obj = {"id": "9", "title": "t", "content": "c", "url": "https://solodit.cyfrin.io/issues/x"}
        self.assertEqual(len(efm.parse_findings_json(json.dumps([obj]))), 1)
        self.assertEqual(len(efm.parse_findings_json(json.dumps({"findings": [obj]}))), 1)
        self.assertEqual(len(efm.parse_findings_json(json.dumps(obj))), 1)

    def test_single_get_finding_block(self):
        text = (
            "# [HIGH] Reentrancy to UnicrowClaim can claim twice\n"
            "| Field | Value |\n|-------|-------|\n"
            "| Firm | AuditOne |\n| Protocol | Unicrow |\n"
            "| Solodit | https://solodit.cyfrin.io/issues/reentrancy-unicrow |\n\n"
            "Body with `singleClaim()` and `nonReentrant`."
        )
        fs = efm.parse_findings_md(text)
        self.assertEqual(len(fs), 1)
        self.assertEqual(fs[0]["firm"], "AuditOne")


class TestRecord(unittest.TestCase):
    def setUp(self):
        self.fs = efm.parse_findings_md((FIX / "reentrancy_solodit.md").read_text())

    def test_record_tier_is_tier2(self):
        frow = efm.family_row("reentrancy")
        rec = efm.build_record("reentrancy", self.fs[0], frow)
        self.assertEqual(rec["verification_tier"], "tier-2-verified-public-archive")

    def test_record_excerpt_is_verbatim_substring(self):
        # M14: the excerpt MUST be a literal slice of the finding content
        frow = efm.family_row("reentrancy")
        rec = efm.build_record("reentrancy", self.fs[2], frow)
        self.assertIn(rec["attacker_action_sequence"], self.fs[2]["content"])

    def test_record_carries_source_ref(self):
        frow = efm.family_row("reentrancy")
        rec = efm.build_record("reentrancy", self.fs[0], frow)
        self.assertTrue(rec["source_audit_ref"].startswith("http"))


class TestGeneralizedInvariant(unittest.TestCase):
    def test_invariant_is_cross_domain_and_protocol_agnostic(self):
        fs = efm.parse_findings_md((FIX / "reentrancy_solodit.md").read_text())
        frow = efm.family_row("reentrancy")
        inv = efm.build_generalized_invariant("reentrancy", fs, frow)
        self.assertEqual(inv["abstraction_level"], "cross-domain")
        # no protocol name from the inputs leaks into the generalized statement
        low = inv["statement"].lower()
        self.assertNotIn("arcadia", low)
        self.assertNotIn("unicrow", low)
        self.assertNotIn("notional", low)
        self.assertEqual(inv["category"], "atomicity")
        self.assertEqual(inv["source_count"], 3)

    def test_family_keyword_variants_map_same_row(self):
        for fam in ("oracle-staleness", "stale oracle price", "oracle"):
            self.assertEqual(efm.family_row(fam)["category"], "freshness")

    def test_unknown_family_uses_fallback(self):
        row = efm.family_row("some-novel-thing-xyz")
        self.assertEqual(row["category"], "ordering")
        self.assertIn("validation", row["statement"].lower())


class TestDetectorSeedAndBacktest(unittest.TestCase):
    def setUp(self):
        self.fs = efm.parse_findings_md((FIX / "reentrancy_solodit.md").read_text())
        self.frow = efm.family_row("reentrancy")

    def test_seed_tokens_are_verbatim_substrings(self):
        seed = efm.build_detector_seed("reentrancy", self.fs, 2, self.frow)
        for t in seed["tokens"]:
            tok = t["token"].rstrip("(")  # ident tokens stored with trailing (
            # the token must appear literally in at least one finding
            self.assertTrue(any(tok in f["content"] for f in self.fs),
                            f"token {tok!r} not verbatim in any finding")

    def test_recurring_token_threshold(self):
        seed = efm.build_detector_seed("reentrancy", self.fs, 2, self.frow)
        for t in seed["tokens"]:
            self.assertGreaterEqual(t["distinct_finding_hits"], 2)

    def test_backtest_strong_recall_on_self_corpus(self):
        seed = efm.build_detector_seed("reentrancy", self.fs, 2, self.frow)
        bt = efm.backtest_seed(seed, self.fs)
        self.assertEqual(bt["verdict"], "strong-recall")
        self.assertEqual(bt["recall"], 1.0)
        self.assertEqual(bt["matched"], 3)

    def test_backtest_miss_is_reported_honestly(self):
        # high recurrence threshold -> no token recurs -> empty seed -> miss
        seed = efm.build_detector_seed("reentrancy", self.fs, 99, self.frow)
        self.assertEqual(seed["regex"], "")
        bt = efm.backtest_seed(seed, self.fs)
        self.assertEqual(bt["verdict"], "no-seed-no-recall")
        self.assertEqual(bt["matched"], 0)
        self.assertEqual(set(bt["missed_finding_ids"]), {"30447", "35121", "21040"})

    def test_backtest_partial_recall_counts_misses(self):
        # one finding shares no recurring token with the others
        odd = efm._norm_finding({
            "id": "999", "title": "unrelated", "severity": "HIGH",
            "content": "totally different prose with `uniqueThing()` only",
            "url": "https://solodit.cyfrin.io/issues/odd",
        })
        fs = self.fs + [odd]
        seed = efm.build_detector_seed("reentrancy", fs, 2, self.frow)
        bt = efm.backtest_seed(seed, fs)
        # the odd finding is NOT matched -> honest miss recorded
        self.assertIn("999", bt["missed_finding_ids"])
        self.assertLess(bt["recall"], 1.0)


class TestSchemaConformance(unittest.TestCase):
    def _validate(self, obj, schema_file):
        try:
            import jsonschema
        except ImportError:
            self.skipTest("jsonschema not installed")
        schema = json.loads((SCHEMAS / schema_file).read_text())
        jsonschema.validate(obj, schema)

    def test_invariant_conforms_to_candidate_schema(self):
        fs = efm.parse_findings_md((FIX / "reentrancy_solodit.md").read_text())
        frow = efm.family_row("reentrancy")
        inv = efm.build_generalized_invariant("reentrancy", fs, frow)
        self._validate(inv, "auditooor.invariant_candidate.v1.schema.json")

    def test_record_has_required_v12_fields(self):
        fs = efm.parse_findings_md((FIX / "reentrancy_solodit.md").read_text())
        frow = efm.family_row("reentrancy")
        rec = efm.build_record("reentrancy", fs[0], frow)
        for field in ("schema_version", "record_id", "verification_tier"):
            self.assertIn(field, rec)
        self.assertEqual(rec["schema_version"], "auditooor.hackerman_record.v1.2")


class TestEndToEnd(unittest.TestCase):
    def test_main_no_usable_findings_exits_2(self):
        import tempfile, os
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            json.dump([{"id": "1", "title": "no url", "content": "x"}], fh)
            path = fh.name
        try:
            rc = efm.main(["--family", "reentrancy", "--findings-json", path])
            self.assertEqual(rc, 2)
        finally:
            os.unlink(path)

    def test_main_dry_run_writes_nothing_exits_0(self):
        rc = efm.main([
            "--family", "reentrancy",
            "--findings-md", str(FIX / "reentrancy_solodit.md"),
            "--dry-run",
        ])
        self.assertEqual(rc, 0)


if __name__ == "__main__":
    unittest.main()
