# <!-- r36-rebuttal: lane advisory-corpus-completeness registered in .auditooor/agent_pathspec.json -->
"""Tests for tools/advisory-corpus-completeness-check.py (MechanizeGate #4).

Calibration fixtures mirror the WHAT_WE_KEEP_MISSING #8 Zebra anchor: the
miner baked only N of M published GHSAs, so the corpus was incomplete and the
originality check was a false-clean. These tests build a synthetic published
advisory set (cache-file) + a synthetic corpus tag dir (record.json tree) and
assert every verdict branch:

  pass-advisory-corpus-complete    (25-of-25 ingested)
  fail-advisory-corpus-incomplete  (4-of-25 ingested -> 21 missing listed)
  fail-no-published-advisories     (no cache, no live -> unverifiable)
  fail-corpus-dir-missing          (published>0, corpus dir absent)
  pass (0 published, cache present) (honest empty advisory repo)
  ok-rebuttal                      (gap accepted via bounded marker)
  error                            (loader failure)

<!-- r36-rebuttal: lane advisory-corpus-completeness registered in .auditooor/agent_pathspec.json -->
"""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

TOOL = Path(__file__).resolve().parents[1] / "advisory-corpus-completeness-check.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location("_adv_corpus_completeness_check", str(TOOL))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


MOD = _load_tool()

REPO = "ZcashFoundation/zebra"


def _ghsa(n: int) -> str:
    """Deterministic well-formed GHSA-xxxx-xxxx-xxxx id for index n."""
    # base32-ish, 4-4-4 lowercase
    chars = "abcdefghjkmnpqrstuvwxyz23456789"
    s = f"{n:012d}"
    # map digits into the GHSA charset deterministically
    body = "".join(chars[int(c) % len(chars)] for c in s)
    return f"GHSA-{body[0:4]}-{body[4:8]}-{body[8:12]}"


def _published_cache(path: Path, ids):
    """Write a cache-file payload (the {repo:[advisory,...]} shape)."""
    advisories = [
        {
            "ghsa_id": gid,
            "html_url": f"https://github.com/{REPO}/security/advisories/{gid}",
            "severity": "high",
            "summary": f"synthetic advisory {gid}",
            "state": "published",
        }
        for gid in ids
    ]
    path.write_text(json.dumps({REPO: advisories}, indent=2), encoding="utf-8")


def _ingest_corpus(records_dir: Path, ids):
    """Write one corpus record.json per GHSA id (mirroring the miner emit shape)."""
    records_dir.mkdir(parents=True, exist_ok=True)
    for gid in ids:
        sub = records_dir / f"zebra__{gid.lower()}"
        sub.mkdir(parents=True, exist_ok=True)
        rec = {
            "schema_version": "auditooor.hackerman_record.v1",
            "record_id": f"adv:zebra:{gid.lower()}:deadbeef0000",
            "source_audit_ref": f"https://github.com/{REPO}/security/advisories/{gid}",
            "function_shape": {"shape_tags": [gid.lower(), "verification_tier=tier-1-officially-disclosed"]},
        }
        (sub / "record.json").write_text(json.dumps(rec, indent=2), encoding="utf-8")


class AdvisoryCorpusCompletenessTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.published_ids = [_ghsa(i) for i in range(25)]
        # sanity: all ids are well-formed and unique
        self.assertEqual(len(set(self.published_ids)), 25)
        for gid in self.published_ids:
            self.assertIsNotNone(MOD.normalize_ghsa(gid), gid)

    def tearDown(self):
        self._tmp.cleanup()

    # --- 25-of-25 -> pass ---------------------------------------------------
    def test_complete_25_of_25_passes(self):
        cache = self.tmp / "published.json"
        _published_cache(cache, self.published_ids)
        records = self.tmp / "corpus"
        _ingest_corpus(records, self.published_ids)

        out = MOD.check_completeness(
            repo=REPO, records_dir=records, cache_file=cache
        )
        self.assertEqual(out["verdict"], "pass-advisory-corpus-complete", out)
        self.assertEqual(out["exit_code"], 0)
        self.assertEqual(out["published_count"], 25)
        self.assertEqual(out["ingested_count"], 25)
        self.assertEqual(out["missing_ghsa_ids"], [])

    # --- 4-of-25 -> fail listing the 21 missing -----------------------------
    def test_incomplete_4_of_25_fails_lists_21_missing(self):
        cache = self.tmp / "published.json"
        _published_cache(cache, self.published_ids)
        records = self.tmp / "corpus"
        # ingest only the first 4 published advisories (the Zebra anchor shape)
        _ingest_corpus(records, self.published_ids[:4])

        out = MOD.check_completeness(
            repo=REPO, records_dir=records, cache_file=cache
        )
        self.assertEqual(out["verdict"], "fail-advisory-corpus-incomplete", out)
        self.assertEqual(out["exit_code"], 1)
        self.assertEqual(out["published_count"], 25)
        self.assertEqual(out["ingested_count"], 4)
        self.assertEqual(len(out["missing_ghsa_ids"]), 21)
        # the missing set is exactly the 21 not-ingested published ids
        expected_missing = sorted(g.upper() for g in self.published_ids[4:])
        self.assertEqual(out["missing_ghsa_ids"], expected_missing)
        # and the 4 ingested are NOT in the missing list
        for gid in self.published_ids[:4]:
            self.assertNotIn(gid.upper(), out["missing_ghsa_ids"])

    # --- rebuttal flips the 4-of-25 fail to ok-rebuttal ---------------------
    def test_rebuttal_flips_incomplete_to_ok(self):
        cache = self.tmp / "published.json"
        _published_cache(cache, self.published_ids)
        records = self.tmp / "corpus"
        _ingest_corpus(records, self.published_ids[:4])

        out = MOD.check_completeness(
            repo=REPO,
            records_dir=records,
            cache_file=cache,
            rebuttal="advisory-corpus-rebuttal: M14/R37 anti-fabrication; remaining 21 unverifiable",
        )
        self.assertEqual(out["verdict"], "ok-rebuttal", out)
        self.assertEqual(out["underlying_verdict"], "fail-advisory-corpus-incomplete")
        self.assertEqual(out["exit_code"], 0)

    def test_rebuttal_does_not_flip_a_pass(self):
        cache = self.tmp / "published.json"
        _published_cache(cache, self.published_ids)
        records = self.tmp / "corpus"
        _ingest_corpus(records, self.published_ids)
        out = MOD.check_completeness(
            repo=REPO,
            records_dir=records,
            cache_file=cache,
            rebuttal="advisory-corpus-rebuttal: not needed",
        )
        self.assertEqual(out["verdict"], "pass-advisory-corpus-complete", out)

    def test_oversized_rebuttal_ignored(self):
        cache = self.tmp / "published.json"
        _published_cache(cache, self.published_ids)
        records = self.tmp / "corpus"
        _ingest_corpus(records, self.published_ids[:4])
        out = MOD.check_completeness(
            repo=REPO,
            records_dir=records,
            cache_file=cache,
            rebuttal="advisory-corpus-rebuttal: " + ("x" * 250),
        )
        self.assertEqual(out["verdict"], "fail-advisory-corpus-incomplete", out)
        self.assertEqual(out["exit_code"], 1)

    # --- corpus dir absent, published>0 -> fail-corpus-dir-missing ----------
    def test_corpus_dir_missing_fails(self):
        cache = self.tmp / "published.json"
        _published_cache(cache, self.published_ids)
        records = self.tmp / "does_not_exist"
        out = MOD.check_completeness(
            repo=REPO, records_dir=records, cache_file=cache
        )
        self.assertEqual(out["verdict"], "fail-corpus-dir-missing", out)
        self.assertEqual(out["exit_code"], 1)

    # --- 0 published with cache present -> trivially complete (pass) --------
    def test_zero_published_with_cache_passes(self):
        cache = self.tmp / "published.json"
        _published_cache(cache, [])
        records = self.tmp / "corpus_empty"
        records.mkdir(parents=True, exist_ok=True)
        out = MOD.check_completeness(
            repo=REPO, records_dir=records, cache_file=cache
        )
        self.assertEqual(out["verdict"], "pass-advisory-corpus-complete", out)
        self.assertEqual(out["exit_code"], 0)
        self.assertEqual(out["published_count"], 0)

    # --- published unknown (no cache, live returned nothing) -> fail-close --
    def test_published_unknown_fails_closed(self):
        records = self.tmp / "corpus"
        _ingest_corpus(records, self.published_ids[:4])
        # advisories=[] simulates a live fetch that returned nothing AND no cache
        out = MOD.check_completeness(
            repo=REPO, records_dir=records, cache_file=None, advisories=[]
        )
        self.assertEqual(out["verdict"], "fail-no-published-advisories", out)
        self.assertEqual(out["exit_code"], 1)

    # --- loader failure -> error (fail-close) -------------------------------
    def test_loader_failure_errors_closed(self):
        # nonexistent cache file forces miner.load_advisories to raise
        records = self.tmp / "corpus"
        _ingest_corpus(records, self.published_ids)
        out = MOD.check_completeness(
            repo=REPO,
            records_dir=records,
            cache_file=self.tmp / "no-such-cache.json",
        )
        self.assertEqual(out["verdict"], "error", out)
        self.assertEqual(out["exit_code"], 1)

    # --- GHSA extraction fallbacks ------------------------------------------
    def test_ghsa_extracted_from_record_id_fallback(self):
        gid = _ghsa(7)
        records = self.tmp / "corpus_fallback"
        sub = records / "rec"
        sub.mkdir(parents=True)
        # only record_id carries the GHSA (no source_audit_ref, no shape_tags)
        (sub / "record.json").write_text(
            json.dumps({"record_id": f"adv:zebra:{gid.lower()}:abc"}), encoding="utf-8"
        )
        ids, count = MOD.ingested_ghsa_ids(records)
        self.assertEqual(count, 1)
        self.assertIn(gid.upper(), ids)

    def test_ghsa_extracted_from_shape_tags_fallback(self):
        gid = _ghsa(9)
        records = self.tmp / "corpus_tags"
        sub = records / "rec"
        sub.mkdir(parents=True)
        (sub / "record.json").write_text(
            json.dumps({"function_shape": {"shape_tags": [gid.lower(), "other"]}}),
            encoding="utf-8",
        )
        ids, count = MOD.ingested_ghsa_ids(records)
        self.assertEqual(count, 1)
        self.assertIn(gid.upper(), ids)

    # --- target resolution --------------------------------------------------
    def test_resolve_owner_repo_shape(self):
        self.assertEqual(MOD.resolve_target_repo("paradigmxyz/reth"), "paradigmxyz/reth")

    def test_resolve_workspace_marker(self):
        ws = self.tmp / "ws"
        (ws / ".auditooor").mkdir(parents=True)
        (ws / ".auditooor" / "advisory_target").write_text(
            "# the target repo\nparadigmxyz/reth\n", encoding="utf-8"
        )
        self.assertEqual(MOD.resolve_target_repo(str(ws)), "paradigmxyz/reth")

    def test_resolve_bare_workspace_no_marker_returns_none(self):
        ws = self.tmp / "ws2"
        ws.mkdir()
        self.assertIsNone(MOD.resolve_target_repo(str(ws)))

    def test_default_records_dir_shape(self):
        d = MOD.default_records_dir("ZcashFoundation/zebra")
        self.assertEqual(d.name, "zcashfoundation_zebra_advisories")

    # --- CLI end-to-end (exit codes) ----------------------------------------
    def test_cli_pass_exit_0(self):
        cache = self.tmp / "published.json"
        _published_cache(cache, self.published_ids)
        records = self.tmp / "corpus"
        _ingest_corpus(records, self.published_ids)
        rc = MOD.main([REPO, "--records-dir", str(records), "--cache-file", str(cache), "--json"])
        self.assertEqual(rc, 0)

    def test_cli_fail_exit_1(self):
        cache = self.tmp / "published.json"
        _published_cache(cache, self.published_ids)
        records = self.tmp / "corpus"
        _ingest_corpus(records, self.published_ids[:4])
        rc = MOD.main([REPO, "--records-dir", str(records), "--cache-file", str(cache), "--json"])
        self.assertEqual(rc, 1)

    def test_cli_unresolvable_target_exit_2(self):
        ws = self.tmp / "ws3"
        ws.mkdir()
        rc = MOD.main([str(ws), "--json"])
        self.assertEqual(rc, 2)

    def test_summary_schema_present(self):
        cache = self.tmp / "published.json"
        _published_cache(cache, self.published_ids)
        records = self.tmp / "corpus"
        _ingest_corpus(records, self.published_ids)
        out = MOD.check_completeness(repo=REPO, records_dir=records, cache_file=cache)
        self.assertEqual(out["schema_version"], "auditooor.advisory_corpus_completeness.v1")


if __name__ == "__main__":
    unittest.main()
