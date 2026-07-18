"""Regression for tools/workspace-advisory-corpus-scan.py - generic L37
advisory-corpus producer. OSV calls are mocked so the test is network-free.
Verifies: (a) 0 published -> honest 0/0 PARITY ledger with scan evidence;
(b) published>0 all-in-corpus -> parity; (c) published>0 with corpus gap ->
the ledger reports the gap (gate will fail); (d) OSV unreachable -> writes
NOTHING (no fake 0/0). Generic-fix anchor: audit-deep produced no advisory
ledger, so the L37 advisory-corpus gate hard-failed on every workspace.
"""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

_HERE = Path(__file__).resolve().parent
_TOOL = _HERE.parent / "workspace-advisory-corpus-scan.py"


def _load():
    spec = importlib.util.spec_from_file_location("wacs", _TOOL)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


WACS = _load()


def _ws(td):
    ws = Path(td)
    (ws / ".auditooor").mkdir(parents=True, exist_ok=True)
    crate = ws / "src" / "thecrate"
    crate.mkdir(parents=True)
    (crate / "Cargo.toml").write_text(
        '[package]\nname = "thecrate"\nversion = "0.1.0"\n', encoding="utf-8")
    return ws


class TestAdvisoryCorpusScan(unittest.TestCase):
    def test_zero_published_is_parity(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _ws(td)
            with mock.patch.object(WACS, "osv_query", return_value=([], None)):
                rc = WACS.main([str(ws)])
            self.assertEqual(rc, 0)
            obj = json.loads((ws / ".auditooor" / "advisory_corpus_parity.json").read_text())
            self.assertEqual(obj["published_advisory_count"], 0)
            self.assertEqual(obj["corpus_advisory_record_count"], 0)
            self.assertIn("scan_method", obj)
            self.assertTrue(obj["source_files_used"])  # scan evidence present

    def test_published_in_corpus_is_parity(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _ws(td)
            pa = ws / "prior_audits"; pa.mkdir()
            (pa / "a.txt").write_text("see RUSTSEC-2024-0001 for details", encoding="utf-8")
            with mock.patch.object(WACS, "osv_query", return_value=(["RUSTSEC-2024-0001"], None)):
                rc = WACS.main([str(ws)])
            self.assertEqual(rc, 0)
            obj = json.loads((ws / ".auditooor" / "advisory_corpus_parity.json").read_text())
            self.assertEqual(obj["published_advisory_count"], 1)
            self.assertEqual(obj["corpus_advisory_record_count"], 1)

    def test_published_gap_reported_truthfully(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _ws(td)  # no prior_audits -> id not in corpus
            with mock.patch.object(WACS, "osv_query", return_value=(["RUSTSEC-2024-0002"], None)):
                rc = WACS.main([str(ws)])
            self.assertEqual(rc, 0)
            obj = json.loads((ws / ".auditooor" / "advisory_corpus_parity.json").read_text())
            self.assertEqual(obj["published_advisory_count"], 1)
            self.assertEqual(obj["corpus_advisory_record_count"], 0)  # honest gap
            self.assertIn("RUSTSEC-2024-0002", obj["unmatched_published"])

    def test_osv_unreachable_writes_nothing(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _ws(td)
            with mock.patch.object(WACS, "osv_query", return_value=([], "URLError: unreachable")):
                rc = WACS.main([str(ws)])
            self.assertEqual(rc, 1)  # honest refusal
            self.assertFalse((ws / ".auditooor" / "advisory_corpus_parity.json").exists())


    def test_mined_corpus_union_and_case_insensitive_match(self):
        # published must UNION the OSV per-package subset with the already-mined
        # corpus advisories (the zebra 13-vs-26 false-PARITY fix), and corpus
        # matching must be case-insensitive. Mock OSV to a strict subset; place a
        # mined corpus file with the full set (mixed case); the prior_audits text
        # carries the ids lowercase.
        import importlib, tempfile, json as _json
        from pathlib import Path as _P
        with tempfile.TemporaryDirectory() as td:
            ws = _ws(td)
            (ws / "targets.tsv").write_text(
                "https://github.com/acme/widget.git\tabc123\tsrc\n", encoding="utf-8")
            pa = ws / "prior_audits"; pa.mkdir()
            # corpus text has the full set, LOWERCASE
            (pa / "a.txt").write_text(
                "ghsa-aaaa-bbbb-cccc and ghsa-dddd-eeee-ffff both disclosed", encoding="utf-8")
            # point the mined-corpus glob at a temp derived dir with the full set (mixed case)
            derived = _P(td) / "derived"; derived.mkdir()
            (derived / f"{ws.name}_advisories.jsonl").write_text(
                _json.dumps({"id": "GHSA-AAAA-BBBB-CCCC"}) + "\n" +
                _json.dumps({"id": "GHSA-dddd-eeee-ffff"}) + "\n", encoding="utf-8")
            with mock.patch.object(WACS, "_DERIVED_ROOT", derived), \
                 mock.patch.object(WACS, "osv_query", return_value=(["GHSA-AAAA-BBBB-CCCC"], None)), \
                 mock.patch.object(WACS, "github_repo_advisories", return_value=([], "TimeoutExpired")):
                rc = WACS.main([str(ws)])
            self.assertEqual(rc, 0)
            obj = _json.loads((ws / ".auditooor" / "advisory_corpus_parity.json").read_text())
            # OSV alone would be 1; union with mined corpus = 2
            self.assertEqual(obj["published_advisory_count"], 2)
            # both reconciled despite case differences -> parity
            self.assertEqual(obj["corpus_advisory_record_count"], 2)
            self.assertEqual(obj["advisory_source_counts"]["osv"], 1)
            self.assertEqual(obj["advisory_source_counts"]["mined_corpus"], 2)


    def test_vendor_flood_does_not_starve_real_package(self):
        """Regression: unsorted rglob with [:200] cap silently excluded the real
        audited crate when 200 vendor/ Cargo.toml files were present and filesystem
        inode order yielded vendor/ entries first.

        Setup: create vendor/dep-000/Cargo.toml ... vendor/dep-210/Cargo.toml (211
        files - exceeds the 200 cap) plus src/real-audited-crate/Cargo.toml (the
        package that MUST be found). With the fix (depth-sorted rglob), src/ at
        depth N sorts before vendor/dep-N/... at depth N+1, so the real crate
        occupies position 0 in the sorted list regardless of inode order.
        Without the fix this test fails non-deterministically (depending on whether
        vendor/ inodes happen to be enumerated first) - on most OSes it fails
        consistently because vendor/ was created first.
        """
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            (ws / ".auditooor").mkdir(parents=True, exist_ok=True)

            # Real audited crate at src/ (shallow - depth src/<crate>/Cargo.toml)
            real_crate_dir = ws / "src" / "real-audited-crate"
            real_crate_dir.mkdir(parents=True)
            (real_crate_dir / "Cargo.toml").write_text(
                '[package]\nname = "real-audited-crate"\nversion = "1.0.0"\n',
                encoding="utf-8")

            # 211 vendored crates at vendor/ (each has a valid [package] section -
            # standard for `cargo vendor` output). Create vendor/ BEFORE src/ in
            # inode order to maximize the chance of inode-order enumeration
            # returning vendor entries first.
            vendor_dir = ws / "vendor"
            vendor_dir.mkdir()
            for i in range(211):
                d = vendor_dir / f"dep-{i:03d}"
                d.mkdir()
                (d / "Cargo.toml").write_text(
                    f'[package]\nname = "vendored-dep-{i}"\nversion = "0.1.0"\n',
                    encoding="utf-8")

            pkgs = WACS.enumerate_packages(ws)
            names = {p["name"] for p in pkgs}
            self.assertIn(
                "real-audited-crate", names,
                f"real-audited-crate was not discovered - vendor flood starved the cap. "
                f"Found {len(pkgs)} packages: {sorted(names)[:10]}...")
            # vendor/ copies are vendored third-party - must NOT be enumerated
            self.assertFalse(
                any(n.startswith("vendored-dep-") for n in names),
                "vendored deps under vendor/ leaked into enumerated packages")

    def test_vendored_manifests_hard_skipped(self):
        """A manifest under a vendored dependency dir (soldeer dependencies/,
        foundry lib/, npm node_modules/) is a third-party copy, NOT the target's
        own published package - it must be EXCLUDED so the advisory-corpus parity
        gate does not demand every dependency's CVEs be in our corpus (the
        hyperlane 57-of-60 dependency scope-leak)."""
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            (ws / ".auditooor").mkdir(parents=True)
            # the REAL in-scope target package
            real = ws / "src" / "solidity"
            real.mkdir(parents=True)
            (real / "package.json").write_text(
                '{"name": "@target/core"}', encoding="utf-8")
            # vendored third-party copies that MUST be dropped
            vendored = {
                "src/solidity/dependencies/@openzeppelin-contracts-4.9.3": "@openzeppelin/contracts",
                "src/solidity/dependencies/@arbitrum-nitro-1.2.1": "@arbitrum/nitro-contracts",
                "src/solidity/lib/openzeppelin-contracts": "openzeppelin-solidity",
                "src/solidity/node_modules/@uniswap/permit2": "@uniswap/permit2",
            }
            for rel, name in vendored.items():
                d = ws / rel
                d.mkdir(parents=True)
                (d / "package.json").write_text(
                    json.dumps({"name": name}), encoding="utf-8")
            names = {p["name"] for p in WACS.enumerate_packages(ws)}
            self.assertIn("@target/core", names)
            for leaked in vendored.values():
                self.assertNotIn(
                    leaked, names,
                    f"vendored dependency {leaked} leaked into enumerated packages")


if __name__ == "__main__":
    unittest.main()
