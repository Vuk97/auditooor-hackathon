#!/usr/bin/env python3
"""Tests for tools/corpus-coverage-burndown.py.

Covers: (1) mining clusters bug_class into logic signatures with severity +
count; (2) set-difference coverage (mapped-reasoner-on-disk => covered,
unmapped => uncovered); (3) surface enumeration of a workspace by extension +
MPC marker; (4) the surface matrix flags an MPC/threshold-sig blind spot when
the surface is present but no reasoner covers it (the axelar regression);
(5) end-to-end run() over the real corpus recomputes a coverage number.
"""
import importlib.util
import os
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(HERE, "..", "corpus-coverage-burndown.py")
spec = importlib.util.spec_from_file_location("ccb", TOOL)
ccb = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ccb)


def _write(root, rel, text):
    p = os.path.join(root, rel)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w", encoding="utf-8") as fh:
        fh.write(text)
    return p


class TestMining(unittest.TestCase):
    def test_jsonl_clusters_to_two_segment_signature_with_severity(self):
        with tempfile.TemporaryDirectory() as d:
            _write(d, "findings_go.jsonl",
                   '{"bug_class":"go.cosmos.endblocker_panic_chain_halt","impact_tier":"critical"}\n'
                   '{"bug_class":"go.cosmos.tx_decode_overflow","impact_tier":"high"}\n'
                   '{"bug_class":"go.ecdsa.panic_on_input","impact_tier":"medium"}\n')
            classes, prov = ccb.mine_corpus(d)
            self.assertIn("go.cosmos", classes)
            self.assertIn("go.ecdsa", classes)
            self.assertEqual(classes["go.cosmos"].count, 2)   # two members clustered
            self.assertEqual(classes["go.cosmos"].tier_rank, 4)  # max = critical
            self.assertTrue(any(p["source"] == "findings_go.jsonl" for p in prov))

    def test_frost_yaml_becomes_mpc_logic_classes(self):
        with tempfile.TemporaryDirectory() as d:
            _write(d, "frost_prior_audit_classes.yaml",
                   "classes:\n"
                   "  - class_id: nonce-reuse-across-signing-sessions\n"
                   "    severity_class: CRIT-1\n"
                   "  - class_id: signer-set-rotation-without-key-resharing\n"
                   "    severity_class: HIGH-1\n")
            classes, _ = ccb.mine_corpus(d)
            self.assertIn("mpc.nonce-reuse-across-signing-sessions", classes)
            self.assertEqual(
                classes["mpc.nonce-reuse-across-signing-sessions"].surface,
                "MPC/threshold-sig")


class TestCoverageDiff(unittest.TestCase):
    def test_covered_only_if_mapped_reasoner_exists_on_disk(self):
        cls = {
            "sol.crosschain": ccb.MinedClass("sol.crosschain"),
            "mpc.nonce-reuse": ccb.MinedClass("mpc.nonce-reuse"),
        }
        cls["sol.crosschain"].add(3, "ex")
        cls["mpc.nonce-reuse"].add(4, "ex")
        # crosschain reasoner present; MPC reasoner deliberately absent
        inv = {"crosschain-message-authenticity-reasoner.py"}
        covered, uncovered = ccb.build_diff(cls, inv)
        cov_names = {c["class"] for c in covered}
        unc_names = {c["class"] for c in uncovered}
        self.assertIn("sol.crosschain", cov_names)
        self.assertIn("mpc.nonce-reuse", unc_names)     # MPC stays uncovered

    def test_mapped_reasoner_missing_on_disk_is_uncovered(self):
        cls = {"sol.crosschain": ccb.MinedClass("sol.crosschain")}
        cls["sol.crosschain"].add(3, "ex")
        covered, uncovered = ccb.build_diff(cls, set())  # empty inventory
        self.assertEqual(covered, [])
        self.assertEqual(uncovered[0]["class"], "sol.crosschain")


class TestSurfaceEnumeration(unittest.TestCase):
    def test_extensions_and_mpc_marker(self):
        with tempfile.TemporaryDirectory() as d:
            _write(d, "contracts/Vault.sol", "contract V {}")
            _write(d, "x/reward/abci.go", "package reward")
            _write(d, "tofn/src/lib.rs", "// threshold keygen")
            surf = ccb.enumerate_workspace_surfaces(d)
            self.assertIn("EVM", surf["present"])
            self.assertIn("Cosmos-Go", surf["present"])
            self.assertIn("Rust", surf["present"])
            self.assertIn("MPC/threshold-sig", surf["present"])  # tofn path marker


class TestSurfaceMatrixGap(unittest.TestCase):
    def test_mpc_surface_present_but_no_reasoner_is_blind_spot(self):
        classes = {"mpc.nonce-reuse": ccb.MinedClass("mpc.nonce-reuse")}
        classes["mpc.nonce-reuse"].add(4, "frost")
        inv = set()  # no MPC reasoner built
        ws = {"present": ["MPC/threshold-sig", "Rust", "Cosmos-Go"]}
        matrix = ccb.surface_coverage_matrix(classes, inv, ws)
        mpc = next(r for r in matrix if r["surface"] == "MPC/threshold-sig")
        self.assertTrue(mpc["flagged"])
        self.assertIn("BLIND-SPOT", mpc["verdict"])

    def test_surface_not_in_workspace_is_not_flagged(self):
        classes = {"mpc.nonce-reuse": ccb.MinedClass("mpc.nonce-reuse")}
        classes["mpc.nonce-reuse"].add(4, "frost")
        ws = {"present": ["EVM"]}
        matrix = ccb.surface_coverage_matrix(classes, set(), ws)
        mpc = next(r for r in matrix if r["surface"] == "MPC/threshold-sig")
        self.assertFalse(mpc["flagged"])
        self.assertEqual(mpc["verdict"], "not-in-workspace")


class TestEndToEnd(unittest.TestCase):
    def test_run_over_real_corpus_recomputes_coverage(self):
        repo = os.path.dirname(os.path.dirname(HERE))
        corpus = os.path.join(repo, "reference")
        tools = os.path.join(repo, "tools")
        result = ccb.run(corpus, tools, [])
        self.assertGreater(result["total_classes"], 40)
        self.assertGreater(result["covered_classes"], 0)
        self.assertLessEqual(result["covered_classes"], result["total_classes"])
        # MPC classes were mined from frost and remain uncovered (no reasoner)
        unc = {e["class"] for e in result["uncovered_build_queue"]}
        self.assertTrue(any(c.startswith("mpc.") for c in unc))


if __name__ == "__main__":
    unittest.main()
