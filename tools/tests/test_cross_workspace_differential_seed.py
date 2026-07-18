# r36-rebuttal: PR7b lane cross-workspace-differential-seed; orchestrator commits
"""Tests for tools/cross-workspace-differential-seed.py (ADD-A differential seed)."""

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parent.parent / "cross-workspace-differential-seed.py"
_spec = importlib.util.spec_from_file_location("cross_workspace_differential_seed", _TOOL)
cwds = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cwds)


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _make_target(tmp: Path, name="midnight", repo="morpho-org/midnight",
                 src_body=None) -> Path:
    ws = tmp / "audits" / name
    ws.mkdir(parents=True, exist_ok=True)
    _write(ws / "targets.tsv",
           f"# header\nhttps://github.com/{repo}.git\tabc\t{name}\n")
    body = src_body if src_body is not None else (
        "// SPDX\n"
        "contract Midnight {\n"
        "    function liquidate(uint256 id) external {}\n"  # reentrancy
        "    function price() public view returns (uint256) {}\n"  # oracle
        "    function claimSettlementFee() external {}\n"  # fee
        "    function setRoleSetter(address a) external {}\n"  # auth
        "    function lossFactor() public view {}\n"  # bad-debt / irm
        "}\n"
    )
    _write(ws / "src" / "Midnight.sol", body)
    return ws


def _make_sibling(tmp: Path, name, repo, *, submissions=None,
                  findings=None, invariants=None) -> Path:
    ws = tmp / "audits" / name
    ws.mkdir(parents=True, exist_ok=True)
    _write(ws / "targets.tsv",
           f"# header\nhttps://github.com/{repo}.git\tdef\t{name}\n")
    # A minimal source file so the sibling's primary language resolves to
    # solidity (matches how a real audited workspace carries source).
    _write(ws / "src" / "Stub.sol",
           "contract Stub { function f() external {} }\n")
    if submissions:
        _write(ws / "submissions" / "SUBMISSIONS.md", submissions)
    for fid in (findings or []):
        (ws / "findings" / fid).mkdir(parents=True, exist_ok=True)
        _write(ws / "findings" / fid / "rationale.txt", "stub")
    for inv in (invariants or []):
        _write(ws / "invariant_hunt" / inv, "// invariant stub")
    return ws


class TestLanguageFamilyDerivation(unittest.TestCase):
    def test_solidity_morpho_family(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _make_target(Path(td))
            lang, _ = cwds.derive_language(ws)
            fams = cwds.derive_families(ws)
            self.assertEqual(lang, "solidity")
            self.assertIn("morpho-blue", fams)

    def test_midnight_maps_to_morpho_blue(self):
        # The midnight repo name alone should resolve to morpho-blue family.
        with tempfile.TemporaryDirectory() as td:
            ws = _make_target(Path(td), name="morpho-midnight",
                              repo="morpho-org/midnight")
            self.assertIn("morpho-blue", cwds.derive_families(ws))

    def test_unknown_repo_no_family(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _make_target(Path(td), name="weirdthing",
                              repo="acme/weirdthing")
            self.assertEqual(cwds.derive_families(ws), [])


class TestSiblingScoring(unittest.TestCase):
    def test_same_lang_same_family_scores_highest(self):
        s = cwds.score_sibling("solidity", ["morpho-blue"],
                               "solidity", ["morpho-blue"])
        self.assertEqual(s, 5.0)  # 2 (lang) + 3 (family overlap)

    def test_same_lang_diff_family(self):
        s = cwds.score_sibling("solidity", ["morpho-blue"],
                               "solidity", ["cross-chain-bridge"])
        self.assertEqual(s, 2.0)

    def test_diff_lang_no_family(self):
        s = cwds.score_sibling("solidity", ["morpho-blue"],
                               "rust", ["cosmos-sdk"])
        self.assertEqual(s, 0.0)


class TestBugClassification(unittest.TestCase):
    def test_reentrancy_signal(self):
        self.assertIn("reentrancy",
                      cwds._classify_bug_classes("PreLiquidation atomic reentrancy"))

    def test_oracle_signal(self):
        self.assertIn("oracle-price-zero-or-truncation",
                      cwds._classify_bug_classes("Oracle SCALE_FACTOR truncation"))

    def test_no_signal_returns_empty(self):
        self.assertEqual(cwds._classify_bug_classes("just a refactor note"), [])


class TestPriorFindingExtraction(unittest.TestCase):
    def test_submissions_headings_extracted(self):
        with tempfile.TemporaryDirectory() as td:
            sib = _make_sibling(
                Path(td), "morpho", "morpho-org/morpho-blue",
                submissions=("## #I2.B PreLiquidation atomic reentrancy\n"
                             "## #I2.A Oracle SCALE_FACTOR price truncation\n"),
            )
            pf = cwds.extract_prior_findings(sib)
            classes = {c for f in pf for c in f["bug_classes"]}
            self.assertIn("reentrancy", classes)
            self.assertIn("oracle-price-zero-or-truncation", classes)

    def test_invariant_files_extracted(self):
        with tempfile.TemporaryDirectory() as td:
            sib = _make_sibling(
                Path(td), "morpho", "morpho-org/morpho-blue",
                invariants=["OracleReentrancy.invariants.sol"],
            )
            pf = cwds.extract_prior_findings(sib)
            self.assertTrue(any(f["kind"] == "invariant" for f in pf))


class TestTargetFunctionIndex(unittest.TestCase):
    def test_indexes_solidity_functions_with_lines(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _make_target(Path(td))
            idx = cwds.build_target_function_index(ws, "solidity")
            names = {f["function"] for f in idx}
            self.assertIn("liquidate", names)
            self.assertIn("price", names)
            for f in idx:
                self.assertGreaterEqual(f["line"], 1)
                self.assertTrue(f["file"].endswith("Midnight.sol"))

    def test_excludes_test_and_out_dirs(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _make_target(Path(td))
            _write(ws / "src" / "test" / "Foo.t.sol",
                   "contract T { function testThing() public {} }\n")
            _write(ws / "out" / "Bar.sol",
                   "contract B { function builtArtifact() public {} }\n")
            idx = cwds.build_target_function_index(ws, "solidity")
            names = {f["function"] for f in idx}
            self.assertNotIn("testThing", names)
            self.assertNotIn("builtArtifact", names)


class TestHypothesisBuild(unittest.TestCase):
    def test_reentrancy_prior_maps_to_liquidate(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _make_target(Path(td))
            sib = _make_sibling(
                Path(td), "morpho", "morpho-org/morpho-blue",
                submissions="## #I2.B PreLiquidation atomic reentrancy\n",
            )
            findings = cwds.extract_prior_findings(sib)
            selected = [{
                "workspace": "morpho", "_findings": findings,
            }]
            idx = cwds.build_target_function_index(ws, "solidity")
            hyps = cwds.build_hypotheses(selected, idx)
            targets = {(h["bug_class"], h["target_function"]) for h in hyps}
            self.assertIn(("reentrancy", "liquidate"), targets)

    def test_oracle_prior_maps_to_price(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _make_target(Path(td))
            sib = _make_sibling(
                Path(td), "morpho", "morpho-org/morpho-blue",
                submissions="## #I2.A Oracle SCALE_FACTOR price truncation\n",
            )
            findings = cwds.extract_prior_findings(sib)
            selected = [{"workspace": "morpho", "_findings": findings}]
            idx = cwds.build_target_function_index(ws, "solidity")
            hyps = cwds.build_hypotheses(selected, idx)
            targets = {(h["bug_class"], h["target_function"]) for h in hyps}
            self.assertIn(("oracle-price-zero-or-truncation", "price"), targets)

    def test_hypothesis_has_file_line_and_id(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _make_target(Path(td))
            sib = _make_sibling(
                Path(td), "morpho", "morpho-org/morpho-blue",
                submissions="## #I2.B atomic reentrancy callback\n",
            )
            findings = cwds.extract_prior_findings(sib)
            selected = [{"workspace": "morpho", "_findings": findings}]
            idx = cwds.build_target_function_index(ws, "solidity")
            hyps = cwds.build_hypotheses(selected, idx)
            self.assertTrue(hyps)
            for h in hyps:
                self.assertTrue(h["hypothesis_id"].startswith("DIFF-"))
                self.assertRegex(h["target_file_line"], r".+:\d+$")
                self.assertEqual(h["verdict"], "unproven")

    def test_cap_enforced(self):
        with tempfile.TemporaryDirectory() as td:
            # Many functions; ensure the cap holds.
            body = "contract M {\n" + "".join(
                f"    function liquidate{i}() external {{}}\n" for i in range(200)
            ) + "}\n"
            ws = _make_target(Path(td), src_body=body)
            sib = _make_sibling(
                Path(td), "morpho", "morpho-org/morpho-blue",
                submissions="## #I2.B atomic reentrancy callback\n",
            )
            findings = cwds.extract_prior_findings(sib)
            selected = [{"workspace": "morpho", "_findings": findings}]
            idx = cwds.build_target_function_index(ws, "solidity")
            hyps = cwds.build_hypotheses(selected, idx)
            self.assertLessEqual(len(hyps), cwds.MAX_HYPOTHESES)


class TestEndToEndAnchor(unittest.TestCase):
    """The morpho -> morpho-midnight calibration anchor (synthetic clone)."""

    def _build(self, td):
        tmp = Path(td)
        target = _make_target(tmp, name="morpho-midnight",
                              repo="morpho-org/midnight")
        # Morpho sibling: top match (same lang + family).
        _make_sibling(
            tmp, "morpho", "morpho-org/morpho-blue",
            submissions=("## #I2.B PreLiquidation atomic reentrancy\n"
                         "## #I2.A Oracle SCALE_FACTOR price truncation\n"),
        )
        # Off-family solidity sibling: lower score (lang only).
        _make_sibling(
            tmp, "hyperbridge", "polytope-labs/hyperbridge",
            submissions="## #H1 ISMP bridge root verification gap\n",
        )
        # Different language sibling: excluded.
        cosmos = tmp / "audits" / "dydx"
        cosmos.mkdir(parents=True, exist_ok=True)
        _write(cosmos / "targets.tsv",
               "https://github.com/dydxprotocol/v4-chain.git\tx\tdydx\n")
        _write(cosmos / "x" / "clob.go", "package x\nfunc PlaceOrder() {}\n")
        return target, tmp / "audits"

    def test_morpho_is_top_sibling(self):
        with tempfile.TemporaryDirectory() as td:
            target, audits = self._build(td)
            payload = cwds.build_payload(target, audits, k=3)
            self.assertEqual(payload["target_language"], "solidity")
            self.assertIn("morpho-blue", payload["target_families"])
            sibs = payload["selected_siblings"]
            self.assertTrue(sibs)
            self.assertEqual(sibs[0]["workspace"], "morpho")
            # morpho shares language (solidity) + family (morpho-blue) =>
            # the maximum score, strictly above the off-family sibling.
            self.assertEqual(sibs[0]["similarity_score"], 5.0)
            off_family = next(
                (s for s in sibs if s["workspace"] == "hyperbridge"), None)
            if off_family is not None:
                self.assertGreater(sibs[0]["similarity_score"],
                                   off_family["similarity_score"])

    def test_dydx_excluded_for_language_mismatch(self):
        with tempfile.TemporaryDirectory() as td:
            target, audits = self._build(td)
            payload = cwds.build_payload(target, audits, k=5)
            names = {s["workspace"] for s in payload["selected_siblings"]}
            self.assertNotIn("dydx", names)

    def test_anchor_emits_reentrancy_and_oracle_hyps(self):
        with tempfile.TemporaryDirectory() as td:
            target, audits = self._build(td)
            payload = cwds.build_payload(target, audits, k=3)
            morpho_classes = {
                h["bug_class"] for h in payload["hypotheses"]
                if h["prior_workspace"] == "morpho"
            }
            self.assertIn("reentrancy", morpho_classes)
            self.assertIn("oracle-price-zero-or-truncation", morpho_classes)

    def test_schema_and_required_fields(self):
        with tempfile.TemporaryDirectory() as td:
            target, audits = self._build(td)
            payload = cwds.build_payload(target, audits, k=3)
            self.assertEqual(payload["schema"], cwds.SCHEMA)
            for key in ("generated_at", "target_workspace", "target_language",
                        "target_families", "selected_siblings", "hypotheses",
                        "notes"):
                self.assertIn(key, payload)


class TestProofQueueMerge(unittest.TestCase):
    def test_merge_preserves_existing_and_appends(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _make_target(Path(td))
            (ws / ".auditooor").mkdir(parents=True, exist_ok=True)
            _write(ws / ".auditooor" / "proof_obligation_queue.json",
                   json.dumps([{"obligation_id": "HAND-1", "claim": "curated"}]))
            rows = [{"obligation_id": "DIFF-abc", "claim": "x",
                     "source": "cross-workspace-differential-seed"}]
            res = cwds.merge_proof_queue(ws, rows)
            self.assertEqual(res["appended"], 1)
            q = json.loads(
                (ws / ".auditooor" / "proof_obligation_queue.json").read_text())
            ids = {r["obligation_id"] for r in q}
            self.assertIn("HAND-1", ids)
            self.assertIn("DIFF-abc", ids)
            # Backup of the original was created.
            self.assertTrue(
                (ws / ".auditooor"
                 / "proof_obligation_queue.json.pre-diffseed.bak").exists())

    def test_merge_idempotent(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _make_target(Path(td))
            (ws / ".auditooor").mkdir(parents=True, exist_ok=True)
            rows = [{"obligation_id": "DIFF-abc", "claim": "x"}]
            cwds.merge_proof_queue(ws, rows)
            res2 = cwds.merge_proof_queue(ws, rows)
            self.assertEqual(res2["appended"], 0)
            self.assertEqual(res2["total"], 1)

    def test_merge_preserves_tasks_schema_queue(self):
        # Regression: a {"tasks":[...]} corpus-driven queue must NOT be
        # clobbered. The 86-task hand-curated hyperbridge queue was destroyed
        # once because the merge treated this shape as "unrecognized -> empty".
        with tempfile.TemporaryDirectory() as td:
            ws = _make_target(Path(td))
            (ws / ".auditooor").mkdir(parents=True, exist_ok=True)
            _write(ws / ".auditooor" / "proof_obligation_queue.json",
                   json.dumps({"schema": "corpus.v1", "workspace": "x",
                               "tasks": [
                                   {"task_id": "HAND-1", "proof_needed": "y"},
                                   {"task_id": "HAND-2", "proof_needed": "z"}]}))
            rows = [{"obligation_id": "DIFF-abc", "claim": "c",
                     "file_hint": "F.sol:1", "bug_class": "reentrancy",
                     "target_function": "liquidate", "prior_workspace": "morpho",
                     "verdict": "unproven",
                     "source": "cross-workspace-differential-seed"}]
            res = cwds.merge_proof_queue(ws, rows)
            self.assertEqual(res["container"], "tasks")
            self.assertEqual(res["appended"], 1)
            self.assertEqual(res["total"], 3)
            obj = json.loads(
                (ws / ".auditooor" / "proof_obligation_queue.json").read_text())
            # Object envelope + hand-curated tasks preserved.
            self.assertEqual(obj["schema"], "corpus.v1")
            ids = {t["task_id"] for t in obj["tasks"]}
            self.assertEqual(ids, {"HAND-1", "HAND-2", "DIFF-abc"})
            # The appended row carries task-schema fields.
            diff = next(t for t in obj["tasks"] if t["task_id"] == "DIFF-abc")
            self.assertEqual(diff["bug_class"], "reentrancy")
            self.assertEqual(diff["target_function"], "liquidate")

    def test_merge_handles_rows_object_container(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _make_target(Path(td))
            (ws / ".auditooor").mkdir(parents=True, exist_ok=True)
            _write(ws / ".auditooor" / "proof_obligation_queue.json",
                   json.dumps({"schema": "x", "rows": [
                       {"obligation_id": "HAND-1"}]}))
            rows = [{"obligation_id": "DIFF-abc"}]
            cwds.merge_proof_queue(ws, rows)
            obj = json.loads(
                (ws / ".auditooor" / "proof_obligation_queue.json").read_text())
            self.assertIsInstance(obj, dict)
            self.assertEqual(len(obj["rows"]), 2)


class TestCorpusAndOwnPriorSources(unittest.TestCase):
    """ADD: in-repo corpus + the target's OWN prior submissions as seed sources."""

    def test_corpus_findings_filtered_by_family_token(self):
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            derived = repo / "audit" / "corpus_tags" / "derived"
            derived.mkdir(parents=True, exist_ok=True)
            # One cross-chain-bridge record (matches family token + bug class),
            # one off-family record (no token) that must be excluded.
            rows = [
                {"attack_class": "reentrancy", "category": "general",
                 "statement": "hyperbridge ISMP reentrancy callback gap"},
                {"attack_class": "oracle stale price",
                 "statement": "morpho oracle scale_factor truncation"},
                {"attack_class": "unrelated", "statement": "ui copy typo"},
            ]
            with (derived / "detector_seeds_x_advisories.jsonl").open("w") as fh:
                for r in rows:
                    fh.write(json.dumps(r) + "\n")
            out = cwds.extract_corpus_findings(repo, ["cross-chain-bridge"])
            classes = {c for f in out for c in f["bug_classes"]}
            # The hyperbridge record (family token "hyperbridge") classifies as
            # reentrancy; the morpho oracle record lacks a cross-chain token.
            self.assertIn("reentrancy", classes)
            self.assertTrue(all(f["kind"] == "corpus" for f in out))
            self.assertTrue(all(
                f["source"].startswith("audit/corpus_tags/derived/")
                for f in out))

    def test_corpus_no_families_returns_empty(self):
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            (repo / "audit" / "corpus_tags" / "derived").mkdir(parents=True)
            self.assertEqual(cwds.extract_corpus_findings(repo, []), [])

    def test_own_prior_pseudo_sibling_from_submissions(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _make_target(Path(td), name="hyperbridge",
                              repo="polytope-labs/hyperbridge")
            _write(ws / "submissions" / "SUBMISSIONS.md",
                   "## hb optimism l2oracle unfinalized output price gap\n"
                   "## hb relayer fee accounting rounding\n")
            ps = cwds.build_own_prior_pseudo_sibling(ws)
            self.assertIsNotNone(ps)
            self.assertTrue(ps["workspace"].endswith("(own-prior)"))
            classes = {c for f in ps["_findings"] for c in f["bug_classes"]}
            self.assertIn("oracle-price-zero-or-truncation", classes)
            self.assertIn("fee-accounting", classes)

    def test_own_prior_none_when_no_submissions(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _make_target(Path(td), name="fresh", repo="acme/fresh")
            self.assertIsNone(cwds.build_own_prior_pseudo_sibling(ws))

    def test_payload_records_extra_sources_in_notes(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            target = _make_target(tmp, name="hyperbridge",
                                  repo="polytope-labs/hyperbridge")
            _write(target / "submissions" / "SUBMISSIONS.md",
                   "## hb optimism l2oracle unfinalized output price gap\n")
            _make_sibling(
                tmp, "morpho", "morpho-org/morpho-blue",
                submissions="## #I2.B atomic reentrancy callback\n",
            )
            payload = cwds.build_payload(target, tmp / "audits", k=3)
            joined = " ".join(payload["notes"])
            self.assertIn("own-prior submissions source:", joined)
            self.assertIn("in-repo corpus source:", joined)
            # The own-prior source contributed at least one source row.
            names = {s["workspace"] for s in payload["selected_siblings"]}
            self.assertTrue(
                any(n.endswith("(own-prior)") for n in names))


class TestCLI(unittest.TestCase):
    def test_main_writes_artifacts(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            target = _make_target(tmp, name="morpho-midnight",
                                  repo="morpho-org/midnight")
            _make_sibling(
                tmp, "morpho", "morpho-org/morpho-blue",
                submissions="## #I2.B atomic reentrancy callback\n",
            )
            rc = cwds.main([
                "--workspace", str(target),
                "--audits-dir", str(tmp / "audits"),
                "--k", "2", "--quiet",
            ])
            self.assertEqual(rc, 0)
            self.assertTrue(
                (target / ".auditooor" / "differential_seed_queue.json").exists())
            self.assertTrue(
                (target / ".auditooor" / "differential_seed_queue.md").exists())

    def test_main_bad_workspace_rc2(self):
        rc = cwds.main(["--workspace", "/nonexistent/path/xyz123", "--quiet"])
        self.assertEqual(rc, 2)


class TestZcashConsensusNodeCapability(unittest.TestCase):
    """Bitcoin/Zcash consensus-node coverage: family signals, consensus
    bug-class classification, GHSA sidecar extraction, src-only function
    index, and within-bucket relevance ranking (zebra calibration)."""

    def test_zebra_family_signal(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            ws = tmp / "zebra"
            ws.mkdir()
            _write(ws / "targets.tsv",
                   "# h\nhttps://github.com/ZcashFoundation/zebra.git\tx\tzebra\n")
            self.assertEqual(cwds.derive_families(ws), ["zcash-consensus-node"])

    def test_consensus_bug_classes_classify(self):
        # Each GHSA attack_class phrase must classify into a consensus class.
        cases = {
            "attacker-controlled-allocation / pre-read memory amplification / CWE-770":
                "attacker-controlled-allocation-dos",
            "length-prefix-trust / non-canonical-encoding":
                "non-canonical-encoding-divergence",
            "consensus-divergence / sigop-undercount-via-zip-truncation":
                "consensus-divergence-sigop-script",
            "misbehavior-score-evasion / per-peer-identity-keying-defect":
                "p2p-misbehavior-score-evasion",
            "on-disk-state-corruption / incomplete-revert-cleanup":
                "incomplete-cleanup-state-residue",
            "config-gated-panic / Option-unwrap / shared-mutex-poison-cascade":
                "panic-unwrap-liveness",
            "silent-error-drop / Result-IntoIterator-footgun / value-balance-bypass":
                "silent-error-drop-footgun",
        }
        for text, expected in cases.items():
            self.assertIn(expected, cwds._classify_bug_classes(text),
                          f"{text!r} did not classify into {expected}")

    def test_sidecar_extraction_reads_ghsa(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            ws = tmp / "zebra"
            sc = ws / ".auditooor" / "hunt_findings_sidecars"
            sc.mkdir(parents=True)
            _write(sc / "T6-GHSA-xr93-alloc.json", json.dumps({
                "id": "T6-GHSA-xr93-allocation-cap-siblings",
                "attack_class": "attacker-controlled-allocation / pre-read "
                                "memory amplification / CWE-770",
                "summary": "pre-read length-prefix allocation amplification.",
                "verdict": "HARDENED",
            }))
            findings = cwds.extract_prior_findings(ws)
            kinds = {f["kind"] for f in findings}
            self.assertIn("sidecar", kinds)
            classes = set()
            for f in findings:
                classes.update(f["bug_classes"])
            self.assertIn("attacker-controlled-allocation-dos", classes)

    def test_function_index_excludes_poc_and_test_rs(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            ws = tmp / "zebra"
            # production source (kept)
            _write(ws / "src" / "zebra-chain" / "src" / "serialization"
                   / "zcash_deserialize.rs",
                   "pub fn zcash_deserialize_external_count() {}\n")
            # unit-test module by basename (excluded)
            _write(ws / "src" / "zebra-script" / "src" / "tests.rs",
                   "fn p2sh_sigop_count_counts_redeem_script() {}\n")
            # filed-PoC harness under submissions/ (excluded)
            _write(ws / "submissions" / "filed" / "x" / "poc" / "poc.rs",
                   "fn one_ip_saturates_global_queue() {}\n")
            idx = cwds.build_target_function_index(ws, "rust")
            names = {f["function"] for f in idx}
            self.assertIn("zcash_deserialize_external_count", names)
            self.assertNotIn("p2sh_sigop_count_counts_redeem_script", names)
            self.assertNotIn("one_ip_saturates_global_queue", names)

    def test_bucket_relevance_prefers_core_source_exact_match(self):
        aff = cwds._affinity_for_class("attacker-controlled-allocation-dos")
        self.assertTrue(aff)
        core = {
            "target_function": "zcash_deserialize_external_count",
            "target_file_line":
                "src/zebra-chain/src/serialization/zcash_deserialize.rs:86",
        }
        rpc = {
            "target_function": "get_block_count",
            "target_file_line": "src/zebra-rpc/src/methods.rs:484",
        }
        self.assertGreater(cwds._bucket_relevance(core, aff),
                           cwds._bucket_relevance(rpc, aff))

    def test_consensus_prior_maps_to_serialization_fn(self):
        # An allocation-DoS prior should map onto the deserialize-count fn,
        # not onto a generic RPC getter, after relevance ranking.
        fn_index = [
            {"function": "get_block_count",
             "file": "src/zebra-rpc/src/methods.rs", "line": 484},
            {"function": "zcash_deserialize_external_count",
             "file": "src/zebra-chain/src/serialization/zcash_deserialize.rs",
             "line": 86},
        ]
        sib = {
            "workspace": "zebra (own-prior)",
            "_findings": [{
                "kind": "sidecar",
                "title": "length-prefix-trust / non-canonical-encoding",
                "bug_classes": ["attacker-controlled-allocation-dos"],
                "source": ".auditooor/hunt_findings_sidecars/x.json",
            }],
        }
        hyps = cwds.build_hypotheses([sib], fn_index)
        alloc = [h for h in hyps
                 if h["bug_class"] == "attacker-controlled-allocation-dos"]
        self.assertTrue(alloc)
        self.assertEqual(alloc[0]["target_function"],
                         "zcash_deserialize_external_count")


if __name__ == "__main__":
    unittest.main()
