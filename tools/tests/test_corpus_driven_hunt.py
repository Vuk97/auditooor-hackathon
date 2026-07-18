import json
import os
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO / "tools"))

import importlib.util
_spec = importlib.util.spec_from_file_location(
    "corpus_driven_hunt", str(REPO / "tools" / "corpus-driven-hunt.py"))
cdh = importlib.util.module_from_spec(_spec)
sys.modules["corpus_driven_hunt"] = cdh
_spec.loader.exec_module(cdh)


def write(p, text):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


def _load_tool(mod_name, filename):
    """Load a sibling tools/*.py module by file path (these have hyphens in
    their names, so a normal import is impossible). Mirrors the cdh loader
    above and the importlib pattern hunt-resume-planner.py itself uses."""
    spec = importlib.util.spec_from_file_location(
        mod_name, str(REPO / "tools" / filename))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)
    return mod


# REAL resume-side classifier + planner (NOT reimplemented in-test). The
# unbounded-queue budget-halt path delegates throttle/resume to these tools;
# tests (c) assert against the SAME classify_record + build_resume_plan the
# production resume lane uses.
_hrh = _load_tool("_hrh_test", "hunt-run-health-check.py")
_hrp = _load_tool("_hrp_test", "hunt-resume-planner.py")


def _mock_dispatcher_halt_record(task_id, halt_reason="BUDGET_CAP_EXCEEDED",
                                 provider="deepseek"):
    """Return the EXACT result-record shape llm-fanout-dispatcher.py emits
    when the batch is halted (status=halted, result=None, error carries the
    halt_reason). Verbatim from the dispatcher's halted-task branch so the test
    classifies a real on-disk shape, not an invented one. In-memory only: no
    live LLM/provider call is made."""
    return {
        "task_id": task_id,
        "status": "halted",
        "provider": provider,
        "model_id": None,
        "input_tokens": 0,
        "output_tokens": 0,
        "cost_usd": 0.0,
        "verification_tier": "tier-3-synthetic-taxonomy-anchored",
        "duration_s": 0.0,
        "result": None,
        "error": "batch-halted: " + halt_reason,
        "retries": 0,
        "started_at_utc": "2026-01-01T00:00:00Z",
        "ended_at_utc": "2026-01-01T00:00:00Z",
    }


def _mock_dispatcher_ok_record(task_id, fn, file, provider="deepseek"):
    """A real status=ok dispatcher record carrying a structured function anchor
    so classify_record returns ``success`` (NEVER re-queued). In-memory only."""
    return {
        "task_id": task_id,
        "status": "ok",
        "provider": provider,
        "result": json.dumps({"verdict": "NEEDS_MANUAL",
                              "file_line": file + ":1"}),
        "function_anchor": {"file": file, "fn": fn},
        "error": "",
        "started_at_utc": "2026-01-01T00:00:00Z",
        "ended_at_utc": "2026-01-01T00:00:00Z",
    }


class TestLangFamily(unittest.TestCase):
    def test_lang_by_ext(self):
        self.assertEqual(cdh.LANG_BY_EXT[".rs"], "rust")
        self.assertEqual(cdh.LANG_BY_EXT[".sol"], "solidity")

    def test_category_to_family_populated(self):
        self.assertEqual(cdh.CATEGORY_TO_FAMILY["determinism"], "crypto_signing")
        self.assertEqual(cdh.CATEGORY_TO_FAMILY["conservation"], "accounting_conservation")

    def test_family_for_invariant_by_category(self):
        inv = cdh.Invariant("INV-X", "atomicity", "s", "solidity", "reentrancy",
                            "nonReentrant", "guard", [], "f")
        self.assertEqual(cdh._family_for_invariant(inv), "reentrancy_atomicity")

    def test_family_for_invariant_by_signature_fallback(self):
        inv = cdh.Invariant("INV-Y", "", "s", "any", "cross-chain-replay",
                            "", "", [], "f")
        self.assertEqual(cdh._family_for_invariant(inv), "bridge_replay")

    def test_lang_match_any(self):
        inv = cdh.Invariant("I", "c", "s", "any", "", "", "", [], "f")
        self.assertTrue(cdh._lang_match(inv, ["rust"]))

    def test_lang_match_exact_and_miss(self):
        inv = cdh.Invariant("I", "c", "s", "solidity", "", "", "", [], "f")
        self.assertTrue(cdh._lang_match(inv, ["solidity", "go"]))
        self.assertFalse(cdh._lang_match(inv, ["rust"]))


class TestFamilyFit(unittest.TestCase):
    def test_active_first_is_strongest(self):
        self.assertEqual(cdh._family_fit("a", ["a", "b"]), 1.0)
        self.assertAlmostEqual(cdh._family_fit("b", ["a", "b"]), 0.88)

    def test_inactive_is_weak(self):
        self.assertEqual(cdh._family_fit("z", ["a", "b"]), 0.15)

    def test_empty_active_is_neutral(self):
        self.assertEqual(cdh._family_fit("a", []), 0.3)


class TestEvidenceKeywords(unittest.TestCase):
    def test_keywords_extracted_and_stopwords_dropped(self):
        inv = cdh.Invariant("I", "c", "s", "any",
                            "nonce|replay", "verify-then-mark-consumed before state",
                            "consumed_set", [], "f")
        kws = cdh._evidence_keywords(inv)
        self.assertIn("nonce", kws)
        self.assertIn("replay", kws)
        self.assertIn("consumed", kws)
        self.assertNotIn("before", kws)   # stopword
        self.assertNotIn("state", kws)     # stopword


class TestLoadInvariants(unittest.TestCase):
    def test_load_and_dedupe(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "inv.jsonl"
            rows = [
                {"invariant_id": "INV-1", "category": "Uniqueness",
                 "statement": "x", "target_lang": "Rust",
                 "attack_signature": "replay", "source_finding_ids": ["a", "b"]},
                {"invariant_id": "INV-1", "category": "uniqueness",
                 "statement": "dup", "target_lang": "rust"},  # dupe id -> skipped
                {"no_id": True},  # skipped
                "{bad json",       # skipped
            ]
            with p.open("w") as fh:
                for r in rows:
                    fh.write((r if isinstance(r, str) else json.dumps(r)) + "\n")
            invs = cdh.load_invariants([p])
            self.assertEqual(len(invs), 1)
            self.assertEqual(invs[0].category, "uniqueness")   # lowercased
            self.assertEqual(invs[0].target_lang, "rust")       # lowercased
            self.assertEqual(invs[0].source_finding_ids, ["a", "b"])


class TestTargetModelAndScan(unittest.TestCase):
    def setUp(self):
        import tempfile
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        write(self.root / "src" / "sign.rs",
              "fn sign_nonce(secret: u8) -> u8 {\n    // canonical nonce path\n    secret\n}\n")
        write(self.root / "tests" / "t.rs", "fn ignored() {}\n")  # SKIP_DIRS

    def tearDown(self):
        self.tmp.cleanup()

    def test_build_target_model_detects_lang_family_fns(self):
        tm = cdh.build_target_model(self.root, max_functions=100)
        self.assertEqual(tm.languages, ["rust"])
        self.assertEqual(tm.file_count, 1)  # tests/ skipped
        self.assertIn("crypto_signing", tm.families_active)
        self.assertTrue(any(f.name == "sign_nonce" for f in tm.functions))

    def test_scan_evidence_finds_keyword_and_fn(self):
        tm = cdh.build_target_model(self.root, max_functions=100)
        hits, fns = cdh._scan_evidence(["nonce"], tm)
        self.assertTrue(hits)
        self.assertEqual(hits[0]["keyword"], "nonce")
        self.assertTrue(any(c["fn"] == "sign_nonce" for c in fns))

    def test_scan_evidence_miss(self):
        tm = cdh.build_target_model(self.root, max_functions=100)
        hits, fns = cdh._scan_evidence(["zzzznotpresent"], tm)
        self.assertEqual(hits, [])


class TestMaterializeAndRank(unittest.TestCase):
    def setUp(self):
        import tempfile
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        write(self.root / "src" / "lib.rs",
              "fn verify_signature() {\n  // canonical deterministic path\n}\n")

    def tearDown(self):
        self.tmp.cleanup()

    def test_hit_outranks_miss_and_flags_need_more(self):
        tm = cdh.build_target_model(self.root, max_functions=100)
        invs = [
            cdh.Invariant("INV-HIT", "determinism", "deterministic out", "rust",
                          "deterministic", "canonical", "deterministic", ["x"] * 6, "f"),
            cdh.Invariant("INV-MISS", "determinism", "no match here", "rust",
                          "zzzznotpresent", "qqqqnotpresent", "wwwwnotpresent", [], "f"),
        ]
        hyps = cdh.materialize(invs, tm, top=10)
        self.assertEqual(hyps[0].invariant_id, "INV-HIT")
        self.assertEqual(hyps[0].rank, 1)
        self.assertFalse(hyps[0].need_more_evidence)
        miss = [h for h in hyps if h.invariant_id == "INV-MISS"][0]
        self.assertTrue(miss.need_more_evidence)
        self.assertGreater(hyps[0].score, miss.score)

    def test_lang_mismatch_excluded(self):
        tm = cdh.build_target_model(self.root, max_functions=100)
        invs = [cdh.Invariant("INV-SOL", "atomicity", "s", "solidity",
                              "reentrancy", "x", "y", [], "f")]
        hyps = cdh.materialize(invs, tm, top=10)
        self.assertEqual(hyps, [])


class TestMimoBatch(unittest.TestCase):
    def test_concurrency_capped_at_4(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            write(root / "a.rs", "fn f(){ let nonce=1; }\n")
            tm = cdh.build_target_model(root, 100)
            inv = cdh.Invariant("INV-1", "determinism", "s", "rust",
                                "nonce", "nonce", "nonce", [], "f")
            hyps = cdh.materialize([inv] * 1, tm, top=10)
            # duplicate ids dedupe in load only; here build 6 distinct
            many = [cdh.Hypothesis(rank=i, score=1.0, invariant_id=f"I{i}",
                    category="c", family="crypto_signing", target_lang="rust",
                    statement="s", hypothesis="h", evidence_keywords=[],
                    in_target_evidence=[], candidate_functions=[],
                    corpus_source_ids=[], need_more_evidence=True,
                    differential_test_idea="d") for i in range(6)]
            batch = cdh.build_mimo_batch(many, tm, "ws", concurrency=10)
            self.assertEqual(batch["concurrency"], 4)
            self.assertEqual(batch["task_count"], 4)
            self.assertTrue(all("prompt" in t for t in batch["tasks"]))


class TestResolveSourceRoot(unittest.TestCase):
    def test_explicit_present_and_missing(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            p, res = cdh.resolve_source_root(root, str(root))
            self.assertEqual(res, "explicit")
            p2, res2 = cdh.resolve_source_root(root, str(root / "nope"))
            self.assertIsNone(p2)
            self.assertEqual(res2, "explicit-missing")

    def test_workspace_tree_detected(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            write(root / "x.rs", "fn f(){}\n")
            p, res = cdh.resolve_source_root(root, None)
            self.assertEqual(res, "workspace-tree")

    def test_unresolved_when_empty(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            p, res = cdh.resolve_source_root(Path(d), None)
            self.assertIsNone(p)
            self.assertEqual(res, "unresolved")

    def test_pointer_file(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            srcdir = root / "actualsrc"
            write(srcdir / "x.rs", "fn f(){}\n")
            write(root / ".auditooor" / "source_root", "actualsrc\n")
            p, res = cdh.resolve_source_root(root, None)
            self.assertTrue(res.startswith("workspace-pointer"))
            self.assertEqual(p, srcdir.resolve())


def _write_brain_prime(ws_root, lanes=None):
    """Helper: write a minimal valid brain_prime_receipt.json into a workspace."""
    lanes = lanes if lanes is not None else []
    receipt = {
        "schema": cdh.BRAIN_PRIME_RECEIPT_SCHEMA,
        "workspace_path": str(ws_root),
        "top_phase_f_lanes": lanes,
    }
    p = Path(ws_root) / ".auditooor" / "brain_prime_receipt.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(receipt), encoding="utf-8")
    return p


class TestRunEndToEnd(unittest.TestCase):
    def test_run_no_source_honest_error(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            # gate disabled so we reach the source-resolution path
            res = cdh.run(d, None, cdh.DEFAULT_INVARIANT_CORPORA, 10, 100,
                          brain_prime_gate=False)
            self.assertEqual(res["source_resolution"], "unresolved")
            self.assertIn("error", res)
            self.assertEqual(res["hypotheses"], [])

    def test_run_with_source_emits_ranked(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            root = Path(d) / "ws"
            write(root / "sign.rs",
                  "fn sign(){ let nonce=1; // canonical deterministic\n}\n")
            _write_brain_prime(root)
            with tempfile.TemporaryDirectory() as cd:
                corpus = Path(cd) / "c.jsonl"
                corpus.write_text(json.dumps({
                    "invariant_id": "INV-DET", "category": "determinism",
                    "statement": "deterministic output", "target_lang": "rust",
                    "attack_signature": "deterministic", "commit_point_pattern": "canonical",
                    "defense_layer": "deterministic", "source_finding_ids": ["a"]}) + "\n",
                    encoding="utf-8")
                res = cdh.run(str(root), str(root), [str(corpus)], 10, 100,
                              hacker_questions_enabled=False)
                self.assertEqual(res["schema"], cdh.SCHEMA)
                self.assertEqual(res["brain_prime"]["gate"], "pass")
                self.assertTrue(res["hypotheses"])
                h = res["hypotheses"][0]
                self.assertEqual(h["invariant_id"], "INV-DET")
                self.assertFalse(h["need_more_evidence"])
                self.assertTrue(h["candidate_functions"])

    def test_render_md_smoke(self):
        res = {"workspace": "ws", "source_resolution": "explicit",
               "corpus_loaded": 1, "eligible": 1,
               "target": {"source_root": "/x", "languages": ["rust"],
                          "file_count": 1, "function_count": 1,
                          "families_active": ["crypto_signing"]},
               "hypotheses": [{"rank": 1, "score": 1.0, "invariant_id": "INV-1",
                               "category": "determinism", "family": "crypto_signing",
                               "statement": "s", "hypothesis": "h",
                               "evidence_keywords": [], "in_target_evidence": [],
                               "candidate_functions": [], "corpus_source_ids": ["x"],
                               "need_more_evidence": True,
                               "differential_test_idea": "d"}]}
        md = cdh.render_md(res)
        self.assertIn("Corpus-driven hunt: ws", md)
        self.assertIn("INV-1", md)
        self.assertIn("NEED-MORE-EVIDENCE", md)


class TestBrainPrimeSeedGate(unittest.TestCase):
    def test_gate_fails_closed_when_receipt_missing(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            seed = cdh.load_brain_prime_seed(Path(d), None, gate_enabled=True)
            self.assertEqual(seed.gate, "fail")
            self.assertFalse(seed.present)

    def test_gate_override_when_disabled(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            seed = cdh.load_brain_prime_seed(Path(d), None, gate_enabled=False)
            self.assertEqual(seed.gate, "pass-override")

    def test_gate_passes_and_extracts_seed_tokens(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            _write_brain_prime(d, lanes=[
                {"attack_class": "crypto_signing/nonce-reuse", "lane_id": "L1"},
                {"attack_class": "bridge-replay", "lane_id": "L2"},
            ])
            seed = cdh.load_brain_prime_seed(Path(d), None, gate_enabled=True)
            self.assertEqual(seed.gate, "pass")
            self.assertTrue(seed.schema_valid)
            self.assertIn("nonce", seed.seed_tokens)
            self.assertIn("bridge", seed.seed_tokens)

    def test_run_fail_closed_returns_error(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            root = Path(d) / "ws"
            write(root / "x.rs", "fn f(){}\n")
            res = cdh.run(str(root), str(root),
                          cdh.DEFAULT_INVARIANT_CORPORA, 5, 50,
                          brain_prime_gate=True)
            self.assertIn("error", res)
            self.assertIn("brain-prime seed gate failed", res["error"])
            self.assertEqual(res["hypotheses"], [])

    def test_brain_prime_boost_aligns_ranking(self):
        h = cdh.Hypothesis(
            rank=0, score=0.5, invariant_id="I", category="determinism",
            family="crypto_signing", target_lang="rust", statement="s",
            hypothesis="h", evidence_keywords=["nonce"], in_target_evidence=[],
            candidate_functions=[], corpus_source_ids=[], need_more_evidence=True,
            differential_test_idea="d")
        seed = cdh.BrainPrimeSeed(present=True, path="p", schema_valid=True,
                                  seed_tokens=["crypto", "signing", "nonce"], gate="pass")
        boost = cdh._brain_prime_boost(h, seed)
        self.assertGreater(boost, 0.0)
        # no overlap -> no boost
        seed2 = cdh.BrainPrimeSeed(present=True, path="p", schema_valid=True,
                                   seed_tokens=["unrelated"], gate="pass")
        self.assertEqual(cdh._brain_prime_boost(h, seed2), 0.0)


class TestHackerQuestionFoldIn(unittest.TestCase):
    def setUp(self):
        import tempfile
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        write(self.root / "gateway.rs",
              "fn dispatch_arbitrary(data: u8) -> u8 {\n  // executeRaw path\n  data\n}\n")

    def tearDown(self):
        self.tmp.cleanup()

    def test_match_emits_only_matched_questions(self):
        tm = cdh.build_target_model(self.root, 100)
        questions = [
            {"question_id": "HQ-1", "question_text": "arbitrary call?",
             "attack_class_anchor": "arbitrary-call",
             "target_function_patterns": ["(?i)dispatch_arbitrary"],
             "grep_patterns": ["executeRaw"],
             "linked_invariant_ids": ["INV-ARB-1"],
             "target_language": "rust"},
            {"question_id": "HQ-MISS", "question_text": "no match",
             "target_function_patterns": ["(?i)zzzznotpresent"],
             "grep_patterns": [], "target_language": "rust"},
        ]
        hits = cdh.match_hacker_questions(questions, tm, {"rust"})
        ids = [h.question_id for h in hits]
        self.assertIn("HQ-1", ids)
        self.assertNotIn("HQ-MISS", ids)
        h1 = [h for h in hits if h.question_id == "HQ-1"][0]
        self.assertTrue(any(m["fn"] == "dispatch_arbitrary" for m in h1.matched_functions))

    def test_multi_invariant_question_splits_into_exact_obligations(self):
        tm = cdh.build_target_model(self.root, 100)
        question = {
            "question_id": "HQ-MULTI", "question_text": "check both?",
            "target_function_patterns": ["(?i)dispatch_arbitrary"],
            "linked_invariant_ids": ["INV-A", "INV-B", "INV-A"],
            "target_language": "rust",
        }
        hits = cdh.match_hacker_questions([question], tm, {"rust"})
        self.assertEqual([hit.binding_invariant_id for hit in hits], ["INV-A", "INV-B"])
        self.assertEqual([hit.linked_invariant_ids for hit in hits], [["INV-A"], ["INV-B"]])

    def test_lang_filter_excludes_mismatch(self):
        tm = cdh.build_target_model(self.root, 100)
        q = [{"question_id": "HQ-SOL", "target_function_patterns": ["(?i)dispatch_arbitrary"],
              "target_language": "solidity"}]
        self.assertEqual(cdh.match_hacker_questions(q, tm, {"rust"}), [])

    def test_bad_regex_treated_as_substring(self):
        # An invalid regex (unbalanced paren) must not crash; it is escaped to
        # a literal substring. "executeRaw(" appears verbatim in the body.
        tm = cdh.build_target_model(self.root, 100)
        q = [{"question_id": "HQ-BAD", "grep_patterns": ["executeraw"],
              "target_language": "any"},
             {"question_id": "HQ-BADRE", "grep_patterns": ["foo(bar"],
              "target_language": "any"}]
        hits = cdh.match_hacker_questions(q, tm, {"rust"})
        # HQ-BAD matches the "executeRaw" comment substring; HQ-BADRE's invalid
        # regex is escaped to a literal and simply does not match (no crash).
        ids = [h.question_id for h in hits]
        self.assertIn("HQ-BAD", ids)
        self.assertNotIn("HQ-BADRE", ids)


class TestMandatoryProofQueue(unittest.TestCase):
    def _hyp(self, iid="INV-1", fn="sign_nonce", file="sign.rs", need_more=False):
        return cdh.Hypothesis(
            rank=1, score=0.7, invariant_id=iid, category="determinism",
            family="crypto_signing", target_lang="rust",
            statement="deterministic output", hypothesis="h",
            evidence_keywords=["nonce"],
            in_target_evidence=[{"keyword": "nonce", "file": file, "line": 2,
                                 "fn": (fn, 1)}],
            candidate_functions=[{"fn": fn, "file": file, "line": 1}],
            corpus_source_ids=["F-1"], need_more_evidence=need_more,
            differential_test_idea="diff")

    def test_emit_writes_open_proof_rows(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            qp = Path(d) / ".auditooor" / "exploit_queue.json"
            summary = cdh.emit_proof_queue(qp, "ws", [self._hyp()], [])
            self.assertEqual(summary["rows_written"], 1)
            data = json.loads(qp.read_text())
            self.assertEqual(data["schema"], "auditooor.exploit_queue.v1")
            row = data["queue"][0]
            self.assertEqual(row["proof_status"], "open")
            self.assertEqual(row["source"], cdh.CORPUS_HUNT_FUEL_SOURCE)
            self.assertEqual(row["broken_invariant_ids"], ["INV-1"])
            self.assertEqual(row["function"], "sign_nonce")

    def test_emit_idempotent_dedupe(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            qp = Path(d) / ".auditooor" / "exploit_queue.json"
            cdh.emit_proof_queue(qp, "ws", [self._hyp()], [])
            s2 = cdh.emit_proof_queue(qp, "ws", [self._hyp()], [])
            self.assertEqual(s2["rows_written"], 0)
            self.assertEqual(s2["rows_updated"], 1)
            data = json.loads(qp.read_text())
            self.assertEqual(len([r for r in data["queue"]
                                  if r["source"] == cdh.CORPUS_HUNT_FUEL_SOURCE]), 1)

    def test_emit_preserves_existing_non_fuel_rows(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            qp = Path(d) / ".auditooor" / "exploit_queue.json"
            qp.parent.mkdir(parents=True, exist_ok=True)
            qp.write_text(json.dumps({
                "schema": "auditooor.exploit_queue.v1", "queue": [
                    {"lead_id": "REAL-1", "source": "source-mined",
                     "contract": "other.rs", "function": "fff",
                     "proof_status": "proven"}]}), encoding="utf-8")
            cdh.emit_proof_queue(qp, "ws", [self._hyp()], [])
            data = json.loads(qp.read_text())
            leads = {r["lead_id"] for r in data["queue"]}
            self.assertIn("REAL-1", leads)
            real = [r for r in data["queue"] if r["lead_id"] == "REAL-1"][0]
            self.assertEqual(real["proof_status"], "proven")  # untouched

    def test_emit_dry_run_does_not_write(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            qp = Path(d) / ".auditooor" / "exploit_queue.json"
            summary = cdh.emit_proof_queue(qp, "ws", [self._hyp()], [], dry_run=True)
            self.assertTrue(summary["dry_run"])
            self.assertFalse(qp.exists())

    def test_emit_includes_hacker_q_rows(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            qp = Path(d) / ".auditooor" / "exploit_queue.json"
            hit = cdh.HackerQuestionHit(
                question_id="HQ-1", question_text="arbitrary call?",
                attack_class="arbitrary-call",
                matched_functions=[{"fn": "dispatch", "file": "g.rs", "line": 1}],
                grep_patterns=["executeRaw"], linked_invariant_ids=["INV-ARB"],
                source="case_study/x.md")
            summary = cdh.emit_proof_queue(qp, "ws", [], [hit])
            self.assertEqual(summary["fuel_rows_from_hacker_questions"], 1)
            data = json.loads(qp.read_text())
            hq_rows = [r for r in data["queue"]
                       if r["source"] == cdh.CORPUS_HUNT_HACKER_Q_SOURCE]
            self.assertEqual(len(hq_rows), 1)
            self.assertEqual(hq_rows[0]["proof_status"], "open")
            self.assertEqual(hq_rows[0]["attack_class"], "arbitrary-call")

    def test_run_emit_end_to_end(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            root = Path(d) / "ws"
            write(root / "sign.rs",
                  "fn sign(){ let nonce=1; // canonical deterministic\n}\n")
            _write_brain_prime(root, lanes=[{"attack_class": "crypto_signing"}])
            corpus = Path(d) / "c.jsonl"
            corpus.write_text(json.dumps({
                "invariant_id": "INV-DET", "category": "determinism",
                "statement": "deterministic output", "target_lang": "rust",
                "attack_signature": "deterministic", "commit_point_pattern": "canonical",
                "defense_layer": "deterministic", "source_finding_ids": ["a"]}) + "\n",
                encoding="utf-8")
            res = cdh.run(str(root), str(root), [str(corpus)], 10, 100,
                          hacker_questions_enabled=False)
            qp = root / cdh.EXPLOIT_QUEUE_REL
            summary = cdh.emit_proof_queue(
                qp, res["workspace"], res["_hypothesis_objs"], res["_hacker_hit_objs"])
            self.assertGreaterEqual(summary["rows_written"], 1)
            self.assertTrue(qp.exists())


class TestReviewedAwarenessFilter(unittest.TestCase):
    logical = {
        "target_unit": "generic.unit",
        "asset_invariant": "debits match credits",
        "violation_relation": "debit omitted",
        "actor_model": "permissionless caller",
        "impact_class": "direct-theft-funds",
    }

    def _hypothesis(self):
        return cdh.Hypothesis(
            rank=1, score=1.0, invariant_id="INV-AWARE", category="accounting",
            family="accounting_conservation", target_lang="rust", statement="s",
            hypothesis="h", evidence_keywords=[], in_target_evidence=[],
            candidate_functions=[{"fn": "withdraw", "file": "vault.rs", "line": 1}],
            corpus_source_ids=["SRC-1"], need_more_evidence=False,
            differential_test_idea="d")

    def _write_identity_map(self, root, obligation_id):
        row = {
            "schema": "auditooor.zero_day_identity_map.v1",
            "identity_key": "corpus_hypothesis:INV-AWARE:withdraw",
            "obligation_id": obligation_id,
            "revision_id": "zdr_current",
            "source_refs": ["src/vault.rs:1"],
            "asset_invariant": self.logical["asset_invariant"],
            "impact_class": self.logical["impact_class"],
        }
        path = root / "identity.jsonl"
        path.write_text(json.dumps(row) + "\n", encoding="utf-8")
        return path

    def _write_ledger(self, root, candidate):
        path = root / "awareness.json"
        path.write_text(json.dumps({
            "schema": cdh.AWARENESS_LEDGER_SCHEMA,
            "fail_closed": False,
            "validation_errors": [],
            "candidates": [candidate],
        }), encoding="utf-8")
        return path

    def test_filters_exact_reviewed_known_obligation_before_outputs(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            obligation_id = "zdo_" + cdh.zero_day_identity.digest(self.logical)
            identity = self._write_identity_map(root, obligation_id)
            ledger = self._write_ledger(root, {
                "candidate_id": "known-1", "terminal": True, "novelty_blocked": True,
                "state": "team_aware", "source_ids": ["github-issue-1"],
                "obligation_logical": self.logical,
            })
            hyps, questions, summary = cdh.filter_reviewed_awareness(
                [self._hypothesis()], [], identity, ledger, strict=True)
            self.assertEqual(hyps, [])
            self.assertEqual(questions, [])
            self.assertEqual(summary["excluded"], 1)
            self.assertEqual(summary["excluded_rows"][0]["obligation_id"], obligation_id)

    def test_marked_fixed_live_is_not_excluded(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            obligation_id = "zdo_" + cdh.zero_day_identity.digest(self.logical)
            identity = self._write_identity_map(root, obligation_id)
            ledger = self._write_ledger(root, {
                "candidate_id": "fixed-claim", "terminal": True, "novelty_blocked": False,
                "state": "marked_fixed_live", "source_ids": ["commit-1"],
                "obligation_logical": self.logical,
            })
            hyps, _, summary = cdh.filter_reviewed_awareness(
                [self._hypothesis()], [], identity, ledger, strict=True)
            self.assertEqual(len(hyps), 1)
            self.assertEqual(summary["excluded"], 0)

    def test_strict_mode_rejects_unlinked_candidate_before_queue_write(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            obligation_id = "zdo_" + cdh.zero_day_identity.digest(self.logical)
            identity = self._write_identity_map(root, obligation_id)
            ledger = self._write_ledger(root, {
                "candidate_id": "known-1", "terminal": True, "novelty_blocked": True,
                "state": "team_aware", "source_ids": ["github-issue-1"],
                "obligation_logical": self.logical,
            })
            source = self._hypothesis()
            other = cdh.Hypothesis(**{**source.__dict__, "invariant_id": "INV-UNLINKED"})
            with self.assertRaisesRegex(cdh.AwarenessFilterError, "unlinked_applicable_fuel"):
                cdh.filter_reviewed_awareness([other], [], identity, ledger, strict=True)


class TestInternalFnEnumeration(unittest.TestCase):
    """iter9-B: class-matched hypotheses must ALSO anchor to internal/private
    functions whose own name matches the bug class, not only the external
    entrypoint where a keyword first appears. Generic fixtures only - no
    target-specific symbol names.
    """

    def test_visibility_detected_per_language(self):
        import tempfile
        cases = [
            ("Demo.sol",
             "contract D {\n"
             "  function submit(bytes sig) external { _verifySig(sig); }\n"
             "  function _verifySig(bytes sig) internal { /* check */ }\n"
             "}\n",
             {"submit": "external", "_verifySig": "internal"}),
            ("lib.rs",
             "pub fn claim(e: u64) { settle_epoch(e); }\n"
             "fn settle_epoch(e: u64) { /* internal */ }\n",
             {"claim": "external", "settle_epoch": "internal"}),
            ("svc.go",
             "package x\n"
             "func ProcessReward(e uint64) { settleReward(e) }\n"
             "func settleReward(e uint64) {}\n",
             {"ProcessReward": "external", "settleReward": "internal"}),
            ("m.move",
             "public fun deposit() { settle_reward() }\n"
             "fun settle_reward() {}\n",
             {"deposit": "external", "settle_reward": "internal"}),
        ]
        for fname, src, expected in cases:
            with tempfile.TemporaryDirectory() as d:
                root = Path(d)
                write(root / fname, src)
                tm = cdh.build_target_model(root, 100)
                got = {f.name: f.visibility for f in tm.functions}
                for name, vis in expected.items():
                    self.assertEqual(got.get(name), vis,
                                     f"{fname}:{name} expected {vis} got {got.get(name)}")

    def test_internal_helper_anchored_as_candidate(self):
        """A signature-class keyword whose only token-presence is in the
        external entrypoint comment must still surface the internal
        `_validateSig`-style helper as a candidate (general, name-matched)."""
        import tempfile
        src = (
            "contract D {\n"
            "  function submit(bytes sig) external {\n"
            "    // signature is validated by the helper below\n"
            "    _validateSig(sig);\n"
            "  }\n"
            "  function _validateSig(bytes sig) internal {\n"
            "    // the actual signature validation lives here\n"
            "  }\n"
            "}\n")
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            write(root / "D.sol", src)
            tm = cdh.build_target_model(root, 100)
            hits, fns = cdh._scan_evidence(["signature", "validate"], tm)
            names = {c["fn"] for c in fns}
            self.assertIn("_validateSig", names,
                          "internal helper not anchored as candidate")
            internal_cands = [c for c in fns if c.get("internal")]
            self.assertTrue(any(c["fn"] == "_validateSig" for c in internal_cands))
            # external entrypoint behavior preserved (not dropped)
            self.assertIn("submit", names)

    def test_external_only_when_no_internal_match(self):
        """No internal fn matches the class -> behavior is unchanged (no
        spurious internal candidates injected)."""
        import tempfile
        src = (
            "contract D {\n"
            "  function transfer(uint amt) external {\n"
            "    // signature unrelated\n"
            "  }\n"
            "}\n")
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            write(root / "D.sol", src)
            tm = cdh.build_target_model(root, 100)
            hits, fns = cdh._scan_evidence(["signature"], tm)
            self.assertFalse(any(c.get("internal") for c in fns))

    def test_no_hardcoded_symbol_names(self):
        """An arbitrary internal validator name (not _validateSig / settle*)
        that matches a class keyword is still enumerated - proving the fix is
        general and not pattern-tuned to specific symbols."""
        import tempfile
        src = (
            "contract D {\n"
            "  function go() external { _checkNonceFresh(); }\n"
            "  function _checkNonceFresh() internal {}\n"
            "}\n")
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            write(root / "D.sol", src)
            tm = cdh.build_target_model(root, 100)
            hits, fns = cdh._scan_evidence(["nonce"], tm)
            self.assertTrue(any(c["fn"] == "_checkNonceFresh" and c.get("internal")
                                for c in fns))


class TestReadClassViewAnchoring(unittest.TestCase):
    """iter10-B: READ-class invariant families (conservation/monotonicity/
    bounds/epoch-boundary/rounding/freshness) must ALSO anchor to internal/
    private VIEW (pure-read) helpers whose name matches the bug class, not just
    internal mutating helpers (iter9-B). Generic fixtures only - no
    target-specific symbol names.
    """

    def test_view_detected_per_language(self):
        import tempfile
        cases = [
            ("V.sol",
             "contract V {\n"
             "  function poke() external { _calcEnd(); }\n"
             "  function _calcEnd() internal view returns (uint) { return 1; }\n"
             "  function _writeEnd() internal { x = 1; }\n"
             "}\n",
             {"_calcEnd": True, "_writeEnd": False, "poke": False}),
            ("v.rs",
             "pub fn run(&mut self) { self.calc_end(); }\n"
             "fn calc_end(&self) -> u64 { 1 }\n"
             "fn write_end(&mut self) {}\n",
             {"calc_end": True, "write_end": False, "run": False}),
            ("v.move",
             "public fun run() { calc_end() }\n"
             "fun calc_end(s: &S): u64 { 1 }\n"
             "fun write_end(s: &mut S) acquires R {}\n",
             {"calc_end": True, "write_end": False}),
        ]
        for fname, src, expected in cases:
            with tempfile.TemporaryDirectory() as d:
                root = Path(d)
                write(root / fname, src)
                tm = cdh.build_target_model(root, 100)
                got = {f.name: f.is_view for f in tm.functions}
                for name, want in expected.items():
                    self.assertEqual(got.get(name), want,
                                     f"{fname}:{name} expected is_view={want} got {got.get(name)}")

    def test_is_read_class_classifier(self):
        self.assertTrue(cdh._is_read_class("conservation", "general"))
        self.assertTrue(cdh._is_read_class("epoch-boundary", "general"))
        self.assertTrue(cdh._is_read_class("rounding", "general"))
        self.assertTrue(cdh._is_read_class("", "accounting_conservation"))
        self.assertTrue(cdh._is_read_class("", "state_freshness"))
        self.assertTrue(cdh._is_read_class("epoch-boundary-rounding", "general"))
        self.assertFalse(cdh._is_read_class("reentrancy", "reentrancy_atomicity"))
        self.assertFalse(cdh._is_read_class("authorization", "access_control"))

    def test_read_class_anchors_internal_view_helper(self):
        """An epoch-boundary (read-class) hypothesis must surface the internal
        VIEW helper _epochEnd even though the byte-scan lands on the external
        mutating entrypoint. General, name-matched: no symbol hard-coded."""
        import tempfile
        src = (
            "contract C {\n"
            "  function settle() external {\n"
            "    // epoch boundary computed by the view helper below\n"
            "    uint e = _epochEnd();\n"
            "  }\n"
            "  function _epochEnd() internal view returns (uint) {\n"
            "    return block.timestamp;\n"
            "  }\n"
            "}\n")
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            write(root / "C.sol", src)
            tm = cdh.build_target_model(root, 100)
            hits, fns = cdh._scan_evidence(["epoch", "boundary"], tm,
                                           read_class=True)
            view_cands = [c for c in fns if c.get("view")]
            self.assertTrue(any(c["fn"] == "_epochEnd" for c in view_cands),
                            "internal view helper not anchored for read-class")

    def test_view_helper_surfaces_even_when_mutating_fills_cap(self):
        """When several internal MUTATING helpers match first and fill the
        iter9-B name cap, the read-class second pass still surfaces the internal
        VIEW helper. Proves view anchoring is not crowded out by mutating cap."""
        import tempfile
        src = (
            "contract C {\n"
            "  function _round1() internal { y = 1; }\n"
            "  function _round2() internal { y = 2; }\n"
            "  function _round3() internal { y = 3; }\n"
            "  function _round4() internal { y = 4; }\n"
            "  function _round5() internal { y = 5; }\n"
            "  function _roundView() internal view returns (uint) { return y; }\n"
            "}\n")
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            write(root / "C.sol", src)
            tm = cdh.build_target_model(root, 100)
            # Without read_class: name-cap (4) fills with mutating helpers,
            # the view helper can be crowded out.
            _, fns_no = cdh._scan_evidence(["round"], tm, read_class=False)
            # With read_class: the dedicated view pass guarantees the view
            # helper is present.
            _, fns_yes = cdh._scan_evidence(["round"], tm, read_class=True)
            self.assertTrue(any(c["fn"] == "_roundView" and c.get("view")
                                for c in fns_yes),
                            "read-class view pass failed to surface view helper")

    def test_non_read_class_does_not_force_view_pass(self):
        """A non-read-class hypothesis keeps iter9-B behavior unchanged: no
        dedicated view pass, so behavior matches read_class=False."""
        import tempfile
        src = (
            "contract C {\n"
            "  function go() external { _authView(); }\n"
            "  function _authView() internal view returns (bool) { return true; }\n"
            "}\n")
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            write(root / "C.sol", src)
            tm = cdh.build_target_model(root, 100)
            # _authView is matched by name in pass 1 regardless (iter9-B), so it
            # is present - but its presence is NOT a result of the read-class
            # view pass. Assert behavior identical with/without read_class here.
            _, fns_no = cdh._scan_evidence(["auth"], tm, read_class=False)
            _, fns_yes = cdh._scan_evidence(["auth"], tm, read_class=True)
            names_no = sorted(c["fn"] for c in fns_no)
            names_yes = sorted(c["fn"] for c in fns_yes)
            self.assertEqual(names_no, names_yes)

    def test_read_class_no_matching_view_helper_no_injection(self):
        """Read-class hypothesis but no internal view helper name-matches ->
        no spurious view candidate injected."""
        import tempfile
        src = (
            "contract C {\n"
            "  function transfer(uint a) external {}\n"
            "}\n")
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            write(root / "C.sol", src)
            tm = cdh.build_target_model(root, 100)
            _, fns = cdh._scan_evidence(["conservation"], tm, read_class=True)
            self.assertFalse(any(c.get("view") for c in fns))

    def test_materialize_threads_read_class_flag(self):
        """End-to-end: a conservation-category invariant materialized against a
        target with an internal view helper surfaces the view helper in the
        hypothesis candidate_functions. Generic fixture."""
        import tempfile
        inv = cdh.Invariant(
            invariant_id="INV-TEST-CONS",
            category="conservation",
            statement="sum of shares conserved across mint and burn",
            target_lang="solidity",
            attack_signature="shares conservation rounding mint burn",
            commit_point_pattern="shares conserved",
            defense_layer="shares accounting",
            source_finding_ids=["X-1"],
            source_file="test.jsonl",
        )
        src = (
            "contract Vault {\n"
            "  function mint(uint a) external { _sharesFor(a); }\n"
            "  function _sharesFor(uint a) internal view returns (uint) {\n"
            "    return a; // shares computation\n"
            "  }\n"
            "}\n")
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            write(root / "Vault.sol", src)
            tm = cdh.build_target_model(root, 100)
            hyps = cdh.materialize([inv], tm, top=10)
            self.assertTrue(hyps)
            cands = hyps[0].candidate_functions
            self.assertTrue(
                any(c["fn"] == "_sharesFor" and c.get("view") for c in cands),
                "read-class view helper not threaded through materialize")


class TestReadClassPublicViewAnchoring(unittest.TestCase):
    """iter11-B: READ-class hypotheses must anchor VIEW helpers at ANY
    visibility (public/external AND internal) AND must match a view helper by a
    generic read-class computation token even when the invariant's own corpus
    keywords are absent from the helper name. Generic fixtures only - no
    target-specific symbol names. Anchored by the unbiased Predy fresh-target
    measurement (getSqrtPrice, external view) and the Intuition M-02
    totalBondedBalanceAtEpochEnd (public view) cases.
    """

    def test_public_view_helper_anchored_for_read_class(self):
        """A PUBLIC/external view helper that computes the contested read-class
        quantity is anchored (iter10 gate was internal-only and skipped it)."""
        import tempfile
        src = (
            "contract C {\n"
            "  function trade() external { uint p = getSqrtPrice(); }\n"
            "  function getSqrtPrice() external view returns (uint) {\n"
            "    return 1; // price computed by this pure-read helper\n"
            "  }\n"
            "}\n")
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            write(root / "C.sol", src)
            tm = cdh.build_target_model(root, 100)
            # Sanity: the helper parses as external + view.
            gsp = next(f for f in tm.functions if f.name == "getSqrtPrice")
            self.assertEqual(gsp.visibility, "external")
            self.assertTrue(gsp.is_view)
            # A bounds/conservation read-class hypothesis whose corpus keyword
            # ("conservation") does NOT appear in the helper name still anchors
            # it via the generic read-class computation token ("price").
            _, fns = cdh._scan_evidence(["conservation"], tm, read_class=True)
            view_cands = [c for c in fns if c.get("view")]
            self.assertTrue(
                any(c["fn"] == "getSqrtPrice" for c in view_cands),
                "public/external view helper not anchored for read-class")
            # Visibility is recorded honestly (external -> internal=False).
            gsp_cand = next(c for c in view_cands if c["fn"] == "getSqrtPrice")
            self.assertFalse(gsp_cand.get("internal"))

    def test_generic_token_match_when_corpus_keyword_absent(self):
        """The generic read-class computation-token arm fires for a numeric
        view helper whose name shares no token with the invariant keywords."""
        import tempfile
        # Helper name contains a generic read-class token ("epoch","end","total"
        # "balance") but NOT the invariant keyword "inflation".
        src = (
            "contract C {\n"
            "  function claim() external { _q(); }\n"
            "  function totalBalanceAtEpochEnd() public view returns (uint) {\n"
            "    return 1;\n"
            "  }\n"
            "  function _q() internal {}\n"
            "}\n")
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            write(root / "C.sol", src)
            tm = cdh.build_target_model(root, 100)
            _, fns = cdh._scan_evidence(["inflation"], tm, read_class=True)
            self.assertTrue(
                any(c["fn"] == "totalBalanceAtEpochEnd" and c.get("view")
                    for c in fns),
                "generic-token view anchoring failed when corpus keyword absent")

    def test_generic_token_matcher_unit(self):
        """Unit cover for _matches_read_class_view_name: the three live view
        bug-helper names match; a name with no compute token does not; a bare
        'get' getter does not (intentionally excluded as too broad)."""
        # getsqrtprice contains both "sqrt" and "price" tokens; either is a
        # valid read-class compute-token match (frozenset order is unspecified).
        self.assertIn(cdh._matches_read_class_view_name("getsqrtprice"),
                      {"sqrt", "price"})
        self.assertTrue(cdh._matches_read_class_view_name(
            "totalbondedbalanceatepochend"))
        self.assertTrue(cdh._matches_read_class_view_name(
            "_calculateepochtimestampend"))
        self.assertIsNone(cdh._matches_read_class_view_name("transferfrom"))
        # A bare "getThing" getter shares no compute token -> not matched.
        self.assertIsNone(cdh._matches_read_class_view_name("getowner"))

    def test_non_view_not_anchored_by_generic_token(self):
        """The generic-token arm only fires on VIEW helpers; a MUTATING fn whose
        name contains a compute token is NOT injected by Pass 2 (it is Pass 1's
        job, gated on internal visibility)."""
        import tempfile
        # External MUTATING fn named with a compute token ("price").
        src = (
            "contract C {\n"
            "  function setPrice(uint p) external { stored = p; }\n"
            "}\n")
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            write(root / "C.sol", src)
            tm = cdh.build_target_model(root, 100)
            _, fns = cdh._scan_evidence(["conservation"], tm, read_class=True)
            # setPrice is external+mutating: not a view, so Pass 2 skips it, and
            # Pass 1 skips it (external). No view candidate injected.
            self.assertFalse(any(c.get("view") for c in fns))

    def test_internal_view_still_anchored_regression(self):
        """Regression: the original internal-view anchoring (iter10-B) still
        works after the iter11-B visibility-widening + generic-token change."""
        import tempfile
        src = (
            "contract C {\n"
            "  function settle() external { uint e = _epochEnd(); }\n"
            "  function _epochEnd() internal view returns (uint) {\n"
            "    return block.timestamp;\n"
            "  }\n"
            "}\n")
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            write(root / "C.sol", src)
            tm = cdh.build_target_model(root, 100)
            _, fns = cdh._scan_evidence(["epoch", "boundary"], tm,
                                        read_class=True)
            ic = next(c for c in fns if c["fn"] == "_epochEnd")
            self.assertTrue(ic.get("view"))
            self.assertTrue(ic.get("internal"))


class TestFamilyNameAnchoring(unittest.TestCase):
    """iter14: the INV-CON-004 mislanding fix. A conservation/normalization
    hypothesis must anchor the function whose OWN NAME carries the CLASS signal
    (validator/distribution/weight/epoch/reward/normalize), not merely the
    nearest-preceding fn of a literal-keyword byte-hit in an unrelated dense
    file. GENERAL: keyed on the invariant's CLASS-FAMILY vocabulary; NO
    target-specific symbol names (validateIntents / intents / Quicksilver /
    Synthetify) are hard-coded.
    """

    def test_family_name_tokens_accounting_widened(self):
        toks = cdh._family_name_tokens("accounting_conservation")
        # source_tokens of the accounting family ...
        self.assertIn("balance", toks)
        self.assertIn("shares", toks)
        # ... PLUS the widened distribution/validator/epoch/reward vocabulary
        # that names the real conserved-quantity function.
        for t in ("distribution", "validator", "weight", "epoch", "reward",
                  "normalize", "intents", "settle"):
            self.assertIn(t, toks, f"accounting family missing class token {t}")

    def test_family_name_tokens_no_cross_family_leak(self):
        """The accounting widening must NOT leak into another family: a
        crypto_signing hypothesis does not gain validator/distribution tokens."""
        crypto = cdh._family_name_tokens("crypto_signing")
        self.assertNotIn("distribution", crypto)
        self.assertNotIn("validator", crypto)
        self.assertNotIn("reward", crypto)
        # but its own class vocabulary is present
        self.assertIn("nonce", crypto)
        self.assertIn("signature", crypto)

    def test_family_name_tokens_none_and_unknown(self):
        self.assertEqual(cdh._family_name_tokens(None), frozenset())
        self.assertEqual(cdh._family_name_tokens(""), frozenset())
        # unknown family -> empty (no crash)
        self.assertEqual(cdh._family_name_tokens("not_a_family"), frozenset())

    def test_conservation_anchors_external_class_named_fn(self):
        """The core mislanding fixture, GENERIC. The conservation invariant's
        only literal byte-hit lands on an unrelated handler in a dense file; the
        REAL bug fn is EXTERNAL and named for the conserved quantity
        (distribution/weight) but carries NONE of the invariant's literal grep
        keywords. It must still be anchored AND ranked ahead of the decoy."""
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            write(root / "ibc_packet_handlers.go",
                  "package x\n"
                  "func handlePacket(p Packet) {\n"
                  "  // conservation invariant maintained upstream\n"
                  "  process(p)\n"
                  "}\n")
            write(root / "distrib.go",
                  "package x\n"
                  "func ApplyValidatorDistribution(w Weights) {\n"
                  "  // sums and normalizes weights; no literal corpus keyword\n"
                  "}\n")
            tm = cdh.build_target_model(root, 100)
            hits, fns = cdh._scan_evidence(
                ["conservation"], tm, read_class=True,
                family="accounting_conservation")
            names = [c["fn"] for c in fns]
            self.assertIn("ApplyValidatorDistribution", names,
                          "class-named external fn not anchored (mislanding)")
            # ranked AHEAD of the spurious byte-position decoy
            self.assertLess(names.index("ApplyValidatorDistribution"),
                            names.index("handlePacket"),
                            "class-named anchor not promoted above byte-position decoy")
            fa = next(c for c in fns if c["fn"] == "ApplyValidatorDistribution")
            self.assertTrue(fa.get("family_anchor"))
            self.assertFalse(fa.get("internal"))  # honest: it's external

    def test_no_family_arg_is_unchanged(self):
        """Backward-compat: with no family supplied, NO family anchor is
        injected and behavior matches the prior byte-position + name passes."""
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            write(root / "a.go",
                  "package x\n"
                  "func ApplyValidatorDistribution() {}\n"
                  "func handlePacket() { // conservation\n }\n")
            tm = cdh.build_target_model(root, 100)
            _, fns_none = cdh._scan_evidence(["conservation"], tm, family=None)
            self.assertFalse(any(c.get("family_anchor") for c in fns_none))
            # and the default (no kwarg) path is identical
            _, fns_def = cdh._scan_evidence(["conservation"], tm)
            self.assertEqual([c["fn"] for c in fns_none],
                             [c["fn"] for c in fns_def])

    def test_no_cross_family_anchor_in_scan(self):
        """A crypto_signing hypothesis must NOT anchor a distribution/validator
        function (proves the widening is class-gated, not global)."""
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            write(root / "a.go",
                  "package x\n"
                  "func ApplyValidatorDistribution() {}\n"
                  "func signMessage() { /* nonce path */ }\n")
            tm = cdh.build_target_model(root, 100)
            _, fns = cdh._scan_evidence(["nonce"], tm, family="crypto_signing")
            fam_anchored = {c["fn"] for c in fns if c.get("family_anchor")}
            self.assertNotIn("ApplyValidatorDistribution", fam_anchored)

    def test_no_spurious_anchor_when_no_class_named_fn(self):
        """Conservation hypothesis but no function carries a class-family token
        -> no family anchor injected (no false positives)."""
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            write(root / "a.go",
                  "package x\n"
                  "func handlePacket() { // conservation\n }\n"
                  "func process() {}\n")
            tm = cdh.build_target_model(root, 100)
            _, fns = cdh._scan_evidence(
                ["conservation"], tm, family="accounting_conservation")
            self.assertFalse(any(c.get("family_anchor") for c in fns))

    def test_materialize_threads_family_anchor_end_to_end(self):
        """End-to-end through materialize(): a conservation invariant whose only
        literal byte-hit is in a decoy file surfaces the class-named external fn
        as the FIRST candidate. Generic fixture, no symbol hard-coding."""
        import tempfile
        inv = cdh.Invariant(
            invariant_id="INV-CON-004", category="conservation",
            statement="validator-set weight distribution conserves total",
            target_lang="go", attack_signature="conservation",
            commit_point_pattern="total conserved", defense_layer="accounting",
            source_finding_ids=["F-1"], source_file="f.jsonl")
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            write(root / "ibc_packet_handlers.go",
                  "package x\n"
                  "func handlePacket(p Packet) {\n"
                  "  // conservation invariant maintained\n"
                  "  process(p)\n"
                  "}\n")
            write(root / "distrib.go",
                  "package x\nfunc ApplyValidatorDistribution(w Weights) {}\n")
            tm = cdh.build_target_model(root, 100)
            hyps = cdh.materialize([inv], tm, top=10)
            self.assertTrue(hyps)
            cands = hyps[0].candidate_functions
            self.assertTrue(cands)
            self.assertEqual(cands[0]["fn"], "ApplyValidatorDistribution",
                             "materialize did not rank the class-named fn first")
            # the proof-queue row therefore points at the right function
            row = cdh._hypothesis_to_row(hyps[0], "ws")
            self.assertEqual(row["function"], "ApplyValidatorDistribution")

    def test_generalizes_across_class_signals(self):
        """The fix reaches the CLASS of real symbols (epoch/reward/normalize),
        not just one keyword. Each distinct class-named external fn anchors for a
        conservation hypothesis with an unrelated literal byte-hit."""
        import tempfile
        for fn_name in ("SettleEpochRewards", "NormalizeWeights",
                        "AccrueDelegationCommission"):
            with tempfile.TemporaryDirectory() as d:
                root = Path(d)
                write(root / "decoy.go",
                      "package x\nfunc handlePacket() { // conservation\n }\n")
                write(root / "real.go",
                      f"package x\nfunc {fn_name}() {{}}\n")
                tm = cdh.build_target_model(root, 100)
                _, fns = cdh._scan_evidence(
                    ["conservation"], tm, family="accounting_conservation")
                names = [c["fn"] for c in fns]
                self.assertIn(fn_name, names,
                              f"class signal {fn_name} not anchored")
                self.assertLess(names.index(fn_name), names.index("handlePacket"),
                                f"{fn_name} not ranked above byte-position decoy")


class TestUnboundedQueue(unittest.TestCase):
    """Pillar-1 unbounded-resumable per-fn queue (the --unbounded-queue mode).

    The capability is COMMITTED in corpus-driven-hunt.py but its dedicated unit
    tests were never written. These four tests close that gap, mirroring the
    mocked-workspace / in-memory-record discipline of test_hunt_resume_planner.py.
    NO live LLM/provider call is made anywhere: build_target_model walks a
    tempfile tree, materialize is pure, and the budget-halt path is exercised by
    classifying an in-memory copy of the dispatcher's real halted-record shape.
    """

    def _index_corpus(self, n):
        """Build an in-memory corpus of `n` distinct rust crypto_signing
        invariants, each grep-anchored to a distinct function via the shared
        'nonce' token, so EACH materializes to its own hypothesis."""
        return [
            cdh.Invariant(
                invariant_id="INV-%03d" % i, category="determinism",
                statement="deterministic nonce %d" % i, target_lang="rust",
                attack_signature="nonce", commit_point_pattern="nonce",
                defense_layer="nonce", source_finding_ids=["F-%d" % i],
                source_file="c.jsonl")
            for i in range(n)
        ]

    def _write_n_fn_workspace(self, root, n):
        """Write a mocked N-function rust workspace (one nonce-bearing fn per
        file so every fn is in-scope + family-relevant). Generic: no
        target/workspace name appears in any symbol."""
        for i in range(n):
            write(root / ("mod_%03d.rs" % i),
                  "fn handle_%03d() { let nonce = %d; // canonical nonce path\n}\n"
                  % (i, i))

    # (a) ALL-FNS-QUEUED -------------------------------------------------------
    def test_unbounded_indexes_and_queues_all_functions(self):
        """37-function workspace + unbounded sentinels -> ALL 37 functions are
        indexed (not the prior 12 cap) and ONE MIMO task is queued per
        hypothesis (no top-N / concurrency truncation)."""
        import tempfile
        N = 37
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            self._write_n_fn_workspace(root, N)
            # max_functions<=0 is the committed unbounded sentinel that routes
            # build_target_model to float("inf") (index every fn).
            tm = cdh.build_target_model(root, max_functions=0)
            self.assertEqual(tm.function_count, N,
                             "unbounded did not index ALL functions")
            self.assertEqual(len(tm.functions), N)

            invs = self._index_corpus(N)
            # top=None is the committed unbounded sentinel -> keep every
            # materialized hypothesis (no top-N cap).
            hyps = cdh.materialize(invs, tm, top=None)
            self.assertEqual(len(hyps), N,
                             "unbounded materialize dropped hypotheses")

            # unbounded=True -> ONE task per hypothesis (no hyps[:concurrency]).
            batch = cdh.build_mimo_batch(hyps, tm, "ws", concurrency=4,
                                         unbounded=True)
            self.assertTrue(batch["unbounded"])
            self.assertEqual(batch["task_count"], N,
                             "unbounded batch truncated below the full set")
            self.assertEqual(batch["hypotheses_total"], N)
            self.assertEqual(batch["mimo_pending"], N)
            # concurrency is recorded as the inter-batch cap, NOT a truncator.
            self.assertEqual(batch["concurrency"], 4)

    def test_unbounded_via_run_sets_function_count_to_all(self):
        """End-to-end: run(..., unbounded_queue=True) forces both committed
        sentinels (max_functions=0, top=None) so function_count == N and every
        hypothesis survives. Proves the public run() entrypoint, not just the
        helpers, honors the unbounded opt-in."""
        import tempfile
        N = 20
        with tempfile.TemporaryDirectory() as d:
            root = Path(d) / "ws"
            self._write_n_fn_workspace(root, N)
            _write_brain_prime(root, lanes=[{"attack_class": "crypto_signing"}])
            corpus = Path(d) / "c.jsonl"
            with corpus.open("w", encoding="utf-8") as fh:
                for inv in self._index_corpus(N):
                    fh.write(json.dumps({
                        "invariant_id": inv.invariant_id,
                        "category": inv.category, "statement": inv.statement,
                        "target_lang": inv.target_lang,
                        "attack_signature": inv.attack_signature,
                        "commit_point_pattern": inv.commit_point_pattern,
                        "defense_layer": inv.defense_layer,
                        "source_finding_ids": inv.source_finding_ids}) + "\n")
            # Pass a deliberately SMALL bounded cap (12) and top (5): the
            # unbounded_queue flag must OVERRIDE both to the all-fns path.
            res = cdh.run(str(root), str(root), [str(corpus)], top=5,
                          max_functions=12, hacker_questions_enabled=False,
                          unbounded_queue=True)
            self.assertNotIn("error", res)
            self.assertEqual(res["target"]["function_count"], N,
                             "run() did not index all fns under unbounded_queue")
            self.assertEqual(len(res["hypotheses"]), N,
                             "run() capped hypotheses despite unbounded_queue")

    # (b) DEFAULT-UNCHANGED ----------------------------------------------------
    def test_default_bounded_path_unchanged_no_unbounded_keys(self):
        """Same workspace, NO unbounded flag -> the prior caps still apply and
        the batch emits NO unbounded/coverage key. Regression guard that the
        committed default path is byte-for-byte unchanged."""
        import tempfile
        N = 37
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            self._write_n_fn_workspace(root, N)
            # Default bounded build with the historical 12-fn cap.
            tm = cdh.build_target_model(root, max_functions=12)
            self.assertEqual(tm.function_count, 12,
                             "bounded cap of 12 no longer applies (regression)")

            invs = self._index_corpus(N)
            # Default bounded materialize with a positive top cap.
            hyps = cdh.materialize(invs, tm, top=10)
            self.assertEqual(len(hyps), 10,
                             "bounded top=10 cap no longer applies (regression)")

            # Default (unbounded omitted) -> clamp to min(concurrency,4) and
            # emit NONE of the unbounded keys.
            batch = cdh.build_mimo_batch(hyps, tm, "ws", concurrency=10)
            self.assertEqual(batch["concurrency"], 4)
            self.assertEqual(batch["task_count"], 4)
            for k in ("unbounded", "hypotheses_total", "mimo_pending",
                      "throttle_note"):
                self.assertNotIn(k, batch,
                                 "default bounded batch leaked unbounded key " + k)

    def test_default_run_result_has_no_coverage_key(self):
        """run() default (unbounded_queue absent) -> result carries no
        coverage/unbounded_queue key. The coverage block is set ONLY on the
        unbounded path."""
        import tempfile
        N = 20
        with tempfile.TemporaryDirectory() as d:
            root = Path(d) / "ws"
            self._write_n_fn_workspace(root, N)
            _write_brain_prime(root, lanes=[{"attack_class": "crypto_signing"}])
            corpus = Path(d) / "c.jsonl"
            with corpus.open("w", encoding="utf-8") as fh:
                for inv in self._index_corpus(N):
                    fh.write(json.dumps({
                        "invariant_id": inv.invariant_id,
                        "category": inv.category, "statement": inv.statement,
                        "target_lang": inv.target_lang,
                        "attack_signature": inv.attack_signature,
                        "commit_point_pattern": inv.commit_point_pattern,
                        "defense_layer": inv.defense_layer,
                        "source_finding_ids": inv.source_finding_ids}) + "\n")
            res = cdh.run(str(root), str(root), [str(corpus)], top=5,
                          max_functions=12, hacker_questions_enabled=False)
            self.assertNotIn("error", res)
            # bounded caps held
            self.assertEqual(res["target"]["function_count"], 12)
            self.assertEqual(len(res["hypotheses"]), 5)
            # no unbounded/coverage emission on the default path
            self.assertNotIn("coverage", res)
            self.assertNotIn("unbounded_queue", res)

    # (c) BUDGET-STOP ----------------------------------------------------------
    def test_budget_halt_records_are_nonsuccess_and_requeuable(self):
        """A budget-exceeded run writes the remaining tasks as HALTED records
        (status=halted, result=null). The resume-side classifier must mark them
        non-success, and the resume planner must re-select them (re-queuable).
        Already-anchored (status=ok+anchor) tasks must NEVER be re-queued."""
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            record_dir = Path(d) / "records"
            record_dir.mkdir(parents=True, exist_ok=True)

            # 2 completed-before-halt tasks (success) + 3 halted-by-budget tasks.
            done_ids = ["corpus_hunt_ws_001", "corpus_hunt_ws_002"]
            halted_ids = ["corpus_hunt_ws_003", "corpus_hunt_ws_004",
                          "corpus_hunt_ws_005"]
            for i, tid in enumerate(done_ids):
                rec = _mock_dispatcher_ok_record(tid, "handle_%d" % i,
                                                 "mod_%d.rs" % i)
                (record_dir / (tid + ".json")).write_text(
                    json.dumps(rec), encoding="utf-8")
            for tid in halted_ids:
                rec = _mock_dispatcher_halt_record(tid)
                # halt record carries the budget halt_reason and a null result.
                self.assertIsNone(rec["result"])
                self.assertEqual(rec["status"], "halted")
                self.assertIn("BUDGET_CAP_EXCEEDED", rec["error"])
                (record_dir / (tid + ".json")).write_text(
                    json.dumps(rec), encoding="utf-8")

            # The REAL resume-side classifier: a halted/null-result record is
            # non-success (classified "empty" == ran-but-anchored-nothing, the
            # re-huntable bucket), an anchored ok record is "success".
            for tid in halted_ids:
                klass, _ = _hrh.classify_record(_mock_dispatcher_halt_record(tid))
                self.assertNotEqual(klass, "success",
                                    "halted record misclassified as success")
                self.assertIn(klass, _hrp._REHUNT_KLASSES,
                              "halted record is not in the re-queuable set")
            for i, tid in enumerate(done_ids):
                klass, _ = _hrh.classify_record(
                    _mock_dispatcher_ok_record(tid, "handle_%d" % i,
                                               "mod_%d.rs" % i))
                self.assertEqual(klass, "success",
                                 "anchored ok record not classified success")

            # The resume planner over the whole dir: it must re-select exactly
            # the 3 halted tasks and NEVER the 2 successes (no silent cap; the
            # full pending denominator is surfaced).
            plan, _ = _hrp.build_resume_plan(
                record_dir, _hrh.classify_record, providers=["deepseek"])
            requeued = {e["task_id"] for e in plan["resume_tasks"]}
            self.assertEqual(requeued, set(halted_ids),
                             "resume plan did not re-queue exactly the halted set")
            for tid in done_ids:
                self.assertNotIn(tid, requeued,
                                 "resume plan re-queued an already-anchored task")
            self.assertEqual(plan["resume_task_count"], len(halted_ids))
            # honest pending denominator, no silent halt swallow
            self.assertFalse(plan["idempotent_empty"])

    def test_unbounded_batch_surfaces_pending_denominator_no_silent_cap(self):
        """NO-SILENT-CAPS: in unbounded mode mimo_pending == task_count ==
        hypotheses_total at generation time, so the operator sees the honest
        coverage denominator a budget-halt would otherwise hide."""
        import tempfile
        N = 15
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            self._write_n_fn_workspace(root, N)
            tm = cdh.build_target_model(root, max_functions=0)
            hyps = cdh.materialize(self._index_corpus(N), tm, top=None)
            batch = cdh.build_mimo_batch(hyps, tm, "ws", concurrency=4,
                                         unbounded=True)
            self.assertEqual(
                batch["mimo_pending"], batch["task_count"])
            self.assertEqual(
                batch["hypotheses_total"], batch["task_count"])
            self.assertIn("hunt-resume-planner.py", batch["throttle_note"])

    # (d) GENERIC --------------------------------------------------------------
    def test_no_workspace_literal_in_unbounded_output(self):
        """The unbounded batch + run output must carry NO hardcoded
        workspace/target literal: the only workspace string present is the one
        the caller passes in (here the neutral token 'WS-PLACEHOLDER'), proving
        the code is target-agnostic."""
        import tempfile
        N = 8
        token = "WS-PLACEHOLDER"
        # Tokens that would betray a hardcoded target if they leaked into output.
        forbidden = ("dydx", "spark", "hyperbridge", "polymarket", "centrifuge",
                     "morpho", "intuition", "predy")
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            self._write_n_fn_workspace(root, N)
            tm = cdh.build_target_model(root, max_functions=0)
            hyps = cdh.materialize(self._index_corpus(N), tm, top=None)
            batch = cdh.build_mimo_batch(hyps, tm, token, concurrency=4,
                                         unbounded=True)
            blob = json.dumps(batch).lower()
            for bad in forbidden:
                self.assertNotIn(bad, blob,
                                 "unbounded batch leaked hardcoded target " + bad)
            # the workspace string in the batch is exactly the caller's token
            self.assertEqual(batch["workspace"], token)
            self.assertTrue(all(t["workspace"] == token for t in batch["tasks"]))
            # task_ids are parameterized on the caller token, not a literal
            self.assertTrue(
                all(token in t["task_id"] for t in batch["tasks"]))


class MakefileCorpusDrivenHuntDefaultsTest(unittest.TestCase):
    def test_makefile_defaults_to_all_functions_for_standalone_target(self):
        makefile = (REPO / "Makefile").read_text(encoding="utf-8")
        start = makefile.index("corpus-driven-hunt:")
        end = makefile.index("corpus-driven-hunt-test:", start)
        body = makefile[start:end]
        self.assertIn("[MAX_FUNCTIONS=all]", body)
        self.assertIn('--max-functions "$(if $(MAX_FUNCTIONS),$(MAX_FUNCTIONS),all)"', body)
        self.assertNotIn("MAX_FUNCTIONS=200", body)
        self.assertNotIn('$(if $(MAX_FUNCTIONS),$(MAX_FUNCTIONS),200)', body)


if __name__ == "__main__":
    unittest.main()
