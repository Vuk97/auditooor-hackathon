"""Unit tests for tools/fetchable-vuln-corpus-build.py.

Hermetic: each test builds a synthetic audits-root with a REAL throwaway git
checkout so the fetchability gate (file_line resolves on disk at HEAD) is
exercised end-to-end without touching /Users/wolf/audits.
"""
from __future__ import annotations

import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location(
    "fetchable_vuln_corpus_build",
    ROOT / "tools" / "fetchable-vuln-corpus-build.py",
)
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)  # type: ignore[union-attr]

SCHEMA_PATH = ROOT / "reference" / "schemas" / "auditooor.fetchable_vuln_corpus.v1.schema.json"


def _git(args, cwd):
    subprocess.run(["git", "-C", str(cwd), *args],
                   check=True, capture_output=True, text=True)


def _make_checkout(src_dir: Path, repo_url: str, files: dict) -> str:
    """Create a real git repo at src_dir with `files` (relpath->content),
    a remote origin url, and return its HEAD sha."""
    src_dir.mkdir(parents=True, exist_ok=True)
    _git(["init", "-q"], src_dir)
    _git(["config", "user.email", "t@t.t"], src_dir)
    _git(["config", "user.name", "t"], src_dir)
    _git(["remote", "add", "origin", repo_url], src_dir)
    for rel, content in files.items():
        p = src_dir / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    _git(["add", "-A"], src_dir)
    _git(["commit", "-q", "-m", "init"], src_dir)
    return subprocess.run(["git", "-C", str(src_dir), "rev-parse", "HEAD"],
                          capture_output=True, text=True).stdout.strip()


def _write_finding(ws: Path, status: str, slug: str, body: str, folder=True):
    if folder:
        d = ws / "submissions" / status / slug
        d.mkdir(parents=True, exist_ok=True)
        (d / f"{slug}.md").write_text(body)
    else:
        d = ws / "submissions" / status
        d.mkdir(parents=True, exist_ok=True)
        (d / f"{slug}.md").write_text(body)


class TestNormalizeAndSplit(unittest.TestCase):
    def test_class_synonyms_merge(self):
        self.assertEqual(mod.normalize_vuln_class("theft"), "fund-theft")
        self.assertEqual(mod.normalize_vuln_class("denial-of-service"),
                         "dos-resource-exhaustion")
        self.assertEqual(mod.normalize_vuln_class("decode-mismatch (RLP)"),
                         "decode-mismatch")

    def test_split_is_deterministic_and_class_level(self):
        # same class -> same split regardless of repetition
        s1 = mod.assign_split("fund-theft", 50, 0)
        s2 = mod.assign_split("fund-theft", 50, 0)
        self.assertEqual(s1, s2)
        self.assertIn(s1, ("TRAIN", "HELD_OUT"))

    def test_held_out_pct_zero_puts_all_in_train(self):
        for cls in ("a", "b", "fund-theft", "arithmetic"):
            self.assertEqual(mod.assign_split(cls, 0, 0), "TRAIN")

    def test_held_out_pct_hundred_puts_all_in_heldout(self):
        for cls in ("a", "b", "fund-theft", "arithmetic"):
            self.assertEqual(mod.assign_split(cls, 100, 0), "HELD_OUT")


class TestInstanceHoldoutSplit(unittest.TestCase):
    """Instance-holdout mode: classes with >=2 cases land in BOTH splits;
    singleton classes are wholly TRAIN; the split is deterministic."""

    def _cases(self):
        # 3 instances of one class, 2 of another, 1 singleton
        cases = []
        for i in range(3):
            cases.append({"case_id": f"ws--theft-{i}", "vuln_class": "fund-theft"})
        for i in range(2):
            cases.append({"case_id": f"ws--dos-{i}",
                          "vuln_class": "dos-resource-exhaustion"})
        cases.append({"case_id": "ws--solo-0", "vuln_class": "access-control"})
        return cases

    def test_multi_case_class_lands_in_both_splits(self):
        cases = self._cases()
        mod.assign_splits_instance_holdout(cases, held_out_pct=30, seed=0)
        per = {}
        for c in cases:
            per.setdefault(c["vuln_class"], set()).add(c["split"])
        # both multi-case classes appear in TRAIN and HELD_OUT
        self.assertEqual(per["fund-theft"], {"TRAIN", "HELD_OUT"})
        self.assertEqual(per["dos-resource-exhaustion"], {"TRAIN", "HELD_OUT"})

    def test_singleton_class_is_wholly_train(self):
        cases = self._cases()
        mod.assign_splits_instance_holdout(cases, held_out_pct=30, seed=0)
        solo = [c for c in cases if c["vuln_class"] == "access-control"]
        self.assertEqual({c["split"] for c in solo}, {"TRAIN"})

    def test_instance_holdout_is_deterministic(self):
        a = self._cases(); b = self._cases()
        mod.assign_splits_instance_holdout(a, 30, 0)
        mod.assign_splits_instance_holdout(b, 30, 0)
        self.assertEqual({c["case_id"]: c["split"] for c in a},
                         {c["case_id"]: c["split"] for c in b})

    def test_split_mode_field_stamped(self):
        cases = self._cases()
        mod.assign_splits_instance_holdout(cases, 30, 0)
        self.assertTrue(all(c["split_mode"] == "instance-holdout" for c in cases))
        cd = self._cases()
        mod.assign_splits_class_disjoint(cd, 50, 0)
        self.assertTrue(all(c["split_mode"] == "class-disjoint" for c in cd))

    def test_two_case_class_keeps_one_each_side_even_if_hash_skews(self):
        # exercise the forced-non-empty invariant across many seeds: a 2-case
        # class must never collapse to a single split
        for seed in range(25):
            cases = [{"case_id": f"x--a-{seed}", "vuln_class": "k"},
                     {"case_id": f"x--b-{seed}", "vuln_class": "k"}]
            mod.assign_splits_instance_holdout(cases, 30, seed)
            splits = {c["split"] for c in cases}
            self.assertEqual(splits, {"TRAIN", "HELD_OUT"},
                             f"seed={seed} collapsed 2-case class to {splits}")

    def test_build_corpus_instance_holdout_mode(self):
        # end-to-end through build_corpus with a real checkout + two same-class
        # findings so the class spans both splits
        tmp = Path(tempfile.mkdtemp(prefix="fvc_ih_"))
        audits = tmp / "audits"
        ws = audits / "demo"
        _make_checkout(ws / "src", "https://github.com/acme/demo.git",
                       {"src/V.sol": "x\n" * 80})
        for i in range(4):
            _write_finding(
                ws, "filed", f"theft-{i}-HIGH",
                f"# theft {i}\n- attack_class: fund-theft\n- Severity: High\n"
                f"- source-proof: `src/V.sol:{10 + i}`\n",
            )
        cases, header, _ = mod.build_corpus(
            audits, ["demo"], held_out_pct=30, seed=0,
            split_mode="instance-holdout",
        )
        self.assertEqual(header["split_mode"], "instance-holdout")
        per = {}
        for c in cases:
            per.setdefault(c["vuln_class"], set()).add(c["split"])
        self.assertEqual(per["fund-theft"], {"TRAIN", "HELD_OUT"})
        self.assertIn("fund-theft", header["classes_in_both_splits"])
        self.assertTrue(all(c["split_mode"] == "instance-holdout" for c in cases))

    def test_build_corpus_rejects_unknown_split_mode(self):
        with self.assertRaises(ValueError):
            mod.build_corpus(Path("/nonexistent"), [], 50, 0,
                             split_mode="bogus-mode")


class TestExtraction(unittest.TestCase):
    def test_keyword_classifier(self):
        text = "# X\n- selected_impact: Stealing or loss of funds via drain"
        self.assertEqual(mod.classify_by_keywords(text, "x"), "fund-theft")

    def test_candidate_refs_prefers_frequent_bug_site(self):
        text = (
            "# bug\n"
            "the bug is at `src/Vault.sol:10`\n"
            "again `src/Vault.sol:10` and `src/Vault.sol:10`\n"
            "the correct sibling is `src/Other.sol:99`\n"
        )
        refs = mod._candidate_refs(text)
        self.assertEqual(refs[0], ("src/Vault.sol", 10))

    def test_candidate_refs_primary_field_wins(self):
        text = (
            "# bug\n"
            "noise `src/Noise.sol:1` `src/Noise.sol:1` `src/Noise.sol:1`\n"
            "- source-proof: `src/Real.sol:42` is the bug\n"
        )
        refs = mod._candidate_refs(text)
        self.assertEqual(refs[0], ("src/Real.sol", 42))


class TestEndToEndBuild(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="fvc_"))
        self.audits = self.tmp / "audits"
        ws = self.audits / "demo"
        # real checkout with the vulnerable file present at HEAD
        self.sha = _make_checkout(
            ws / "src",
            "https://github.com/acme/demo.git",
            {"src/Vault.sol": "// L1\n" * 50},
        )
        # a confirmed finding (folder layout) citing a RESOLVING line
        _write_finding(
            ws, "filed", "vault-reentrancy-HIGH",
            "# Reentrancy in Vault\n"
            "- attack_class: reentrancy\n"
            "- Severity: High\n"
            "- source-proof: `src/Vault.sol:12` is the reentrant call\n",
        )
        # a confirmed finding citing a NON-resolving line -> must be dropped
        _write_finding(
            ws, "filed", "ghost-bug-MEDIUM",
            "# Ghost\n- attack_class: oracle\n- Severity: Medium\n"
            "- source-proof: `src/DoesNotExist.sol:5`\n",
        )
        # a KILLED finding -> not confirmed positive
        _write_finding(
            ws, "filed", "dead-KILLED-dupe",
            "# Dead\n- attack_class: dos\n- Severity: High\n"
            "`src/Vault.sol:20`\n",
        )
        # a research note -> excluded by shape/notes filter
        _write_finding(
            ws, "staging", "R1-consolidated.notes",
            "# Notes\nVerdict: FALSE POSITIVE\nVerdict: FALSE POSITIVE\n"
            "`src/Vault.sol:30`\n", folder=False,
        )

    def test_build_admits_only_resolving_confirmed_findings(self):
        cases, header, skipped = mod.build_corpus(
            self.audits, ["demo"], held_out_pct=50, seed=0
        )
        ids = {c["case_id"] for c in cases}
        self.assertIn("demo--vault-reentrancy-HIGH", ids)
        self.assertNotIn("demo--ghost-bug-MEDIUM", ids)       # ref didn't resolve
        self.assertNotIn("demo--dead-KILLED-dupe", ids)       # KILLED
        self.assertNotIn("demo--R1-consolidated.notes", ids)  # research note
        # admitted case carries the real HEAD sha + resolving file_line
        c = next(c for c in cases if c["case_id"] == "demo--vault-reentrancy-HIGH")
        self.assertEqual(c["prefix_ref"], self.sha)
        self.assertEqual(c["repo"], "acme/demo")
        rel = c["file_line"].split(":")[0]
        self.assertTrue((Path(c["local_checkout"]) / rel).is_file())
        self.assertEqual(c["source_tier"], "onchain-confirmed-finding")

    def test_split_is_class_disjoint(self):
        # add several classes across many findings to exercise the partition
        ws = self.audits / "demo"
        for i, vc in enumerate(["arithmetic", "signature-replay", "fund-freeze"]):
            _write_finding(
                ws, "filed", f"extra-{i}-{vc}-HIGH",
                f"# extra {vc}\n- attack_class: {vc}\n- Severity: High\n"
                f"- source-proof: `src/Vault.sol:{15 + i}`\n",
            )
        cases, _, _ = mod.build_corpus(self.audits, ["demo"], 50, 0)
        per_class = {}
        for c in cases:
            per_class.setdefault(c["vuln_class"], set()).add(c["split"])
        spanning = [k for k, v in per_class.items() if len(v) > 1]
        self.assertEqual(spanning, [], f"classes spanning both splits: {spanning}")

    def test_dedupe_by_repo_and_file_line(self):
        # same root cause filed twice (filed + staging) -> one case
        ws = self.audits / "demo"
        _write_finding(
            ws, "staging", "vault-reentrancy-HIGH",
            "# Reentrancy in Vault (staging copy)\n"
            "- attack_class: reentrancy\n- Severity: High\n"
            "- source-proof: `src/Vault.sol:12`\n",
        )
        cases, _, skipped = mod.build_corpus(self.audits, ["demo"], 50, 0)
        rey = [c for c in cases if c["file_line"].endswith("Vault.sol:12")]
        self.assertEqual(len(rey), 1)
        self.assertTrue(any(s.get("reason") == "dupe-repo-file_line" for s in skipped))


class TestSchemaConformance(unittest.TestCase):
    def test_schema_file_is_valid_json(self):
        schema = json.loads(SCHEMA_PATH.read_text())
        self.assertEqual(schema["$id"], "auditooor.fetchable_vuln_corpus.v1")
        self.assertIn("file_line", schema["required"])
        self.assertIn("split", schema["required"])

    def test_built_cases_conform_to_required_fields(self):
        tmp = Path(tempfile.mkdtemp(prefix="fvc_schema_"))
        audits = tmp / "audits"
        ws = audits / "demo"
        _make_checkout(ws / "src", "https://github.com/acme/demo.git",
                       {"src/A.sol": "x\n" * 30})
        _write_finding(
            ws, "filed", "a-bug-HIGH",
            "# A bug\n- attack_class: fund-theft\n- Severity: High\n"
            "- source-proof: `src/A.sol:5`\n",
        )
        cases, _, _ = mod.build_corpus(audits, ["demo"], 50, 0)
        self.assertTrue(cases)
        schema = json.loads(SCHEMA_PATH.read_text())
        required = schema["required"]
        enum_split = set(schema["properties"]["split"]["enum"])
        enum_tier = set(schema["properties"]["source_tier"]["enum"])
        for c in cases:
            for r in required:
                self.assertIn(r, c, f"missing required field {r}")
            self.assertIn(c["split"], enum_split)
            self.assertIn(c["source_tier"], enum_tier)

    def test_real_corpus_if_present_conforms(self):
        """If the real corpus exists on disk, every row must conform + resolve."""
        corpus = ROOT / "reference" / "fetchable_vuln_corpus.jsonl"
        if not corpus.is_file():
            self.skipTest("real corpus not built")
        schema = json.loads(SCHEMA_PATH.read_text())
        required = schema["required"]
        n = 0
        for raw in corpus.read_text().splitlines():
            raw = raw.strip()
            if not raw or raw.startswith("#"):
                continue
            row = json.loads(raw)
            for r in required:
                self.assertIn(r, row)
            # fetchability: file_line resolves on disk (when checkout present)
            lc = row.get("local_checkout")
            if lc and Path(lc).is_dir():
                rel = row["file_line"].split(":")[0]
                self.assertTrue(
                    (Path(lc) / rel).is_file(),
                    f"file_line does not resolve: {row['file_line']}",
                )
            n += 1
        self.assertGreater(n, 0, "corpus is empty")


if __name__ == "__main__":
    unittest.main()
