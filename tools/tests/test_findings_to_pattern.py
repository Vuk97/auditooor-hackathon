"""Regression tests for tools/findings-to-pattern.py and
tools/pattern-taxonomy-cluster.py (V5 PR-G — Gap-24/27/34).

Covers Codex's required test list verbatim:

  1. Accepted-finding fixture converts to a candidate pattern file
     plus TODO fixture scaffolds.
  2. Generated candidate cannot be promoted without vuln/clean
     fixture pair (suffix-stripping gate).
  3. Taxonomy clustering fixture narrows a broad pattern set and
     marks overlap as unknown when incomplete.
  4. Empty taxonomy → empty output, no crash.
  5. ``make all`` remains green if a generated ``.candidate`` file
     is committed (covered indirectly: the candidate suffix is
     globbed out by the parity / compile passes; we assert the
     suffix shape and that compile-time globbing rules out the file).

Stdlib-only.
"""
from __future__ import annotations

import importlib.util
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest


REPO = pathlib.Path(__file__).resolve().parents[2]


def _load(rel_path: str):
    """Load a hyphenated tool by path. Cached on sys.modules."""
    name = "_test_" + rel_path.replace("/", "_").replace("-", "_").replace(".py", "")
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, REPO / rel_path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


F2P = _load("tools/findings-to-pattern.py")
TAX = _load("tools/pattern-taxonomy-cluster.py")


class FindingsToPatternBasicTests(unittest.TestCase):
    """Codex test #1 — finding fixture → candidate + TODO scaffolds."""

    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="f2p-test-")
        self.patterns_dir = pathlib.Path(self.tmp) / "patterns.dsl"
        self.fixtures_dir = pathlib.Path(self.tmp) / "test_fixtures"

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _md_fixture(self) -> str:
        return (REPO / "tools" / "tests" / "fixtures" / "finding_oracle_stale.md").read_text()

    def test_markdown_finding_produces_candidate_and_scaffolds(self) -> None:
        spec = F2P.parse_finding_markdown(self._md_fixture())
        spec["name"] = "test-oracle-stale-no-grace-period"
        res = F2P.generate(spec, patterns_dir=self.patterns_dir, fixtures_dir=self.fixtures_dir)
        self.assertIsNotNone(res.pattern_path)
        self.assertIsNotNone(res.vuln_path)
        self.assertIsNotNone(res.clean_path)
        self.assertIsNotNone(res.checklist_path)
        # Candidate suffix is critical — must NOT be globbed by `make compile`.
        self.assertTrue(str(res.pattern_path).endswith(".yaml.candidate"),
                        f"pattern path {res.pattern_path} must use .yaml.candidate")
        self.assertTrue(str(res.vuln_path).endswith(".sol.todo"))
        self.assertTrue(str(res.clean_path).endswith(".sol.todo"))
        # Pattern body sanity.
        body = res.pattern_path.read_text()
        self.assertIn("pattern: test-oracle-stale-no-grace-period", body)
        self.assertIn("severity: HIGH", body)
        self.assertIn("CANDIDATE PATTERN", body)
        self.assertIn("TODO-positive-regex", body)
        self.assertIn("impact_contract_required: true", body)
        self.assertIn("selected_impact: ''", body)
        self.assertIn("submission_posture: NOT_SUBMIT_READY", body)
        # Markdown fields propagated.
        self.assertIn("oracle-staleness", body)
        self.assertIn("src/Oracle.sol:42", body)
        # Fixture scaffolds carry the marker but NOT the forbidden trigger words.
        for fix in (res.vuln_path, res.clean_path):
            txt = fix.read_text()
            self.assertIn(F2P.SCAFFOLD_MARKER, txt)
            for trigger in ("// VULN", "// BUG", "// CLEAN", "// missing"):
                self.assertNotIn(trigger, txt, f"trigger {trigger} leaked into {fix}")

    def test_cli_args_override_markdown_fields(self) -> None:
        spec = F2P.parse_finding_markdown(self._md_fixture())
        spec["name"] = "test-cli-override"
        spec["severity"] = "MEDIUM"
        spec["confidence"] = "LOW"
        F2P.generate(spec, patterns_dir=self.patterns_dir, fixtures_dir=self.fixtures_dir)
        body = (self.patterns_dir / "test-cli-override.yaml.candidate").read_text()
        self.assertIn("severity: MEDIUM", body)
        self.assertIn("confidence: LOW", body)

    def test_invalid_severity_rejected(self) -> None:
        with self.assertRaises(ValueError):
            F2P.generate(
                {"name": "ok-name", "severity": "WRONG"},
                patterns_dir=self.patterns_dir,
                fixtures_dir=self.fixtures_dir,
            )

    def test_invalid_name_rejected(self) -> None:
        with self.assertRaises(ValueError):
            F2P.generate(
                {"name": "Bad_Name"},  # snake_case, not kebab — rejected
                patterns_dir=self.patterns_dir,
                fixtures_dir=self.fixtures_dir,
            )
        with self.assertRaises(ValueError):
            F2P.generate(
                {"name": "-leading-hyphen"},
                patterns_dir=self.patterns_dir,
                fixtures_dir=self.fixtures_dir,
            )

    def test_refuses_to_clobber_canonical_pattern(self) -> None:
        # Pre-create a canonical pattern of the same name.
        self.patterns_dir.mkdir(parents=True, exist_ok=True)
        canonical = self.patterns_dir / "already-promoted.yaml"
        canonical.write_text("pattern: already-promoted\n")
        with self.assertRaises(ValueError) as ctx:
            F2P.generate(
                {"name": "already-promoted"},
                patterns_dir=self.patterns_dir,
                fixtures_dir=self.fixtures_dir,
            )
        self.assertIn("already-promoted", str(ctx.exception))


class PromotionGateTests(unittest.TestCase):
    """Codex test #2 — promotion refused without paired fixtures."""

    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="promote-test-")
        self.patterns_dir = pathlib.Path(self.tmp) / "patterns.dsl"
        self.fixtures_dir = pathlib.Path(self.tmp) / "test_fixtures"
        F2P.generate(
            {
                "name": "test-no-fixtures-yet",
                "severity": "MEDIUM",
                "confidence": "LOW",
                "bug_class": "test-class",
            },
            patterns_dir=self.patterns_dir,
            fixtures_dir=self.fixtures_dir,
        )

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _solidity_body(self, kind: str) -> str:
        # Non-trivial Solidity (>= 10 non-comment lines), no trigger words.
        return textwrap.dedent(
            f"""\
            // SPDX-License-Identifier: UNLICENSED
            pragma solidity ^0.8.20;

            contract {kind.title()}Case {{
                uint256 public x;
                address public owner;

                constructor() {{
                    owner = msg.sender;
                }}

                function setX(uint256 v) external {{
                    require(msg.sender == owner);
                    x = v;
                }}

                function getX() external view returns (uint256) {{
                    return x;
                }}
            }}
            """
        )

    def test_promotion_blocked_when_fixtures_missing(self) -> None:
        ok, msgs = F2P.promote(
            "test-no-fixtures-yet",
            patterns_dir=self.patterns_dir,
            fixtures_dir=self.fixtures_dir,
        )
        self.assertFalse(ok)
        # Both fixtures missing (still .sol.todo, not .sol).
        joined = "\n".join(msgs)
        # Either a "missing" message or a "scaffold" message — both are
        # acceptable signals of the gate firing.
        self.assertTrue(
            "missing" in joined.lower() or "scaffold" in joined.lower(),
            f"expected missing/scaffold in {joined!r}",
        )
        # Candidate file must NOT have been renamed.
        self.assertTrue((self.patterns_dir / "test-no-fixtures-yet.yaml.candidate").exists())
        self.assertFalse((self.patterns_dir / "test-no-fixtures-yet.yaml").exists())

    def test_promotion_blocked_when_only_one_fixture_exists(self) -> None:
        # Only the vulnerable fixture exists with content.
        (self.fixtures_dir / "test-no-fixtures-yet_vulnerable.sol").write_text(
            self._solidity_body("vulnerable")
        )
        ok, msgs = F2P.promote(
            "test-no-fixtures-yet",
            patterns_dir=self.patterns_dir,
            fixtures_dir=self.fixtures_dir,
        )
        self.assertFalse(ok)
        self.assertTrue(any("clean" in m.lower() for m in msgs))

    def test_promotion_blocked_when_fixtures_too_short(self) -> None:
        # Both files exist but each has <10 non-comment lines.
        (self.fixtures_dir / "test-no-fixtures-yet_vulnerable.sol").write_text(
            "// stub\npragma solidity ^0.8.20;\n"
        )
        (self.fixtures_dir / "test-no-fixtures-yet_clean.sol").write_text(
            "// stub\npragma solidity ^0.8.20;\n"
        )
        ok, msgs = F2P.promote(
            "test-no-fixtures-yet",
            patterns_dir=self.patterns_dir,
            fixtures_dir=self.fixtures_dir,
        )
        self.assertFalse(ok)
        self.assertTrue(any("non-comment" in m for m in msgs))

    def test_promotion_blocked_when_trigger_words_leak(self) -> None:
        body = self._solidity_body("vulnerable")
        # Inject the forbidden trigger.
        bad = body.replace("uint256 public x;", "uint256 public x; // VULN: bug here")
        (self.fixtures_dir / "test-no-fixtures-yet_vulnerable.sol").write_text(bad)
        (self.fixtures_dir / "test-no-fixtures-yet_clean.sol").write_text(self._solidity_body("clean"))
        ok, msgs = F2P.promote(
            "test-no-fixtures-yet",
            patterns_dir=self.patterns_dir,
            fixtures_dir=self.fixtures_dir,
        )
        self.assertFalse(ok)
        self.assertTrue(any("trigger" in m.lower() for m in msgs))

    def test_promotion_blocked_when_scaffold_marker_remains(self) -> None:
        body = self._solidity_body("vulnerable")
        body_with_marker = "// " + F2P.SCAFFOLD_MARKER + "\n" + body
        (self.fixtures_dir / "test-no-fixtures-yet_vulnerable.sol").write_text(body_with_marker)
        (self.fixtures_dir / "test-no-fixtures-yet_clean.sol").write_text(self._solidity_body("clean"))
        ok, msgs = F2P.promote(
            "test-no-fixtures-yet",
            patterns_dir=self.patterns_dir,
            fixtures_dir=self.fixtures_dir,
        )
        self.assertFalse(ok)
        self.assertTrue(any("scaffold" in m.lower() for m in msgs))

    def _resolve_candidate_todos(self, name: str) -> None:
        """Strip every TODO placeholder out of a candidate YAML, simulating
        the human review pass that fills in the predicate / description /
        remediation slots. Required by the post-Kimi-review promotion
        gate that refuses unresolved TODOs."""
        cand = self.patterns_dir / f"{name}{F2P.CANDIDATE_SUFFIX}"
        text = cand.read_text(encoding="utf-8")
        for marker in F2P.CANDIDATE_TODO_MARKERS:
            text = text.replace(marker, "x")
        cand.write_text(text, encoding="utf-8")

    def test_promotion_blocked_when_todo_placeholders_remain(self) -> None:
        # Both fixtures are valid; the candidate still has TODO markers.
        (self.fixtures_dir / "test-no-fixtures-yet_vulnerable.sol").write_text(
            self._solidity_body("vulnerable")
        )
        (self.fixtures_dir / "test-no-fixtures-yet_clean.sol").write_text(
            self._solidity_body("clean")
        )
        ok, msgs = F2P.promote(
            "test-no-fixtures-yet",
            patterns_dir=self.patterns_dir,
            fixtures_dir=self.fixtures_dir,
        )
        self.assertFalse(ok)
        joined = " ".join(msgs)
        self.assertIn("TODO", joined)

    def test_promotion_blocked_when_reportable_candidate_lacks_impact_posture(self) -> None:
        (self.fixtures_dir / "test-no-fixtures-yet_vulnerable.sol").write_text(
            self._solidity_body("vulnerable")
        )
        (self.fixtures_dir / "test-no-fixtures-yet_clean.sol").write_text(
            self._solidity_body("clean")
        )
        self._resolve_candidate_todos("test-no-fixtures-yet")
        cand = self.patterns_dir / f"test-no-fixtures-yet{F2P.CANDIDATE_SUFFIX}"
        text = cand.read_text(encoding="utf-8")
        text = "\n".join(
            line for line in text.splitlines()
            if not line.startswith((
                "impact_contract_required:",
                "impact_contract_id:",
                "selected_impact:",
                "submission_posture:",
                "submit_status:",
            ))
        )
        cand.write_text(text + "\n", encoding="utf-8")
        ok, msgs = F2P.promote(
            "test-no-fixtures-yet",
            patterns_dir=self.patterns_dir,
            fixtures_dir=self.fixtures_dir,
        )
        self.assertFalse(ok)
        self.assertIn("impact_contract_id", " ".join(msgs))

    def test_promotion_succeeds_when_both_fixtures_nontrivial(self) -> None:
        (self.fixtures_dir / "test-no-fixtures-yet_vulnerable.sol").write_text(
            self._solidity_body("vulnerable")
        )
        (self.fixtures_dir / "test-no-fixtures-yet_clean.sol").write_text(
            self._solidity_body("clean")
        )
        self._resolve_candidate_todos("test-no-fixtures-yet")
        ok, msgs = F2P.promote(
            "test-no-fixtures-yet",
            patterns_dir=self.patterns_dir,
            fixtures_dir=self.fixtures_dir,
        )
        self.assertTrue(ok, msgs)
        self.assertFalse((self.patterns_dir / "test-no-fixtures-yet.yaml.candidate").exists())
        self.assertTrue((self.patterns_dir / "test-no-fixtures-yet.yaml").exists())


class TaxonomyClusterTests(unittest.TestCase):
    """Codex test #3+#4 — clustering narrows broad sets; empty input is safe."""

    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="taxonomy-test-")
        self.patterns_dir = pathlib.Path(self.tmp) / "patterns.dsl"
        self.patterns_dir.mkdir(parents=True, exist_ok=True)

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _write_pattern(self, name: str) -> None:
        (self.patterns_dir / f"{name}.yaml").write_text(
            f"pattern: {name}\nseverity: MEDIUM\n"
        )

    def test_empty_input_yields_empty_output_no_crash(self) -> None:
        # Test #4 — fresh worktree, no patterns yet.
        names = TAX.discover_patterns(self.patterns_dir)
        self.assertEqual(names, [])
        manifest = TAX.build_manifest(names)
        self.assertEqual(manifest["pattern_count"], 0)
        self.assertEqual(manifest["buckets"], {})
        self.assertEqual(manifest["uncategorised"], [])
        self.assertEqual(manifest["overlap"], {})

    def test_missing_patterns_dir_yields_empty(self) -> None:
        # Even more conservative: directory doesn't exist at all.
        names = TAX.discover_patterns(pathlib.Path(self.tmp) / "no-such-dir")
        self.assertEqual(names, [])

    def test_clustering_narrows_broad_set(self) -> None:
        # Plant a representative slice of each bucket.
        seeds = [
            "oracle-stale-price-no-grace-period",
            "oracle-twap-fallback-uses-spot-on-revert",
            "auth-onlyowner-bypass-via-delegate",
            "auth-permit-replay-cross-chain",
            "reentrancy-cei-violation-erc777",
            "merkle-leaf-second-preimage-via-ambiguous-encoding",
            "vault-erc4626-deposit-frontrun",
            "amm-swap-payout-denom-from-user-not-strategy",
            # An outlier that should land in __uncategorised — no taxonomy
            # token matches.
            "miscellaneous-foo-bar-baz",
        ]
        for s in seeds:
            self._write_pattern(s)
        names = TAX.discover_patterns(self.patterns_dir)
        self.assertEqual(set(names), set(seeds))
        manifest = TAX.build_manifest(names)
        # Narrowing — oracle bucket should have exactly the two oracle entries.
        self.assertIn("oracle", manifest["buckets"])
        self.assertEqual(
            set(manifest["buckets"]["oracle"]),
            {"oracle-stale-price-no-grace-period",
             "oracle-twap-fallback-uses-spot-on-revert"},
        )
        # Outlier is uncategorised — Codex's "marks overlap as unknown when
        # incomplete" requirement: a name that fits no bucket lands in the
        # explicit uncategorised list, NOT in some random bucket.
        self.assertIn("miscellaneous-foo-bar-baz", manifest["uncategorised"])

    def test_overlap_recorded_when_pattern_fits_multiple_buckets(self) -> None:
        # 'oracle' bucket has 'twap' as a token; 'amm_swap' has 'swap'.
        # A pattern containing both legitimately overlaps.
        self._write_pattern("oracle-twap-spot-swap-mismatch")
        names = TAX.discover_patterns(self.patterns_dir)
        manifest = TAX.build_manifest(names)
        self.assertIn("oracle-twap-spot-swap-mismatch", manifest["overlap"])
        buckets_for_pattern = manifest["overlap"]["oracle-twap-spot-swap-mismatch"]
        self.assertGreaterEqual(len(buckets_for_pattern), 2)

    def test_select_for_finding_picks_bucket_relevant_sample(self) -> None:
        # Plant 5 oracle patterns + 5 reentrancy patterns.
        oracle_names = [f"oracle-finding-{i}" for i in range(5)]
        reentrancy_names = [f"reentrancy-finding-{i}" for i in range(5)]
        for n in oracle_names + reentrancy_names:
            self._write_pattern(n)
        names = TAX.discover_patterns(self.patterns_dir)
        manifest = TAX.build_manifest(names)
        # Use text with a single unambiguous taxonomy hint so we can
        # assert the bucket list deterministically. ``staleness +
        # oracle`` matches only the oracle bucket because no other
        # bucket carries those tokens.
        sample, buckets = TAX.select_for_finding(
            manifest,
            text="oracle staleness check missing",
            cap=20,
        )
        self.assertIn("oracle", buckets)
        # Reentrancy names must NOT leak into the oracle sample even if
        # other buckets fire — Codex foot-gun #15: keep neutral.
        self.assertTrue(set(oracle_names).issubset(set(sample)))
        self.assertTrue(set(reentrancy_names).isdisjoint(set(sample)))

    def test_select_for_finding_returns_empty_on_unknown_taxonomy(self) -> None:
        manifest = TAX.build_manifest([])
        sample, buckets = TAX.select_for_finding(
            manifest, text="totally unrelated noise", cap=10,
        )
        self.assertEqual(sample, [])
        self.assertEqual(buckets, [])


class PatternNameExtractionTests(unittest.TestCase):
    def test_extracts_pattern_field_first(self) -> None:
        text = "# leading comment\npattern: foo-bar\nseverity: HIGH\n"
        self.assertEqual(TAX.extract_pattern_name(text), "foo-bar")

    def test_returns_none_when_missing(self) -> None:
        self.assertIsNone(TAX.extract_pattern_name("severity: HIGH\n"))

    def test_handles_inline_comment(self) -> None:
        text = "pattern: foo-bar  # the canonical name\n"
        self.assertEqual(TAX.extract_pattern_name(text), "foo-bar")


class CompileGlobSafetyTests(unittest.TestCase):
    """Codex test #5 — `make all` stays green if a .candidate file is committed.

    The repo's compile passes glob ``reference/patterns.dsl/*.yaml``. We
    assert the candidate filename pattern doesn't match that glob —
    which is the whole point of using ``.yaml.candidate`` over a
    sidecar dotfile.
    """

    def test_candidate_suffix_does_not_match_yaml_glob(self) -> None:
        cand = pathlib.Path("reference/patterns.dsl/foo.yaml.candidate")
        # `pathlib.PurePath.match` for `*.yaml` (used by glob) treats the
        # full filename — `foo.yaml.candidate` does NOT end with ".yaml"
        # so it's not picked up.
        self.assertFalse(cand.match("*.yaml"))
        # And the canonical sibling DOES match the glob — sanity.
        self.assertTrue(pathlib.Path("reference/patterns.dsl/foo.yaml").match("*.yaml"))


class CliSmokeTests(unittest.TestCase):
    """End-to-end smoke: invoke each tool from the shell and parse output."""

    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="cli-smoke-")

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_taxonomy_cli_json_smoke(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(REPO / "tools" / "pattern-taxonomy-cluster.py"),
             "--json", "--quiet"],
            capture_output=True, text=True, timeout=60,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        manifest = json.loads(proc.stdout)
        self.assertIn("buckets", manifest)
        self.assertEqual(manifest["schema_version"], 1)

    def test_findings_to_pattern_cli_smoke(self) -> None:
        patterns = pathlib.Path(self.tmp) / "patterns.dsl"
        fixtures = pathlib.Path(self.tmp) / "fixtures"
        proc = subprocess.run(
            [sys.executable, str(REPO / "tools" / "findings-to-pattern.py"),
             "--name", "test-cli-smoke",
             "--bug-class", "test",
             "--severity", "LOW",
             "--confidence", "LOW",
             "--citation", "src/Foo.sol:1",
             "--description", "smoke",
             "--patterns-dir", str(patterns),
             "--fixtures-dir", str(fixtures),
             "--json"],
            capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        data = json.loads(proc.stdout)
        self.assertTrue(data["pattern"].endswith(".yaml.candidate"))
        self.assertTrue(data["vuln_fixture"].endswith(".sol.todo"))
        self.assertTrue(data["clean_fixture"].endswith(".sol.todo"))


if __name__ == "__main__":
    unittest.main()
