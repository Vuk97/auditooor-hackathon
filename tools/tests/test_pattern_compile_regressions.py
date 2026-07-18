"""Regression guards for malformed YAML and unsupported DSL keys.

Burn-down item #12 (P1-1 row in `docs/KNOWN_LIMITATIONS.md`).

Historically, several YAML shapes silently compiled into a no-op
detector:

1. An unquoted colon in a scalar value parses as `key: value` so the
   matcher key disappears (e.g. `function.body_contains_regex: foo: bar`
   yields `{"function.body_contains_regex": "foo"}` plus a bare key
   `bar` in the same map — engine treats it as garbage).
2. `match: {function.kind: external}` is a mapping where a list of
   single-key maps is expected; the legacy compiler tolerated it but
   the runtime never iterated correctly.
3. `match: []` (empty matcher list) compiled into an `_MATCH = []`
   detector that matched zero functions but never warned.
4. `function.totally_made_up: true` compiled because the legacy
   compiler did not consult the predicate engine's supported-key set;
   the engine returned False at scan time with a stderr warning.

These tests pin the strict-mode burn-down behavior:

* `strict_yaml_shapes=True` rejects (1)–(3) loud.
* `strict_unsupported_keys=True` rejects (4) loud.
* A known-good YAML still compiles cleanly under both flags.

Default (non-strict) compile path is exercised in
`test_pattern_compile_documentation_only.py` so we do not duplicate
those legacy-compatibility checks here.
"""

from __future__ import annotations

import importlib.util
import io
import tempfile
import textwrap
import unittest
from contextlib import redirect_stderr
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
TOOL = REPO / "tools" / "pattern-compile.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location("pattern_compile", TOOL)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


def _write(ws: Path, body: str, name: str = "regression.yaml") -> Path:
    yf = ws / name
    yf.write_text(textwrap.dedent(body), encoding="utf-8")
    return yf


class UnquotedColonRegressionTest(unittest.TestCase):
    """An unquoted scalar containing a colon-separated value historically
    eats the inner `:` and turns the matcher into a nested-map shape.
    YAML's scanner refuses the document outright when the second colon
    appears inside what was meant to be a list item value — make sure
    the compiler surfaces the parse error loud, not as a silent skip.
    """

    def test_unquoted_colon_in_scalar_value_yaml_parse_error_propagates(self):
        tool = _load_tool()
        # `- function.body_contains_regex: foo: bar` — YAML refuses the
        # second `:` ("mapping values are not allowed here"). The
        # compiler reads the file with `yaml.safe_load`, which must
        # surface a YAMLError (the strict CLI converts that into a
        # non-zero exit). We assert the exception bubbles out cleanly.
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            yf = _write(
                ws,
                """\
                pattern: regression-unquoted-colon
                severity: MEDIUM
                confidence: MEDIUM
                help: test
                preconditions: []
                match:
                  - function.body_contains_regex: foo: bar
                """,
            )
            import yaml as _yaml
            with self.assertRaises(_yaml.YAMLError):
                tool.compile_pattern(
                    yf,
                    ws / "wave99",
                    strict_yaml_shapes=True,
                )

    def test_quoted_scalar_with_colon_strict_rejects(self):
        """`- "function.body_contains_regex: foo:bar"` parses as a bare
        scalar string instead of a single-key map. Strict-shape mode
        must catch this so the matcher does not silently degrade into
        a no-op."""
        tool = _load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            yf = _write(
                ws,
                """\
                pattern: regression-quoted-scalar-colon
                severity: MEDIUM
                confidence: MEDIUM
                help: test
                preconditions: []
                match:
                  - "function.body_contains_regex: foo:bar"
                """,
            )
            with self.assertRaisesRegex(
                tool.PatternCompileError,
                "single-key predicate map",
            ):
                tool.compile_pattern(
                    yf,
                    ws / "wave99",
                    strict_yaml_shapes=True,
                )


class MalformedDictWhereListExpectedTest(unittest.TestCase):
    """`match:` rendered as a dict (missing leading `-`) must fail loud
    in strict mode — `match` is required to be a list of single-key
    predicate maps."""

    def test_dict_match_strict_fails(self):
        tool = _load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            yf = _write(
                ws,
                """\
                pattern: regression-dict-match
                severity: MEDIUM
                confidence: MEDIUM
                help: test
                preconditions: []
                match:
                  function.kind: external
                """,
            )
            with self.assertRaisesRegex(
                tool.PatternCompileError,
                "must be a YAML list",
            ):
                tool.compile_pattern(
                    yf,
                    ws / "wave99",
                    strict_yaml_shapes=True,
                )


class EmptyMatcherEmissionTest(unittest.TestCase):
    """Strict mode must refuse `match: []` (empty matcher) so a
    silently-no-op detector cannot ship. Pin this regression even
    though the existing documentation-only suite covers the path —
    keep one canonical assertion in this regression file too."""

    def test_empty_match_strict_fails(self):
        tool = _load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            yf = _write(
                ws,
                """\
                pattern: regression-empty-match
                severity: MEDIUM
                confidence: MEDIUM
                help: test
                preconditions: []
                match: []
                """,
            )
            with self.assertRaisesRegex(
                tool.PatternCompileError,
                "empty matcher",
            ):
                tool.compile_pattern(
                    yf,
                    ws / "wave99",
                    strict_yaml_shapes=True,
                )


class UnsupportedDslKeyTest(unittest.TestCase):
    """Strict-unsupported-keys mode must refuse predicate keys that
    `_predicate_engine.py` does not handle. Otherwise the YAML
    compiles, the detector ships, and the engine silently returns
    False at scan time (only a stderr warning betrays the bug)."""

    def test_unsupported_match_key_strict_fails(self):
        tool = _load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            yf = _write(
                ws,
                """\
                pattern: regression-unsupported-match-key
                severity: MEDIUM
                confidence: MEDIUM
                help: test
                preconditions: []
                match:
                  - function.totally_made_up: true
                """,
            )
            with self.assertRaisesRegex(
                tool.PatternCompileError,
                r"unsupported predicate key.*function\.totally_made_up",
            ):
                tool.compile_pattern(
                    yf,
                    ws / "wave99",
                    strict_unsupported_keys=True,
                )

    def test_unsupported_precondition_key_strict_fails(self):
        tool = _load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            yf = _write(
                ws,
                """\
                pattern: regression-unsupported-precond-key
                severity: MEDIUM
                confidence: MEDIUM
                help: test
                preconditions:
                  - contract.does_not_exist: true
                match:
                  - function.kind: external
                """,
            )
            with self.assertRaisesRegex(
                tool.PatternCompileError,
                r"unsupported predicate key.*contract\.does_not_exist",
            ):
                tool.compile_pattern(
                    yf,
                    ws / "wave99",
                    strict_unsupported_keys=True,
                )

    def test_unsupported_key_default_compile_still_emits(self):
        """Backward-compat: default compile must still emit the
        detector even with an unsupported key (so the 1,400+ legacy
        YAMLs keep building). The strict flag is opt-in."""
        tool = _load_tool()
        # Tempdir under REPO so `Path.relative_to(AUDITOOOR_DIR)` in
        # the success-path log line resolves cleanly.
        with tempfile.TemporaryDirectory(dir=REPO) as tmp:
            ws = Path(tmp)
            yf = _write(
                ws,
                """\
                pattern: legacy-unsupported-key-tolerated
                severity: MEDIUM
                confidence: MEDIUM
                help: test
                preconditions: []
                match:
                  - function.totally_made_up: true
                """,
            )
            err = io.StringIO()
            with redirect_stderr(err):
                ok = tool.compile_pattern(yf, ws / "wave99")
            self.assertTrue(ok, "default path must keep compiling legacy YAMLs")
            self.assertTrue(
                (ws / "wave99" / "legacy_unsupported_key_tolerated.py").exists(),
                "default path must still emit the detector .py file",
            )

    def test_supported_function_contract_cross_context_key_passes(self):
        """`function.contract.source_matches_regex` is a cross-context
        predicate that lives in `_check_function_pred` but routes to
        contract source — make sure SUPPORTED_FUNCTION_KEYS includes it
        so strict mode does not reject valid usage."""
        tool = _load_tool()
        self.assertIn(
            "function.contract.source_matches_regex",
            tool.SUPPORTED_FUNCTION_KEYS,
        )
        self.assertIn(
            "function.contract.not_source_matches_regex",
            tool.SUPPORTED_FUNCTION_KEYS,
        )
        self.assertIn(
            "function.parameters_include",
            tool.SUPPORTED_FUNCTION_KEYS,
        )

    def test_safe_alias_keys_compile_under_strict_unsupported_keys(self):
        tool = _load_tool()
        self.assertIn("contract.has_func_matching", tool.SUPPORTED_PRECONDITION_KEYS)
        self.assertIn("contract.has_func_body_matching", tool.SUPPORTED_PRECONDITION_KEYS)
        self.assertIn("contract.has_func_body_matching_invert", tool.SUPPORTED_PRECONDITION_KEYS)
        self.assertIn("contract.source_contains_regex", tool.SUPPORTED_PRECONDITION_KEYS)
        self.assertIn("function.body_matches_regex", tool.SUPPORTED_FUNCTION_KEYS)
        self.assertIn("function.not_body_matches_regex", tool.SUPPORTED_FUNCTION_KEYS)
        self.assertIn("function.contract_has_source_matching", tool.SUPPORTED_FUNCTION_KEYS)
        self.assertIn("function.not_calls_function_matching", tool.SUPPORTED_FUNCTION_KEYS)
        self.assertIn("function.not_in_slither_synthetic", tool.SUPPORTED_FUNCTION_KEYS)

        with tempfile.TemporaryDirectory(dir=REPO) as tmp:
            ws = Path(tmp)
            yf = _write(
                ws,
                """\
                pattern: regression-safe-alias-keys
                severity: MEDIUM
                confidence: MEDIUM
                help: test
                preconditions:
                  - contract.has_func_matching: withdraw
                  - contract.has_func_body_matching: transfer
                  - contract.has_func_body_matching_invert: _disableInitializers
                  - contract.source_contains_regex: owner
                match:
                  - function.body_matches_regex: return
                  - function.not_body_matches_regex: transfer
                  - function.contract_has_source_matching: owner
                  - function.not_calls_function_matching: refresh
                  - function.not_in_slither_synthetic: true
                """,
            )
            ok = tool.compile_pattern(
                yf,
                ws / "wave99",
                strict_unsupported_keys=True,
            )

        self.assertTrue(ok)


class KnownGoodYamlRegressionPin(unittest.TestCase):
    """A canonical well-formed YAML must compile cleanly under BOTH
    strict flags simultaneously — proves the strict path is not
    over-eager."""

    def test_known_good_yaml_compiles_under_strict_all(self):
        tool = _load_tool()
        with tempfile.TemporaryDirectory(dir=REPO) as tmp:
            ws = Path(tmp)
            yf = _write(
                ws,
                """\
                pattern: regression-known-good
                severity: HIGH
                confidence: MEDIUM
                help: "well-formed regression pin"
                preconditions:
                  - contract.implements_any_interface:
                      - IERC1155Receiver
                      - IERC721Receiver
                match:
                  - function.kind: external_or_public
                  - function.has_external_call: true
                  - function.post_external_call_mutates_state: true
                  - function.has_modifier:
                      includes: [nonReentrant]
                      negate: true
                  - function.not_in_skip_list: true
                """,
            )
            err = io.StringIO()
            with redirect_stderr(err):
                ok = tool.compile_pattern(
                    yf,
                    ws / "wave99",
                    strict_yaml_shapes=True,
                    strict_unsupported_keys=True,
                )
            self.assertTrue(ok)
            self.assertTrue(
                (ws / "wave99" / "regression_known_good.py").exists(),
                "known-good YAML must emit a detector .py under strict-all",
            )
            # No warning lines should leak to stderr on the strict-all
            # success path for a fully-clean YAML.
            self.assertNotIn("[warn]", err.getvalue())

    def test_body_ordered_regex_yaml_compiles_under_strict_all(self):
        """Pin R103's compiler support so strict validation keeps accepting
        ordered body regex predicates and preserves their object payload."""
        tool = _load_tool()
        with tempfile.TemporaryDirectory(dir=REPO) as tmp:
            ws = Path(tmp)
            yf = _write(
                ws,
                """\
                pattern: regression-body-ordered-regex
                severity: MEDIUM
                confidence: MEDIUM
                help: "ordered regex regression pin"
                preconditions: []
                match:
                  - function.body_ordered_regex:
                      first: rewardDebt\\s*\\[[^\\]]+\\]\\s*=\\s*0
                      second: cachedRewards\\s*\\[[^\\]]+\\]\\s*\\+=
                      ignore_comments_and_strings: true
                  - function.not_in_skip_list: true
                """,
            )
            err = io.StringIO()
            with redirect_stderr(err):
                ok = tool.compile_pattern(
                    yf,
                    ws / "wave99",
                    strict_yaml_shapes=True,
                    strict_unsupported_keys=True,
                )
            self.assertTrue(ok)
            emitted = (ws / "wave99" / "regression_body_ordered_regex.py").read_text(
                encoding="utf-8"
            )
            self.assertIn("function.body_ordered_regex", emitted)
            self.assertIn("'ignore_comments_and_strings': True", emitted)
            self.assertNotIn("[warn]", err.getvalue())


class SupportedKeySetSanityTest(unittest.TestCase):
    """The SUPPORTED_KEYS_BY_FIELD constant must stay in sync with
    `detectors/_predicate_engine.py`. We sanity-check key shape and
    cardinality so the file does not get accidentally cleared."""

    def test_constants_are_non_empty_frozensets(self):
        tool = _load_tool()
        self.assertGreater(len(tool.SUPPORTED_PRECONDITION_KEYS), 10)
        self.assertGreater(len(tool.SUPPORTED_FUNCTION_KEYS), 30)
        self.assertIn("preconditions", tool.SUPPORTED_KEYS_BY_FIELD)
        self.assertIn("match", tool.SUPPORTED_KEYS_BY_FIELD)

    def test_all_supported_function_keys_share_function_prefix(self):
        tool = _load_tool()
        for k in tool.SUPPORTED_FUNCTION_KEYS:
            self.assertTrue(
                k.startswith("function."),
                f"function-level supported key without `function.` prefix: {k!r}",
            )

    def test_all_supported_precondition_keys_share_contract_prefix(self):
        tool = _load_tool()
        for k in tool.SUPPORTED_PRECONDITION_KEYS:
            self.assertTrue(
                k.startswith("contract."),
                f"contract-level supported key without `contract.` prefix: {k!r}",
            )


if __name__ == "__main__":
    unittest.main()
