"""test_llm_invariant_extractor.py - tests for tools/llm-invariant-extractor.py.

Tests for the REAL honesty gate (symbol_exists_grep) plus pipeline smoke tests.
Uses a tiny temp .sol fixture so no real workspace is required.

agent_pathspec.json: tools/tests/test_llm_invariant_extractor.py registered via
tools/agent-pathspec-register.py lane LLM-INVARIANT-EXTRACTOR-BUILD.
"""

from __future__ import annotations

import importlib.util
import sys
import textwrap
import unittest
from pathlib import Path

# ---------------------------------------------------------------------------
# Import the module under test.
# Module has a hyphen in its filename; must be registered in sys.modules
# BEFORE exec_module so that Python 3.14 dataclass field resolution works.
# (Pattern from cross-function-harness-producer._load_module.)
# ---------------------------------------------------------------------------
_TOOLS = Path(__file__).resolve().parents[1]
_MODNAME = "llm_invariant_extractor"

_spec = importlib.util.spec_from_file_location(
    _MODNAME,
    str(_TOOLS / "llm-invariant-extractor.py"),
)
assert _spec and _spec.loader, "Cannot load llm-invariant-extractor.py"
_mod = importlib.util.module_from_spec(_spec)
sys.modules[_MODNAME] = _mod        # register BEFORE exec (Python 3.14 dataclass fix)
_spec.loader.exec_module(_mod)      # type: ignore[union-attr]

symbol_exists_grep = _mod.symbol_exists_grep
InvariantClaim = _mod.InvariantClaim
bind_claim = _mod.bind_claim
extract_invariant_claims = _mod.extract_invariant_claims
seeded_mutation_must_fail = _mod.seeded_mutation_must_fail
pass_on_clean = _mod.pass_on_clean
FuzzableAssertion = _mod.FuzzableAssertion
compile_assertion = _mod.compile_assertion


# ---------------------------------------------------------------------------
# Tiny .sol fixture helpers.
# ---------------------------------------------------------------------------

_FIXTURE_SOL = textwrap.dedent("""\
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.0;

    /// @dev Invariant: totalSupply must always equal sum of balances.
    /// @dev transferFrom must never allow more than allowance.
    contract FixtureToken {
        uint256 public totalSupply;
        mapping(address => uint256) public balanceOf;
        mapping(address => mapping(address => uint256)) public allowance;

        function transfer(address to, uint256 amount) external returns (bool) {
            balanceOf[msg.sender] -= amount;
            balanceOf[to] += amount;
            return true;
        }

        function transferFrom(address from, address to, uint256 amount)
            external returns (bool)
        {
            allowance[from][msg.sender] -= amount;
            balanceOf[from] -= amount;
            balanceOf[to] += amount;
            return true;
        }
    }
""")


def _make_sol_workspace(tmp_path: Path, content: str = _FIXTURE_SOL) -> tuple[Path, Path]:
    """Write a .sol file into tmp_path and return (sol_path, ws_path)."""
    sol_path = tmp_path / "FixtureToken.sol"
    sol_path.write_text(content, encoding="utf-8")
    return sol_path, tmp_path


# ---------------------------------------------------------------------------
# Tests: symbol_exists_grep (Gate a) - REAL AND TESTED.
# ---------------------------------------------------------------------------

class TestSymbolExistsGrep(unittest.TestCase):
    """Gate (a) must accept real symbols and reject hallucinated ones."""

    def setUp(self) -> None:
        import tempfile
        self._tmpdir = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmpdir.name)
        self.sol_path, self.ws = _make_sol_workspace(self.tmp)

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def test_accepts_real_symbol_totalSupply(self) -> None:
        """totalSupply IS in the fixture - must return True."""
        result = symbol_exists_grep("totalSupply", self.ws)
        self.assertTrue(
            result,
            "symbol_exists_grep must return True for 'totalSupply' "
            "which exists in FixtureToken.sol",
        )

    def test_accepts_real_symbol_transfer(self) -> None:
        """transfer IS in the fixture - must return True."""
        result = symbol_exists_grep("transfer", self.ws)
        self.assertTrue(result, "symbol_exists_grep must return True for 'transfer'")

    def test_accepts_real_symbol_balanceOf(self) -> None:
        """balanceOf IS in the fixture - must return True."""
        result = symbol_exists_grep("balanceOf", self.ws)
        self.assertTrue(result, "symbol_exists_grep must return True for 'balanceOf'")

    def test_rejects_hallucinated_symbol(self) -> None:
        """hallucinated_fn_that_does_not_exist is NOT in any .sol - must return False."""
        result = symbol_exists_grep("hallucinated_fn_that_does_not_exist", self.ws)
        self.assertFalse(
            result,
            "symbol_exists_grep must return False for a symbol not present "
            "in any .sol file under the workspace",
        )

    def test_rejects_another_hallucinated_symbol(self) -> None:
        """flashLoanCallback is NOT in the fixture - must return False."""
        result = symbol_exists_grep("flashLoanCallback", self.ws)
        self.assertFalse(
            result,
            "symbol_exists_grep must return False for 'flashLoanCallback' "
            "which does not exist in FixtureToken.sol",
        )

    def test_rejects_totally_fake_symbol(self) -> None:
        """A totally fabricated symbol must return False."""
        result = symbol_exists_grep("totallyFakeSymbolXYZ999", self.ws)
        self.assertFalse(result)

    def test_returns_false_for_nonexistent_workspace(self) -> None:
        """A non-existent directory must return False, not raise."""
        result = symbol_exists_grep("transfer", Path("/nonexistent/workspace/xyz"))
        self.assertFalse(result)

    def test_returns_false_for_empty_workspace(self) -> None:
        """A workspace with no .sol files must return False."""
        import tempfile
        with tempfile.TemporaryDirectory() as empty:
            result = symbol_exists_grep("transfer", Path(empty))
            self.assertFalse(result)


# ---------------------------------------------------------------------------
# Tests: placeholder gates (b) and (c).
# ---------------------------------------------------------------------------

class TestPlaceholderGates(unittest.TestCase):
    """Gates (b) and (c) are placeholders - they must return False until wired."""

    def test_seeded_mutation_must_fail_returns_false(self) -> None:
        """Gate (b) placeholder must return False (not wired yet)."""
        result = seeded_mutation_must_fail("invariant_foo() { assert(a != b); }", Path("."))
        self.assertFalse(
            result,
            "seeded_mutation_must_fail must return False until wired to medusa/echidna",
        )

    def test_pass_on_clean_returns_false(self) -> None:
        """Gate (c) placeholder must return False (not wired yet)."""
        result = pass_on_clean("invariant_foo() { assert(a != b); }", Path("."))
        self.assertFalse(
            result,
            "pass_on_clean must return False until wired to medusa/echidna",
        )


# ---------------------------------------------------------------------------
# Tests: extract_invariant_claims (Stage 1 stub).
# ---------------------------------------------------------------------------

class TestExtractInvariantClaims(unittest.TestCase):
    """Stage 1 stub must extract NatSpec claims that contain invariant keywords."""

    def setUp(self) -> None:
        import tempfile
        self._tmpdir = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmpdir.name)
        self.sol_path, _ = _make_sol_workspace(self.tmp)

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def test_extracts_natspec_invariant_lines(self) -> None:
        """Lines containing 'invariant' keyword in NatSpec comments are extracted."""
        claims = extract_invariant_claims(self.sol_path)
        self.assertGreater(
            len(claims), 0,
            "Must extract at least one claim from the fixture which contains "
            "NatSpec lines with 'invariant' and 'never'",
        )

    def test_source_quote_is_substring_of_source(self) -> None:
        """Every extracted claim's source_quote must literally appear in the source."""
        src_text = self.sol_path.read_text()
        claims = extract_invariant_claims(self.sol_path)
        for c in claims:
            self.assertIn(
                c.source_quote, src_text,
                f"source_quote {c.source_quote!r} must be a literal substring "
                "of the source (anti-hallucination gate)",
            )

    def test_extracts_zero_from_no_natspec(self) -> None:
        """A file with no NatSpec invariant comments yields zero claims."""
        import tempfile
        bare = textwrap.dedent("""\
            // SPDX-License-Identifier: MIT
            pragma solidity ^0.8.0;
            contract Bare {
                uint256 public x;
                function setX(uint256 v) external { x = v; }
            }
        """)
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "Bare.sol"
            p.write_text(bare)
            claims = extract_invariant_claims(p)
            self.assertEqual(len(claims), 0)


# ---------------------------------------------------------------------------
# Tests: bind_claim (Stage 2).
# ---------------------------------------------------------------------------

class TestBindClaim(unittest.TestCase):
    """bind_claim must use symbol_exists_grep to gate each candidate symbol."""

    def setUp(self) -> None:
        import tempfile
        self._tmpdir = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmpdir.name)
        self.sol_path, self.ws = _make_sol_workspace(self.tmp)

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def _make_claim(self, text: str, quote: str) -> InvariantClaim:
        return InvariantClaim(
            claim=text,
            source_quote=quote,
            source_file=str(self.sol_path),
            line_start=1,
            line_end=1,
        )

    def test_bound_when_symbol_exists(self) -> None:
        """A claim referencing totalSupply (exists) must bind at least one symbol."""
        claim = self._make_claim(
            "totalSupply must always equal sum of balances",
            "/// @dev totalSupply must always equal sum of balances",
        )
        result = bind_claim(claim, self.ws)
        self.assertIn(result.bind_status, ("BOUND", "PARTIAL_BIND"))
        self.assertIn("totalSupply", result.bound_symbols)

    def test_bind_failed_when_no_symbol_exists(self) -> None:
        """A claim whose only candidate symbols are hallucinated must be BIND_FAILED."""
        claim = self._make_claim(
            "hallucinated_fn_that_does_not_exist must never revert",
            "/// @dev hallucinated_fn_that_does_not_exist must never revert",
        )
        result = bind_claim(claim, self.ws)
        self.assertEqual(
            result.bind_status, "BIND_FAILED",
            "A claim with only hallucinated symbols must be BIND_FAILED",
        )
        self.assertEqual(result.bound_symbols, [])
        self.assertIn("hallucinated_fn_that_does_not_exist", result.bind_failures)


# ---------------------------------------------------------------------------
# Tests: compile_assertion (Stage 3 stub).
# ---------------------------------------------------------------------------

class TestCompileAssertion(unittest.TestCase):
    """compile_assertion must produce a FuzzableAssertion with a TODO body."""

    def setUp(self) -> None:
        import tempfile
        self._tmpdir = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmpdir.name)
        _, self.ws = _make_sol_workspace(self.tmp)

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def _bound_claim(self) -> InvariantClaim:
        c = InvariantClaim(
            claim="totalSupply must equal balanceOf sum",
            source_quote="/// @dev totalSupply must equal balanceOf sum",
            source_file="FixtureToken.sol",
            line_start=3,
            line_end=3,
            bound_symbols=["totalSupply", "balanceOf"],
            bind_status="BOUND",
        )
        return c

    def test_returns_fuzzer_assertion(self) -> None:
        """compile_assertion must return a FuzzableAssertion."""
        a = compile_assertion(self._bound_claim(), "LLM-INV-001", self.ws)
        self.assertIsInstance(a, FuzzableAssertion)
        self.assertEqual(a.inv_id, "LLM-INV-001")

    def test_fn_name_starts_with_invariant(self) -> None:
        """Generated fn name must start with 'invariant_'."""
        a = compile_assertion(self._bound_claim(), "LLM-INV-001", self.ws)
        self.assertTrue(
            a.fn_name.startswith("invariant_"),
            f"fn_name must start with 'invariant_', got: {a.fn_name!r}",
        )

    def test_mutation_verified_false_while_placeholder(self) -> None:
        """mutation_verified must be False while Gate (b) is a placeholder."""
        a = compile_assertion(self._bound_claim(), "LLM-INV-001", self.ws)
        self.assertFalse(
            a.mutation_verified,
            "mutation_verified must be False until Gate (b) is wired",
        )

    def test_clean_verified_false_while_placeholder(self) -> None:
        """clean_verified must be False while Gate (c) is a placeholder."""
        a = compile_assertion(self._bound_claim(), "LLM-INV-001", self.ws)
        self.assertFalse(
            a.clean_verified,
            "clean_verified must be False until Gate (c) is wired",
        )

    def test_is_real_contract_true_when_bound(self) -> None:
        """is_real_contract must be True when bind_status=BOUND and symbols non-empty."""
        a = compile_assertion(self._bound_claim(), "LLM-INV-001", self.ws)
        self.assertTrue(
            a.is_real_contract,
            "is_real_contract must be True when symbols are grep-verified (BOUND)",
        )

    def test_body_is_marked_placeholder(self) -> None:
        # r36-rebuttal: lane FIX-AUTO-INVARIANT-DEFECTS registered
        """Stub body must be clearly marked non-real so it cannot be mistaken for a real invariant."""
        a = compile_assertion(self._bound_claim(), "LLM-INV-001", self.ws)
        low = a.solidity_body.lower()
        self.assertTrue(
            "placeholder" in low and "not counted" in low,
            "Stub body must carry a PLACEHOLDER / NOT COUNTED marker",
        )

    def test_body_does_not_revert(self) -> None:
        """Polarity guard: the stub must NOT emit an unconditional revert() - that would
        mark every CORRECT contract as broken on the first fuzz call (inverted polarity)."""
        a = compile_assertion(self._bound_claim(), "LLM-INV-001", self.ws)
        self.assertNotIn(
            "revert(", a.solidity_body,
            "Stub body must not unconditionally revert (inverted-polarity false positive)",
        )

    def test_body_does_not_assert_true(self) -> None:
        """Stub body must never contain assert(true) (vacuous-assertion guard)."""
        a = compile_assertion(self._bound_claim(), "LLM-INV-001", self.ws)
        self.assertNotIn(
            "assert(true)", a.solidity_body,
            "Stub body must never contain assert(true)",
        )


# ---------------------------------------------------------------------------
# Entry point.
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    unittest.main(verbosity=2)
