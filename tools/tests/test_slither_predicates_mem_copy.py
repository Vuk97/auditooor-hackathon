#!/usr/bin/env python3
"""Memory-copy-of-storage-never-written-back oracle (Glider gap W6 P8) - tests.

Regression + mutation pinning of `memory_copy_no_writeback` added to
``tools/slither_predicates.py``:

  - `memory_copy_no_writeback(function)` - returns a list of LEAD dicts for
    functions that read a storage state-var into a MEMORY local, mutate the
    local, but NEVER write the mutation back to the state var.

Honesty (R80): the semantic cases require a real Slither compile of the
in-tree fixtures; if Slither is not importable they SKIP (no faked pass).
The DEGRADE path is tested without Slither. Mutation evidence:
`test_mutation_writeback_flips_flagged_to_clean` adds `storageVar = localCopy`
to the base fixture and asserts memory_copy_no_writeback flips from FLAGGED []
to [] (clean), proving non-vacuity.

Never-false-positive: storage-pointer, read-only-copy, and writeback-present
all yield [] (no annotation).

"No question when slice absent" contract: all gen_* functions tested with an
empty path list yield [].
"""
from __future__ import annotations

import importlib.util
import pathlib
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
TOOLS = ROOT / "tools"
FX = ROOT / "tests" / "fixtures" / "callgraph_closure"

if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))


def _load_sp():
    spec = importlib.util.spec_from_file_location(
        "slither_predicates", TOOLS / "slither_predicates.py"
    )
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


sp = _load_sp()


def _slither_available() -> bool:
    try:
        import slither  # noqa: F401
        return True
    except Exception:
        return False


SKIP_NO_SLITHER = unittest.skipUnless(
    _slither_available(),
    "slither-analyzer not importable; mem-copy tests need a real compile",
)


def _compile(path: pathlib.Path):
    from slither import Slither
    return Slither(str(path))


def _get_fn(sl, cname, fname):
    for c in sl.contracts:
        if c.name == cname:
            for f in c.functions:
                if f.name == fname:
                    return c, f
    return None, None


# ─── Degrade path (no Slither needed) ────────────────────────────────────────


class MemCopyDegradeTest(unittest.TestCase):
    """R80: a non-navigable input degrades (distinct sentinel), never a guess."""

    class _Dummy:
        pass

    def test_non_navigable_returns_degraded(self):
        """A plain object with no `nodes` attr degrades."""
        self.assertTrue(sp.is_degraded(sp.memory_copy_no_writeback(self._Dummy())))

    def test_none_input_degrades(self):
        """None input degrades."""
        self.assertTrue(sp.is_degraded(sp.memory_copy_no_writeback(None)))


# ─── Semantic path: FLAGGED cases ────────────────────────────────────────────


@SKIP_NO_SLITHER
class MemCopyFlaggedTest(unittest.TestCase):
    """memory_copy_no_writeback flags the FLAGGED fixture and returns correct fields."""

    def test_a_no_writeback_suspect_flagged(self):
        """(a) Memory copy mutated, no writeback -> FLAGGED."""
        sl = _compile(FX / "mem_copy_no_writeback_suspect.sol")
        _, fn = _get_fn(sl, "MemCopyNoWritebackSuspect", "updateLimit")
        self.assertIsNotNone(fn, "updateLimit function not found")
        res = sp.memory_copy_no_writeback(fn)
        self.assertFalse(sp.is_degraded(res))
        self.assertEqual(len(res), 1, f"expected 1 lead, got {res}")
        lead = res[0]
        self.assertEqual(lead["state_var"], "config")
        self.assertEqual(lead["local"], "c")
        self.assertIsNotNone(lead["copy_line"])
        self.assertIsNotNone(lead["mutate_line"])
        self.assertGreater(lead["mutate_line"], lead["copy_line"],
                           "mutate line must be after copy line")
        self.assertEqual(lead["severity_hint"], "lost-state-update")
        self.assertIn("contract", lead)
        self.assertIn("function", lead)

    def test_a_lead_dict_has_all_required_keys(self):
        """Lead dict contains all required fields for downstream consumers."""
        sl = _compile(FX / "mem_copy_no_writeback_suspect.sol")
        _, fn = _get_fn(sl, "MemCopyNoWritebackSuspect", "updateLimit")
        res = sp.memory_copy_no_writeback(fn)
        self.assertEqual(len(res), 1)
        lead = res[0]
        required_keys = {"contract", "function", "state_var", "local",
                         "copy_line", "mutate_line", "severity_hint"}
        for k in required_keys:
            self.assertIn(k, lead, f"missing key: {k}")

    def test_mutation_base_also_flagged(self):
        """The mutation_base fixture is also FLAGGED (same shape, different names)."""
        sl = _compile(FX / "mem_copy_mutation_base.sol")
        _, fn = _get_fn(sl, "MemCopyMutationBase", "setValue")
        self.assertIsNotNone(fn, "setValue function not found")
        res = sp.memory_copy_no_writeback(fn)
        self.assertFalse(sp.is_degraded(res))
        self.assertEqual(len(res), 1)
        lead = res[0]
        self.assertEqual(lead["state_var"], "data")
        self.assertEqual(lead["local"], "d")


# ─── Semantic path: CLEAN cases (never-false-positive) ───────────────────────


@SKIP_NO_SLITHER
class MemCopyCleanNeverFpTest(unittest.TestCase):
    """memory_copy_no_writeback returns [] on all CLEAN fixtures (never-FP)."""

    def test_b_writeback_present_clean(self):
        """(b) Memory copy mutated AND written back -> CLEAN (not flagged)."""
        sl = _compile(FX / "mem_copy_writeback_clean.sol")
        _, fn = _get_fn(sl, "MemCopyWritebackClean", "updateLimit")
        self.assertIsNotNone(fn, "updateLimit function not found")
        res = sp.memory_copy_no_writeback(fn)
        self.assertFalse(sp.is_degraded(res))
        self.assertEqual(res, [], f"writeback present -> must be CLEAN, got: {res}")

    def test_c_storage_pointer_never_fp(self):
        """(c) Storage pointer (location=='storage') -> NOT flagged (never-FP)."""
        sl = _compile(FX / "mem_copy_storage_pointer_clean.sol")
        _, fn = _get_fn(sl, "MemCopyStoragePointerClean", "updateLimit")
        self.assertIsNotNone(fn, "updateLimit function not found")
        res = sp.memory_copy_no_writeback(fn)
        self.assertFalse(sp.is_degraded(res))
        self.assertEqual(res, [], f"storage pointer -> must be CLEAN, got: {res}")

    def test_d_no_mutation_clean(self):
        """(d) Memory copy but local NEVER mutated (read-only) -> CLEAN."""
        sl = _compile(FX / "mem_copy_no_mutation_clean.sol")
        _, fn = _get_fn(sl, "MemCopyNoMutationClean", "getLimit")
        self.assertIsNotNone(fn, "getLimit function not found")
        res = sp.memory_copy_no_writeback(fn)
        self.assertFalse(sp.is_degraded(res))
        self.assertEqual(res, [], f"no mutation -> must be CLEAN, got: {res}")


# ─── __all__ export ───────────────────────────────────────────────────────────


class MemCopyAllExportTest(unittest.TestCase):
    """memory_copy_no_writeback is in __all__."""

    def test_exported_in_all(self):
        self.assertIn("memory_copy_no_writeback", sp.__all__)

    def test_callable_from_module(self):
        self.assertTrue(callable(getattr(sp, "memory_copy_no_writeback", None)))


# ─── Mutation evidence (non-vacuity) ─────────────────────────────────────────


@SKIP_NO_SLITHER
class MemCopyMutationEvidenceTest(unittest.TestCase):
    """Non-vacuity: adding `storageVar = localCopy;` (the writeback) to the base
    fixture must flip memory_copy_no_writeback from FLAGGED -> CLEAN."""

    def test_mutation_writeback_flips_flagged_to_clean(self):
        """Adding storageVar = localCopy; (writeback) must flip FLAGGED -> [].

        This proves the FLAGGED result is not vacuous: the test discriminates
        the presence vs absence of the writeback line.
        """
        base_path = FX / "mem_copy_mutation_base.sol"
        src = base_path.read_text(encoding="utf-8")

        # Base: no writeback -> FLAGGED.
        sl_base = _compile(base_path)
        _, fn_base = _get_fn(sl_base, "MemCopyMutationBase", "setValue")
        res_base = sp.memory_copy_no_writeback(fn_base)
        self.assertEqual(len(res_base), 1,
                         "base fixture must be FLAGGED before mutation")

        # ONE EDIT: insert `data = d;` (the writeback) after the mutation.
        # This is the minimal flip: storage var IS now written -> CLEAN.
        mutated = src.replace(
            "        // MUTATION_TARGET_WRITEBACK_HERE",
            "        data = d;              // WRITEBACK added by mutation test",
        )
        # Verify the replacement actually happened (fail-fast on fixture drift).
        self.assertNotEqual(mutated, src, "mutation replacement did not match source")

        with tempfile.TemporaryDirectory() as td:
            mp = pathlib.Path(td) / "mem_copy_mutation_base.sol"
            mp.write_text(mutated, encoding="utf-8")
            sl_mutated = _compile(mp)
            _, fn_mutated = _get_fn(sl_mutated, "MemCopyMutationBase", "setValue")
            res_mutated = sp.memory_copy_no_writeback(fn_mutated)
            self.assertEqual(
                res_mutated, [],
                "after writeback insertion the annotation must flip FLAGGED->[] "
                "(non-vacuity proof failed - the result is vacuous!)"
            )


# ─── per-function-hacker-questions I1 consumer ───────────────────────────────


class MemCopyI1ConsumerTest(unittest.TestCase):
    """I1: gen_memory_copy_no_writeback_questions and filter work correctly.

    'No question when slice absent' contract: an empty path list yields [].
    These tests do NOT require Slither (they test the question-generation layer
    directly on synthetic path dicts, mirroring the per-function-hacker-questions
    test pattern).
    """

    def _load_pfhq(self):
        """Load per-function-hacker-questions module."""
        spec = importlib.util.spec_from_file_location(
            "per_function_hacker_questions",
            TOOLS / "per-function-hacker-questions.py",
        )
        assert spec and spec.loader
        mod = importlib.util.module_from_spec(spec)
        # per-function-hacker-questions parses argv at module level; patch it.
        import sys as _sys
        old_argv = _sys.argv
        _sys.argv = ["per-function-hacker-questions.py", "--help"]
        try:
            spec.loader.exec_module(mod)
        except SystemExit:
            pass
        finally:
            _sys.argv = old_argv
        return mod

    def _make_suspect_path(self, *, state_var="config", local_var="c",
                           copy_line=17, mutate_line=18, fn="updateLimit",
                           file="Vault.sol"):
        """Synthetic DefUsePath record stamped with memory_copy_no_writeback_suspect."""
        return {
            "path_id": "dfp-test-001",
            "degraded": False,
            "confidence": "exact",
            "language": "solidity",
            "unguarded": True,
            "memory_copy_no_writeback_suspect": True,
            "memory_copy_no_writeback": {
                "state_var": state_var,
                "local": local_var,
                "copy_line": copy_line,
                "mutate_line": mutate_line,
                "at_fn": fn,
                "at_end": "source",
                "severity_hint": "lost-state-update",
            },
            "source": {"fn": fn, "file": file, "kind": "storage-value"},
            "sink": {"fn": fn, "file": file, "kind": "storage-value"},
        }

    def test_empty_paths_yields_no_questions(self):
        """No question when slice absent: empty list -> []."""
        mod = self._load_pfhq()
        result = mod.gen_memory_copy_no_writeback_questions([])
        self.assertEqual(result, [])

    def test_filter_flags_suspect_path(self):
        """_flow_path_is_memory_copy_no_writeback_suspect returns True on suspect path."""
        mod = self._load_pfhq()
        path = self._make_suspect_path()
        self.assertTrue(mod._flow_path_is_memory_copy_no_writeback_suspect(path))

    def test_filter_rejects_degraded_path(self):
        """Degraded path is NOT flagged (R80 honest filter)."""
        mod = self._load_pfhq()
        path = self._make_suspect_path()
        path["degraded"] = True
        self.assertFalse(mod._flow_path_is_memory_copy_no_writeback_suspect(path))

    def test_filter_rejects_heuristic_confidence(self):
        """Heuristic-confidence path is NOT flagged."""
        mod = self._load_pfhq()
        path = self._make_suspect_path()
        path["confidence"] = "heuristic"
        self.assertFalse(mod._flow_path_is_memory_copy_no_writeback_suspect(path))

    def test_filter_rejects_unstamped_path(self):
        """Path without the annotation is NOT flagged."""
        mod = self._load_pfhq()
        path = {"path_id": "x", "degraded": False, "confidence": "exact"}
        self.assertFalse(mod._flow_path_is_memory_copy_no_writeback_suspect(path))

    def test_gen_emits_one_question_per_path(self):
        """gen_memory_copy_no_writeback_questions emits one question per path."""
        mod = self._load_pfhq()
        paths = [self._make_suspect_path(state_var="config", local_var="c"),
                 self._make_suspect_path(state_var="settings", local_var="s",
                                         copy_line=30, mutate_line=31,
                                         fn="configure")]
        result = mod.gen_memory_copy_no_writeback_questions(paths)
        self.assertEqual(len(result), 2)

    def test_gen_question_class_is_lost_state_update(self):
        """Emitted question has question_class == 'lost-state-update'."""
        mod = self._load_pfhq()
        path = self._make_suspect_path()
        result = mod.gen_memory_copy_no_writeback_questions([path])
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["question_class"], "lost-state-update")

    def test_gen_question_source_is_flow_seeded(self):
        """Emitted question carries flow_seeded=True and correct source tag."""
        mod = self._load_pfhq()
        path = self._make_suspect_path()
        result = mod.gen_memory_copy_no_writeback_questions([path])
        self.assertEqual(len(result), 1)
        q = result[0]
        self.assertTrue(q["flow_seeded"])
        self.assertEqual(q["question_source"], "flow-seeded-memory-copy-no-writeback")

    def test_gen_question_carries_suspect_flag(self):
        """Emitted question carries memory_copy_no_writeback_suspect=True."""
        mod = self._load_pfhq()
        path = self._make_suspect_path()
        result = mod.gen_memory_copy_no_writeback_questions([path])
        self.assertTrue(result[0].get("memory_copy_no_writeback_suspect"))

    def test_gen_question_names_state_var_and_local(self):
        """Emitted question text mentions the state_var and local names."""
        mod = self._load_pfhq()
        path = self._make_suspect_path(state_var="myStorage", local_var="tmp")
        result = mod.gen_memory_copy_no_writeback_questions([path])
        q_text = result[0]["question"]
        self.assertIn("myStorage", q_text)
        self.assertIn("tmp", q_text)

    def test_gen_question_carries_path_id(self):
        """Emitted question carries dataflow_path_id."""
        mod = self._load_pfhq()
        path = self._make_suspect_path()
        result = mod.gen_memory_copy_no_writeback_questions([path])
        self.assertEqual(result[0]["dataflow_path_id"], "dfp-test-001")


# ─── lib/dataflow_attack_class.py I2 consumer ────────────────────────────────


class MemCopyI2AttackClassTest(unittest.TestCase):
    """I2: suggest_memory_copy_no_writeback_attack_class returns a taxonomy-
    verbatim class or None (never invents). Tests do NOT require Slither."""

    def _load_dac(self):
        spec = importlib.util.spec_from_file_location(
            "dataflow_attack_class",
            TOOLS / "lib" / "dataflow_attack_class.py",
        )
        assert spec and spec.loader
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    def test_suggest_returns_none_or_string(self):
        """suggest_memory_copy_no_writeback_attack_class returns None or a string."""
        mod = self._load_dac()
        result = mod.suggest_memory_copy_no_writeback_attack_class("storage-value")
        self.assertIn(type(result), (type(None), str))

    def test_suggest_result_verbatim_in_taxonomy_or_none(self):
        """The returned class (if not None) is verbatim in the taxonomy (R38)."""
        mod = self._load_dac()
        result = mod.suggest_memory_copy_no_writeback_attack_class("storage-value")
        if result is not None:
            classes = mod.canonical_classes()
            self.assertIn(result, classes,
                          f"suggested class '{result}' is NOT in the taxonomy "
                          f"(R38 violation - never invent a class)")

    def test_suggest_with_empty_taxonomy_returns_none(self):
        """When taxonomy is unavailable/empty, suggest returns None (never invents)."""
        mod = self._load_dac()
        # Pass a nonexistent file so canonical_classes returns frozenset().
        result = mod.suggest_memory_copy_no_writeback_attack_class(
            "storage-value",
            taxonomy_path="/nonexistent/path/taxonomy.json",
        )
        self.assertIsNone(result, "must return None when taxonomy absent (never invent)")

    def test_callable_in_module(self):
        """suggest_memory_copy_no_writeback_attack_class is callable from the module."""
        mod = self._load_dac()
        self.assertTrue(
            callable(getattr(mod, "suggest_memory_copy_no_writeback_attack_class", None))
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
