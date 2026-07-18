#!/usr/bin/env python3
"""test_notapplicable_revalidate_e6.py

E6 (enforcement id17, 2026-07-03): stale note-only "not-applicable" hacker-Q
credit revalidation.

check_hacker_questions_resolved credits a NOT-APPLICABLE auto-disposition
UNCONDITIONALLY - it trusts a sticky "auto-resolved not-applicable" note that
claims the anchored function is ABSENT from this workspace. That note goes STALE:
if the cited function IS in fact defined in in-scope source, the "absent" premise
is false and the credit is wrong. NUVA: 58 rows credited FromUnderlyingAssetAmount
@ valuation_engine.go:135 and CalculateAUMFee @ interest.go:87 as absent while
both ARE present in-scope; 72 OTHER rows correctly credit vendored cosmos-sdk fns
in ~/go/pkg/mod that are genuinely out-of-tree.

DEFAULT-ON graduation (2026-07-03): the revalidation now defaults ENFORCED under
the L37 strict umbrella (what `make audit-complete STRICT=1` exports), with a
per-gate OPT-OUT via AUDITOOOR_NOTAPPLICABLE_REVALIDATE_STRICT=0. The uniform
4-case matrix:
  - default-under-L37 (env unset, AUDITOOOR_L37_STRICT=1) -> ENFORCED (reopens);
  - opt-out (env=0, even under L37)                       -> advisory (credits);
  - explicit-on (env=1)                                    -> ENFORCED (reopens);
  - non-strict-advisory (env unset, no L37)                -> advisory (credits).

This test builds a synthetic workspace with (a) a stale row whose fn IS defined
in an in-workspace .go file, and (b) a vendored row whose file lives outside the
workspace, and pins the 4-case matrix plus: env-set reopens ONLY the stale one,
and a non-identifier function_signature is never reopened.
"""
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

_TOOLS = Path(__file__).resolve().parents[1]
_ACC_SRC = (_TOOLS / "audit-completeness-check.py").read_text(
    encoding="utf-8", errors="replace")
_ENV = "AUDITOOOR_NOTAPPLICABLE_REVALIDATE_STRICT"
_L37 = "AUDITOOOR_L37_STRICT"


def _load_acc():
    spec = importlib.util.spec_from_file_location(
        "acc_e6", str(_TOOLS / "audit-completeness-check.py"))
    m = importlib.util.module_from_spec(spec)
    sys.modules["acc_e6"] = m
    spec.loader.exec_module(m)
    return m


def _na_row(oid, fn, file_path):
    """A terminal not-applicable auto-disposed obligation row."""
    return {
        "obligation_id": oid,
        "function_name": fn,
        "file": file_path,
        "state": "killed",
        "language": "go",
        "operator_notes": "auto-resolved not-applicable: function absent from workspace",
    }


def _build_ws(tmp: Path):
    """Workspace with an in-scope .go file DEFINING FromUnderlyingAssetAmount, and
    an obligations file carrying a STALE not-applicable row (fn present in-scope)
    plus a VENDORED not-applicable row (fn in ~/go/pkg/mod, outside the ws)."""
    ad = tmp / ".auditooor"
    ad.mkdir(parents=True, exist_ok=True)
    src = tmp / "src" / "vault" / "keeper"
    src.mkdir(parents=True, exist_ok=True)
    present = src / "valuation_engine.go"
    present.write_text(
        "package keeper\n\n"
        "func (k Keeper) FromUnderlyingAssetAmount(ctx Ctx, v Vault, "
        "a Int, d string) (Int, error) {\n\treturn a, nil\n}\n")
    vendored_path = "/Users/wolf/go/pkg/mod/github.com/cosmos/cosmos-sdk/baseapp/baseapp.go"
    rows = [
        _na_row("stale1", "FromUnderlyingAssetAmount", str(present)),
        _na_row("vendored1", "ProcessProposalVerifyTx", vendored_path),
    ]
    with (ad / "hacker_question_obligations.jsonl").open("w") as fh:
        for r in rows:
            fh.write(json.dumps(r) + "\n")
    return tmp


class TestE6NotApplicableRevalidate(unittest.TestCase):
    def setUp(self):
        self._saved = os.environ.pop(_ENV, None)
        self._saved_l37 = os.environ.pop(_L37, None)
        self.acc = _load_acc()

    def tearDown(self):
        for k, v in ((_ENV, self._saved), (_L37, self._saved_l37)):
            os.environ.pop(k, None)
            if v is not None:
                os.environ[k] = v

    # ---- 4-case default-ON-under-L37 matrix ------------------------------
    def test_case_non_strict_advisory_env_unset_no_l37(self):
        # env unset AND no L37 -> advisory (a bare/library caller): both credited.
        with tempfile.TemporaryDirectory() as tmp:
            ws = _build_ws(Path(tmp))
            os.environ.pop(_ENV, None)
            os.environ.pop(_L37, None)
            r = self.acc.check_hacker_questions_resolved(ws)
            self.assertEqual(r.detail.get("stale_not_applicable_reopened"), 0)
            self.assertEqual(r.detail.get("open"), 0)
            self.assertTrue(r.ok)
            self.assertFalse(r.detail.get("notapplicable_revalidate"))

    def test_case_default_under_l37_enforced(self):
        # env UNSET but AUDITOOOR_L37_STRICT=1 -> NEW default: ENFORCED. The stale
        # in-scope row reopens; the outer signal (also L37-strict) FAILs on it.
        with tempfile.TemporaryDirectory() as tmp:
            ws = _build_ws(Path(tmp))
            os.environ.pop(_ENV, None)
            os.environ[_L37] = "1"
            r = self.acc.check_hacker_questions_resolved(ws)
            self.assertTrue(r.detail.get("notapplicable_revalidate"),
                            "env-unset under L37 must ENFORCE the revalidation (default-ON)")
            self.assertEqual(r.detail.get("stale_not_applicable_reopened"), 1)
            self.assertEqual(r.detail.get("open"), 1)
            self.assertFalse(r.ok, "reopened stale row under L37-strict must FAIL the signal")

    def test_case_opt_out_env_zero_even_under_l37(self):
        # explicit AUDITOOOR_NOTAPPLICABLE_REVALIDATE_STRICT=0 -> DISABLED escape
        # hatch even when L37 is set: both credited, revalidation off.
        with tempfile.TemporaryDirectory() as tmp:
            ws = _build_ws(Path(tmp))
            os.environ[_ENV] = "0"
            os.environ[_L37] = "1"
            r = self.acc.check_hacker_questions_resolved(ws)
            self.assertFalse(r.detail.get("notapplicable_revalidate"),
                             "env=0 is an explicit opt-out even under L37")
            self.assertEqual(r.detail.get("stale_not_applicable_reopened"), 0)
            self.assertEqual(r.detail.get("open"), 0)
            self.assertTrue(r.ok)

    def test_case_explicit_on_env_one(self):
        # explicit opt-in reopens the stale row (no L37 needed for the E6 branch;
        # the outer signal WARN-passes since it is not L37-strict here).
        with tempfile.TemporaryDirectory() as tmp:
            ws = _build_ws(Path(tmp))
            os.environ[_ENV] = "1"
            os.environ.pop(_L37, None)
            r = self.acc.check_hacker_questions_resolved(ws)
            self.assertTrue(r.detail.get("notapplicable_revalidate"))
            self.assertEqual(r.detail.get("stale_not_applicable_reopened"), 1)
            self.assertEqual(r.detail.get("open"), 1)

    def test_env_set_reopens_only_the_stale_row(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = _build_ws(Path(tmp))
            os.environ[_ENV] = "1"
            r = self.acc.check_hacker_questions_resolved(ws)
            # exactly the in-scope-present row is reopened; the vendored one stays credited
            self.assertEqual(r.detail.get("stale_not_applicable_reopened"), 1)
            self.assertEqual(r.detail.get("open"), 1)
            sample = r.detail.get("stale_not_applicable_sample") or []
            self.assertEqual(len(sample), 1)
            self.assertEqual(sample[0]["function_name"], "FromUnderlyingAssetAmount")

    def test_vendored_absent_stays_credited(self):
        # A workspace with ONLY the vendored row must reopen 0 even under the env
        with tempfile.TemporaryDirectory() as tmp:
            ad = Path(tmp) / ".auditooor"
            ad.mkdir(parents=True)
            vend = "/Users/wolf/go/pkg/mod/github.com/cosmos/cosmos-sdk/baseapp/baseapp.go"
            (ad / "hacker_question_obligations.jsonl").write_text(
                json.dumps(_na_row("v1", "ProcessProposalVerifyTx", vend)) + "\n")
            os.environ[_ENV] = "1"
            r = self.acc.check_hacker_questions_resolved(Path(tmp))
            self.assertEqual(r.detail.get("stale_not_applicable_reopened"), 0)
            self.assertEqual(r.detail.get("open"), 0)

    def test_non_identifier_signature_never_reopened(self):
        # A function_signature that is a hash / shape id (not a real symbol) must
        # never trigger a source-grep reopen (no false-reopen).
        with tempfile.TemporaryDirectory() as tmp:
            ad = Path(tmp) / ".auditooor"
            ad.mkdir(parents=True)
            row = _na_row("h1", "", str(Path(tmp) / "x.go"))
            row["function_signature"] = "07064cecff58"
            (ad / "hacker_question_obligations.jsonl").write_text(json.dumps(row) + "\n")
            os.environ[_ENV] = "1"
            r = self.acc.check_hacker_questions_resolved(Path(tmp))
            self.assertEqual(r.detail.get("stale_not_applicable_reopened"), 0)

    def test_fn_present_helper_direct(self):
        # Direct unit test of the presence helper: present-in-ws -> True;
        # vendored / absent -> False.
        with tempfile.TemporaryDirectory() as tmp:
            ws = _build_ws(Path(tmp))
            present_row = _na_row(
                "s", "FromUnderlyingAssetAmount",
                str(ws / "src" / "vault" / "keeper" / "valuation_engine.go"))
            vend_row = _na_row(
                "v", "ProcessProposalVerifyTx",
                "/Users/wolf/go/pkg/mod/x/baseapp.go")
            self.assertTrue(self.acc._fn_present_in_workspace_source(ws, present_row))
            self.assertFalse(self.acc._fn_present_in_workspace_source(ws, vend_row))

    def test_default_on_predicate_wiring(self):
        # DEFAULT-ON graduation: the E6 revalidation predicate now delegates to the
        # shared _gate_default_on_strict() over the DEDICATED env, which defaults ON
        # under the L37 umbrella with a per-gate opt-out.
        self.assertIn(f'_NOTAPPLICABLE_REVALIDATE_STRICT_ENV = "{_ENV}"', _ACC_SRC)
        i = _ACC_SRC.find("_notapplicable_revalidate = _gate_default_on_strict")
        self.assertGreater(i, 0, "E6 must call the shared default-ON helper")
        seg = _ACC_SRC[i:i + 160]
        self.assertIn("_NOTAPPLICABLE_REVALIDATE_STRICT_ENV", seg)
        # the shared helper itself must read L37 as the default umbrella
        h = _ACC_SRC.find("def _gate_default_on_strict")
        self.assertGreater(h, 0)
        hseg = _ACC_SRC[h:h + 1400]
        self.assertIn("AUDITOOOR_L37_STRICT", hseg)
        self.assertIn('("0", "false", "no")', hseg)  # explicit opt-out branch

    def test_syntax_ok(self):
        import ast
        ast.parse(_ACC_SRC)


if __name__ == "__main__":
    unittest.main()
