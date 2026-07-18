#!/usr/bin/env python3
"""LG3 per-language guard-shape precision tests for guard-negative-space-analyzer.

PROBLEM these tests pin: the broad _GUARD_PATTERNS over-match on Go idioms -
``if err != nil``, bare ``if x == nil { return ... }`` error-propagation,
struct-field declarations, and bodyless interface method signatures - tagging
~56% boilerplate as "guards" (measured on bor). The LG3 fix makes guard-shape
detection PER-LANGUAGE:

  - go        : DROP err/nil propagation, struct field decls, bodyless interface
                signatures; KEEP auth/bounds/state conditionals + require/assert.
  - solidity  : require/revert/assert/modifier kept (behavior ~unchanged).
  - rust      : DROP bodyless trait method signatures; keep ensure!/assert!/etc.
  - unknown   : KEEP-ALL broad behavior + a loud WARN (completeness-safe, never
                under-scope a new language).

These tests assert the Go boilerplate DENOMINATOR DROPS while real guards are
KEPT, that Solidity is unchanged, and that an unknown extension retains the
broad behavior.
"""
import importlib.util
import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path

_TOOL = Path(__file__).resolve().parent.parent / "guard-negative-space-analyzer.py"
_spec = importlib.util.spec_from_file_location("guard_negative_space_analyzer_lang", _TOOL)
gns = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gns)


def _write(p: Path, text: str) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


def _mk_ws(tmp: Path, files: dict[str, str], units: list[dict]) -> Path:
    ws = tmp / "ws"
    (ws / ".auditooor").mkdir(parents=True)
    for rel, body in files.items():
        _write(ws / rel, body)
    inscope = ws / ".auditooor" / "inscope_units.jsonl"
    inscope.write_text("\n".join(json.dumps(u) for u in units) + "\n", encoding="utf-8")
    return ws


def _worklist_lines(ws: Path) -> list[str]:
    p = ws / ".auditooor" / "negative_space_worklist.jsonl"
    if not p.is_file():
        return []
    return [ln for ln in p.read_text(encoding="utf-8").splitlines() if ln.strip()]


def _checks_of(ws: Path) -> list[str]:
    return [json.loads(ln).get("checks", "") for ln in _worklist_lines(ws)]


# ---------------------------------------------------------------------------
# GO: boilerplate pruned, real auth guard kept.
# ---------------------------------------------------------------------------
# Every flagged line below is matched by the BROAD _GUARD_PATTERNS:
#   - ``checkInterval uint64``    -> verify-call pattern (field name starts 'check')
#   - ``Validate(ctx Context) ..``-> verify-call pattern (bodyless interface sig)
#   - ``if err != nil {``         -> go-err-return pattern (boilerplate)
#   - ``if store == nil {``       -> go-nil-check pattern (bare nil propagation)
#   - ``validateOwner(caller)``   -> verify-call pattern (REAL auth guard, kept)
#   - ``require(amount <= ...)``  -> require pattern (REAL bound guard, kept)
GO_FILE = """\
package keeper

type Config struct {
	Owner         string
	checkInterval uint64
}

type Validator interface {
	Validate(ctx Context) error
}

func (k Keeper) Withdraw(amount uint64, caller string) error {
	store := k.get()
	if err != nil {
		return err
	}
	if store == nil {
		return ErrNilStore
	}
	if err := validateOwner(caller); err != nil {
		return err
	}
	require(amount <= balance, "insufficient balance")
	return nil
}
"""


class GoPruningTests(unittest.TestCase):
    def test_go_boilerplate_pruned_real_guards_kept(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _mk_ws(
                Path(td),
                {"x/keeper/withdraw.go": GO_FILE},
                [{"file": "x/keeper/withdraw.go", "function": "Withdraw",
                  "file_line": "x/keeper/withdraw.go:13"}],
            )
            gns.emit_worklist(ws)
            checks = _checks_of(ws)
            joined = "\n".join(checks)

            # KEPT: the real auth guard (validateOwner call) and require bound.
            self.assertTrue(any("validateOwner" in c for c in checks),
                            "auth validate guard must be KEPT")
            self.assertTrue(any("require(amount" in c for c in checks),
                            "require bound must be KEPT")

            # PRUNED: bare err-propagation, bare nil-propagation, struct-field
            # decl, and bodyless interface signature boilerplate.
            self.assertFalse(any(c.strip() == "if err != nil {" for c in checks),
                             "bare err-propagation must be PRUNED")
            self.assertFalse(any(c.strip() == "if store == nil {" for c in checks),
                             "bare nil-propagation must be PRUNED")
            self.assertFalse(any(c.strip() == "checkInterval uint64" for c in checks),
                             "struct-field decl (checkInterval) must be PRUNED")
            self.assertFalse(any(c.strip().startswith("Validate(ctx Context)")
                                 for c in checks),
                             "bodyless interface signature must be PRUNED")

    def test_go_denominator_drops_vs_broad_but_keeps_real(self):
        """The candidate count DROPS for Go boilerplate yet real guards survive.

        We compare the per-language (pruned) count against the broad (unfiltered)
        count over the SAME file by temporarily widening _PRECISION_LANGS to a set
        that excludes 'go' (forcing the keep-all path), then restoring it.
        """
        with tempfile.TemporaryDirectory() as td:
            ws = _mk_ws(
                Path(td),
                {"x/keeper/withdraw.go": GO_FILE},
                [{"file": "x/keeper/withdraw.go", "function": "Withdraw",
                  "file_line": "x/keeper/withdraw.go:13"}],
            )
            # pruned (default: go IS in _PRECISION_LANGS)
            gns.emit_worklist(ws)
            pruned = len(_worklist_lines(ws))

            # broad: drop 'go' from the precision set so keep-all path runs
            orig = set(gns._PRECISION_LANGS)
            try:
                gns._PRECISION_LANGS.discard("go")
                # suppress the now-fired unknown-language WARN
                with redirect_stderr(io.StringIO()):
                    gns.emit_worklist(ws)
                broad = len(_worklist_lines(ws))
            finally:
                gns._PRECISION_LANGS.clear()
                gns._PRECISION_LANGS.update(orig)

            self.assertLess(pruned, broad,
                            "Go pruning must DROP the candidate denominator")
            self.assertGreaterEqual(pruned, 2,
                                    "real guards (auth + require) must be KEPT")


# ---------------------------------------------------------------------------
# SOLIDITY: behavior unchanged - require kept.
# ---------------------------------------------------------------------------
SOL_FILE = """\
pragma solidity ^0.8.0;
contract Vault {
    function withdraw(uint256 amount) external onlyOwner {
        require(msg.sender == owner, "not owner");
        require(amount <= balance, "insufficient");
        balance -= amount;
    }
}
"""


class SolidityUnchangedTests(unittest.TestCase):
    def test_solidity_require_is_a_guard(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _mk_ws(
                Path(td),
                {"src/Vault.sol": SOL_FILE},
                [{"file": "src/Vault.sol", "function": "withdraw",
                  "file_line": "src/Vault.sol:3"}],
            )
            gns.emit_worklist(ws)
            checks = _checks_of(ws)
            self.assertTrue(any("require(msg.sender == owner" in c for c in checks),
                            "Solidity auth require must be a guard")
            self.assertTrue(any("onlyOwner" in c or "require(amount" in c
                                for c in checks),
                            "Solidity bound/modifier guard must be present")


# ---------------------------------------------------------------------------
# RUST: bodyless trait sig pruned; macro/ensure kept.
# ---------------------------------------------------------------------------
RUST_FILE = """\
pub trait Checker {
    fn validate_owner(&self, caller: &Addr) -> Result<(), Error>;
}

pub fn withdraw(amount: u64, caller: &Addr) -> Result<(), Error> {
    ensure!(amount <= MAX, "too large");
    require!(caller == &OWNER, Error::Unauthorized);
    Ok(())
}
"""


class RustTests(unittest.TestCase):
    def test_rust_trait_sig_pruned_macros_kept(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _mk_ws(
                Path(td),
                {"src/lib.rs": RUST_FILE},
                [{"file": "src/lib.rs", "function": "withdraw",
                  "file_line": "src/lib.rs:5"}],
            )
            gns.emit_worklist(ws)
            checks = _checks_of(ws)
            joined = "\n".join(checks)
            self.assertIn("ensure!(amount", joined, "ensure! macro guard kept")
            self.assertIn("require!(caller", joined, "require! macro guard kept")
            self.assertFalse(
                any(c.strip().startswith("fn validate_owner") for c in checks),
                "bodyless trait method signature must be PRUNED",
            )


# ---------------------------------------------------------------------------
# UNKNOWN LANGUAGE: keep-all broad behavior + loud WARN (completeness-safe).
# ---------------------------------------------------------------------------
# A .cairo file: scannable (in _SOURCE_EXTS) but with NO precision filter
# (cairo is not in _PRECISION_LANGS). Contains a verify-style call AND the exact
# ``if err != nil`` boilerplate Go would prune - here NOTHING may be pruned, and
# a WARN must fire (completeness-safe over-include on a language we cannot lint).
UNKNOWN_FILE = """\
func validateCaller() {
    if err != nil {
        revert
    }
}
"""


class UnknownLanguageTests(unittest.TestCase):
    def test_unknown_ext_keeps_all_and_warns(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _mk_ws(
                Path(td),
                {"src/thing.cairo": UNKNOWN_FILE},
                [{"file": "src/thing.cairo", "function": "validateCaller",
                  "file_line": "src/thing.cairo:1"}],
            )
            buf = io.StringIO()
            with redirect_stderr(buf):
                gns.emit_worklist(ws)
            warn = buf.getvalue()

            # loud WARN with a one-line manual step
            self.assertIn("WARN", warn)
            self.assertIn("DEGRADED", warn)
            self.assertIn("Manual step", warn)
            self.assertIn("src/thing.cairo", warn)

            # broad behavior retained: the bare ``if err != nil`` that Go prunes
            # is KEPT here (over-include, never drop on an unknown language).
            joined = "\n".join(_checks_of(ws))
            self.assertIn("if err != nil", joined,
                          "unknown language must KEEP boilerplate (no under-scope)")

    def test_known_language_does_not_warn(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _mk_ws(
                Path(td),
                {"src/Vault.sol": SOL_FILE},
                [{"file": "src/Vault.sol", "function": "withdraw",
                  "file_line": "src/Vault.sol:3"}],
            )
            buf = io.StringIO()
            with redirect_stderr(buf):
                gns.emit_worklist(ws)
            self.assertNotIn("DEGRADED", buf.getvalue(),
                             "a known language must NOT emit the degraded WARN")


class DetectLangTests(unittest.TestCase):
    def test_detect_lang_mapping(self):
        self.assertEqual(gns._detect_lang("a/b/c.go"), "go")
        self.assertEqual(gns._detect_lang("X.sol"), "solidity")
        self.assertEqual(gns._detect_lang("lib.rs"), "rust")
        self.assertEqual(gns._detect_lang("weird.zok"), "")  # unknown


if __name__ == "__main__":
    unittest.main()
