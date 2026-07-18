#!/usr/bin/env python3
"""Tests for tools/finding-evidence-honesty-check.py (Rule R80)."""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_TOOL = _HERE.parent / "finding-evidence-honesty-check.py"
_spec = importlib.util.spec_from_file_location("finding_evidence_honesty_check", str(_TOOL))
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)


def _write(p: Path, content: str) -> Path:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    return p


def _make_real_harness(ws: Path, *, with_mutation: bool, mock_only: bool = False) -> None:
    """Craft a workspace whose harness reality classifier sees a real / mock CUT."""
    chim = ws / "poc-tests" / "chimera"
    chim.mkdir(parents=True, exist_ok=True)
    if mock_only:
        # Setup deploys ONLY mock contracts -> mock-only run.
        _write(chim / "Setup.sol",
               'import "src/Foo.sol";\n'
               "contract Setup {\n"
               "  function setup() public {\n"
               "    new MockToken();\n"
               "    new MockOracle();\n"
               "  }\n}\n")
    else:
        # Setup imports from src/ and deploys a real (non-mock) CUT plus an external mock.
        _write(chim / "Setup.sol",
               'import "src/Vault.sol";\n'
               "contract Setup {\n"
               "  function setup() public {\n"
               "    new MockERC20();\n"
               "    new Vault();\n"
               "  }\n}\n")
    # Real invariant in Properties.sol.
    _write(chim / "Properties.sol",
           "contract Properties {\n"
           "  function property_solvency() public {\n"
           "    assert(totalAssets >= totalSupply);\n"
           "  }\n}\n")
    if with_mutation:
        _write(ws / ".auditooor" / "chimera_mutation_verification.json",
               json.dumps({"injected": "underflow", "invariant_failed": True,
                           "restored": True, "passes_after_restore": True}))


class TestFindingEvidenceHonesty(unittest.TestCase):
    def _run(self, draft: Path, ws: Path | None = None, **kw):
        return mod.run(draft.resolve(), workspace=ws, **kw)

    # 1. prose-only draft -> pass-no-harness-evidence-cited
    def test_prose_only(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            (ws / "submissions").mkdir()
            draft = _write(ws / "submissions" / "f.md",
                           "Severity: High\nThe function lacks an access check. "
                           "An attacker can call admin() directly and drain funds.")
            code, p = self._run(draft, ws)
            self.assertEqual(p["verdict"], "pass-no-harness-evidence-cited")
            self.assertEqual(code, 0)

    # 2. real, mutation-verified, non-mock harness -> pass-real-in-scope-proof
    def test_real_in_scope_proof(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            (ws / "src").mkdir()
            _write(ws / "src" / "Vault.sol", "contract Vault {}\n")
            _make_real_harness(ws, with_mutation=True)
            draft = _write(ws / "submissions" / "f.md",
                           "Severity: High\nProven by the Chimera invariant harness "
                           "(property_solvency). The PoC passes against poc-tests/chimera/Setup.sol.")
            code, p = self._run(draft, ws)
            self.assertEqual(p["verdict"], "pass-real-in-scope-proof", msg=json.dumps(p, indent=2))
            self.assertEqual(code, 0)
            self.assertTrue(p["mutation_record"]["present"])

    # 3. cites an engine-error / hollow run -> fail-hollow-engine-cited
    def test_hollow_engine_cited(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            (ws / "src").mkdir()
            _write(ws / "src" / "Vault.sol", "contract Vault {}\n")
            # halmos artifact present but status engine-error; per-function only stub harnesses.
            _write(ws / ".auditooor" / "halmos" / "artifact.json",
                   json.dumps({"status": "engine-error"}))
            pfi = ws / "poc-tests" / "per_function_invariants"
            pfi.mkdir(parents=True)
            _write(pfi / "stub.t.sol",
                   "contract S { function test() public { assert(true); } }\n")
            draft = _write(ws / "submissions" / "f.md",
                           "Severity: Critical\nProven by the halmos symbolic run "
                           "(poc-tests/per_function_invariants/stub.t.sol).")
            code, p = self._run(draft, ws)
            self.assertEqual(p["verdict"], "fail-hollow-engine-cited", msg=json.dumps(p, indent=2))
            self.assertEqual(code, 1)

    # 4. real harness but no mutation record -> fail-non-mutation-verified
    def test_non_mutation_verified(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            (ws / "src").mkdir()
            _write(ws / "src" / "Vault.sol", "contract Vault {}\n")
            _make_real_harness(ws, with_mutation=False)
            draft = _write(ws / "submissions" / "f.md",
                           "Severity: High\nProven by the invariant harness "
                           "(poc-tests/chimera/Setup.sol). The PoC passes.")
            code, p = self._run(draft, ws)
            self.assertEqual(p["verdict"], "fail-non-mutation-verified", msg=json.dumps(p, indent=2))
            self.assertEqual(code, 1)

    # 5. mock-only harness -> fail-mock-cut-cited
    def test_mock_cut_cited(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            (ws / "src").mkdir()
            _write(ws / "src" / "Foo.sol", "contract Foo {}\n")
            _make_real_harness(ws, with_mutation=True, mock_only=True)
            draft = _write(ws / "submissions" / "f.md",
                           "Severity: High\nProven by the Chimera harness "
                           "(poc-tests/chimera/Setup.sol). Invariant holds.")
            code, p = self._run(draft, ws)
            self.assertEqual(p["verdict"], "fail-mock-cut-cited", msg=json.dumps(p, indent=2))
            self.assertEqual(code, 1)

    # 6. fail + valid r80-rebuttal line -> ok-rebuttal
    def test_ok_rebuttal(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            (ws / "src").mkdir()
            _write(ws / "src" / "Vault.sol", "contract Vault {}\n")
            _make_real_harness(ws, with_mutation=False)
            draft = _write(ws / "submissions" / "f.md",
                           "Severity: High\nProven by the invariant harness "
                           "(poc-tests/chimera/Setup.sol).\n"
                           "r80-rebuttal: mutation record attached out-of-band in tracker PR-123")
            code, p = self._run(draft, ws)
            self.assertEqual(p["verdict"], "ok-rebuttal", msg=json.dumps(p, indent=2))
            self.assertEqual(p["original_verdict"], "fail-non-mutation-verified")
            self.assertEqual(code, 0)

    # 7. oversized rebuttal is ignored -> original fail stands
    def test_rebuttal_oversized_ignored(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            (ws / "src").mkdir()
            _write(ws / "src" / "Vault.sol", "contract Vault {}\n")
            _make_real_harness(ws, with_mutation=False)
            big = "x" * 250
            draft = _write(ws / "submissions" / "f.md",
                           f"Severity: High\nProven by the invariant harness "
                           f"(poc-tests/chimera/Setup.sol).\n"
                           f"<!-- r80-rebuttal: {big} -->")
            code, p = self._run(draft, ws)
            self.assertEqual(p["verdict"], "fail-non-mutation-verified", msg=json.dumps(p, indent=2))
            self.assertEqual(code, 1)

    # 8. empty rebuttal is ignored -> original fail stands
    def test_rebuttal_empty_ignored(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            (ws / "src").mkdir()
            _write(ws / "src" / "Vault.sol", "contract Vault {}\n")
            _make_real_harness(ws, with_mutation=False)
            draft = _write(ws / "submissions" / "f.md",
                           "Severity: High\nProven by the invariant harness "
                           "(poc-tests/chimera/Setup.sol).\n"
                           "<!-- r80-rebuttal:   -->")
            code, p = self._run(draft, ws)
            self.assertEqual(p["verdict"], "fail-non-mutation-verified", msg=json.dumps(p, indent=2))
            self.assertEqual(code, 1)

    # 9. severity out-of-scope behavior (explicit LOW/MEDIUM downgrades)
    def test_severity_out_of_scope(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            (ws / "src").mkdir()
            _write(ws / "src" / "Vault.sol", "contract Vault {}\n")
            _make_real_harness(ws, with_mutation=False)
            draft = _write(ws / "submissions" / "f.md",
                           "Severity: Medium\nProven by the invariant harness "
                           "(poc-tests/chimera/Setup.sol).")
            code, p = self._run(draft, ws, severity_override="MEDIUM")
            self.assertEqual(p["verdict"], "pass-out-of-scope")
            self.assertEqual(code, 0)

    # 10. JSON schema valid + schema constant
    def test_json_schema_valid(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            (ws / "submissions").mkdir()
            draft = _write(ws / "submissions" / "f.md", "Severity: High\nProse only finding.")
            code, p = self._run(draft, ws)
            # round-trip through json
            s = json.dumps(p)
            back = json.loads(s)
            self.assertEqual(back["schema"], "auditooor.r80_finding_evidence_honesty.v1")
            self.assertEqual(mod.SCHEMA, "auditooor.r80_finding_evidence_honesty.v1")

    # 11. evidence cited, workspace cannot verify, non-strict -> WARN pass
    def test_unlocatable_warn_pass_nonstrict(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            (ws / "submissions").mkdir()
            # no harness anywhere in ws
            draft = _write(ws / "submissions" / "f.md",
                           "Severity: High\nProven by an echidna fuzz campaign (off-tree).")
            code, p = self._run(draft, ws, strict=False)
            self.assertEqual(p["verdict"], "pass-no-harness-evidence-cited")
            self.assertIn("warn", p)
            self.assertEqual(code, 0)

    # 12. same but --strict -> needs-evidence-path, exit 1
    def test_unlocatable_strict_fails(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            (ws / "submissions").mkdir()
            draft = _write(ws / "submissions" / "f.md",
                           "Severity: High\nProven by an echidna fuzz campaign (off-tree).")
            code, p = self._run(draft, ws, strict=True)
            self.assertEqual(p["verdict"], "needs-evidence-path")
            self.assertEqual(code, 1)

    # 13. error: draft not a file
    def test_error_missing_draft(self):
        code, p = mod.run(Path("/nonexistent/abc/xyz.md"))
        self.assertEqual(p["verdict"], "error")
        self.assertEqual(code, 2)

    # 14. workspace inference from draft path (no explicit --workspace)
    def test_workspace_inference(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            (ws / "src").mkdir()
            _write(ws / "src" / "Vault.sol", "contract Vault {}\n")
            _make_real_harness(ws, with_mutation=True)
            draft = _write(ws / "submissions" / "slug" / "slug.md",
                           "Severity: High\nProven by the Chimera invariant harness "
                           "(poc-tests/chimera/Setup.sol). PoC passes.")
            code, p = mod.run(draft.resolve())  # no workspace passed
            self.assertEqual(p["verdict"], "pass-real-in-scope-proof", msg=json.dumps(p, indent=2))
            self.assertEqual(code, 0)


if __name__ == "__main__":
    unittest.main()
