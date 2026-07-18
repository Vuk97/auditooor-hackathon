# r36-rebuttal: lane TASK-B-HP-POC-NOT-INLINE registered in .auditooor/agent_pathspec.json
"""
test_hackenproof_poc_not_inline.py
Unit tests for tools/hackenproof-poc-not-inline-check.py

Gate: a HackenProof .hackenproof-plain.txt MUST NOT inline the full PoC
harness source - the harness + transcript ship in the attached -poc.zip,
the .txt PoC section just references the attachment.

Run:  python3 -m unittest tools.tests.test_hackenproof_poc_not_inline -v
"""

import importlib.util
import os
import sys
import tempfile
import unittest
import zipfile

# Ensure tools/ is importable as a module root
_TOOLS_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _TOOLS_DIR not in sys.path:
    sys.path.insert(0, _TOOLS_DIR)

_TOOL_PATH = os.path.join(_TOOLS_DIR, "hackenproof-poc-not-inline-check.py")
_spec = importlib.util.spec_from_file_location("hackenproof_poc_not_inline_check", _TOOL_PATH)
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)

check = _mod.check
SCHEMA = _mod.SCHEMA
SECTION_LIMIT = _mod.SECTION_LIMIT
LARGE_FENCE_LINES = _mod.LARGE_FENCE_LINES


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

def _rust_harness_body(n_lines=40):
    """A multi-line Rust PoC harness source body that trips the source markers."""
    lines = [
        "#[test]",
        "fn poc_off_by_one_overdraw() {",
        "    let mut bank = Bank::new();",
        "    bank.deposit(attacker, 100);",
    ]
    while len(lines) < n_lines - 2:
        lines.append(f"    bank.step({len(lines)});")
    lines.append("    assert_eq!(bank.balance(victim), 0);")
    lines.append("}")
    return "\n".join(lines)


def _transcript_body(n_lines=40):
    """A long shell transcript body (cargo invocation + result) that must be allowed."""
    lines = ["$ cargo test poc_off_by_one_overdraw", "   Compiling poc v0.1.0", "running 1 test"]
    while len(lines) < n_lines - 2:
        lines.append(f"   step {len(lines)} ...")
    lines.append("test result: ok. 1 passed; 0 failed; exit 0")
    lines.append("Suite result: ok")
    return "\n".join(lines)


def _wrap_txt(title, vuln, validation, files_block):
    return (
        f"1. Title\n\n{title}\n\n"
        f"2. Vulnerability details\n\n{vuln}\n\n"
        f"3. Validation steps\n\n{validation}\n\n"
        f"4. Supporting files / PoC\n\n{files_block}\n"
    )


class _Tmp:
    """Temp per-finding folder with helpers to drop the .txt and -poc.zip."""

    def __init__(self):
        self.dir = tempfile.mkdtemp(prefix="hp_poc_test_")
        self.slug = "off-by-one-overdraw-MEDIUM"

    def write_txt(self, content, name=None):
        name = name or f"{self.slug}.hackenproof-plain.txt"
        path = os.path.join(self.dir, name)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        return path

    def write_zip(self, members, name=None):
        """members: dict {arcname: content} OR list[str] of arcnames."""
        name = name or f"{self.slug}-poc.zip"
        path = os.path.join(self.dir, name)
        with zipfile.ZipFile(path, "w") as zf:
            if isinstance(members, dict):
                for arc, data in members.items():
                    zf.writestr(arc, data)
            else:
                for arc in members:
                    zf.writestr(arc, "x")
        return path

    def write_plain(self, content, name="random.txt"):
        path = os.path.join(self.dir, name)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        return path


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestHackenproofPocNotInline(unittest.TestCase):

    # --- schema / N-A paths ------------------------------------------------

    def test_schema_present(self):
        self.assertEqual(SCHEMA, "auditooor.hackenproof_poc_not_inline_check.v1")
        self.assertEqual(SECTION_LIMIT, 10000)
        self.assertEqual(LARGE_FENCE_LINES, 25)

    def test_not_hackenproof_txt_is_na(self):
        t = _Tmp()
        p = t.write_plain("just some markdown\n", name="finding.md")
        r = check(p)
        self.assertEqual(r["verdict"], "pass-not-hackenproof")
        self.assertTrue(r["ok"])

    def test_missing_file_is_na_path(self):
        # A non-existent path that does not end in the suffix -> N/A.
        r = check("/no/such/file.md")
        self.assertEqual(r["verdict"], "pass-not-hackenproof")

    # --- pass: no inline source -------------------------------------------

    def test_pass_no_poc_source(self):
        t = _Tmp()
        txt = _wrap_txt(
            "Off-by-one overdraw leads to loss of funds",
            "The bank step loop overdraws the victim by one unit.",
            "Run the harness; the assertion confirms victim balance is drained.",
            "(attach PoC archive manually)",
        )
        p = t.write_txt(txt)
        r = check(p)
        self.assertEqual(r["verdict"], "pass-no-poc-source")
        self.assertTrue(r["ok"])

    def test_short_source_fence_allowed(self):
        # A small (<=25-line) source fence is NOT inlined-harness; allowed.
        small = "```rust\n#[test]\nfn t() { assert_eq!(1, 1); }\n```"
        t = _Tmp()
        txt = _wrap_txt("Bug leads to loss", "details", small, "(none)")
        p = t.write_txt(txt)
        r = check(p)
        self.assertEqual(r["verdict"], "pass-no-poc-source")

    def test_long_transcript_fence_allowed(self):
        # A long transcript fence (cargo + result) is evidence, not harness.
        fence = "```bash\n" + _transcript_body(40) + "\n```"
        t = _Tmp()
        txt = _wrap_txt("Bug leads to loss", "details", fence, "(none)")
        p = t.write_txt(txt)
        r = check(p)
        self.assertEqual(r["verdict"], "pass-no-poc-source")

    def test_long_unlabeled_transcript_allowed(self):
        # Unlabeled fence that is transcript-like (no source markers) -> allowed.
        fence = "```\n" + _transcript_body(40) + "\n```"
        t = _Tmp()
        txt = _wrap_txt("Bug leads to loss", "details", fence, "(none)")
        p = t.write_txt(txt)
        r = check(p)
        self.assertEqual(r["verdict"], "pass-no-poc-source")

    # --- fail: poc inlined -------------------------------------------------

    def test_fail_poc_inlined_rust(self):
        fence = "```rust\n" + _rust_harness_body(40) + "\n```"
        t = _Tmp()
        txt = _wrap_txt("Bug leads to loss", "details", fence, "(none)")
        p = t.write_txt(txt)
        r = check(p)
        self.assertEqual(r["verdict"], "fail-poc-inlined")
        self.assertFalse(r["ok"])
        self.assertTrue(r["inlined_fences"])
        self.assertGreater(r["inlined_fences"][0]["lines"], LARGE_FENCE_LINES)

    def test_fail_poc_inlined_solidity_unlabeled(self):
        # Unlabeled large fence with Solidity source markers -> inlined.
        body = "pragma solidity ^0.8.0;\ncontract Exploit {\n" + \
            "\n".join(f"    function step{i}() public {{}}" for i in range(30)) + \
            "\n    function attack() public { require(true); }\n}"
        fence = "```\n" + body + "\n```"
        t = _Tmp()
        txt = _wrap_txt("Bug leads to loss", "details", fence, "(none)")
        p = t.write_txt(txt)
        r = check(p)
        self.assertEqual(r["verdict"], "fail-poc-inlined")

    # --- fail: section over limit due to inlined code ----------------------

    def test_fail_section_over_limit(self):
        # A labeled non-source, non-transcript "big code" fence that pushes the
        # section over 10000 chars. No fn/assert/contract markers -> not "full
        # poc source" (so it dodges fail-poc-inlined), but it is big_code
        # (lang not in the transcript-lang set) -> fail-section-over-limit.
        big = "x = 1\n" * 4000  # ~24000 chars, no source markers, no transcript markers
        fence = "```python\n" + big + "```"
        t = _Tmp()
        txt = _wrap_txt("Bug leads to loss", "details", fence, "(none)")
        p = t.write_txt(txt)
        r = check(p)
        self.assertEqual(r["verdict"], "fail-section-over-limit")
        self.assertFalse(r["ok"])
        self.assertTrue(r["over_limit_sections"])

    # --- zip reference branches -------------------------------------------

    def test_pass_poc_in_zip(self):
        t = _Tmp()
        zip_name = f"{t.slug}-poc.zip"
        t.write_zip({"poc.rs": _rust_harness_body(40), "run.sh": "cargo test\n",
                     "poc-transcript.txt": _transcript_body(10)})
        validation = (
            "PoC test(s): poc_off_by_one_overdraw.\n"
            f"Full runnable harness + transcript: see attached {zip_name} "
            "(poc.rs, run.sh, poc-transcript.txt)."
        )
        txt = _wrap_txt("Bug leads to loss", "details", validation,
                        f"- {zip_name}")
        p = t.write_txt(txt)
        r = check(p)
        self.assertEqual(r["verdict"], "pass-poc-in-zip")
        self.assertTrue(r["ok"])
        self.assertEqual(r["zip"], zip_name)

    def test_fail_zip_missing_referenced_file(self):
        t = _Tmp()
        zip_name = f"{t.slug}-poc.zip"
        # Zip exists with run.sh but NOT the referenced poc.rs harness.
        t.write_zip({"run.sh": "cargo test\n"})
        validation = (
            f"Full runnable harness + transcript: see attached {zip_name} "
            "(poc.rs, run.sh)."
        )
        txt = _wrap_txt("Bug leads to loss", "details", validation,
                        f"- {zip_name}")
        p = t.write_txt(txt)
        r = check(p)
        self.assertEqual(r["verdict"], "fail-zip-missing-file")
        self.assertFalse(r["ok"])
        self.assertIn("poc.rs", r["missing"])

    def test_fail_zip_no_harness_inside(self):
        t = _Tmp()
        zip_name = f"{t.slug}-poc.zip"
        # Zip exists but contains only a README - no harness source, none
        # explicitly named in the .txt either.
        t.write_zip({"README.md": "see code"})
        validation = (
            f"Full runnable harness + transcript: see attached {zip_name}."
        )
        txt = _wrap_txt("Bug leads to loss", "details", validation,
                        f"- {zip_name}")
        p = t.write_txt(txt)
        r = check(p)
        self.assertEqual(r["verdict"], "fail-zip-missing-file")
        self.assertFalse(r["ok"])

    def test_fail_zip_referenced_but_absent(self):
        t = _Tmp()
        # .txt references a zip that does not exist beside it.
        validation = (
            "Full runnable harness + transcript: see attached "
            "missing-poc.zip (poc.rs)."
        )
        txt = _wrap_txt("Bug leads to loss", "details", validation,
                        "- missing-poc.zip")
        p = t.write_txt(txt)
        r = check(p)
        self.assertEqual(r["verdict"], "fail-zip-missing-file")
        self.assertFalse(r["ok"])
        self.assertIsNone(r["zip"])

    # --- folder resolution -------------------------------------------------

    def test_folder_resolution_pass(self):
        t = _Tmp()
        zip_name = f"{t.slug}-poc.zip"
        t.write_zip({"poc.rs": _rust_harness_body(40), "run.sh": "cargo test\n"})
        validation = (
            f"Full runnable harness + transcript: see attached {zip_name} "
            "(poc.rs, run.sh)."
        )
        txt = _wrap_txt("Bug leads to loss", "details", validation,
                        f"- {zip_name}")
        t.write_txt(txt)
        # Pass the FOLDER, not the .txt - the gate resolves <slug>.hackenproof-plain.txt
        r = check(t.dir)
        self.assertEqual(r["verdict"], "pass-poc-in-zip")

    # --- exit code mapping -------------------------------------------------

    def test_exit_code_mapping(self):
        self.assertEqual(_mod._exit_code("pass-poc-in-zip"), 0)
        self.assertEqual(_mod._exit_code("pass-no-poc-source"), 0)
        self.assertEqual(_mod._exit_code("pass-not-hackenproof"), 0)
        self.assertEqual(_mod._exit_code("fail-poc-inlined"), 1)
        self.assertEqual(_mod._exit_code("fail-section-over-limit"), 1)
        self.assertEqual(_mod._exit_code("fail-zip-missing-file"), 1)
        self.assertEqual(_mod._exit_code("error"), 2)


if __name__ == "__main__":
    unittest.main()
