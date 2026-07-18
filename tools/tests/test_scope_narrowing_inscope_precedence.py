#!/usr/bin/env python3
"""Regression: a scope-NARROWING clause ("the only thing IN SCOPE is X"), even
when phrased inside the program's verbatim OUT-OF-SCOPE block, must NOT turn the
named in-scope path X into an OOS exclude glob.

Axelar-DLT field run 2026-07-12: SCOPE.md / OOS_CHECKLIST carried the Immunefi
clause "in the tofn repository, the only thing in scope is src/ecdsa/mod.rs".
The exclude harvesters grabbed `src/ecdsa/mod.rs` as an OOS glob; because the
cloned workspace path `src/tofn/src/ecdsa/mod.rs` ends with that token, the ONE
explicitly in-scope file (7 ecdsa keygen/sign/verify fns) was silently EXCLUDED
from inscope_units.jsonl while sibling ed25519 stayed. resolve_scope now applies
in-scope PRECEDENCE: an exclude glob that equals, or is a path-suffix of, an
explicitly in-scope glob is dropped.
"""
import importlib.util
import tempfile
import unittest
from pathlib import Path

_MOD = Path(__file__).resolve().parent.parent / "workspace-coverage-heatmap.py"
_spec = importlib.util.spec_from_file_location("wch", _MOD)
h = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(h)


class TestInScopePrecedence(unittest.TestCase):
    def _ws(self) -> Path:
        ws = Path(tempfile.mkdtemp())
        (ws / "src" / "tofn" / "src" / "ecdsa").mkdir(parents=True)
        (ws / "src" / "tofn" / "src" / "ecdsa" / "mod.rs").write_text(
            "pub fn keygen() {}\npub fn sign() {}\npub fn verify() {}\n")
        (ws / "targets.tsv").write_text(
            "# repo_url\tpin\tlocal_name\n"
            "https://github.com/x/tofn\t" + "a" * 40 + "\ttofn\n")
        # SCOPE.md: in-scope path enumerated AND the same path named in an OOS
        # narrowing bullet - the exact shape that regressed.
        (ws / "SCOPE.md").write_text(
            "# Scope\n\n"
            "## In-scope paths\n"
            "- src/tofn/src/ecdsa/mod.rs\n\n"
            "## Out-of-scope\n"
            "- In the tofn repository, the only thing in scope is "
            "src/ecdsa/mod.rs and its project dependencies.\n")
        return ws

    def test_resolve_scope_does_not_exclude_explicitly_inscope_path(self):
        ws = self._ws()
        scope = h.resolve_scope(ws)
        excludes = scope.get("scope_exclude_globs", []) or []
        # No exclude glob may be a path-suffix of the in-scope ecdsa file.
        target = "src/tofn/src/ecdsa/mod.rs"
        for e in excludes:
            self.assertFalse(
                target.endswith(e.strip("/")) or e.strip("/") == "src/ecdsa/mod.rs",
                f"exclude glob {e!r} would drop the explicitly in-scope {target!r}; "
                f"excludes={excludes}")

    def test_parse_scope_globs_reconciles_inscope_over_exclude(self):
        ws = self._ws()
        inc, exc = h._parse_scope_globs(ws)
        # the in-scope side names ecdsa; the exclude side must not carry a token
        # that is a path-suffix of it.
        for e in exc:
            self.assertFalse(
                any(g.strip("/") == e.strip("/")
                    or g.strip("/").endswith("/" + e.strip("/")) for g in inc),
                f"exclude {e!r} is a suffix of an in-scope glob; should be dropped")


if __name__ == "__main__":
    unittest.main()
