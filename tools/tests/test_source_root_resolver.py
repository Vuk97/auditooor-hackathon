import importlib.util, tempfile, unittest
from pathlib import Path

s = importlib.util.spec_from_file_location("srr", Path(__file__).resolve().parent.parent / "lib" / "source_root_resolver.py")
srr = importlib.util.module_from_spec(s); s.loader.exec_module(srr)


class TestResolver(unittest.TestCase):
    def test_cargo_workspace_picks_src_not_stub(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            # thin stub: ws/src/src/lib.rs (1 file)
            (ws / "src" / "src").mkdir(parents=True)
            (ws / "src" / "src" / "lib.rs").write_text("fn setup(){}")
            # real code: ws/src/crates/*/src/*.rs (3 files)
            for c in ("a", "b", "c"):
                (ws / "src" / "crates" / c / "src").mkdir(parents=True)
                (ws / "src" / "crates" / c / "src" / "lib.rs").write_text("pub fn f(){}")
            roots = srr.resolve_src_roots(ws)
            self.assertEqual(roots, [ws / "src"], f"expected ws/src, got {roots}")

    def test_solidity_nesting_keeps_src_src(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            (ws / "src" / "src").mkdir(parents=True)
            # all source under src/src (genuine Solidity nesting)
            (ws / "src" / "src" / "A.sol").write_text("contract A{}")
            (ws / "src" / "src" / "B.sol").write_text("contract B{}")
            roots = srr.resolve_src_roots(ws)
            self.assertEqual(roots, [ws / "src" / "src"], f"got {roots}")

    def test_sibling_source_dirs_fall_back_to_ws(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            (ws / "external").mkdir()
            (ws / "external" / "a.rs").write_text("fn a(){}")
            (ws / "contracts").mkdir()
            (ws / "contracts" / "b.sol").write_text("contract B{}")
            roots = srr.resolve_src_roots(ws)
            self.assertEqual(roots, [ws], f"got {roots}")

    def test_excludes_tests_and_target(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            (ws / "src").mkdir()
            (ws / "src" / "real.rs").write_text("fn r(){}")
            (ws / "src" / "foo_test.rs").write_text("fn t(){}")
            (ws / "target" / "x").mkdir(parents=True)
            (ws / "target" / "x" / "gen.rs").write_text("fn g(){}")
            self.assertEqual(srr.count_sources(ws / "src"), 1)


if __name__ == "__main__":
    unittest.main()
