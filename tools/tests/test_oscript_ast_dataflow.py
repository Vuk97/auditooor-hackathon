import importlib.util
import json
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("oscript_ast", REPO / "tools" / "oscript-ast-dataflow.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def test_extracts_only_ocore_ast_trigger_payload(monkeypatch, tmp_path):
    source = tmp_path / "aa.oscript"
    source.write_text("ignored", encoding="utf-8")
    root = tmp_path / "ocore"
    (root / "formula").mkdir(parents=True)
    (root / "formula" / "parse_ojson.js").write_text("", encoding="utf-8")
    (root / "node_modules").mkdir()
    monkeypatch.setattr(mod.shutil, "which", lambda _: "node")
    monkeypatch.setattr(mod, "run_parser", lambda *_: {"messages": [
        {"app": "payment", "guard_ast": ["trigger.data"], "payload_ast": {"amount": {"formula_ast": ["trigger.output"]}}},
        {"app": "state", "guard_ast": None, "payload_ast": {"x": {"formula_ast": ["state.var"]}}},
    ]})
    rows, report = mod.extract(tmp_path, root)
    assert report["parsed"] == 1
    assert len(rows) == 1
    assert rows[0]["engine"] == "ocore-nearley-ast"
    assert rows[0]["sink"]["callee"] == "payment"
    assert rows[0]["unguarded"] is False


def test_main_merges_only_oscript_rows_into_shared_sidecar(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(mod, "extract", lambda *_: ([
        mod.dfs.new_path(
            path_id="oscript-path", language="oscript", direction="forward",
            engine="ocore-nearley-ast",
            source={"kind": "trigger", "fn": "entry", "var": "data", "file": "aa.oscript", "line": 1},
            sink={"kind": "message", "callee": "payment", "arg_pos": None, "fn": "entry", "file": "aa.oscript", "line": 2},
            hops=[], guard_nodes=[], source_unit_ids=["aa.oscript"], sink_unit_ids=["aa.oscript"],
            confidence="syntactic",
        )], {"backend": "ocore-nearley-ast", "files": 1, "parsed": 1, "errors": []}))
    sidecar = tmp_path / ".auditooor" / "dataflow_paths.jsonl"
    sidecar.parent.mkdir()
    sidecar.write_text(json.dumps({"language": "go", "keep": True}) + "\n", encoding="utf-8")

    assert mod.main(["--workspace", str(tmp_path), "--json"]) == 0

    result = json.loads(capsys.readouterr().out)
    records = [json.loads(line) for line in sidecar.read_text().splitlines()]
    assert result["backend"] == "ocore-nearley-ast"
    assert result["records_written"] == 1
    assert {record["language"] for record in records} == {"go", "oscript"}
