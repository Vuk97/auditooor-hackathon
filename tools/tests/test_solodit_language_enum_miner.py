"""Tests for tools/solodit-language-enum-miner.py.

Fixtures are local strings only; no network calls.
"""
from __future__ import annotations

import importlib.util
import json
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "_solodit_language_enum_miner",
        str(REPO_ROOT / "tools" / "solodit-language-enum-miner.py"),
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


SLM = _load_module()


class TestSoloditLanguageEnumMiner(unittest.TestCase):
    def test_devalue_serializer_matches_public_trpc_shape_for_plain_objects(self):
        payload = {"filters": {"impact": ["HIGH"], "read": True}, "page": 2}
        encoded = SLM.devalue_serialize(payload)
        self.assertEqual(
            encoded,
            '[{"filters":1,"page":5},{"impact":2,"read":4},[3],"HIGH",true,2]',
        )
        url = SLM.trpc_query_url("findings.get", payload)
        self.assertIn("/api/trpc/findings.get?input=", url)
        self.assertIn("%22%5B", url)

    def test_parse_issue_languages(self):
        data = '{languages:["Cairo","Noir","Python","Solidity","TypeScript","Yul"]}'
        self.assertEqual(
            SLM.parse_issue_languages(data),
            ["Cairo", "Noir", "Python", "Solidity", "TypeScript", "Yul"],
        )

    def test_parse_findings_stats_uses_last_count_not_finders_count(self):
        data = (
            '{findings:[{id:10n,finders_count:1,title:"A",slug:"a"},'
            '{id:9n,finders_count:4,title:"B",slug:"b"}],count:200,pages:20}'
        )
        stats = SLM.parse_findings_page_stats(data)
        self.assertEqual(stats["finding_count"], 2)
        self.assertEqual(stats["first_id"], "10")
        self.assertEqual(stats["last_id"], "9")
        self.assertEqual(stats["total_count"], 200)
        self.assertEqual(stats["total_pages"], 20)

    def test_scan_findings_data_extracts_target_hit_context(self):
        data = (
            '{findings:[{id:77n,title:"Huff parser accepts invalid opcode",'
            'content:"The Huff bytecode path skips validation.",'
            'slug:"huff-parser-accepts-invalid-opcode"},'
            '{id:76n,title:"Generic Cairo issue",content:"Cairo code but no zk marker",'
            'slug:"generic-cairo"}],count:2,pages:1}'
        )
        scan = SLM.scan_findings_data(data, page=3)
        self.assertEqual(len(scan["target_hits"]["huff"]), 3)
        first = scan["target_hits"]["huff"][0]
        self.assertEqual(first["finding_id"], "77")
        self.assertEqual(first["source_url"], "https://solodit.cyfrin.io/issues/huff-parser-accepts-invalid-opcode")
        self.assertEqual(scan["generic_cairo_mentions"], 3)
        self.assertEqual(len(scan["target_hits"]["cairo-zk"]), 0)

    def test_trpc_data_string_rejects_error_payloads(self):
        with self.assertRaises(SLM.SoloditMinerError):
            SLM.trpc_data_string({"error": "boom"})
        self.assertEqual(SLM.trpc_data_string({"result": {"data": "{ok:true}"}}), "{ok:true}")


if __name__ == "__main__":
    unittest.main()
