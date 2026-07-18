"""Guard: D2 - bare attack-class query terms expand to canonical index keys.

(The load-bearing D2 win: vault_cross_language_pattern_lift("reentrancy"/"stale-oracle")
now reaches the canonical index keys instead of returning empty. The separate
vacuity-stub removal needs a class-level analogue fallback and is a tracked follow-up.)
"""
import importlib.util, sys, unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]
def _load(n,p):
    s=importlib.util.spec_from_file_location(n,p); m=importlib.util.module_from_spec(s); sys.modules[n]=m; s.loader.exec_module(m); return m
class TestD2(unittest.TestCase):
    def test_bare_terms_expand(self):
        m=_load('hqc', ROOT/'tools'/'hackerman_query_common.py')
        self.assertIn('reentrancy-classic', m.attack_class_query_terms('reentrancy'))
        self.assertIn('stale-or-manipulated-oracle', m.attack_class_query_terms('stale-oracle'))
        self.assertIn('stale-or-manipulated-oracle', m.attack_class_query_terms('oracle-manipulation'))
if __name__=='__main__':
    unittest.main()
