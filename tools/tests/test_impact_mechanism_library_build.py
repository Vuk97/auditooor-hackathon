import importlib.util
from pathlib import Path
_M = Path(__file__).resolve().parents[1] / "impact-mechanism-library-build.py"
_s = importlib.util.spec_from_file_location("imlb", _M)
imlb = importlib.util.module_from_spec(_s); _s.loader.exec_module(imlb)

def test_etl_inverts_playbooks_to_impact_mechanisms():
    lib = imlb.build()
    assert lib, "ETL must invert the corpus playbooks"
    assert "chain-halt-shutdown" in lib, "the chain-halt impact family must be present"
    # every entry has the required shape + at least one detector-wired cell overall
    wired = [m for v in lib.values() for m in v if m.get("detector")]
    assert wired, "at least the consensus-hook/authority mechanisms wire to a real detector"
    for v in lib.values():
        for m in v:
            assert set(("mechanism", "languages", "detector", "source")) <= set(m)
            assert isinstance(m["languages"], list) and m["languages"]

def test_deterministic():
    assert imlb.build() == imlb.build()
