#!/usr/bin/env python3
"""question-target-fit.py - empirical per-(question, target_language) fit ledger.

The language-aware question selection RANKS by inferred language, but EVM/DeFi
questions that use generic words (oracle, profit-extraction, handler-contract,
ERC-4626) are inferred as "agnostic" and still get selected - then waste the
hunt budget returning "this does not apply to a Rust node" (zebra: 79%
question-inapplicable; monero-oxide: 57%). Language INFERENCE cannot catch them;
empirical OBSERVATION can.

This tool walks every hunt sidecar across all workspaces, and for each verdict
computes (via hunt-failure-breakdown.categorize) whether it was
question-inapplicable. It aggregates per (source_question_id, target_language)
and emits audit/corpus_tags/derived/question_target_fit.jsonl - one row per
(question, language) with inapplicable_rate + an exclude flag. The hunt then
HARD-EXCLUDES exclude=true questions for that target language, so a Rust/crypto
target stops getting blasted with EVM questions - automatically, and it self-
corrects as more hunts run.
"""
from __future__ import annotations

import argparse
import functools
import importlib.util
import json
import sys
from collections import defaultdict
from pathlib import Path

SCHEMA = "auditooor.question_target_fit.v1"
_REPO = Path(__file__).resolve().parent.parent
_DERIVED = _REPO / "audit" / "corpus_tags" / "derived"
_OUT = _DERIVED / "question_target_fit.jsonl"

_SIDECAR_DIR_GLOBS = ("haiku_harness_*", "mimo_harness_*", "mega_perfn_*",
                      "mega_*", "mimo_hunt_*", "mimo_reeval*")


def _all_sidecar_dirs(derived):
    """Every derived dir that holds hunt sidecars (mimo_harness_*.json), across
    the haiku/mimo/mega harness formats. Format-agnostic so dydx (Go, hunted into
    mimo_harness_dydx_full + mega_perfn_dydx) is picked up, not just haiku dirs."""
    seen = {}
    if not derived.is_dir():
        return []
    for pat in _SIDECAR_DIR_GLOBS:
        for d in derived.glob(pat):
            if d.is_dir() and (str(d) not in seen):
                seen[str(d)] = d
    # also any dir that directly contains a mimo_harness_*.json (catch-all)
    try:
        for d in derived.iterdir():
            if d.is_dir() and str(d) not in seen and any(d.glob("mimo_harness_*.json")):
                seen[str(d)] = d
    except OSError:
        pass
    return list(seen.values())


# Workspace -> target language. Falls back to source-tree detection.
# "dydx" pins to go: its audited target is the Go cosmos v4-chain (go.mod present
# under external/v4-chain/protocol), but the tree ALSO carries incidental non-Go
# files - a Rust client SDK (external/v4-chain/v4-proto-rs/Cargo.toml, repos/...)
# and a Solidity fuzz harness we wrote (economic_fuzz/EconomicInvariantFuzz.t.sol).
# Without the pin, language detection would see a multi-language set and skip dydx.
_WS_LANG = {"zebra": "rust", "monero-oxide": "rust", "monero": "rust",
            "morpho-midnight": "solidity", "morpho": "solidity", "near": "rust",
            "dydx": "go"}
_AUDITS = Path.home() / "audits"

# Directories whose contents are INCIDENTAL to the audited target and must not
# count toward language attribution: vendored/external code, sibling client repos,
# our own PoC harnesses, fuzz harnesses, and dependency/build trees. Matched as a
# path component anywhere under the workspace root.
_INCIDENTAL_DIRS = ("external", "repos", "poc-tests", "economic_fuzz",
                    "node_modules", "target", "vendor", "deps")

_EXCLUDE_RATE = 0.6
_MIN_EVALS = 2


def _is_incidental(path, root) -> bool:
    """True if `path` lives under any incidental dir component relative to root."""
    try:
        parts = path.relative_to(root).parts
    except ValueError:
        parts = path.parts
    return any(seg in _INCIDENTAL_DIRS for seg in parts)


# Source-file extensions per language, for the dominant-language file count.
_LANG_EXTS = {"rust": (".rs",), "solidity": (".sol",), "go": (".go",),
              "cadence": (".cdc",), "move": (".move",)}


@functools.lru_cache(maxsize=None)
def _dominant_language(ws_name: str) -> str:
    """The single language with the MOST in-scope source files, counting only
    files OUTSIDE the incidental dirs. Generic tie-broken-by-count fallback used
    when there is neither an explicit _WS_LANG pin nor a clean single-language
    set. Returns "" if no in-scope source files are found."""
    ws = _AUDITS / ws_name
    root = ws / "src" if (ws / "src").is_dir() else ws
    if not root.is_dir():
        return ""
    counts: dict[str, int] = defaultdict(int)
    for lang, exts in _LANG_EXTS.items():
        for ext in exts:
            try:
                for p in root.rglob(f"*{ext}"):
                    if _is_incidental(p, root):
                        continue
                    counts[lang] += 1
            except OSError:
                pass
    if not counts:
        return ""
    return max(counts.items(), key=lambda kv: (kv[1], kv[0]))[0]


def _load_categorize():
    p = _REPO / "tools" / "hunt-failure-breakdown.py"
    spec = importlib.util.spec_from_file_location("hfb_fit", p)
    m = importlib.util.module_from_spec(spec)
    sys.modules["hfb_fit"] = m
    spec.loader.exec_module(m)
    return m.categorize




@functools.lru_cache(maxsize=None)
def _ws_languages_cached(ws_name: str) -> frozenset:
    """Cached, immutable backing for ws_languages (one rglob scan per workspace
    per process; the per-sidecar attribution loop calls this thousands of times)."""
    return frozenset(_ws_languages_uncached(ws_name))


def ws_languages(ws_name: str) -> set:
    """ALL languages present in a workspace (rust/solidity/go/cadence/move).
    A mixed target (e.g. Flow = go + cadence + solidity) returns the full set;
    a question is dead for the target only if it is dead for EVERY language in
    the set, so e.g. Solidity questions are not dropped on a mostly-Go repo.
    Incidental dirs are excluded (see _INCIDENTAL_DIRS)."""
    return set(_ws_languages_cached(ws_name))


def _ws_languages_uncached(ws_name: str) -> set:
    ws = _AUDITS / ws_name
    root = ws / "src" if (ws / "src").is_dir() else ws
    langs = set()
    if root.is_dir():
        try:
            # Each language marker is counted only if at least one matching file
            # lives OUTSIDE the incidental dirs (external/, repos/, poc-tests/,
            # economic_fuzz/, node_modules/, target/, vendor/, deps/). This keeps
            # a genuinely multi-language target's full set (Flow = go+cadence+
            # solidity, all in-scope) while dropping incidental-only languages
            # (dydx's Rust client SDK + Solidity fuzz harness live under excluded
            # dirs, so dydx's set collapses to the audited Go).
            if any(not _is_incidental(p, root) for p in root.rglob("Cargo.toml")):
                langs.add("rust")
            if any(not _is_incidental(p, root) for p in root.rglob("*.sol")):
                langs.add("solidity")
            if any(not _is_incidental(p, root) for p in root.rglob("go.mod")):
                langs.add("go")
            if any(not _is_incidental(p, root) for p in root.rglob("*.cdc")):
                langs.add("cadence")
            if any(not _is_incidental(p, root) for p in root.rglob("*.move")):
                langs.add("move")
        except OSError:
            pass
    if not langs and ws_name in _WS_LANG:
        langs.add(_WS_LANG[ws_name])
    return langs

def _ws_language(ws_name: str) -> str:
    if ws_name in _WS_LANG:
        return _WS_LANG[ws_name]
    ws = _AUDITS / ws_name
    if (ws / "src").is_dir() or ws.is_dir():
        root = ws / "src" if (ws / "src").is_dir() else ws
        try:
            if any(root.rglob("Cargo.toml")):
                return "rust"
            if any(p for p in root.rglob("*.sol") if "/node_modules/" not in str(p)):
                return "solidity"
            if any(root.rglob("go.mod")):
                return "go"
        except OSError:
            pass
    return "unknown"


def build() -> dict:
    categorize = _load_categorize()
    # (qid, lang) -> counts
    agg: dict[tuple, dict] = defaultdict(lambda: {"total": 0, "inapplicable": 0,
                                                  "yes": 0, "maybe": 0})
    if not _DERIVED.is_dir():
        return {"rows": 0, "out": str(_OUT)}
    for d in _all_sidecar_dirs(_DERIVED):
        for f in d.glob("mimo_harness_*.json"):
            try:
                rec = json.loads(f.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            rec = rec if isinstance(rec, dict) else (rec[0] if isinstance(rec, list) and rec else {})
            qid = str(rec.get("source_question_id") or "").strip()
            ws_name = str(rec.get("workspace") or "").strip()
            if not qid or not ws_name:
                continue
            # Attribute the verdict to the audited language:
            #   1. explicit _WS_LANG pin (the audited language) wins;
            #   2. else if exclusion-aware ws_languages() is exactly one, use it;
            #   3. else the DOMINANT in-scope language by file count;
            #   4. else skip (cannot attribute to one language).
            if ws_name in _WS_LANG:
                lang = _WS_LANG[ws_name]
            else:
                _langs = ws_languages(ws_name)
                if len(_langs) == 1:
                    lang = next(iter(_langs))
                else:
                    lang = _dominant_language(ws_name)
            if not lang:
                continue
            res = rec.get("result")
            if isinstance(res, str):
                try:
                    res = json.loads(res)
                except (ValueError, TypeError):
                    res = {}
            if not isinstance(res, dict):
                continue
            cat = categorize(res)
            a = agg[(qid, lang)]
            a["total"] += 1
            if cat == "question-inapplicable":
                a["inapplicable"] += 1
            elif cat == "candidate-yes":
                a["yes"] += 1
            elif cat == "candidate-maybe":
                a["maybe"] += 1

    rows = []
    for (qid, lang), a in agg.items():
        tot = a["total"]
        rate = a["inapplicable"] / tot if tot else 0.0
        rows.append({
            "schema": SCHEMA, "question_id": qid, "target_language": lang,
            "total_evals": tot, "inapplicable_count": a["inapplicable"],
            "inapplicable_rate": round(rate, 4),
            "yes": a["yes"], "maybe": a["maybe"],
            # a question with NO yes/maybe signal AND high inapplicability is dead weight
            "exclude": (rate >= _EXCLUDE_RATE and tot >= _MIN_EVALS
                        and a["yes"] == 0 and a["maybe"] == 0),
        })
    _OUT.parent.mkdir(parents=True, exist_ok=True)
    with _OUT.open("w", encoding="utf-8") as fh:
        for r in sorted(rows, key=lambda r: (-r["inapplicable_rate"], r["question_id"])):
            fh.write(json.dumps(r) + "\n")
    excl = sum(1 for r in rows if r["exclude"])
    by_lang = defaultdict(lambda: [0, 0])
    for r in rows:
        by_lang[r["target_language"]][0] += 1
        if r["exclude"]:
            by_lang[r["target_language"]][1] += 1
    return {"rows": len(rows), "excluded": excl, "out": str(_OUT),
            "by_language": {k: {"questions": v[0], "excluded": v[1]} for k, v in by_lang.items()}}


def load_exclusions(target_language: str) -> set:
    """Set of question_ids to HARD-EXCLUDE for this target language."""
    if not _OUT.is_file() or not target_language:
        return set()
    out = set()
    for ln in _OUT.read_text(encoding="utf-8", errors="ignore").splitlines():
        if not ln.strip():
            continue
        try:
            r = json.loads(ln)
        except ValueError:
            continue
        if r.get("exclude") and str(r.get("target_language")) == target_language:
            out.add(str(r.get("question_id")))
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Empirical question-target-fit ledger.")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    rep = build()
    print(f"[question-target-fit] {rep['rows']} (question,language) rows; "
          f"{rep.get('excluded', 0)} EXCLUDE -> {rep['out']}")
    for lang, v in (rep.get("by_language") or {}).items():
        print(f"    {lang:<10} {v['excluded']}/{v['questions']} excluded")
    if a.json:
        print(json.dumps(rep, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
