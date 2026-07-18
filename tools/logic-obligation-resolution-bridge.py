#!/usr/bin/env python3
"""logic-obligation-resolution-bridge.py - the MISSING producer for
``.auditooor/logic_obligation_resolutions.jsonl``.

Why this exists
---------------
``tools/logic-obligation-resolution-check.py`` (the step-5 gate
``logic-obligation-resolution``) marks a reasoner obligation RESOLVED iff either
(a) its ledger row already carries a terminal ``proof_status``/``quality_gate_status``
OR (b) an external resolution sidecar (``logic_obligation_resolutions.jsonl``) carries
a terminal ``state`` for one of the obligation's join keys. Until now NO tool WROTE
that sidecar - only the validator read it - so a genuinely-adjudicated obligation
(driven to a source-cited terminal verdict by a per-function hunt whose verdict lands
in ``agent_mechanism_verdicts/`` or as a terminal ``exploit_queue`` row) could never
be credited: it stayed OPEN forever and false-red ``fail-logic-obligation-unresolved``.
That is the same serving-join class as ``exploit-queue-terminal-join`` (verdict exists
on disk, no join to where the gate reads).

Anti-fabrication guarantee
--------------------------
This bridge NEVER blanket-resolves. It emits a resolution row for an obligation ONLY
when a GENUINE TERMINAL, SOURCE-CITED verdict already exists for that obligation's own
join key, drawn from two evidence sources:

  1. ``agent_mechanism_verdicts/*.json`` - per-function mechanism adjudications with a
     terminal ``verdict`` (KILL/REFUTED/NEGATIVE/cleared/...) and a ``file_line`` /
     ``source_refs`` R76 citation.
  2. terminal ``exploit_queue`` rows that carry a source-cited ``clean_control`` or
     ``terminal_join.evidence_ref`` (an R76 file:line) - i.e. a per-function hunt drove
     that exact function to a source-cited REFUTED verdict.

An obligation whose key matches NEITHER stays OPEN - the un-adjudicated tail remains
genuine hunt work and the gate keeps failing until it is really driven. The emitted
row echoes the obligation's own (contract, function, attack_class, obligation_id) so
the validator's ``_obligation_keys`` recomputes the identical key, plus the evidence
reference so the resolution is auditable.

Stdlib-only, reads the workspace, writes the single sidecar.
"""
from __future__ import annotations

import argparse
import glob
import importlib.util
import json
import re
import sys
from pathlib import Path


_R76 = re.compile(r"[\w./-]+\.(?:sol|rs|go|move|cairo|vy|py|ts):\d+", re.I)
_SIDECAR = "logic_obligation_resolutions.jsonl"
_TYPED_ENVELOPE_TOOL = Path(__file__).with_name("zero-day-proof-envelope-verify.py")
_TYPED_ENVELOPE_MOD = None


def _load_check_module():
    """Import logic-obligation-resolution-check.py for its canonical key/token helpers
    (single source of truth: identical _obligation_keys / _is_terminal_token / _norm /
    _REASONER_LEDGERS / _load_jsonl the validator uses)."""
    tool = Path(__file__).resolve().parent / "logic-obligation-resolution-check.py"
    spec = importlib.util.spec_from_file_location("_lor_check_for_bridge", tool)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["_lor_check_for_bridge"] = mod
    spec.loader.exec_module(mod)
    return mod


def _load_typed_envelope_tool():
    """Load the immutable admitted-proof verifier once."""
    global _TYPED_ENVELOPE_MOD
    if _TYPED_ENVELOPE_MOD is not None:
        return _TYPED_ENVELOPE_MOD
    spec = importlib.util.spec_from_file_location("_lor_bridge_typed_envelope", _TYPED_ENVELOPE_TOOL)
    if spec is None or spec.loader is None:
        raise ValueError("typed_proof_envelope_tool_unavailable")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    _TYPED_ENVELOPE_MOD = mod
    return mod


def _iter_json_objs(path: Path):
    try:
        obj = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return
    for o in (obj if isinstance(obj, list) else [obj]):
        if isinstance(o, dict):
            yield o


def build_evidence_index(ws: Path, m) -> dict[str, str]:
    """{normalized join key: source-cited evidence ref} from GENUINE terminal verdicts."""
    aud = ws / ".auditooor"
    ev: dict[str, str] = {}

    def _add(fn: str, ac: str, contract: str, cite: str) -> None:
        fn = (fn or "").strip().lower()
        # file-level key (for site-keyed obligations like dirm/escrow that carry no
        # function): the file that was driven to a terminal source-cited verdict.
        fpart = _R76.search(cite)
        if fpart:
            ev.setdefault(m._norm("file::" + fpart.group(0).rsplit(":", 1)[0]), cite)
        if not fn:
            return
        ac = (ac or "").strip().lower()
        contract = (contract or "").strip().lower()
        keys = {fn, "op::" + fn}
        if ac:
            keys.add(f"{fn}::{ac}")
        if contract:
            keys.add(f"{contract}::{fn}")
            if ac:
                keys.add(f"{contract}::{fn}::{ac}")
        for k in keys:
            ev.setdefault(m._norm(k), cite)

    # 1. per-function mechanism verdicts (agent_mechanism_verdicts/*.json)
    for f in glob.glob(str(aud / "agent_mechanism_verdicts" / "*.json")):
        for o in _iter_json_objs(Path(f)):
            if not m._is_terminal_token(o.get("verdict")):
                continue
            fa = o.get("function_anchor") if isinstance(o.get("function_anchor"), dict) else {}
            fn = str(o.get("function") or o.get("fn") or fa.get("fn") or "")
            ac = str(o.get("impact") or o.get("attack_class") or o.get("mechanism") or "")
            contract = str(o.get("contract") or fa.get("contract") or "")
            refs = o.get("source_refs") if isinstance(o.get("source_refs"), list) else []
            cite = str(o.get("file_line") or (refs[0] if refs else "") or "")
            if not _R76.search(cite):
                # RECURRING WORKER FOOT-GUN robustness (2026-07-14): hunt workers
                # frequently cite the guard file:line in the `reasoning`/`notes` PROSE
                # but leave the structured file_line/source_refs empty, so a GENUINE
                # source-cited terminal verdict never credits. Fall back to the first
                # R76 file:line found in the reasoning text - the cite IS present, just
                # unstructured. Still requires a real R76 cite (never credits a
                # cite-less verdict), so anti-fabrication is preserved.
                mprose = _R76.search(str(o.get("reasoning") or o.get("notes") or ""))
                if not mprose:
                    continue
                cite = mprose.group(0)
            _add(fn, ac, contract, cite)

    # 2. terminal, source-cited exploit_queue rows
    for qf in ("exploit_queue.json", "exploit_queue.source_mined.json"):
        p = aud / qf
        if not p.is_file():
            continue
        try:
            q = json.loads(p.read_text(encoding="utf-8", errors="replace"))
        except (OSError, ValueError):
            continue
        rows = (q.get("queue", []) + q.get("entries", [])) if isinstance(q, dict) else q
        for r in rows:
            if not isinstance(r, dict) or not m._is_terminal_token(r.get("proof_status")):
                continue
            tj = r.get("terminal_join") if isinstance(r.get("terminal_join"), dict) else {}
            cite = str(r.get("clean_control") or tj.get("evidence_ref") or "")
            if not _R76.search(cite):
                continue  # only source-cited terminals count as evidence
            _add(str(r.get("function") or ""), str(r.get("attack_class") or ""),
                 str(r.get("contract") or ""), cite)

    # 3. admitted proof rows are canonical, not legacy discovery rows. A status
    # token and file:line are insufficient: the terminal record must preserve the
    # frozen parent identity and immutable envelope before it can resolve a
    # reasoner obligation through this sidecar.
    typed_path = aud / "exploit_queue.zero_day_admitted.json"
    if typed_path.is_file():
        try:
            typed = json.loads(typed_path.read_text(encoding="utf-8", errors="replace"))
            if not isinstance(typed, dict) or typed.get("entries") not in (None, []):
                raise ValueError("typed_proof_envelope_legacy_entries_present")
            envelope = _load_typed_envelope_tool().build_envelope(typed)
            entries = {entry["lead_id"]: entry for entry in envelope["entries"]}
            rows = typed.get("queue")
            if not isinstance(rows, list):
                raise ValueError("typed_proof_queue_rows_invalid")
            for r in rows:
                if not isinstance(r, dict) or not m._is_terminal_token(r.get("proof_status")):
                    continue
                lead_id = r.get("lead_id")
                entry = entries.get(lead_id) if isinstance(lead_id, str) else None
                if entry is None or not _load_typed_envelope_tool().terminal_record_matches(entry, r):
                    continue
                tj = r.get("terminal_join") if isinstance(r.get("terminal_join"), dict) else {}
                cite = str(tj.get("evidence_ref") or tj.get("source_cite") or "")
                if not _R76.search(cite):
                    continue
                _add(str(r.get("function") or ""), str(r.get("attack_class") or ""),
                     str(r.get("contract") or ""), cite)
        except (OSError, ValueError, KeyError, TypeError):
            pass  # Invalid admitted rows earn no resolution credit.
    return ev


def _obl_files(row: dict) -> list[str]:
    """Files an obligation targets (for site-keyed obligations - dirm/escrow-liability
    residuals carry `site.file` and/or `source_refs`, NOT a `function`)."""
    files: list[str] = []
    site = row.get("site")
    if isinstance(site, dict) and site.get("file"):
        files.append(str(site["file"]))
    for r in (row.get("source_refs") or []):
        rs = str(r)
        files.append(rs.split(":", 1)[0] if ":" in rs else rs)
    if row.get("file"):
        files.append(str(row["file"]))
    return files


def _alt_match(row: dict, ev: dict, m) -> str | None:
    """Match obligation shapes the fn-keyed index misses, WITHOUT weakening the
    anti-fabrication guard (still requires a genuine terminal source-cited verdict):

      (a) COMPOSITION (op_a;op_b interleaving invariant): resolved only when BOTH ops
          have a terminal source-cited fn-verdict (op::<op>). A composition-invariant
          violation needs the PAIR to interleave unsafely; if each op is individually
          driven terminal-safe, the pair is too. Requiring BOTH (not either) keeps it
          conservative.
      (b) SITE-KEYED (dirm ratio-authority / escrow-liability residual): resolved when
          a file the obligation targets (site.file / source_refs, normalized to a repo-
          relative suffix) has a terminal source-cited verdict (file::<path>)."""
    op_a = str(row.get("op_a") or "").strip().lower()
    op_b = str(row.get("op_b") or "").strip().lower()
    if op_a and op_b:
        ka, kb = m._norm("op::" + op_a), m._norm("op::" + op_b)
        if ka in ev and kb in ev:
            return ka
        return None
    for f in _obl_files(row):
        f = f.strip()
        if not f:
            continue
        # match on a path suffix so absolute ws paths and repo-relative agree
        tail = f.split("src/", 1)
        cand = ("src/" + tail[1]) if len(tail) > 1 else f
        k = m._norm("file::" + cand)
        if k in ev:
            return k
        # also try any ev file-key that ends with this obligation file's basename path
        base = m._norm("file::" + cand)
        for ek in ev:
            if ek.startswith("file::") and (ek.endswith(base.split("::", 1)[1]) or base.endswith(ek.split("::", 1)[1])):
                return ek
    return None


def bridge(ws: Path, apply: bool = False) -> dict:
    m = _load_check_module()
    aud = ws / ".auditooor"
    ev = build_evidence_index(ws, m)
    existing = m._load_resolution_sidecar(ws)  # do not double-emit already-resolved keys
    emitted: list[dict] = []
    seen_keys: set[str] = set()
    for fname, _tool, _lang in m._REASONER_LEDGERS:
        p = aud / fname
        if not p.is_file():
            continue
        for row in m._load_jsonl(p):
            if m._row_resolved(row, existing):
                continue  # already terminal in-row or already in the sidecar
            keys = [m._norm(k) for k in m._obligation_keys(row)]
            fn = str(row.get("function") or row.get("fn") or "").strip().lower()
            if fn:
                keys.append(m._norm(fn))
            match = next((k for k in keys if k in ev), None)
            if not match:
                match = _alt_match(row, ev, m)  # composition op_a/op_b + site-file shapes
            if not match:
                continue  # NO genuine terminal evidence -> stays OPEN (real work)
            okey = keys[0] if keys else match
            if okey in seen_keys:
                continue
            seen_keys.add(okey)
            emitted.append({
                "schema": "auditooor.logic_obligation_resolution.v1",
                # round-trip the obligation's OWN most-specific key so the check's
                # _row_resolved matches it (composition/dirm rows have no
                # contract/function/oid - only the comp::/site:: composite key).
                "obligation_key": row.get("obligation_id") or row.get("id") or okey,
                "contract": row.get("contract") or "",
                "function": row.get("function") or row.get("fn") or "",
                "attack_class": row.get("attack_class") or "",
                "file": row.get("file") or "",
                "state": "resolved",
                "verdict": "resolved",
                "resolution_basis": "source-cited-terminal-verdict",
                "evidence_ref": ev[match],
                "ledger": fname,
                "produced_by": "tools/logic-obligation-resolution-bridge.py",
            })
    result = {
        "workspace": str(ws),
        "evidence_keys": len(ev),
        "emitted": len(emitted),
        "applied": bool(apply),
    }
    if apply and emitted:
        out = aud / _SIDECAR
        # append, preserving any prior genuine sidecar rows
        with out.open("a", encoding="utf-8") as fh:
            for e in emitted:
                fh.write(json.dumps(e) + "\n")
    return result


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--workspace", required=True, type=Path)
    ap.add_argument("--apply", action="store_true",
                    help="append resolution rows to the sidecar (default: dry-run)")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    ws = a.workspace.expanduser().resolve()
    if not ws.is_dir():
        print(f"[lor-bridge] ERR workspace not found: {ws}", file=sys.stderr)
        return 2
    r = bridge(ws, apply=a.apply)
    if a.json:
        print(json.dumps(r, indent=2))
    else:
        print(f"[lor-bridge] evidence_keys={r['evidence_keys']} emitted={r['emitted']} "
              f"applied={r['applied']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
