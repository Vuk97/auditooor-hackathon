"""Single-source-of-truth per-UNIT non-economic-surface disposition.

THE PROBLEM THIS FIXES
----------------------
The three deep-audit completeness gates -

  * tools/invariant-fuzz-completeness.py      (signal: invariant-fuzz)
  * tools/cross-function-invariant-coverage.py (signal: cross-function)
  * tools/audit-honesty-check.py               (signal: hollow)

- all demand a MUTATION-VERIFIED ECONOMIC-INVARIANT harness over every in-scope
unit. That bar is correct for a value-moving contract (a vault, a market, a
bundler). But a real workspace also ships LEGITIMATELY NON-ECONOMIC in-scope
contracts: a pure interest-rate-model (rate math, holds no funds), a price
view-oracle (a documented Faulty-Oracle OOS risk surface), a msg.sender-
namespaced config registry (writes a config mapping, custodies nothing), an
owner-only allow-list. None of these has a fund/share CONSERVATION oracle to
assert, so the only way to satisfy the gate is an `assert(true)` scaffold -
COVERAGE-THEATER, the exact thing R80/R81 forbid.

There was NO per-unit escape valve. The only overrides were WHOLE-WORKSPACE
blanket rebuttals (invariant_fuzz_rebuttal / xfi-rebuttal), which would scope
out the ENTIRE workspace - including the core value-moving protocols that DO
need (and already have) genuine harnesses. So a workspace with 3 genuinely-
audited core protocols + 5 pure-config contracts had no honest path: either
author 5 vacuous scaffolds (theater) or blanket-rebut all 8 (hides the core
obligation).

THE FIX
-------
A per-UNIT, documented, source-cited disposition. The operator (or a research
agent) records, in <ws>/.auditooor/non_economic_dispositions.json, that a SPECIFIC
contract/file has no fund/share-conservation invariant, WITH a written rationale
and a bounded classification. Each gate, when a harness-dir / cross-function
requirement / value-moving fn maps ONLY to dispositioned units, credits it as
``non-economic-surface-dispositioned`` instead of failing - NOT a blanket
scope-out, and NOT a vacuous assert(true).

NEVER-FALSE-PASS GUARDS (the whole point)
-----------------------------------------
A disposition credits a unit ONLY when ALL hold:

  1. ``classification`` is one of the bounded set
     {non-economic-rationale, oos} - free-text classes are ignored.
  2. ``rationale`` is non-empty and >= MIN_RATIONALE_CHARS (a real argument,
     not a rubber stamp).
  3. The cited ``repo`` resolves to an in-scope path that EXISTS on disk
     (a disposition cannot name a phantom contract).
  4. CRUCIAL: the unit is NOT a genuine value-MOVER. We cross-check
     value_moving_functions.json: a disposition is REJECTED for any unit whose
     value-moving record has ``transfer_hit`` true (a real token .transfer/.call
     {value:} - that is custody, never "non-economic"). A pure ``ledger_write_hit``
     (a config-mapping write, no transfer) MAY be dispositioned, because the
     value-moving detector is shape-based and over-flags msg.sender-namespaced
     config registries - BUT only with a documented rationale that says so.

  5. OPERATOR-APPROVAL (fail-closed). A disposition SHRINKS a required gate's
     denominator - it is a per-gate REBUTTAL, and the standing rule is that an
     agent may NEVER self-apply a gate rebuttal; it needs EXPLICIT per-gate
     operator approval, every time. So each entry (or the artifact top-level)
     must carry an ``approval_ref`` holding an operator-issued, HMAC-signed
     session token (tools/auditooor_mcp_token.py) whose scope includes
     ``disposition-approve`` and whose workspace matches. This is the SAME
     signature primitive the whole system trusts for gate approvals - an agent's
     default session token carries scope ``write`` (not ``disposition-approve``),
     so a plain agent token can NEVER auto-credit a disposition. A missing /
     malformed / wrong-scope / wrong-workspace / expired token => the entry is
     DROPPED (not credited); the gate stays red. Agent authorship alone is never
     enough.

So: the most dangerous case (a real transfer) can NEVER be silently disposed;
the over-flagged config-write case CAN, but only with an on-record argument AND
an operator-signed approval token. An agent cannot green the floor on its own.

This is the same SERVING-JOIN discipline as the other gate credits
(_mvc_sidecar_credit, _mutation_verified_cut_harnesses): an additive credit
that is impossible to fake, keyed off un-fakeable disk facts + an explicit
operator-authored disposition.

ARTIFACT SCHEMA  (<ws>/.auditooor/non_economic_dispositions.json)
-----------------------------------------------------------------
{
  "schema": "auditooor.non_economic_disposition.v1",
  "approval_ref": "<optional artifact-level operator token; per-entry wins>",
  "dispositions": [
    {
      "repo": "morpho-blue-irm",            // path-segment / src-subdir / file
      "classification": "non-economic-rationale" | "oos",
      "rationale": "<>=40 chars: why no fund/share invariant applies>",
      "cut_path": "src/morpho-blue-irm/src/AdaptiveCurveIrm.sol",  // optional, strengthens the cite
      "source_ref": "<optional: SCOPE.md / docs URL backing an OOS class>",
      "approval_ref": "<REQUIRED: operator-issued HMAC session token with scope
                        'disposition-approve' (tools/auditooor_mcp_token.py). May
                        be given once at artifact top level instead.>"
    },
    ...
  ]
}

A disposition's ``repo`` matches a unit when the unit's file path contains the
repo token as a path segment (``/<repo>/``) OR the file path ends with /equals
the ``repo`` value (so a file-level disposition works too) OR the optional
``cut_path`` is a path-prefix of / equal to the unit file.

Pure stdlib, offline, no workspace name in any decision.
"""
from __future__ import annotations

import json
from pathlib import Path

SCHEMA = "auditooor.non_economic_disposition.v1"
ARTIFACT_NAME = "non_economic_dispositions.json"
CREDIT_LABEL = "non-economic-surface-dispositioned"

# A bounded set of classifications. A free-text class is ignored (never credits).
_VALID_CLASSIFICATIONS = {"non-economic-rationale", "oos"}

# A rationale must be a real argument, not a rubber stamp.
MIN_RATIONALE_CHARS = 40

# OPERATOR-APPROVAL primitive (fail-closed). A disposition shrinks a required
# gate's denominator => it is a per-gate rebuttal and needs an EXPLICIT operator
# approval. We reuse the repo's HMAC-signed session-token primitive
# (tools/auditooor_mcp_token.py) for consistency. The approval token must carry
# this dedicated scope, which an agent's default session token (scope 'write')
# does NOT hold - so agent authorship alone can never credit a disposition.
APPROVAL_SCOPE = "disposition-approve"


def _load_token_module():
    """Import tools/auditooor_mcp_token.py by path (stdlib importlib). Returns the
    module or None. The token module is a sibling of this lib's parent dir."""
    import importlib.util as _ilu
    tokp = Path(__file__).resolve().parent.parent / "auditooor_mcp_token.py"
    if not tokp.is_file():
        return None
    try:
        spec = _ilu.spec_from_file_location("auditooor_mcp_token", str(tokp))
        mod = _ilu.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod
    except Exception:
        return None


def _approval_valid(ws: Path, token: str) -> bool:
    """FAIL-CLOSED operator-approval check. True iff ``token`` is an operator-
    issued, HMAC-signed session token that verifies for THIS workspace and carries
    the ``disposition-approve`` scope. Any error / missing module / bad signature /
    wrong scope / wrong workspace / expiry => False (not credited)."""
    if not token or not isinstance(token, str):
        return False
    mod = _load_token_module()
    if mod is None or not hasattr(mod, "verify_token"):
        return False
    try:
        valid, _err, _payload = mod.verify_token(
            token,
            require_scope=APPROVAL_SCOPE,
            require_workspace=str(ws),
        )
    except Exception:
        return False
    return bool(valid)


def _norm(p: str) -> str:
    return str(p or "").strip().lstrip("./").replace("\\", "/")


def _load_value_moving_transfer_files(ws: Path) -> set[str]:
    """Return the normalised file paths of every value-moving fn whose record
    has ``transfer_hit`` true (a REAL token transfer / .call{value:}). A
    disposition for any such file is REJECTED - custody is never non-economic.

    A pure ``ledger_write_hit`` (config-mapping write, no transfer) file is NOT
    returned here, so it remains dispositionable with a documented rationale."""
    out: set[str] = set()
    p = ws / ".auditooor" / "value_moving_functions.json"
    try:
        d = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return out
    if not isinstance(d, dict):
        return out
    for fn in (d.get("functions") or []):
        if isinstance(fn, dict) and fn.get("transfer_hit") is True:
            f = _norm(fn.get("file"))
            if f:
                out.add(f)
    return out


def _disposition_paths_on_disk(ws: Path, repo: str, cut_path: str) -> bool:
    """True iff the disposition resolves to at least one real in-scope path on
    disk. A disposition that names a phantom contract credits nothing."""
    # Explicit cut_path wins when present.
    if cut_path:
        cp = ws / cut_path
        if cp.is_file():
            return True
    if not repo:
        return False
    # repo may be a file path, an src-subdir, or a bare path segment.
    direct = ws / repo
    if direct.exists():
        return True
    # bare-segment: any in-scope .sol under a /<repo>/ segment.
    seg = f"/{repo.strip('/')}/"
    src_root = ws / "src"
    walk_root = src_root if src_root.is_dir() else ws
    for sp in walk_root.rglob("*.sol"):
        rel = "/" + _norm(str(sp.relative_to(ws)))
        if seg in rel:
            return True
    return False


def load_dispositions(ws) -> list[dict]:
    """Load + VALIDATE the workspace's per-unit non-economic dispositions.

    Returns the list of ACCEPTED dispositions (each a dict with normalised
    ``repo`` / ``classification`` / ``rationale`` / ``cut_path``). A disposition
    that fails any never-false-pass guard is silently dropped (it simply does not
    credit its unit - the gate then fails honestly on that unit). Stdlib-only;
    a missing / malformed artifact returns []."""
    ws = Path(ws)
    p = ws / ".auditooor" / ARTIFACT_NAME
    try:
        d = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    if not isinstance(d, dict) or d.get("schema") != SCHEMA:
        return []
    raw = d.get("dispositions")
    if not isinstance(raw, list):
        return []
    transfer_files = _load_value_moving_transfer_files(ws)
    # Artifact-level approval token (applies to every entry that omits its own).
    top_approval = str(d.get("approval_ref") or "").strip()
    accepted: list[dict] = []
    for row in raw:
        if not isinstance(row, dict):
            continue
        cls = str(row.get("classification") or "").strip().lower()
        if cls not in _VALID_CLASSIFICATIONS:
            continue
        rationale = str(row.get("rationale") or "").strip()
        if len(rationale) < MIN_RATIONALE_CHARS:
            continue
        repo = _norm(row.get("repo"))
        cut_path = _norm(row.get("cut_path"))
        if not repo and not cut_path:
            continue
        # Never-false-pass guard 4: reject if it names a genuine transfer-mover.
        # A disposition file/segment that overlaps ANY transfer-hit file is unsafe.
        rejected_for_transfer = False
        for tf in transfer_files:
            tf_slashed = "/" + tf
            if cut_path and (tf == cut_path or tf_slashed.endswith("/" + cut_path)):
                rejected_for_transfer = True
                break
            if repo and (f"/{repo.strip('/')}/" in tf_slashed or tf == repo
                         or tf_slashed.endswith("/" + repo)):
                rejected_for_transfer = True
                break
        if rejected_for_transfer:
            continue
        # Never-false-pass guard 3: the cited unit must exist on disk.
        if not _disposition_paths_on_disk(ws, repo, cut_path):
            continue
        # Never-false-pass guard 5 (OPERATOR-APPROVAL, fail-closed): a disposition
        # shrinks a required gate's denominator - it is a per-gate rebuttal and an
        # agent may never self-apply it. Require an operator-signed approval token
        # (row-level ``approval_ref`` wins, else the artifact-level one). Missing /
        # invalid / wrong-scope / wrong-workspace => DROP (not credited).
        approval_ref = str(row.get("approval_ref") or "").strip() or top_approval
        if not _approval_valid(ws, approval_ref):
            continue
        accepted.append({
            "repo": repo,
            "classification": cls,
            "rationale": rationale,
            "cut_path": cut_path,
            "source_ref": str(row.get("source_ref") or "").strip(),
            "approval_ref": approval_ref,
        })
    return accepted


def file_is_dispositioned(file_rel: str, dispositions: list[dict]) -> dict | None:
    """Return the matching accepted disposition for ``file_rel`` (a ws-relative
    source path), or None. Matching: the disposition's cut_path is a prefix of /
    equals the file, OR the repo token appears as a path segment, OR the file
    path ends with the repo value."""
    f = "/" + _norm(file_rel)
    for disp in dispositions:
        cp = disp.get("cut_path")
        if cp and (f == "/" + cp or f.endswith("/" + cp) or ("/" + cp + "/") in f):
            return disp
        repo = disp.get("repo")
        if repo:
            seg = f"/{repo.strip('/')}/"
            if seg in f or f.endswith("/" + repo) or f == "/" + repo:
                return disp
    return None


def all_files_dispositioned(file_rels, dispositions: list[dict]) -> bool:
    """True iff EVERY file in ``file_rels`` is covered by an accepted disposition
    (and the list is non-empty). A single non-dispositioned file means the unit
    is NOT fully non-economic and the gate must still evaluate it normally."""
    files = [f for f in (file_rels or []) if f]
    if not files:
        return False
    return all(file_is_dispositioned(f, dispositions) is not None for f in files)
