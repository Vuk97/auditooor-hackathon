#!/usr/bin/env python3
"""Prior-audit COMPLETENESS check (R47/R53 disk-coverage gate).

PURPOSE
-------
This is the COMPLEMENT of ``early-prior-audit-dedup-gate.py``.

  - ``early-prior-audit-dedup-gate.py`` answers: "does my candidate finding
    dupe something already written in a prior audit ON DISK?".  It can only
    catch a dupe against audits that have actually been pulled into
    ``prior_audits/``.
  - THIS tool answers the upstream question: "are there KNOWN-PUBLISHED audits
    for my in-scope products that are NOT on disk at all?".  If a published
    audit is missing from ``prior_audits/`` then the dedup gate has a blind
    spot for that whole product - an R47/R53 dedup GAP.

  Morpho-class motivation: 4 in-scope products each had a published audit
  (firm + date) that was never pulled into ``prior_audits/``, so the dedup gate
  silently passed candidates that those audits had already disclosed.

WHAT IT DOES (generic, workspace-driven - NEVER fetches anything)
-----------------------------------------------------------------
Given a workspace it builds three sets and diffs them:

  1. IN-SCOPE PRODUCTS  - parsed from SCOPE.md (repo slugs ``org/repo``, product
     line names) and/or supplied via ``--product`` / a products manifest.
  2. AUDITS ON DISK     - parsed from ``prior_audits/`` filenames
     (``YYYY-MM-DD_Firm_version.{pdf,txt,md}``) plus an optional ``INDEX.md``
     line table, yielding (firm, date, product_key) tuples present.
  3. EXPECTED AUDITS    - supplied, NOT fetched, via either:
       a. ``--expected <manifest.json>``  (per-product expected-audit list), OR
       b. ``--repo-audits-listing <dir-or-file>``  - a plain listing of an
          official repo's ``audits/`` folder (filenames one per line, or a
          directory whose entries are read).  This is the "official-repo audits/
          folder listing if provided as input" path from the lane brief.

For every expected audit it reports: product | expected-audit | present? |
dedup-gap.  An expected audit is PRESENT iff an on-disk audit matches by
(firm, date, product_key) with date/firm normalized.

FAIL-CLOSED SEMANTICS
---------------------
  - An expected audit not matched on disk -> dedup_gap = True (flagged).
  - An IN-SCOPE product that has a KNOWN PUBLISHER (it appears in the expected
    set, i.e. someone knows an audit exists) AND has ZERO prior_audits on disk
    for that product -> flagged as a hard ``missing_all_audits`` gap.  The whole
    product's prior-audit corpus is absent; the dedup gate is blind for it.
  - If NO expected set is provided at all, the tool cannot assert completeness;
    it returns ``warn`` (not a false ``pass``).  Completeness can only be
    asserted relative to a known-published set.

VERDICTS
--------
  pass  - every expected audit is represented on disk (no dedup gap)
  FLAG  - >=1 expected audit missing from disk (R47/R53 dedup gap)
  warn  - no expected-audit set supplied (cannot assert completeness)
  error - workspace missing / bad input

EXIT CODES
----------
  0 - pass / warn          (not a hard gap)
  1 - FLAG                  (dedup gap: a known audit is missing on disk)
  2 - error                 (bad input)

USAGE
-----
    tools/prior-audit-completeness-check.py <workspace> \\
        [--expected expected_audits.json] \\
        [--repo-audits-listing <dir-or-listing.txt> ...] \\
        [--product org/repo ...] \\
        [--json]

expected_audits.json schema (any of these shapes accepted):
    {
      "products": {
        "morpho-org/morpho-blue": [
          {"firm": "Spearbit", "date": "2024-01-15"},
          {"firm": "Cantina",  "date": "2024-03"}
        ]
      }
    }
  OR a flat list:
    [
      {"product": "morpho-org/morpho-blue", "firm": "Spearbit", "date": "2024"}
    ]
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

SCHEMA = "auditooor.prior_audit_completeness_check.v1"
GATE = "GATE-PRIOR-AUDIT-COMPLETENESS"

# ---------------------------------------------------------------------------
# Filename / date / firm normalization
# ---------------------------------------------------------------------------

# A prior_audits filename like "2024-02-15_Quantstamp_v1.1.0.pdf" or
# "2024-01_Spearbit_morpho-blue.txt".  We tolerate firm-then-date too.
_DATE_RE = re.compile(r"(20\d{2})(?:[-_](\d{1,2}))?(?:[-_](\d{1,2}))?")
# Firm token: a run of letters (and internal & / -) - e.g. Quantstamp, OpenZeppelin,
# Trail-of-Bits, ChainSecurity.  Lowercased + stripped of separators for compare.
_FIRM_TOKEN_RE = re.compile(r"[A-Za-z][A-Za-z&\-]{2,}")

# Audit-firm canonical aliases -> a single normalized key.  Generic, extend as
# needed.  Normalization strips case / separators first, then maps aliases.
_FIRM_ALIASES = {
    "trailofbits": "trailofbits",
    "tob": "trailofbits",
    "openzeppelin": "openzeppelin",
    "oz": "openzeppelin",
    "chainsecurity": "chainsecurity",
    "spearbit": "spearbit",
    "cantina": "cantina",
    "quantstamp": "quantstamp",
    "consensysdiligence": "consensys",
    "consensys": "consensys",
    "sherlock": "sherlock",
    "code4rena": "code4rena",
    "c4": "code4rena",
    "zellic": "zellic",
    "hexens": "hexens",
    "certora": "certora",
    "sigmaprime": "sigmaprime",
    "macro": "macro",
    "pashov": "pashov",
}


def normalize_firm(raw: str) -> str:
    """Lowercase + strip separators + map aliases to a canonical firm key."""
    if not raw:
        return ""
    base = re.sub(r"[^a-z0-9]", "", raw.lower())
    return _FIRM_ALIASES.get(base, base)


def normalize_date(raw: str) -> str:
    """Normalize a date to YYYY or YYYY-MM (day dropped).

    We match at YEAR granularity by default because expected manifests are often
    only year-precise; if both sides carry a month we keep YYYY-MM.  Returns ""
    if no year is found.
    """
    if not raw:
        return ""
    m = _DATE_RE.search(str(raw))
    if not m:
        return ""
    year = m.group(1)
    month = m.group(2)
    if month:
        return f"{year}-{int(month):02d}"
    return year


def date_matches(disk_date: str, expected_date: str) -> bool:
    """Does a disk audit's date satisfy an expected audit's date?

    Fail-closed: the disk date must be AT LEAST as precise as the expected date
    and agree on every field the expected date specifies.

      - expected year-only  -> disk year must equal it (disk may be more precise).
      - expected year-month -> disk must ALSO be month-precise and agree on the
        month.  A year-only disk date does NOT satisfy a month-precise
        expectation (we cannot confirm it is the same audit -> no over-credit).
      - empty expected date  -> matches any (date was not part of the expectation).
    """
    if not expected_date:
        return True
    dn = normalize_date(disk_date)
    en = normalize_date(expected_date)
    if not dn or not en:
        return False
    if "-" in en:
        # Expected is month-precise: require disk month-precise + month match.
        return "-" in dn and dn[:7] == en[:7]
    # Expected is year-only: require year agreement (disk may be more precise).
    return dn[:4] == en[:4]


# ---------------------------------------------------------------------------
# Product-key normalization
# ---------------------------------------------------------------------------

def product_key(raw: str) -> str:
    """Normalize a product identifier to a stable comparison key.

    Accepts ``org/repo``, ``repo``, or a free product name.  We key on the repo
    leaf (after the last ``/``) lowercased with separators stripped, so
    ``morpho-org/morpho-blue`` and ``morpho-blue`` collide.
    """
    if not raw:
        return ""
    leaf = raw.strip().rstrip("/").split("/")[-1]
    return re.sub(r"[^a-z0-9]", "", leaf.lower())


# ---------------------------------------------------------------------------
# 1. In-scope products from SCOPE.md
# ---------------------------------------------------------------------------

# Backticked repo slug: `org/repo`  (org and repo are slug-safe)
_REPO_SLUG_RE = re.compile(r"`([A-Za-z0-9][\w.\-]*/[A-Za-z0-9][\w.\-]*)`")


def parse_scope_products(workspace: Path) -> list[str]:
    """Extract in-scope product identifiers (repo slugs) from SCOPE.md.

    Returns the RAW identifiers (e.g. ``morpho-org/morpho-blue``); callers
    normalize via ``product_key``.  Only backticked ``org/repo`` slugs are
    treated as products (high precision); free product names are left to the
    --product flag / manifest to avoid false in-scope inferences.
    """
    scope = workspace / "SCOPE.md"
    if not scope.is_file():
        return []
    try:
        text = scope.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    seen: set[str] = set()
    out: list[str] = []
    for m in _REPO_SLUG_RE.finditer(text):
        slug = m.group(1)
        # Skip obvious URLs / docs slugs that slipped into backticks
        if slug.lower().startswith(("http", "www.")):
            continue
        if slug not in seen:
            seen.add(slug)
            out.append(slug)
    return out


# ---------------------------------------------------------------------------
# 2. Audits ON DISK from prior_audits/
# ---------------------------------------------------------------------------

def _parse_audit_filename(name: str) -> dict[str, str]:
    """Parse a prior_audits filename into {date, firm, product_hint}.

    Handles ``DATE_Firm_version`` and ``Firm_DATE_product`` orderings by
    extracting the first year-bearing token as the date and the first firm-like
    alpha token (that is not purely a version like ``v1.0.0``) as the firm.
    """
    stem = Path(name).stem
    parts = re.split(r"[_\s]+", stem)
    date = ""
    firm = ""
    leftovers: list[str] = []
    for p in parts:
        if not date and _DATE_RE.fullmatch(p):
            date = normalize_date(p)
            continue
        # version tokens like v1.0.0 / v2.0.0-rc3 are not firms
        if re.fullmatch(r"v?\d+(?:\.\d+)*(?:-[\w]+)?", p, re.IGNORECASE):
            leftovers.append(p)
            continue
        if not firm and _FIRM_TOKEN_RE.fullmatch(p):
            firm = normalize_firm(p)
            continue
        leftovers.append(p)
    return {
        "date": date,
        "firm": firm,
        "product_hint": " ".join(leftovers),
        "raw": name,
    }


# INDEX.md line carrying firm/date/product, e.g.
# "| morpho-blue | Spearbit | 2024-01 | spearbit_morpho_blue.pdf |"
def _parse_index_md(path: Path) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return out
    for line in lines:
        if "|" not in line:
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) < 2:
            continue
        # Heuristic: find a firm cell and a date cell among the cells.
        firm = ""
        date = ""
        product_hint = ""
        for cell in cells:
            if not date:
                nd = normalize_date(cell)
                if nd:
                    date = nd
                    continue
            if not firm:
                nf = normalize_firm(cell)
                if nf in _FIRM_ALIASES.values():
                    firm = nf
                    continue
            product_hint = product_hint + " " + cell
        if firm or date:
            out.append({
                "firm": firm,
                "date": date,
                "product_hint": product_hint.strip(),
                "raw": line.strip(),
            })
    return out


def parse_disk_audits(workspace: Path) -> dict[str, Any]:
    """Return audits present on disk in prior_audits/.

    Returns:
        {
          "present": bool,             # prior_audits/ dir exists and non-empty
          "audits": [ {date, firm, product_hint, raw}, ... ],
          "files": [str, ...],
        }
    """
    base = workspace / "prior_audits"
    result: dict[str, Any] = {"present": False, "audits": [], "files": []}
    if not base.is_dir():
        return result
    audits: list[dict[str, str]] = []
    files: list[str] = []
    for ext in ("*.pdf", "*.txt", "*.md", "*.markdown"):
        for f in sorted(base.glob(ext)):
            files.append(f.name)
            low = f.name.lower()
            if low in ("index.md", "readme.md"):
                audits.extend(_parse_index_md(f))
                continue
            if low.startswith("digest_") or low.startswith("digest"):
                # digests are derived, not a distinct audit; still record the
                # filename parse as a weak signal.
                pass
            parsed = _parse_audit_filename(f.name)
            if parsed["date"] or parsed["firm"]:
                audits.append(parsed)
    result["present"] = bool(files)
    result["audits"] = audits
    result["files"] = files
    return result


# ---------------------------------------------------------------------------
# 3. Expected audits (supplied, never fetched)
# ---------------------------------------------------------------------------

def parse_expected_manifest(path: Path) -> list[dict[str, str]]:
    """Parse an expected-audits manifest into a flat list of expectations.

    Each entry: {product, firm, date}.  Accepts the {"products": {...}} shape
    and the flat-list shape (see module docstring).
    """
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read expected manifest {path}: {exc}") from exc

    out: list[dict[str, str]] = []
    if isinstance(data, dict) and isinstance(data.get("products"), dict):
        for product, entries in data["products"].items():
            if not isinstance(entries, list):
                continue
            for e in entries:
                if not isinstance(e, dict):
                    continue
                out.append({
                    "product": str(product),
                    "firm": str(e.get("firm", "")),
                    "date": str(e.get("date", "")),
                })
    elif isinstance(data, list):
        for e in data:
            if not isinstance(e, dict):
                continue
            out.append({
                "product": str(e.get("product", "")),
                "firm": str(e.get("firm", "")),
                "date": str(e.get("date", "")),
            })
    else:
        raise ValueError(
            "expected manifest must be a list or {\"products\": {...}} object"
        )
    return out


def parse_repo_audits_listing(
    listing: Path,
    product: str,
) -> list[dict[str, str]]:
    """Parse an official-repo ``audits/`` folder listing into expectations.

    ``listing`` is either a directory (we read its entries) or a text file with
    one filename per line.  Each filename is parsed for firm+date like a
    prior_audits filename.  All entries are attributed to ``product`` (the repo
    the listing belongs to).  NOTHING IS FETCHED - this is a listing supplied as
    input.
    """
    names: list[str] = []
    if listing.is_dir():
        for f in sorted(listing.iterdir()):
            if f.is_file():
                names.append(f.name)
    elif listing.is_file():
        try:
            for line in listing.read_text(encoding="utf-8", errors="replace").splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    names.append(line)
        except OSError:
            return []
    else:
        return []

    out: list[dict[str, str]] = []
    for name in names:
        parsed = _parse_audit_filename(name)
        if parsed["date"] or parsed["firm"]:
            out.append({
                "product": product,
                "firm": parsed["firm"],
                "date": parsed["date"],
                "source_file": name,
            })
    return out


# ---------------------------------------------------------------------------
# Matching: is an expected audit present on disk?
# ---------------------------------------------------------------------------

def _disk_audit_matches_product(
    disk_audit: dict[str, str],
    product_keys: set[str],
) -> bool:
    """A disk audit belongs to a product iff its product_hint contains one of
    the product keys, OR there is only one in-scope product (single-product ws)
    and the disk audit carries no contradicting hint.
    """
    hint_key = product_key(disk_audit.get("product_hint", ""))
    # Loose contains-match on the normalized hint
    hint_norm = re.sub(r"[^a-z0-9]", "", disk_audit.get("product_hint", "").lower())
    for pk in product_keys:
        if not pk:
            continue
        if pk and (pk in hint_norm or hint_key == pk):
            return True
    return False


def expected_is_present(
    expected: dict[str, str],
    disk_audits: list[dict[str, str]],
    *,
    single_product: bool,
) -> dict[str, Any] | None:
    """Return the matching disk audit dict if ``expected`` is present, else None.

    Match requires firm-agreement (when both firms known) AND date-agreement
    (at the coarser granularity).  Product attribution: if the workspace has a
    single in-scope product we do not require the disk audit's product_hint to
    name it; otherwise we require it.
    """
    exp_firm = normalize_firm(expected.get("firm", ""))
    exp_date = expected.get("date", "")
    exp_pk = product_key(expected.get("product", ""))

    for da in disk_audits:
        da_firm = da.get("firm", "")
        da_date = da.get("date", "")
        # Firm must agree when both are known.
        if exp_firm and da_firm and exp_firm != da_firm:
            continue
        # If neither firm is known we cannot confidently match - skip (fail
        # closed: an unattributable disk file does not satisfy an expectation).
        if not exp_firm and not da_firm:
            continue
        if not date_matches(da_date, exp_date):
            continue
        # Product attribution
        if not single_product:
            if not _disk_audit_matches_product(da, {exp_pk} if exp_pk else set()):
                continue
        return da
    return None


# ---------------------------------------------------------------------------
# Core
# ---------------------------------------------------------------------------

def run_completeness_check(
    workspace: Path,
    *,
    expected_manifest: Path | None = None,
    repo_audits_listings: list[tuple[str, Path]] | None = None,
    extra_products: list[str] | None = None,
) -> dict[str, Any]:
    """Run the prior-audit completeness check.

    repo_audits_listings: list of (product, listing_path) tuples.
    """
    workspace = workspace.expanduser().resolve()
    payload: dict[str, Any] = {
        "schema": SCHEMA,
        "gate": GATE,
        "workspace": str(workspace),
        "verdict": "error",
        "reason": "",
        "in_scope_products": [],
        "disk_audits_present": False,
        "disk_audit_count": 0,
        "expected_count": 0,
        "report": [],          # product | expected-audit | present? | dedup-gap
        "gaps": [],            # subset of report where dedup_gap is True
        "warnings": [],
        "errors": [],
        "action": "",
    }

    if not workspace.is_dir():
        payload["errors"].append(f"workspace not found: {workspace}")
        payload["action"] = "Cannot run check - workspace missing."
        return payload

    # 1. In-scope products
    scope_products = parse_scope_products(workspace)
    products_raw = list(dict.fromkeys(scope_products + list(extra_products or [])))
    payload["in_scope_products"] = products_raw
    product_keys = {product_key(p) for p in products_raw if p}
    single_product = len(product_keys) <= 1

    # 2. Disk audits
    disk = parse_disk_audits(workspace)
    payload["disk_audits_present"] = disk["present"]
    payload["disk_audit_count"] = len(disk["audits"])
    payload["disk_files"] = disk["files"]

    # 3. Expected audits
    expected: list[dict[str, str]] = []
    if expected_manifest is not None:
        try:
            expected.extend(parse_expected_manifest(expected_manifest))
        except ValueError as exc:
            payload["errors"].append(str(exc))
            payload["action"] = "Fix the expected manifest."
            return payload
    for product, listing in (repo_audits_listings or []):
        expected.extend(parse_repo_audits_listing(listing, product))

    payload["expected_count"] = len(expected)

    if not expected:
        payload["verdict"] = "warn"
        payload["reason"] = "no_expected_audit_set_supplied"
        payload["warnings"].append(
            "No expected-audit set (--expected / --repo-audits-listing) supplied; "
            "completeness cannot be asserted. Supply a known-published list."
        )
        payload["action"] = (
            "Provide an expected-audits manifest or an official-repo audits/ "
            "folder listing so disk coverage can be checked. Do NOT fetch PDFs "
            "without operator confirmation."
        )
        return payload

    # Diff expected vs disk
    report: list[dict[str, Any]] = []
    # Track, per product, whether ANY expected audit was matched on disk - used
    # for the hard missing_all_audits fail-closed rule.
    product_any_present: dict[str, bool] = {}
    product_has_expected: set[str] = set()

    for exp in expected:
        pk = product_key(exp.get("product", ""))
        product_has_expected.add(pk)
        match = expected_is_present(exp, disk["audits"], single_product=single_product)
        present = match is not None
        product_any_present[pk] = product_any_present.get(pk, False) or present
        row = {
            "product": exp.get("product", ""),
            "product_key": pk,
            "expected_audit": {
                "firm": exp.get("firm", ""),
                "date": exp.get("date", ""),
                "source_file": exp.get("source_file", ""),
            },
            "present": present,
            "matched_disk_file": (match or {}).get("raw", "") if match else "",
            "dedup_gap": not present,
            "gap_kind": "" if present else "missing_expected_audit",
        }
        report.append(row)

    # Fail-closed: a product with a KNOWN PUBLISHER (>=1 expected audit) AND
    # zero matched audits on disk for that product -> escalate every gap row of
    # that product to missing_all_audits (the dedup gate is blind for it).
    for row in report:
        pk = row["product_key"]
        if row["dedup_gap"] and pk in product_has_expected and not product_any_present.get(pk, False):
            row["gap_kind"] = "missing_all_audits"

    payload["report"] = report
    gaps = [r for r in report if r["dedup_gap"]]
    payload["gaps"] = gaps

    if gaps:
        payload["verdict"] = "FLAG"
        n_missing_all = sum(1 for r in gaps if r["gap_kind"] == "missing_all_audits")
        payload["reason"] = (
            f"{len(gaps)} expected audit(s) missing from prior_audits/ on disk"
            + (f"; {n_missing_all} product(s) have NO prior audits on disk at all"
               if n_missing_all else "")
        )
        payload["action"] = (
            "R47/R53 DEDUP GAP: known-published audits are not on disk. Pull each "
            "missing audit into prior_audits/ (operator-confirmed) before relying on "
            "the dedup gate. Products with missing_all_audits have a fully blind "
            "dedup surface."
        )
    else:
        payload["verdict"] = "pass"
        payload["reason"] = "all_expected_audits_present_on_disk"
        payload["action"] = (
            "Every known-published audit is represented in prior_audits/. The dedup "
            "gate has full coverage for the supplied expected set."
        )
    return payload


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__,
                                      formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("workspace", help="workspace root directory path")
    parser.add_argument(
        "--expected", default=None,
        help="path to an expected-audits manifest JSON",
    )
    parser.add_argument(
        "--repo-audits-listing", action="append", default=[],
        metavar="PRODUCT=PATH",
        help="official-repo audits/ folder listing for a product, as "
             "PRODUCT=PATH (PATH is a dir or one-filename-per-line file). "
             "Repeatable. NOTHING is fetched.",
    )
    parser.add_argument(
        "--product", action="append", default=[],
        help="extra in-scope product identifier (org/repo or name). Repeatable.",
    )
    parser.add_argument("--json", action="store_true", help="emit JSON output")
    return parser.parse_args(argv)


def _split_product_listing(spec: str) -> tuple[str, Path]:
    if "=" not in spec:
        raise ValueError(
            f"--repo-audits-listing must be PRODUCT=PATH, got: {spec!r}"
        )
    product, _, path = spec.partition("=")
    return product.strip(), Path(path.strip())


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    workspace = Path(args.workspace)

    listings: list[tuple[str, Path]] = []
    for spec in args.repo_audits_listing:
        try:
            listings.append(_split_product_listing(spec))
        except ValueError as exc:
            print(json.dumps({"schema": SCHEMA, "verdict": "error",
                              "errors": [str(exc)]}, indent=2))
            return 2

    expected_manifest = Path(args.expected) if args.expected else None
    if expected_manifest is not None and not expected_manifest.is_file():
        print(json.dumps({"schema": SCHEMA, "verdict": "error",
                          "errors": [f"expected manifest not found: {expected_manifest}"]},
                         indent=2))
        return 2

    result = run_completeness_check(
        workspace,
        expected_manifest=expected_manifest,
        repo_audits_listings=listings,
        extra_products=args.product or [],
    )
    print(json.dumps(result, indent=2, sort_keys=True))

    verdict = result.get("verdict", "error")
    if verdict == "FLAG":
        return 1
    if verdict == "error":
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
