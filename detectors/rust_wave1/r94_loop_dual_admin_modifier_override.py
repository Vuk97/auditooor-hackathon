"""
r94_loop_dual_admin_modifier_override.py

Flags setter fns whose authorization is satisfied by ANY of
{owner, admin, administrator, operator} — either role overrides the
other's configured values without consent.

Source: Solodit #6836 (SeaDrop onlyOwnerOrAdministrator).
Class: dual-admin-modifier-override (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment

_FN_NAME_RE = re.compile(r"(?i)(update_|set_|configure_|override_)")
_DUAL_AUTH_RE = re.compile(
    r"caller\s*==\s*owner\s*\|\|\s*caller\s*==\s*(admin|administrator|operator)|"
    r"(owner|_owner)\.require_auth\s*\(\s*\)\s*\|\|\s*"
    r"(admin|administrator)\.require_auth\s*\(\s*\)|"
    r"is_owner\s*\(\s*\)\s*\|\|\s*is_admin\s*\(\s*\)|"
    r"only_owner_or_admin|onlyOwnerOrAdministrator|only_owner_or_operator"
)
_WRITE_RE = re.compile(
    r"\.set\s*\(|\.insert\s*\(|\.write\s*\(|\.update\s*\(|"
    r"self\.\w+\s*=\s*"
)


def run(tree, source: bytes, filepath: str):
    hits = []
    for fn, _impl in functions_in_contractimpl(tree.root_node, source):
        if not is_pub(fn, source):
            continue
        name = fn_name(fn, source)
        if not _FN_NAME_RE.search(name):
            continue
        body = fn_body(fn)
        if body is None:
            continue
        body_nc = body_text_nocomment(body, source)
        if not _DUAL_AUTH_RE.search(body_nc):
            continue
        if not _WRITE_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` allows EITHER owner OR admin to "
                f"mutate shared config — either role overrides the "
                f"other's work (dual-admin-modifier-override). "
                f"See Solodit #6836 (SeaDrop)."
            ),
        })
    return hits
