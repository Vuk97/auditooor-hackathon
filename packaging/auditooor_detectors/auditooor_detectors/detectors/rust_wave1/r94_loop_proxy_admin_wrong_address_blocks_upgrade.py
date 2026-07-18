"""
r94_loop_proxy_admin_wrong_address_blocks_upgrade.py

Flags factories / deployers that call `TransparentUpgradeableProxy::new`
(or Rust `Proxy::new`) passing the deployer/factory ITSELF as admin,
where the deployer is also a caller. Admin call hits the impl's
delegatecall path (no upgradeTo), proxy un-upgradeable.

Source: Solodit #49834 (Codehawks One World MembershipFactory).
Class: proxy-admin-wrong-address-blocks-upgrade (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment

_FN_NAME_RE = re.compile(r"(?i)(create_proxy|deploy_proxy|deploy_membership|create_dao|factory_deploy)")
_PROXY_NEW_RE = re.compile(
    r"(TransparentUpgradeableProxy|TransparentProxy|Proxy)\s*::\s*new\s*\(|"
    r"new\s+TransparentUpgradeableProxy\s*\(|new\s+TransparentProxy\s*\("
)
_ADMIN_IS_SELF_RE = re.compile(
    r"(TransparentUpgradeableProxy|Proxy)\s*::\s*new\s*\([^,]+,\s*(address\s*\(\s*this\s*\)|self\.addr|env\.current_contract_address|address\(this\)|address_of\s*\(\s*self\s*\))|"
    r"new\s+TransparentUpgradeableProxy\s*\([^,]+,\s*(address\s*\(\s*this\s*\)|address_of\s*\(\s*self\s*\))"
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
        if not _PROXY_NEW_RE.search(body_nc):
            continue
        if not _ADMIN_IS_SELF_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` creates TransparentUpgradeableProxy "
                f"passing factory (address(this)) as admin — admin "
                f"calls hit impl's delegatecall path (no upgradeTo), "
                f"proxy un-upgradeable (proxy-admin-wrong-address-"
                f"blocks-upgrade). See Solodit #49834 (One World)."
            ),
        })
    return hits
