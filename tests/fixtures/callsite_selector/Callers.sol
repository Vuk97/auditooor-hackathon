// SPDX-License-Identifier: MIT
// The five call-site shapes of the `validateExit` target guard.
//
//   (a) direct          -> ExitLib.validateExit(leafId)
//   (b) alias           -> Checks.validateExit(leafId)   (renamed import)
//   (c) overload-by-sig -> ExitLib.validateExit(leafId, to)
//   (d) virtual-override-> validateExit(leafId) dispatched to a base/override body
//   (e) interface       -> IExitGuard(handle).validateExit(leafId)
pragma solidity ^0.8.0;

import {ExitLib} from "./Guards.sol";
// (b) RENAMED-IMPORT ALIAS: ExitLib imported under a different local name.
import {ExitLib as Checks} from "./Guards.sol";
import {IExitGuard} from "./Guards.sol";

// Base declares the TARGET as a VIRTUAL method.
abstract contract BaseValidator {
    // The TARGET as a virtual member function (overridden by the child).
    function validateExit(uint256 leafId) public virtual returns (bool) {
        return leafId != 0;
    }
}

contract Vault is BaseValidator {
    IExitGuard public guardContract;

    // Child OVERRIDE of the virtual target.
    function validateExit(uint256 leafId) public override returns (bool) {
        return leafId != 1;
    }

    // (a) DIRECT call to the library target by its real name.
    function exitLeaf(uint256 leafId) public pure returns (bool) {
        return ExitLib.validateExit(leafId);
    }

    // (b) RENAMED-IMPORT ALIAS call site: SOURCE TEXT says `Checks.`, not
    // `ExitLib.` -- a grep keyed on the canonical owner name misses this.
    function exitLeafAliased(uint256 leafId) public pure returns (bool) {
        return Checks.validateExit(leafId);
    }

    // (c) OVERLOAD-BY-SIGNATURE: validateExit(uint256,address). A name-only grep
    // cannot distinguish this from the single-arg overload.
    function exitLeafTo(uint256 leafId, address to) public pure returns (bool) {
        return ExitLib.validateExit(leafId, to);
    }

    // (d) VIRTUAL / OVERRIDE dispatch: bare `validateExit(leafId)` resolves to
    // the member-function override (NOT the library overload). This is the
    // base/override dispatch a grep cannot resolve to the concrete body.
    function triggerVirtual(uint256 leafId) public returns (bool) {
        return validateExit(leafId);
    }

    // (e) INTERFACE dispatch: validateExit through an IExitGuard handle,
    // resolved to ExitGuardImpl by resolve_concrete_impl.
    function exitLeafExternal(uint256 leafId) public view returns (bool) {
        return guardContract.validateExit(leafId);
    }
}
