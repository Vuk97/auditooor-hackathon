// SPDX-License-Identifier: MIT
// Fixture: packed-lane-increment-no-overflow-guard — CLEAN
// Detector MUST NOT fire on this contract.
//
// Same packed-lane shape as the vuln fixture, but `incrementQuestionCount`
// adds an explicit `< type(uint8).max` lane-cap guard so the 256th call
// reverts with a typed custom error instead of Panic(0x11).
pragma solidity ^0.8.20;

contract CleanRegistry {
    mapping(bytes32 => uint256) public slot;

    uint256 constant INCREMENT = uint256(bytes32(bytes1(0x01))); // 2^248

    error MaxQuestionsExceeded();

    // CLEAN fix: explicit `require(... < type(uint8).max)` guard before the
    // increment. Detector MUST NOT fire — the negative-regex matches and the
    // pattern is short-circuited.
    function incrementQuestionCount(bytes32 id) external {
        uint256 data = slot[id];
        // Lane-max guard — exactly the shape the DSL negative-regex recognises.
        require(uint8(data >> 248) < type(uint8).max, "MaxQuestionsExceeded");
        uint256 inc = uint256(1) << 248;
        data = data + inc;
        slot[id] = data;
    }

    // Alt clean shape: branch-form guard with `type(uint8).max` token AND an
    // explicit "Panic" mention — both shapes the negative regex accepts.
    function bumpResult(bytes32 id) external {
        uint256 data = slot[id];
        // Panic-mentioning guard — the regex token `Panic` short-circuits
        // the match before name/pos checks promote this to a finding.
        if (uint8(data >> 240) == type(uint8).max) revert MaxQuestionsExceeded(); // Panic(0x11) prevented
        uint256 inc = uint256(1) << 240;
        data = data + inc;
        slot[id] = data;
    }

    function readQuestionCount(bytes32 id) external view returns (uint8) {
        uint256 mask = 0xff;
        return uint8((slot[id] >> 248) & mask);
    }
}
