// SPDX-License-Identifier: MIT
// Fixture: packed-lane-increment-no-overflow-guard — VULNERABLE
// Detector MUST fire on this contract.
//
// Polymarket Draft 7 shape: a Registry-style contract packs a uint8 lane per
// id into a single uint256 slot and increments via `slot += INCREMENT` where
// INCREMENT is the lane's bit-position constant (here 2^248, the byte-0 lane).
// No `< 256` / `< type(uint8).max` cap → the 256th call panics on solc >=0.8
// (or silently corrupts neighbouring lanes under `unchecked`).
pragma solidity ^0.8.20;

contract VulnRegistry {
    // Single uint256 slot packs:
    //   byte 0  : questionCount  (uint8)
    //   byte 1  : determined flag (uint8)
    //   byte 2  : result          (uint8)
    //   bytes 3-4 : feeBips       (uint16)
    //   bytes 12-31 : oracle      (address)
    mapping(bytes32 => uint256) public slot;

    // Polymarket Draft 7 INCREMENT — adds 1 to the byte-0 lane via shift-mask.
    uint256 constant INCREMENT = uint256(bytes32(bytes1(0x01))); // 2^248

    // VULN: increments packed lane via `<<` shifted constant with no
    // `< type(uint8).max` / `< 255` guard. At qCount==255, the next call
    // panics 0x11 on solc>=0.8; under unchecked it would silently carry into
    // the `determined` flag (byte 1). Detector MUST fire — contract name
    // matches `Registry`, function name matches `increment[A-Z]\w*`, body
    // shows `<< 248` (packed-lane indicator), no overflow guard.
    function incrementQuestionCount(bytes32 id) external {
        uint256 data = slot[id];
        // Packed-lane indicator: explicit bit-shift on the lane constant.
        uint256 inc = uint256(1) << 248;
        data = data + inc;
        slot[id] = data;
    }

    // Helper using `>>` and a `mask` — also packed-lane evidence; intentionally
    // co-located so the regex anchors trigger.
    function readQuestionCount(bytes32 id) external view returns (uint8) {
        uint256 mask = 0xff;
        return uint8((slot[id] >> 248) & mask);
    }
}
