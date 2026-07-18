pragma solidity ^0.8.20;

interface ITranscript {
    function observe(bytes32 value) external;
    function challenge() external returns (bytes32);
}

contract R94LoopFiatShamirMissingObservationPositive {
    ITranscript public transcript;

    constructor(ITranscript transcript_) {
        transcript = transcript_;
    }

    function verifyTranscript(bytes32 publicInput) external returns (bytes32) {
        publicInput;
        return transcript.challenge();
    }
}
