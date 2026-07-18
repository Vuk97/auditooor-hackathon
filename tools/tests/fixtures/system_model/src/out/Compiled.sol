// build artifact - must be excluded by the extractor's _SKIP_DIR_PARTS filter
contract Compiled {
    modifier onlyShouldBeSkipped() { _; }
}
