// Fixture: a config-manager-getter shape (docstring anchor: a Pods-style
// IConfigurationManager). The target imports this and CALLS getParameter +
// the per-module owner getter. The synthesizer must back getParameter with a
// SETTABLE per-key getter so the cap/inflation exploit can drive the parameter.
// NO target literal is keyed on in the synthesizer logic; this is a generic
// config-getter SHAPE.
interface IConfigGetter {
    function getParameter(bytes32 key) external view returns (uint256);
    function owner() external view returns (address);
    function setParameter(bytes32 key, uint256 value) external;
}
