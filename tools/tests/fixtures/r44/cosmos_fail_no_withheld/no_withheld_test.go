// cosmos_fail_no_withheld/no_withheld_test.go
// Severity: High
// ANTI-PATTERN: role separation present but NO withheld-artifact assertion loop.
// Rule 44 should fail with fail-no-withheld-artifact-assertion.
package cosmos_nowithheld

import (
	"testing"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/stretchr/testify/require"
)

func TestOpposedTrace_NoWithheldAssertion(t *testing.T) {
	// Role separation present (attacker and victim distinct).
	attackerAddr := sdk.AccAddress([]byte("attacker_address_bytes_1234_____"))
	victimAddr   := sdk.AccAddress([]byte("victim___address_bytes_5678_____"))

	require.NotEqual(t, attackerAddr, victimAddr)

	// This is an opposed-trace harness: attacker withholds tx-real.
	// But there is NO enumeration loop asserting the withheld artifact is absent.
	// (Missing: for msgType := range acceptedMsgs { require.NotEqual ... })

	// Attack-causality present.
	transferStatus := "FINALIZED"
	require.Equal(t, "FINALIZED", transferStatus,
		"transfer.Status -> FINALIZED")

	_ = attackerAddr
	_ = victimAddr
}
