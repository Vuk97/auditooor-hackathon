// Pattern 9 — POSITIVE fixture for
//   go.lightning.htlc_settlement_state_drift
//
// The function constructs both the success-path TX and the timeout-path
// TX in the same body, but never cross-checks them. If the off-chain
// commitment view diverges from the on-chain script, neither side notices.
package fixture

type ChannelState struct {
	HtlcSuccessTx []byte
	HtlcTimeoutTx []byte
}

func buildSuccessTx() []byte { return []byte{0x01} }
func buildTimeoutTx() []byte { return []byte{0x02} }

func ResolveHtlc(s *ChannelState) error {
	s.HtlcSuccessTx = buildSuccessTx()
	s.HtlcTimeoutTx = buildTimeoutTx()
	// No bytes.Equal / require.Equal / CrossCheck between the two — and no
	// reflection-based comparator either. The success/timeout views can
	// drift silently across upgrades.
	if len(s.HtlcSuccessTx) == 0 {
		return nil
	}
	return nil
}
