// Pattern 9 — NEGATIVE fixture.
//
// Same shape as the positive fixture, but the body explicitly cross-checks
// the success- and timeout-path commitments via bytes.Equal before allowing
// settlement.
package fixturen

import "bytes"

type ChannelStateN struct {
	HtlcSuccessTx []byte
	HtlcTimeoutTx []byte
}

func buildSuccessTxN() []byte { return []byte{0x01} }
func buildTimeoutTxN() []byte { return []byte{0x02} }

func ResolveHtlcSafe(s *ChannelStateN) error {
	s.HtlcSuccessTx = buildSuccessTxN()
	s.HtlcTimeoutTx = buildTimeoutTxN()
	if bytes.Equal(s.HtlcSuccessTx, s.HtlcTimeoutTx) {
		return nil
	}
	return nil
}
