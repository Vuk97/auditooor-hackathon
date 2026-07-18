package txinclude

// Fixture for G7 go.crypto.counter.onesided_acceptance.
// Each function isolates one polarity/operator combination.

// REJECT branch, ">=" -> boundary-equal is REJECTED -> CLEAN (benign shape,
// mirrors optimism nonce_manager.InsertGap).
func rejectGE(nonce uint64, nextNonce uint64) bool {
	if nonce >= nextNonce { // no fire: equal is rejected
		return false
	}
	return true
}

// REJECT branch, ">" -> boundary-equal is ADMITTED -> FIRE (the mutant shape:
// admits nonce == nextNonce -> reuse).
func rejectGT(nonce uint64, nextNonce uint64) bool {
	if nonce > nextNonce { // FIRE: equal admitted
		return false
	}
	return true
}

// ACCEPT branch, ">=" -> boundary-equal is ADMITTED into accept -> FIRE.
func acceptGE(seq uint64, expected uint64) bool {
	if seq >= expected { // FIRE: equal accepted (replay)
		process(seq)
		return true
	}
	return false
}

// ACCEPT branch, ">" -> boundary-equal NOT accepted -> CLEAN.
func acceptGT(seq uint64, expected uint64) bool {
	if seq > expected { // no fire: equal not accepted
		process(seq)
		return true
	}
	return false
}

// ACCEPT branch, "==" -> boundary-equal accepted -> FIRE.
func acceptEQ(sequence uint64, want uint64) bool {
	if sequence == want { // FIRE: accept exactly-equal without successor check
		process(sequence)
		return true
	}
	return false
}

// FP-guard: strict-successor "== stored + 1" present -> whole function
// SUPPRESSED (correct monotone-successor validation).
func successorGuarded(seq uint64, expected uint64) bool {
	if seq >= expected { // would fire, but suppressed by successor form below
		if seq == expected+1 {
			process(seq)
		}
		return true
	}
	return false
}

// FP-guard: nil operand -> not a reuse guard -> CLEAN.
func nilCheck(nonce *uint64) bool {
	if nonce == nil { // no fire: nil check
		return false
	}
	return true
}

// FP-guard: comment containing "if seq >= x {" must not match -> CLEAN.
func commentOnly(x uint64) bool {
	// historical note: if seq >= x { we used to reject here }
	return x > 0
}

// Non-nonce comparison -> out of scope -> CLEAN.
func nonNonce(a uint64, b uint64) bool {
	if a >= b {
		return true
	}
	return false
}

func process(x uint64) {}
