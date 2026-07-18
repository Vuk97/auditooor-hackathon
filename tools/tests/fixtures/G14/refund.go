package keeper

import (
	"errors"
	"fmt"
)

// Package-level sentinel errors. Downstream guards key their protected safety
// branch off the IDENTITY of these values (errors.Is / == comparison), so any
// producer that wraps them lossily (non-%w) severs the chain and the guard dies.
var (
	ErrInsufficientFunds = errors.New("insufficient funds")
	ErrPaused            = errors.New("vault paused")
	ErrOrphan            = errors.New("orphan: no guard keys off this")
)

// refundVuln mirrors the PoC-anchor nuva payout.go shape: it wraps the sentinel
// ErrInsufficientFunds with %v (NON-%w), so the returned error no longer
// Unwraps to the sentinel. getReason (below) keys the refund category off
// errors.Is(err, ErrInsufficientFunds) - that guard is now DEAD. FIRES.
func (k *Keeper) refundVuln(shortfall int64) error {
	if shortfall > 0 {
		return fmt.Errorf("payout shortfall %d: %v", shortfall, ErrInsufficientFunds)
	}
	return nil
}

// getReason is the co-located sentinel-identity guard (errors.Is). Because
// refundVuln dropped the sentinel with %v, this branch silently never fires.
func (k *Keeper) getReason(err error) string {
	if errors.Is(err, ErrInsufficientFunds) {
		return "insufficient-funds"
	}
	return "other"
}

// pauseVuln wraps the ErrPaused sentinel with %v; isPaused guards it via a
// DIRECT identity compare (err == ErrPaused) rather than errors.Is. FIRES
// (exercises the ==/!= guard arm).
func (k *Keeper) pauseVuln(id uint64) error {
	if k.isDue(id) {
		return fmt.Errorf("vault %d not eligible: %v", id, ErrPaused)
	}
	return nil
}

func (k *Keeper) isPaused(err error) bool {
	if err == ErrPaused {
		return true
	}
	return false
}

// closeVuln wraps a PACKAGE-QUALIFIED sentinel sdkerrors.ErrClosed with %v;
// checkClosed guards the same qualified sentinel via errors.Is. FIRES
// (exercises qualified-name matching).
func (k *Keeper) closeVuln(id uint64) error {
	return fmt.Errorf("channel %d: %v", id, sdkerrors.ErrClosed)
}

func (k *Keeper) checkClosed(err error) bool {
	return errors.Is(err, sdkerrors.ErrClosed)
}

// refundClean is the benign sibling: it wraps ErrInsufficientFunds with %w, so
// the sentinel chain is PRESERVED and getReason's guard still matches. SILENT.
func (k *Keeper) refundClean(shortfall int64) error {
	if shortfall > 0 {
		return fmt.Errorf("payout shortfall %d: %w", shortfall, ErrInsufficientFunds)
	}
	return nil
}

// orphanVuln wraps ErrOrphan with %v (lossy) but NO code anywhere guards on
// ErrOrphan (no errors.Is / == ErrOrphan). Without a sentinel-identity guard to
// render dead there is no bug - this is the Pattern-29 / bare-wrap shape, NOT
// G14. SILENT (guard-co-location is load-bearing; disjoint from Pattern 29).
func (k *Keeper) orphanVuln(id uint64) error {
	return fmt.Errorf("orphan %d: %v", id, ErrOrphan)
}
