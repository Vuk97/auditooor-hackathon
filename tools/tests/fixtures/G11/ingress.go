package types

// G11 fixtures - external-ingress unbounded loop / panic.

// vulnMsg: Msg receiver ValidateBasic ranges over an attacker slice with NO
// len cap -> FIRES (range sink). Mirrors the sei message_claim_specific.go:45
// natural instance.
func (msg *MsgClaimSpecific) ValidateBasic() error {
	for _, asset := range msg.Assets {
		_ = asset
	}
	return nil
}

// vulnMake: a *...Request handler allocates make([]T, req.Count) with no cap
// -> FIRES (make_slice sink, rpc ingress).
func (s *Server) DoWork(req *WorkRequest) error {
	buf := make([]byte, req.Count)
	_ = buf
	return nil
}

// vulnDiv: divisor is an attacker field, no zero-guard -> FIRES (divmod sink).
func (msg *MsgRate) ValidateBasic() error {
	x := 1000 / msg.Rate
	_ = x
	return nil
}

// benignCapped: a sibling ValidateBasic that CAPS len before the range ->
// SILENT (dominating len guard). This is the FP-guard benign case.
func (msg *MsgCapped) ValidateBasic() error {
	if len(msg.Assets) > 256 {
		return errTooMany
	}
	for _, asset := range msg.Assets {
		_ = asset
	}
	return nil
}

// benignZeroGuard: divisor guarded by a zero-check before the div -> SILENT.
func (msg *MsgGuardedRate) ValidateBasic() error {
	if msg.Rate == 0 {
		return errZero
	}
	x := 1000 / msg.Rate
	_ = x
	return nil
}

// accessorGetter: an accessor/serializer ranges over the same slice but is
// NOT an ingress handler -> SILENT (accessor-name FP-guard).
func (msg *MsgClaimSpecific) GetIAssets() (res []IAsset) {
	for _, a := range msg.Assets {
		res = append(res, a)
	}
	return
}

// localOnly: ranges over a purely LOCAL slice, not a tainted ingress root ->
// SILENT (taint-gate: no external entry point).
func Helper() int {
	local := []int{1, 2, 3}
	n := 0
	for _, v := range local {
		n += v
	}
	return n
}
