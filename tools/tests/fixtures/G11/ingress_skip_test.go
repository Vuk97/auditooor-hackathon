package types

// A *_test.go copy of the vuln shape - MUST be skipped by the file filter.
func (msg *MsgClaimSpecific) ValidateBasic() error {
	for _, asset := range msg.Assets {
		_ = asset
	}
	return nil
}
