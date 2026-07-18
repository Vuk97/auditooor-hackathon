package positive

import "github.com/cosmos/cosmos-sdk/codec"

type Server struct {
	cdc codec.Codec
}

// HandleDecode decodes the incoming tx before any fee/gas guard.
// This is the canonical decode-pre-fee CPU exhaustion shape.
func (s *Server) HandleDecode(raw []byte) error {
	var msg AnyMsg
	if err := s.cdc.Unmarshal(raw, &msg); err != nil {
		return err
	}
	// ... then arbitrary processing on msg ...
	return s.process(&msg)
}

type AnyMsg struct{}

func (s *Server) process(*AnyMsg) error { return nil }
