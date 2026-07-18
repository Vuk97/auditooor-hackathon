package negative

import "github.com/cosmos/cosmos-sdk/codec"

type Server struct {
	cdc codec.Codec
}

// HandleDecode charges gas BEFORE unmarshal, so this is safe.
func (s *Server) HandleDecode(ctx Ctx, raw []byte) error {
	ctx.GasMeter().ConsumeGas(uint64(len(raw))*10, "decode")
	var msg AnyMsg
	if err := s.cdc.Unmarshal(raw, &msg); err != nil {
		return err
	}
	return nil
}

type Ctx struct{}

func (Ctx) GasMeter() Gas    { return Gas{} }

type Gas struct{}

func (Gas) ConsumeGas(uint64, string) {}

type AnyMsg struct{}
