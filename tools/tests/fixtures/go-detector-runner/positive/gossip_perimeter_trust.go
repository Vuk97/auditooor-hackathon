// Pattern 6 — POSITIVE fixture for
//   go.consensus.gossip_perimeter_trust
//
// File registers a gRPC server, opts into tls.NoClientCert (perimeter
// trust), and exposes a Gossip handler whose body does NOT call any
// VerifySignature / VerifyECDSASignature.
package fixture

type tlsCfg struct {
	ClientAuth int
}

var tls = struct{ NoClientCert int }{NoClientCert: 0}

type grpcServer struct{}

func RegisterGossipServer(s *grpcServer, impl interface{}) {
	_ = s
	_ = impl
}

type Server struct{}

type GossipMsg struct {
	Payload []byte
	Sender  string
}

func init() {
	cfg := tlsCfg{ClientAuth: tls.NoClientCert}
	_ = cfg
	s := &grpcServer{}
	RegisterGossipServer(s, &Server{})
}

func (s *Server) Gossip(msg *GossipMsg) error {
	// No signature verification — perimeter-trust assumption.
	_ = msg.Payload
	return nil
}
