// Pattern 6 — NEGATIVE fixture.
//
// Same perimeter setup as the positive case, but the Gossip handler calls
// VerifyECDSASignature before accepting the payload — defence in depth, no
// finding.
package fixturen

var tls = struct{ NoClientCert int }{NoClientCert: 0}

type grpcServer struct{}

func RegisterGossipServer(s *grpcServer, impl interface{}) {
	_ = s
	_ = impl
}

type Server struct{}

type GossipMsg struct {
	Payload []byte
	Sig     []byte
}

func VerifyECDSASignature(pub, msg, sig []byte) bool {
	_ = pub
	_ = msg
	_ = sig
	return true
}

func init() {
	_ = tls.NoClientCert
	s := &grpcServer{}
	RegisterGossipServer(s, &Server{})
}

func (s *Server) Gossip(msg *GossipMsg) error {
	if !VerifyECDSASignature(nil, msg.Payload, msg.Sig) {
		return nil
	}
	return nil
}
