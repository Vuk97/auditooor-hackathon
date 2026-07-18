// Pattern 35 — POSITIVE fixture for
//   go.go.panic.dereference_before_nil_check
//
// Mirrors Swival #028/#029/#042/#074 — function accepts a *T whose
// fields are read unconditionally; a nil caller (legitimate per Go's
// "zero value is valid" idiom) panics.
package fixture

type Options struct {
	Hash  []byte
	Label string
}

type Config struct {
	Endpoint string
	Timeout  int
}

type Request struct {
	Body []byte
	URL  string
}

// BUG: opts.Hash is read unconditionally; nil opts panics.
func ProcessOptions(opts *Options) []byte {
	return opts.Hash
}

// BUG: cfg.Endpoint is read directly with no nil-guard.
func ConnectWithConfig(cfg *Config) string {
	endpoint := cfg.Endpoint
	return endpoint
}

// BUG: req.URL accessed before any nil-check on req.
func RouteRequest(req *Request) string {
	url := req.URL
	if req == nil {
		return ""
	}
	return url
}
