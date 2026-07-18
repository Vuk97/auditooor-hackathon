// Pattern 35 — NEGATIVE fixture: every pointer-typed parameter is
// nil-checked BEFORE any field dereference. Detector must NOT fire.
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

// SAFE: explicit `opts == nil` early-return.
func ProcessOptionsSafe(opts *Options) []byte {
	if opts == nil {
		return nil
	}
	return opts.Hash
}

// SAFE: `cfg != nil` precondition before field deref.
func ConnectWithConfigSafe(cfg *Config) string {
	if cfg != nil {
		return cfg.Endpoint
	}
	return ""
}

// SAFE: nil-check is done up front; remainder of body uses fields
// safely.
func RouteRequestSafe(req *Request) string {
	if req == nil {
		return ""
	}
	return req.URL
}

// SAFE: function takes no pointer parameters at all.
func StaticHelper() string {
	return "hello"
}
