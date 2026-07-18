// Pattern 39 stage-2 narrowing — NEGATIVE fixture for the
// ``setter`` suspect_class. Detector must NOT fire because
// SetX/WithX builder/configuration setters are caller-synchronised
// by Go convention.
package fixture

type Builder struct {
	host string
	port int
	tls  bool
}

// SetX builder pattern — caller-synchronised by Go convention.
func (b *Builder) SetHost(h string) *Builder {
	b.host = h
	return b
}

func (b *Builder) SetPort(p int) *Builder {
	b.port = p
	return b
}

// WithX builder pattern — same convention.
func (b *Builder) WithTLS(enabled bool) *Builder {
	b.tls = enabled
	return b
}
