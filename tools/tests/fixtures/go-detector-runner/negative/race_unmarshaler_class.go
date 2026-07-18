// Pattern 39 stage-2 narrowing — NEGATIVE fixture for the
// ``unmarshaler`` suspect_class. Detector must NOT fire because
// encoding/json (and similar) Unmarshaler implementations are
// caller-synchronised by Go convention pre-publish.
package fixture

import "encoding/json"

type ConfigJSON struct {
	value string
	dirty bool
}

// L24 ABM: type-name suffix `JSON` triggers unmarshaler
// classification — caller-synchronised pre-publish.
func (c *ConfigJSON) UnmarshalJSON(data []byte) error {
	c.value = string(data)
	c.dirty = true
	return nil
}

type ProtoDecoder struct {
	buf  []byte
	read int
}

// L24 ABM: type-name suffix `Decoder` triggers unmarshaler
// classification.
func (p *ProtoDecoder) DecodeMsg(b []byte) error {
	p.buf = b
	p.read = len(b)
	return nil
}

type ScannerWrapper struct {
	bytes []byte
	count int
}

// L24 ABM: method name `Scan` (sql.Scanner contract) triggers
// unmarshaler classification.
func (s *ScannerWrapper) Scan(src interface{}) error {
	s.bytes = []byte("scanned")
	s.count++
	_ = json.Unmarshal
	return nil
}
