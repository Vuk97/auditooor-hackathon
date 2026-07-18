package positive

import "google.golang.org/protobuf/proto"

// ExtractAny extracts a protobuf Any without checking fees or gas first.
func ExtractAny(b []byte) (*Wrapper, error) {
	w := &Wrapper{}
	if err := proto.Unmarshal(b, w); err != nil {
		return nil, err
	}
	return w, nil
}

type Wrapper struct{}
