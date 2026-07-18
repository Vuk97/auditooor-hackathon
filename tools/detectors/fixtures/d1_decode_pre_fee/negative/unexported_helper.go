package negative

import "google.golang.org/protobuf/proto"

// unexportedDecode is a private helper not reachable from the wire; should not fire.
func unexportedDecode(b []byte) (*Inner, error) {
	w := &Inner{}
	if err := proto.Unmarshal(b, w); err != nil {
		return nil, err
	}
	return w, nil
}

type Inner struct{}
