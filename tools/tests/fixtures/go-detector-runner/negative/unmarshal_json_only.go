// Pattern 28 — NEGATIVE fixture (Refinement 2): json.Unmarshal alone.
// stdlib JSON rejects trailing non-whitespace bytes (verified L20
// runtime), so pattern 28 must NOT fire even though there is no
// explicit len(rest)==0 guard.
package fixture

import "encoding/json"

type Payload struct {
	Value int `json:"value"`
}

// SAFE under L21 ABA refinement 2: json.Unmarshal is excluded from
// the permissive-parser set.
func ParsePayloadJSON(buf []byte) (Payload, error) {
	var p Payload
	if err := json.Unmarshal(buf, &p); err != nil {
		return Payload{}, err
	}
	return p, nil
}
