package negative

// Negative: this is not a msgServer/Keeper/Server receiver — it's a
// plain helper struct. Even though it writes and has no auth check,
// the detector requires a msgServer-shape receiver. Should NOT fire.
type helper struct {
	data map[string]string
}

func (h *helper) SetThing(k, v string) {
	h.data[k] = v
}

func (h *helper) DeleteThing(k string) {
	delete(h.data, k)
}
