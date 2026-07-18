// Pattern 39 stage-2 narrowing — NEGATIVE fixture for the
// ``ent_generated`` suspect_class. Detector must NOT fire because
// ent-generated builder code is caller-synchronised by the
// transaction layer above it.
//
// NOTE: the fixture copy-step writes this file under an ``ent/``
// subdirectory of the test workspace so the path-based classifier
// fires. See ``test_race_pattern39_stage2_ent_generated_suppressed``.
package ent

type LeafCreate struct {
	mutation map[string]interface{}
	value    string
	dirty    bool
}

// ent-generated SetX setter shape — would fire pattern 39 absent
// the path-based ent_generated bucket; suppressed because the
// ent transaction layer caller-synchronises.
func (lc *LeafCreate) SetValue(v string) *LeafCreate {
	lc.value = v
	lc.dirty = true
	return lc
}

func (lc *LeafCreate) SetDirty(b bool) *LeafCreate {
	lc.dirty = b
	return lc
}

func (lc *LeafCreate) Build() *LeafCreate {
	lc.value = "built"
	return lc
}
