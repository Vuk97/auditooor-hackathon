package x
func StoreMsg(raw []byte, store KVStore) error {
    var msg Msg
    if err := proto.Unmarshal(raw, &msg); err != nil {
        return err
    }
    key := sha256.Sum256(raw)
    store.Set(key[:], raw)
    return nil
}
func Dedup(bz []byte, seen map[string]bool) bool {
    var m Msg
    proto.Unmarshal(bz, &m)
    if seen[string(bz)] {
        return true
    }
    seen[string(bz)] = true
    return false
}
