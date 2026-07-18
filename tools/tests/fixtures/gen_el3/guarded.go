package x
func StoreGuarded(raw []byte, store KVStore) error {
    var msg Msg
    if err := proto.Unmarshal(raw, &msg); err != nil {
        return err
    }
    canon, _ := proto.Marshal(&msg)
    if !bytes.Equal(canon, raw) {
        return errNonCanonical
    }
    key := sha256.Sum256(raw)
    store.Set(key[:], raw)
    return nil
}
