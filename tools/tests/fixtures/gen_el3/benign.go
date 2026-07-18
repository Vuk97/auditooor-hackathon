package x
func StoreSafe(raw []byte, store KVStore) error {
    var msg Msg
    if err := proto.Unmarshal(raw, &msg); err != nil {
        return err
    }
    canon, _ := proto.Marshal(&msg)
    key := sha256.Sum256(canon)
    store.Set(key[:], canon)
    return nil
}
func StoreByField(raw []byte, store KVStore) error {
    var msg Msg
    proto.Unmarshal(raw, &msg)
    store.Set([]byte(msg.Id), raw)
    return nil
}
