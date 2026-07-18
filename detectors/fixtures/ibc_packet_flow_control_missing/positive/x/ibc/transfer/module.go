package transfer

type Packet struct {
	Data []byte
}

type BankKeeper struct{}

type IBCModule struct {
	bankKeeper BankKeeper
	escrow     string
}

func (BankKeeper) SendCoinsFromModuleToAccount(Packet) error { return nil }
func (BankKeeper) SendCoins(Packet) error { return nil }

func decodePacket(packet Packet) Packet { return packet }

func (im IBCModule) OnRecvPacket(packet Packet) error {
	decoded := decodePacket(packet)
	return im.bankKeeper.SendCoinsFromModuleToAccount(decoded)
}

func (im IBCModule) OnTimeoutPacket(packet Packet) error {
	refund := decodePacket(packet)
	return im.bankKeeper.SendCoins(refund)
}
