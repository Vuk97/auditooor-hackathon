package transfer

type Packet struct{}

type BankKeeper struct{}

type IBCModule struct {
	bankKeeper BankKeeper
}

func (BankKeeper) SendCoinsFromModuleToAccount(Packet) error { return nil }

func (im IBCModule) OnRecvPacket(packet Packet) error {
	return im.bankKeeper.SendCoinsFromModuleToAccount(packet)
}

func (im IBCModule) OnTimeoutPacket(packet Packet) error {
	return im.bankKeeper.SendCoinsFromModuleToAccount(packet)
}
