package transfer

type Packet struct{}

type RateLimitKeeper struct{}

type BankKeeper struct{}

type IBCModule struct {
	rateLimitKeeper RateLimitKeeper
	bankKeeper      BankKeeper
}

func (RateLimitKeeper) CheckRateLimitAndUpdateFlow(Packet) error { return nil }

func (RateLimitKeeper) UndoSend(Packet) error { return nil }

func (BankKeeper) SendCoinsFromModuleToAccount(Packet) error { return nil }

func (im IBCModule) OnRecvPacket(packet Packet) error {
	if err := im.rateLimitKeeper.CheckRateLimitAndUpdateFlow(packet); err != nil {
		return err
	}
	return im.bankKeeper.SendCoinsFromModuleToAccount(packet)
}

func (im IBCModule) OnTimeoutPacket(packet Packet) error {
	return im.rateLimitKeeper.UndoSend(packet)
}
