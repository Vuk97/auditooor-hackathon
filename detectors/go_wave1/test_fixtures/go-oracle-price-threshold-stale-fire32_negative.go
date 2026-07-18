// fixture: negative - full validation or helper-only oracle logic.
package keeper

import (
	"errors"
	"time"
)

const quoteScale int64 = 1_000_000

var (
	ErrBadDeviation = errors.New("bad deviation")
	ErrStalePrice   = errors.New("stale price")
	ErrWrongSource  = errors.New("wrong source")
)

type Context struct{}

func (Context) BlockTime() time.Time { return time.Now() }

type OraclePrice struct {
	Value     int64
	UpdatedAt time.Time
	SourceID  string
}

type Position struct {
	Account   string
	Debt      int64
	LastPrice int64
}

type Oracle struct{}
type SettlementKeeper struct{}

func (Oracle) GetPrice(ctx Context, marketID string) (OraclePrice, error) {
	return OraclePrice{}, nil
}

func (SettlementKeeper) SettleLiquidation(ctx Context, account string, seized int64) {}

type Keeper struct {
	oracle          Oracle
	settlement      SettlementKeeper
	maxAge          time.Duration
	maxDeviationBps int64
	trustedSourceID string
}

func deviationBps(a int64, b int64) int64 {
	if a > b {
		return a - b
	}
	return b - a
}

func (k Keeper) LiquidateWithFullOracleValidation(ctx Context, marketID string, position Position) error {
	price, err := k.oracle.GetPrice(ctx, marketID)
	if err != nil {
		return err
	}
	if price.SourceID != k.trustedSourceID {
		return ErrWrongSource
	}
	if ctx.BlockTime().Sub(price.UpdatedAt) > k.maxAge {
		return ErrStalePrice
	}
	if deviationBps(price.Value, position.LastPrice) > k.maxDeviationBps {
		return ErrBadDeviation
	}
	seized := position.Debt * price.Value / quoteScale
	k.settlement.SettleLiquidation(ctx, position.Account, seized)
	return nil
}

func (k Keeper) GetOraclePriceAge(ctx Context, marketID string) (time.Duration, error) {
	price, err := k.oracle.GetPrice(ctx, marketID)
	if err != nil {
		return 0, err
	}
	return ctx.BlockTime().Sub(price.UpdatedAt), nil
}

func (k Keeper) ReadUnvalidatedPriceForTelemetry(ctx Context, marketID string) (int64, error) {
	price, err := k.oracle.GetPrice(ctx, marketID)
	if err != nil {
		return 0, err
	}
	return price.Value, nil
}

func (k Keeper) StoreDeviationMetric(ctx Context, marketID string, position Position) error {
	price, err := k.oracle.GetPrice(ctx, marketID)
	if err != nil {
		return err
	}
	if deviationBps(price.Value, position.LastPrice) > k.maxDeviationBps {
		return ErrBadDeviation
	}
	return nil
}
