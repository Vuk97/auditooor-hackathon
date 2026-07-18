// fixture: positive - oracle values immediately update protocol risk state.
package keeper

type Context struct{}

const quoteScale int64 = 1_000_000
const thresholdScale int64 = 10_000

type OracleQuote struct {
	Value      int64
	UpdatedAt  int64
	Confidence int64
}

type MedianQuote struct {
	Median    int64
	UpdatedAt int64
}

type ThresholdQuote struct {
	Threshold  int64
	UpdatedAt  int64
	Confidence int64
}

type Position struct {
	Account string
	Debt    int64
	Size    int64
	Margin  int64
}

type Oracle struct{}
type MedianOracle struct{}
type ThresholdFeed struct{}
type SettlementKeeper struct{}
type MarginKeeper struct{}

func (Oracle) GetPrice(ctx Context, marketID string) (OracleQuote, error) {
	return OracleQuote{}, nil
}

func (Oracle) LatestQuote(ctx Context, marketID string) (OracleQuote, error) {
	return OracleQuote{}, nil
}

func (MedianOracle) MedianPrice(ctx Context, asset string) (MedianQuote, error) {
	return MedianQuote{}, nil
}

func (ThresholdFeed) ReadThreshold(ctx Context, asset string) (ThresholdQuote, error) {
	return ThresholdQuote{}, nil
}

func (SettlementKeeper) SettleLiquidation(ctx Context, account string, seized int64) {}
func (SettlementKeeper) SettleFunding(ctx Context, account string, payment int64) {}
func (MarginKeeper) OpenPosition(ctx Context, account string, margin int64) {}

type Keeper struct {
	oracle     Oracle
	median     MedianOracle
	thresholds ThresholdFeed
	settlement SettlementKeeper
	margin     MarginKeeper
	reserves   map[string]int64
}

func (k Keeper) SettleLiquidationFromRawOracle(ctx Context, marketID string, position Position) error {
	price, err := k.oracle.GetPrice(ctx, marketID)
	if err != nil {
		return err
	}
	seized := position.Debt * price.Value / quoteScale
	k.settlement.SettleLiquidation(ctx, position.Account, seized)
	return nil
}

func (k Keeper) ApplyMarginFromMedianIndex(ctx Context, asset string, account string, collateral int64) error {
	index, err := k.median.MedianPrice(ctx, asset)
	if err != nil {
		return err
	}
	margin := collateral * index.Median / quoteScale
	k.margin.OpenPosition(ctx, account, margin)
	return nil
}

func (k Keeper) UpdateReservesFromThreshold(ctx Context, asset string, currentReserve int64) error {
	threshold, err := k.thresholds.ReadThreshold(ctx, asset)
	if err != nil {
		return err
	}
	reserve := currentReserve * threshold.Threshold / thresholdScale
	k.reserves[asset] = reserve
	return nil
}

func (k Keeper) SettleFundingFromCachedQuote(ctx Context, marketID string, position Position) error {
	quote, err := k.oracle.LatestQuote(ctx, marketID)
	if err != nil {
		return err
	}
	payment := position.Size * quote.Value / quoteScale
	k.settlement.SettleFunding(ctx, position.Account, payment)
	return nil
}
