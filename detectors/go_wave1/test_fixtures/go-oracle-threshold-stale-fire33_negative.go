// fixture: negative - guarded state writes and helper-only oracle reads.
package keeper

import "errors"

type Context struct {
	now int64
}

func (c Context) BlockTimeUnix() int64 { return c.now }

const quoteScale int64 = 1_000_000
const thresholdScale int64 = 10_000

var (
	ErrBadDeviation = errors.New("bad deviation")
	ErrBadPrice     = errors.New("bad price")
	ErrStalePrice   = errors.New("stale price")
	ErrWideConf     = errors.New("wide confidence")
)

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
	Account   string
	Debt      int64
	Size      int64
	LastPrice int64
}

type Oracle struct{}
type MedianOracle struct{}
type ThresholdFeed struct{}
type SettlementKeeper struct{}
type MarginKeeper struct{}
type Metrics struct {
	LastOraclePrice int64
}

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
	oracle          Oracle
	median          MedianOracle
	thresholds      ThresholdFeed
	settlement      SettlementKeeper
	margin          MarginKeeper
	metrics         Metrics
	reserves        map[string]int64
	maxAge          int64
	maxConfidence   int64
	maxDeviationBps int64
}

func deviationBps(a int64, b int64) int64 {
	if a > b {
		return a - b
	}
	return b - a
}

func (k Keeper) ValidateOracleQuote(ctx Context, quote OracleQuote, lastPrice int64) error {
	if quote.Value <= 0 {
		return ErrBadPrice
	}
	if ctx.BlockTimeUnix()-quote.UpdatedAt > k.maxAge {
		return ErrStalePrice
	}
	if quote.Confidence > k.maxConfidence {
		return ErrWideConf
	}
	if deviationBps(quote.Value, lastPrice) > k.maxDeviationBps {
		return ErrBadDeviation
	}
	return nil
}

func (k Keeper) SettleLiquidationWithFreshnessConfidenceAndDeviation(ctx Context, marketID string, position Position) error {
	price, err := k.oracle.GetPrice(ctx, marketID)
	if err != nil {
		return err
	}
	if err := k.ValidateOracleQuote(ctx, price, position.LastPrice); err != nil {
		return err
	}
	seized := position.Debt * price.Value / quoteScale
	k.settlement.SettleLiquidation(ctx, position.Account, seized)
	return nil
}

func (k Keeper) OpenMarginWithInlineFreshnessAndZeroGuard(ctx Context, asset string, account string, collateral int64) error {
	index, err := k.median.MedianPrice(ctx, asset)
	if err != nil {
		return err
	}
	if index.Median <= 0 {
		return ErrBadPrice
	}
	if ctx.BlockTimeUnix()-index.UpdatedAt > k.maxAge {
		return ErrStalePrice
	}
	margin := collateral * index.Median / quoteScale
	k.margin.OpenPosition(ctx, account, margin)
	return nil
}

func (k Keeper) UpdateReserveWithHeartbeatAndConfidence(ctx Context, asset string, currentReserve int64) error {
	threshold, err := k.thresholds.ReadThreshold(ctx, asset)
	if err != nil {
		return err
	}
	if ctx.BlockTimeUnix()-threshold.UpdatedAt > k.maxAge {
		return ErrStalePrice
	}
	if threshold.Confidence > k.maxConfidence {
		return ErrWideConf
	}
	reserve := currentReserve * threshold.Threshold / thresholdScale
	k.reserves[asset] = reserve
	return nil
}

func (k Keeper) SettleFundingWithMaxDeviation(ctx Context, marketID string, position Position) error {
	quote, err := k.oracle.LatestQuote(ctx, marketID)
	if err != nil {
		return err
	}
	if deviationBps(quote.Value, position.LastPrice) > k.maxDeviationBps {
		return ErrBadDeviation
	}
	payment := position.Size * quote.Value / quoteScale
	k.settlement.SettleFunding(ctx, position.Account, payment)
	return nil
}

func (k Keeper) GetOraclePriceAge(ctx Context, marketID string) (int64, error) {
	price, err := k.oracle.GetPrice(ctx, marketID)
	if err != nil {
		return 0, err
	}
	return ctx.BlockTimeUnix() - price.UpdatedAt, nil
}

func (k Keeper) StoreOraclePriceMetric(ctx Context, marketID string) error {
	price, err := k.oracle.GetPrice(ctx, marketID)
	if err != nil {
		return err
	}
	k.metrics.LastOraclePrice = price.Value
	return nil
}
