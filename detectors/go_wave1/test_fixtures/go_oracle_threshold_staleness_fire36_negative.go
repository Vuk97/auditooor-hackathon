// fixture: negative - oracle threshold checks are fresh, symmetric, and pair-bound.
package keeper

import "errors"

const priceScale int64 = 1_000_000

var (
	ErrBadDeviation = errors.New("bad deviation")
	ErrBadPrice     = errors.New("bad price")
	ErrStalePrice   = errors.New("stale price")
	ErrWrongPair    = errors.New("wrong pair")
)

type Context struct {
	now int64
}

func (c Context) BlockTimeUnix() int64 { return c.now }

type PriceReport struct {
	Price      int64
	UpdatedAt  int64
	RoundID    uint64
	PairID     string
	MarketID   string
	BaseDenom  string
	QuoteDenom string
}

type Oracle struct{}
type Metrics struct {
	LastOraclePrice int64
}

func (Oracle) FetchPrice(ctx Context, pair string) (PriceReport, error) {
	return PriceReport{}, nil
}

func (Oracle) FetchMedian(ctx Context, marketID string) (PriceReport, error) {
	return PriceReport{}, nil
}

func absDiff(a int64, b int64) int64 {
	if a > b {
		return a - b
	}
	return b - a
}

type Keeper struct {
	oracle          Oracle
	metrics         Metrics
	marketPrices    map[string]int64
	medianPrices    map[string]int64
	thresholdPrices map[string]int64
	riskPrices      map[string]int64
	lastPrices       map[string]int64
	maxAge          int64
	maxDeviationBps int64
	minPrice        int64
	maxPrice        int64
}

func (k Keeper) UpdatePairPriceWithFullFreshnessAndDeviation(ctx Context, pair string) error {
	report, err := k.oracle.FetchPrice(ctx, pair)
	if err != nil {
		return err
	}
	if report.PairID != pair {
		return ErrWrongPair
	}
	if ctx.BlockTimeUnix()-report.UpdatedAt > k.maxAge {
		return ErrStalePrice
	}
	if report.Price < k.minPrice {
		return ErrBadPrice
	}
	if report.Price > k.maxPrice {
		return ErrBadPrice
	}
	if absDiff(report.Price, k.lastPrices[pair]) > k.maxDeviationBps {
		return ErrBadDeviation
	}
	k.marketPrices[pair] = report.Price
	return nil
}

func (k Keeper) AcceptMedianWithSymmetricBounds(ctx Context, marketID string) error {
	median, err := k.oracle.FetchMedian(ctx, marketID)
	if err != nil {
		return err
	}
	if median.MarketID != marketID {
		return ErrWrongPair
	}
	if ctx.BlockTimeUnix()-median.UpdatedAt > k.maxAge {
		return ErrStalePrice
	}
	if median.Price < k.minPrice {
		return ErrBadPrice
	}
	if median.Price > k.maxPrice {
		return ErrBadPrice
	}
	k.medianPrices[marketID] = median.Price
	return nil
}

func (k Keeper) UpdateThresholdWithPairBaseline(ctx Context, pair string) error {
	report, err := k.oracle.FetchPrice(ctx, pair)
	if err != nil {
		return err
	}
	if ctx.BlockTimeUnix()-report.UpdatedAt > k.maxAge {
		return ErrStalePrice
	}
	if absDiff(report.Price, k.lastPrices[pair]) > k.maxDeviationBps {
		return ErrBadDeviation
	}
	k.thresholdPrices[pair] = report.Price / priceScale
	return nil
}

func (k Keeper) UpdateRiskPriceThenRefreshBaseline(ctx Context, pair string) error {
	report, err := k.oracle.FetchPrice(ctx, pair)
	if err != nil {
		return err
	}
	oldPrice := k.lastPrices[pair]
	if ctx.BlockTimeUnix()-report.UpdatedAt > k.maxAge {
		return ErrStalePrice
	}
	if absDiff(report.Price, oldPrice) > k.maxDeviationBps {
		return ErrBadDeviation
	}
	k.riskPrices[pair] = report.Price
	k.lastPrices[pair] = report.Price
	return nil
}

func (k Keeper) StoreOracleMetric(ctx Context, pair string) error {
	report, err := k.oracle.FetchPrice(ctx, pair)
	if err != nil {
		return err
	}
	k.metrics.LastOraclePrice = report.Price
	return nil
}
