// fixture: negative - oracle checks are applied before every state write.
package keeper

import "errors"

const quoteScale int64 = 1_000_000

var (
	ErrBadDenom   = errors.New("bad denominator")
	ErrNoQuorum   = errors.New("no quorum")
	ErrStalePrice = errors.New("stale price")
	ErrWrongFeed  = errors.New("wrong feed")
)

type Context struct {
	now int64
}

func (c Context) BlockTimeUnix() int64 { return c.now }

type PriceReport struct {
	Price     int64
	UpdatedAt int64
	SourceID  string
	Signers   []string
}

type Position struct {
	Account string
	Size    int64
	Debt    int64
}

type Oracle struct{}
type SettlementKeeper struct{}
type MarginKeeper struct{}
type Metrics struct {
	LastOraclePrice int64
}

func (Oracle) FetchPrice(ctx Context, pair string) (PriceReport, error) {
	return PriceReport{}, nil
}

func (Oracle) FetchReport(ctx Context, marketID string) (PriceReport, error) {
	return PriceReport{}, nil
}

func (Oracle) LatestPrice(ctx Context, pair string) (PriceReport, error) {
	return PriceReport{}, nil
}

func (SettlementKeeper) SettleFunding(ctx Context, account string, payment int64) {}
func (MarginKeeper) OpenPosition(ctx Context, account string, margin int64) {}

type Keeper struct {
	oracle          Oracle
	settlement      SettlementKeeper
	margin          MarginKeeper
	metrics         Metrics
	marketPrices    map[string]int64
	acceptedReports map[string]int64
	acceptedPrices  map[string]int64
	reserves        map[string]int64
	lastGoodPrices  map[string]PriceReport
	expectedSources map[string]string
	maxAge          int64
	quorum          int
}

func (k Keeper) ValidateOracleQuote(ctx Context, report PriceReport, pair string) error {
	if report.Price <= 0 {
		return ErrBadDenom
	}
	if ctx.BlockTimeUnix()-report.UpdatedAt > k.maxAge {
		return ErrStalePrice
	}
	if report.SourceID != k.expectedSources[pair] {
		return ErrWrongFeed
	}
	return nil
}

func (k Keeper) UpdateMarketPriceWithFreshnessBeforeWrite(ctx Context, pair string) error {
	report, err := k.oracle.FetchPrice(ctx, pair)
	if err != nil {
		return err
	}
	if ctx.BlockTimeUnix()-report.UpdatedAt > k.maxAge {
		return ErrStalePrice
	}
	k.marketPrices[pair] = report.Price
	return nil
}

func (k Keeper) AcceptReportWithQuorumBeforeWrite(ctx Context, marketID string) error {
	report, err := k.oracle.FetchReport(ctx, marketID)
	if err != nil {
		return err
	}
	if len(report.Signers) < k.quorum {
		return ErrNoQuorum
	}
	k.acceptedReports[marketID] = report.Price
	return nil
}

func (k Keeper) SettleWithValidatedFallback(ctx Context, pair string, position Position) error {
	report, err := k.oracle.LatestPrice(ctx, pair)
	if err != nil || ctx.BlockTimeUnix()-report.UpdatedAt > k.maxAge {
		report = k.lastGoodPrices[pair]
	}
	if err := k.ValidateOracleQuote(ctx, report, pair); err != nil {
		return err
	}
	payment := position.Size * report.Price / quoteScale
	k.settlement.SettleFunding(ctx, position.Account, payment)
	return nil
}

func (k Keeper) UpdateReserveWithPairBoundSource(ctx Context, pair string, currentReserve int64) error {
	report, err := k.oracle.FetchPrice(ctx, pair)
	if err != nil {
		return err
	}
	expectedSource := k.expectedSources[pair]
	if report.SourceID != expectedSource {
		return ErrWrongFeed
	}
	k.reserves[pair] = currentReserve * report.Price / quoteScale
	return nil
}

func (k Keeper) MintSharesAfterDenominatorGuard(ctx Context, asset string, amount int64) error {
	report, err := k.oracle.FetchPrice(ctx, asset)
	if err != nil {
		return err
	}
	if report.Price == 0 {
		return ErrBadDenom
	}
	shares := amount / report.Price
	k.acceptedPrices[asset] = shares
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
