// fixture: positive - oracle checks exist but are not load-bearing at write time.
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
	marketPrices    map[string]int64
	acceptedReports map[string]int64
	acceptedPrices  map[string]int64
	reserves        map[string]int64
	lastGoodPrices  map[string]PriceReport
	expectedSources map[string]string
	trustedSourceID string
	maxAge          int64
	quorum          int
}

func (k Keeper) UpdateMarketPriceBeforeFreshnessCheck(ctx Context, pair string) error {
	report, err := k.oracle.FetchPrice(ctx, pair)
	if err != nil {
		return err
	}
	k.marketPrices[pair] = report.Price
	if ctx.BlockTimeUnix()-report.UpdatedAt > k.maxAge {
		return ErrStalePrice
	}
	return nil
}

func (k Keeper) AcceptReportBeforeQuorum(ctx Context, marketID string) error {
	report, err := k.oracle.FetchReport(ctx, marketID)
	if err != nil {
		return err
	}
	k.acceptedReports[marketID] = report.Price
	if len(report.Signers) < k.quorum {
		return ErrNoQuorum
	}
	return nil
}

func (k Keeper) SettleWithFallbackSkippingValidation(ctx Context, pair string, position Position) error {
	report, err := k.oracle.LatestPrice(ctx, pair)
	if err != nil || ctx.BlockTimeUnix()-report.UpdatedAt > k.maxAge {
		report = k.lastGoodPrices[pair]
	}
	payment := position.Size * report.Price / quoteScale
	k.settlement.SettleFunding(ctx, position.Account, payment)
	return nil
}

func (k Keeper) UpdateReserveWithGlobalSourceOnly(ctx Context, pair string, currentReserve int64) error {
	report, err := k.oracle.FetchPrice(ctx, pair)
	if err != nil {
		return err
	}
	if k.expectedSources == nil {
		return ErrWrongFeed
	}
	if report.SourceID != k.trustedSourceID {
		return ErrWrongFeed
	}
	k.reserves[pair] = currentReserve * report.Price / quoteScale
	return nil
}

func (k Keeper) MintSharesBeforeDenominatorZeroGuard(ctx Context, asset string, amount int64) error {
	report, err := k.oracle.FetchPrice(ctx, asset)
	if err != nil {
		return err
	}
	shares := amount / report.Price
	k.acceptedPrices[asset] = shares
	if report.Price == 0 {
		return ErrBadDenom
	}
	return nil
}
