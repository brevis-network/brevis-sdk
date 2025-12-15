package curvestableswap

import (
	"github.com/brevis-network/brevis-sdk/sdk"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
)

// This circuit proves trading volume on Curve StableSwap pools by analyzing
// TokenExchange events.
//
// Curve is optimized for low-slippage stablecoin swaps (USDC/USDT/DAI).
//
// Use Cases:
// - Stablecoin trading volume verification
// - Low-slippage swap activity proof
// - Curve-specific trading rewards
// - DeFi aggregator usage tracking

// AppCircuit proves trading volume on Curve StableSwap
type AppCircuit struct {
	UserAddr  sdk.Uint248 // Address of the trader to verify
	MinVolume sdk.Uint248 // Minimum volume threshold (in token units)
}

var _ sdk.AppCircuit = &AppCircuit{}

// Curve TokenExchange Event Signature
// event TokenExchange(address indexed buyer, int128 sold_id, uint256 tokens_sold, int128 bought_id, uint256 tokens_bought)
// Signature: 0x8b3e96f2b889fa771c53c981b40daf005f63f637f1869f707052d15a3dd97140
var EventIdTokenExchange = sdk.ParseEventID(
	hexutil.MustDecode("0x8b3e96f2b889fa771c53c981b40daf005f63f637f1869f707052d15a3dd97140"))

// Curve 3pool (most liquid stablecoin pool)
// Pool address: 0xbEbc44782C7dB0a1A60Cb6fe97d0b483032FF1C7
// Contains: DAI (0), USDC (1), USDT (2)
var (
	ThreePoolAddress = sdk.ConstUint248(common.HexToAddress("0xbEbc44782C7dB0a1A60Cb6fe97d0b483032FF1C7"))
	// DAI address: 0x6B175474E89094C44Da98b954EedeAC495271d0F
	DAIAddress = sdk.ConstUint248(common.HexToAddress("0x6B175474E89094C44Da98b954EedeAC495271d0F"))
	// USDC address: 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48
	USDCAddress = sdk.ConstUint248(common.HexToAddress("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"))
	// USDT address: 0xdAC17F958D2ee523a2206206994597C13D831ec7
	USDTAddress = sdk.ConstUint248(common.HexToAddress("0xdAC17F958D2ee523a2206206994597C13D831ec7"))
)

func (c *AppCircuit) Allocate() (maxReceipts, maxSlots, maxTransactions int) {
	// Allocate space for up to 50 token exchange receipts
	return 50, 0, 0
}

func (c *AppCircuit) Define(api *sdk.CircuitAPI, in sdk.DataInput) error {
	u248 := api.Uint248

	receipts := sdk.NewDataStream(api, in.Receipts)

	// Validate all receipts match expected pattern
	sdk.AssertEach(receipts, func(r sdk.Receipt) sdk.Uint248 {
		// Curve TokenExchange event structure:
		// Topics: [0] = event signature, [1] = buyer (indexed)
		// Data: sold_id (int128), tokens_sold (uint256), bought_id (int128), tokens_bought (uint256)

		// We track 2 fields per receipt:
		// [0] = tokens_bought (data field 3) - amount received
		// [1] = buyer address (topic field 1)
		//
		// Note: We're simplifying by only tracking tokens_bought (not tokens_sold)
		// and not distinguishing between which stablecoins were traded

		// Verify all fields are from the correct pool contract
		contractMatches := u248.And(
			u248.IsEqual(r.Fields[0].Contract, ThreePoolAddress),
			u248.IsEqual(r.Fields[1].Contract, ThreePoolAddress),
		)

		// Verify event IDs match TokenExchange event
		eventIdMatches := u248.And(
			u248.IsEqual(r.Fields[0].EventID, EventIdTokenExchange),
			u248.IsEqual(r.Fields[1].EventID, EventIdTokenExchange),
		)

		// Verify field indices and types
		fieldIndicesCorrect := u248.And(
			// tokens_bought is data field 3 (not a topic)
			u248.IsZero(r.Fields[0].IsTopic),
			u248.IsEqual(r.Fields[0].Index, sdk.ConstUint248(3)),
			// buyer is topic field 1 (indexed)
			r.Fields[1].IsTopic,
			u248.IsEqual(r.Fields[1].Index, sdk.ConstUint248(1)),
		)

		// Verify the buyer address matches the user we're verifying
		userMatches := u248.IsEqual(api.ToUint248(r.Fields[1].Value), c.UserAddr)

		return u248.And(contractMatches, eventIdMatches, fieldIndicesCorrect, userMatches)
	})

	// Extract tokens_bought from each exchange
	// Note: This tracks the amount of tokens received (bought)
	// In Curve, all stablecoins are roughly 1:1, so this is a reasonable volume metric
	volumes := sdk.Map(receipts, func(r sdk.Receipt) sdk.Uint248 {
		return api.ToUint248(r.Fields[0].Value) // tokens_bought
	})

	// Sum total volume across all exchanges
	totalVolume := sdk.Sum(volumes)

	// Assert that total volume meets or exceeds minimum threshold
	u248.AssertIsLessOrEqual(c.MinVolume, totalVolume)

	// Count number of exchanges
	exchangeCount := sdk.Count(receipts)

	// Output results for on-chain verification
	api.OutputAddress(c.UserAddr)      // Verified user address
	api.OutputUint(248, totalVolume)   // Total volume (tokens bought)
	api.OutputUint(248, c.MinVolume)   // Minimum threshold
	api.OutputUint(64, exchangeCount)  // Number of exchanges

	return nil
}
