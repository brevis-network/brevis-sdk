package pancakeswap

import (
	"github.com/brevis-network/brevis-sdk/sdk"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
)

// This circuit proves that a user traded a minimum volume of a specific token
// on PancakeSwap V2 (BSC) by analyzing Swap events.
//
// PancakeSwap is a Uniswap V2 fork deployed on Binance Smart Chain (BSC, Chain ID 56).
//
// Use Cases:
// - Multi-chain trading activity verification
// - BSC-specific airdrop eligibility
// - Cross-chain trader identification
// - BNB ecosystem engagement rewards

// AppCircuit proves trading volume on PancakeSwap V2 (BSC)
type AppCircuit struct {
	UserAddr  sdk.Uint248 // Address of the trader to verify
	MinVolume sdk.Uint248 // Minimum volume threshold to prove (in token units)
}

var _ sdk.AppCircuit = &AppCircuit{}

// PancakeSwap V2 Swap Event Signature (same as Uniswap V2 - it's a fork)
// event Swap(address indexed sender, uint amount0In, uint amount1In, uint amount0Out, uint amount1Out, address indexed to)
// Signature: 0xd78ad95fa46c994b6551d0da85fc275fe613ce37657fb8d5e3d130840159d822
var EventIdSwap = sdk.ParseEventID(
	hexutil.MustDecode("0xd78ad95fa46c994b6551d0da85fc275fe613ce37657fb8d5e3d130840159d822"))

// PancakeSwap V2 pair addresses (BSC mainnet - Chain ID 56)
var (
	// BUSD/WBNB pair: 0x58F876857a02D6762E0101bb5C46A8c1ED44Dc16
	// This is one of the most liquid pairs on PancakeSwap
	BUSDWBNBPair = sdk.ConstUint248(common.HexToAddress("0x58F876857a02D6762E0101bb5C46A8c1ED44Dc16"))
	// BUSD address: 0xe9e7CEA3DedcA5984780Bafc599bD69ADd087D56 (token0 in this pair)
	BUSDAddress = sdk.ConstUint248(common.HexToAddress("0xe9e7CEA3DedcA5984780Bafc599bD69ADd087D56"))
	// WBNB address: 0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c (token1 in this pair)
	WBNBAddress = sdk.ConstUint248(common.HexToAddress("0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c"))
)

func (c *AppCircuit) Allocate() (maxReceipts, maxSlots, maxTransactions int) {
	// Allocate space for up to 50 swap receipts
	// BSC has faster blocks, so more swaps are possible in a given time period
	return 50, 0, 0
}

func (c *AppCircuit) Define(api *sdk.CircuitAPI, in sdk.DataInput) error {
	u248 := api.Uint248

	receipts := sdk.NewDataStream(api, in.Receipts)

	// Validate all receipts match expected pattern
	sdk.AssertEach(receipts, func(r sdk.Receipt) sdk.Uint248 {
		// PancakeSwap V2 Swap event structure (identical to Uniswap V2):
		// Topics: [0] = event signature, [1] = sender (indexed), [2] = to (indexed)
		// Data: amount0In, amount1In, amount0Out, amount1Out (all uint256, non-indexed)

		// We track 2 fields per receipt:
		// [0] = amount1Out (WBNB received - data field 3)
		// [1] = to address (recipient - topic field 2)

		// Verify all fields are from the correct pair contract (BUSD/WBNB)
		contractMatches := u248.And(
			u248.IsEqual(r.Fields[0].Contract, BUSDWBNBPair),
			u248.IsEqual(r.Fields[1].Contract, BUSDWBNBPair),
		)

		// Verify event IDs match Swap event
		eventIdMatches := u248.And(
			u248.IsEqual(r.Fields[0].EventID, EventIdSwap),
			u248.IsEqual(r.Fields[1].EventID, EventIdSwap),
		)

		// Verify field indices and types
		fieldIndicesCorrect := u248.And(
			// amount1Out is data field 3 (not a topic)
			u248.IsZero(r.Fields[0].IsTopic),
			u248.IsEqual(r.Fields[0].Index, sdk.ConstUint248(3)),
			// to is topic field 2 (indexed)
			r.Fields[1].IsTopic,
			u248.IsEqual(r.Fields[1].Index, sdk.ConstUint248(2)),
		)

		// Verify the "to" address matches the user we're verifying
		userMatches := u248.IsEqual(api.ToUint248(r.Fields[1].Value), c.UserAddr)

		return u248.And(contractMatches, eventIdMatches, fieldIndicesCorrect, userMatches)
	})

	// Extract WBNB volume (amount1Out) from each swap
	volumes := sdk.Map(receipts, func(r sdk.Receipt) sdk.Uint248 {
		// Field[0] contains amount1Out (WBNB received by user)
		return api.ToUint248(r.Fields[0].Value)
	})

	// Sum total volume across all swaps
	totalVolume := sdk.Sum(volumes)

	// Assert that total volume meets or exceeds minimum threshold
	u248.AssertIsLessOrEqual(c.MinVolume, totalVolume)

	// Count number of swaps
	swapCount := sdk.Count(receipts)

	// Output results for on-chain verification
	api.OutputAddress(c.UserAddr)      // Verified user address
	api.OutputUint(248, totalVolume)   // Total WBNB volume received
	api.OutputUint(248, c.MinVolume)   // Minimum threshold that was proven
	api.OutputUint(64, swapCount)      // Number of swaps

	return nil
}
