package sushiswap

import (
	"github.com/brevis-network/brevis-sdk/sdk"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
)

// This circuit proves that a user traded a minimum volume of a specific token
// on SushiSwap by analyzing Swap events.
//
// SushiSwap is a fork of Uniswap V2 and uses identical event structures.
//
// Use Cases:
// - Airdrop eligibility based on SushiSwap trading activity
// - Trading competition verification
// - Loyalty rewards for active SushiSwap traders
// - Volume-based access control

// AppCircuit proves trading volume on SushiSwap
type AppCircuit struct {
	UserAddr  sdk.Uint248 // Address of the trader to verify
	MinVolume sdk.Uint248 // Minimum volume threshold to prove (in token units)
}

var _ sdk.AppCircuit = &AppCircuit{}

// SushiSwap uses the same Swap event as Uniswap V2 (it's a fork)
// event Swap(address indexed sender, uint amount0In, uint amount1In, uint amount0Out, uint amount1Out, address indexed to)
// Signature: 0xd78ad95fa46c994b6551d0da85fc275fe613ce37657fb8d5e3d130840159d822
var EventIdSwap = sdk.ParseEventID(
	hexutil.MustDecode("0xd78ad95fa46c994b6551d0da85fc275fe613ce37657fb8d5e3d130840159d822"))

// SushiSwap pair addresses (Ethereum mainnet)
var (
	// USDC/WETH pair: 0x397FF1542f962076d0BFE58eA045FfA2d347ACa0
	USDCWETHPair = sdk.ConstUint248(common.HexToAddress("0x397FF1542f962076d0BFE58eA045FfA2d347ACa0"))
	// USDC address: 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48 (token0 in this pair)
	USDCAddress = sdk.ConstUint248(common.HexToAddress("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"))
	// WETH address: 0xC02aaA39b223FE8D0A3e5C4F27eAD9083C756Cc2 (token1 in this pair)
	WETHAddress = sdk.ConstUint248(common.HexToAddress("0xC02aaA39b223FE8D0A3e5C4F27eAD9083C756Cc2"))
)

func (c *AppCircuit) Allocate() (maxReceipts, maxSlots, maxTransactions int) {
	// Allocate space for up to 50 swap receipts
	// This allows proving volume across many transactions
	return 50, 0, 0
}

func (c *AppCircuit) Define(api *sdk.CircuitAPI, in sdk.DataInput) error {
	u248 := api.Uint248

	receipts := sdk.NewDataStream(api, in.Receipts)

	// Validate all receipts match expected pattern
	sdk.AssertEach(receipts, func(r sdk.Receipt) sdk.Uint248 {
		// SushiSwap Swap event structure (identical to Uniswap V2):
		// Topics: [0] = event signature, [1] = sender (indexed), [2] = to (indexed)
		// Data: amount0In, amount1In, amount0Out, amount1Out (all uint256, non-indexed)

		// We track 2 fields per receipt:
		// [0] = amount1Out (WETH received - data field 3)
		// [1] = to address (recipient - topic field 2)

		// Verify all fields are from the correct SushiSwap pair contract
		contractMatches := u248.And(
			u248.IsEqual(r.Fields[0].Contract, USDCWETHPair),
			u248.IsEqual(r.Fields[1].Contract, USDCWETHPair),
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

	// Extract WETH volume (amount1Out) from each swap
	volumes := sdk.Map(receipts, func(r sdk.Receipt) sdk.Uint248 {
		// Field[0] contains amount1Out (WETH received by user)
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
	api.OutputUint(248, totalVolume)   // Total WETH volume received
	api.OutputUint(248, c.MinVolume)   // Minimum threshold that was proven
	api.OutputUint(64, swapCount)      // Number of swaps

	return nil
}
