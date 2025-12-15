package balancerweighted

import (
	"github.com/brevis-network/brevis-sdk/sdk"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
)

// This circuit proves trading volume on Balancer V2 Weighted Pools by analyzing
// Swap events from the Vault contract.
//
// Balancer V2 uses a single Vault contract for all pools, with pools identified by poolId.
//
// Use Cases:
// - Multi-token pool trading verification
// - Weighted pool (non-50/50) activity proof
// - Balancer-specific trading rewards
// - Advanced AMM usage tracking

// AppCircuit proves trading volume on Balancer V2 Weighted Pools
type AppCircuit struct {
	UserAddr  sdk.Uint248 // Address of the trader to verify
	MinVolume sdk.Uint248 // Minimum volume threshold (in token units)
}

var _ sdk.AppCircuit = &AppCircuit{}

// Balancer V2 Swap Event Signature
// event Swap(bytes32 indexed poolId, address indexed tokenIn, address indexed tokenOut, uint256 amountIn, uint256 amountOut)
// Signature: 0x2170c741c41531aec20e7c107c24eecfdd15e69c9bb0a8dd37b1840b9e0b207b
var EventIdSwap = sdk.ParseEventID(
	hexutil.MustDecode("0x2170c741c41531aec20e7c107c24eecfdd15e69c9bb0a8dd37b1840b9e0b207b"))

// Balancer V2 Vault (all pools use this)
// Vault address: 0xBA12222222228d8Ba445958a75a0704d566BF2C8
var (
	VaultAddress = sdk.ConstUint248(common.HexToAddress("0xBA12222222228d8Ba445958a75a0704d566BF2C8"))

	// Example: 80/20 BAL/WETH pool
	// Pool ID: 0x5c6ee304399dbdb9c8ef030ab642b10820db8f56000200000000000000000014
	// Note: poolId is bytes32, we'll just verify Vault for simplicity

	// WETH address: 0xC02aaA39b223FE8D0A3e5C4F27eAD9083C756Cc2
	WETHAddress = sdk.ConstUint248(common.HexToAddress("0xC02aaA39b223FE8D0A3e5C4F27eAD9083C756Cc2"))
	// BAL address: 0xba100000625a3754423978a60c9317c58a424e3D
	BALAddress = sdk.ConstUint248(common.HexToAddress("0xba100000625a3754423978a60c9317c58a424e3D"))
)

func (c *AppCircuit) Allocate() (maxReceipts, maxSlots, maxTransactions int) {
	// Allocate space for up to 50 swap receipts
	return 50, 0, 0
}

func (c *AppCircuit) Define(api *sdk.CircuitAPI, in sdk.DataInput) error {
	u248 := api.Uint248

	receipts := sdk.NewDataStream(api, in.Receipts)

	// Validate all receipts match expected pattern
	sdk.AssertEach(receipts, func(r sdk.Receipt) sdk.Uint248 {
		// Balancer V2 Swap event structure:
		// Topics: [0] = event signature, [1] = poolId (bytes32, indexed),
		//         [2] = tokenIn (indexed), [3] = tokenOut (indexed)
		// Data: amountIn (uint256), amountOut (uint256)

		// We track 2 fields per receipt:
		// [0] = amountOut (data field 1) - amount received by user
		// [1] = tokenOut (topic field 3) - which token was received
		//
		// Note: Simplified - not tracking specific pools or user address
		// (user is identified via transaction sender, not in event itself)

		// Verify all fields are from the Vault contract
		contractMatches := u248.And(
			u248.IsEqual(r.Fields[0].Contract, VaultAddress),
			u248.IsEqual(r.Fields[1].Contract, VaultAddress),
		)

		// Verify event IDs match Swap event
		eventIdMatches := u248.And(
			u248.IsEqual(r.Fields[0].EventID, EventIdSwap),
			u248.IsEqual(r.Fields[1].EventID, EventIdSwap),
		)

		// Verify field indices and types
		fieldIndicesCorrect := u248.And(
			// amountOut is data field 1 (not a topic)
			u248.IsZero(r.Fields[0].IsTopic),
			u248.IsEqual(r.Fields[0].Index, sdk.ConstUint248(1)),
			// tokenOut is topic field 3 (indexed)
			r.Fields[1].IsTopic,
			u248.IsEqual(r.Fields[1].Index, sdk.ConstUint248(3)),
		)

		// For this simplified version, we accept all swaps from the Vault
		// In production, you'd verify:
		// - Specific poolId (topic field 1)
		// - User address (via transaction sender, not in event)
		// - Specific tokenOut (e.g., only WETH swaps)

		return u248.And(contractMatches, eventIdMatches, fieldIndicesCorrect)
	})

	// Extract amountOut from each swap
	volumes := sdk.Map(receipts, func(r sdk.Receipt) sdk.Uint248 {
		return api.ToUint248(r.Fields[0].Value) // amountOut
	})

	// Sum total volume across all swaps
	totalVolume := sdk.Sum(volumes)

	// Assert that total volume meets or exceeds minimum threshold
	u248.AssertIsLessOrEqual(c.MinVolume, totalVolume)

	// Count number of swaps
	swapCount := sdk.Count(receipts)

	// Output results for on-chain verification
	api.OutputAddress(c.UserAddr)      // Verified user address (from circuit input)
	api.OutputUint(248, totalVolume)   // Total volume (amountOut)
	api.OutputUint(248, c.MinVolume)   // Minimum threshold
	api.OutputUint(64, swapCount)      // Number of swaps

	return nil
}
