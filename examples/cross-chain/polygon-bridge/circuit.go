package polygonbridge

import (
	"github.com/brevis-network/brevis-sdk/sdk"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
)

// This circuit proves that a user bridged tokens from Ethereum to Polygon
// by analyzing LockedEther events from the Polygon PoS Bridge.
//
// The Polygon bridge uses a Lock-Mint mechanism:
// 1. User locks tokens on Ethereum (LockedEther event)
// 2. Equivalent tokens are minted on Polygon (StateSynced event)
//
// This circuit tracks the Ethereum side (locking).
//
// ⚠️ STATUS: UNTESTED - Awaiting gateway access
//
// Use Cases:
// - Multi-chain user identification
// - Bridge activity rewards
// - L2 adoption tracking
// - Cross-chain portfolio verification

// AppCircuit proves Ethereum → Polygon bridge activity
type AppCircuit struct {
	UserAddr       sdk.Uint248 // Address that bridged tokens
	MinBridgeAmount sdk.Uint248 // Minimum total amount bridged
}

var _ sdk.AppCircuit = &AppCircuit{}

// Polygon PoS Bridge RootChainManager LockedEther Event
// event LockedEther(address indexed depositor, address indexed depositReceiver, address indexed rootToken, uint256 amount)
// Signature: 0x9b217a401a5ddf7c4d474074aff9958a18d48690d77cc2151c4706aa7348b401
var EventIdLockedEther = sdk.ParseEventID(
	hexutil.MustDecode("0x9b217a401a5ddf7c4d474074aff9958a18d48690d77cc2151c4706aa7348b401"))

// Polygon PoS Bridge addresses (Ethereum mainnet)
var (
	// RootChainManager (handles deposits): 0xA0c68C638235ee32657e8f720a23ceC1bFc77C77
	RootChainManager = sdk.ConstUint248(common.HexToAddress("0xA0c68C638235ee32657e8f720a23ceC1bFc77C77"))

	// EtherPredicate (MATIC token): 0x8484Ef722627bf18ca5Ae6BcF031c23E6e922B30
	EtherPredicate = sdk.ConstUint248(common.HexToAddress("0x8484Ef722627bf18ca5Ae6BcF031c23E6e922B30"))

	// WETH on Ethereum: 0xC02aaA39b223FE8D0A3e5C4F27eAD9083C756Cc2
	WETHAddress = sdk.ConstUint248(common.HexToAddress("0xC02aaA39b223FE8D0A3e5C4F27eAD9083C756Cc2"))
)

func (c *AppCircuit) Allocate() (maxReceipts, maxSlots, maxTransactions int) {
	// Track up to 30 bridge transactions
	// Bridging is less frequent than swapping
	return 30, 0, 0
}

func (c *AppCircuit) Define(api *sdk.CircuitAPI, in sdk.DataInput) error {
	u248 := api.Uint248

	receipts := sdk.NewDataStream(api, in.Receipts)

	// Validate all receipts match expected LockedEther event pattern
	sdk.AssertEach(receipts, func(r sdk.Receipt) sdk.Uint248 {
		// LockedEther event structure:
		// Topics: [0] = event signature, [1] = depositor (indexed),
		//         [2] = depositReceiver (indexed), [3] = rootToken (indexed)
		// Data: amount (uint256)

		// We track 2 fields per receipt:
		// [0] = amount (data field 0) - amount bridged
		// [1] = depositor (topic field 1) - who initiated bridge

		// Verify all fields are from the RootChainManager contract
		contractMatches := u248.And(
			u248.IsEqual(r.Fields[0].Contract, RootChainManager),
			u248.IsEqual(r.Fields[1].Contract, RootChainManager),
		)

		// Verify event IDs match LockedEther event
		eventIdMatches := u248.And(
			u248.IsEqual(r.Fields[0].EventID, EventIdLockedEther),
			u248.IsEqual(r.Fields[1].EventID, EventIdLockedEther),
		)

		// Verify field indices and types
		fieldIndicesCorrect := u248.And(
			// amount is data field 0 (not a topic)
			u248.IsZero(r.Fields[0].IsTopic),
			u248.IsEqual(r.Fields[0].Index, sdk.ConstUint248(0)),
			// depositor is topic field 1 (indexed)
			r.Fields[1].IsTopic,
			u248.IsEqual(r.Fields[1].Index, sdk.ConstUint248(1)),
		)

		// Verify the depositor matches the user we're verifying
		userMatches := u248.IsEqual(api.ToUint248(r.Fields[1].Value), c.UserAddr)

		return u248.And(contractMatches, eventIdMatches, fieldIndicesCorrect, userMatches)
	})

	// Extract bridge amounts from each LockedEther event
	amounts := sdk.Map(receipts, func(r sdk.Receipt) sdk.Uint248 {
		return api.ToUint248(r.Fields[0].Value) // amount
	})

	// Sum total amount bridged
	totalBridged := sdk.Sum(amounts)

	// Assert total bridged amount meets minimum threshold
	u248.AssertIsLessOrEqual(c.MinBridgeAmount, totalBridged)

	// Count number of bridge transactions
	bridgeCount := sdk.Count(receipts)

	// Output results for on-chain verification
	api.OutputAddress(c.UserAddr)          // Verified depositor address
	api.OutputUint(248, totalBridged)      // Total amount bridged
	api.OutputUint(248, c.MinBridgeAmount) // Minimum threshold
	api.OutputUint(64, bridgeCount)        // Number of bridge transactions

	return nil
}
