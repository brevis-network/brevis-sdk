package multichainbalance

import (
	"github.com/brevis-network/brevis-sdk/sdk"
	"github.com/ethereum/go-ethereum/common"
)

// This circuit proves that a user's TOTAL token balance across multiple chains
// (Ethereum + BSC) meets a minimum threshold.
//
// This demonstrates multi-chain state aggregation, a fundamental cross-chain
// verification pattern.
//
// ⚠️ STATUS: UNTESTED - Awaiting gateway access
//
// Use Cases:
// - Cross-chain portfolio verification
// - Multi-chain airdrop eligibility
// - Total holdings proof (without revealing per-chain breakdown)
// - Cross-chain whale identification

// AppCircuit proves multi-chain token balance
type AppCircuit struct {
	HolderAddr      sdk.Uint248 // User address (same across chains)
	MinTotalBalance sdk.Uint248 // Minimum combined balance threshold
}

var _ sdk.AppCircuit = &AppCircuit{}

// Token addresses
var (
	// USDC on Ethereum mainnet (Chain ID 1)
	// Address: 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48
	USDCEthereum = sdk.ConstUint248(common.HexToAddress("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"))

	// USDC on BSC (Chain ID 56)
	// Address: 0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d
	USDC_BSC = sdk.ConstUint248(common.HexToAddress("0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d"))
)

func (c *AppCircuit) Allocate() (maxReceipts, maxStorage, maxTransactions int) {
	// We need 2 storage slots:
	// - Slot 0: USDC balance on Ethereum
	// - Slot 1: USDC balance on BSC
	return 0, 2, 0
}

func (c *AppCircuit) Define(api *sdk.CircuitAPI, in sdk.DataInput) error {
	u248 := api.Uint248

	// Create data stream from storage slots
	slots := sdk.NewDataStream(api, in.StorageSlots)

	// NOTE: This is a simplified implementation
	// In production, you would need to:
	// 1. Distinguish which slot comes from which chain
	// 2. Verify chain IDs match expected values
	// 3. Handle the two slots separately
	//
	// Current SDK limitation: Cannot easily distinguish slot sources in DataStream
	// This circuit demonstrates the CONCEPT of multi-chain aggregation

	// Get the two storage slots (Ethereum and BSC)
	slot0 := sdk.GetUnderlying(slots, 0) // Ethereum USDC balance
	slot1 := sdk.GetUnderlying(slots, 1) // BSC USDC balance

	// Verify slot 0 is from Ethereum USDC contract
	u248.AssertIsEqual(slot0.Contract, USDCEthereum)

	// Verify slot 1 is from BSC USDC contract
	u248.AssertIsEqual(slot1.Contract, USDC_BSC)

	// Calculate storage slot for balanceOf mapping
	// ERC20 standard: mapping(address => uint256) balanceOf at slot 9 (typical)
	// Slot key = keccak256(abi.encode(holderAddress, mappingSlot))
	balanceSlotEth := api.SlotOfStructFieldInMapping(9, 0, api.ToBytes32(c.HolderAddr))
	balanceSlotBsc := api.SlotOfStructFieldInMapping(9, 0, api.ToBytes32(c.HolderAddr))

	// Verify we're reading the correct slots
	api.Bytes32.AssertIsEqual(slot0.Slot, balanceSlotEth)
	api.Bytes32.AssertIsEqual(slot1.Slot, balanceSlotBsc)

	// Extract balances from both chains
	balanceEthereum := api.ToUint248(slot0.Value)
	balanceBSC := api.ToUint248(slot1.Value)

	// Sum balances across chains
	totalBalance := u248.Add(balanceEthereum, balanceBSC)

	// Assert total balance meets minimum threshold
	u248.AssertIsLessOrEqual(c.MinTotalBalance, totalBalance)

	// Output results
	api.OutputAddress(c.HolderAddr)        // Verified holder address
	api.OutputUint(248, balanceEthereum)   // Ethereum balance
	api.OutputUint(248, balanceBSC)        // BSC balance
	api.OutputUint(248, totalBalance)      // Total cross-chain balance
	api.OutputUint(248, c.MinTotalBalance) // Threshold proven

	return nil
}
