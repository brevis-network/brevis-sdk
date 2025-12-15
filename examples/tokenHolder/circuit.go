package tokenHolder

import (
	"github.com/brevis-network/brevis-sdk/sdk"
	"github.com/ethereum/go-ethereum/common"
)

type AppCircuit struct {
	HolderAddr sdk.Uint248
}

var _ sdk.AppCircuit = &AppCircuit{}

// USDC token address on Ethereum mainnet
var USDCTokenAddr = sdk.ConstUint248(
	common.HexToAddress("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"))

// Minimum balance threshold: 100 USDC (USDC has 6 decimals)
var minimumBalance = sdk.ConstUint248(100000000) // 100 * 10^6

func (c *AppCircuit) Allocate() (maxReceipts, maxStorage, maxTransactions int) {
	// This circuit only needs to verify one storage slot (the balance)
	// maxReceipts=0, maxStorage=1, maxTransactions=0
	return 0, 1, 0
}

func (c *AppCircuit) Define(api *sdk.CircuitAPI, in sdk.DataInput) error {
	// Create a data stream from storage slots
	slots := sdk.NewDataStream(api, in.StorageSlots)

	// Get the single storage slot we're checking
	slot := sdk.GetUnderlying(slots, 0)

	// Verify the storage slot is from the correct contract (USDC)
	api.Uint248.AssertIsEqual(slot.Contract, USDCTokenAddr)

	// ERC20 standard: mapping(address => uint256) public balanceOf;
	// For USDC, the balanceOf mapping is at slot 9
	// Slot key = keccak256(abi.encode(holderAddress, 9))
	balanceSlot := api.SlotOfStructFieldInMapping(9, 0, api.ToBytes32(c.HolderAddr))

	// Verify we're reading the correct storage slot for this holder
	api.Bytes32.AssertIsEqual(slot.Slot, balanceSlot)

	// Extract the balance value from storage
	balance := api.ToUint248(slot.Value)

	// Assert that the balance meets the minimum threshold
	api.Uint248.AssertIsLessOrEqual(minimumBalance, balance)

	// Output the results
	api.OutputAddress(c.HolderAddr)           // Output holder address
	api.OutputUint(248, balance)              // Output actual balance
	api.OutputUint(64, api.ToUint248(slot.BlockNum)) // Output block number

	return nil
}
