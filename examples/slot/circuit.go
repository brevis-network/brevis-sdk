package slot

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/celer-network/brevis-sdk/sdk"
)

type AppCircuit struct{}

var _ sdk.AppCircuit = &AppCircuit{}

func (c *AppCircuit) Allocate() (maxReceipts, maxSlots, maxTransactions int) {
	// Here we have allocated 2 circuit slots for proving storage slots, but in this
	// example we will show that we can only use one of those slots. We will also
	// show that you can "fixate" a piece of data at a specific index.
	return 0, 2, 0
}

// For simplicity, we assume that the storage at slot 0 is the `owner` field of
// the contract Please consult [solidity doc] for how to compute the storage key
//
// [solidity doc]: https://docs.soliditylang.org/en/latest/internals/layout_in_storage.html
var slot = common.LeftPadBytes([]byte{0}, 32)
var expectedKey = sdk.ParseBytes32(crypto.Keccak256(slot))

func (c *AppCircuit) Define(api *sdk.CircuitAPI, in sdk.CircuitInput) error {
	slots := sdk.NewDataStream(api, in.StorageSlots)

	// For educational purposes, when we added the queries to the querier, we
	// specifically requested index "1" for storage slots to be our "special" data.
	// We can access this special index directly and use it in circuit.
	s := slots.Get(1)
	api.AssertIsEqualBytes32(s.Key, expectedKey)

	owner := api.ToVariable(s.Value)
	// Output will be reflected in our contract in the form of
	// abi.encodePacked(address,address,uint64)
	api.OutputAddress(s.Contract)
	api.OutputAddress(owner)
	api.OutputUint(64, s.BlockNum)

	return nil
}
