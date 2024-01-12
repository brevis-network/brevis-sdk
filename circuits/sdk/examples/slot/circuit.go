package slot

import (
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/celer-network/brevis-sdk/circuits/sdk/sdk"
)

type GuestCircuit struct{}

var _ sdk.GuestCircuit = &GuestCircuit{}

func (c *GuestCircuit) Allocate() (maxReceipts, maxSlots, maxTransactions int) {
	return 0, 1, 0
}

// The storage at slot 0 is the `owner` field of the contract
// Please consult [solidity doc] for how to compute the storage key
//
// [solidity doc]: https://docs.soliditylang.org/en/latest/internals/layout_in_storage.html
var slot = common.LeftPadBytes([]byte{0}, 32)
var expectedKey = sdk.ParseBytes32(crypto.Keccak256(slot))

func (c *GuestCircuit) Define(api *sdk.CircuitAPI, witness sdk.Witness) error {
	slots := sdk.NewDataStream(api, witness.StorageSlots)

	// Since we only have 1 input which is the owner slot of the contract, we simply
	// get the 0th element and do computation on it
	s := slots.Get(0)
	api.AssertIsEqualBytes32(s.Key, expectedKey)

	fmt.Println("s.Value", s.Value)
	owner := api.ToVariable(s.Value)
	// Output will be reflected in our contract in the form of
	// abi.encodePacked(address,address,uint64)
	api.OutputAddress(s.Contract)
	api.OutputAddress(owner)
	api.OutputUint(64, s.BlockNum)

	return nil
}
