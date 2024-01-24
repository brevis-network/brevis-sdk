package age

import (
	"github.com/celer-network/brevis-sdk/sdk"
)

type GuestCircuit struct {
	UserAddr sdk.Variable
}

var _ sdk.GuestCircuit = &GuestCircuit{}

func (c *GuestCircuit) Allocate() (maxReceipts, maxStorage, maxTransactions int) {
	// Our app is only ever going to use one storage data at a time so
	// we can simply limit the max number of data for storage to 1 and
	// 0 for all others
	return 0, 0, 1
}

func (c *GuestCircuit) Define(api *sdk.CircuitAPI, in sdk.CircuitInput) error {
	txs := sdk.NewDataStream(api, in.Transactions)

	tx := txs.Get(0)
	// This is our main check logic
	api.AssertIsEqual(tx.Nonce, 0)

	// Output variables can be later accessed in our app contract
	api.OutputAddress(tx.From)
	api.OutputUint(64, tx.BlockNum)

	return nil
}
