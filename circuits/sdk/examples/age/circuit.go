package age

import (
	"github.com/celer-network/brevis-sdk/circuits/sdk/sdk"
)

type GuestCircuit struct {
	UserAddr sdk.Variable
	Nonce    sdk.Variable
}

var _ sdk.GuestCircuit = &GuestCircuit{}

func (c *GuestCircuit) Allocate() (maxReceipts, maxSlots, maxTransactions int) {
	return 1, 1, 1
}

func (c *GuestCircuit) Define(api *sdk.CircuitAPI, witness sdk.Witness) error {
	txs := sdk.NewDataStream(api, witness.Transactions)

	txs.AssertEach(func(tx sdk.Transaction) sdk.Variable { return api.Equal(tx.From, c.UserAddr) })

	minNonceBlock := txs.Reduce2([2]sdk.Variable{sdk.MaxInt, 0},
		func(acc [2]sdk.Variable, tx sdk.Transaction) (newAcc [2]sdk.Variable) {
			minNonce := acc[0]
			block := acc[1]
			curLtMin := api.LT(tx.Nonce, acc[0])
			return [2]sdk.Variable{
				api.Select(curLtMin, tx.Nonce, minNonce),
				api.Select(curLtMin, tx.BlockNum, block),
			}
		})

	minNonce := minNonceBlock[0]
	block := minNonceBlock[1]
	api.AssertIsEqual(minNonce, c.Nonce)

	api.OutputAddress(c.UserAddr)
	api.OutputUint(64, block)
	api.OutputUint(64, c.Nonce)

	return nil
}
