package test

import (
	"math/big"
	"testing"

	"github.com/brevis-network/brevis-sdk/common/utils"
	"github.com/brevis-network/brevis-sdk/sdk"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/test"
)

func TestDemo(t *testing.T) {
	assert := test.NewAssert(t)
	app, err := sdk.NewBrevisApp()
	assert.NoError(err)

	logFieldData := sdk.LogFieldData{
		Contract:   utils.Hex2Addr("0x961ad289351459a45fc90884ef3ab0278ea95dde"),
		LogIndex:   0,
		EventID:    utils.Hex2Hash("0xf6a97944f31ea060dfde0566e4167c1a1082551e64b60ecb14d599a9d023d451"),
		IsTopic:    false,
		FieldIndex: 0,
		Value:      utils.Hex2Hash("0x00000000000000000000000000000000000000000000000000000574335d87c5"),
	}

	receipt := sdk.ReceiptData{
		BlockNum: new(big.Int).SetUint64(13898775),
		TxHash:   utils.Hex2Hash("0xbef5e22dec94fd5ed9630f3cee52d7d914ad796f5a31048086f8a956892db05e"),
		Fields: [sdk.NumMaxLogFields]sdk.LogFieldData{
			logFieldData,
			logFieldData,
			logFieldData,
			logFieldData,
		},
	}

	receipt1 := sdk.ReceiptData{
		BlockNum: new(big.Int).SetUint64(13898776),
		TxHash:   utils.Hex2Hash("0xbef5e22dec94fd5ed9630f3cee52d7d914ad796f5a31048086f8a956892db05e"),
		Fields: [sdk.NumMaxLogFields]sdk.LogFieldData{
			logFieldData,
			logFieldData,
			logFieldData,
			logFieldData,
		},
	}
	guest := &AppCircuit{}

	for i := 0; i < 13; i++ {
		app.AddReceipt(receipt, i)
	}
	app.AddReceipt(receipt, 15)

	// app.AddReceipt(receipt1, 16)
	app.AddReceipt(receipt1, 17)
	app.AddReceipt(receipt, 18)

	guestAssignment := &AppCircuit{}

	circuitInput, err := app.BuildCircuitInput(guest)
	assert.NoError(err)

	host := sdk.DefaultHostCircuit(guest)
	assignment := sdk.NewHostCircuit(circuitInput.Clone(), guestAssignment)

	err = test.IsSolved(host, assignment, ecc.BN254.ScalarField())
	assert.NoError(err)

	assert.ProverSucceeded(host, assignment, test.WithBackends(backend.PLONK), test.WithCurves(ecc.BN254))
}

type AppCircuit struct{}

func (c *AppCircuit) Allocate() (maxReceipts, maxStorage, maxTransactions int) {
	// Our app is only ever going to use one storage data at a time so
	// we can simply limit the max number of data for storage to 1 and
	// 0 for all others
	return 32, 32, 32
}

func (c *AppCircuit) Define(api *sdk.CircuitAPI, in sdk.DataInput) error {
	return nil
}
