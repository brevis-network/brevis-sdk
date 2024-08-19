package test

import (
	"context"
	"github.com/brevis-network/brevis-sdk/common/utils"
	"github.com/brevis-network/brevis-sdk/sdk"
	test2 "github.com/brevis-network/brevis-sdk/test"
	"github.com/celer-network/goutils/log"
	"github.com/consensys/gnark/test"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"testing"
)

func TestDemo(t *testing.T) {
	assert := test.NewAssert(t)
	app, err := sdk.NewBrevisApp()
	assert.NoError(err)
	ec, err := ethclient.Dial("https://eth.llamarpc.com")
	assert.NoError(err)

	chainId, err := ec.ChainID(context.Background())
	assert.NoError(err)

	log.Infof("chainId: %d", chainId)

	txHash := common.HexToHash(
		"fa83502d12b5307074dbac97436c6366443b83a6ac48299837408337a0c5d5bc")
	receipt, err := ec.TransactionReceipt(context.Background(), txHash)
	assert.NoError(err)

	app.AddReceipt(sdk.ReceiptData{
		BlockNum: receipt.BlockNumber,
		TxHash:   receipt.TxHash,
		Fields: [sdk.NumMaxLogFields]sdk.LogFieldData{
			{Contract: utils.Hex2Addr("0x5427FEFA711Eff984124bFBB1AB6fbf5E3DA1820"), LogIndex: 1, EventID: utils.Hex2Hash("89d8051e597ab4178a863a5190407b98abfeff406aa8db90c59af76612e58f01"), IsTopic: false, FieldIndex: 4, Value: utils.Hex2Hash("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")},
		},
	})

	guest := &AppCircuit{}
	guestAssignment := &AppCircuit{}

	circuitInput, err := app.BuildCircuitInput(guest)
	assert.NoError(err)

	test2.ProverSucceeded(t, guest, guestAssignment, circuitInput)
}

type AppCircuit struct{}

func (c *AppCircuit) Allocate() (maxReceipts, maxStorage, maxTransactions int) {
	// Our app is only ever going to use one storage data at a time so
	// we can simply limit the max number of data for storage to 1 and
	// 0 for all others
	return 1, 0, 0
}

func (c *AppCircuit) Define(api *sdk.CircuitAPI, in sdk.DataInput) error {
	return nil
}
