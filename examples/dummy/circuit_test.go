package dummy

import (
	"math/big"
	"testing"

	"github.com/brevis-network/brevis-sdk/sdk"
	"github.com/brevis-network/brevis-sdk/test"
	"github.com/ethereum/go-ethereum/common"
)

func TestCircuit(t *testing.T) {
	app, err := sdk.NewBrevisApp()
	check(err)

	usdcPool := common.HexToAddress("0x88e6A0c2dDD26FEEb64F039a2c41296FcB3f5640")
	usdc := common.HexToAddress("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")
	swapEvent := common.HexToHash("0xc42079f94a6350d7e6235f29174924f928cc2ac818eb64fed8004e115fbcca67")
	amount0 := common.BytesToHash(big.NewInt(724999999).Bytes())
	recipient := common.HexToHash("0xEf1c6E67703c7BD7107eed8303Fbe6EC2554BF6B")
	transferEvent := common.HexToHash("0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef")
	from := common.HexToHash("0xaefB31e9EEee2822f4C1cBC13B70948b0B5C0b3c")

	app.AddReceipt(sdk.ReceiptData{
		BlockNum: big.NewInt(18064070),
		TxHash:   common.HexToHash("53b37ec7975d217295f4bdadf8043b261fc49dccc16da9b9fc8b9530845a5794"),
		Fields: [sdk.NumMaxLogFields]sdk.LogFieldData{
			{Contract: usdcPool, LogIndex: 3, EventID: swapEvent, IsTopic: false, FieldIndex: 0, Value: amount0},
			{Contract: usdcPool, LogIndex: 3, EventID: swapEvent, IsTopic: true, FieldIndex: 2, Value: recipient},
			{Contract: usdc, LogIndex: 2, EventID: transferEvent, IsTopic: true, FieldIndex: 1, Value: from},
		},
	})
	app.AddStorage(sdk.StorageData{
		BlockNum: big.NewInt(19526368),
		Address:  common.HexToAddress("0xb4e16d0168e52d35cacd2c6185b44281ec28c9dc"),
		Slot:     common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000008"),
		Value:    common.HexToHash("0x660432e30000000002c4161b6fe645e05c7300000000000000002a22f3e2696a"),
	})
	// app.AddTransaction(sdk.TransactionData{
	// 	Hash:                common.HexToHash("0x6dc75e61220cc775aafa17796c20e49ac08030020fce710e3e546aa4e003454c"),
	// 	ChainId:             big.NewInt(1),
	// 	BlockNum:            big.NewInt(19073244),
	// 	Nonce:               0,
	// 	GasTipCapOrGasPrice: big.NewInt(90000000000),
	// 	GasFeeCap:           big.NewInt(90000000000),
	// 	GasLimit:            21000,
	// 	From:                common.HexToAddress("0x6c2843bA78Feb261798be1AAC579d1A4aE2C64b4"),
	// 	To:                  common.HexToAddress("0x2F19E5C3C66C44E6405D4c200fE064ECe9bC253a"),
	// 	Value:               big.NewInt(22329290000000000),
	// })

	appCircuit := DefaultAppCircuit()
	appCircuitAssignment := DefaultAppCircuit()

	circuitInput, err := app.BuildCircuitInput(appCircuit)
	check(err)

	///////////////////////////////////////////////////////////////////////////////
	// Testing
	///////////////////////////////////////////////////////////////////////////////

	//test.IsSolved(t, appCircuit, appCircuitAssignment, circuitInput)
	test.ProverSucceeded(t, appCircuit, appCircuitAssignment, circuitInput)
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}
