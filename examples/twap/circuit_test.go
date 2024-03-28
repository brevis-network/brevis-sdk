package twap

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

	EthUsdcPair := common.HexToAddress("0xb4e16d0168e52d35cacd2c6185b44281ec28c9dc")

	app.AddStorage(sdk.StorageData{
		BlockNum: big.NewInt(19526368),
		Address:  EthUsdcPair,
		Slot:     common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000008"),
		Value:    common.HexToHash("0x660432e30000000002c4161b6fe645e05c7300000000000000002a22f3e2696a"),
	})
	app.AddStorage(sdk.StorageData{
		BlockNum: big.NewInt(19526368),
		Address:  EthUsdcPair,
		Slot:     common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000009"),
		Value:    common.HexToHash("0x00000000000000000000019b6ca7cb3f482e755f0ae619a871a9063e714e0228"),
	})
	app.AddStorage(sdk.StorageData{
		BlockNum: big.NewInt(19526368),
		Address:  EthUsdcPair,
		Slot:     common.HexToHash("0x000000000000000000000000000000000000000000000000000000000000000a"),
		Value:    common.HexToHash("0x0000000000000000000000000000000000003c6758abe60870a58346dc922d52"),
	})

	app.AddStorage(sdk.StorageData{
		BlockNum: big.NewInt(19526488),
		Address:  EthUsdcPair,
		Slot:     common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000008"),
		Value:    common.HexToHash("0x660438fb0000000002c6557cb610af1b5a9a00000000000000002a01003339d6"),
	})
	app.AddStorage(sdk.StorageData{
		BlockNum: big.NewInt(19526488),
		Address:  EthUsdcPair,
		Slot:     common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000009"),
		Value:    common.HexToHash("0x00000000000000000000019b6d0e62545015c41043d402698c29cd0e2ff08de8"),
	})
	app.AddStorage(sdk.StorageData{
		BlockNum: big.NewInt(19526488),
		Address:  EthUsdcPair,
		Slot:     common.HexToHash("0x000000000000000000000000000000000000000000000000000000000000000a"),
		Value:    common.HexToHash("0x0000000000000000000000000000000000003c67b555a558e4d4d6ed040d547a"),
	})

	appCircuit := &AppCircuit{}
	appCircuitAssignment := &AppCircuit{}

	in, err := app.BuildCircuitInput(appCircuitAssignment)
	check(err)

	///////////////////////////////////////////////////////////////////////////////
	// Testing
	///////////////////////////////////////////////////////////////////////////////

	// Use the test package to check if the circuit can be solved using the given
	// assignment
	test.ProverSucceeded(t, appCircuit, appCircuitAssignment, in)
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}
