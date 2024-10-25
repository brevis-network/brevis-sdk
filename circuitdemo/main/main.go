package main

import (
	"bytes"
	"fmt"
	"math/big"
	"path/filepath"

	"github.com/brevis-network/brevis-sdk/common/utils"
	"github.com/brevis-network/brevis-sdk/sdk"
	"github.com/brevis-network/brevis-sdk/sdk/proto/gwproto"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
)

type AppCircuit struct{}

func (c *AppCircuit) Allocate() (maxReceipts, maxStorage, maxTransactions int) {
	// Our app is only ever going to use one storage data at a time so
	// we can simply limit the max number of data for storage to 1 and
	// 0 for all others
	return 32, 32, 32
}

func (c *AppCircuit) Define(api *sdk.CircuitAPI, in sdk.DataInput) error {
	api.OutputBool(sdk.ConstUint248(1))

	receipts := sdk.NewDataStream(api, in.Receipts)
	receipt := sdk.GetUnderlying(receipts, 0)
	api.OutputUint32(32, receipt.BlockNum)
	api.OutputAddress(receipt.Fields[0].Contract)

	api.AssertInputsAreUnique()
	return nil
}

func main() {
	outDir := "$HOME/circuitOut/myBrevisApp"
	localDir := "$HOME/circuitOut/myBrevisApp/input"
	srsDir := "$HOME/kzgsrs"
	rpc := "RPC_URL"
	app, err := sdk.NewBrevisApp(1, rpc, localDir)
	check(err)
	logFieldData := sdk.LogFieldData{
		LogPos:     0,
		IsTopic:    false,
		FieldIndex: 0,
	}

	receipt := sdk.ReceiptData{
		TxHash: utils.Hex2Hash("0x3b762c2829801787b44ea8afba9510241014faa7dd86dbf03d729846aa346894"),
		Fields: []sdk.LogFieldData{
			logFieldData,
		},
	}

	app.AddReceipt(receipt)

	for i := 0; i < 1; i++ {
		app.AddStorage(sdk.StorageData{
			BlockNum: new(big.Int).SetUint64(20861588),
			Address:  utils.Hex2Addr("0x4446e0f8417C1db113899929A8F3cEe8e0DcBCDb"),
			Slot:     utils.Hex2Hash("0x0000000000000000000000000000000000000000000000000000000000000000"),
		})
	}

	for i := 0; i < 10; i++ {
		app.AddTransaction(sdk.TransactionData{
			Hash: utils.Hex2Hash("0x3b762c2829801787b44ea8afba9510241014faa7dd86dbf03d729846aa346894"),
		}, i)
	}

	appCircuitAssignment := &AppCircuit{}

	compiledCircuit, pk, vk, vkHash, err := sdk.Compile(&AppCircuit{}, outDir, srsDir)
	check(err)
	circuitInput, err := app.BuildCircuitInput(appCircuitAssignment)
	check(err)
	witness, publicWitness, err := sdk.NewFullWitness(appCircuitAssignment, circuitInput)
	check(err)
	proof, err := sdk.Prove(compiledCircuit, pk, witness)
	check(err)
	err = sdk.WriteTo(proof, filepath.Join(outDir, "proof-"))
	check(err)
	err = sdk.Verify(vk, publicWitness, proof)
	check(err)

	appContract := common.HexToAddress("0xeec66d9b615ff84909be1cb1fe633cc26150417d")
	refundee := common.HexToAddress("0x1bF81EA1F2F6Afde216cD3210070936401A14Bd4")

	buf := bytes.NewBuffer([]byte{})
	proof.WriteTo(buf)
	fmt.Println("Proof: ", hexutil.Encode(buf.Bytes()))

	_, _, _, _, err = app.PrepareRequest(vk, witness, 1, 11155111, refundee, appContract, 400000, gwproto.QueryOption_ZK_MODE.Enum(), "", vkHash)
	check(err)

	err = app.SubmitProof(proof)
	check(err)
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}
