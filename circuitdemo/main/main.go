package main

import (
	"bytes"
	"context"
	"fmt"
	"math/big"
	"path/filepath"

	"github.com/brevis-network/brevis-sdk/common/utils"
	"github.com/brevis-network/brevis-sdk/sdk"
	"github.com/brevis-network/brevis-sdk/sdk/proto/gwproto"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/ethclient/gethclient"
	"github.com/ethereum/go-ethereum/rpc"
)

type AppCircuit struct{}

func (c *AppCircuit) Allocate() (maxReceipts, maxStorage, maxTransactions int) {
	return 32, 32, 64
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
	outDir := "$HOME/circuitOut/circuitDemo"
	srsDir := "$HOME/kzgsrs"
	rpcUrl := "https://xlayer.drpc.org"
	app, err := sdk.NewBrevisApp(196, rpcUrl, outDir)
	check(err)
	logFieldData := sdk.LogFieldData{
		LogPos:     0,
		IsTopic:    true,
		FieldIndex: 0,
	}

	receipt := sdk.ReceiptData{
		TxHash: utils.Hex2Hash("0x302b1d5e3cbd699961330bfbcce50dae38aa33ee1012c173fd360952cbfca8f9"),
		Fields: []sdk.LogFieldData{
			logFieldData,
		},
	}

	for i := 0; i < 1; i++ {
		app.AddReceipt(receipt)
	}

	rpcc, err := rpc.Dial(rpcUrl)
	ec := ethclient.NewClient(rpcc)
	bk, err := ec.BlockNumber(context.Background())
	// gc := gethclient.New(rpcc)

	for i := 0; i < 1; i++ {
		app.AddStorage(sdk.StorageData{
			BlockNum: new(big.Int).SetUint64(bk),
			Address:  utils.Hex2Addr("0x17e3F630D07cd78def09020D3F8dc0198A07fe1A"),
			Slot:     utils.Hex2Hash("0x0000000000000000000000000000000000000000000000000000000000000000"),
		})
	}

	for i := 0; i < 1; i++ {
		app.AddTransaction(sdk.TransactionData{
			Hash: utils.Hex2Hash("0x302b1d5e3cbd699961330bfbcce50dae38aa33ee1012c173fd360952cbfca8f9"),
		}, i)
	}

	appCircuitAssignment := &AppCircuit{}

	circuitInput, err := app.BuildCircuitInput(appCircuitAssignment)
	check(err)

	for _, a := range circuitInput.InputCommitments {
		fmt.Println(a)
	}

	compiledCircuit, pk, vk, _, err := sdk.Compile(&AppCircuit{}, outDir, srsDir)
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

	_, _, _, _, err = app.PrepareRequest(vk, witness, 196, 196, refundee, appContract, 400000, gwproto.QueryOption_ZK_MODE.Enum(), "")
	check(err)

	err = app.SubmitProof(proof)
	check(err)
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}

func newGethClient(rpcc *rpc.Client) *gethclient.Client {
	gethC := gethclient.New(rpcc)
	return gethC
}
