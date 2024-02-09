package sdk

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/celer-network/zk-utils/circuits/gadgets/utils"
	"github.com/consensys/gnark-crypto/ecc"
	mimc_native "github.com/consensys/gnark-crypto/ecc/bls12-377/fr/mimc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/test"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
)

type TestPackBitsToFrCircuit struct {
	Bits         []Uint248
	ExpectPacked []Uint248
}

func (c *TestPackBitsToFrCircuit) Define(api frontend.API) error {
	packed := packBitsToFr(api, c.Bits)
	fmt.Printf("circuit packed %v\n", packed)
	for i, v := range packed {
		api.AssertIsEqual(v, c.ExpectPacked[i])
	}
	return nil
}

func TestPackBitsToFr(t *testing.T) {
	bits := []uint{0, 1, 1, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 1, 1, 1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1, 1, 1, 1, 1, 1, 0, 1, 1, 0, 1, 0, 0, 1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 1, 0, 0, 1, 1, 0, 1, 1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 0, 0, 1, 0, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0, 1, 1, 0, 1, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 1, 0, 0, 0, 1, 0, 0, 0, 1, 1, 1, 0, 0, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 1, 0, 1, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 1, 1, 1, 1, 1, 0, 0, 1, 0, 1, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1, 1, 1, 1, 1, 1, 0, 1, 1, 0, 1, 0, 0, 1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 1, 0, 0, 1, 1, 0, 1, 1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 0, 0, 1, 0, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0, 1, 1, 0, 1, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 1, 0, 0, 0, 1, 0, 0, 0, 1, 1, 1, 0, 0, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 1, 0, 1, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 1, 0, 1, 1, 0, 0, 0, 1, 1, 1, 0, 0, 0, 1, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 1, 1, 0, 1, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 1, 1, 0, 1, 1, 1, 0, 1, 1, 0, 0, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 1, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0, 1, 1, 1, 1, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 1, 0, 0, 0, 1, 1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0, 0, 1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 1, 0, 1, 0, 0, 1, 0, 1, 0, 1, 1, 1, 0, 0, 1, 1, 0, 0, 0, 1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 1, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0, 0, 0, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 0, 0, 1, 1, 1, 1, 1, 0, 1, 1, 0, 0, 0, 1, 0, 1, 1, 0, 1, 0, 1, 0, 1, 0, 0, 1, 0, 1, 0, 0, 1, 0, 0, 1, 1, 1, 1, 1, 0, 1, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0, 1, 1, 0, 0, 0, 1, 1, 0, 1, 1, 1, 0, 1, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	packed := packBitsToInt(bits, 252)
	fmt.Printf("go packed %v\n", packed)
	c := &TestPackBitsToFrCircuit{
		Bits:         utils.Slice2FVs(bits),
		ExpectPacked: utils.Slice2FVs(packed),
	}
	w := &TestPackBitsToFrCircuit{
		Bits:         utils.Slice2FVs(bits),
		ExpectPacked: utils.Slice2FVs(packed),
	}
	err := test.IsSolved(c, w, ecc.BLS12_377.ScalarField())
	if err != nil {
		t.Error(err)
	}
}

type TestReceiptPackCircuit struct {
	Receipt      Receipt   `gnark:",public"`
	ExpectPacked []Uint248 `gnark:",public"`
	ExpectHash   Uint248   `gnark:",public"`
}

func (c *TestReceiptPackCircuit) Define(api frontend.API) error {
	packed := c.Receipt.pack(api)
	fmt.Println("circuit packed", packed)
	for i, v := range packed {
		api.AssertIsEqual(v, c.ExpectPacked[i])
	}
	hasher, _ := mimc.NewMiMC(api)
	hasher.Write(packed...)
	h := hasher.Sum()
	fmt.Printf("circuit hash: %s\n", h)
	api.AssertIsEqual(h, c.ExpectHash)
	return nil
}

func TestReceiptPack(t *testing.T) {
	r := Receipt{
		BlockNum: 1234567,
		Fields: [3]LogField{
			{
				Contract: ParseAddress(common.HexToAddress("0xDEF171Fe48CF0115B1d80b88dc8eAB59176FEe57")),
				EventID:  ParseEventID(hexutil.MustDecode("0xDEF171Fe48CF")),
				IsTopic:  ParseBool(true),
				Index:    0,
				Value:    ParseBytes32(hexutil.MustDecode("0x1234")),
			},
			{
				Contract: ParseAddress(common.HexToAddress("0xDEF171Fe18CF0115B1d80b88dc8eAB59176FEe57")),
				EventID:  ParseEventID(hexutil.MustDecode("0xDEF171F148CF")),
				IsTopic:  ParseBool(false),
				Index:    0,
				Value:    ParseBytes32(hexutil.MustDecode("0x1234")),
			},
			NewLogField(),
		},
	}
	fmt.Println("expected packed", r.goPack())

	hasher := mimc_native.NewMiMC()
	for _, v := range r.goPack() {
		hasher.Write(common.LeftPadBytes(v.Bytes(), 32))
	}
	h := new(big.Int).SetBytes(hasher.Sum(nil))
	fmt.Printf("expected hash: %s\n", h)

	c := &TestReceiptPackCircuit{
		Receipt:      r,
		ExpectPacked: utils.Slice2FVs(r.goPack()),
		ExpectHash:   h,
	}
	a := &TestReceiptPackCircuit{
		Receipt:      r,
		ExpectPacked: utils.Slice2FVs(r.goPack()),
		ExpectHash:   h,
	}

	err := test.IsSolved(c, a, ecc.BLS12_377.ScalarField())
	if err != nil {
		t.Error(err)
	}
}

type TestStoragePackCircuit struct {
	Slot   StorageSlot `gnark:",public"`
	Packed []Uint248   `gnark:",public"`
}

func (c *TestStoragePackCircuit) Define(api frontend.API) error {
	packed := c.Slot.pack(api)
	fmt.Println("expected packed", c.Packed)
	fmt.Println("circuit packed", packed)
	for i, v := range packed {
		api.AssertIsEqual(v, c.Packed[i])
	}
	return nil
}

func TestStoragePack(t *testing.T) {
	s := StorageSlot{
		BlockNum: 1234567,
		Contract: ParseAddress(common.HexToAddress("0xDEF171Fe48CF0115B1d80b88dc8eAB59176FEe57")),
		Key:      ParseBytes32(hexutil.MustDecode("0x9c2d3d42dcdafb0cb8c10089d02447b96c5fce87f298e50f88f2e188a6afcc41")),
		Value:    ParseBytes32(hexutil.MustDecode("0xaa4ba4b304228a9d05087e147c9e86d84c708bbbe62bb35b28dab74492f6c726")),
	}
	c := &TestStoragePackCircuit{
		Slot:   s,
		Packed: utils.Slice2FVs(s.goPack()),
	}
	a := &TestStoragePackCircuit{
		Slot:   s,
		Packed: utils.Slice2FVs(s.goPack()),
	}

	err := test.IsSolved(c, a, ecc.BLS12_377.ScalarField())
	if err != nil {
		t.Error(err)
	}
}

type TestTransactionPackCircuit struct {
	Transaction Transaction `gnark:",public"`
	Packed      []Uint248   `gnark:",public"`
}

func (c *TestTransactionPackCircuit) Define(api frontend.API) error {
	packed := c.Transaction.pack(api)
	fmt.Println("expected packed", c.Packed)
	fmt.Println("circuit packed", packed)
	for i, v := range packed {
		api.AssertIsEqual(v, c.Packed[i])
	}
	return nil
}

func TestTransactionPack(t *testing.T) {
	tx := Transaction{
		ChainId:              1,
		BlockNum:             1234567,
		Nonce:                123,
		MaxPriorityFeePerGas: 1234567890,
		GasPriceOrFeeCap:     1876543212,
		GasLimit:             123456,
		From:                 ParseAddress(common.HexToAddress("0x58b529F9084D7eAA598EB3477Fe36064C5B7bbC1")),
		To:                   ParseAddress(common.HexToAddress("0xDEF171Fe48CF0115B1d80b88dc8eAB59176FEe57")),
		Value:                ParseBytes32(hexutil.MustDecode("0xaa4ba4b304228a9d05087e147c9e86d84c708bbbe62bb35b28dab74492f6c726")),
	}
	c := &TestTransactionPackCircuit{
		Transaction: tx,
		Packed:      utils.Slice2FVs(tx.goPack()),
	}
	a := &TestTransactionPackCircuit{
		Transaction: tx,
		Packed:      utils.Slice2FVs(tx.goPack()),
	}

	err := test.IsSolved(c, a, ecc.BLS12_377.ScalarField())
	if err != nil {
		t.Error(err)
	}
}
