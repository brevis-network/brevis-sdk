package sdk

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/brevis-network/zk-hash/poseidon"
	"github.com/brevis-network/zk-hash/utils"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
)

type TestPackBitsToFrCircuit struct {
	Bits         []frontend.Variable
	ExpectPacked []frontend.Variable
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
	packed := packBitsToInt(bits, 253)
	fmt.Printf("go packed %v\n", packed)
	c := &TestPackBitsToFrCircuit{
		Bits:         newVars(bits),
		ExpectPacked: newVars(packed),
	}
	w := &TestPackBitsToFrCircuit{
		Bits:         newVars(bits),
		ExpectPacked: newVars(packed),
	}
	err := test.IsSolved(c, w, ecc.BN254.ScalarField())
	if err != nil {
		t.Error(err)
	}
}

type TestReceiptPackCircuit struct {
	Receipt      Receipt             `gnark:",public"`
	ExpectPacked []frontend.Variable `gnark:",public"`
	ExpectHash   frontend.Variable   `gnark:",public"`
}

func (c *TestReceiptPackCircuit) Define(api frontend.API) error {
	packed := c.Receipt.pack(api)
	fmt.Println("circuit packed", packed)
	hasher, _ := poseidon.NewBn254PoseidonCircuit(api)
	if len(packed) > 16 {
		panic("out of length")
	}
	for i, v := range packed {
		api.AssertIsEqual(v, c.ExpectPacked[i])
		hasher.Write(v)
	}
	h := hasher.Sum()
	fmt.Printf("circuit hash: %s\n", h)
	api.AssertIsEqual(h, c.ExpectHash)
	return nil
}

func TestReceiptPack(t *testing.T) {
	r := Receipt{
		BlockNum:     ConstUint32(1234567),
		BlockBaseFee: ConstUint248(1),
		MptKeyPath:   ConstUint32(240),
		Fields:       [NumMaxLogFields]LogField{},
	}
	for i := range r.Fields {
		r.Fields[i] = LogField{
			Contract: ConstUint248(common.HexToAddress("0xDEF171Fe48CF0115B1d80b88dc8eAB59176FEe57")),
			LogPos:   ConstUint32(1),
			EventID:  ParseEventID(hexutil.MustDecode("0xDEF171Fe48CF")),
			IsTopic:  ConstUint248(true),
			Index:    ConstUint248(0),
			Value:    ConstFromBigEndianBytes(hexutil.MustDecode("0x1234")),
		}
	}
	fmt.Println("expected packed", r.goPack())

	hasher := utils.NewPoseidonBn254()
	for _, v := range r.goPack() {
		hasher.Write(new(big.Int).SetBytes(common.LeftPadBytes(v.Bytes(), 32)))
	}

	h, err := hasher.Sum()
	if err != nil {
		t.Error(err)
	}
	fmt.Printf("expected hash: %s\n", h)

	c := &TestReceiptPackCircuit{
		Receipt:      r,
		ExpectPacked: newVars(r.goPack()),
		ExpectHash:   h,
	}
	a := &TestReceiptPackCircuit{
		Receipt:      r,
		ExpectPacked: newVars(r.goPack()),
		ExpectHash:   h,
	}

	err = test.IsSolved(c, a, ecc.BN254.ScalarField())
	if err != nil {
		t.Error(err)
	}
}

type TestStoragePackCircuit struct {
	Slot   StorageSlot         `gnark:",public"`
	Packed []frontend.Variable `gnark:",public"`
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
		BlockNum:     ConstUint32(1234567),
		BlockBaseFee: ConstUint248(1),
		Contract:     ConstUint248(common.HexToAddress("0xDEF171Fe48CF0115B1d80b88dc8eAB59176FEe57")),
		Slot:         ConstFromBigEndianBytes(common.FromHex("0x9c2d3d42dcdafb0cb8c10089d02447b96c5fce87f298e50f88f2e188a6afcc41")),
		Value:        ConstFromBigEndianBytes(common.FromHex("0xaa4ba4b304228a9d05087e147c9e86d84c708bbbe62bb35b28dab74492f6c726")),
	}
	c := &TestStoragePackCircuit{
		Slot:   s,
		Packed: newVars(s.goPack()),
	}
	a := &TestStoragePackCircuit{
		Slot:   s,
		Packed: newVars(s.goPack()),
	}

	err := test.IsSolved(c, a, ecc.BN254.ScalarField())
	if err != nil {
		t.Error(err)
	}
}

type TestTransactionPackCircuit struct {
	Transaction Transaction         `gnark:",public"`
	Packed      []frontend.Variable `gnark:",public"`
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
		// ChainId:             ConstUint248(1),
		BlockNum:     ConstUint32(1234567),
		BlockBaseFee: ConstUint248(1),
		MptKeyPath:   ConstUint32(240),
		// Nonce:               ConstUint248(123),
		// GasTipCapOrGasPrice: ConstUint248(1234567890),
		// GasFeeCap:           ConstUint248(1876543212),
		// GasLimit:            ConstUint248(123456),
		// From:                ConstUint248(common.HexToAddress("0x58b529F9084D7eAA598EB3477Fe36064C5B7bbC1")),
		// To:                  ConstUint248(common.HexToAddress("0xDEF171Fe48CF0115B1d80b88dc8eAB59176FEe57")),
		// Value:               ConstBytes32(hexutil.MustDecode("0xaa4ba4b304228a9d05087e147c9e86d84c708bbbe62bb35b28dab74492f6c726")),
		LeafHash: ConstFromBigEndianBytes(hexutil.MustDecode("0x784ba4b304228a9d05087e147c9e86d84c708bbbe62bb35b28dab74492f6c732")),
	}
	c := &TestTransactionPackCircuit{
		Transaction: tx,
		Packed:      newVars(tx.goPack()),
	}
	a := &TestTransactionPackCircuit{
		Transaction: tx,
		Packed:      newVars(tx.goPack()),
	}

	err := test.IsSolved(c, a, ecc.BN254.ScalarField())
	if err != nil {
		t.Error(err)
	}
}

func TestReceiptCircuitVariable(t *testing.T) {
	r := Receipt{
		BlockNum:     ConstUint32(1234567),
		BlockBaseFee: ConstUint248(1),
		MptKeyPath:   ConstUint32(240),
		Fields: [NumMaxLogFields]LogField{
			{
				Contract: ConstUint248(common.HexToAddress("0xDEF171Fe48CF0115B1d80b88dc8eAB59176FEe57")),
				LogPos:   ConstUint32(1),
				EventID:  ParseEventID(hexutil.MustDecode("0xDEF171Fe48CF")),
				IsTopic:  ConstUint248(true),
				Index:    ConstUint248(0),
				Value:    ConstFromBigEndianBytes(hexutil.MustDecode("0x1234")),
			},
			{
				Contract: ConstUint248(common.HexToAddress("0xDEF171Fe18CF0115B1d80b88dc8eAB59176FEe57")),
				LogPos:   ConstUint32(1),
				EventID:  ParseEventID(hexutil.MustDecode("0xDEF171F148CF")),
				IsTopic:  ConstUint248(false),
				Index:    ConstUint248(0),
				Value:    ConstFromBigEndianBytes(hexutil.MustDecode("0x1234")),
			},
		},
	}
	values := r.Values()
	reconstructed := r.FromValues(values...)
	compareValues(t, values, reconstructed.Values())
}

func TestStorageCircuitVariable(t *testing.T) {
	s := StorageSlot{
		BlockNum: ConstUint32(1234567),
		Contract: ConstUint248(common.HexToAddress("0xDEF171Fe48CF0115B1d80b88dc8eAB59176FEe57")),
		Slot:     ConstFromBigEndianBytes(hexutil.MustDecode("0x9c2d3d42dcdafb0cb8c10089d02447b96c5fce87f298e50f88f2e188a6afcc41")),
		Value:    ConstFromBigEndianBytes(hexutil.MustDecode("0xaa4ba4b304228a9d05087e147c9e86d84c708bbbe62bb35b28dab74492f6c726")),
	}
	values := s.Values()
	reconstructed := s.FromValues(values...)
	compareValues(t, values, reconstructed.Values())
}

func TestTransactionCircuitVariable(t *testing.T) {
	tx := Transaction{
		// ChainId:             ConstUint248(1),
		// BlockNum:            ConstUint32(1234567),
		// Nonce:               ConstUint248(123),
		// GasTipCapOrGasPrice: ConstUint248(1234567890),
		// GasFeeCap:           ConstUint248(1876543212),
		// GasLimit:            ConstUint248(123456),
		// From:                ConstUint248(common.HexToAddress("0x58b529F9084D7eAA598EB3477Fe36064C5B7bbC1")),
		// To:                  ConstUint248(common.HexToAddress("0xDEF171Fe48CF0115B1d80b88dc8eAB59176FEe57")),
		// Value:               ConstBytes32(hexutil.MustDecode("0xaa4ba4b304228a9d05087e147c9e86d84c708bbbe62bb35b28dab74492f6c726")),
		LeafHash: ConstFromBigEndianBytes(hexutil.MustDecode("0x784ba4b304228a9d05087e147c9e86d84c708bbbe62bb35b28dab74492f6c732")),
	}
	values := tx.Values()
	reconstructed := tx.FromValues(values...)
	compareValues(t, values, reconstructed.Values())
}

func compareValues(t *testing.T, a, b []frontend.Variable) {
	if len(a) != len(b) {
		t.Errorf("len(a) (%d) != len(b) (%d)", len(a), len(b))
	}
	for i, v := range a {
		if b[i] == nil && v == nil {
			continue
		}
		if b[i].(*big.Int).Cmp(v.(*big.Int)) != 0 {
			fmt.Println("a", a)
			fmt.Println("b", b)
			t.Errorf("a[%d] (%d) != b[%d] (%d)", i, a[i], i, b[i])
			t.FailNow()
		}
	}
}
