package sdk

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"math/big"
	"testing"
)

func TestCircuitAPI(t *testing.T) {
	c := &TestCircuitAPICircuit{}
	err := test.IsSolved(c, c, ecc.BLS12_377.ScalarField())
	check(err)
}

type TestCircuitAPICircuit struct {
	g   frontend.API
	api *CircuitAPI
}

var testU248_a = ConstUint248(1)
var testBytes32_b = ConstBytes32([]byte{1})
var testU521_c = ConstUint521([]byte{1})

func (c *TestCircuitAPICircuit) Define(g frontend.API) error {
	api := NewCircuitAPI(g)
	c.api = api
	c.g = g

	c.testCasting()
	c.testOutput()
	c.testMappingStorageKey()

	return nil
}

func (c *TestCircuitAPICircuit) testToBytes32() {
	A := ConstBytes32([]byte{1})
	B := ConstUint248(1)
	C := ConstUint521([]byte{1})
	D := ConstInt248(big.NewInt(1))

	api := c.api
	api.Bytes32.AssertIsEqual(api.ToBytes32(B), A)
	api.Bytes32.AssertIsEqual(api.ToBytes32(C), A)
	api.Bytes32.AssertIsEqual(api.ToBytes32(D), A)
}

func (c *TestCircuitAPICircuit) testCasting() {
	api := c.api
	api.Bytes32.AssertIsEqual(api.ToBytes32(testU248_a), testBytes32_b)
	api.Bytes32.AssertIsEqual(api.ToBytes32(testU521_c), testBytes32_b)

	api.Uint248.AssertIsEqual(api.ToUint248(testBytes32_b), testU248_a)
	api.Uint248.AssertIsEqual(api.ToUint248(testU521_c), testU248_a)

	api.Uint521.AssertIsEqual(api.ToUint521(testU248_a), testU521_c)
	api.Uint521.AssertIsEqual(api.ToUint521(testBytes32_b), testU521_c)

	one := ConstUint521([]byte{1})
	_u256Max := new(big.Int)
	_u256Max.Lsh(big.NewInt(1), 256).Sub(_u256Max, big.NewInt(1))
	u256Max := ConstUint521(_u256Max.Bytes())

	sum := api.Uint521.Add(u256Max, u256Max)
	_sum := new(big.Int).Add(_u256Max, _u256Max)
	api.Uint521.AssertIsEqual(sum, ConstUint521(_sum.Bytes()))

	diff := api.Uint521.Sub(u256Max, api.Uint521.Sub(u256Max, one))
	api.Uint521.AssertIsEqual(diff, one)

	product := api.Uint521.Mul(u256Max, u256Max)
	_product := new(big.Int).Mul(_u256Max, _u256Max)
	api.Uint521.AssertIsEqual(product, ConstUint521(_product.Bytes()))

	q, r := api.Uint521.Div(ConstUint521([]byte{4}), ConstUint521([]byte{3}))
	api.Uint521.AssertIsEqual(q, one)
	api.Uint521.AssertIsEqual(r, ConstUint521([]byte{1}))

	q, r = api.Uint521.Div(u256Max, api.Uint521.Sub(u256Max, one))
	api.Uint521.AssertIsEqual(q, one)
	api.Uint521.AssertIsEqual(r, one)
}

func (c *TestCircuitAPICircuit) testOutput() {
	api := c.api

	bool1 := common.FromHex("0x01")
	bool2 := common.FromHex("0x00")
	u32 := common.LeftPadBytes(big.NewInt(32).Bytes(), 4)
	u64 := common.LeftPadBytes(big.NewInt(64).Bytes(), 8)
	u248 := common.LeftPadBytes(big.NewInt(248).Bytes(), 31)
	addr := common.HexToAddress("0xaefB31e9EEee2822f4C1cBC13B70948b0B5C0b3c")
	b32 := common.FromHex("c6a377bfc4eb120024a8ac08eef205be16b817020812c73223e81d1bdb9708ec")

	api.OutputBool(ConstUint248(1))
	api.OutputBool(ConstUint248(0))
	api.OutputUint(32, ConstUint248(32))
	api.OutputUint(64, ConstUint248(64))
	api.OutputUint(248, ConstUint248(248))
	api.OutputAddress(ConstUint248(addr))
	api.OutputBytes32(ConstBytes32(b32))

	var packed []byte
	packed = append(packed, bool1...)
	packed = append(packed, bool2...)
	packed = append(packed, u32...)
	packed = append(packed, u64...)
	packed = append(packed, u248...)
	packed = append(packed, addr[:]...)
	packed = append(packed, b32...)

	var bits []uint
	for _, b := range packed {
		for i := 0; i < 8; i++ {
			bits = append(bits, uint(b>>i&1))
		}
	}

	if len(bits) != len(api.output) {
		panic("inconsistent len")
	}
	for i, bit := range bits {
		c.g.AssertIsEqual(bit, api.output[i])
	}
}

func (c *TestCircuitAPICircuit) testMappingStorageKey() {
	api := c.api
	mapKey := common.FromHex("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFCEE6A")
	storageKey := api.StorageKeyOfStructFieldInMapping(6, 1, ConstBytes32(mapKey))
	fmt.Printf("feeGrowthOutside0X128 storage key %s\n", storageKey)

	k := common.FromHex("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFCEE6A")
	k = append(k, common.LeftPadBytes([]byte{6}, 32)...)
	expected := crypto.Keccak256(k)
	fmt.Printf("expected: %x\n", expected)
}
