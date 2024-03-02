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

func (c *TestCircuitAPICircuit) Define(g frontend.API) error {
	api := NewCircuitAPI(g)
	c.api = api
	c.g = g

	c.testCasting()
	c.testOutput()
	c.testMappingStorageKey()

	return nil
}

func (c *TestCircuitAPICircuit) testCasting() {
	A := ConstUint248(1)
	B := ConstBytes32([]byte{1})
	C := ConstUint521([]byte{1})
	D := ConstInt248(big.NewInt(-2))
	E := ConstBytes32(common.FromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE"))
	F := ConstInt248(big.NewInt(1))
	G := ConstUint248(common.FromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE"))

	api := c.api
	api.Bytes32.AssertIsEqual(api.ToBytes32(A), B)
	api.Bytes32.AssertIsEqual(api.ToBytes32(C), B)
	api.Bytes32.AssertIsEqual(api.ToBytes32(D), E)

	api.Uint248.AssertIsEqual(api.ToUint248(B), A)
	api.Uint248.AssertIsEqual(api.ToUint248(C), A)
	api.Uint248.AssertIsEqual(api.ToUint248(D), G)

	api.Uint521.AssertIsEqual(api.ToUint521(A), C)
	api.Uint521.AssertIsEqual(api.ToUint521(B), C)

	api.Int248.AssertIsEqual(api.ToInt248(E), D)
	api.Int248.AssertIsEqual(api.ToInt248(A), F)
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
	storageMptKey := api.StorageKeyOfStructFieldInMapping(6, 1, ConstBytes32(mapKey))
	fmt.Printf("storage mpt key %s\n", storageMptKey)

	preimage := common.FromHex("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFCEE6A")
	preimage = append(preimage, common.LeftPadBytes([]byte{6}, 32)...)
	h := crypto.Keccak256(preimage)
	expected := new(big.Int).SetBytes(h)
	expected.Add(expected, big.NewInt(1))
	expectedKey := expected.Bytes()
	expectedKey = crypto.Keccak256(expectedKey)
	fmt.Printf("expected: %x\n", expectedKey)

	api.Bytes32.AssertIsEqual(storageMptKey, ConstBytes32(expectedKey))

	// TODO add tests for nested mapping cases
}
