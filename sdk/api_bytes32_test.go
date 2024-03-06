package sdk

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"github.com/ethereum/go-ethereum/common"
	"testing"
)

func TestBytes32API(t *testing.T) {
	c := &TestBytes32APICircuit{}
	err := test.IsSolved(c, c, ecc.BLS12_377.ScalarField())
	check(err)
}

type TestBytes32APICircuit struct {
	g   frontend.API
	b32 *Bytes32API
}

func (c *TestBytes32APICircuit) Define(g frontend.API) error {
	c.g = g
	c.b32 = newBytes32API(g)

	c.testBinary()
	c.testEqual()
	c.testSelect()
	c.testIsZero()

	return nil
}

var testBytes = common.HexToHash("65ad6deeb12705855d1d6232650400730e14e78ad5d3c8f160879f33dacf07f4")
var testBytes2 = common.HexToHash("75ad6deeb12705855d1d6232650400730e14e78ad5d3c8f160879f33dacf07f4")
var testBits = "0110010110101101011011011110111010110001001001110000010110000101010111010001110101100010001100100110010100000100000000000111001100001110000101001110011110001010110101011101001111001000111100010110000010000111100111110011001111011010110011110000011111110100"

func (c *TestBytes32APICircuit) testBinary() {
	a := ConstBytes32(testBytes[:])
	bin := c.b32.ToBinary(a)
	for i, b := range flipByGroups(parseBitStr(testBits), 1) {
		c.g.AssertIsEqual(b, bin[i].Val)
	}

	original := c.b32.FromBinary(bin...)
	c.g.AssertIsEqual(original.Val[0], a.Val[0])
	c.g.AssertIsEqual(original.Val[1], a.Val[1])
}

func (c *TestBytes32APICircuit) testEqual() {
	data := ConstBytes32(testBytes[:])
	data1 := ConstBytes32(testBytes[:])
	data2 := ConstBytes32(testBytes2[:])

	eq := c.b32.IsEqual(data, data1)
	c.g.AssertIsEqual(eq.Val, 1)

	eq2 := c.b32.IsEqual(data, data2)
	c.g.AssertIsEqual(eq2.Val, 0)

	c.b32.AssertIsEqual(data, data1)
	c.b32.AssertIsDifferent(data, data2)
}

func (c *TestBytes32APICircuit) testSelect() {
	data1 := ConstBytes32(testBytes[:])
	data2 := ConstBytes32(testBytes2[:])

	selected := c.b32.Select(newU248(1), data1, data2)
	c.b32.AssertIsEqual(selected, data1)

	selected = c.b32.Select(newU248(0), data1, data2)
	c.b32.AssertIsEqual(selected, data2)
}

func (c *TestBytes32APICircuit) testIsZero() {
	data1 := ConstBytes32(testBytes[:])
	data2 := ConstBytes32([]byte{0})

	z := c.b32.IsZero(data1)
	c.g.AssertIsEqual(z.Val, 0)

	z = c.b32.IsZero(data2)
	c.g.AssertIsEqual(z.Val, 1)
}
