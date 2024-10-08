package sdk

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

func TestUint64API(t *testing.T) {
	c := &TestUint64APICircuit{}
	err := test.IsSolved(c, c, ecc.BN254.ScalarField())
	check(err)
}

type TestUint64APICircuit struct {
	g   frontend.API
	u64 *Uint64API
}

func (c *TestUint64APICircuit) Define(g frontend.API) error {
	c.g = g
	c.u64 = newUint64API(g)

	c.testBinary()
	c.testSelect()
	c.testArithmetic()
	c.testComparisons()
	c.testLogical()

	return nil
}

var testUint64 = big.NewInt(12345678912345)
var testU64 = ConstUint64(testUint64)
var testUint64_2 = big.NewInt(22345678912345)
var testU64_2 = ConstUint64(testUint64_2)
var testUint64_bits = "000010110011101001110011110011100101101101011001"

func (c *TestUint64APICircuit) testBinary() {
	v := c.u64.ToBinary(testU64, 48)
	bits := flipByGroups(parseBitStr(testUint64_bits), 1)
	for i, b := range bits {
		c.g.AssertIsEqual(b, v[i].Val)
	}

	num := c.u64.FromBinary(v...)
	c.g.AssertIsEqual(num.Val, testUint64)
}

func (c *TestUint64APICircuit) testSelect() {
	selected := c.u64.Select(ConstUint64(1), testU64, testU64_2)
	c.g.AssertIsEqual(selected.Val, testUint64)

	selected = c.u64.Select(ConstUint64(0), testU64, testU64_2)
	c.g.AssertIsEqual(selected.Val, testUint64_2)
}

func (c *TestUint64APICircuit) testArithmetic() {
	// Add
	c.g.AssertIsEqual(
		c.u64.Add(testU64, testU64_2).Val,
		new(big.Int).Add(testUint64, testUint64_2),
	)
	// Sub
	c.g.AssertIsEqual(
		c.u64.Sub(testU64_2, testU64).Val,
		new(big.Int).Sub(testUint64_2, testUint64),
	)
	// Mul
	c.g.AssertIsEqual(
		c.u64.Mul(testU64_2, testU64).Val,
		new(big.Int).Mul(testUint64, testUint64_2),
	)
	// Div
	q, r := c.u64.Div(testU64_2, testU64)
	qe, re := new(big.Int).QuoRem(testUint64_2, testUint64, new(big.Int))
	c.g.AssertIsEqual(q.Val, qe)
	c.g.AssertIsEqual(r.Val, re)

	// Sqrt
	c.g.AssertIsEqual(c.u64.Sqrt(testU64).Val, new(big.Int).Sqrt(testUint64))
}

func (c *TestUint64APICircuit) testComparisons() {
	// AssertIsEqual
	c.u64.AssertIsEqual(testU64, testU64)
	// AssertIsDifferent
	c.u64.AssertIsDifferent(testU64, testU64_2)
	// IsZero
	c.g.AssertIsEqual(c.u64.IsZero(testU64).Val, 0)
	c.g.AssertIsEqual(c.u64.IsZero(ConstUint64(0)).Val, 1)
	// IsEqual
	c.g.AssertIsEqual(c.u64.IsEqual(testU64, testU64).Val, 1)
	c.g.AssertIsEqual(c.u64.IsEqual(testU64, testU64_2).Val, 0)
	// IsLessThan
	c.g.AssertIsEqual(c.u64.IsLessThan(testU64, testU64_2).Val, 1)
	// IsGreaterThan
	c.g.AssertIsEqual(c.u64.IsGreaterThan(testU64, testU64_2).Val, 0)
}

func (c *TestUint64APICircuit) testLogical() {
	one := ConstUint64(1)
	zero := ConstUint64(0)
	// And
	c.g.AssertIsEqual(c.u64.And(one, one, one).Val, 1)
	c.g.AssertIsEqual(c.u64.And(one, one, zero).Val, 0)
	// Or
	c.g.AssertIsEqual(c.u64.Or(one, one, zero).Val, 1)
	c.g.AssertIsEqual(c.u64.Or(zero, zero, zero).Val, 0)
	// Not
	c.g.AssertIsEqual(c.u64.Not(one).Val, 0)
	c.g.AssertIsEqual(c.u64.Not(zero).Val, 1)
}
