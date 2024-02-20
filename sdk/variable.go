package sdk

import (
	"github.com/consensys/gnark/frontend"
	"math/big"
)

// MaxUint248 is the largest safe number for uint248 type
var MaxUint248 = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 248), big.NewInt(1))

// BLS12377 fr is 253 bits or 32 bytes, but it doesn't mean we can use any
// uint253 because max uint253 would still overflow the field. Reducing the bit
// size to 248 would suffice the purpose.
var numBitsPerVar = 248

type CircuitVariable interface {
	Values() []frontend.Variable
	FromValues(vs ...frontend.Variable) CircuitVariable
}

type List[T CircuitVariable] []T

func (t List[T]) Values() []frontend.Variable {
	var ret []frontend.Variable
	for _, data := range t {
		ret = append(ret, data.Values()...)
	}
	return ret
}

func (t List[T]) FromValues(vs ...frontend.Variable) CircuitVariable {
	for i, v := range vs {
		t[i] = t[i].FromValues(v).(T)
	}
	return t
}
