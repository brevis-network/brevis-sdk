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

type Variable = frontend.Variable

type CircuitVariable interface {
	Values() []frontend.Variable
	FromValues(vs ...frontend.Variable) CircuitVariable
	NumVars() uint32
}

type List[T CircuitVariable] []T

func (l List[T]) Values() []frontend.Variable {
	var ret []frontend.Variable
	for _, data := range l {
		ret = append(ret, data.Values()...)
	}
	return ret
}

func (l List[T]) FromValues(vs ...frontend.Variable) CircuitVariable {
	typ := *new(T)
	nv := int(typ.NumVars())
	for i := 0; i < len(vs); i += nv {
		values := vs[i : i+nv]
		l[i] = l[i].FromValues(values...).(T)
	}
	return l
}

func (l List[T]) NumVars() uint32 {
	sum := uint32(0)
	for _, item := range l {
		sum += item.NumVars()
	}
	return sum
}

type Tuple2[F0, F1 CircuitVariable] struct {
	F0 F0
	F1 F1
}

func (t Tuple2[F0, F1]) Values() []frontend.Variable {
	var ret []frontend.Variable
	ret = append(ret, t.F0.Values()...)
	ret = append(ret, t.F1.Values()...)
	return ret
}

func (t Tuple2[F0, F1]) FromValues(vs ...frontend.Variable) CircuitVariable {
	ret := Tuple2[F0, F1]{}
	start, end := uint32(0), ret.F0.NumVars()
	ret.F0 = ret.F0.FromValues(vs[start:end]...).(F0)

	start, end = end, end+ret.F1.NumVars()
	ret.F1 = ret.F1.FromValues(vs[start:end]...).(F1)

	return ret
}

func (t Tuple2[F0, F1]) NumVars() uint32 {
	return t.F0.NumVars() + t.F1.NumVars()
}

type Tuple3[F0, F1, F2 CircuitVariable] struct {
	F0 F0
	F1 F1
	F2 F2
}

func (t Tuple3[F0, F1, F2]) Values() []frontend.Variable {
	var ret []frontend.Variable
	ret = append(ret, t.F0.Values()...)
	ret = append(ret, t.F1.Values()...)
	ret = append(ret, t.F2.Values()...)
	return ret
}

func (t Tuple3[F0, F1, F2]) FromValues(vs ...frontend.Variable) CircuitVariable {
	ret := Tuple3[F0, F1, F2]{}
	start, end := uint32(0), ret.F0.NumVars()
	ret.F0 = ret.F0.FromValues(vs[start:end]...).(F0)

	start, end = end, end+ret.F1.NumVars()
	ret.F1 = ret.F1.FromValues(vs[start:end]...).(F1)

	start, end = end, end+ret.F2.NumVars()
	ret.F2 = ret.F2.FromValues(vs[start:end]...).(F2)
	return ret
}

func (t Tuple3[F0, F1, F2]) NumVars() uint32 {
	return t.F0.NumVars() + t.F1.NumVars() + t.F2.NumVars()
}

type Tuple4[F0, F1, F2, F3 CircuitVariable] struct {
	F0 F0
	F1 F1
	F2 F2
	F3 F3
}

func (t Tuple4[F0, F1, F2, F3]) Values() []frontend.Variable {
	var ret []frontend.Variable
	ret = append(ret, t.F0.Values()...)
	ret = append(ret, t.F1.Values()...)
	ret = append(ret, t.F2.Values()...)
	ret = append(ret, t.F3.Values()...)
	return ret
}

func (t Tuple4[F0, F1, F2, F3]) FromValues(vs ...frontend.Variable) CircuitVariable {
	ret := Tuple4[F0, F1, F2, F3]{}
	start, end := uint32(0), ret.F0.NumVars()
	ret.F0 = ret.F0.FromValues(vs[start:end]...).(F0)

	start, end = end, end+ret.F1.NumVars()
	ret.F1 = ret.F1.FromValues(vs[start:end]...).(F1)

	start, end = end, end+ret.F2.NumVars()
	ret.F2 = ret.F2.FromValues(vs[start:end]...).(F2)

	start, end = end, end+ret.F3.NumVars()
	ret.F3 = ret.F3.FromValues(vs[start:end]...).(F3)

	return ret
}

func (t Tuple4[F0, F1, F2, F3]) NumVars() uint32 {
	return t.F0.NumVars() + t.F1.NumVars() + t.F2.NumVars() + t.F3.NumVars()
}
