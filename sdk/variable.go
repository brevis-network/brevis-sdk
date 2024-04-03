package sdk

import (
	"fmt"
	"github.com/consensys/gnark/frontend"
	"math/big"
	"strings"
)

const (
	Uint248Type = "Uint248"
	Uint521Type = "Uint521"
	Int248Type  = "Int248"
	Bytes32Type = "Bytes32"
)

// MaxUint248 is the largest safe number for uint248 type
var MaxUint248 = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 248), big.NewInt(1))

// BLS12377 fr is 253 bits or 32 bytes, but it doesn't mean we can use any
// uint253 because max uint253 would still overflow the field. Reducing the bit
// size to 248 would suffice the purpose.
var numBitsPerVar = 248

type variable = frontend.Variable

type CircuitVariable interface {
	Values() []frontend.Variable
	FromValues(vs ...frontend.Variable) CircuitVariable
	NumVars() uint32
	String() string
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

func (l List[T]) String() string {
	strs := make([]string, len(l))
	for i, t := range l {
		strs[i] = t.String()
	}
	return strings.Join(strs, ", ")
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

func (t Tuple2[F0, F1]) String() string {
	return fmt.Sprintf("(%s, %s)", t.F0, t.F1)
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

func (t Tuple3[F0, F1, F2]) String() string {
	return fmt.Sprintf("(%s, %s, %s)", t.F0, t.F1, t.F2)
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

func (t Tuple4[F0, F1, F2, F3]) String() string {
	return fmt.Sprintf("(%s, %s, %s, %s)", t.F0, t.F1, t.F2, t.F3)
}

type Tuple5[F0, F1, F2, F3, F4 CircuitVariable] struct {
	F0 F0
	F1 F1
	F2 F2
	F3 F3
	F4 F4
}

func (t Tuple5[F0, F1, F2, F3, F4]) Values() []frontend.Variable {
	var ret []frontend.Variable
	ret = append(ret, t.F0.Values()...)
	ret = append(ret, t.F1.Values()...)
	ret = append(ret, t.F2.Values()...)
	ret = append(ret, t.F3.Values()...)
	ret = append(ret, t.F4.Values()...)
	return ret
}

func (t Tuple5[F0, F1, F2, F3, F4]) FromValues(vs ...frontend.Variable) CircuitVariable {
	ret := Tuple5[F0, F1, F2, F3, F4]{}
	start, end := uint32(0), ret.F0.NumVars()
	ret.F0 = ret.F0.FromValues(vs[start:end]...).(F0)

	start, end = end, end+ret.F1.NumVars()
	ret.F1 = ret.F1.FromValues(vs[start:end]...).(F1)

	start, end = end, end+ret.F2.NumVars()
	ret.F2 = ret.F2.FromValues(vs[start:end]...).(F2)

	start, end = end, end+ret.F3.NumVars()
	ret.F3 = ret.F3.FromValues(vs[start:end]...).(F3)

	start, end = end, end+ret.F4.NumVars()
	ret.F4 = ret.F4.FromValues(vs[start:end]...).(F4)

	return ret
}

func (t Tuple5[F0, F1, F2, F3, F4]) NumVars() uint32 {
	return t.F0.NumVars() + t.F1.NumVars() + t.F2.NumVars() + t.F3.NumVars() + t.F4.NumVars()
}

func (t Tuple5[F0, F1, F2, F3, F4]) String() string {
	return fmt.Sprintf("(%s, %s, %s, %s, %s)", t.F0, t.F1, t.F2, t.F3, t.F4)
}

type Tuple6[F0, F1, F2, F3, F4, F5 CircuitVariable] struct {
	F0 F0
	F1 F1
	F2 F2
	F3 F3
	F4 F4
	F5 F5
}

func (t Tuple6[F0, F1, F2, F3, F4, F5]) Values() []frontend.Variable {
	var ret []frontend.Variable
	ret = append(ret, t.F0.Values()...)
	ret = append(ret, t.F1.Values()...)
	ret = append(ret, t.F2.Values()...)
	ret = append(ret, t.F3.Values()...)
	ret = append(ret, t.F4.Values()...)
	ret = append(ret, t.F5.Values()...)
	return ret
}

func (t Tuple6[F0, F1, F2, F3, F4, F5]) FromValues(vs ...frontend.Variable) CircuitVariable {
	ret := Tuple6[F0, F1, F2, F3, F4, F5]{}
	start, end := uint32(0), ret.F0.NumVars()
	ret.F0 = ret.F0.FromValues(vs[start:end]...).(F0)

	start, end = end, end+ret.F1.NumVars()
	ret.F1 = ret.F1.FromValues(vs[start:end]...).(F1)

	start, end = end, end+ret.F2.NumVars()
	ret.F2 = ret.F2.FromValues(vs[start:end]...).(F2)

	start, end = end, end+ret.F3.NumVars()
	ret.F3 = ret.F3.FromValues(vs[start:end]...).(F3)

	start, end = end, end+ret.F4.NumVars()
	ret.F4 = ret.F4.FromValues(vs[start:end]...).(F4)

	start, end = end, end+ret.F5.NumVars()
	ret.F5 = ret.F5.FromValues(vs[start:end]...).(F5)

	return ret
}

func (t Tuple6[F0, F1, F2, F3, F4, F5]) NumVars() uint32 {
	return t.F0.NumVars() + t.F1.NumVars() + t.F2.NumVars() + t.F3.NumVars() + t.F4.NumVars() + t.F5.NumVars()
}

func (t Tuple6[F0, F1, F2, F3, F4, F5]) String() string {
	return fmt.Sprintf("(%s, %s, %s, %s, %s, %s)", t.F0, t.F1, t.F2, t.F3, t.F4, t.F5)
}

type Tuple7[F0, F1, F2, F3, F4, F5, F6 CircuitVariable] struct {
	F0 F0
	F1 F1
	F2 F2
	F3 F3
	F4 F4
	F5 F5
	F6 F6
}

func (t Tuple7[F0, F1, F2, F3, F4, F5, F6]) Values() []frontend.Variable {
	var ret []frontend.Variable
	ret = append(ret, t.F0.Values()...)
	ret = append(ret, t.F1.Values()...)
	ret = append(ret, t.F2.Values()...)
	ret = append(ret, t.F3.Values()...)
	ret = append(ret, t.F4.Values()...)
	ret = append(ret, t.F5.Values()...)
	ret = append(ret, t.F6.Values()...)
	return ret
}

func (t Tuple7[F0, F1, F2, F3, F4, F5, F6]) FromValues(vs ...frontend.Variable) CircuitVariable {
	ret := Tuple7[F0, F1, F2, F3, F4, F5, F6]{}
	start, end := uint32(0), ret.F0.NumVars()
	ret.F0 = ret.F0.FromValues(vs[start:end]...).(F0)

	start, end = end, end+ret.F1.NumVars()
	ret.F1 = ret.F1.FromValues(vs[start:end]...).(F1)

	start, end = end, end+ret.F2.NumVars()
	ret.F2 = ret.F2.FromValues(vs[start:end]...).(F2)

	start, end = end, end+ret.F3.NumVars()
	ret.F3 = ret.F3.FromValues(vs[start:end]...).(F3)

	start, end = end, end+ret.F4.NumVars()
	ret.F4 = ret.F4.FromValues(vs[start:end]...).(F4)

	start, end = end, end+ret.F5.NumVars()
	ret.F5 = ret.F5.FromValues(vs[start:end]...).(F5)

	start, end = end, end+ret.F6.NumVars()
	ret.F6 = ret.F6.FromValues(vs[start:end]...).(F6)

	return ret
}

func (t Tuple7[F0, F1, F2, F3, F4, F5, F6]) NumVars() uint32 {
	return t.F0.NumVars() + t.F1.NumVars() + t.F2.NumVars() + t.F3.NumVars() + t.F4.NumVars() + t.F5.NumVars() + t.F6.NumVars()
}

func (t Tuple7[F0, F1, F2, F3, F4, F5, F6]) String() string {
	return fmt.Sprintf("(%s, %s, %s, %s, %s, %s, %s)", t.F0, t.F1, t.F2, t.F3, t.F4, t.F5, t.F6)
}

type Tuple8[F0, F1, F2, F3, F4, F5, F6, F7 CircuitVariable] struct {
	F0 F0
	F1 F1
	F2 F2
	F3 F3
	F4 F4
	F5 F5
	F6 F6
	F7 F7
}

func (t Tuple8[F0, F1, F2, F3, F4, F5, F6, F7]) Values() []frontend.Variable {
	var ret []frontend.Variable
	ret = append(ret, t.F0.Values()...)
	ret = append(ret, t.F1.Values()...)
	ret = append(ret, t.F2.Values()...)
	ret = append(ret, t.F3.Values()...)
	ret = append(ret, t.F4.Values()...)
	ret = append(ret, t.F5.Values()...)
	ret = append(ret, t.F6.Values()...)
	ret = append(ret, t.F7.Values()...)
	return ret
}

func (t Tuple8[F0, F1, F2, F3, F4, F5, F6, F7]) FromValues(vs ...frontend.Variable) CircuitVariable {
	ret := Tuple8[F0, F1, F2, F3, F4, F5, F6, F7]{}
	start, end := uint32(0), ret.F0.NumVars()
	ret.F0 = ret.F0.FromValues(vs[start:end]...).(F0)

	start, end = end, end+ret.F1.NumVars()
	ret.F1 = ret.F1.FromValues(vs[start:end]...).(F1)

	start, end = end, end+ret.F2.NumVars()
	ret.F2 = ret.F2.FromValues(vs[start:end]...).(F2)

	start, end = end, end+ret.F3.NumVars()
	ret.F3 = ret.F3.FromValues(vs[start:end]...).(F3)

	start, end = end, end+ret.F4.NumVars()
	ret.F4 = ret.F4.FromValues(vs[start:end]...).(F4)

	start, end = end, end+ret.F5.NumVars()
	ret.F5 = ret.F5.FromValues(vs[start:end]...).(F5)

	start, end = end, end+ret.F6.NumVars()
	ret.F6 = ret.F6.FromValues(vs[start:end]...).(F6)

	start, end = end, end+ret.F7.NumVars()
	ret.F7 = ret.F7.FromValues(vs[start:end]...).(F7)

	return ret
}

func (t Tuple8[F0, F1, F2, F3, F4, F5, F6, F7]) NumVars() uint32 {
	return t.F0.NumVars() + t.F1.NumVars() + t.F2.NumVars() + t.F3.NumVars() +
		t.F4.NumVars() + t.F5.NumVars() + t.F6.NumVars() + t.F7.NumVars()
}

func (t Tuple8[F0, F1, F2, F3, F4, F5, F6, F7]) String() string {
	return fmt.Sprintf("(%s, %s, %s, %s, %s, %s, %s, %s)", t.F0, t.F1, t.F2, t.F3, t.F4, t.F5, t.F6, t.F7)
}
