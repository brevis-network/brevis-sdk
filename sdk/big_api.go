//package sdk
//
//import (
//	"fmt"
//
//	"github.com/consensys/gnark/std/math/emulated"
//
//	"github.com/consensys/gnark/frontend"
//)
//
//// BigAPI contains a set of APIs that can only be used in circuit to perform
//// logical and arithmetic operations over circuit variables. It is an extension
//// of g's frontend.API.
//type BigAPI struct {
//	g        frontend.API
//	bigField *emulated.Field[BigField]
//
//	output []Variable `g:"-"`
//}
//
//func NewBigAPI(gapi frontend.API) *BigAPI {
//	f, err := emulated.NewField[BigField](gapi)
//	if err != nil {
//		panic(err)
//	}
//	api := &BigAPI{g: gapi, bigField: f}
//	return api
//}
//
//func Cmp(api *BigAPI, a, b Variable) Variable {
//	return newVariable(api.g.Cmp(a.Val, b.Val))
//}
//
//// LT returns 1 if a < b, and 0 otherwise
//func LT(api *BigAPI, a, b Variable) Variable {
//	return IsZero(api, Add(api, Cmp(api, a, b), newVariable(1)))
//}
//
//// GT returns 1 if a > b, and 0 otherwise
//func GT(api *BigAPI, a, b Variable) Variable {
//	return IsZero(api, Sub(api, newVariable(Cmp(api, a, b)), newVariable(1)))
//}
//
//func Select[T CircuitVariable](api *BigAPI, s Variable, a, b T) T {
//	aVals := a.Values()
//	bVals := b.Values()
//	if len(aVals) != len(bVals) {
//		panic(fmt.Errorf("cannot select: inconsistent value length of a (%d) and b (%d)", len(aVals), len(bVals)))
//	}
//	res := make([]frontend.Variable, len(aVals))
//	for i := range aVals {
//		res[i] = api.g.Select(s, aVals[i], bVals[i])
//	}
//	t := *new(T)
//	t.SetValues(res)
//	return t
//}
//
//// Equal returns 1 if a == b, and 0 otherwise
//func Equal(api *BigAPI, a, b Variable) Variable {
//	return IsZero(api, Sub(api, a, b))
//}
//
//func Sub(api *BigAPI, a, b Variable) Variable {
//	return newVariable(api.g.Sub(a.Val, b.Val))
//}
//
//func IsZero(api *BigAPI, a Variable) Variable {
//	return newVariable(api.g.IsZero(a.Val))
//}
//
//// Sqrt returns √a. Uses SqrtHint
//func (api *BigAPI) Sqrt(a Variable) Variable {
//	out, err := api.g.Compiler().NewHint(SqrtHint, 1, a)
//	if err != nil {
//		panic(fmt.Errorf("failed to initialize SqrtHint instance: %s", err.Error()))
//	}
//	return out[0]
//}
//
//type Var interface {
//	Variable | BigVariable
//}
//
//// QuoRem computes the standard unsigned integer division a / b and
//// its remainder. Uses QuoRemHint.
//func (api *BigAPI) QuoRem(a, b Variable) (quotient, remainder Variable) {
//	out, err := api.g.Compiler().NewHint(QuoRemHint, 2, a, b)
//	if err != nil {
//		panic(fmt.Errorf("failed to initialize QuoRem hint instance: %s", err.Error()))
//	}
//	quo, rem := out[0], out[1]
//	orig := api.g.Add(api.g.Mul(quo, b), rem)
//	api.g.AssertIsEqual(orig, a)
//	return quo, rem
//}
//
//func (api *BigAPI) ToBytes32(i interface{}) Bytes32 {
//	switch v := i.(type) {
//	case *BigVariable:
//		api.bigField.AssertIsLessOrEqual(v.Element, MaxBytes32.Element)
//		r := api.bigField.Reduce(v.Element)
//		bits := api.bigField.ToBits(r)
//		lo := api.FromBinary(bits[:numBitsPerVar]...)
//		hi := api.FromBinary(bits[numBitsPerVar:256]...)
//		return Bytes32{Val: [2]Variable{lo, hi}}
//	case Variable:
//		return Bytes32{Val: [2]Variable{v, 0}}
//	}
//	panic(fmt.Errorf("unsupported casting from %T to Bytes32", i))
//}
//
//// ToBigVariable casts a Bytes32 or a Variable type to a BigVariable type
//func (api *BigAPI) ToBigVariable(i interface{}) *BigVariable {
//	switch v := i.(type) {
//	case Bytes32:
//		// Recompose the Bytes32 into BigField.NbLimbs limbs
//		bits := v.toBinaryVars(api.g)
//		f := BigField{}
//		limbs := make([]Variable, f.NbLimbs())
//		b := f.BitsPerLimb()
//		limbs[0] = api.FromBinary(bits[:b]...)
//		limbs[1] = api.FromBinary(bits[b : 2*b]...)
//		limbs[2] = api.FromBinary(bits[2*b:]...)
//		limbs[3], limbs[4], limbs[5] = 0, 0, 0
//		el := api.bigField.NewElement(limbs)
//		return newBigVariable(el)
//	case Variable:
//		el := api.bigField.NewElement(v)
//		return newBigVariable(el)
//	}
//	panic(fmt.Errorf("unsupported casting from %T to *BigVariable", i))
//}
//
//// ToVariable casts a BigVariable or a Bytes32 type to a Variable type. It
//// requires the variable being cast does not overflow the circuit's scalar field
//// max
//func (api *BigAPI) ToVariable(i interface{}) Variable {
//	switch v := i.(type) {
//	case Bytes32:
//		api.AssertIsEqual(v.Val[1], 0)
//		return v.Val[0]
//	case *BigVariable:
//		reduced := api.bigField.Reduce(v.Element)
//		api.AssertIsEqual(reduced.Limbs[1], 0)
//		api.AssertIsEqual(reduced.Limbs[2], 0)
//		return v.Limbs[0]
//	}
//	panic(fmt.Errorf("unsupported casting from %T to Variable", i))
//}
//
//func (api *BigAPI) AddBig(a, b *BigVariable) *BigVariable {
//	return newBigVariable(api.bigField.Add(a.Element, b.Element))
//}
//
//func (api *BigAPI) SubBig(a, b *BigVariable) *BigVariable {
//	return newBigVariable(api.bigField.Sub(a.Element, b.Element))
//}
//
//func (api *BigAPI) MulBig(a, b *BigVariable) *BigVariable {
//	return newBigVariable(api.bigField.Mul(a.Element, b.Element))
//}
//
//func (api *BigAPI) DivBig(a, b *BigVariable) *BigVariable {
//	return newBigVariable(api.bigField.Div(a.Element, b.Element))
//}
//
//func (api *BigAPI) AssertIsEqualBig(a, b *BigVariable) {
//	fmt.Printf("a %+v\nb %+v\n", a.Limbs, b.Limbs)
//	api.bigField.AssertIsEqual(a.Element, b.Element)
//}
