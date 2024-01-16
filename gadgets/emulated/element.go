package emulated

import (
	"fmt"

	"github.com/celer-network/brevis-sdk/gadgets/limbs"
	"github.com/celer-network/brevis-sdk/gadgets/utils"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
)

func FromElement[T emulated.FieldParams](api frontend.API, in *emulated.Element[T], outBitSize int) []frontend.Variable {
	var p T
	la := limbs.NewAPI(api)
	ls := limbs.NewLimbs(in.Limbs, int(p.BitsPerLimb()))
	ls = utils.FlipSubSlice(ls, int(p.NbLimbs()))
	return la.Resplit(ls, outBitSize).Values()
}

func ToElement[T emulated.FieldParams](api frontend.API, in []frontend.Variable, inBitSize int) *emulated.Element[T] {
	var p T
	la := limbs.NewAPI(api)
	ls := limbs.NewLimbs(in, inBitSize)
	elLimbs := la.Resplit(ls, int(p.BitsPerLimb()))
	elLimbs = utils.Flip(elLimbs)
	f, err := emulated.NewField[T](api)
	if err != nil {
		panic(fmt.Errorf("failed to new field: %s", err.Error()))
	}
	return f.NewElement(elLimbs.Values())
}

func ToElements[T emulated.FieldParams](api frontend.API, in []frontend.Variable, inBitSize int) []*emulated.Element[T] {
	var p T
	s := inBitSize
	inBits := len(in) * s
	varsPerLimb := int(p.BitsPerLimb()) / s
	la := limbs.NewAPI(api)
	ls := limbs.NewLimbs(in, s)
	elLimbs := make([]frontend.Variable, inBits/int(p.BitsPerLimb()))
	for i := range elLimbs {
		elLimb := la.Merge(ls[i*varsPerLimb : (i+1)*varsPerLimb])
		elLimbs[i] = elLimb.Val
	}
	elLimbs = utils.FlipSubSlice(elLimbs, int(p.NbLimbs()))
	f, err := emulated.NewField[T](api)
	if err != nil {
		panic(fmt.Errorf("failed to new field: %s", err.Error()))
	}
	var els []*emulated.Element[T]
	for i := 0; i < len(elLimbs); i += int(p.NbLimbs()) {
		els = append(els, f.NewElement(elLimbs[i:i+int(p.NbLimbs())]))
	}
	return els
}
