package sdk

import (
	"fmt"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/std/math/emulated"
	"math/big"
	"sort"
	"sync"
)

var registerOnce sync.Once

func init() {
	registerOnce.Do(registerHints)
}

func registerHints() {
	solver.RegisterHint(GetHints()...)
}

func GetHints() []solver.Hint {
	return []solver.Hint{QuoRemHint, SqrtHint, SortHint}
}

func QuoRemHint(_ *big.Int, in, out []*big.Int) error {
	if len(in) != 2 {
		return fmt.Errorf("QuoRemHint: input len must be 2")
	}
	if len(out) != 2 {
		return fmt.Errorf("QuoRemHint: output len must be 2")
	}
	out[0] = new(big.Int)
	out[1] = new(big.Int)
	out[0].QuoRem(in[0], in[1], out[1])
	return nil
}

func SqrtHint(field *big.Int, in, out []*big.Int) error {
	if len(in) != 1 {
		return fmt.Errorf("SqrtHint: input len must be 1")
	}
	if len(out) != 1 {
		return fmt.Errorf("SqrtHint: output len must be 1")
	}
	out[0] = new(big.Int)
	out[0].ModSqrt(in[0], field)
	return nil
}

// SortHint sorts the input in descending order
func SortHint(_ *big.Int, in, out []*big.Int) error {
	inCopy := make([]*big.Int, len(in))
	copy(inCopy, in)

	sort.Slice(in, func(i, j int) bool {
		return in[i].Cmp(in[j]) == 1
	})

	copy(out, inCopy)

	return nil
}

func QuoRemBigHint(_ *big.Int, in []*big.Int, out []*big.Int) error {
	return emulated.UnwrapHint(in, out, func(mod *big.Int, in, out []*big.Int) error {
		out[0].QuoRem(in[0], in[1], out[1])
		return nil
	})
}
