package sdk

import (
	"fmt"
	"github.com/consensys/gnark/constraint/solver"
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

//func TwoLimbsMulHint(f *big.Int, in []*big.Int, out []*big.Int) error {
//	if len(in) != 4 {
//		return fmt.Errorf("Uint256MulHint in len %d != 4", len(in))
//	}
//	if len(out) != 2 {
//		return fmt.Errorf("Uint256MulHint out len %d != 2", len(out))
//	}
//	if out[0] == nil || out[1] == nil {
//		return fmt.Errorf("output not initialized")
//	}
//
//	leftLo, leftHi := in[0], in[1]
//	left := new(big.Int).Lsh(leftHi, uint(f.BitLen()))
//	left.Add(left, leftLo)
//
//	rightLo, rightHi := in[2], in[3]
//	right := new(big.Int).Lsh(rightHi, uint(f.BitLen()))
//	right.Add(right, rightLo)
//
//	res := new(big.Int).Mul(left, right)
//
//	b32 := ParseBytes32(res.Bytes())
//	out[0].Set(b32.Val[0].(*big.Int))
//	out[1].Set(b32.Val[1].(*big.Int))
//
//	return nil
//}
