package limbs

import (
	"fmt"
	"math/big"
)

func checkLen[T any](arr []T, length int) {
	if len(arr) != length {
		panic(fmt.Sprintf("arr len %d, expected %d", len(arr), length))
	}
}

func parseBinary(bs string) Limb {
	var sum uint64 = 0
	for i, c := range bs {
		var d uint64 = 0
		if c == '1' {
			d = 1
		}
		sum += d << (len(bs) - 1 - i)
	}
	return Limb{Val: sum, Size: len(bs)}
}

func parseBinaryBig(bs string) Limb {
	sum := big.NewInt(0)
	for i, c := range bs {
		if c == '0' {
			continue
		}
		// performs lshift using big int: sum += 2 ^ (len(bs) - 1 - i)
		d := big.NewInt(2)
		p := big.NewInt(int64(len(bs)))
		p.Sub(p, big.NewInt(1))
		p.Sub(p, big.NewInt(int64(i)))
		d.Exp(d, p, nil)
		sum.Add(sum, d)
	}
	return Limb{Val: sum, Size: len(bs)}
}
