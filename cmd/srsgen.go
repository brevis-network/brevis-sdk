package main

import (
	"fmt"
	"github.com/celer-network/brevis-sdk/sdk/srs"
)

func main() {
	var kStart uint64 = 18
	var kEnd uint64 = 18

	for k := kStart; k <= kEnd; k++ {
		var sizeLagrange uint64 = 1 << k
		sizeCanonical := sizeLagrange + 3

		fmt.Printf("generating SRS for k=%d\n", k)
		canonical, lagrange, err := srs.Generate(sizeCanonical)
		if err != nil {
			panic(err)
		}

		path := fmt.Sprintf("./%s", srs.CacheKey(k))
		err = srs.WriteFile(path, srs.CacheEntry{Canonical: canonical, Lagrange: lagrange})
		if err != nil {
			panic(err)
		}
	}
}
