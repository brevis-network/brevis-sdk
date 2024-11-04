package main

import (
	"fmt"
	"os"

	"github.com/brevis-network/brevis-sdk/sdk/srs"
	"github.com/consensys/gnark-crypto/ecc"
	kzg_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/kzg"
	"github.com/consensys/gnark-crypto/kzg"
)

func main() {
	var kStart uint64 = 20
	var kEnd uint64 = 26

	for k := kStart; k <= kEnd; k++ {
		var sizeLagrange uint64 = 1 << k

		fmt.Printf("generating SRS for k=%d\n", k)
		canonical, lagrange, err := generate(sizeLagrange)
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

func generate(sizeLagrange uint64) (kzg.SRS, kzg.SRS, error) {
	kzgSrs := kzg.NewSRS(ecc.BN254)
	kzgFile := ""
	f, err := os.Open(kzgFile)
	if err != nil {
		fmt.Println("open file err:", err)
		return nil, nil, err
	}

	flag, err := kzgSrs.UnsafeReadFrom(f)
	if err != nil {
		fmt.Println("unsafe read error:", err)
	}
	fmt.Println(flag)

	bn254Srs := kzgSrs.(*kzg_bn254.SRS)

	lagrangeSRS := &kzg_bn254.SRS{Vk: bn254Srs.Vk}

	lagrangeSRS.Pk.G1, err = kzg_bn254.ToLagrangeG1(bn254Srs.Pk.G1[:sizeLagrange])
	if err != nil {
		fmt.Println("convert lagrangeG1 err:", err)
		return nil, nil, err
	}

	return bn254Srs, lagrangeSRS, nil
}
