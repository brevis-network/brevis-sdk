package utils

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
	"math/big"

	mimc_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	replonk "github.com/consensys/gnark/std/recursion/plonk"
)

func CalculateAppVkHashForBn254(vk replonk.VerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine]) []byte {
	hasher := mimc_bn254.NewMiMC()
	var hashData []byte

	var data [mimc_bn254.BlockSize]byte
	hashData = append(hashData, new(big.Int).SetUint64(vk.BaseVerifyingKey.NbPublicVariables).FillBytes(data[:])...)

	for _, limb := range vk.BaseVerifyingKey.CosetShift.Limbs {
		hashData = append(hashData, limb.(*big.Int).FillBytes(data[:])...)
	}

	for _, limb := range vk.BaseVerifyingKey.Kzg.G1.X.Limbs {
		hashData = append(hashData, limb.(*big.Int).FillBytes(data[:])...)
	}

	for _, limb := range vk.BaseVerifyingKey.Kzg.G1.Y.Limbs {
		hashData = append(hashData, limb.(*big.Int).FillBytes(data[:])...)
	}

	for _, kzgG2 := range vk.BaseVerifyingKey.Kzg.G2 {
		for _, limb := range kzgG2.P.X.A0.Limbs {
			hashData = append(hashData, limb.(*big.Int).FillBytes(data[:])...)
		}

		for _, limb := range kzgG2.P.X.A1.Limbs {
			hashData = append(hashData, limb.(*big.Int).FillBytes(data[:])...)
		}

		for _, limb := range kzgG2.P.Y.A0.Limbs {
			hashData = append(hashData, limb.(*big.Int).FillBytes(data[:])...)
		}

		for _, limb := range kzgG2.P.Y.A1.Limbs {
			hashData = append(hashData, limb.(*big.Int).FillBytes(data[:])...)
		}
	}

	// CircuitVerifyingKey
	hashData = append(hashData, new(big.Int).SetUint64(vk.CircuitVerifyingKey.Size.(uint64)).FillBytes(data[:])...)
	for _, limb := range vk.SizeInv.Limbs {
		hashData = append(hashData, limb.(*big.Int).FillBytes(data[:])...)
	}
	for _, limb := range vk.Generator.Limbs {
		hashData = append(hashData, limb.(*big.Int).FillBytes(data[:])...)
	}

	for _, se := range vk.S {
		for _, limb := range se.G1El.X.Limbs {
			hashData = append(hashData, limb.(*big.Int).FillBytes(data[:])...)
		}

		for _, limb := range se.G1El.Y.Limbs {
			hashData = append(hashData, limb.(*big.Int).FillBytes(data[:])...)
		}
	}

	for _, limb := range vk.Ql.G1El.X.Limbs {
		hashData = append(hashData, limb.(*big.Int).FillBytes(data[:])...)
	}

	for _, limb := range vk.Ql.G1El.Y.Limbs {
		hashData = append(hashData, limb.(*big.Int).FillBytes(data[:])...)
	}

	for _, limb := range vk.Qr.G1El.X.Limbs {
		hashData = append(hashData, limb.(*big.Int).FillBytes(data[:])...)
	}

	for _, limb := range vk.Qr.G1El.Y.Limbs {
		hashData = append(hashData, limb.(*big.Int).FillBytes(data[:])...)
	}

	for _, limb := range vk.Qm.G1El.X.Limbs {
		hashData = append(hashData, limb.(*big.Int).FillBytes(data[:])...)
	}

	for _, limb := range vk.Qm.G1El.Y.Limbs {
		hashData = append(hashData, limb.(*big.Int).FillBytes(data[:])...)
	}

	for _, limb := range vk.Qo.G1El.X.Limbs {
		hashData = append(hashData, limb.(*big.Int).FillBytes(data[:])...)
	}

	for _, limb := range vk.Qo.G1El.Y.Limbs {
		hashData = append(hashData, limb.(*big.Int).FillBytes(data[:])...)
	}

	for _, limb := range vk.Qk.G1El.X.Limbs {
		hashData = append(hashData, limb.(*big.Int).FillBytes(data[:])...)
	}

	for _, limb := range vk.Qk.G1El.Y.Limbs {
		hashData = append(hashData, limb.(*big.Int).FillBytes(data[:])...)
	}

	for _, qcp := range vk.Qcp {
		for _, limb := range qcp.G1El.X.Limbs {
			hashData = append(hashData, limb.(*big.Int).FillBytes(data[:])...)
		}

		for _, limb := range qcp.G1El.Y.Limbs {
			hashData = append(hashData, limb.(*big.Int).FillBytes(data[:])...)
		}
	}

	for _, cci := range vk.CommitmentConstraintIndexes {
		hashData = append(hashData, new(big.Int).SetUint64(cci.(uint64)).FillBytes(data[:])...)
	}

	hasher.Write(hashData[:])

	return hasher.Sum(nil)
}

func CalculateAppVkHashForBn254InCircuit(api frontend.API, vk replonk.VerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine]) (frontend.Variable, error) {
	hasher, err := mimc.NewMiMC(api)
	if err != nil {
		return nil, err
	}

	hasher.Write(vk.BaseVerifyingKey.NbPublicVariables)

	for _, limb := range vk.BaseVerifyingKey.CosetShift.Limbs {
		hasher.Write(limb)
	}

	for _, limb := range vk.BaseVerifyingKey.Kzg.G1.X.Limbs {
		hasher.Write(limb)
	}

	for _, limb := range vk.BaseVerifyingKey.Kzg.G1.Y.Limbs {
		hasher.Write(limb)
	}

	for _, kzgG2 := range vk.BaseVerifyingKey.Kzg.G2 {
		for _, limb := range kzgG2.P.X.A0.Limbs {
			hasher.Write(limb)
		}

		for _, limb := range kzgG2.P.X.A1.Limbs {
			hasher.Write(limb)
		}

		for _, limb := range kzgG2.P.Y.A0.Limbs {
			hasher.Write(limb)
		}

		for _, limb := range kzgG2.P.Y.A1.Limbs {
			hasher.Write(limb)
		}
	}

	// CircuitVerifyingKey
	hasher.Write(vk.CircuitVerifyingKey.Size)
	for _, limb := range vk.SizeInv.Limbs {
		hasher.Write(limb)
	}
	for _, limb := range vk.Generator.Limbs {
		hasher.Write(limb)
	}

	for _, se := range vk.S {
		for _, limb := range se.G1El.X.Limbs {
			hasher.Write(limb)
		}

		for _, limb := range se.G1El.Y.Limbs {
			hasher.Write(limb)
		}
	}

	for _, limb := range vk.Ql.G1El.X.Limbs {
		hasher.Write(limb)
	}

	for _, limb := range vk.Ql.G1El.Y.Limbs {
		hasher.Write(limb)
	}

	for _, limb := range vk.Qr.G1El.X.Limbs {
		hasher.Write(limb)
	}

	for _, limb := range vk.Qr.G1El.Y.Limbs {
		hasher.Write(limb)
	}

	for _, limb := range vk.Qm.G1El.X.Limbs {
		hasher.Write(limb)
	}

	for _, limb := range vk.Qm.G1El.Y.Limbs {
		hasher.Write(limb)
	}

	for _, limb := range vk.Qo.G1El.X.Limbs {
		hasher.Write(limb)
	}

	for _, limb := range vk.Qo.G1El.Y.Limbs {
		hasher.Write(limb)
	}

	for _, limb := range vk.Qk.G1El.X.Limbs {
		hasher.Write(limb)
	}

	for _, limb := range vk.Qk.G1El.Y.Limbs {
		hasher.Write(limb)
	}

	for _, qcp := range vk.Qcp {
		for _, limb := range qcp.G1El.X.Limbs {
			hasher.Write(limb)
		}

		for _, limb := range qcp.G1El.Y.Limbs {
			hasher.Write(limb)
		}
	}

	for _, cci := range vk.CommitmentConstraintIndexes {
		hasher.Write(cci)
	}

	return hasher.Sum(), nil
}

// MiMCBlockPad0 pad 0 into miMC block up to specific block size in Big-Endian
func MiMCBlockPad0(data []byte, blockSize int) []byte {
	var block = make([]byte, blockSize)
	for i := 0; i < blockSize; i++ {
		if i < blockSize-len(data) {
			block[i] = 0
		} else {
			block[i] = data[len(data)-blockSize+i]
		}
	}
	return block
}
