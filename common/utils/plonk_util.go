package utils

import (
	"math/big"

	bn254mimc "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	fr_761 "github.com/consensys/gnark-crypto/ecc/bw6-761/fr"
	mimc_761 "github.com/consensys/gnark-crypto/ecc/bw6-761/fr/mimc"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	replonk "github.com/consensys/gnark/std/recursion/plonk"
)

func CalculateAppVkHashFor761(vk replonk.VerifyingKey[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine]) []byte {
	hasher := mimc_761.NewMiMC()
	var hashData []byte

	var data [mimc_761.BlockSize]byte
	hashData = append(hashData, new(big.Int).SetUint64(vk.BaseVerifyingKey.Size).FillBytes(data[:])...)
	hashData = append(hashData, new(big.Int).SetUint64(vk.BaseVerifyingKey.NbPublicVariables).FillBytes(data[:])...)

	for _, generatorLimb := range vk.BaseVerifyingKey.Generator.Limbs {
		hashData = append(hashData, generatorLimb.(*big.Int).FillBytes(data[:])...)
	}
	for _, sizeInvLimb := range vk.BaseVerifyingKey.SizeInv.Limbs {
		hashData = append(hashData, sizeInvLimb.(*big.Int).FillBytes(data[:])...)
	}
	for _, cosetShiftLimb := range vk.BaseVerifyingKey.CosetShift.Limbs {
		hashData = append(hashData, cosetShiftLimb.(*big.Int).FillBytes(data[:])...)
	}

	element := vk.BaseVerifyingKey.Kzg.G1.X.(fr_761.Element)
	elementData := element.Bytes()
	hashData = append(hashData, elementData[:]...)

	element = vk.BaseVerifyingKey.Kzg.G1.Y.(fr_761.Element)
	elementData = element.Bytes()
	hashData = append(hashData, elementData[:]...)

	for _, kzgG2 := range vk.BaseVerifyingKey.Kzg.G2 {
		element = kzgG2.P.X.A0.(fr_761.Element)
		elementData = element.Bytes()
		hashData = append(hashData, elementData[:]...)

		element = kzgG2.P.X.A1.(fr_761.Element)
		elementData = element.Bytes()
		hashData = append(hashData, elementData[:]...)

		element = kzgG2.P.Y.A0.(fr_761.Element)
		elementData = element.Bytes()
		hashData = append(hashData, elementData[:]...)

		element = kzgG2.P.Y.A1.(fr_761.Element)
		elementData = element.Bytes()
		hashData = append(hashData, elementData[:]...)
	}

	for _, se := range vk.S {
		element = se.G1El.X.(fr_761.Element)
		elementData = element.Bytes()
		hashData = append(hashData, elementData[:]...)

		element = se.G1El.Y.(fr_761.Element)
		elementData = element.Bytes()
		hashData = append(hashData, elementData[:]...)
	}

	element = vk.Ql.G1El.X.(fr_761.Element)
	elementData = element.Bytes()
	hashData = append(hashData, elementData[:]...)

	element = vk.Ql.G1El.Y.(fr_761.Element)
	elementData = element.Bytes()
	hashData = append(hashData, elementData[:]...)

	element = vk.Qr.G1El.X.(fr_761.Element)
	elementData = element.Bytes()
	hashData = append(hashData, elementData[:]...)

	element = vk.Qr.G1El.Y.(fr_761.Element)
	elementData = element.Bytes()
	hashData = append(hashData, elementData[:]...)

	element = vk.Qm.G1El.X.(fr_761.Element)
	elementData = element.Bytes()
	hashData = append(hashData, elementData[:]...)

	element = vk.Qm.G1El.Y.(fr_761.Element)
	elementData = element.Bytes()
	hashData = append(hashData, elementData[:]...)

	element = vk.Qo.G1El.X.(fr_761.Element)
	elementData = element.Bytes()
	hashData = append(hashData, elementData[:]...)

	element = vk.Qo.G1El.Y.(fr_761.Element)
	elementData = element.Bytes()
	hashData = append(hashData, elementData[:]...)

	element = vk.Qk.G1El.X.(fr_761.Element)
	elementData = element.Bytes()
	hashData = append(hashData, elementData[:]...)

	element = vk.Qk.G1El.Y.(fr_761.Element)
	elementData = element.Bytes()
	hashData = append(hashData, elementData[:]...)

	hasher.Write(hashData[:])

	return hasher.Sum(nil)
}

func CalculateAppVkHashFrom761To254(appVkHash []byte) []byte {
	bn254Hash := bn254mimc.NewMiMC()

	bn254Hash.Write(MiMCBlockPad0(appVkHash[0:24], bn254Hash.BlockSize()))
	bn254Hash.Write(MiMCBlockPad0(appVkHash[24:], bn254Hash.BlockSize()))

	return bn254Hash.Sum(nil)
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
