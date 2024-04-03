package prover

import (
	"bytes"
	"fmt"
	"path/filepath"

	"github.com/ethereum/go-ethereum/crypto"

	"github.com/brevis-network/brevis-sdk/sdk"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/constraint"
)

func readOrSetup(circuit sdk.AppCircuit, setupDir, srsDir string) (pk plonk.ProvingKey, vk plonk.VerifyingKey, ccs constraint.ConstraintSystem, err error) {
	fmt.Println(">> compiling circuit")
	ccs, err = sdk.CompileOnly(circuit)
	if err != nil {
		return
	}

	ccsBytes := bytes.NewBuffer(nil)
	_, err = ccs.WriteTo(ccsBytes)
	if err != nil {
		return
	}

	ccsDigest := crypto.Keccak256(ccsBytes.Bytes())
	fmt.Printf("circuit digest 0x%x\n", ccsDigest)

	pkFilepath := filepath.Join(setupDir, fmt.Sprintf("0x%x", ccsDigest), "pk")
	vkFilepath := filepath.Join(setupDir, fmt.Sprintf("0x%x", ccsDigest), "vk")

	var found bool
	pk, vk, found = readSetup(pkFilepath, vkFilepath)
	if found {
		return
	}

	fmt.Printf(">> no setup matching circuit digest 0x%x is found in %s\n", ccsDigest, setupDir)
	fmt.Println(">> setup")

	pk, vk, err = sdk.Setup(ccs, srsDir)
	if err != nil {
		return
	}

	err = sdk.WriteTo(pk, pkFilepath)
	if err != nil {
		return
	}
	err = sdk.WriteTo(vk, vkFilepath)
	if err != nil {
		return
	}

	return
}

func readSetup(pkFilepath, vkFilepath string) (pk plonk.ProvingKey, vk plonk.VerifyingKey, ok bool) {
	var err error
	pk, err = sdk.ReadPkFrom(pkFilepath)
	if err != nil {
		return
	}
	vk, err = sdk.ReadVkFrom(vkFilepath)
	if err != nil {
		return
	}
	ok = true
	return
}
