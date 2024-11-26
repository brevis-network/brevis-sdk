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

func readOrSetup(circuit sdk.AppCircuitV2, setupDir, srsDir string) (pk plonk.ProvingKey, vk plonk.VerifyingKey, ccs constraint.ConstraintSystem, vkHash []byte, err error) {
	fmt.Println(">> compiling circuit")
	ccs, err = sdk.CompileOnlyV2(circuit)
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

	fmt.Println("trying to read setup from cache...")
	var found bool
	pk, vk, vkHash, found = readSetup(pkFilepath, vkFilepath, circuit.Allocate())
	if found {
		return
	}

	fmt.Printf("no setup matching circuit digest 0x%x is found in %s\n", ccsDigest, setupDir)
	fmt.Println(">> setup")

	pk, vk, vkHash, err = sdk.Setup(ccs, srsDir, circuit.Allocate())
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

func readSetup(pkFilepath, vkFilepath string, info sdk.AppCircuitAllocationInfo) (pk plonk.ProvingKey, vk plonk.VerifyingKey, vkHash []byte, ok bool) {
	var err error
	pk, err = sdk.ReadPkFrom(pkFilepath)
	if err != nil {
		return
	}
	vk, vkHash, err = sdk.ReadVkFrom(vkFilepath, info)
	if err != nil {
		return
	}
	ok = true
	return
}
