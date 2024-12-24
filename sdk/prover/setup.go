package prover

import (
	"bytes"
	"fmt"
	"log"
	"path/filepath"
	"sync"

	"github.com/ethereum/go-ethereum/crypto"

	"github.com/brevis-network/brevis-sdk/sdk"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/constraint"
)

func readOnly(circuit sdk.AppCircuit, setupDir string, brevisApp *sdk.BrevisApp) (pk plonk.ProvingKey, vk plonk.VerifyingKey, ccs constraint.ConstraintSystem, vkHash []byte, err error) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		fmt.Println(">> compiling circuit")
		ccs, err = sdk.CompileOnly(circuit)
		if err != nil {
			log.Panicln(err)
		}

		ccsBytes := bytes.NewBuffer(nil)
		_, err = ccs.WriteTo(ccsBytes)
		if err != nil {
			log.Panicln(err)
		}

		ccsDigest := crypto.Keccak256(ccsBytes.Bytes())
		fmt.Printf("circuit digest 0x%x\n", ccsDigest)
	}()

	go func() {
		defer wg.Done()
		fmt.Println(">> load vk pk")
		var foundPkVk bool
		maxReceipts, maxStorage, maxTxs := circuit.Allocate()
		dataPoints := sdk.DataPointsNextPowerOf2(maxReceipts + maxStorage + maxTxs)
		pk, vk, vkHash, foundPkVk = readSetup(filepath.Join(setupDir, "pk"), filepath.Join(setupDir, "vk"), maxReceipts, maxStorage, dataPoints, brevisApp)
		if !foundPkVk {
			log.Panicf("fail to find pk vk")
		}
		fmt.Printf("load pk vk success, vk hash: %x \n", vkHash)
	}()

	wg.Wait()

	fmt.Printf("load ccs, pk, vk success from %s", setupDir)

	return
}

func readOrSetup(circuit sdk.AppCircuit, setupDir, srsDir string, brevisApp *sdk.BrevisApp) (pk plonk.ProvingKey, vk plonk.VerifyingKey, ccs constraint.ConstraintSystem, vkHash []byte, err error) {
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

	maxReceipts, maxStorage, maxTxs := circuit.Allocate()
	dataPoints := sdk.DataPointsNextPowerOf2(maxReceipts + maxStorage + maxTxs)

	pkFilepath := filepath.Join(setupDir, fmt.Sprintf("0x%x", ccsDigest), "pk")
	vkFilepath := filepath.Join(setupDir, fmt.Sprintf("0x%x", ccsDigest), "vk")

	fmt.Println("trying to read setup from cache...")
	var found bool
	pk, vk, vkHash, found = readSetup(pkFilepath, vkFilepath, maxReceipts, maxStorage, dataPoints, brevisApp)
	if found {
		return
	}

	fmt.Printf("no setup matching circuit digest 0x%x is found in %s\n", ccsDigest, setupDir)
	fmt.Println(">> setup")

	pk, vk, vkHash, err = sdk.Setup(ccs, srsDir, maxReceipts, maxStorage, dataPoints, brevisApp)
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

func readSetup(pkFilepath, vkFilepath string, maxReceipt, maxStorage, numMaxDataPoints int, brevisApp *sdk.BrevisApp) (pk plonk.ProvingKey, vk plonk.VerifyingKey, vkHash []byte, ok bool) {
	var err error
	fmt.Printf("load pk from %s \n", pkFilepath)
	pk, err = sdk.ReadPkFrom(pkFilepath)
	if err != nil {
		return
	}
	fmt.Printf("load vk from %s \n", vkFilepath)
	vk, vkHash, err = sdk.ReadVkFrom(vkFilepath, maxReceipt, maxStorage, numMaxDataPoints, brevisApp)
	if err != nil {
		return
	}
	fmt.Printf("load vk done, and vk hash is %x \n", vkHash)
	ok = true
	return
}
