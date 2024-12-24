package prover

import (
	"bytes"
	"fmt"
	"path/filepath"

	"github.com/celer-network/goutils/log"

	"github.com/ethereum/go-ethereum/crypto"
	"golang.org/x/sync/errgroup"

	"github.com/brevis-network/brevis-sdk/sdk"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/constraint"
)

func readOnly(circuit sdk.AppCircuit, setupDir string, brevisApp *sdk.BrevisApp) (pk plonk.ProvingKey, vk plonk.VerifyingKey, ccs constraint.ConstraintSystem, vkHash []byte, err error) {
	errG := errgroup.Group{}
	errG.Go(func() error {
		log.Debugln(">> compiling circuit")
		ccs, err = sdk.CompileOnly(circuit)
		if err != nil {
			return fmt.Errorf("sdk.CompileOnly err: %w", err)
		}

		ccsBytes := bytes.NewBuffer(nil)
		_, err = ccs.WriteTo(ccsBytes)
		if err != nil {
			return fmt.Errorf("ccs.WriteTo err: %w", err)
		}

		ccsDigest := crypto.Keccak256(ccsBytes.Bytes())
		log.Debugf("circuit digest 0x%x\n", ccsDigest)
		return nil
	})
	errG.Go(func() error {
		log.Debugln(">> load vk pk")
		maxReceipts, maxStorage, maxTxs := circuit.Allocate()
		dataPoints := sdk.DataPointsNextPowerOf2(maxReceipts + maxStorage + maxTxs)
		pk, vk, vkHash, err = readSetup(filepath.Join(setupDir, "pk"), filepath.Join(setupDir, "vk"), maxReceipts, maxStorage, dataPoints, brevisApp)
		if err != nil {
			return fmt.Errorf("fail to find pk vk, err: %w", err)
		}
		log.Debugf("load pk vk success, vk hash: %x\n", vkHash)
		return nil
	})
	err = errG.Wait()
	if err != nil {
		return nil, nil, nil, nil, err
	}

	log.Debugf("load ccs, pk, vk success from %s \n", setupDir)

	return pk, vk, ccs, vkHash, nil
}

func readOrSetup(circuit sdk.AppCircuit, setupDir, srsDir string, brevisApp *sdk.BrevisApp) (pk plonk.ProvingKey, vk plonk.VerifyingKey, ccs constraint.ConstraintSystem, vkHash []byte, err error) {
	log.Debugln(">> compiling circuit")
	ccs, err = sdk.CompileOnly(circuit)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	ccsBytes := bytes.NewBuffer(nil)
	_, err = ccs.WriteTo(ccsBytes)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	ccsDigest := crypto.Keccak256(ccsBytes.Bytes())
	log.Debugf("circuit digest 0x%x", ccsDigest)

	maxReceipts, maxStorage, maxTxs := circuit.Allocate()
	dataPoints := sdk.DataPointsNextPowerOf2(maxReceipts + maxStorage + maxTxs)

	pkFilepath := filepath.Join(setupDir, fmt.Sprintf("0x%x", ccsDigest), "pk")
	vkFilepath := filepath.Join(setupDir, fmt.Sprintf("0x%x", ccsDigest), "vk")

	log.Debugln("trying to read setup from cache...")
	pk, vk, vkHash, err = readSetup(pkFilepath, vkFilepath, maxReceipts, maxStorage, dataPoints, brevisApp)
	if err == nil {
		return pk, vk, ccs, vkHash, nil
	}

	log.Debugf("no setup matching circuit digest 0x%x is found in %s\n", ccsDigest, setupDir)
	log.Debugln(">> setup")

	pk, vk, vkHash, err = sdk.Setup(ccs, srsDir, maxReceipts, maxStorage, dataPoints, brevisApp)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	err = sdk.WriteTo(pk, pkFilepath)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	err = sdk.WriteTo(vk, vkFilepath)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	return pk, vk, ccs, vkHash, nil
}

func readSetup(pkFilepath, vkFilepath string, maxReceipt, maxStorage, numMaxDataPoints int, brevisApp *sdk.BrevisApp) (pk plonk.ProvingKey, vk plonk.VerifyingKey, vkHash []byte, err error) {
	log.Debugf("load pk from %s\n", pkFilepath)
	pk, err = sdk.ReadPkFrom(pkFilepath)
	if err != nil {
		return nil, nil, nil, err
	}
	log.Debugf("load vk from %s\n", vkFilepath)
	vk, vkHash, err = sdk.ReadVkFrom(vkFilepath, maxReceipt, maxStorage, numMaxDataPoints, brevisApp)
	if err != nil {
		return nil, nil, nil, err
	}
	log.Debugf("load vk done, and vk hash is %x\n", vkHash)
	return pk, vk, vkHash, nil
}
