package prover

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/ethereum/go-ethereum/crypto"

	"github.com/brevis-network/brevis-sdk/sdk"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/constraint"
)

type SetupManager struct {
	setupDir string
	srsDir   string
}

func newSetupManager(setupDir, srsDir string) *SetupManager {
	return &SetupManager{
		setupDir: setupDir,
		srsDir:   srsDir,
	}
}

func (m *SetupManager) readOrSetup(circuit sdk.AppCircuit) (pk plonk.ProvingKey, vk plonk.VerifyingKey, ccs constraint.ConstraintSystem, err error) {
	fmt.Println(">> compile")
	ccs, err = sdk.CompileCircuitOnly(circuit, m.setupDir)
	if err != nil {
		return
	}
	var ccsBytes bytes.Buffer
	foo := bufio.NewWriter(&ccsBytes)
	_, err = ccs.WriteTo(foo)
	if err != nil {
		return
	}

	ccsDigest := crypto.Keccak256(ccsBytes.Bytes())

	pkFilepath := filepath.Join(m.setupDir, fmt.Sprintf("0x%x", ccsDigest), "pk")
	vkFilepath := filepath.Join(m.setupDir, fmt.Sprintf("0x%x", ccsDigest), "vk")
	pk, vk, err = m.read(pkFilepath, vkFilepath)
	if err == nil {
		return
	}

	fmt.Println(">> pk vk not found")
	fmt.Println(">> setup")

	pk, vk, err = sdk.Setup(ccs, m.srsDir)
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

func (m *SetupManager) read(pkFilepath, vkFilepath string) (pk plonk.ProvingKey, vk plonk.VerifyingKey, err error) {
	pk = plonk.NewProvingKey(ecc.BLS12_377)
	pkr, err := openFile(pkFilepath)
	if err != nil {
		err = fmt.Errorf("cannot find pk from %s: %s", pkFilepath, err.Error())
		return
	}
	_, err = pk.UnsafeReadFrom(pkr)
	if err != nil {
		err = fmt.Errorf("cannot read pk from %s: %s", pkFilepath, err.Error())
		return
	}

	vk = plonk.NewVerifyingKey(ecc.BLS12_377)
	vkr, err := openFile(vkFilepath)
	if err != nil {
		err = fmt.Errorf("cannot find vk from %s: %s", vkFilepath, err.Error())
		return
	}
	_, err = pk.UnsafeReadFrom(vkr)
	if err != nil {
		err = fmt.Errorf("cannot read vk from %s: %s", vkFilepath, err.Error())
		return
	}
	return
}

func openFile(filename string) (reader io.Reader, err error) {
	f, err := os.Open(filename)
	if err != nil {
		return
	}
	defer f.Close()
	reader = f
	return
}
