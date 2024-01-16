package sdk

import (
	"fmt"
	"github.com/celer-network/brevis-sdk/common/utils"
	"github.com/celer-network/brevis-sdk/sdk/srs"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	cs "github.com/consensys/gnark/constraint/bls12-377"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	replonk "github.com/consensys/gnark/std/recursion/plonk"
	"github.com/ethereum/go-ethereum/common"
	"io"
	"os"
	"path/filepath"
	"time"
)

func Compile(guest GuestCircuit, w Witness) (constraint.ConstraintSystem, error) {
	fmt.Println(">> compile")
	host := NewHostCircuit(w.Clone(), guest)

	before := time.Now()
	ccs, err := frontend.Compile(ecc.BLS12_377.ScalarField(), scs.NewBuilder, host)
	if err != nil {
		return nil, fmt.Errorf("failed to compile: %s", err.Error())
	}

	fmt.Printf("circuit compiled in %s, number constraints %d", time.Since(before), ccs.GetNbConstraints())
	return ccs, nil
}

func NewFullWitness(assign GuestCircuit, w Witness) (wit, wpub witness.Witness, err error) {
	fmt.Println(">> compile")
	host := NewHostCircuit(w.Clone(), assign)

	wit, err = frontend.NewWitness(host, ecc.BLS12_377.ScalarField())
	if err != nil {
		return
	}
	wpub, err = wit.Public()
	if err != nil {
		return
	}
	return
}

func Setup(ccs constraint.ConstraintSystem, cacheDir ...string) (pk plonk.ProvingKey, vk plonk.VerifyingKey, err error) {
	fmt.Println(">> setup")

	if len(cacheDir) > 1 {
		panic("Setup called with multiple paths")
	}
	dir := cacheDir[0]
	if len(cacheDir) == 0 {
		dir = "./"
	}

	r1cs := ccs.(*cs.SparseR1CS)
	srsDir := os.ExpandEnv(dir)

	canonical, lagrange, err := srs.NewSRS(r1cs, "https://kzg-srs.s3.us-west-2.amazonaws.com", srsDir)
	if err != nil {
		return
	}

	return plonk.Setup(ccs, canonical, lagrange)
}

func computeVkHash(vk plonk.VerifyingKey) (common.Hash, error) {
	plonkCircuitVk, err := replonk.ValueOfVerifyingKey[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine](vk)
	if err != nil {
		return common.Hash{}, err
	}

	appVkHash761 := utils.CalculateAppVkHashFor761(plonkCircuitVk)
	appVkHash := utils.CalculateAppVkHashFrom761To254(appVkHash761)
	return common.BytesToHash(appVkHash), nil
}

func Prove(ccs constraint.ConstraintSystem, pk plonk.ProvingKey, w witness.Witness) (plonk.Proof, error) {
	fmt.Println(">> prove")

	opts := replonk.GetNativeProverOptions(ecc.BW6_761.ScalarField(), ecc.BLS12_377.ScalarField())
	return plonk.Prove(ccs, pk, w, opts)
}

func Verify(vk plonk.VerifyingKey, publicWitness witness.Witness, proof plonk.Proof) error {
	fmt.Println(">> verify")

	opts := replonk.GetNativeVerifierOptions(ecc.BW6_761.ScalarField(), ecc.BLS12_377.ScalarField())
	return plonk.Verify(proof, vk, publicWitness, opts)
}

func WriteTo(w io.WriterTo, path string) error {
	path = os.ExpandEnv(path)
	dir, _ := filepath.Split(path)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		if err = os.MkdirAll(dir, os.ModePerm); err != nil {
			return err
		}
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, os.ModePerm)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = w.WriteTo(f)
	return err
}

//
//func ReadCircuitFrom(path string) (constraint.ConstraintSystem, error) {
//	f, err := os.Open(path)
//	if err != nil {
//		return nil, err
//	}
//	defer f.Close()
//	_, err = vk.UnsafeReadFrom(f)
//	return vk, err
//}

func ReadPkFrom(path string) (plonk.ProvingKey, error) {
	f, err := os.Open(os.ExpandEnv(path))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	vk := plonk.NewProvingKey(ecc.BLS12_377)
	_, err = vk.UnsafeReadFrom(f)
	return vk, err
}

func ReadVkFrom(path string) (plonk.VerifyingKey, error) {
	f, err := os.Open(os.ExpandEnv(path))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	vk := plonk.NewVerifyingKey(ecc.BLS12_377)
	_, err = vk.UnsafeReadFrom(f)
	return vk, err
}
