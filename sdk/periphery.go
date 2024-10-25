package sdk

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/brevis-network/brevis-sdk/common/utils"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	cs "github.com/consensys/gnark/constraint/bn254"
	cs_bn254 "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	replonk "github.com/consensys/gnark/std/recursion/plonk"
	"github.com/consensys/gnark/test/unsafekzg"
	"github.com/ethereum/go-ethereum/common"
)

func Compile(app AppCircuit, compileOutDir, srsDir string) (constraint.ConstraintSystem, plonk.ProvingKey, plonk.VerifyingKey, []byte, error) {
	fmt.Println(">> compile")
	ccs, err := CompileOnly(app)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	maxReceipt, maxStorage, _ := app.Allocate()
	fmt.Println(">> setup")
	pk, vk, vkHash, err := Setup(ccs, srsDir, maxReceipt, maxStorage, NumMaxDataPoints)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	err = WriteTo(ccs, filepath.Join(compileOutDir, "compiledCircuit"))
	if err != nil {
		return nil, nil, nil, nil, err
	}
	err = WriteTo(pk, filepath.Join(compileOutDir, "pk"))
	if err != nil {
		return nil, nil, nil, nil, err
	}
	err = WriteTo(vk, filepath.Join(compileOutDir, "vk"))
	fmt.Println("compilation/setup complete")
	return ccs, pk, vk, vkHash, err
}

func NewFullWitness(assign AppCircuit, in CircuitInput) (w, wpub witness.Witness, err error) {
	fmt.Println(">> generate full witness")
	host := NewHostCircuit(in.Clone(), assign)

	w, err = frontend.NewWitness(host, ecc.BN254.ScalarField())
	if err != nil {
		return
	}
	wpub, err = w.Public()
	if err != nil {
		return
	}
	return
}

// CompileOnly is like Compile, but it does not automatically save the compilation output
func CompileOnly(app AppCircuit) (constraint.ConstraintSystem, error) {
	host := DefaultHostCircuit(app)

	before := time.Now()
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, host)
	if err != nil {
		return nil, fmt.Errorf("failed to compile: %s", err.Error())
	}

	fmt.Printf("circuit compiled in %s, number constraints %d\n", time.Since(before), ccs.GetNbConstraints())
	return ccs, nil
}

func Setup(ccs constraint.ConstraintSystem, cacheDir string, maxReceipt, maxStorage, numMaxDataPoints int) (pk plonk.ProvingKey, vk plonk.VerifyingKey, vkHash []byte, err error) {
	if len(cacheDir) == 0 {
		return nil, nil, nil, fmt.Errorf("must provide a directory to save SRS")
	}
	r1cs := ccs.(*cs.SparseR1CS)
	// srsDir := os.ExpandEnv(cacheDir)

	// canonical, lagrange, err := srs.NewSRS(r1cs, "https://kzg-srs.s3.us-west-2.amazonaws.com", srsDir)
	// if err != nil {
	// 	return
	// }

	canonical, lagrange, err := unsafekzg.NewSRS(r1cs)
	if err != nil {
		return
	}

	before := time.Now()
	pk, vk, err = plonk.Setup(ccs, canonical, lagrange)
	if err != nil {
		return
	}
	fmt.Printf("setup done in %s\n", time.Since(before))

	vkHash, err = printVkHash(vk, maxReceipt, maxStorage, numMaxDataPoints)

	return
}

func printVkHash(vk plonk.VerifyingKey, maxReceipt, maxStorage, total int) ([]byte, error) {
	if maxReceipt%32 != 0 {
		panic("invalid max receipts")
	}
	if maxStorage%32 != 0 {
		panic("invalid max storage")
	}
	if total != NumMaxDataPoints {
		panic("invalid total data points")
	}

	vkHash, err := CalBrevisCircuitDigest(maxReceipt, maxStorage, total-maxReceipt-maxStorage, vk)
	if err != nil {
		fmt.Printf("error computing vk hash: %s", err.Error())
		return nil, err
	}
	fmt.Println()
	fmt.Println("///////////////////////////////////////////////////////////////////////////////")
	fmt.Printf("// vk hash: 0x%x\n", vkHash.Bytes())
	fmt.Println("///////////////////////////////////////////////////////////////////////////////")
	fmt.Printf("// max receipts: %d, max storage: %d, numMaxDataPoints: %d\n", maxReceipt, maxStorage, total)
	fmt.Println("///////////////////////////////////////////////////////////////////////////////")
	fmt.Println()
	return vkHash.Bytes(), nil
}

func ComputeVkHash(vk plonk.VerifyingKey) (common.Hash, error) {
	plonkCircuitVk, err := replonk.ValueOfVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](vk)
	if err != nil {
		return common.Hash{}, err
	}

	appVkHash := utils.CalculateAppVkHashForBn254(plonkCircuitVk)
	return common.BytesToHash(appVkHash), nil
}

func Prove(ccs constraint.ConstraintSystem, pk plonk.ProvingKey, w witness.Witness) (plonk.Proof, error) {
	fmt.Println(">> prove")

	opts := replonk.GetNativeProverOptions(ecc.BN254.ScalarField(), ecc.BN254.ScalarField())

	return plonk.Prove(ccs, pk, w, opts)
}

func Verify(vk plonk.VerifyingKey, publicWitness witness.Witness, proof plonk.Proof) error {
	fmt.Println(">> verify")

	opts := replonk.GetNativeVerifierOptions(ecc.BN254.ScalarField(), ecc.BN254.ScalarField())
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
	f, err := os.OpenFile(path, os.O_TRUNC|os.O_CREATE|os.O_WRONLY, os.ModePerm)
	if err != nil {
		return err
	}
	defer f.Close()
	d, err := w.WriteTo(f)
	if err != nil {
		return err
	}
	fmt.Printf("%d bytes written to %s\n", d, path)
	return nil
}

func ReadSetupFrom(appCircuit AppCircuit, compileOutDir string) (constraint.ConstraintSystem, plonk.ProvingKey, plonk.VerifyingKey, []byte, error) {
	ccs, err := ReadCircuitFrom(filepath.Join(compileOutDir, "compiledCircuit"))
	if err != nil {
		return nil, nil, nil, nil, err
	}
	pk, err := ReadPkFrom(filepath.Join(compileOutDir, "pk"))
	if err != nil {
		return nil, nil, nil, nil, err
	}

	maxReceipt, maxStorage, _ := appCircuit.Allocate()

	vk, vkHash, err := ReadVkFrom(filepath.Join(compileOutDir, "vk"), maxReceipt, maxStorage, NumMaxDataPoints)
	return ccs, pk, vk, vkHash, err
}

func ReadCircuitFrom(path string) (constraint.ConstraintSystem, error) {
	f, err := os.Open(os.ExpandEnv(path))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	ccs := new(cs_bn254.R1CS)
	d, err := ccs.ReadFrom(f)
	if err != nil {
		return nil, err
	}
	fmt.Printf("Constraint system: %d bytes read from %s\n", d, path)
	return ccs, nil
}

func ReadPkFrom(path string) (plonk.ProvingKey, error) {
	f, err := os.Open(os.ExpandEnv(path))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	pk := plonk.NewProvingKey(ecc.BN254)
	d, err := pk.ReadFrom(f)
	if err != nil {
		return nil, err
	}
	fmt.Printf("Proving key: %d bytes read from %s\n", d, path)
	return pk, err
}

func ReadVkFrom(path string, maxReceipt, maxStorage, numMaxDataPoints int) (plonk.VerifyingKey, []byte, error) {
	f, err := os.Open(os.ExpandEnv(path))
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	vk := plonk.NewVerifyingKey(ecc.BN254)
	d, err := vk.ReadFrom(f)
	if err != nil {
		return nil, nil, err
	}
	fmt.Printf("Verifying key: %d bytes read from %s\n", d, path)

	vkHash, err := printVkHash(vk, maxReceipt, maxStorage, numMaxDataPoints)
	return vk, vkHash, err
}

func ReadProofFrom(path string) (plonk.Proof, error) {
	f, err := os.Open(os.ExpandEnv(path))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	proof := plonk.NewProof(ecc.BN254)
	d, err := proof.ReadFrom(f)
	if err != nil {
		return nil, err
	}
	fmt.Printf("Proof: %d bytes read from %s\n", d, path)
	return proof, err
}
