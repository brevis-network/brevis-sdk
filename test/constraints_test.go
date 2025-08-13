package test

import (
	"fmt"
	"os"
	"testing"

	"github.com/brevis-network/brevis-sdk/common/utils"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/logger"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/multicommit"
	replonk "github.com/consensys/gnark/std/recursion/plonk"
	"github.com/consensys/gnark/test"
	"github.com/consensys/gnark/test/unsafekzg"
	"github.com/rs/zerolog"
)

func TestBn254VkHash(t *testing.T) {
	logger.Set(zerolog.New(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: "15:04:05"}).With().Timestamp().Logger())

	assert := test.NewAssert(t)

	circuit := &CustomPlonkCircuit{
		InputCommitmentsRoot: 100,
		TogglesCommitment:    100,
		OutputCommitment:     [2]frontend.Variable{100, 100},
	}

	assignment := &CustomPlonkCircuit{
		InputCommitmentsRoot: 100,
		TogglesCommitment:    100,
		OutputCommitment:     [2]frontend.Variable{100, 100},
	}

	err := test.IsSolved(circuit, assignment, ecc.BN254.ScalarField())
	assert.NoError(err)

	witnessFull, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	assert.NoError(err)

	witnessPublic, err := witnessFull.Public()
	assert.NoError(err)

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, circuit)
	assert.NoError(err)

	canonical, lagrange, err := unsafekzg.NewSRS(ccs)

	pk, vk, err := plonk.Setup(ccs, canonical, lagrange)
	assert.NoError(err)

	plonkProof, err := plonk.Prove(ccs, pk, witnessFull, replonk.GetNativeProverOptions(ecc.BN254.ScalarField(), ecc.BN254.ScalarField()))
	assert.NoError(err)

	fmt.Println(">> verify")
	err = plonk.Verify(plonkProof, vk, witnessPublic, replonk.GetNativeVerifierOptions(ecc.BN254.ScalarField(), ecc.BN254.ScalarField()))
	assert.NoError(err)

	plonkCircuitVk, err := replonk.ValueOfVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](vk)
	assert.NoError(err)

	fmt.Printf("sum: %x", utils.CalculateAppVkHashForBn254(plonkCircuitVk))

	c := &Bn254VkHashTestCircuit{
		Vk: replonk.PlaceholderVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](ccs),
	}

	a := &Bn254VkHashTestCircuit{
		Vk: plonkCircuitVk,
	}

	err = test.IsSolved(c, a, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type Bn254VkHashTestCircuit struct {
	Vk replonk.VerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine] `gnark:",public"`
}

func (c *Bn254VkHashTestCircuit) Define(api frontend.API) error {
	res, err := utils.CalculateAppVkHashForBn254InCircuit(api, c.Vk)
	if err != nil {
		return err
	}
	fmt.Printf("res: %x", res)
	return nil
}

type CustomPlonkCircuit struct {
	InputCommitmentsRoot frontend.Variable    `gnark:",public"`
	TogglesCommitment    frontend.Variable    `gnark:",public"`
	OutputCommitment     [2]frontend.Variable `gnark:",public"`
}

func (c *CustomPlonkCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(c.InputCommitmentsRoot, c.TogglesCommitment)
	api.AssertIsEqual(c.InputCommitmentsRoot, c.OutputCommitment[0])
	api.AssertIsEqual(c.InputCommitmentsRoot, c.OutputCommitment[1])

	multicommit.WithCommitment(api, func(api frontend.API, gamma frontend.Variable) error {
		api.AssertIsDifferent(gamma, 1)
		return nil
	}, c.InputCommitmentsRoot)
	return nil
}
