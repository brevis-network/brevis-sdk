package test

import (
	"testing"

	"github.com/brevis-network/brevis-sdk/sdk"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/test"
)

// ProverSucceeded checks:
// - a proof can be generated with the application circuit/assignment and the sdk generated circuit inputs.
// - the generated proof can be verified.
func ProverSucceeded(t *testing.T, circuit, assign sdk.AppCircuit, in sdk.CircuitInput) {
	host := sdk.DefaultHostCircuit(circuit, in.NumMaxDataPoints)
	assignment := sdk.NewHostCircuit(in.Clone(), assign)

	assert := test.NewAssert(t)
	assert.ProverSucceeded(host, assignment, test.WithBackends(backend.PLONK), test.WithCurves(ecc.BN254))
}

// ProverFailed checks:
// - a proof cannot be generated with the application circuit & invalid assignment and the sdk generated circuit inputs.
func ProverFailed(t *testing.T, circuit, assign sdk.AppCircuit, in sdk.CircuitInput) {
	host := sdk.DefaultHostCircuit(circuit, in.NumMaxDataPoints)
	assignment := sdk.NewHostCircuit(in.Clone(), assign)

	assert := test.NewAssert(t)
	assert.ProverFailed(host, assignment, test.WithBackends(backend.PLONK), test.WithCurves(ecc.BN254))
}

// IsSolved checks if the given application circuit/assignment and the input can be solved
func IsSolved(t *testing.T, circuit, assign sdk.AppCircuit, in sdk.CircuitInput) {
	host := sdk.DefaultHostCircuit(circuit, in.NumMaxDataPoints)
	assignment := sdk.NewHostCircuit(in.Clone(), assign)

	err := test.IsSolved(host, assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Error(err)
	}
}
