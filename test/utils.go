package test

import (
	"github.com/celer-network/brevis-sdk/sdk"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/test"
	"testing"
)

func ProverSucceeded(t *testing.T, guest, assign sdk.AppCircuit, in sdk.CircuitInput) {
	host := sdk.NewHostCircuit(in.Clone(), guest)
	assignment := sdk.NewHostCircuit(in.Clone(), assign)

	assert := test.NewAssert(t)
	assert.ProverSucceeded(host, assignment, test.WithBackends(backend.PLONK), test.WithCurves(ecc.BLS12_377))
}

func ProverFailed(t *testing.T, guest, assign sdk.AppCircuit, in sdk.CircuitInput) {
	host := sdk.NewHostCircuit(in.Clone(), guest)
	assignment := sdk.NewHostCircuit(in.Clone(), assign)

	assert := test.NewAssert(t)
	assert.ProverFailed(host, assignment, test.WithBackends(backend.PLONK), test.WithCurves(ecc.BLS12_377))
}

func IsSolved(t *testing.T, guest, assign sdk.AppCircuit, in sdk.CircuitInput) {
	host := sdk.NewHostCircuit(in.Clone(), guest)
	assignment := sdk.NewHostCircuit(in.Clone(), assign)

	err := test.IsSolved(host, assignment, ecc.BLS12_377.ScalarField())
	if err != nil {
		t.Error(err)
	}
}
