package sdk

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"testing"
)

func TestHostCircuit_assertInputUniqueness(t *testing.T) {
	assert := test.NewAssert(t)

	// valid
	c := &TestInputUniqueness{[]frontend.Variable{1, 2, 3}}
	assert.ProverSucceeded(c, c, test.WithBackends(backend.PLONK), test.WithCurves(ecc.BLS12_377))

	// valid. duplicated zeros should be ignored
	c = &TestInputUniqueness{[]frontend.Variable{1, 2, 3, 0, 0}}
	assert.ProverSucceeded(c, c, test.WithBackends(backend.PLONK), test.WithCurves(ecc.BLS12_377))

	// valid. ordering doesn't matter
	c = &TestInputUniqueness{[]frontend.Variable{1, 0, 3, 0, 2}}
	assert.ProverSucceeded(c, c, test.WithBackends(backend.PLONK), test.WithCurves(ecc.BLS12_377))

	// invalid. duplicated element
	c = &TestInputUniqueness{[]frontend.Variable{1, 1, 2, 3, 0}}
	assert.ProverFailed(c, c, test.WithBackends(backend.PLONK), test.WithCurves(ecc.BLS12_377))
}

type TestInputUniqueness struct {
	In []frontend.Variable
}

func (c *TestInputUniqueness) Define(api frontend.API) error {
	assertUnique(api, c.In)
	return nil
}
