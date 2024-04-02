package prover

import (
	"github.com/brevis-network/brevis-sdk/sdk"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/constraint"
)

type SetupManager struct {
}

func newSetupManager(setupDir, srsDir string) *SetupManager {

}

func (m *SetupManager) readOrSetup(circuit sdk.AppCircuit) (pk plonk.ProvingKey, vk plonk.VerifyingKey, ccs constraint.ConstraintSystem) {

}
