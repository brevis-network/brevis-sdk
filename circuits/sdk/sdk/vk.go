package sdk

import (
	"github.com/celer-network/brevis-sdk/common/utils"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	replonk "github.com/consensys/gnark/std/recursion/plonk"

	"github.com/consensys/gnark/backend/plonk"
	"github.com/ethereum/go-ethereum/common"
)

func VkHash(vk plonk.VerifyingKey) (common.Hash, error) {
	plonkCircuitVk, err := replonk.ValueOfVerifyingKey[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine](vk)
	if err != nil {
		return common.Hash{}, err
	}

	appVkHash761 := utils.CalculateAppVkHashFor761(plonkCircuitVk)
	appVkHash := utils.CalculateAppVkHashFrom761To254(appVkHash761)
	return common.BytesToHash(appVkHash), nil
}
