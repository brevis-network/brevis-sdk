package dummy

import (
	"github.com/brevis-network/brevis-sdk/sdk"
	"github.com/ethereum/go-ethereum/common"
	"math/big"
)

type AppCircuit struct {
	U248Var sdk.Uint248
	U521Var sdk.Uint521
	I248Var sdk.Int248
	B32Var  sdk.Bytes32
	U248Arr [3]sdk.Uint248
	U521Arr []sdk.Uint521
	I248Arr [3]sdk.Int248
	B32Arr  [2]sdk.Bytes32
}

func DefaultAppCircuit() *AppCircuit {
	return &AppCircuit{
		U248Var: sdk.ConstUint248(0),
		U521Var: sdk.ConstUint521(1),
		I248Var: sdk.ConstInt248(big.NewInt(-2)),
		B32Var:  sdk.ConstBytes32(common.FromHex("0x3333333333333333333333333333333333333333333333333333333333333333")),
		U248Arr: [3]sdk.Uint248{sdk.ConstUint248(1), sdk.ConstUint248(2), sdk.ConstUint248(3)},
		U521Arr: []sdk.Uint521{sdk.ConstUint521(11), sdk.ConstUint521(22), sdk.ConstUint521(33)},
		I248Arr: [3]sdk.Int248{sdk.ConstInt248(big.NewInt(111)), sdk.ConstInt248(big.NewInt(-222)), sdk.ConstInt248(big.NewInt(333))},
		B32Arr: [2]sdk.Bytes32{
			sdk.ConstBytes32(common.FromHex("0x1111111111111111111111111111111111111111111111111111111111111111")),
			sdk.ConstBytes32(common.FromHex("0x2222222222222222222222222222222222222222222222222222222222222222")),
		},
	}
}

var _ sdk.AppCircuit = &AppCircuit{}

func (c *AppCircuit) Allocate() (maxReceipts, maxStorage, maxTransactions int) {
	return 1, 1, 1
}

func (c *AppCircuit) Define(api *sdk.CircuitAPI, in sdk.DataInput) error {
	api.OutputUint(248, c.U248Var)
	api.OutputUint(248, api.ToUint248(c.U521Var))
	api.OutputUint(248, api.ToUint248(c.I248Var))
	api.OutputBytes32(c.B32Var)
	for _, uint248 := range c.U248Arr {
		api.OutputUint(248, uint248)
	}
	for _, uint521 := range c.U521Arr {
		api.OutputUint(248, api.ToUint248(uint521))
	}
	for _, int248 := range c.I248Arr {
		api.OutputUint(248, api.ToUint248(int248))
	}
	for _, bytes32 := range c.B32Arr {
		api.OutputBytes32(bytes32)
	}
	return nil
}
