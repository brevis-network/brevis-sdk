package main

import (
	"fmt"
	"os"

	"github.com/brevis-network/brevis-sdk/examples/dummy"
	"github.com/brevis-network/brevis-sdk/sdk/prover"
)

func main() {
	proverService, err := prover.NewService(
		dummy.DefaultAppCircuit(),
		prover.ServiceConfig{
			SetupDir: "$HOME/circuitOut",
			SrsDir:   "$HOME/kzgsrs",
		},
		prover.SourceChainConfigs{
			&prover.SourceChainConfig{
				RpcUrl:  "RPC_URL",
				ChainId: 1,
			},
		},
	)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	err = proverService.Serve("localhost", 33247, 33257)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
