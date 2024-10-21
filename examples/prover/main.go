package main

import (
	"fmt"
	"os"

	"github.com/brevis-network/brevis-sdk/examples/dummy"
	"github.com/brevis-network/brevis-sdk/sdk/prover"
)

func main() {
	proverService, err := prover.NewService(
		"RPC_URL",
		1,
		128,
		dummy.DefaultAppCircuit(),
		prover.ServiceConfig{
			SetupDir: "$HOME/circuitOut",
			SrsDir:   "$HOME/kzgsrs",
		})
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	proverService.Serve("localhost", 33247)
}
