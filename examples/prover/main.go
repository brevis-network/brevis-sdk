package main

import (
	"fmt"
	"github.com/brevis-network/brevis-sdk/examples/dummy"
	"github.com/brevis-network/brevis-sdk/sdk/prover"
	"os"
)

func main() {
	proverService, err := prover.NewService(dummy.DefaultAppCircuit(), prover.ServiceConfig{
		SetupDir: "$HOME/circuitOut",
		SrsDir:   "$HOME/kzgsrs",
	})
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	proverService.Serve(33247)
}
