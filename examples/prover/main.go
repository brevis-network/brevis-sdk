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
			SetupDir:         "$HOME/circuitOut",
			SrsDir:           "$HOME/kzgsrs",
			RpcURL:           "RPC_URL",
			LocalStoragePath: "$HOME/circuitInput",
			ChainId:          1,
		})
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	proverService.Serve("localhost", 33247)
}
