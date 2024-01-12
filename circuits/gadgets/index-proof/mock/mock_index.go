package mock

import (
	"github.com/celer-network/brevis-sdk/circuits/gadgets/index-proof/core"
	"github.com/consensys/gnark/frontend"
)

func GetIndexProofWitness() core.IndexCheckCircuit {
	witness := core.IndexCheckCircuit{
		//Index:     133,
		//RlpString: [6]frontend.Variable{8, 1, 8, 5, 0, 0},
		//Index:     280,
		//RlpString: [6]frontend.Variable{8, 2, 0, 1, 1, 8},
		Index:     4664,
		RlpString: [6]frontend.Variable{8, 2, 1, 2, 3, 8},
		//Index:     0,
		//RlpString: [6]frontend.Variable{8, 0, 0, 0, 0, 0},
		//Index:     121,
		//RlpString: [6]frontend.Variable{7, 9, 0, 0, 0, 0},
	}
	return witness
}
