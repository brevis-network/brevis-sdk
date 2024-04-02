package prover

import (
	"github.com/brevis-network/brevis-sdk/sdk"
	"github.com/brevis-network/brevis-sdk/sdk/proto/sdkproto"
	"reflect"
)

func assignCustomInput(app sdk.AppCircuit, input *sdkproto.CustomInput) (sdk.AppCircuit, error) {
	vv := reflect.ValueOf(app)

	// deref until we get the actual value
	for vv.Kind() == reflect.Pointer {
		vv = vv.Elem()
	}

	if vv.Kind() != reflect.Struct {

	}

	return nil, nil
}
