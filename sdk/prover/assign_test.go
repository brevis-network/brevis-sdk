package prover

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/brevis-network/brevis-sdk/sdk"
	"github.com/brevis-network/brevis-sdk/sdk/proto/sdkproto"
	"github.com/stretchr/testify/assert"
)

func TestAssignCustomInput(t *testing.T) {
	customInput := &sdkproto.CustomInput{JsonBytes: testJson}

	assigned, err := assignCustomInput(&AppCircuit{}, customInput)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("%+v\n", assigned)
	c, ok := assigned.(*AppCircuit)
	if !ok {
		t.Fatal("failed to cast back to AppCircuit")
	}
	assert.Equal(t, big.NewInt(27), c.U32Var.Val)
	assert.Equal(t, big.NewInt(0), c.U248Var.Val)
	assert.Equal(t, big.NewInt(1), c.U521Var.Limbs[0])
	assert.Equal(t, "-2", c.I248Var.String())
	assert.Equal(t, "3333333333333333333333333333333333333333333333333333333333333333", c.B32Var.String())
	assert.Equal(t, big.NewInt(0), c.U32Arr[0].Val)
	assert.Equal(t, big.NewInt(1), c.U248Arr[0].Val)
	assert.Equal(t, big.NewInt(2), c.U248Arr[1].Val)
	assert.Equal(t, big.NewInt(3), c.U248Arr[2].Val)
	assert.Equal(t, big.NewInt(11), c.U521Arr[0].Limbs[0])
	assert.Equal(t, big.NewInt(22), c.U521Arr[1].Limbs[0])
	assert.Equal(t, big.NewInt(33), c.U521Arr[2].Limbs[0])
	assert.Equal(t, "111", c.I248Arr[0].String())
	assert.Equal(t, "-222", c.I248Arr[1].String())
	assert.Equal(t, "333", c.I248Arr[2].String())
}

func TestAssignCustomInput_Incorrect(t *testing.T) {
	var err error

	_, err = assignCustomInput(&AppCircuit2{}, &sdkproto.CustomInput{JsonBytes: testJsonNested})
	println(err.Error())
	assert.Error(t, err)

	_, err = assignCustomInput(&AppCircuit3{}, &sdkproto.CustomInput{JsonBytes: testJsonIllegalObject})
	println(err.Error())
	assert.Error(t, err)

	_, err = assignCustomInput(&AppCircuit4{}, &sdkproto.CustomInput{JsonBytes: testJsonNonExistent})
	println(err.Error())
	assert.Error(t, err)
}

type dummyImpl struct{}

func (d dummyImpl) Allocate() (info sdk.AppCircuitAllocationInfo) {
	return sdk.AppCircuitAllocationInfo{
		MaxReceipts:     1,
		MaxSlots:        2,
		MaxTxs:          3,
		MaxBlockHeaders: 0,
	}
}
func (d dummyImpl) Define(api *sdk.CircuitAPI, in sdk.DataInput) error { return nil }

type AppCircuit struct {
	dummyImpl

	U32Var  sdk.Uint32
	U248Var sdk.Uint248
	U521Var sdk.Uint521
	I248Var sdk.Int248
	B32Var  sdk.Bytes32
	U32Arr  []sdk.Uint32
	U248Arr [3]sdk.Uint248
	U521Arr []sdk.Uint521
	I248Arr [3]sdk.Int248
	B32Arr  [2]sdk.Bytes32
}

type AppCircuit2 struct {
	dummyImpl
	MyNestedList [][]sdk.Uint248
}

type AppCircuit3 struct {
	dummyImpl
	MyField struct{ MyIllegalField string }
}

type AppCircuit4 struct {
	dummyImpl
	MyExistentField sdk.Uint248
}

const testJsonNested = `{
	"myNestedList": [
		[ { "type": "Uint248", "data": "1" } ]
	]
}`

const testJsonIllegalObject = `{
	"myField": { "myIllegalField": "hi" }
}`

const testJsonNonExistent = `{
	"myNonExistentField": { "type": "Uint248", "data": "0" }
}`

const testJson = `{
    "u32Var": { "type": "Uint32", "data": "27" },
    "u248Var": { "type": "Uint248", "data": "0" },
    "u521Var": { "type": "Uint521", "data": "1" },
    "i248Var": { "type": "Int248", "data": "-2" },
    "b32Var": { "type": "Bytes32", "data": "0x3333333333333333333333333333333333333333333333333333333333333333" },
    "u32Arr": [
        { "type": "Uint32", "data": "0" }
    ],
	"u248Arr": [
        { "type": "Uint248", "data": "1" },
        { "type": "Uint248", "data": "2" },
        { "type": "Uint248", "data": "3" }
    ],
    "u521Arr": [
        { "type": "Uint521", "data": "11" },
        { "type": "Uint521", "data": "22" },
        { "type": "Uint521", "data": "33" }
    ],
    "i248Arr": [
        { "type": "Int248", "data": "111" },
        { "type": "Int248", "data": "-222" },
        { "type": "Int248", "data": "333" }
    ],
    "b32Arr": [
        { "type": "Bytes32", "data": "0x1111111111111111111111111111111111111111111111111111111111111111" },
        { "type": "Bytes32", "data": "0x2222222222222222222222222222222222222222222222222222222222222222" }
    ]
}
`
