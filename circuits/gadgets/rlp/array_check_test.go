package rlp

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/profile"
	"github.com/consensys/gnark/test"
	"strconv"
	"testing"
)

const LeafMaxHexLen = 140
const LeafFields = 2
const LeafArrayPrefixMaxHexLen = 4
const LeafMaxKeyHexLen = 64
const LeafMaxValueHexLen = 66

type MPTNodeArrayCheckCircuit struct {
	In      [LeafMaxHexLen]frontend.Variable
	Checked frontend.Variable
	//FieldHexLen    [N_FIELDS]frontend.Variable
	//Fields         [N_FIELDS][MaxHexLen]frontend.Variable
	//TotalRlpHexLen frontend.Variable
}

func (c *MPTNodeArrayCheckCircuit) Define(api frontend.API) error {
	arrayCheckParams := &ArrayCheck{
		MaxHexLen:            LeafMaxHexLen,
		MaxFields:            LeafFields,
		ArrayPrefixMaxHexLen: LeafArrayPrefixMaxHexLen,
		FieldMinHexLen:       []int{0, 0},
		FieldMaxHexLen:       []int{LeafMaxKeyHexLen + 2, LeafMaxValueHexLen},
	}

	out, _, _, _ := arrayCheckParams.RlpArrayCheck(api, c.In[:])

	api.AssertIsEqual(out, c.Checked)

	return nil
}

func Test_MPT_Leaf_Node_check(t *testing.T) {
	// test a leaf node: 0xf7a0200decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e5639594bc50cbd395314a43302e3bf56677755e5a543a8c
	// leaf value, 0xbc50cbd395314a43302e3bf56677755e5a543a8c
	// rlp decode leaf node: ["0x200decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563","0x94bc50cbd395314a43302e3bf56677755e5a543a8c"]
	// include two fields. keyPath and value.
	// for value, the prefix is 0x94(range [0x82, 0xb7]), the string length is 0x94-0x80 = 0x14, result in the length is 20 bytes.

	hexStr := "f7a0200decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e5639594bc50cbd395314a43302e3bf56677755e5a543a8c"
	//hexStr := "f838a0200decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e5639594bc50cbd395314a43302e3bf56677755e5a543a8c12"
	hexLen := len(hexStr)
	var inputs [LeafMaxHexLen]frontend.Variable
	for i := 0; i < LeafMaxHexLen; i++ {
		if i < hexLen {
			intValue, _ := strconv.ParseInt(string(hexStr[i]), 16, 64)
			inputs[i] = intValue
		} else {
			inputs[i] = 0
		}
	}

	witness := &MPTNodeArrayCheckCircuit{
		In:      inputs,
		Checked: 1,
	}

	err := test.IsSolved(&MPTNodeArrayCheckCircuit{}, witness, ecc.BN254.ScalarField())

	p := profile.Start()
	csc, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &MPTNodeArrayCheckCircuit{})
	fmt.Println("constraints:", csc.GetNbConstraints())
	p.Stop()
	fmt.Println(p.Top())
	assert := test.NewAssert(t)
	assert.NoError(err)
}
