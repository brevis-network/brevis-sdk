package mimc

import (
	"fmt"
	emu "github.com/celer-network/brevis-sdk/gadgets/emulated"
	"github.com/consensys/gnark-crypto/ecc"
	bls12377MiMC "github.com/consensys/gnark-crypto/ecc/bls12-377/fr/mimc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	bw6761MiMC "github.com/consensys/gnark-crypto/ecc/bw6-761/fr/mimc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/profile"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"math"
	"math/big"
	"testing"
)

type EmulatedBls12377MiMCTestCircuit struct {
	PreImage *emulated.Element[emulated.BLS12377Fr]
	Hash     *emulated.Element[emulated.BLS12377Fr]
}

func (c *EmulatedBls12377MiMCTestCircuit) Define(api frontend.API) error {
	miMC := NewMiMC[emulated.BLS12377Fr](api, ecc.BLS12_377)
	miMC.Write(c.PreImage)
	out := miMC.Sum()
	fmt.Println(out, c.Hash)
	miMC.fp.AssertIsEqual(out, c.Hash)
	return nil
}

func TestEmulateBls12377MiMC(t *testing.T) {
	assert := test.NewAssert(t)

	var one = 1
	var buffer = make([]byte, bls12377MiMC.BlockSize)
	buffer[bls12377MiMC.BlockSize-1] = 1
	hash := bls12377MiMC.NewMiMC()
	hash.Write(buffer)
	res := hash.Sum(nil)

	var witness, circuit EmulatedBls12377MiMCTestCircuit
	preimage := emulated.ValueOf[emulated.BLS12377Fr](one)
	witness.PreImage = &preimage
	circuit.PreImage = &preimage
	resHash := emulated.ValueOf[emulated.BLS12377Fr](res)
	witness.Hash = &resHash
	circuit.Hash = &resHash
	fmt.Printf("expected hash %+v\n", witness.Hash)

	err := test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type EmulatedBw6761MiMCTestCircuit struct {
	PreImage *emulated.Element[emulated.BW6761Fr]
	Hash     *emulated.Element[emulated.BW6761Fr]
}

func (c *EmulatedBw6761MiMCTestCircuit) Define(api frontend.API) error {
	miMC := NewMiMC[emulated.BW6761Fr](api, ecc.BW6_761)
	miMC.Write(c.PreImage)
	out := miMC.Sum()
	fmt.Println(out, c.Hash)
	miMC.fp.AssertIsEqual(out, c.Hash)
	return nil
}

func TestEmulateBw6761MiMC(t *testing.T) {
	assert := test.NewAssert(t)

	var one = 1
	var buffer = make([]byte, bw6761MiMC.BlockSize)
	buffer[bw6761MiMC.BlockSize-1] = 1
	hash := bw6761MiMC.NewMiMC()
	hash.Write(buffer)
	res := hash.Sum(nil)

	var witness, circuit EmulatedBw6761MiMCTestCircuit
	preimage := emulated.ValueOf[emulated.BW6761Fr](one)
	witness.PreImage = &preimage
	circuit.PreImage = &preimage
	resHash := emulated.ValueOf[emulated.BW6761Fr](res)
	witness.Hash = &resHash
	circuit.Hash = &resHash
	fmt.Printf("expected hash %+v\n", witness.Hash)

	err := test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	assert.NoError(err)

	fmt.Println(ccs.GetNbConstraints())
}

type MiMCConstMulTestCircuit struct {
	PreImage emulated.Element[emulated.BLS12377Fr]
	Out      emulated.Element[emulated.BLS12377Fr]
}

func (c *MiMCConstMulTestCircuit) Define(api frontend.API) error {
	fp, err := emulated.NewField[emulated.BLS12377Fr](api)
	if err != nil {
		fmt.Println("err:", err)
	}
	res := fp.MulMod(&c.PreImage, &c.PreImage)
	fp.AssertIsEqual(res, &c.Out)
	return nil
}

func TestMiMCConstantsMul(t *testing.T) {
	//consts := mimc.GetConstants()
	const0 := new(big.Int).SetUint64(math.MaxInt64)
	var tmp fr.Element

	tmp.SetBigInt(const0)
	//tmp.Square(&tmp)
	tmp.Mul(&tmp, &tmp)
	res := tmp.Bytes()

	var witness, circuit MiMCConstMulTestCircuit

	circuit.PreImage = emulated.ValueOf[emulated.BLS12377Fr](const0)
	witness.PreImage = emulated.ValueOf[emulated.BLS12377Fr](const0)
	circuit.Out = emulated.ValueOf[emulated.BLS12377Fr](res[:])
	witness.Out = emulated.ValueOf[emulated.BLS12377Fr](res[:])

	err := test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())

	assert := test.NewAssert(t)
	assert.NoError(err)
}

type BenchMiMCTestCircuit struct {
	PreImage [2]*emulated.Element[emulated.BLS12377Fr]
	Hash     *emulated.Element[emulated.BLS12377Fr]
}

func (c *BenchMiMCTestCircuit) Define(api frontend.API) error {
	miMC := NewMiMC[emulated.BLS12377Fr](api, ecc.BLS12_377)
	miMC.Write(c.PreImage[:]...)
	out := miMC.Sum()
	miMC.fp.AssertIsEqual(out, c.Hash)
	return nil
}

func TestMiMCOverBN254(t *testing.T) {
	assert := test.NewAssert(t)

	var assigment, circuit BenchMiMCTestCircuit

	goMiMC := bls12377MiMC.NewMiMC()
	for i := 0; i < 2; i++ {
		var data []byte
		for j := 0; j < bls12377MiMC.BlockSize; j++ {
			data = append(data, 0)
		}
		goMiMC.Write(data)
		preimage := emulated.ValueOf[emulated.BLS12377Fr](data)
		assigment.PreImage[i] = &preimage
		circuit.PreImage[i] = &preimage
	}

	result := goMiMC.Sum(nil)
	hash := emulated.ValueOf[emulated.BLS12377Fr](result)
	assigment.Hash = &hash
	circuit.Hash = &hash

	err := test.IsSolved(&circuit, &assigment, ecc.BN254.ScalarField())
	assert.NoError(err)

	p := profile.Start()
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	p.Stop()

	fmt.Println("ccs", ccs.GetNbConstraints())

	fmt.Println("top:", p.Top())
}

type TestMiMCBytesCircuit struct {
	InBytes  []frontend.Variable
	OutBytes []frontend.Variable `gnark:",public"`
}

func (c *TestMiMCBytesCircuit) Define(api frontend.API) error {
	if len(c.InBytes)%32 != 0 {
		panic("input bytes length must be multiple of 32")
	}
	el := emu.ToElement[emulated.BLS12377Fr](api, c.InBytes, 8)
	fmt.Printf("el %+v\n", el)
	mapi := NewMiMC[emulated.BLS12377Fr](api, ecc.BLS12_377)
	mapi.Write(el)
	mapi.Write(el)
	hash := mapi.Sum()
	fmt.Printf("actual hash limbs %x\n", hash.Limbs)
	hashBytes := emu.FromElement[emulated.BLS12377Fr](api, hash, 8)
	fmt.Printf("actual hash %x\n", hashBytes)
	for i, b := range hashBytes {
		api.AssertIsEqual(c.OutBytes[i], b)
	}
	return nil
}

func TestMiMCBytes(t *testing.T) {
	assert := test.NewAssert(t)
	data, _ := hexutil.Decode("0x0000000000000004000000000000000300000000000000020000000000000001")
	decomposed := emulated.ValueOf[emulated.BLS12377Fr](data)
	fmt.Printf("decomposed %+v\n", decomposed)
	inBytes := make([]frontend.Variable, len(data))
	for i, b := range data {
		inBytes[i] = b
	}
	hasher := bls12377MiMC.NewMiMC()
	hasher.Write(data)
	hasher.Write(data)
	expectedHash := hasher.Sum(nil)
	expected := emulated.ValueOf[emulated.BLS12377Fr](expectedHash).Limbs
	fmt.Printf("expected hash limbs %x\n", expected)
	fmt.Printf("expected hash %x\n", expectedHash)
	outBytes := make([]frontend.Variable, len(expectedHash))
	for i, b := range expectedHash {
		outBytes[i] = b
	}

	circuit := &TestMiMCBytesCircuit{
		InBytes:  inBytes,
		OutBytes: outBytes,
	}
	assignment := &TestMiMCBytesCircuit{
		InBytes:  inBytes,
		OutBytes: outBytes,
	}

	err := test.IsSolved(circuit, assignment, ecc.BN254.ScalarField())
	assert.NoError(err)
}
