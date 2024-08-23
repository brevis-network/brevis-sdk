package sdk

import (
	"fmt"
	"math/big"
	"sync"

	"github.com/brevis-network/brevis-sdk/common/utils"
	"github.com/brevis-network/zk-utils/circuits/gadgets/keccak"
	"github.com/celer-network/goutils/log"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/multicommit"
	"github.com/consensys/gnark/test"
	"github.com/ethereum/go-ethereum/common"
)

type AppCircuit interface {
	Define(api *CircuitAPI, in DataInput) error
	Allocate() (maxReceipts, maxStorage, maxTransactions int)
}

type HostCircuit struct {
	api frontend.API

	Input CircuitInput
	Guest AppCircuit
}

func DefaultHostCircuit(app AppCircuit) *HostCircuit {
	maxReceipts, maxStorage, maxTxs := app.Allocate()
	var inputCommits = make([]frontend.Variable, NumMaxDataPoints)
	for i := 0; i < NumMaxDataPoints; i++ {
		inputCommits[i] = 0
	}
	h := &HostCircuit{
		Input: defaultCircuitInput(maxReceipts, maxStorage, maxTxs),
		Guest: app,
	}
	return h
}

func NewHostCircuit(in CircuitInput, guest AppCircuit) *HostCircuit {
	return &HostCircuit{
		Input: in,
		Guest: guest,
	}
}

func (c *HostCircuit) Define(gapi frontend.API) error {
	c.api = gapi
	api := NewCircuitAPI(gapi)
	err := c.commitInput()
	if err != nil {
		return err
	}
	err = c.Guest.Define(api, c.Input.DataInput)
	if err != nil {
		return fmt.Errorf("error building user-defined circuit %s", err.Error())
	}
	//assertInputUniqueness(gapi, c.Input.InputCommitments, api.checkInputUniqueness)
	inputCommitmentRoot, err := calMerkelRoot(gapi, c.Input.InputCommitments)
	if err != nil {
		return fmt.Errorf("error building user-defined circuit calMerkelRoot fail, %s", err.Error())
	}
	gapi.AssertIsEqual(inputCommitmentRoot, c.Input.InputCommitmentsRoot)
	outputCommit := c.commitOutput(api.output)
	dryRunOutputCommit = outputCommit
	gapi.AssertIsEqual(outputCommit[0], c.Input.OutputCommitment[0])
	gapi.AssertIsEqual(outputCommit[1], c.Input.OutputCommitment[1])
	return nil
}

func (c *HostCircuit) commitInput() error {
	err := c.validateInput()
	if err != nil {
		return fmt.Errorf("invalid witness assignment: %s", err.Error())
	}
	hasher, err := mimc.NewMiMC(c.api)
	if err != nil {
		return fmt.Errorf("error creating mimc hasher instance: %s", err.Error())
	}
	hashOrZero := func(toggle frontend.Variable, vs []frontend.Variable) frontend.Variable {
		hasher.Write(vs...)
		sum := hasher.Sum()
		hasher.Reset()
		h := c.api.Select(toggle, sum, new(big.Int).SetBytes(common.Hex2Bytes("2369aa59f1f52216f305b9ad3b88be1479b25ff97b933be91329c803330966cd")))
		return h
	}

	var inputCommits [NumMaxDataPoints]frontend.Variable
	receipts := c.Input.Receipts
	j := 0
	for i, receipt := range receipts.Raw {
		packed := receipt.pack(c.api)
		inputCommits[j] = hashOrZero(receipts.Toggles[i], packed)
		j++
	}

	storage := c.Input.StorageSlots
	for i, slot := range storage.Raw {
		packed := slot.pack(c.api)
		inputCommits[j] = hashOrZero(storage.Toggles[i], packed)
		j++
	}
	txs := c.Input.Transactions
	for i, tx := range txs.Raw {
		packed := tx.pack(c.api)
		inputCommits[j] = hashOrZero(txs.Toggles[i], packed)
		j++
	}

	toggles := c.Input.Toggles()

	log.Infof("toggles: %v", toggles)

	for x := 0; x < NumMaxDataPoints; x = x + 16 {
		firstNotEmptyIndex := -1
		for y := 0; y < 16; y++ {
			if toggles[x+y] != 0 {
				if firstNotEmptyIndex == -1 {
					firstNotEmptyIndex = x + y
					break
				}
			}
		}
		if firstNotEmptyIndex == -1 {
			// do noting
			for y := x; y < 16; y++ {
				inputCommits[x+y] = new(big.Int).SetBytes(common.Hex2Bytes("2369aa59f1f52216f305b9ad3b88be1479b25ff97b933be91329c803330966cd"))
			}
		} else {
			// fill empty with first no empty
			for y := x; y < 16; y++ {
				if toggles[x+y] == 0 {
					inputCommits[x+y] = inputCommits[firstNotEmptyIndex]
				}
			}
		}
	}

	// adding constraint for input commitments (both effective commitments and dummies)
	for i := 0; i < c.dataLen(); i++ {
		log.Infof("%d %x == %x", i, c.Input.InputCommitments[i], inputCommits[i])
		c.api.AssertIsEqual(c.Input.InputCommitments[i], inputCommits[i])
	}

	log.Infof("toggles: %v", toggles)

	// sanity check, this shouldn't happen
	if len(toggles) != NumMaxDataPoints {
		panic(fmt.Errorf("toggles len %d != NumMaxDataPoints %d", len(toggles), NumMaxDataPoints))
	}

	packed := packBitsToFr(c.api, toggles)
	hasher.Write(packed...)
	togglesCommit := hasher.Sum()
	c.api.AssertIsEqual(togglesCommit, c.Input.TogglesCommitment)

	return nil
}

// Asserts that in the sorted list of inputs, each element is different from its
// next element. Zeros are not checked.
func assertInputUniqueness(api frontend.API, in []frontend.Variable, shouldCheck int) {
	multicommit.WithCommitment(api, func(api frontend.API, gamma frontend.Variable) error {
		sorted, err := api.Compiler().NewHint(SortHint, len(in), in...)
		if err != nil {
			panic(err)
		}
		// Grand product check. Asserts the following equation holds:
		// Σ_{a \in in} a+ɣ = Σ_{b \in sorted} b+ɣ
		var lhs, rhs frontend.Variable = 0, 0
		for i := 0; i < len(sorted); i++ {
			lhs = api.Mul(lhs, api.Add(in[i], gamma))
			rhs = api.Mul(rhs, api.Add(sorted[i], gamma))
		}
		api.AssertIsEqual(lhs, rhs)

		for i := 0; i < len(sorted)-1; i++ {
			a, b := sorted[i], sorted[i+1]
			// are both a and b zero? if yes, then it's valid; if not, then they must be different
			bothZero := api.Select(api.IsZero(a), api.IsZero(b), 0)
			isDifferent := api.Sub(1, api.IsZero(api.Sub(a, b)))
			isValid := api.Select(bothZero, 1, isDifferent)
			isValid = api.Select(shouldCheck, isValid, 1)
			api.AssertIsEqual(isValid, 1)
		}
		return nil
	}, in...)
}

func (c *HostCircuit) dataLen() int {
	d := c.Input
	return len(d.Receipts.Raw) + len(d.StorageSlots.Raw) + len(d.Transactions.Raw)
}

func (c *HostCircuit) validateInput() error {
	d := c.Input
	inputLen := len(d.Receipts.Raw) + len(d.StorageSlots.Raw) + len(d.Transactions.Raw)
	if inputLen > NumMaxDataPoints {
		return fmt.Errorf("input len must be less than %d", NumMaxDataPoints)
	}
	maxReceipts, maxSlots, maxTransactions := c.Guest.Allocate()
	if len(d.Receipts.Raw) != len(d.Receipts.Toggles) || len(d.Receipts.Raw) != maxReceipts {
		return fmt.Errorf("receipt input/toggle len mismatch: %d vs %d",
			len(d.Receipts.Raw), len(d.Receipts.Toggles))
	}
	if len(d.StorageSlots.Raw) != len(d.StorageSlots.Toggles) || len(d.StorageSlots.Raw) != maxSlots {
		return fmt.Errorf("storageSlots input/toggle len mismatch: %d vs %d",
			len(d.StorageSlots.Raw), len(d.StorageSlots.Toggles))
	}
	if len(d.Transactions.Raw) != len(d.Transactions.Toggles) || len(d.Transactions.Raw) != maxTransactions {
		return fmt.Errorf("transaction input/toggle len mismatch: %d vs %d",
			len(d.Transactions.Raw), len(d.Transactions.Toggles))
	}
	return nil
}

// commitOutput commits the user's output using Keccak256
// assumes `bits` are already little-endian bits in every byte. see CircuitAPI.addOutput
func (c *HostCircuit) commitOutput(bits []frontend.Variable) OutputCommitment {
	if len(bits)%8 != 0 {
		panic(fmt.Errorf("len bits (%d) must be multiple of 8", len(bits)))
	}

	rounds := len(bits)/1088 + 1
	paddedLen := rounds * 1088
	padded := make([]frontend.Variable, paddedLen)
	copy(padded, bits)

	// pad 101, start from one bit after the
	padded[len(bits)] = 1
	for i := len(bits) + 1; i < paddedLen-1; i++ {
		padded[i] = 0
	}
	padded[len(padded)-1] = 1

	fmt.Printf("commit output: rounds %d, data len %d, padded len %d\n",
		rounds, len(bits), paddedLen)

	// output hash bits are per 8 bits little-endian
	hashBits := keccak.Keccak256Bits(c.api, rounds, rounds-1, padded)
	// convert it to full little-endian to do recomposition
	bitsLE := utils.FlipByGroups(hashBits[:], 8)
	commit := OutputCommitment{
		c.api.FromBinary(bitsLE[128:]...),
		c.api.FromBinary(bitsLE[:128]...),
	}

	return commit
}

func bits2Bytes(data []frontend.Variable) []byte {
	var bits []uint
	for _, b := range data {
		bits = append(bits, uint(fromInterface(b).Int64()))
	}

	bytes := make([]byte, len(bits)/8)
	for i := 0; i < len(bits)/8; i++ {
		for j := 0; j < 8; j++ {
			bytes[i] += byte(bits[i*8+j] << j)
		}
	}

	return bytes
}

// will be set when run solve.
// be careful to use it with lock.
var dryRunOutput []byte
var dryRunOutputCommit OutputCommitment
var dryRunLock sync.Mutex

func dryRun(in CircuitInput, guest AppCircuit) (OutputCommitment, []byte, error) {
	dryRunLock.Lock()
	defer dryRunLock.Unlock()
	// resetting state
	dryRunOutputCommit = OutputCommitment{nil, nil}
	dryRunOutput = nil

	circuit := &HostCircuit{Input: in, Guest: guest}
	assignment := &HostCircuit{Input: in, Guest: guest}

	err := test.IsSolved(circuit, assignment, ecc.BN254.ScalarField())
	if err != nil {
		// if dry out == 0 after dry run, means the run failed
		if dryRunOutputCommit[0] == nil && dryRunOutputCommit[1] == nil {
			return dryRunOutputCommit, nil, fmt.Errorf("dry run failed: %s", err.Error())
		}
	}

	// making copies of these global variables to avoid sharing memory
	out := make([]byte, len(dryRunOutput))
	copy(out, dryRunOutput)

	commit := OutputCommitment{}
	copy(commit[:], dryRunOutputCommit[:])

	return commit, out, nil
}

// return merkel root hash,
// must be a full binary tree
// leafs is the InputCommitments list
func calMerkelRoot(gapi frontend.API, datas []frontend.Variable) (frontend.Variable, error) {
	hasher, err := mimc.NewMiMC(gapi)
	if err != nil {
		return nil, err
	}
	elementCount := len(datas)
	leafs := make([]frontend.Variable, elementCount)
	copy(leafs, datas)
	for {
		if elementCount == 1 {
			log.Infof("in circuitnputCommitmentsRoot: %x", leafs[0])
			return leafs[0], nil
		}
		log.Infof("calMerkelRoot with element size: %d", elementCount)
		for i := 0; i < elementCount/2; i++ {
			hasher.Reset()
			hasher.Write(leafs[2*i])
			hasher.Write(leafs[2*i+1])
			leafs[i] = hasher.Sum()
		}
		elementCount = elementCount / 2
	}
}
