package sdk

import (
	"fmt"
	"sync"

	"github.com/brevis-network/brevis-sdk/common/utils"
	"github.com/brevis-network/zk-hash/keccak"
	"github.com/brevis-network/zk-hash/poseidon"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/multicommit"
	"github.com/consensys/gnark/test"
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
	dataPoints := DataPointsNextPowerOf2(maxReceipts + maxStorage + maxTxs)
	h := &HostCircuit{
		Input: defaultCircuitInput(maxReceipts, maxStorage, maxTxs, dataPoints),
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
	inputCommitmentRoot, err := CalMerkleRoot(gapi, c.Input.InputCommitments)
	if err != nil {
		return fmt.Errorf("error building user-defined circuit calMerkleRoot fail, %s", err.Error())
	}
	gapi.AssertIsEqual(inputCommitmentRoot, c.Input.InputCommitmentsRoot)
	outputCommit := c.commitOutput(api.output)
	dryRunOutputCommit = outputCommit
	gapi.AssertIsEqual(outputCommit[0], c.Input.OutputCommitment[0])
	gapi.AssertIsEqual(outputCommit[1], c.Input.OutputCommitment[1])

	// add commitment, then the proof will have same size without use assertUniq or not.
	multicommit.WithCommitment(gapi, func(api frontend.API, gamma frontend.Variable) error {
		api.AssertIsEqual(inputCommitmentRoot, c.Input.InputCommitmentsRoot)
		return nil
	}, c.Input.InputCommitmentsRoot)
	return nil
}

func (c *HostCircuit) commitInput() error {
	err := c.validateInput()
	if err != nil {
		return fmt.Errorf("invalid witness assignment: %s", err.Error())
	}
	hasher, err := poseidon.NewBn254PoseidonCircuit(c.api)
	if err != nil {
		return fmt.Errorf("error creating poseidon hasher instance: %s", err.Error())
	}

	maxReceipts, maxStorage, maxTxs := c.Guest.Allocate()
	dataPoints := DataPointsNextPowerOf2(maxReceipts + maxStorage + maxTxs)

	inputCommits := make([]frontend.Variable, dataPoints)
	receipts := c.Input.Receipts
	j := 0
	for i, receipt := range receipts.Raw {
		packed := receipt.pack(c.api)
		hasher.Reset()
		if len(packed) > 16 {
			panic(fmt.Sprintf("input is more than 16: %d", len(packed)))
		}
		for _, v := range packed {
			hasher.Write(v)
		}
		sum := hasher.Sum()

		inputCommits[j] = c.api.Select(receipts.Toggles[i], sum, c.Input.DummyReceiptInputCommitment)
		j++
	}

	storageSlots := c.Input.StorageSlots
	for i, slot := range storageSlots.Raw {
		packed := slot.pack(c.api)
		hasher.Reset()
		if len(packed) > 16 {
			panic(fmt.Sprintf("input is more than 16: %d", len(packed)))
		}
		for _, v := range packed {
			hasher.Write(v)
		}
		sum := hasher.Sum()

		inputCommits[j] = c.api.Select(storageSlots.Toggles[i], sum, c.Input.DummyStorageInputCommitment)
		j++
	}
	txs := c.Input.Transactions
	for i, tx := range txs.Raw {
		packed := tx.pack(c.api)
		hasher.Reset()
		if len(packed) > 16 {
			panic(fmt.Sprintf("input is more than 16: %d", len(packed)))
		}
		for _, v := range packed {
			hasher.Write(v)
		}
		sum := hasher.Sum()
		inputCommits[j] = c.api.Select(txs.Toggles[i], sum, c.Input.DummyTransactionInputCommitment)
		j++
	}

	// adding constraint for input commitments (both effective commitments and dummies)
	for i := 0; i < c.dataLen(); i++ {
		c.api.AssertIsEqual(c.Input.InputCommitments[i], inputCommits[i])
	}

	toggles := c.Input.Toggles()

	// sanity check, this shouldn't happen
	if len(toggles) != dataPoints {
		panic(fmt.Errorf("toggles len %d != DataPoints %d", len(toggles), dataPoints))
	}

	if len(toggles)%32 != 0 {
		panic(fmt.Errorf("toggles len %d is not an integral multiple of 32", len(toggles)))
	}

	var toggleTreeLeaf = make([]frontend.Variable, len(toggles)/32)
	for i := range toggleTreeLeaf {
		packed := packBitsToFr(c.api, toggles[i*32:i*32+32])
		hasher.Reset()
		hasher.Write(packed[0])
		toggleTreeLeaf[i] = hasher.Sum()
	}

	togglesCommit, err := CalMerkleRoot(c.api, toggleTreeLeaf)
	if err != nil {
		return fmt.Errorf("error building user-defined circuit calMerkleRoot fail, %s", err.Error())
	}
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
	maxReceipts, maxStorage, maxTxs := c.Guest.Allocate()
	dataPoints := DataPointsNextPowerOf2(maxReceipts + maxStorage + maxTxs)
	d := c.Input
	inputLen := len(d.Receipts.Raw) + len(d.StorageSlots.Raw) + len(d.Transactions.Raw)
	if inputLen > dataPoints {
		return fmt.Errorf("input len must be less than %d", dataPoints)
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

// return merkle root hash,
// must be a full binary tree
func CalMerkleRoot(gapi frontend.API, datas []frontend.Variable) (frontend.Variable, error) {
	hasher, err := poseidon.NewBn254PoseidonCircuit(gapi)
	if err != nil {
		return nil, err
	}
	elementCount := len(datas)
	leafs := make([]frontend.Variable, elementCount)
	copy(leafs, datas)
	for {
		if elementCount == 1 {
			return leafs[0], nil
		}
		for i := 0; i < elementCount/2; i++ {
			hasher.Reset()
			hasher.Write(leafs[2*i])
			hasher.Write(leafs[2*i+1])
			leafs[i] = hasher.Sum()
		}
		elementCount = elementCount / 2
	}
}
