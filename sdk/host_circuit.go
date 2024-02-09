package sdk

import (
	"fmt"
	"github.com/brevis-network/brevis-sdk/common/utils"
	"github.com/celer-network/zk-utils/circuits/gadgets/keccak"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/test"
)

type AppCircuit interface {
	Define(api *CircuitAPI, in DataInput) error
	Allocate() (maxReceipts, maxStorage, maxTransactions int)
}

type HostCircuit struct {
	api frontend.API

	Input CircuitInput
	guest AppCircuit `gnark:"-"`
}

func NewHostCircuit(in CircuitInput, guest AppCircuit) *HostCircuit {
	return &HostCircuit{
		Input: in,
		guest: guest,
	}
}

func (c *HostCircuit) Define(gapi frontend.API) error {
	c.api = gapi
	api := NewCircuitAPI(gapi)
	err := c.commitInput()
	if err != nil {
		return err
	}
	err = c.guest.Define(api, c.Input.DataInput)
	if err != nil {
		return fmt.Errorf("error building user-defined circuit %s", err.Error())
	}
	outputCommit := c.commitOutput(api.output)
	dryRunOutputCommit = outputCommit
	api.AssertIsEqual(outputCommit[0], c.Input.OutputCommitment[0])
	api.AssertIsEqual(outputCommit[1], c.Input.OutputCommitment[1])
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
	hashOrZero := func(toggle Variable, vs []Variable) Variable {
		hasher.Write(vs...)
		sum := hasher.Sum()
		hasher.Reset()
		h := c.api.Select(toggle, sum, 0)
		return h
	}

	var inputCommits []Variable
	for i, receipt := range c.Input.Receipts.Raw {
		packed := receipt.pack(c.api)
		inputCommits = append(inputCommits, hashOrZero(c.Input.Receipts.Toggles[i], packed))
	}
	for i, slot := range c.Input.StorageSlots.Raw {
		packed := slot.pack(c.api)
		inputCommits = append(inputCommits, hashOrZero(c.Input.StorageSlots.Toggles[i], packed))
	}
	for i, tx := range c.Input.Transactions.Raw {
		packed := tx.pack(c.api)
		inputCommits = append(inputCommits, hashOrZero(c.Input.Transactions.Toggles[i], packed))
	}

	// adding constraint for input commitments (both effective commitments and dummies)
	for i := 0; i < c.dataLen(); i++ {
		c.api.AssertIsEqual(c.Input.InputCommitments[i], inputCommits[i])
	}

	toggles := c.Input.Toggles()
	// sanity check, this shouldn't happen
	if len(toggles) != NumMaxDataPoints {
		panic(fmt.Errorf("toggles len %d != NumMaxDataPoints %d", len(toggles), NumMaxDataPoints))
	}

	packed := packBitsToFr(c.api, toggles)
	hasher.Write(packed...)
	togglesCommit := hasher.Sum()
	c.api.AssertIsEqual(togglesCommit, c.Input.TogglesCommitment)

	assertUnique(c.api, c.Input.InputCommitments)

	return nil
}

// Asserts that in the sorted list of inputs, each element is different from its
// next element. Zeros are not checked.
func assertUnique(api frontend.API, in []frontend.Variable) {
	if len(in) < 2 {
		return // no need to check uniqueness
	}

	hasher, err := mimc.NewMiMC(api)
	if err != nil {
		panic(err)
	}
	hasher.Write(in...)
	gamma := hasher.Sum()

	sorted, err := api.Compiler().NewHint(SortHint, len(in), in...)
	if err != nil {
		panic(err)
	}
	// Grand product check. Asserts the following equation holds:
	// Σ_{a \in in} a+ɣ = Σ_{b \in sorted} b+ɣ
	var lhs, rhs Variable = 0, 0
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
		api.AssertIsEqual(isValid, 1)
	}
}

func (c *HostCircuit) dataLen() int {
	return len(c.Input.Receipts.Raw) + len(c.Input.StorageSlots.Raw) + len(c.Input.Transactions.Raw)
}

func (c *HostCircuit) validateInput() error {
	w := c.Input
	inputLen := len(w.Receipts.Raw) + len(w.StorageSlots.Raw) + len(w.Transactions.Raw)
	if inputLen > NumMaxDataPoints {
		return fmt.Errorf("input len must be less than %d", NumMaxDataPoints)
	}
	maxReceipts, maxSlots, maxTransactions := c.guest.Allocate()
	if len(w.Receipts.Raw) != len(w.Receipts.Toggles) || len(w.Receipts.Raw) != maxReceipts {
		return fmt.Errorf("receipt input/toggle len mismatch: %d vs %d",
			len(w.Receipts.Raw), len(w.Receipts.Toggles))
	}
	if len(w.StorageSlots.Raw) != len(w.StorageSlots.Toggles) || len(w.StorageSlots.Raw) != maxSlots {
		return fmt.Errorf("storageSlots input/toggle len mismatch: %d vs %d",
			len(w.StorageSlots.Raw), len(w.StorageSlots.Toggles))
	}
	if len(w.Transactions.Raw) != len(w.Transactions.Toggles) || len(w.Transactions.Raw) != maxTransactions {
		return fmt.Errorf("transaction input/toggle len mismatch: %d vs %d",
			len(w.Transactions.Raw), len(w.Transactions.Toggles))
	}
	return nil
}

// commitOutput commits the user's output using Keccak256
// assumes `bits` are already little-endian bits in every byte. see CircuitAPI.addOutput
func (c *HostCircuit) commitOutput(bits []Variable) OutputCommitment {
	if len(bits)%8 != 0 {
		panic(fmt.Errorf("len bits (%d) must be multiple of 8", len(bits)))
	}

	rounds := len(bits)/1088 + 1
	paddedLen := rounds * 1088
	padded := make([]Variable, paddedLen)
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

	fmt.Printf("output commit data %x\n", bits2Bytes(bits))
	fmt.Printf("output commit hash %x%x\n", commit[0], commit[1])

	return commit
}

func bits2Bytes(data []Variable) []byte {
	var bits []uint
	for _, b := range data {
		bits = append(bits, uint(var2BigInt(b).Int64()))
	}

	bytes := make([]byte, len(bits)/8)
	for i := 0; i < len(bits)/8; i++ {
		for j := 0; j < 8; j++ {
			bytes[i] += byte(bits[i*8+j] << j)
		}
	}

	return bytes
}

var dryRunOutput []byte
var dryRunOutputCommit OutputCommitment

func dryRun(in CircuitInput, guest AppCircuit) (OutputCommitment, []byte, error) {
	// resetting state
	dryRunOutputCommit = OutputCommitment{nil, nil}
	dryRunOutput = nil

	circuit := &HostCircuit{Input: in, guest: guest}
	assignment := &HostCircuit{Input: in, guest: guest}

	err := test.IsSolved(circuit, assignment, ecc.BLS12_377.ScalarField())
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
