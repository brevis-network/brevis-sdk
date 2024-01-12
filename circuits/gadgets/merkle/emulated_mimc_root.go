package merkle

import (
	"fmt"
	"github.com/celer-network/brevis-sdk/circuits/gadgets/emulated/mimc"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
)

type MimcRootAPI[T emulated.FieldParams] struct {
	hasher *mimc.MiMC[T]
	api    frontend.API
	field  *emulated.Field[T]
}

func NewMimcRootAPI[T emulated.FieldParams](api frontend.API, id ecc.ID) *MimcRootAPI[T] {
	hasher := mimc.NewMiMC[T](api, id)
	f, err := emulated.NewField[T](api)
	if err != nil {
		panic(fmt.Errorf("failed to new emulated field: %s", err.Error()))
	}
	return &MimcRootAPI[T]{
		api:    api,
		hasher: hasher,
		field:  f,
	}
}

func (a *MimcRootAPI[T]) RestoreMimcRoot(
	leaf *emulated.Element[T],
	path []*emulated.Element[T],
	leftRight []frontend.Variable,
) *emulated.Element[T] {
	if len(path) != len(leftRight) {
		panic(fmt.Errorf("len path != len leftRight"))
	}
	h := leaf
	f, err := emulated.NewField[T](a.api)
	if err != nil {
		panic(err)
	}
	for i, node := range path {
		hash0 := a.hasher.Hash(node, h)
		hash1 := a.hasher.Hash(h, node)
		h = f.Select(leftRight[i], hash0, hash1)
	}
	h = f.Reduce(h)
	return h
}

// MimcRoot computes the merkle root of leaves using mimc hash
// uses emulated.RemHint and limbs.SplitHint
func (a *MimcRootAPI[T]) MimcRoot(leaves []*emulated.Element[T]) *emulated.Element[T] {
	if len(leaves) == 1 {
		return leaves[0]
	}
	var hashes []*emulated.Element[T]
	for i := 0; i < len(leaves); i += 2 {
		a.hasher.Reset()
		a.hasher.Write(leaves[i], leaves[i+1])
		h := a.hasher.Sum()
		hashes = append(hashes, h)
	}
	return a.MimcRoot(hashes)
}
