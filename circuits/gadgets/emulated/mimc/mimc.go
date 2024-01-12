package mimc

import (
	"github.com/consensys/gnark-crypto/ecc"
	bls12377MiMC "github.com/consensys/gnark-crypto/ecc/bls12-377/fr/mimc"
	bn254MiMC "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	bw6761MiMC "github.com/consensys/gnark-crypto/ecc/bw6-761/fr/mimc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"math/big"
)

// MiMC contains the params of the Mimc hash func and the curves on which it is implemented
type MiMC[Base emulated.FieldParams] struct {
	params []big.Int                 // slice containing constants for the encryption rounds
	h      *emulated.Element[Base]   // current vector in the Miyaguchi–Preneel scheme
	data   []*emulated.Element[Base] // state storage. data is updated when Write() is called. Sum sums the data.
	fp     *emulated.Field[Base]
	ecc    ecc.ID
}

func NewMiMC[Base emulated.FieldParams](api frontend.API, id ecc.ID) *MiMC[Base] {
	fp, err := emulated.NewField[Base](api)
	if err != nil {
		panic(err)
	}
	res := &MiMC[Base]{}
	switch id {
	case ecc.BLS12_377:
		res.params = bls12377MiMC.GetConstants()
	case ecc.BN254:
		res.params = bn254MiMC.GetConstants()
	case ecc.BW6_761:
		res.params = bw6761MiMC.GetConstants()
	default:
		res.params = bls12377MiMC.GetConstants()
	}
	res.h = fp.Zero()
	res.fp = fp
	res.ecc = id
	return res
}

func (h *MiMC[Base]) Hash(data ...*emulated.Element[Base]) *emulated.Element[Base] {
	h.Reset()
	h.Write(data...)
	return h.Sum()
}

func (h *MiMC[Base]) encrypt(m *emulated.Element[Base]) *emulated.Element[Base] {
	x := m
	for i := 0; i < len(h.params); i++ {
		tmp := h.fp.Add(x, h.h)
		k := emulated.ValueOf[Base](h.params[i])
		//m = (m+k+c)^5
		tmp = h.fp.Add(tmp, &k)
		switch h.ecc {
		case ecc.BLS12_377:
			x = encryptPow17[Base](h, tmp)
		case ecc.BN254, ecc.BW6_761:
			x = encryptPow5[Base](h, tmp)
		// todo: implement other curves
		default:
			x = encryptPow17(h, tmp)
		}
	}
	return h.fp.Add(x, h.h)
}

func (h *MiMC[Base]) Write(data ...*emulated.Element[Base]) {
	h.data = append(h.data, data...)
}

func (h *MiMC[Base]) Reset() {
	h.data = nil
	h.h = h.fp.Zero()
}

func (h *MiMC[Base]) Sum() *emulated.Element[Base] {
	for _, stream := range h.data {
		r := h.encrypt(stream)
		temp := h.fp.Add(h.h, r)
		h.h = h.fp.Add(temp, stream)
	}
	return h.fp.Reduce(h.h)
}
