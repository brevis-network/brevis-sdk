package core

import (
	rlputil "github.com/celer-network/brevis-sdk/circuits/gadgets/rlp"
	"github.com/consensys/gnark/frontend"
)

type IndexCheckCircuit struct {
	Index frontend.Variable `gnark:",public"`

	RlpString [6]frontend.Variable // pad 0 at right
}

func SumNibble(api frontend.API, nb []frontend.Variable) frontend.Variable {
	return api.Add(api.Mul(nb[0], 1),
		api.Mul(nb[1], 2),
		api.Mul(nb[2], 4),
		api.Mul(nb[3], 8),
	)
}

func (c *IndexCheckCircuit) Define(api frontend.API) error {
	res := CalTxOrReceiptIndexRlp(api, c.Index)
	for i, v := range res {
		api.AssertIsEqual(v, c.RlpString[i])
	}
	return nil
}

func CalTxOrReceiptIndexRlp(api frontend.API, index frontend.Variable) [6]frontend.Variable {
	//var b [6]frontend.Variable
	equaltozero := api.IsZero(index)
	lessthan7 := rlputil.LessThan(api, index, 128)
	lessthan8 := rlputil.LessThan(api, index, 256)
	lessthan16 := rlputil.LessThan(api, index, 1<<16)
	lessthan8 = api.Sub(lessthan8, lessthan7)
	lessthan7 = api.Sub(lessthan7, equaltozero)
	lessthan16 = api.Sub(lessthan16, equaltozero, lessthan7, lessthan8)

	api.AssertIsLessOrEqual(index, (1<<16)-1)

	BinaryIndex := api.ToBinary(index)
	// b0, high bit
	var b0, b1 [8]frontend.Variable
	// p3 is prefix of 0<i<128
	var p0, p1, p2, p3 [8]frontend.Variable

	Prefix0 := frontend.Variable(0x80)
	Prefix1 := frontend.Variable(0x81)
	Prefix2 := frontend.Variable(0x82)

	BinaryPrefix0 := api.ToBinary(Prefix0)
	BinaryPrefix1 := api.ToBinary(Prefix1)
	BinaryPrefix2 := api.ToBinary(Prefix2)

	for i := 0; i < 8; i++ {
		p0[i] = BinaryPrefix0[i]
		p1[i] = BinaryPrefix1[i]
		p2[i] = BinaryPrefix2[i]
	}

	// BinaryIndex save from low bit
	for i := 0; i < 8; i++ {
		p3[i] = BinaryIndex[i]
		b0[i] = BinaryIndex[i+8]
		b1[i] = BinaryIndex[i]
	}

	nibblep0 := [][]frontend.Variable{p0[4:8], p0[0:4]}
	nibblep1 := [][]frontend.Variable{p1[4:8], p1[0:4]}
	nibblep2 := [][]frontend.Variable{p2[4:8], p2[0:4]}
	nibblep3 := [][]frontend.Variable{p3[4:8], p3[0:4]}

	np0 := []frontend.Variable{SumNibble(api, nibblep0[0]), SumNibble(api, nibblep0[1])}
	np1 := []frontend.Variable{SumNibble(api, nibblep1[0]), SumNibble(api, nibblep1[1])}
	np2 := []frontend.Variable{SumNibble(api, nibblep2[0]), SumNibble(api, nibblep2[1])}
	np3 := []frontend.Variable{SumNibble(api, nibblep3[0]), SumNibble(api, nibblep3[1])}

	var np [2]frontend.Variable

	for i := 0; i < 2; i++ {
		np0[i] = api.Mul(np0[i], equaltozero)
		np1[i] = api.Mul(np1[i], lessthan8)
		np2[i] = api.Mul(np2[i], lessthan16)
		np3[i] = api.Mul(np3[i], lessthan7)
		np[i] = api.Add(np0[i],
			np1[i],
			np2[i],
			np3[i],
		)
	}

	nibble0 := [][]frontend.Variable{b0[4:8], b0[0:4]}
	nibble1 := [][]frontend.Variable{b1[4:8], b1[0:4]}

	n0 := []frontend.Variable{SumNibble(api, nibble0[0]), SumNibble(api, nibble0[1])}
	n1 := []frontend.Variable{SumNibble(api, nibble1[0]), SumNibble(api, nibble1[1])}

	// high is all 0, swap high and low, 1 < 256, if exchange = 1, should swap
	exchange := rlputil.LessThan(api, 1, api.Add(api.IsZero(n0[0]), api.IsZero(n0[1])))
	n0[0], n0[1], n1[0], n1[1] = api.Select(api.IsZero(exchange), n0[0], n1[0]),
		api.Select(api.IsZero(exchange), n0[1], n1[1]),
		api.Select(api.IsZero(exchange), n1[0], n0[0]),
		api.Select(api.IsZero(exchange), n1[1], n0[1])

	for i := 0; i < 2; i++ {
		n0[i] = api.Mul(n0[i], api.IsZero(lessthan7))
		n1[i] = api.Mul(n1[i], api.IsZero(lessthan7))
	}

	var res [6]frontend.Variable
	res[0] = np[0]
	res[1] = np[1]
	res[2] = n0[0]
	res[3] = n0[1]
	res[4] = n1[0]
	res[5] = n1[1]

	return res
}
