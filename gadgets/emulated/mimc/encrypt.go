package mimc

import (
	"github.com/consensys/gnark/std/math/emulated"
)

func encryptPow17[F emulated.FieldParams](mimc *MiMC[F], x *emulated.Element[F]) *emulated.Element[F] {
	r := mimc.fp.MulMod(x, x)
	r = mimc.fp.MulMod(r, r)
	r = mimc.fp.MulMod(r, r)
	r = mimc.fp.MulMod(r, r)
	return mimc.fp.MulMod(r, x)
}

func encryptPow5[F emulated.FieldParams](mimc *MiMC[F], x *emulated.Element[F]) *emulated.Element[F] {
	r := mimc.fp.MulMod(x, x)
	s := mimc.fp.MulMod(r, r)
	return mimc.fp.MulMod(s, x)
}
