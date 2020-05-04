package arith

import (
	"crypto/rand"
	"math/big"
)

func lagrangeCoef(index *big.Int, args []*big.Int, groupOrd *big.Int) *big.Int {
	num := big.NewInt(1)
	den := big.NewInt(1)
	for _, arg := range args {
		if index.Cmp(arg) == 0 {
			continue

		}
		partialNum := new(big.Int).Add(arg, big.NewInt(1))
		partialNum.Neg(partialNum)
		partialDen := new(big.Int).Sub(index, arg)

		num.Mul(num, partialNum)
		den.Mul(den, partialDen)
	}

	den.ModInverse(den, groupOrd)
	num.Mul(num, den)
	num.Mod(num, groupOrd)

	return num
}

func poly(deg uint16, a0 *big.Int) ([]*big.Int, error) {
	var err error
	f := make([]*big.Int, deg+1)
	for i := range f {
		if i == 0 {
			f[i] = a0
			continue
		}
		if i == int(deg) {
			tmp := big.NewInt(1)
			tmp.Sub(Q, tmp)
			if f[i], err = rand.Int(randReader, tmp); err != nil {
				return nil, err
			}
			tmp.SetInt64(1)
			f[i].Add(f[i], tmp)

			continue
		}
		if f[i], err = rand.Int(randReader, Q); err != nil {
			return nil, err
		}
	}
	return f, nil
}

func polyEval(f []*big.Int, x *big.Int, q *big.Int) *big.Int {
	deg := len(f) - 1
	eval := new(big.Int).Set(f[deg])
	for i := deg - 1; i >= 0; i-- {
		eval.Mul(eval, x)
		eval.Add(eval, f[i])
	}
	eval.Mod(eval, q)
	return eval
}
