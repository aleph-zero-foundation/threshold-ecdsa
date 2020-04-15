package pkg

import (
	"crypto/sha256"
	"math/big"

	"golang.org/x/crypto/hkdf"
)

var (
	dst = [...]byte{0, 1}
	p   = big.NewInt(13)
)

func hashToField(msg, dst []byte) *big.Int {
	var t [48]byte
	info := []byte{'H', '2', 'F', byte(0), byte(1)}
	r := hkdf.New(sha256.New, msg, dst, info)
	if _, err := r.Read(t[:]); err != nil {
		panic(err)
	}
	var x big.Int
	return x.SetBytes(t[:]).Mod(&x, p)
}
