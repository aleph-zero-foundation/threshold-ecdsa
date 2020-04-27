package pkg

import (
	"crypto/sha256"
	"math/big"

	"golang.org/x/crypto/hkdf"
)

// Q TODO: placeholder, should be replaced with order of the curve
var Q, _ = big.NewInt(0).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)

//HashToBigInt takes []byte and returns its hash as a big.Int
func HashToBigInt(msg []byte) *big.Int {
	//48 = ceil((ceil(log2(p)) + k) / 8), where k is a bit security level
	var t [48]byte
	info := []byte{'H', '2', 'F', byte(0), byte(1)}
	r := hkdf.New(sha256.New, msg, []byte("ThresholdECDSA"), info)
	if _, err := r.Read(t[:]); err != nil {
		panic(err)
	}
	var x big.Int
	return x.SetBytes(t[:]).Mod(&x, Q)
}
