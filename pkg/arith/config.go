package arith

import (
	"crypto/rand"
	"io"
	"math/big"
)

var (
	randReader io.Reader = rand.Reader
	// Q TODO: placeholder, should be replaced with order of the curve
	Q, _ = big.NewInt(0).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)
)
