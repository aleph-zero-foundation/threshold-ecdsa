package commitment

import (
	"encoding/binary"
	"math/big"

	"../../curve"
)

var secp256k1 = curve.NewSecp256k1Group()

//NewElGamalFactory creates a new ElGamal-type Commitments factory
func NewElGamalFactory(h curve.Point) *ElGamalFactory {
	egf := &ElGamalFactory{h: h}
	egf.neutral = egf.Create(big.NewInt(0), big.NewInt(0))
	return egf
}

//ElGamalFactory is a factory for ElGamal-type Commitment
type ElGamalFactory struct {
	h       curve.Point
	neutral *ElGamal
}

//NewElGamal creates a new ElGamal-type Commitment
func NewElGamal(a, b *big.Int) *ElGamal {
	return &ElGamal{secp256k1.ScalarBaseMult(a), secp256k1.ScalarBaseMult(b)}
}

//ElGamal is an implementation of ElGamal-type Commitments
type ElGamal struct {
	first, second curve.Point
}

//Create creates new ElGamal Commitment
func (e *ElGamalFactory) Create(value, r *big.Int) *ElGamal {
	return &ElGamal{
		first: secp256k1.ScalarBaseMult(r),
		second: secp256k1.Add(
			secp256k1.ScalarMult(e.h, r),
			secp256k1.ScalarBaseMult(value)),
	}
}

//Neutral creates neutral element for compose operation of ElGamal Commitments
func (e *ElGamalFactory) Neutral() *ElGamal {
	return e.Create(big.NewInt(0), big.NewInt(0))
}

//IsNeutral Chackes if element is equal to neutral one
func (e *ElGamalFactory) IsNeutral(a *ElGamal) bool {
	return a.Cmp(e.neutral, a)
}

//Compose composes two ElGamal Commitments
func (c *ElGamal) Compose(a, b *ElGamal) *ElGamal {
	secp256k1.Add(a.first, b.first)
	secp256k1.Add(a.second, b.second)
	return c
}

//Exp performs exp operation on ElGamal Commitments
func (c *ElGamal) Exp(x *ElGamal, n *big.Int) *ElGamal {
	secp256k1.ScalarMult(x.first, n)
	secp256k1.ScalarMult(x.second, n)
	return c
}

//Inverse returns inversed element for given ElGamal Commitment
func (c *ElGamal) Inverse(a *ElGamal) *ElGamal {
	//secp256k1.Neg(a.first)
	//secp256k1.Neg(a.second)
	return c
}

//Cmp compares to ElGamal ElGamals (maybe should be called equal)
func (*ElGamal) Cmp(a, b *ElGamal) bool {
	//return secp256k1.Equal(a.first, b.first) && secp256k1.Equal(a.second, b.second)
	return false
}

//MarshalBinary marshals ElGamal Commitment
func (c *ElGamal) MarshalBinary() ([]byte, error) {
	firstBytes := secp256k1.Marshal(c.first)
	secondBytes := secp256k1.Marshal(c.second)

	result := make([]byte, 4, 4+len(firstBytes)+len(secondBytes))
	binary.LittleEndian.PutUint32(result, uint32(len(firstBytes)))

	result = append(result, firstBytes...)
	result = append(result, secondBytes...)
	return result, nil
}

//UnmarshalBinary unmarshals ElGamal Commitment
func (c *ElGamal) UnmarshalBinary(b []byte) error {
	firstLen := binary.LittleEndian.Uint32(b[0:4])

	tmp, _ := secp256k1.Unmarshal(b[4 : 4+firstLen])
	c.first = tmp

	tmp, _ = secp256k1.Unmarshal(b[4+firstLen:])
	c.second = tmp

	return nil
}
