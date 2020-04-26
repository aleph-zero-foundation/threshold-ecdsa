package commitment

import (
	"encoding/binary"
	"math/big"

	"gitlab.com/alephledger/threshold-ecdsa/pkg/curve"
)

//NewElGamalFactory creates a new ElGamal-type Commitments factory
func NewElGamalFactory(h curve.Point) *ElGamalFactory {
	egf := &ElGamalFactory{h: h}
	egf.curve = curve.NewSecp256k1Group()
	egf.neutral = egf.Create(big.NewInt(0), big.NewInt(0))
	return egf
}

//ElGamalFactory is a factory for ElGamal-type Commitment
type ElGamalFactory struct {
	h       curve.Point
	neutral *ElGamal
	curve   curve.Group
}

//ElGamal is an implementation of ElGamal-type Commitments
type ElGamal struct {
	first, second curve.Point
	curve         curve.Group
}

//Create creates new ElGamal Commitment
func (e *ElGamalFactory) Create(value, r *big.Int) *ElGamal {
	return &ElGamal{
		first: e.curve.ScalarBaseMult(r),
		second: e.curve.Add(
			e.curve.ScalarMult(e.h, r),
			e.curve.ScalarBaseMult(value)),
		curve: e.curve,
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
	c.first = c.curve.Add(a.first, b.first)
	c.second = c.curve.Add(a.second, b.second)
	return c
}

//Exp performs exp operation on ElGamal Commitments
func (c *ElGamal) Exp(x *ElGamal, n *big.Int) *ElGamal {
	c.first = c.curve.ScalarMult(x.first, n)
	c.second = c.curve.ScalarMult(x.second, n)
	return c
}

//Inverse returns inversed element for given ElGamal Commitment
func (c *ElGamal) Inverse(a *ElGamal) *ElGamal {
	c.first = c.curve.Neg(a.first)
	c.second = c.curve.Neg(a.second)
	return c
}

//Cmp compares to ElGamal ElGamals (maybe should be called equal)
func (c *ElGamal) Cmp(a, b *ElGamal) bool {
	return c.curve.Equal(a.first, b.first) && c.curve.Equal(a.second, b.second)
}

//MarshalBinary marshals ElGamal Commitment
func (c *ElGamal) MarshalBinary() ([]byte, error) {
	firstBytes := c.curve.Marshal(c.first)
	secondBytes := c.curve.Marshal(c.second)

	result := make([]byte, 4, 4+len(firstBytes)+len(secondBytes))
	binary.LittleEndian.PutUint32(result, uint32(len(firstBytes)))

	result = append(result, firstBytes...)
	result = append(result, secondBytes...)
	return result, nil
}

//UnmarshalBinary unmarshals ElGamal Commitment
func (c *ElGamal) UnmarshalBinary(b []byte) error {
	firstLen := binary.LittleEndian.Uint32(b[0:4])

	tmp, _ := c.curve.Unmarshal(b[4 : 4+firstLen])
	c.first = tmp

	tmp, _ = c.curve.Unmarshal(b[4+firstLen:])
	c.second = tmp

	return nil
}
