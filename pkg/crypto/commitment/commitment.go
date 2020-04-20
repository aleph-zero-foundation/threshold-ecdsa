package commitment

import (
	"encoding/binary"
	"math/big"

	"gitlab.com/alephledger/threshold-ecdsa/pkg/group"
)

//NewElGamalFactory creates a new ElGamal-type Commitments factory
func NewElGamalFactory(h group.Elem) *ElGamalFactory {
	egf := &ElGamalFactory{h: h}
	egf.neutral = egf.Create(big.NewInt(0), big.NewInt(0))
	return egf
}

//ElGamalFactory is a factory for ElGamal-type Commitment
type ElGamalFactory struct {
	h       group.Elem
	neutral *ElGamal
}

//NewElGamal creates a new ElGamal-type Commitment
func NewElGamal(a, b *big.Int) *ElGamal {
	return &ElGamal{group.NewCurvePoint(a), group.NewCurvePoint(b)}
}

//ElGamal is an implementation of ElGamal-type Commitments
type ElGamal struct {
	first, second group.Elem
}

//Create creates new ElGamal Commitment
func (e *ElGamalFactory) Create(value, r *big.Int) *ElGamal {
	return &ElGamal{
		first: group.NewCurvePoint(big.NewInt(0)).Mult(&group.CGen, r),
		second: group.NewCurvePoint(big.NewInt(0)).Add(
			group.NewCurvePoint(big.NewInt(0)).Mult(e.h, r),
			group.NewCurvePoint(big.NewInt(0)).Mult(&group.CGen, value)),
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
	c.first.Add(a.first, b.first)
	c.second.Add(a.second, b.second)
	return c
}

//Exp performs exp operation on ElGamal Commitments
func (c *ElGamal) Exp(x *ElGamal, n *big.Int) *ElGamal {
	c.first.Mult(x.first, n)
	c.second.Mult(x.second, n)
	return c
}

//Inverse returns inversed element for given ElGamal Commitment
func (c *ElGamal) Inverse(a *ElGamal) *ElGamal {
	c.first.Inverse(a.first)
	c.second.Inverse(a.second)
	return c
}

//Cmp compares to ElGamal ElGamals (maybe should be called equal)
func (*ElGamal) Cmp(a, b *ElGamal) bool {
	return (a.first).Cmp(a.first, b.first) && (a.second).Cmp(a.second, b.second)
}

//MarshalBinary marshals ElGamal Commitment
func (c *ElGamal) MarshalBinary() ([]byte, error) {
	firstBytes, _ := c.first.MarshalBinary()
	secondBytes, _ := c.second.MarshalBinary()

	result := make([]byte, 4, 4+len(firstBytes)+len(secondBytes))
	binary.LittleEndian.PutUint32(result, uint32(len(firstBytes)))

	result = append(result, firstBytes...)
	result = append(result, secondBytes...)
	return result, nil
}

//UnmarshalBinary unmarshals ElGamal Commitment
func (c *ElGamal) UnmarshalBinary(b []byte) error {
	firstLen := binary.LittleEndian.Uint32(b[0:4])

	tmp := &group.CurvePoint{}
	tmp.UnmarshalBinary(b[4 : 4+firstLen])
	c.first = tmp

	tmp = &group.CurvePoint{}
	tmp.UnmarshalBinary(b[4+firstLen:])
	c.second = tmp

	return nil
}
