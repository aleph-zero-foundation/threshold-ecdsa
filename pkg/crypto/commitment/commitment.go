package commitment

import (
	"encoding/binary"
	"math/big"

	"../group"
)

//NewElGamalFactory creates a new ElGamal-type Commitments factory
func NewElGamalFactory(h group.Elem) *ElGamalFactory {
	egf := &ElGamalFactory{h: h}
	egf.neutral = egf.Create(big.NewInt(0), big.NewInt(0))
	return egf
}

//ElGamalFactory Factory for ElGamal-type Commitment
type ElGamalFactory struct {
	h       group.Elem
	neutral *ElGamal
}

//NewElGamal creates a new ElGamal-type Commitment
func NewElGamal(a, b *big.Int) *ElGamal {
	return &ElGamal{group.NewElem(a), group.NewElem(b)}
}

//ElGamal Implementation of ElGamal-type Commitments
type ElGamal struct {
	first, second group.Elem
}

//Create Create new ElGamal Commitment
func (e *ElGamalFactory) Create(value, r *big.Int) *ElGamal {
	return &ElGamal{
		first:  group.NewElem(big.NewInt(0)).Mult(group.Gen, r),
		second: group.NewElem(big.NewInt(0)).Add(group.NewElem(big.NewInt(0)).Mult(e.h, r), group.NewElem(big.NewInt(0)).Mult(group.Gen, value)),
	}
}

//Neutral Create neutral element for compose operation of ElGamal Commitments
func (e *ElGamalFactory) Neutral() *ElGamal {
	return e.neutral
}

//Compose Compose two ElGamal Commitments
func (c *ElGamal) Compose(a, b *ElGamal) *ElGamal {
	c.first.Add(a.first, b.first)
	c.second.Add(a.second, b.second)
	return c
}

//Exp Perform exp operation on ElGamal Commitments
func (c *ElGamal) Exp(x *ElGamal, n *big.Int) *ElGamal {
	c.first.Mult(x.first, n)
	c.second.Mult(x.second, n)
	return c
}

//Inverse Return inversed element for given ElGamal Commitment
func (c *ElGamal) Inverse(a *ElGamal) *ElGamal {
	c.first.Inverse(a.first)
	c.second.Inverse(a.second)
	return c
}

//Cmp Compare to ElGamal ElGamals (maybe should be called equal)
func (c *ElGamal) Cmp(a, b *ElGamal) bool {
	return (a.first).Cmp(a.first, b.first) && (a.second).Cmp(a.second, b.second)
}

//Marshal Marshal ElGamal Commitment
func (c *ElGamal) Marshal() []byte {
	firstBytes := c.first.Marshal()
	secondBytes := c.second.Marshal()

	result := make([]byte, 4, 4+len(firstBytes)+len(secondBytes))
	binary.LittleEndian.PutUint32(result, uint32(len(firstBytes)))

	result = append(result, firstBytes...)
	result = append(result, secondBytes...)
	return result
}

//Unmarshal Unmarshal ElGamal Commitment
func (c *ElGamal) Unmarshal(b []byte) *ElGamal {
	firstLen := binary.LittleEndian.Uint32(b[0:4])
	c.first.Unmarshal(b[4 : 4+firstLen])
	c.second.Unmarshal(b[4+firstLen:])
	return c
}
