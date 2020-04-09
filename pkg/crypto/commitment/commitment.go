package commitment

import (
	"encoding/binary"
	"math/big"

	"../group"
)

//NewElGamalFactory creates a new ElGamal-type ElGamal factory
func NewElGamalFactory(h group.GroupElem) *ElGamalFactory {
	return &ElGamalFactory{
		h: h,
		neutral: &ElGamal{
			first:  group.NewGroupElem(big.NewInt(0)).Exp(group.G, big.NewInt(0)),
			second: group.NewGroupElem(big.NewInt(0)).Operation(group.NewGroupElem(big.NewInt(0)).Exp(h, big.NewInt(0)), group.NewGroupElem(big.NewInt(0)).Exp(group.G, big.NewInt(0))),
		},
	}
}

//ElGamalFactory Factory for ElGamal-type ElGamal
type ElGamalFactory struct {
	h       group.GroupElem
	neutral *ElGamal
}

//NewElGamal creates a new ElGamal-type ElGamal
func NewElGamal(a, b *big.Int) *ElGamal {
	return &ElGamal{group.NewGroupElem(a), group.NewGroupElem(b)}
}

//ElGamal Implementation of ElGamal-type ElGamal
type ElGamal struct {
	first, second group.GroupElem
}

//Create Create new ElGamal ElGamal
func (e *ElGamalFactory) Create(value, r *big.Int) *ElGamal {
	return &ElGamal{
		first:  group.NewGroupElem(big.NewInt(0)).Exp(group.G, r),
		second: group.NewGroupElem(big.NewInt(0)).Operation(group.NewGroupElem(big.NewInt(0)).Exp(e.h, r), group.NewGroupElem(big.NewInt(0)).Exp(group.G, value)),
	}
}

//Neutral Create neutral element for compose operation of ElGamal ElGamals
func (e *ElGamalFactory) Neutral() *ElGamal {
	return e.neutral
}

//Compose Compose two ElGamal ElGamals
func (c *ElGamal) Compose(a, b *ElGamal) *ElGamal {
	c.first.Operation(a.first, b.first)
	c.second.Operation(a.second, b.second)
	return c
}

//Exp Perform exp operation on ElGamal ElGamals
func (c *ElGamal) Exp(x *ElGamal, n *big.Int) *ElGamal {
	c.first.Exp(x.first, n)
	c.second.Exp(x.second, n)
	return c
}

//Inverse Return inversed element for given ElGamal ElGamal
func (c *ElGamal) Inverse(a *ElGamal) *ElGamal {
	c.first.Inverse(a.first)
	c.second.Inverse(a.second)
	return c
}

//Cmp Compare to ElGamal ElGamals (maybe should be called equal)
func (c *ElGamal) Cmp(a, b *ElGamal) bool {
	return (a.first).Cmp(a.first, b.first) && (a.second).Cmp(a.second, b.second)
}

//Marshal Marshal ElGamal ElGamal
func (c *ElGamal) Marshal() []byte {
	firstBytes := c.first.Marshal()
	secondBytes := c.second.Marshal()

	result := make([]byte, 4, 4+len(firstBytes)+len(secondBytes))
	binary.LittleEndian.PutUint32(result, uint32(len(firstBytes)))

	result = append(result, firstBytes...)
	result = append(result, secondBytes...)
	return result
}

//Unmarshal Unmarshal ElGamal ElGamal
func (c *ElGamal) Unmarshal(b []byte) *ElGamal {
	firstLen := binary.LittleEndian.Uint32(b[0:4])
	c.first.Unmarshal(b[4 : 4+firstLen])
	c.second.Unmarshal(b[4+firstLen:])
	return c
}
