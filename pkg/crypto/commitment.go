package crypto

import (
	"encoding/binary"
	"math/big"
)

//CommitmentCreator Creator for interfaces
type CommitmentCreator interface {
	Create(*big.Int, *big.Int) Commitment
	Neutral() Commitment
}

//NewCommitmentCreator Create new CommitmentCreator for ElGamal type of cCommitments
func NewCommitmentCreator(h *big.Int) CommitmentCreator {
	return elGamalCreator{
		groupElem{
			value: h,
		},
	}
}

type elGamalCreator struct {
	h groupElem
}

//Commitment Commitment interface
type Commitment interface {
	Compose(Commitment, Commitment) Commitment
	Exp(Commitment, *big.Int) Commitment
	Inverse(Commitment) Commitment
	Cmp(Commitment, Commitment) bool
	Unmarshal([]byte) Commitment
	Marshal() []byte
}

//NewCommitment Create new commitment based on elGamal implementation
func NewCommitment(a, b *big.Int) Commitment {
	return elGamal{groupElem{a}, groupElem{b}}
}

//elGamal Implementation of ElGamal type of commitments
type elGamal struct {
	first, second GroupElem
}

//Create Create new ElGamal Commitment
func (e elGamalCreator) Create(value, r *big.Int) Commitment {
	return elGamal{
		first:  groupElem{big.NewInt(0)}.Exp(G, r),
		second: groupElem{big.NewInt(0)}.Operation(groupElem{big.NewInt(0)}.Exp(e.h, r), groupElem{big.NewInt(0)}.Exp(G, value)),
	}
}

//Neutral Create neutral element for compose operation of ElGamal commitments
func (e elGamalCreator) Neutral() Commitment {
	return elGamal{
		first:  groupElem{big.NewInt(0)}.Exp(G, big.NewInt(0)),
		second: groupElem{big.NewInt(0)}.Operation(groupElem{big.NewInt(0)}.Exp(e.h, big.NewInt(0)), groupElem{big.NewInt(0)}.Exp(G, big.NewInt(0))),
	}
}

//Compose Compose two ElGamal commitments
func (c elGamal) Compose(a, b Commitment) Commitment {
	c.first.Operation(a.(elGamal).first, b.(elGamal).first)
	c.second.Operation(a.(elGamal).second, b.(elGamal).second)
	return c
}

//Exp Perform exp operation on ElGamal commitments
func (c elGamal) Exp(x Commitment, n *big.Int) Commitment {
	c.first.Exp(x.(elGamal).first, n)
	c.second.Exp(x.(elGamal).second, n)
	return c
}

//Inverse Return inversed element for given ElGamal commitment
func (c elGamal) Inverse(a Commitment) Commitment {
	c.first.Inverse(a.(elGamal).first)
	c.second.Inverse(a.(elGamal).second)
	return c
}

//Cmp Compare to ElGamal commitments (maybe should be called equal)
func (c elGamal) Cmp(a, b Commitment) bool {
	return (a.(elGamal).first).Cmp(a.(elGamal).first, b.(elGamal).first) && (a.(elGamal).second).Cmp(a.(elGamal).second, b.(elGamal).second)
}

//Marshal Marshal ElGamal commitment
func (c elGamal) Marshal() []byte {
	firstBytes := c.first.Marshal()
	secondBytes := c.second.Marshal()

	result := make([]byte, 4)
	binary.LittleEndian.PutUint32(result, uint32(len(firstBytes)))

	result = append(result, firstBytes...)
	result = append(result, secondBytes...)
	return result
}

//Unmarshal Unmarshal ElGamal commitment
func (c elGamal) Unmarshal(b []byte) Commitment {
	firstLen := binary.LittleEndian.Uint32(b[0:4])
	c.first.Unmarshal(b[4 : 4+firstLen])
	c.second.Unmarshal(b[4+firstLen:])
	return c
}
