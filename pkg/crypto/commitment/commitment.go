package commitment

import (
	"fmt"
	"io"
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

//Curve returns group used by ElGamalFactory
func (e *ElGamalFactory) Curve() curve.Group {
	return e.curve
}

//Neutral creates neutral element for compose operation of ElGamal Commitments
func (e *ElGamalFactory) Neutral() *ElGamal {
	return e.Create(big.NewInt(0), big.NewInt(0))
}

//IsNeutral Chackes if element is equal to neutral one
func (e *ElGamalFactory) IsNeutral(a *ElGamal) bool {
	return a.Equal(e.neutral, a)
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

// Equal checks the equality of the provided commitments
func (c *ElGamal) Equal(a, b *ElGamal) bool {
	return c.curve.Equal(a.first, b.first) && c.curve.Equal(a.second, b.second)
}

// Encode encodes ElGamal Commitment
func (c *ElGamal) Encode(w io.Writer) error {
	if err := c.curve.Encode(c.first, w); err != nil {
		return fmt.Errorf("Encoding first coordinate in ElGamal: %v", err)
	}
	if err := c.curve.Encode(c.second, w); err != nil {
		return fmt.Errorf("Encoding second coordinate in ElGamal: %v", err)
	}
	return nil
}

// Decode decodes ElGamal Commitment
func (c *ElGamal) Decode(r io.Reader) error {
	c.curve = curve.NewSecp256k1Group()

	var err error
	c.first, err = c.curve.Decode(r)
	if err != nil {
		return fmt.Errorf("Decoding first coordinate in ElGamal: %v", err)
	}
	c.second, err = c.curve.Decode(r)
	if err != nil {
		return fmt.Errorf("Decoding second coordinate in ElGamal: %v", err)
	}

	return nil
}
