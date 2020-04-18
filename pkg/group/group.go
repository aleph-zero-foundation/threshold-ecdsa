package group

import "math/big"

//Gen Simplest generator of group
var Gen = FieldElem{
	value: big.NewInt(1),
}

//Elem element of group
type Elem interface {
	Add(Elem, Elem) Elem
	Mult(Elem, *big.Int) Elem
	Inverse(Elem) Elem
	Cmp(Elem, Elem) bool
	Neutral() Elem
	MarshalBinary() ([]byte, error)
}

// FieldElem implements the Elem interface and represents an element in a field
type FieldElem struct {
	value *big.Int
}

// NewFieldElem constructs a new FieldElem object
func NewFieldElem(value *big.Int) *FieldElem {
	return &FieldElem{value}
}

// TODO: reimplement operations so that they are field operations

//Add performs based operation between two Elems
func (g *FieldElem) Add(a, b Elem) Elem {
	g.value.Add(a.(*FieldElem).value, b.(*FieldElem).value)
	return g
}

//Mult performs exp operation on given Elem and value
func (g *FieldElem) Mult(h Elem, x *big.Int) Elem {
	g.value.Mul(h.(*FieldElem).value, x)
	return g
}

//Inverse returns inversed element for given Elem
func (g *FieldElem) Inverse(h Elem) Elem {
	g.value.Mul(h.(*FieldElem).value, big.NewInt(-1))
	return g
}

//Cmp compares two FieldElems (equal?)
func (*FieldElem) Cmp(a, b Elem) bool {
	return a.(*FieldElem).value.Cmp(b.(*FieldElem).value) == 0
}

//Neutral sets value of this Elem to neutral value of group
func (g *FieldElem) Neutral() Elem {
	g.value.SetInt64(0)
	return g
}

// MarshalBinary encodes Elem as bytes
func (g FieldElem) MarshalBinary() ([]byte, error) {
	return g.value.Bytes(), nil
}

// UnmarshalBinary decodes Elem from bytes
func (g *FieldElem) UnmarshalBinary(b []byte) error {
	if g.value == nil {
		g.value = big.NewInt(0)
	}
	g.value.SetBytes(b)

	return nil
}
