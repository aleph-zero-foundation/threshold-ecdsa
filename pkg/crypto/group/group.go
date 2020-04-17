package group

import "math/big"

//Gen Simplest generator of group
var Gen = groupElem{
	value: big.NewInt(1),
}

//Elem element of group
type Elem interface {
	Add(Elem, Elem) Elem
	Mult(Elem, *big.Int) Elem
	Inverse(Elem) Elem
	Cmp(Elem, Elem) bool
	Neutral() Elem
	Marshal() []byte
	Unmarshal([]byte) Elem
}

type groupElem struct {
	value *big.Int
}

//NewElem creates new instance of Elem based on given value
func NewElem(value *big.Int) Elem {
	return groupElem{value}
}

//Add performs based operation between two Elems
func (g groupElem) Add(a, b Elem) Elem {
	g.value.Add(a.(groupElem).value, b.(groupElem).value)
	return g
}

//Mult performs exp operation on given Elem and value
func (g groupElem) Mult(h Elem, x *big.Int) Elem {
	g.value.Mul(h.(groupElem).value, x)
	return g
}

//Inverse returns inversed element for given Elem
func (g groupElem) Inverse(h Elem) Elem {
	g.value.Mul(h.(groupElem).value, big.NewInt(-1))
	return g
}

//Cmp compares two groupElems (equal?)
func (groupElem) Cmp(a, b Elem) bool {
	return a.(groupElem).value.Cmp(b.(groupElem).value) == 0
}

//Neutral sets value of this Elem to neutral value of group
func (g groupElem) Neutral() Elem {
	g.value.SetInt64(0)
	return g
}

//Marshal marshals Elem
func (g groupElem) Marshal() []byte {
	return g.value.Bytes()
}

//Marshal unmarshals Elem
func (g groupElem) Unmarshal(b []byte) Elem {
	g.value.SetBytes(b)
	return g
}
