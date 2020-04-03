package crypto

import "math/big"

//G Simplest generator of group
var G = groupElem{
	value: big.NewInt(1),
}

//GroupElem element of group
type GroupElem interface {
	Operation(GroupElem, GroupElem) GroupElem
	Exp(GroupElem, *big.Int) GroupElem
	Inverse(GroupElem) GroupElem
	Cmp(GroupElem, GroupElem) bool
	Neutral() GroupElem
	Marshal() []byte
	Unmarshal([]byte) GroupElem
}

type groupElem struct {
	value *big.Int
}

//NewGroupElem Create new instance of GroupElem based on given value
func NewGroupElem(value *big.Int) GroupElem {
	return groupElem{value}
}

//Operation Perform based operation between two GroupElems
func (g groupElem) Operation(a, b GroupElem) GroupElem {
	(*g.value).Add(a.(groupElem).value, b.(groupElem).value)
	return g
}

//Exp Perform exp operation on given GroupElem and value
func (g groupElem) Exp(h GroupElem, x *big.Int) GroupElem {
	(*g.value).Mul(h.(groupElem).value, x)
	return g
}

//Inverse Return inversed element for given GroupElem
func (g groupElem) Inverse(h GroupElem) GroupElem {
	(*g.value).Mul(h.(groupElem).value, big.NewInt(-1))
	return g
}

//Cmp Compare two groupElems (equal?)
func (g groupElem) Cmp(a, b GroupElem) bool {
	return a.(groupElem).value.Cmp(b.(groupElem).value) == 0
}

//Neutral Set value of this GroupElem to neutral value of group
func (g groupElem) Neutral() GroupElem {
	g.value = big.NewInt(0)
	return g
}

//Marshal Marshal GroupElem
func (g groupElem) Marshal() []byte {
	return g.value.Bytes()
}

//Marshal Unmarshal GroupElem
func (g groupElem) Unmarshal(b []byte) GroupElem {
	g.value.SetBytes(b)
	return g
}
