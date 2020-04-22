package curve

import "math/big"

// Point is an element of a group on an elliptic curve
type Point interface {
}

// Group is a group formed on an elliptic curve
type Group interface {
	Order() *big.Int
	Gen() Point
	Add(Point, Point) Point
	Neutral() Point
	ScalarMult(Point, *big.Int) Point
	ScalarBaseMult(Point, *big.Int) Point
	Marshal(Point) []byte
	Unmarshal([]byte) (Point, error)
}
