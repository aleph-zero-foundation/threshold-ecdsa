package curve

import (
	"io"
	"math/big"
)

// Point is an element of a group on an elliptic curve
type Point interface {
}

// Group is a group formed on an elliptic curve
type Group interface {
	Order() *big.Int
	Gen() Point
	Add(Point, Point) Point
	Neutral() Point
	Neg(Point) Point
	ScalarMult(Point, *big.Int) Point
	ScalarBaseMult(*big.Int) Point
	Equal(Point, Point) bool
	Encode(Point, io.Writer) error
	Decode(io.Reader) (Point, error)
}
