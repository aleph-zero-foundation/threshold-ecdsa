package curve

import (
	"encoding/binary"
	"math/big"

	"github.com/ethereum/go-ethereum/crypto/secp256k1"
)

// secpP implements the Point interface
type sPoint struct {
	x, y *big.Int
}

// sGroup implements the Group interface
type sGroup struct {
	curve *secp256k1.BitCurve
}

// NewSecp256k1Group returns the impelementation of the group interface with the secp256k1 elliptic curve
func NewSecp256k1Group() Group {
	return &sGroup{secp256k1.S256()}
}

func (g sGroup) Order() *big.Int {
	return g.curve.N
}

func (g sGroup) Gen() Point {
	return sPoint{g.curve.Gx, g.curve.Gy}
}

func (g sGroup) Add(a Point, b Point) Point {
	var resultX, resultY *big.Int
	as := a.(sPoint)
	bs := b.(sPoint)

	if as.x == nil && as.y == nil {
		if bs.x == nil && bs.y == nil {
			resultX = nil
			resultY = nil
		} else {
			//Using Add to create copy of value, since there is no such function
			resultX = big.NewInt(0).Add(bs.x, big.NewInt(0))
			resultY = big.NewInt(0).Add(bs.y, big.NewInt(0))
		}
	} else if bs.x == nil && bs.y == nil {
		resultX = big.NewInt(0).Add(as.x, big.NewInt(0))
		resultY = big.NewInt(0).Add(as.y, big.NewInt(0))
	} else if (as.x.Cmp(bs.x) == 0) && (as.y.Cmp(bs.y) == 0) {
		resultX, resultY = g.curve.Double(as.x, as.y)
	} else {
		resultX, resultY = g.curve.Add(as.x, as.y, bs.x, bs.y)
	}

	return sPoint{resultX, resultY}
}

func (g sGroup) Neutral() Point {
	return sPoint{nil, nil}
}

func (g sGroup) Neg(a Point) Point {
	return g.ScalarMult(a, big.NewInt(0).Sub(g.curve.N, big.NewInt(1)))
}

func (g sGroup) ScalarMult(a Point, scale *big.Int) Point {
	resultX, resultY := g.curve.ScalarMult(a.(sPoint).x, a.(sPoint).y, scale.Bytes())
	return sPoint{resultX, resultY}
}

func (g sGroup) ScalarBaseMult(scale *big.Int) Point {
	resultX, resultY := g.curve.ScalarBaseMult(scale.Bytes())
	return sPoint{resultX, resultY}
}

func (g sGroup) Equal(a Point, b Point) bool {
	as := a.(sPoint)
	bs := b.(sPoint)
	if as.x == nil && as.y == nil && bs.x == nil && bs.y == nil {
		return true
	} else if (as.x == nil && as.y == nil) || (bs.x == nil && bs.y == nil) {
		return false
	}
	return (as.x.Cmp(bs.x) == 0) && (as.y.Cmp(bs.y) == 0)
}

func (g sGroup) Marshal(a Point) []byte {
	arr := make([]byte, 4)
	binary.BigEndian.PutUint32(arr, uint32(len(a.(sPoint).x.Bytes())))

	arr = append(arr, a.(sPoint).x.Bytes()...)
	arr = append(arr, a.(sPoint).y.Bytes()...)

	return arr
}

func (g sGroup) Unmarshal(b []byte) (Point, error) {
	length := binary.BigEndian.Uint32(b[0:4])
	resultX := big.NewInt(0).SetBytes(b[4 : 4+length])
	resultY := big.NewInt(0).SetBytes(b[4+length : len(b)])
	return sPoint{resultX, resultY}, nil
}
