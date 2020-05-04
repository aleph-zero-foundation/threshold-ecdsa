package curve

import (
	"encoding/binary"
	"fmt"
	"io"
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
	pow   *big.Int
}

// NewSecp256k1Group returns the impelementation of the group interface with the secp256k1 elliptic curve
func NewSecp256k1Group() Group {
	cur := secp256k1.S256()
	return &sGroup{cur, new(big.Int).Sub(cur.N, big.NewInt(1))}
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
			resultX = new(big.Int).Set(bs.x)
			resultY = new(big.Int).Set(bs.y)
		}
	} else if bs.x == nil && bs.y == nil {
		resultX = new(big.Int).Set(as.x)
		resultY = new(big.Int).Set(as.y)
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
	return g.ScalarMult(a, g.pow)
}

//scale has to be a nonnegative integer
func (g sGroup) ScalarMult(a Point, scale *big.Int) Point {
	if len(scale.Bytes()) > 32 {
		scale.Mod(scale, g.Order())
	}
	resultX, resultY := g.curve.ScalarMult(a.(sPoint).x, a.(sPoint).y, scale.Bytes())
	return sPoint{resultX, resultY}
}

//scale has to be a nonnegative integer
func (g sGroup) ScalarBaseMult(scale *big.Int) Point {
	if len(scale.Bytes()) > 32 {
		scale.Mod(scale, g.Order())
	}
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

func (g sGroup) Encode(a Point, w io.Writer) error {
	buf := make([]byte, 4)
	as := a.(sPoint)
	// encoding of a neutral element is [0 0 0 0]
	if as.x == nil {
		binary.BigEndian.PutUint32(buf, uint32(0))
		if _, err := w.Write(buf); err != nil {
			return err
		}
		return nil
	}
	lenX := uint32(len(as.x.Bytes()))
	lenY := uint32(len(as.y.Bytes()))
	buf = make([]byte, 8, 8+lenX+lenY)
	binary.BigEndian.PutUint32(buf[:4], lenX)
	binary.BigEndian.PutUint32(buf[4:8], lenY)
	buf = append(buf, as.x.Bytes()...)
	buf = append(buf, as.y.Bytes()...)

	if _, err := w.Write(buf); err != nil {
		return err
	}

	return nil
}

func (g sGroup) Decode(r io.Reader) (Point, error) {
	lenBytes := make([]byte, 8)
	n, err := r.Read(lenBytes)
	if err != nil {
		return nil, err
	}
	if n < 8 {
		return nil, fmt.Errorf("Too few bytes for lenX and lenY: expected 8, got %d", n)
	}

	lenX := binary.BigEndian.Uint32(lenBytes[:4])
	if lenX == 0 {
		return sPoint{nil, nil}, nil
	}

	lenY := binary.BigEndian.Uint32(lenBytes[4:8])
	xyBytes := make([]byte, lenX+lenY)
	n, err = r.Read(xyBytes)
	if err != nil {
		return nil, err
	}
	if uint32(n) < lenX+lenY {
		return nil, fmt.Errorf("Too few bytes for lenX and lenY: expected %d, got %d", lenX+lenY, n)
	}
	x := new(big.Int).SetBytes(xyBytes[:lenX])
	y := new(big.Int).SetBytes(xyBytes[lenX:])

	return sPoint{x, y}, nil
}
