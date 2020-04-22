package curve

import (
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

// TODO: @Jedrzej Kula have fun :)
func (g sGroup) Order() *big.Int                          { return nil }
func (g sGroup) Gen() Point                               { return nil }
func (g sGroup) Add(_ Point, _ Point) Point               { return nil }
func (g sGroup) Neutral() Point                           { return nil }
func (g sGroup) ScalarMult(_ Point, _ *big.Int) Point     { return nil }
func (g sGroup) ScalarBaseMult(_ Point, _ *big.Int) Point { return nil }
func (g sGroup) Marshal(_ Point) []byte                   { return nil }
func (g sGroup) Unmarshal(_ []byte) (Point, error)        { return nil, nil }
