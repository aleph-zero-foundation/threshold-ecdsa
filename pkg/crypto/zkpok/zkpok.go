package zkpok

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"

	"gitlab.com/alephledger/threshold-ecdsa/pkg/crypto"
	"gitlab.com/alephledger/threshold-ecdsa/pkg/crypto/commitment"
	"gitlab.com/alephledger/threshold-ecdsa/pkg/curve"
)

//ZKproof represents a zero-knowledge proof that may be verified
type ZKproof interface {
	Verify() bool
	Encode(w io.Writer) error
}

//ZKEGKnow implements proof of knowledge of ElGamal-committed value.
type ZKEGKnow struct {
	z1 *big.Int
	z2 *big.Int
	xy *commitment.ElGamal
}

//NewZKEGKnow creates ZKEGKnow proof of knowledge of witness (value, r) for commitment c
func NewZKEGKnow(fct *commitment.ElGamalFactory, comm *commitment.ElGamal, value, rnd *big.Int) (*ZKEGKnow, error) {
	order := fct.Curve().Order()
	sigma, _ := rand.Int(rand.Reader, order)
	rho, _ := rand.Int(rand.Reader, order)

	//e is the randomly produced challenge, here hash by Fiat-Shamir heuristic
	buf := &bytes.Buffer{}
	if err := comm.Encode(buf); err != nil {
		return nil, err
	}
	e := pkg.HashToBigInt(buf.Bytes())
	var z1, z2 big.Int

	d := fct.Neutral()
	d = d.Compose(fct.Create(rho, sigma), d.Exp(comm, e))
	z1.Add(sigma, z1.Mul(e, rnd))
	z2.Add(rho, z2.Mul(e, value))
	xy := fct.Create(rho, sigma)
	z1.Mod(&z1, order)
	z2.Mod(&z2, order)

	return &ZKEGKnow{
		z1: &z1,
		z2: &z2,
		xy: xy,
	}, nil
}

//Verify verifies proof z of knowledge of value and r for commitment c
func (z *ZKEGKnow) Verify(fct *commitment.ElGamalFactory, comm *commitment.ElGamal) error {
	d := fct.Neutral()
	buf := &bytes.Buffer{}
	if err := comm.Encode(buf); err != nil {
		return err
	}
	e := pkg.HashToBigInt(buf.Bytes())
	d = d.Compose(z.xy, d.Exp(comm, e))

	if !comm.Equal(d, fct.Create(z.z2, z.z1)) {
		return fmt.Errorf("verification failed")
	}

	return nil
}

//Encode encodes ZKEGKnow proof
func (z *ZKEGKnow) Encode(w io.Writer) error {
	z1Bytes := z.z1.Bytes()
	z2Bytes := z.z2.Bytes()
	buf := make([]byte, 8, 8+len(z1Bytes)+len(z2Bytes))
	binary.BigEndian.PutUint32(buf[0:4], uint32(len(z1Bytes)))
	binary.BigEndian.PutUint32(buf[4:8], uint32(len(z2Bytes)))

	buf = append(buf, z1Bytes...)
	buf = append(buf, z2Bytes...)

	if _, err := w.Write(buf); err != nil {
		return err
	}
	if err := z.xy.Encode(w); err != nil {
		return err
	}

	return nil
}

//Decode decodes ZKEGKnow proof
func (z *ZKEGKnow) Decode(r io.Reader) error {
	lenBytes := make([]byte, 8)
	n, err := r.Read(lenBytes)
	if err != nil {
		return err
	}
	if n < 8 {
		return fmt.Errorf("Too few bytes: expected 8, got %d", n)
	}

	z1Len := binary.BigEndian.Uint32(lenBytes[:4])
	z2Len := binary.BigEndian.Uint32(lenBytes[4:8])
	allBytes := make([]byte, z1Len+z2Len)

	n, err = r.Read(allBytes)
	if err != nil {
		return err
	}
	if uint32(n) < z1Len+z2Len {
		return fmt.Errorf("Too few bytes for payload: expected %d, got %d", z1Len+z2Len, n)
	}

	z.z1 = new(big.Int).SetBytes(allBytes[:z1Len])
	z.z2 = new(big.Int).SetBytes(allBytes[z1Len : z1Len+z2Len])
	z.xy = &commitment.ElGamal{}
	z.xy.Decode(r)

	return nil
}

//ZKEGRerand implements proof that a comitment c2 is a proper rerandomization of commitment c1
type ZKEGRerand struct {
	z1 big.Int
	z2 big.Int
	xy commitment.ElGamal
}

//NewZKEGRerand creates ZKEGRerand proof of knowledge
func NewZKEGRerand(fct *commitment.ElGamalFactory, c1, c2 *commitment.ElGamal, r, s *big.Int) *ZKEGRerand {
	return &ZKEGRerand{}
}

//Verify verifies ZKEGRerand proof
func (z *ZKEGRerand) Verify(fct *commitment.ElGamalFactory, c1, c2 *commitment.ElGamal) bool {
	return true
}

//Encode encodes  ZKEGRerand proof
func (z *ZKEGRerand) Encode(w io.Writer) error { return nil }

//Decode decodes ZKEGRerand proof
func (z *ZKEGRerand) Decode(r io.Reader) error { return nil }

//ZKEGExp implements proof that commitment c3 results from commitments c1 and c2.
//Specicically, if c2 is an ElGamal commitment to y with t as a randomizing element,
//then ZKEGExp proves that c3 is formed as c1^y*ElGamal(0,r).
type ZKEGExp struct {
	z1 big.Int
	z2 big.Int
	xy commitment.ElGamal
	w  curve.Point
}

//NewZKEGExp creates ZKEGExp proof of knowledge
func NewZKEGExp(fct *commitment.ElGamalFactory, c1, c2, c3 *commitment.ElGamal, t, r, y *big.Int) *ZKEGExp {
	return &ZKEGExp{}
}

//Verify verifies ZKEGExp proof
func (z *ZKEGExp) Verify(fct *commitment.ElGamalFactory, c1, c2, c3 *commitment.ElGamal) bool {
	return true
}

//Encode encodes ZKEGExp proof
func (z *ZKEGExp) Encode(w io.Writer) error { return nil }

//Decode decodes ZKEGExp proof
func (z *ZKEGExp) Decode(r io.Reader) error { return nil }

//ZKEGReveal implements proof that reveiled value is the same that was committed via ElGamal
type ZKEGReveal struct {
	z1 big.Int
	z2 big.Int
	xy commitment.ElGamal
}

//NewZKEGReveal creates ZKEGReveal proof of knowledge
func NewZKEGReveal(fct *commitment.ElGamalFactory, c *commitment.ElGamal, x, r *big.Int) *ZKEGReveal {
	return &ZKEGReveal{}
}

//Verify verifies ZKEGReveal proof
func (z *ZKEGReveal) Verify(fct *commitment.ElGamalFactory, c *commitment.ElGamal, x *big.Int) bool {
	return true
}

//Encode encodes ZKEGReveal proof
func (z *ZKEGReveal) Encode(w io.Writer) error { return nil }

//Decode decodes ZKEGReveal proof
func (z *ZKEGReveal) Decode(r io.Reader) error { return nil }

//ZKEGRefresh implements proof that a comitment c2 is a proper refreshment of commitment c2
type ZKEGRefresh struct {
	z1 *big.Int
	z2 *big.Int
	xy *commitment.ElGamal
}

//NewZKEGRefresh creates ZKEGRefresh proof of knowledge
func NewZKEGRefresh(fct *commitment.ElGamalFactory, c1, c2 *commitment.ElGamal, r *big.Int) (*ZKEGRefresh, error) {
	g := fct.Curve()
	sigma, _ := rand.Int(rand.Reader, g.Order())
	tau, _ := rand.Int(rand.Reader, g.Order())

	//e is the randomly produced challenge, here hash by Fiat-Shamir heuristic
	buf := &bytes.Buffer{}
	if err := c1.Encode(buf); err != nil {
		return nil, err
	}
	if err := c2.Encode(buf); err != nil {
		return nil, err
	}
	e := pkg.HashToBigInt(buf.Bytes())

	var z1 big.Int
	var z2 big.Int
	z1.Add(sigma, z1.Mul(e, r))
	z2.Add(tau, e)
	z1.Mod(&z1, fct.Curve().Order())
	z2.Mod(&z2, fct.Curve().Order())
	xy := fct.Neutral()
	xy.Compose(xy.Exp(c1, tau), fct.Create(big.NewInt(0), sigma))

	return &ZKEGRefresh{
		z1: &z1,
		z2: &z2,
		xy: xy,
	}, nil
}

//Verify verifies ZKEGRefresh proof
func (z *ZKEGRefresh) Verify(fct *commitment.ElGamalFactory, c1, c2 *commitment.ElGamal) error {
	buf := &bytes.Buffer{}
	if err := c1.Encode(buf); err != nil {
		return err
	}
	if err := c2.Encode(buf); err != nil {
		return err
	}
	e := pkg.HashToBigInt(buf.Bytes())

	d := fct.Neutral()
	dtmp := fct.Neutral()
	d.Compose(fct.Create(big.NewInt(0), z.z1), d.Exp(c1, z.z2))
	d.Compose(d, dtmp.Inverse(dtmp.Exp(c2, e)))

	if !c1.Equal(d, z.xy) {
		return fmt.Errorf("verification failed")
	}
	return nil
}

//Encode encodes ZKEGRefresh proof
func (z *ZKEGRefresh) Encode(w io.Writer) error {
	z1Bytes := z.z1.Bytes()
	z2Bytes := z.z2.Bytes()
	buf := make([]byte, 8, 8+len(z1Bytes)+len(z2Bytes))
	binary.BigEndian.PutUint32(buf[0:4], uint32(len(z1Bytes)))
	binary.BigEndian.PutUint32(buf[4:8], uint32(len(z2Bytes)))

	buf = append(buf, z1Bytes...)
	buf = append(buf, z2Bytes...)

	if _, err := w.Write(buf); err != nil {
		return err
	}
	if err := z.xy.Encode(w); err != nil {
		return err
	}

	return nil
}

//Decode decodes ZKEGRefresh proof
func (z *ZKEGRefresh) Decode(r io.Reader) error {
	lenBytes := make([]byte, 8)
	n, err := r.Read(lenBytes)
	if err != nil {
		return err
	}
	if n < 8 {
		return fmt.Errorf("Too few bytes: expected 8, got %d", n)
	}

	z1Len := binary.BigEndian.Uint32(lenBytes[:4])
	z2Len := binary.BigEndian.Uint32(lenBytes[4:8])
	allBytes := make([]byte, z1Len+z2Len)

	n, err = r.Read(allBytes)
	if err != nil {
		return err
	}
	if uint32(n) < z1Len+z2Len {
		return fmt.Errorf("Too few bytes for payload: expected %d, got %d", z1Len+z2Len, n)
	}
	z.z1 = new(big.Int).SetBytes(allBytes[:z1Len])
	z.z2 = new(big.Int).SetBytes(allBytes[z1Len : z1Len+z2Len])
	z.xy = &commitment.ElGamal{}
	z.xy.Decode(r)
	return nil
}

// ZKDLog implements proof of knowledge of discrete logarithm
type ZKDLog struct {
	z big.Int
	w curve.Point
}

//NewZKDLog creates ZKDLog proof of knowledge
func NewZKDLog(y *curve.Point, x *big.Int) *ZKDLog { return &ZKDLog{} }

//Verify verifies ZKDLog proof
func (z *ZKDLog) Verify(y *curve.Point) bool { return true }

//Encode encodes ZKDLog proof
func (z *ZKDLog) Encode(w io.Writer) error { return nil }

//Decode decodes ZKDLog proof
func (z *ZKDLog) Decode(r io.Reader) error { return nil }

// NoopZKproof is a trivial proof that always returns true
type NoopZKproof struct{}

// Verify implements a ZKproof.Verify method
func (NoopZKproof) Verify() bool { return true }

// Encode implements a method needed for encoding
func (NoopZKproof) Encode(w io.Writer) error { return nil }

// Decode implements a method needed for decoding
func (*NoopZKproof) Decode(r io.Reader) error { return nil }
