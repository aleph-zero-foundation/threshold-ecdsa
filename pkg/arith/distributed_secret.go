package arith

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/gob"
	"fmt"
	"math/big"
	"time"

	"gitlab.com/alephledger/threshold-ecdsa/pkg/crypto/commitment"
	"gitlab.com/alephledger/threshold-ecdsa/pkg/crypto/zkpok"
	"gitlab.com/alephledger/threshold-ecdsa/pkg/sync"
)

// DSecret is a distributed secret
type DSecret interface {
	Label() string
	Reveal() (*big.Int, error)
	Exp() (DKey, error)
}

// ADSecret is an arithmetic distirbuted secret
type ADSecret interface {
	DSecret
	Reshare(uint16) (TDSecret, error)
}

// TDSecret is a thresholded distributed secret
type TDSecret interface {
	DSecret
	Threshold() uint16
}

type dsecret struct {
	label  string
	secret *big.Int
	server sync.Server
}

func (ds *dsecret) Label() string {
	return ds.label
}

func (ds *dsecret) Reveal() (*big.Int, error) {
	return nil, nil
}

func (ds *dsecret) Exp() (DKey, error) {
	return nil, nil
}

type adsecret struct {
	dsecret
	r   *big.Int
	egf commitment.ElGamalFactory
	eg  *commitment.ElGamal
	egs []*commitment.ElGamal
}

type tdsecret struct {
	adsecret
	t uint16
}

func (tds tdsecret) Threshold() uint16 {
	return tds.t
}

// Gen generates a new distributed key with given label
func Gen(label string, server sync.Server, egf *commitment.ElGamalFactory, start time.Time) (ADSecret, error) {
	var err error
	// create a secret
	ads := &adsecret{dsecret: dsecret{label: label, server: server}, egf: egf}
	if ads.secret, err = rand.Int(randReader, Q); err != nil {
		return nil, err
	}
	if ads.r, err = rand.Int(randReader, Q); err != nil {
		return nil, err
	}

	// create a commitment and a zkpok
	ads.eg = egf.Create(ads.secret, ads.r)
	// TODO: replace with a proper zkpok when it's ready
	zkp := zkpok.NoopZKproof{}

	toSendBuf := bytes.Buffer{}
	enc := gob.NewEncoder(&toSendBuf)
	if err := enc.Encode(ads.eg); err != nil {
		return nil, err
	}
	if err := enc.Encode(zkp); err != nil {
		return nil, err
	}

	// TODO: reimplement after ZKPs are implemented
	check := func(_ uint16, data []byte) error {
		var (
			eg  commitment.ElGamal
			zkp zkpok.NoopZKproof
		)
		buf := bytes.NewBuffer(data)
		dec := gob.NewDecoder(buf)
		if err := dec.Decode(&eg); err != nil {
			return fmt.Errorf("decode: eg %v", err)
		}
		if err := dec.Decode(&zkp); err != nil {
			return fmt.Errorf("decode: zkp %v", err)
		}
		if !zkp.Verify() {
			return fmt.Errorf("Wrong proof")
		}
		return nil
	}

	data, _, err := ads.server.Round(toSendBuf.Bytes(), check, start, 0)
	if err != nil {
		return nil, err
	}

	ads.egs = make([]*commitment.ElGamal, len(data))
	buf := &bytes.Buffer{}
	dec := gob.NewDecoder(buf)
	for i := range data {
		if data[i] == nil {
			continue
		}
		ads.egs[i] = &commitment.ElGamal{}
		buf.Reset()
		if _, err := buf.Write(data[i]); err != nil {
			return nil, err
		}
		if err := dec.Decode(ads.egs[i]); err != nil {
			return nil, fmt.Errorf("decode: egs %v", err)
		}
	}

	return ads, nil
}

func poly(t uint16, a0 *big.Int) ([]*big.Int, error) {
	var err error
	f := make([]*big.Int, t)
	for i := range f {
		if i == 0 {
			f[i] = a0
			continue
		}
		if i == int(t)-1 {
			tmp := big.NewInt(1)
			tmp.Sub(Q, tmp)
			if f[i], err = rand.Int(randReader, tmp); err != nil {
				return nil, err
			}
			tmp.SetInt64(1)
			f[i].Add(f[i], tmp)

		}
		if f[i], err = rand.Int(randReader, Q); err != nil {
			return nil, err
		}
	}
	return f, nil
}

func polyEval(f []*big.Int, x *big.Int) *big.Int {
	// TODO: implement
	return nil
}
