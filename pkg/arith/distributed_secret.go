package arith

import (
	"bytes"
	"crypto/rand"
	"encoding/gob"
	"fmt"
	"math/big"

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
	egf *commitment.ElGamalFactory
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
func Gen(label string, server sync.Server, egf *commitment.ElGamalFactory, nProc uint16) (ADSecret, error) {
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
	ads.egs = make([]*commitment.ElGamal, nProc)
	check := func(pid uint16, data []byte) error {
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
		ads.egs[pid] = &eg

		return nil
	}

	err = ads.server.Round([][]byte{toSendBuf.Bytes()}, check)
	if err != nil {
		return nil, err
	}

	return ads, nil
}
