package pkg

import (
	"bytes"
	"crypto/rand"
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

type adsecret struct {
	dsecret
	r   *big.Int
	eg  *commitment.ElGamal
	egs []*commitment.ElGamal
}

// Gen generates a new distributed key with given label
func Gen(label string, server sync.Server, egf commitment.ElGamalFactory) (ADSecret, error) {
	var err error
	// create a secret
	ads := &adsecret{dsecret: dsecret{label: label, server: server}}
	if ads.secret, err = rand.Int(randReader, q); err != nil {
		return nil, err
	}
	if ads.r, err = rand.Int(randReader, q); err != nil {
		return nil, err
	}

	// create a commitment and a zkpok
	ads.eg = egf.Create(a, r)
	// TODO: replace with a proper zkpok when it's ready
	zkp := zkpok.NoopZKproof{}

	toSend := bytes.Buffer{}
	enc := gob.NewEncoder(&toSend)
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
			zkp zkpop.NewNoopZKProof
		)
		buf := bytes.NewBuffer(data)
		dec := gob.NewDecoder(buf)
		if err := dec.Decode(&eg); err != nil {
			return err
		}
		if err := dec.Decode(&zkp); err != nil {
			return err
		}
		if !zkp.Verify() {
			return fmt.Errorf("Wrong proof")
		}
		return nil
	}

	data, _, err := ads.server.Round(toSend.Bytes(), check, time.Now())
	if err != nil {
		return nil, err
	}

	ads.egs = make([]*commitment.ElGamal, len(data))
	for i := range data {
		egMarsh := data[i][len(zkp):]
		ads.egs[i] = commitment.ElGamal{}.Unmarshal(egMarsh)
	}

	return nil
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
