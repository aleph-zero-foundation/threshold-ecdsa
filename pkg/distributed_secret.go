package pkg

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"time"

	"./crypto/commitment"
	"./sync"
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

// Gen generates a new distributed key with given label
func Gen(label string, server sync.Server, egf commitment.ElGamalFactory) (ADSecret, error) {
	ads := &adsecret{label: label, server: server}
	ads.secret = rand.Int(randReader, q)
	ads.r = rand.Int(randReader, q)

	ads.eg = egf.Create(a, r)
	zkp := []byte("R_EGKnow")
	toSend := append(zkp, ads.eg.Marshal()...)

	// TODO: reimplement after ZKPs are implemented
	check := func(data []byte) error {
		if len(data) < len(zkp)+2 {
			return fmt.Errorf("received too short data %d", len(data))
		}

		// TODO: check zkp
		return data == zkp
	}

	data, _, err := ads.server.Round(toSend, check)
	if err != nil {
		return nil, err
	}

	ads.egs = make([]commitment.ElGamal, len(data))
	for i := range data {
		egMarsh := data[i][len(zkp):]
		ads.egs[i] = commitment.ElGamal{}.Unmarshal(egMarsh)
	}

	return nil
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
	eg  commitment.ElGamal
	egs []commitment.ElGamal
}
