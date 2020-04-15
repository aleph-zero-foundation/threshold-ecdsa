package pkg

import (
	"crypto/rand"
	"math/big"
	"time"

	"./crypto/commitment"
	"./group"
	"./sync"
)

// Elem is an element in a group
type Elem interface{}

// DKey is a distirbuted key
type DKey interface {
	Label() string
	RevealExp() (Elem, error)
}

// ADKey is an arithmetic distirbuted key
type ADKey interface {
	DKey
	Reshare(uint16) (TDKey, error)
}

// TDKey is a thresholded distirbuted key
type TDKey interface {
	DKey
	Threshold() uint16
}

func GenExpReveal(label string, server sync.Server) (DKey, error) {
	dsecret := &dsecret{
		label:  label,
		secret: rand.Int(randReader, q),
		server: server,
	}
	dkey := &dkey{dsecret}

	dkey.pk = group.NewElem(dsecret.secret)

	// Round 1: commmit to (g^{a_k}, pi_k)
	zkp := []byte("comm: R_DLog")
	// TODO: use non-malleable commitments
	NMC := dkey.pk
	toSend := append(zkp, NMC.Marshal())

	// TODO: sth we can check here?
	check := func(data []byte) error { return nil }

	data, _, err = server.Round(toSend, check)
	if err != nil {
		return nil, err
	}
	nmcs := make([][]byte, len(data))
	for i := range data {
		// TODO: unmarshal nmc
		nmcs[i] = data[i]
	}

	// Round 2: decommit to (g^{a_k}, pi_k)
	zkp = []byte("R_DLog")
	toSend = append(zkp, dkey.pk.Marshal()...)

	check = func(data []byte) error {
		// TODO: use commitments from round 1

		if len(data) < len(zkp)+2 {
			return fmt.Errorf("received too short data %d", len(data))
		}

		// TODO: check zkp
		return data == zkp
	}

	data, _, err = server.Round(toSend, check)
	if err != nil {
		return nil, err
	}

	dkey.pks = make([]group.Elem, len(data))
	for i := range data {
		dkey.pks[i] = group.Elem{}.Unmarshal(data[i])
	}

	// TODO: form global public key

	return dkey, nil
}

type dkey struct {
	secret *dsecret
	pk     group.Elem
	pks    []group.Elem
}

func (dk *dkey) Label() string {
	return dk.secret.Label()
}

func (dk *dkey) RevealExp() (Elem, error) {
	return nil, nil
}

type adkey struct {
	secret adsecret
}
