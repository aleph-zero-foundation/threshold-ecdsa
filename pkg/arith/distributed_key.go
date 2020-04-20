package arith

import (
	"bytes"
	"crypto/rand"
	"encoding/gob"
	"fmt"
	"time"

	"gitlab.com/alephledger/threshold-ecdsa/pkg/crypto/zkpok"
	"gitlab.com/alephledger/threshold-ecdsa/pkg/group"
	"gitlab.com/alephledger/threshold-ecdsa/pkg/sync"
)

// DKey is a distirbuted key
type DKey interface {
	Label() string
	RevealExp() (group.Elem, error)
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

type dkey struct {
	secret *dsecret
	pk     *group.CurvePoint
	pks    []*group.CurvePoint
}

func (dk *dkey) Label() string {
	return dk.secret.Label()
}

func (dk *dkey) RevealExp() (group.Elem, error) {
	return nil, nil
}

type adkey struct {
	secret adsecret
}

// NMCtmp is a temporary placeholder
type NMCtmp struct {
	CpBytes, ZkpBytes []byte
}

// Verify tests if ncm is a commitment to given args
func (nmc *NMCtmp) Verify(cp *group.CurvePoint, zkp zkpok.ZKproof) error {
	zkpBytes, err := zkp.MarshalBinary()
	if err != nil {
		return err
	}
	if !bytes.Equal(nmc.ZkpBytes, zkpBytes) {
		return fmt.Errorf("wrong proof")
	}
	cpBytes, err := cp.MarshalBinary()
	if err != nil {
		return err
	}
	if !bytes.Equal(nmc.CpBytes, cpBytes) {
		return fmt.Errorf("wrong curve point")
	}

	return nil
}

// GenExpReveal is a method for generating a new distirbuted key
func GenExpReveal(label string, server sync.Server, start time.Time) (DKey, error) {
	// generate a secret
	secret, err := rand.Int(randReader, Q)
	if err != nil {
		return nil, err
	}
	dsecret := &dsecret{
		label:  label,
		secret: secret,
		server: server,
	}
	dkey := &dkey{secret: dsecret}

	dkey.pk = group.NewCurvePoint(dsecret.secret)

	// Round 1: commmit to (g^{a_k}, pi_k)
	// TODO: replace with a proper zkpok and nmc when it's ready
	cpBytes, err := dkey.pk.MarshalBinary()
	if err != nil {
		return nil, err
	}
	zkp := zkpok.NoopZKproof{}
	zkpBytes, err := zkp.MarshalBinary()
	if err != nil {
		return nil, err
	}
	nmc := &NMCtmp{cpBytes, zkpBytes}

	toSend := bytes.Buffer{}
	enc := gob.NewEncoder(&toSend)
	if err := enc.Encode(nmc); err != nil {
		return nil, err
	}

	// TODO: sth we can check here?
	check := func(_ uint16, _ []byte) error { return nil }

	data, _, err := server.Round(toSend.Bytes(), check, start, 0)
	if err != nil {
		return nil, err
	}
	nmcs := make([]*NMCtmp, len(data))
	for i := range data {
		if data[i] == nil {
			continue
		}
		nmcs[i] = &NMCtmp{}
		dec := gob.NewDecoder(bytes.NewBuffer(data[i]))
		if err := dec.Decode(nmcs[i]); err != nil {
			return nil, err
		}
	}

	// Round 2: decommit to (g^{a_k}, pi_k)
	zkp = zkpok.NoopZKproof{}
	toSend.Reset()
	if err := enc.Encode(dkey.pk); err != nil {
		return nil, err
	}
	if err := enc.Encode(zkp); err != nil {
		return nil, err
	}

	check = func(pid uint16, data []byte) error {
		dec := gob.NewDecoder(bytes.NewBuffer(data))
		cp := &group.CurvePoint{}
		if err := dec.Decode(cp); err != nil {
			return err
		}
		zkp := &zkpok.NoopZKproof{}
		if err := dec.Decode(zkp); err != nil {
			return err
		}

		if err := nmcs[pid].Verify(cp, zkp); err != nil {
			return err
		}

		if !zkp.Verify() {
			return fmt.Errorf("Wrong proof")
		}

		return nil
	}

	data, _, err = server.Round(toSend.Bytes(), check, start, 1)
	if err != nil {
		return nil, err
	}

	dkey.pks = make([]*group.CurvePoint, len(data))
	buf := &bytes.Buffer{}
	dec := gob.NewDecoder(buf)
	for i := range data {
		if data[i] == nil {
			continue
		}
		dkey.pks[i] = &group.CurvePoint{}
		buf.Reset()
		if _, err := buf.Write(data[i]); err != nil {
			return nil, err
		}
		if err := dec.Decode(dkey.pks[i]); err != nil {
			return nil, err
		}
	}

	// TODO: form global public key

	return dkey, nil
}
