package arith

import (
	"bytes"
	"crypto/rand"
	"encoding/gob"
	"fmt"

	"gitlab.com/alephledger/threshold-ecdsa/pkg/crypto/zkpok"
	"gitlab.com/alephledger/threshold-ecdsa/pkg/curve"
	"gitlab.com/alephledger/threshold-ecdsa/pkg/sync"
)

// DKey is a distirbuted key
type DKey interface {
	Label() string
	RevealExp() (curve.Point, error)
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
	pk     curve.Point
	pks    []curve.Point
}

func (dk *dkey) Label() string {
	return dk.secret.Label()
}

func (dk *dkey) RevealExp() (curve.Point, error) {
	return nil, nil
}

type adkey struct {
	secret adsecret
}

// NMCtmp is a temporary placeholder
type NMCtmp struct {
	DataBytes, ZkpBytes []byte
}

// Verify tests if ncm is a commitment to given args
func (nmc *NMCtmp) Verify(dataBytes, zkpBytes []byte) error {
	if !bytes.Equal(nmc.DataBytes, dataBytes) {
		return fmt.Errorf("wrong data bytes")
	}
	if !bytes.Equal(nmc.ZkpBytes, zkpBytes) {
		return fmt.Errorf("wrong proof bytes")
	}

	return nil
}

// GenExpReveal is a method for generating a new distirbuted key
func GenExpReveal(label string, server sync.Server, nProc uint16, group curve.Group) (DKey, error) {
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

	dkey.pk = group.ScalarBaseMult(dsecret.secret)

	// Round 1: commmit to (g^{a_k}, pi_k)
	// TODO: replace with a proper zkpok and nmc when it's ready
	dataBytes := group.Marshal(dkey.pk)

	zkp := zkpok.NoopZKproof{}
	zkpBytes, err := zkp.MarshalBinary()
	if err != nil {
		return nil, err
	}
	nmc := &NMCtmp{dataBytes, zkpBytes}

	toSend := bytes.Buffer{}
	enc := gob.NewEncoder(&toSend)
	if err := enc.Encode(nmc); err != nil {
		return nil, err
	}

	// TODO: sth we can check here?
	nmcs := make([]*NMCtmp, nProc)
	check := func(pid uint16, data []byte) error {

		nmcs[pid] = &NMCtmp{}
		dec := gob.NewDecoder(bytes.NewBuffer(data))
		if err := dec.Decode(nmcs); err != nil {
			return err
		}
		return nil
	}

	err = server.Round([][]byte{toSend.Bytes()}, check)
	if err != nil {
		return nil, err
	}

	// Round 2: decommit to (g^{a_k}, pi_k)
	zkp = zkpok.NoopZKproof{}
	toSend.Reset()
	if err := enc.Encode(zkp); err != nil {
		return nil, err
	}
	if err := enc.Encode(dkey.pk); err != nil {
		return nil, err
	}

	dkey.pks = make([]curve.Point, nProc)
	check = func(pid uint16, data []byte) error {
		buf := bytes.NewBuffer(data)
		dec := gob.NewDecoder(buf)

		zkp := &zkpok.NoopZKproof{}
		if err := dec.Decode(zkp); err != nil {
			return err
		}

		cpBuf := bytes.Buffer{}
		if _, err := buf.WriteTo(&cpBuf); err != nil {
			return err
		}
		cp, err := group.Unmarshal(cpBuf.Bytes())
		if err != nil {
			return err
		}

		if !zkp.Verify() {
			return fmt.Errorf("Wrong proof")
		}

		dkey.pks[pid] = cp

		zkpBytesLen := len(data) - len(cpBuf.Bytes())
		if err := nmcs[pid].Verify(cpBuf.Bytes(), data[:zkpBytesLen]); err != nil {
			return err
		}

		return nil
	}

	err = server.Round([][]byte{toSend.Bytes()}, check)
	if err != nil {
		return nil, err
	}

	// TODO: form global public key

	return dkey, nil
}
