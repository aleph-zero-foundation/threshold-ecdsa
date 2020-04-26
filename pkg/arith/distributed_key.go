package arith

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/gob"
	"fmt"

	"gitlab.com/alephledger/threshold-ecdsa/pkg/crypto/zkpok"
	"gitlab.com/alephledger/threshold-ecdsa/pkg/curve"
	"gitlab.com/alephledger/threshold-ecdsa/pkg/sync"
)

// DKey is a distirbuted key
type DKey struct {
	secret *DSecret
	pk     curve.Point
	pks    []curve.Point
}

// Label returns the name of the variable
func (dk *DKey) Label() string {
	return dk.secret.Label()
}

// RevealExp computes the common public key which share is kept in this key
func (dk *DKey) RevealExp() (curve.Point, error) {
	return nil, nil
}

// ADKey is an arithmetic distirbuted key
type ADKey struct {
	secret ADSecret
}

// TDKey is a thresholded distirbuted key
type TDKey struct {
	ADKey
	t uint16
}

// Threshold returns the number of parties that must collude to reveal the secret
func (tdk TDKey) Threshold() uint16 {
	return tdk.t
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
func GenExpReveal(label string, server sync.Server, nProc uint16, group curve.Group) (*DKey, error) {
	// generate a secret
	secret, err := rand.Int(randReader, Q)
	if err != nil {
		return nil, err
	}
	DSecret := &DSecret{
		label:  label,
		secret: secret,
		server: server,
	}
	DKey := &DKey{secret: DSecret}

	DKey.pk = group.ScalarBaseMult(DSecret.secret)

	// Round 1: commmit to (g^{a_k}, pi_k)
	// TODO: replace with a proper zkpok and nmc when it's ready
	dataBytes := group.Marshal(DKey.pk)

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

		var nmc NMCtmp
		dec := gob.NewDecoder(bytes.NewBuffer(data))
		if err := dec.Decode(&nmc); err != nil {
			return err
		}
		nmcs[pid] = &nmc
		return nil
	}

	err = server.Round([][]byte{toSend.Bytes()}, check)
	if err != nil {
		return nil, err
	}

	// Round 2: decommit to (g^{a_k}, pi_k)
	toSend.Reset()
	zkp = zkpok.NoopZKproof{}
	zkpBytes, _ = zkp.MarshalBinary()
	buf := make([]byte, 2+len(zkpBytes))
	binary.LittleEndian.PutUint16(buf[:2], uint16(len(zkpBytes)))
	copy(buf[2:], zkpBytes)

	if _, err = toSend.Write(buf); err != nil {
		return nil, err
	}
	if _, err = toSend.Write(group.Marshal(DKey.pk)); err != nil {
		return nil, err
	}

	DKey.pks = make([]curve.Point, nProc)
	check = func(pid uint16, data []byte) error {
		zkpBytesLen := binary.LittleEndian.Uint16(data[:2])
		zkp := &zkpok.NoopZKproof{}
		zkp.UnmarshalBinary(data[2 : 2+zkpBytesLen])

		cp, err := group.Unmarshal(data[2+zkpBytesLen:])
		if err != nil {
			return err
		}

		if !zkp.Verify() {
			return fmt.Errorf("Wrong proof")
		}

		if err := nmcs[pid].Verify(data[2+zkpBytesLen:], data[2:2+zkpBytesLen]); err != nil {
			return err
		}

		DKey.pks[pid] = cp

		return nil
	}

	err = server.Round([][]byte{toSend.Bytes()}, check)
	if err != nil {
		return nil, err
	}

	// TODO: form global public key

	return DKey, nil
}
