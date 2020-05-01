package arith

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"

	"gitlab.com/alephledger/threshold-ecdsa/pkg/crypto/zkpok"
	"gitlab.com/alephledger/threshold-ecdsa/pkg/curve"
	"gitlab.com/alephledger/threshold-ecdsa/pkg/sync"
)

// DKey is a distirbuted key
type DKey struct {
	secret   *DSecret
	pk       curve.Point
	pkShare  curve.Point
	pkShares []curve.Point
}

// NewDKey returns a pointer to new DKey instance
func NewDKey(secret *DSecret, pkShare curve.Point, pkShares []curve.Point, group curve.Group) *DKey {
	pk := pkShare
	for _, pkOtherShare := range pkShares {
		if pkOtherShare != nil {
			pk = group.Add(pk, pkOtherShare)
		}
	}

	return &DKey{
		secret:   secret,
		pk:       pk,
		pkShare:  pkShare,
		pkShares: pkShares,
	}
}

// Label returns the name of the variable
func (dk *DKey) Label() string {
	return dk.secret.Label()
}

// PublicKey returns global public key
func (dk *DKey) PublicKey() curve.Point {
	return dk.pk
}

// TDKey is a thresholded distirbuted key
type TDKey struct {
	DKey
	secret *TDSecret
}

// Threshold returns the number of parties that must collude to reveal the secret
func (tdk TDKey) Threshold() uint16 {
	return tdk.secret.t
}

// NMCtmp is a temporary placeholder
type NMCtmp struct {
	dataBytes, zkpBytes []byte
}

func (nmc *NMCtmp) encode(w io.Writer) error {
	lenBytes := make([]byte, 8)
	binary.LittleEndian.PutUint32(lenBytes[:4], uint32(len(nmc.dataBytes)))
	binary.LittleEndian.PutUint32(lenBytes[4:8], uint32(len(nmc.zkpBytes)))
	if _, err := w.Write(lenBytes); err != nil {
		return err
	}
	if _, err := w.Write(nmc.dataBytes); err != nil {
		return err
	}
	if _, err := w.Write(nmc.zkpBytes); err != nil {
		return err
	}
	return nil
}

func (nmc *NMCtmp) decode(r io.Reader) error {
	lenBytes := make([]byte, 8)
	n, err := r.Read(lenBytes)
	if err != nil {
		return err
	}
	if n < 8 {
		return fmt.Errorf("nmc wrong number of bytes in decode")
	}

	lenData := int(binary.LittleEndian.Uint32(lenBytes[:4]))
	nmc.dataBytes = make([]byte, lenData)
	n, err = r.Read(nmc.dataBytes)
	if err != nil {
		return err
	}
	if n < lenData {
		return fmt.Errorf("nmc wrong number of dataBytes in decode")
	}

	lenZkp := int(binary.LittleEndian.Uint32(lenBytes[4:8]))
	nmc.zkpBytes = make([]byte, lenZkp)
	n, err = r.Read(nmc.zkpBytes)
	if err != nil {
		return err
	}
	if n < lenZkp {
		return fmt.Errorf("nmc wrong number of zkpBytes in decode")
	}

	return nil

}

// Verify tests if ncm is a commitment to given args
func (nmc *NMCtmp) Verify(dataBytes, zkpBytes []byte) error {
	if !bytes.Equal(nmc.dataBytes, dataBytes) {
		return fmt.Errorf("wrong data bytes")
	}
	if !bytes.Equal(nmc.zkpBytes, zkpBytes) {
		return fmt.Errorf("wrong proof bytes")
	}

	return nil
}

// GenExpReveal is a method for generating a new distirbuted key
func GenExpReveal(label string, server sync.Server, nProc uint16, group curve.Group) (*DKey, error) {
	// generate a secret key share
	skShare, err := rand.Int(randReader, Q)
	if err != nil {
		return nil, err
	}
	dSecret := NewDSecret(label, skShare, server)
	pkShare := group.ScalarBaseMult(dSecret.skShare)

	// Round 1: commmit to (g^{a_k}, pi_k)
	// TODO: replace with a proper zkpok and nmc when it's ready, now it sends just the values
	toSendBuf := &bytes.Buffer{}
	if err = group.Encode(pkShare, toSendBuf); err != nil {
		return nil, err
	}
	dataBytes := make([]byte, len(toSendBuf.Bytes()))
	copy(dataBytes, toSendBuf.Bytes())

	zkp := zkpok.NoopZKproof{}
	if err = zkp.Encode(toSendBuf); err != nil {
		return nil, err
	}
	zkpBytes := toSendBuf.Bytes()[len(dataBytes):]

	nmc := &NMCtmp{dataBytes, zkpBytes}
	toSendBuf.Reset()
	if err = nmc.encode(toSendBuf); err != nil {
		return nil, err
	}

	// TODO: sth we can check here?
	nmcs := make([]*NMCtmp, nProc)
	check := func(pid uint16, data []byte) error {
		buf := bytes.NewBuffer(data)
		nmcs[pid] = &NMCtmp{}
		if err := nmcs[pid].decode(buf); err != nil {
			return err
		}

		return nil
	}

	err = server.Round([][]byte{toSendBuf.Bytes()}, check)
	if err != nil {
		return nil, err
	}

	// Round 2: decommit to (g^{a_k}, pi_k)
	toSendBuf.Reset()
	if err = group.Encode(pkShare, toSendBuf); err != nil {
		return nil, err
	}
	if err = zkp.Encode(toSendBuf); err != nil {
		return nil, err
	}

	pkShares := make([]curve.Point, nProc)
	check = func(pid uint16, data []byte) error {
		buf := bytes.NewBuffer(data)
		cp, err := group.Decode(buf)
		if err != nil {
			return err
		}
		var zkp zkpok.NoopZKproof
		if err = zkp.Decode(buf); err != nil {
			return err
		}
		if !zkp.Verify() {
			return fmt.Errorf("Wrong proof")
		}

		if err := nmcs[pid].Verify(data, []byte{}); err != nil {
			return err
		}

		pkShares[pid] = cp

		return nil
	}

	err = server.Round([][]byte{toSendBuf.Bytes()}, check)
	if err != nil {
		return nil, err
	}

	return NewDKey(dSecret, pkShare, pkShares, group), nil
}
