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
type DSecret struct {
	label   string
	skShare *big.Int
	server  sync.Server
}

// Label returns the name of the variable
func (ds *DSecret) Label() string {
	return ds.label
}

// Reveal returns the secret kept in this variable
func (ds *DSecret) Reveal() (*big.Int, error) {
	return nil, nil
}

// Exp computes a common public key and its share related to this secret
func (ds *DSecret) Exp() (*DKey, error) {
	return nil, nil
}

// ADSecret is an arithmetic distirbuted secret
type ADSecret struct {
	DSecret
	r   *big.Int
	egf *commitment.ElGamalFactory
	eg  *commitment.ElGamal
	egs []*commitment.ElGamal
}

// TDSecret is a thresholded distributed secret
type TDSecret struct {
	ADSecret
	t uint16
}

// Threshold returns the number of parties that must collude to reveal the secret
func (tds TDSecret) Threshold() uint16 {
	return tds.t
}

// Gen generates a new distributed key with given label
func Gen(label string, server sync.Server, egf *commitment.ElGamalFactory, nProc uint16) (*ADSecret, error) {
	var err error
	// create a secret
	ads := &ADSecret{DSecret: DSecret{label: label, server: server}, egf: egf}
	if ads.skShare, err = rand.Int(randReader, Q); err != nil {
		return nil, err
	}
	if ads.r, err = rand.Int(randReader, Q); err != nil {
		return nil, err
	}

	// create a commitment and a zkpok
	ads.eg = egf.Create(ads.skShare, ads.r)
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
