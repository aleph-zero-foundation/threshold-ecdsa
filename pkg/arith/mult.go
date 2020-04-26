package arith

import (
	"bytes"
	"crypto/rand"
	"encoding/gob"
	"fmt"
	"math/big"

	"gitlab.com/alephledger/threshold-ecdsa/pkg/crypto/commitment"
	"gitlab.com/alephledger/threshold-ecdsa/pkg/crypto/zkpok"
)

// Mult computes a multiplication of two arithmetic secrets
func Mult(a, b *ADSecret, cLabel string) (c *ADSecret, err error) {
	nProc := len(a.egs)

	c.label = cLabel
	c.server = a.server

	// Step 1. Compute a product of commitments to b
	bProd := b.egf.Neutral()
	for _, eg := range b.egs {
		bProd.Compose(bProd, eg)
	}

	// Step 2. Run priv mult and compute the share of c
	if c.secret, err = PrivMult(a.secret, b.secret); err != nil {
		return nil, err
	}

	// Step 3. Compute and publish an ElGamal commitment to the share of c
	if c.r, err = rand.Int(randReader, Q); err != nil {
		return nil, err
	}
	c.eg = a.egf.Create(c.secret, c.r)

	toSendBuf := bytes.Buffer{}
	enc := gob.NewEncoder(&toSendBuf)
	// TODO: replace the following commitment and check with EGKnow
	egknow := zkpok.NoopZKproof{}
	if err := enc.Encode(egknow); err != nil {
		return nil, err
	}
	if err := enc.Encode(c.eg); err != nil {
		return nil, err
	}

	c.egs = make([]*commitment.ElGamal, nProc)
	check := func(pid uint16, data []byte) error {
		var egknow zkpok.NoopZKproof
		buf := bytes.NewBuffer(data)
		dec := gob.NewDecoder(buf)
		if err := dec.Decode(&egknow); err != nil {
			return fmt.Errorf("decode: egknow %v", err)
		}
		if !egknow.Verify() {
			return fmt.Errorf("Wrong egknow proof")
		}

		eg := commitment.ElGamal{}
		if err := dec.Decode(&eg); err != nil {
			return fmt.Errorf("decode: ElGamal %v", err)
		}

		c.egs[pid] = &eg
		return nil
	}

	if err := a.server.Round([][]byte{toSendBuf.Bytes()}, check); err != nil {
		return nil, err
	}

	// Step 4. Compute and publish an ElGamal commitment to product of b and private share of a
	r, err := rand.Int(randReader, Q)
	if err != nil {
		return nil, err
	}
	bProd.Exp(bProd, a.secret)
	baShareEG := a.egf.Create(big.NewInt(0), r)
	baShareEG.Compose(bProd, baShareEG)

	toSendBuf.Reset()
	// TODO: replace the following commitment and check with EGKnow
	egexp := zkpok.NoopZKproof{}
	enc = gob.NewEncoder(&toSendBuf)
	if err := enc.Encode(egexp); err != nil {
		return nil, err
	}
	if err := enc.Encode(baShareEG); err != nil {
		return nil, err
	}

	baShareEGs := make([]*commitment.ElGamal, nProc)
	check = func(pid uint16, data []byte) error {
		var egexp zkpok.NoopZKproof
		buf := bytes.NewBuffer(data)
		dec := gob.NewDecoder(buf)
		if err := dec.Decode(&egexp); err != nil {
			return fmt.Errorf("decode: egknow %v", err)
		}
		if !egknow.Verify() {
			return fmt.Errorf("Wrong egknow proof")
		}

		eg := commitment.ElGamal{}
		if err := dec.Decode(&eg); err != nil {
			return fmt.Errorf("decode: ElGamal %v", err)
		}

		baShareEGs[pid] = &eg
		return nil
	}

	if err := a.server.Round([][]byte{toSendBuf.Bytes()}, check); err != nil {
		return nil, err
	}

	// Step 5. Compute ElGamal commitments to a product ab and c
	abEG := b.egf.Neutral()
	for _, eg := range baShareEGs {
		abEG.Compose(abEG, eg)
	}

	cEG := b.egf.Neutral()
	for _, eg := range c.egs {
		cEG.Compose(cEG, eg)
	}

	// Step 6. Run the CheckDH procedure on E(ab)/E(c)
	// TODO: @Jedrzej Kula

	return c, nil
}

// PrivMult computes the product ab
func PrivMult(a, b *big.Int) (*big.Int, error) {
	return nil, nil
}
