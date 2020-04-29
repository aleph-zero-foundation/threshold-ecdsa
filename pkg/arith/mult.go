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

// Mult computes a multiplication of two arithmetic secrets
func Mult(a, b *ADSecret, cLabel string) (c *ADSecret, err error) {
	nProc := len(a.egs)

	c.label = cLabel
	c.server = a.server

	// Step 1. Compute a product of commitments to b
	pid := -1
	bProd := b.egf.Neutral()
	for id, eg := range b.egs {
		if b.egs == nil {
			pid = id
			bProd.Compose(bProd, b.eg)
		} else {
			bProd.Compose(bProd, eg)
		}
	}

	// Step 2. Run priv mult and compute the share of c
	if c.secret, err = PrivMult(a.secret, b.secret, pid, nProc, a.server); err != nil {
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
func PrivMult(a, b *big.Int, pid, nProc int, server sync.Server) (*big.Int, error) {
	// For all parties with id < pid, we act as Alice in MtA for a and Act as Bob for b.
	// For all parties with id > pid, we act as Bob in MtA for a and act as Alice for b.

	// Step 1. First round of MtA. For id < pid wait for their Enc(a') and send Enc(b), and
	// for id > pid send Enc(a) and wait for their Enc(b').

	toSendBuf1 := make([][]byte, nProc)
	for id := range toSendBuf1 {
		// TODO: Paillier encrypt
		if id < pid {
			// Bob for b
			toSendBuf1[id] = b.Bytes()
		} else if id > pid {
			// Bob for a
			toSendBuf1[id] = a.Bytes()
		}
	}

	encShares := make([]*big.Int, nProc)
	check := func(id uint16, data []byte) error {
		// TODO: Paillier decrypt
		if id < uint16(pid) {
			// Alice for a
			encShares[id] = new(big.Int).SetBytes(data)
		} else if id > uint16(pid) {
			// Alice for b
			encShares[id] = new(big.Int).SetBytes(data)
		}

		return nil
	}

	if err := server.Round(toSendBuf1, check); err != nil {
		return nil, err
	}

	// Step 2. Second round of MtA. For id < pid send Enc(aa'-t) and wait for E(bb'-t), and
	// for id > pid wait for Enc(aa'-t) and send Enc(bb'-t).
	myShares := make([]*big.Int, nProc) // collection of t_A
	toSendBuf2 := make([][]byte, nProc)
	genEncABmt := func(id int, share *big.Int) error {
		var err error
		myShares[id], err = rand.Int(randReader, Q)
		if err != nil {
			return err
		}
		// TODO: homomorphic encrypt mult
		encABmt := new(big.Int).Mul(share, encShares[id])
		// TODO: homomorphic encrypt add
		encABmt.Sub(encABmt, myShares[id])
		toSendBuf2[id] = encABmt.Bytes()

		return nil
	}

	for id := range toSendBuf2 {
		// TODO: Paillier encrypt
		if id < pid {
			// Alice for b
			if err := genEncABmt(id, b); err != nil {
				return nil, err
			}
		} else if id > pid {
			// Alice for a
			if err := genEncABmt(id, a); err != nil {
				return nil, err
			}
		}
	}

	abmts := make([]*big.Int, nProc) // collection of decrypted shares for Bob
	check = func(id uint16, data []byte) error {
		// TODO: Paillier decrypt
		if id < uint16(pid) {
			// Bob for b
			abmts[id] = new(big.Int).SetBytes(data)
		} else if id > uint16(pid) {
			// Bob for a
			abmts[id] = new(big.Int).SetBytes(data)
		}

		return nil
	}

	if err := server.Round(toSendBuf2, check); err != nil {
		return nil, err
	}

	// Step 3. Compute a share of a product of a and b
	share := new(big.Int).Mul(a, b)
	for id, t := range myShares {
		if id == pid {
			continue
		}
		share.Add(share, t)
		share.Add(share, abmts[id])
	}
	if len(share.Bytes()) > 32 {
		share.Mod(share, Q)
	}

	return share, nil
}
