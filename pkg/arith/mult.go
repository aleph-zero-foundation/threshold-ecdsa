package arith

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/binance-chain/tss-lib/crypto/paillier"

	"gitlab.com/alephledger/threshold-ecdsa/pkg/crypto/commitment"
	"gitlab.com/alephledger/threshold-ecdsa/pkg/crypto/zkpok"
	"gitlab.com/alephledger/threshold-ecdsa/pkg/sync"
)

// Mult computes a multiplication of two arithmetic secrets
func Mult(a, b *ADSecret, cLabel string, priv *paillier.PrivateKey, pub *paillier.PublicKey, pubs []*paillier.PublicKey) (c *ADSecret, err error) {
	nProc := len(a.egs)

	c = &ADSecret{}
	c.label = cLabel
	c.server = a.server

	// Step 1. Compute a product of commitments to b
	pid := int(a.pid)
	bProd := b.egf.Neutral()
	for _, eg := range b.egs {
		bProd.Compose(bProd, eg)
	}

	// Step 2. Run priv mult and compute the share of c
	if c.skShare, err = PrivMult(a.skShare, b.skShare, pid, nProc, a.server, priv, pub, pubs); err != nil {
		return nil, err
	}

	// Step 3. Compute and publish an ElGamal commitment to the share of c
	c.egs = make([]*commitment.ElGamal, nProc)
	if c.r, err = rand.Int(randReader, Q); err != nil {
		return nil, err
	}
	c.egs[a.pid] = a.egf.Create(c.skShare, c.r)

	toSendBuf := &bytes.Buffer{}
	// TODO: replace the following commitment and check with EGKnow
	egknow := zkpok.NoopZKproof{}
	if err := egknow.Encode(toSendBuf); err != nil {
		return nil, err
	}
	if err := c.egs[a.pid].Encode(toSendBuf); err != nil {
		return nil, err
	}

	check := func(pid uint16, data []byte) error {
		var egknow zkpok.NoopZKproof
		buf := bytes.NewBuffer(data)
		if err := egknow.Decode(buf); err != nil {
			return fmt.Errorf("decode: egknow %v", err)
		}
		if !egknow.Verify() {
			return fmt.Errorf("Wrong egknow proof")
		}

		eg := commitment.ElGamal{}
		if err := eg.Decode(buf); err != nil {
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
	bProd.Exp(bProd, a.skShare)
	baShareEG := a.egf.Create(big.NewInt(0), r)
	baShareEG.Compose(bProd, baShareEG)

	toSendBuf.Reset()
	// TODO: replace the following commitment and check with EGKnow
	egexp := zkpok.NoopZKproof{}
	if err := egexp.Encode(toSendBuf); err != nil {
		return nil, err
	}
	if err := baShareEG.Encode(toSendBuf); err != nil {
		return nil, err
	}

	baShareEGs := make([]*commitment.ElGamal, nProc)
	check = func(pid uint16, data []byte) error {
		var egexp zkpok.NoopZKproof
		buf := bytes.NewBuffer(data)
		if err := egexp.Decode(buf); err != nil {
			return fmt.Errorf("decode: egknow %v", err)
		}
		if !egknow.Verify() {
			return fmt.Errorf("Wrong egknow proof")
		}

		eg := commitment.ElGamal{}
		if err := eg.Decode(buf); err != nil {
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
		if eg == nil {
			abEG.Compose(abEG, baShareEG)
		} else {
			abEG.Compose(abEG, eg)
		}
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
func PrivMult(a, b *big.Int, pid, nProc int, server sync.Server, priv *paillier.PrivateKey, pub *paillier.PublicKey, pubs []*paillier.PublicKey) (*big.Int, error) {
	// For all parties with id < pid, we act as Alice in MtA for a and Act as Bob for b.
	// For all parties with id > pid, we act as Bob in MtA for a and act as Alice for b.

	// Step 1. First round of MtA. For id < pid wait for their Enc(a') and send Enc(b), and
	// for id > pid send Enc(a) and wait for their Enc(b').

	toSendBuf1 := make([][]byte, nProc)
	encA, err := pub.Encrypt(a)
	if err != nil {
		return nil, err
	}
	encB, err := pub.Encrypt(b)
	if err != nil {
		return nil, err
	}
	for id := range toSendBuf1 {
		if id < pid {
			// Bob for b
			toSendBuf1[id] = encB.Bytes()
		} else if id > pid {
			// Bob for a
			toSendBuf1[id] = encA.Bytes()
		}
	}

	encShares := make([]*big.Int, nProc)
	check := func(id uint16, data []byte) error {
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
		encABmt, err := pubs[id].HomoMult(share, encShares[id])
		if err != nil {
			return err
		}

		myShares[id], err = rand.Int(randReader, Q)
		if err != nil {
			return err
		}

		negMyShare := new(big.Int).Sub(pubs[id].N, myShares[id])
		enc, err := pubs[id].Encrypt(negMyShare)
		if err != nil {
			return err
		}

		encABmt, err = pubs[id].HomoAdd(encABmt, enc)
		if err != nil {
			return err
		}
		toSendBuf2[id] = encABmt.Bytes()

		return nil
	}

	for id := range toSendBuf2 {
		if id < pid {
			// Alice for a
			if err := genEncABmt(id, a); err != nil {
				return nil, err
			}
		} else if id > pid {
			// Alice for b
			if err := genEncABmt(id, b); err != nil {
				return nil, err
			}
		}
	}

	abmts := make([]*big.Int, nProc) // collection of decrypted shares for Bob
	check = func(id uint16, data []byte) error {
		if id != uint16(pid) {
			var err error
			// Bob for b
			abmts[id] = new(big.Int).SetBytes(data)
			abmts[id].Sub(abmts[id], pub.N)
			if abmts[id], err = priv.Decrypt(abmts[id]); err != nil {
				return err
			}
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
