package arith

import (
	"bytes"
	"crypto/rand"
	"encoding/gob"
	"fmt"
	"math/big"
	"time"

	"gitlab.com/alephledger/threshold-ecdsa/pkg/crypto/commitment"
	"gitlab.com/alephledger/threshold-ecdsa/pkg/crypto/zkpok"
	"gitlab.com/alephledger/threshold-ecdsa/pkg/sync"
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
	egf commitment.ElGamalFactory
	eg  *commitment.ElGamal
	egs []*commitment.ElGamal
}

// Reshare transforms the arithmetic secret into a threshold secret
func (ads *adsecret) Reshare(t uint16) (TDSecret, error) {
	if t < 2 {
		return nil, fmt.Errorf("Cannot reshare with threshold %v", t)
	}
	nProc := len(ads.egs)
	// 1. Publish a proof of knowledge of ads.secret and ads.r
	toSend := bytes.Buffer{}
	enc := gob.NewEncoder(&toSend)
	// TODO: replace the following commitment and check with EGKnow
	egknow := zkpok.NoopZKproof{}
	if err := enc.Encode(egknow); err != nil {
		return nil, err
	}
	egknows := make([]zkpok.NoopZKproof, nProc)
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

		egknows[pid] = egknow
		return nil
	}

	if err := ads.server.Round(toSend.Bytes(), check); err != nil {
		return nil, err
	}

	// 2. Pick a random polynomial f of degree t such that f(0) = ads.secret
	var f []*big.Int
	if f, err := poly(t, ads.secret); err != nil {
		return nil, err
	}

	// 3. Compute commitments to coefs of f, EGKnow, and EGRefresh
	egknow = zkpok.NoopZKproof{}
	egrefresh := zkpok.NoopZKproof{}
	coefComms := make([]*commitment.ElGamal, t)
	rands := make([]*big.Int, t)
	for i := range coefComms {
		if rands[i], err = rand.Int(randReader, Q); err != nil {
			return nil, err
		}
		coefComms[i] = ads.egf.Create(f[i], rands[i])
	}

	// 4. Commit to values from Step 3.
	toSend.Reset()
	// TODO: build proper NMC
	buildNMC = func(coefComms []*commitment.ElGamal, egknow, egrefresh zkpok.NoopZKproof) (*NMCtmp, err) {
		dataBuf, zkpBuf := bytes.Buffer{}, bytes.Buffer{}
		for _, c := range coefComms {
			p, _ := c.MarshalBinary()
			if _, err = dataBuf.Write(p); err != nil {
				return nil, err
			}
		}
		p, _ := egknow.MarshalBinary()
		if _, err = zkpBuf.Write(p); err != nil {
			return nil, err
		}
		p, _ = egrefresh.MarshalBinary()
		if _, err = zkpBuf.Write(p); err != nil {
			return nil, err
		}
		nmc := &NMCtmp{dataBuf.Bytes(), zkpBuf.Bytes()}
		if err := enc.Encode(nmc); err != nil {
			return nil, err
		}
	}
	nmc, err = buildNMC()
	if err != nil {
		return nil, err
	}

	nmcs := make([]*NMCtmp, nProc)
	check = func(pid uint16, data []byte) error {
		nmcs[pid] = &NMCtmp{}
		dec := gob.NewDecoder(bytes.NewBuffer(data))
		if err := dec.Decode(nmcs[pid]); err != nil {
			return err
		}
		return nil
	}

	if err := ads.server.Round(toSend.Bytes(), check); err != nil {
		return nil, err
	}

	// 5. Decommit to values from Step 4.
	toSend.Reset()
	if err := enc.Encode(egknow); err != nil {
		return nil, err
	}
	if err := enc.Encode(egrefresh); err != nil {
		return nil, err
	}
	for _, c := range comms {
		if err := enc.Encode(c); err != nil {
			return nil, err
		}
	}

	check = func(pid uint16, data []byte) error {
		dec := gob.NewDecoder(bytes.NewBuffer(data))
		egknow := &zkpok.NoopZKproof{}
		if err := dec.Decode(egknow); err != nil {
			return err
		}
		if !egknow.Verify() {
			return fmt.Errorf("Wrong egknow proof")
		}
		egrefresh := &zkpok.NoopZKproof{}
		if err := dec.Decode(egrefresh); err != nil {
			return err
		}
		if !egrefresh.Verify() {
			return fmt.Errorf("Wrong egknow proof")
		}
		coefComms := make([]*commitment.ElGamal, t)
		for i := range coefComms {
			coefComms[i] = &commitment.ElGamal{}
			if err := dec.Decode(coefComms[i]); err != nil {
				return err
			}
		}

		nmc, err := buildNMC(coefComms[i], egknow, egrefresh)
		if err != nil {
			return err
		}

		if err := nmcs[pid].Verify(nmc.DataBytes, nmc.ZkpBytes); err != nil {
			return err
		}

		return nil
	}

	if err := ads.server.Round(toSend.Bytes(), check); err != nil {
		return nil, err
	}

	// 6. Compute commitments to evaluations f(l) for l in [N]
	egEval := make([]*commitment.ElGamal, nProc)
	var tmp commitment.ElGamal
	for pid := 0; pid < nProc; pid++ {
		egEval[pid] = ads.egf.Neutral()
		exp := big.NewInt(int64(pid))
		for i := uint16(0); i < t; i++ {
			expexp := big.NewInt(int64(i))
			expexp.Exp(exp, expexp)
			tmp.Exp(coefComms[i], expexp)
			egEval.Compose(egEval, tmp)
		}
	}

	// 7. Recommit to f(l), fresh r_l, and ERRefresh
	eval := make([]*big.Int, nProc)
	randEval := make([]*big.Int, nProc)
	egEvalRefresh := make([]*commitment.ElGamal, nProc)
	for pid := range eval {
		eval[pid] = eval(f, big.NewInt(int64(pid)))
		if randEval[pid], err = rand.Int(randReader, Q); err != nil {
			return nil, err
		}
		egEvalRefresh[pid] = ads.egf.Create(eval[pid], randEval[pid])
	}

	toSend.Reset()
	for _, c := range egEvalRefresh {
		// TODO: you know what
		egrefresh = zkpok.NoopZKproof{}
		if err := enc.Encode(egrefresh); err != nil {
			return nil, err
		}
		if err := enc.Encode(c); err != nil {
			return nil, err
		}
	}

	allEgEvalRefresh := make([][]*commitment.ElGamal, nProc)
	check = func(pid uint16, data []byte) error {
		dec := gob.NewDecoder(bytes.NewBuffer(data))
		allEgEvalRefresh[pid] = make([]*commitment.ElGamal, nProc)
		for i := range allEgEvalRefresh[pid] {
			egrefresh := &zkpok.NoopZKproof{}
			if err := dec.Decode(egrefresh); err != nil {
				return err
			}
			if !egrefresh.Verify() {
				return fmt.Errorf("Wrong proof")
			}

			allEgEvalRefresh[i] = &commitment.ElGamal{}
			if err := dec.Decode(allEgEvalRefresh[i]); err != nil {
				return err
			}
		}

		return nil
	}

	if err := ads.server.Round(toSend.Bytes(), check); err != nil {
		return nil, err
	}

	// 8. Send f(l), r_l to party l
	recvEvals := make([]*big.Int, nProc)
	recvRand := make([]*big.Int, nProc)
	// TODO: add appropriate method to server

	// 9. compute coefs of final polynomial F, sum respective random elements and join comms
	share := big.NewInt(0)
	shareRand := big.NewInt(0)
	shareComm := ads.egf.Neutral()
	for pid, e := range recvEvals {
		if e == nil {
			share.Add(share, evals[pid])
			shareRand.Add(shareRand, randEval[pid])
			// TODO: update shareComm
			continue
		}
		share.Add(share, e)
		shareRand.Add(shareRand, recvRand[pid])
		// TODO: update shareComm
	}

	// 10. Commit to coefs of F and EGRefresh
	// TODO. recommit to share

	return nil, nil
}

// Gen generates a new distributed key with given label
func Gen(label string, server sync.Server, egf *commitment.ElGamalFactory, start time.Time) (ADSecret, error) {
	var err error
	// create a secret
	ads := &adsecret{dsecret: dsecret{label: label, server: server}, egf: egf}
	if ads.secret, err = rand.Int(randReader, Q); err != nil {
		return nil, err
	}
	if ads.r, err = rand.Int(randReader, Q); err != nil {
		return nil, err
	}

	// create a commitment and a zkpok
	ads.eg = egf.Create(ads.secret, ads.r)
	// TODO: replace with a proper zkpok when it's ready
	zkp := zkpok.NoopZKproof{}

	toSend := bytes.Buffer{}
	enc := gob.NewEncoder(&toSend)
	if err := enc.Encode(ads.eg); err != nil {
		return nil, err
	}
	if err := enc.Encode(zkp); err != nil {
		return nil, err
	}

	// TODO: reimplement after ZKPs are implemented
	check := func(_ uint16, data []byte) error {
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
		return nil
	}

	data, _, err := ads.server.Round(toSend.Bytes(), check, start, 0)
	if err != nil {
		return nil, err
	}

	ads.egs = make([]*commitment.ElGamal, len(data))
	buf := &bytes.Buffer{}
	dec := gob.NewDecoder(buf)
	for i := range data {
		if data[i] == nil {
			continue
		}
		ads.egs[i] = &commitment.ElGamal{}
		buf.Reset()
		if _, err := buf.Write(data[i]); err != nil {
			return nil, err
		}
		if err := dec.Decode(ads.egs[i]); err != nil {
			return nil, fmt.Errorf("decode: egs %v", err)
		}
	}

	return ads, nil
}

func poly(t uint16, a0 *big.Int) ([]*big.Int, error) {
	var err error
	f := make([]*big.Int, t)
	for i := range f {
		if i == 0 {
			f[i] = a0
			continue
		}
		if i == int(t)-1 {
			tmp := big.NewInt(1)
			tmp.Sub(Q, tmp)
			if f[i], err = rand.Int(randReader, tmp); err != nil {
				return nil, err
			}
			tmp.SetInt64(1)
			f[i].Add(f[i], tmp)

		}
		if f[i], err = rand.Int(randReader, Q); err != nil {
			return nil, err
		}
	}
	return f, nil
}

func polyEval(f []*big.Int, x *big.Int) *big.Int {
	// TODO: implement
	return nil
}
