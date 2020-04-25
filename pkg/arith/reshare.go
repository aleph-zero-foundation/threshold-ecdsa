package arith

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/gob"
	"fmt"
	"math/big"

	"gitlab.com/alephledger/threshold-ecdsa/pkg/crypto/commitment"
	"gitlab.com/alephledger/threshold-ecdsa/pkg/crypto/zkpok"
)

// Reshare transforms the arithmetic secret into a threshold secret
func (ads *adsecret) Reshare(t uint16) (TDSecret, error) {
	if t < 1 {
		return nil, fmt.Errorf("Cannot reshare with threshold %v", t)
	}

	nProc := len(ads.egs)
	var err error

	// STEP 1. Publish a proof of knowledge of ads.secret and ads.r
	toSendBuf := bytes.Buffer{}
	toSend := [][]byte{nil}
	enc := gob.NewEncoder(&toSendBuf)
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

	toSend[0] = toSendBuf.Bytes()
	if err := ads.server.Round(toSend, check); err != nil {
		return nil, err
	}

	// STEP 2. Pick a random polynomial f of degree t such that f(0) = ads.secret
	var f []*big.Int
	if f, err = poly(t, ads.secret); err != nil {
		return nil, err
	}

	// STEP 3. Compute commitments to coefs of f, EGKnow, and EGRefresh
	egknow = zkpok.NoopZKproof{}
	egrefresh := zkpok.NoopZKproof{}
	coefComms := make([]*commitment.ElGamal, t)
	rands := make([]*big.Int, t)
	for i := range coefComms {
		var err error
		if rands[i], err = rand.Int(randReader, Q); err != nil {
			return nil, err
		}
		coefComms[i] = ads.egf.Create(f[i], rands[i])
	}

	// STEP 4. Commit to values from Step 3.
	// TODO: build proper NMC
	buildNMC := func(coefComms []*commitment.ElGamal, egknow, egrefresh *zkpok.NoopZKproof) (*NMCtmp, error) {
		dataBuf, zkpBuf := bytes.Buffer{}, bytes.Buffer{}
		for _, c := range coefComms {
			p, _ := c.MarshalBinary()
			if _, err := dataBuf.Write(p); err != nil {
				return nil, err
			}
		}
		p, _ := egknow.MarshalBinary()
		if _, err := zkpBuf.Write(p); err != nil {
			return nil, err
		}
		p, _ = egrefresh.MarshalBinary()
		if _, err := zkpBuf.Write(p); err != nil {
			return nil, err
		}
		nmc := &NMCtmp{dataBuf.Bytes(), zkpBuf.Bytes()}

		return nmc, nil

	}
	nmc, err := buildNMC(coefComms, &egknow, &egrefresh)
	if err != nil {
		return nil, err
	}
	toSendBuf.Reset()
	enc = gob.NewEncoder(&toSendBuf)
	if err := enc.Encode(nmc); err != nil {
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

	toSend[0] = toSendBuf.Bytes()
	if err := ads.server.Round(toSend, check); err != nil {
		return nil, err
	}

	// STEP 5. Decommit to values from Step 4.
	toSendBuf.Reset()
	enc = gob.NewEncoder(&toSendBuf)
	if err := enc.Encode(egknow); err != nil {
		return nil, err
	}
	if err := enc.Encode(egrefresh); err != nil {
		return nil, err
	}
	for _, c := range coefComms {
		if err := enc.Encode(c); err != nil {
			return nil, err
		}
	}

	check = func(pid uint16, data []byte) error {
		var egknow zkpok.NoopZKproof
		dec := gob.NewDecoder(bytes.NewBuffer(data))
		if err := dec.Decode(&egknow); err != nil {
			return err
		}
		if !egknow.Verify() {
			return fmt.Errorf("Wrong egknow proof")
		}
		var egrefresh zkpok.NoopZKproof
		if err := dec.Decode(&egrefresh); err != nil {
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

		nmc, err := buildNMC(coefComms, &egknow, &egrefresh)
		if err != nil {
			return err
		}

		if err := nmcs[pid].Verify(nmc.DataBytes, nmc.ZkpBytes); err != nil {
			return err
		}

		return nil
	}

	toSend[0] = toSendBuf.Bytes()
	if err := ads.server.Round(toSend, check); err != nil {
		return nil, err
	}

	// STEP 6. Compute commitments to evaluations f(l) for l in [N]
	egEval := make([]*commitment.ElGamal, nProc)
	tmp := ads.egf.Neutral()
	for pid := 0; pid < nProc; pid++ {
		egEval[pid] = ads.egf.Neutral()
		exp := big.NewInt(int64(pid))
		for i := uint16(0); i < t; i++ {
			expexp := big.NewInt(int64(i))
			expexp.Exp(exp, expexp, nil)
			tmp.Exp(coefComms[i], expexp)
			egEval[pid].Compose(egEval[pid], tmp)
		}
	}

	// STEP 7. Recommit to f(l), fresh r_l, and ERRefresh
	eval := make([]*big.Int, nProc)
	randEval := make([]*big.Int, nProc)
	egEvalRefresh := make([]*commitment.ElGamal, nProc)
	for pid := range eval {
		eval[pid] = polyEval(f, big.NewInt(int64(pid)))
		if randEval[pid], err = rand.Int(randReader, Q); err != nil {
			return nil, err
		}
		egEvalRefresh[pid] = ads.egf.Create(eval[pid], randEval[pid])
	}

	toSendBuf.Reset()
	enc = gob.NewEncoder(&toSendBuf)
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
			var egrefresh zkpok.NoopZKproof
			if err := dec.Decode(&egrefresh); err != nil {
				return err
			}
			if !egrefresh.Verify() {
				return fmt.Errorf("Wrong proof")
			}

			allEgEvalRefresh[pid][i] = &commitment.ElGamal{}
			if err := dec.Decode(allEgEvalRefresh[pid][i]); err != nil {
				return err
			}
		}

		return nil
	}

	toSend[0] = toSendBuf.Bytes()
	if err := ads.server.Round(toSend, check); err != nil {
		return nil, err
	}

	// STEP 8. Send f(l), r_l to party l
	toSend = make([][]byte, nProc)
	for pid := 0; pid < nProc; pid++ {
		toSend[pid] = make([]byte, 4+len(eval[pid].Bytes())+len(randEval[pid].Bytes()))
		binary.LittleEndian.PutUint32(toSend[pid][:4], uint32(len(eval[pid].Bytes())))
		copy(toSend[pid][4:4+len(eval[pid].Bytes())], eval[pid].Bytes())
		copy(toSend[pid][4+len(eval[pid].Bytes()):], randEval[pid].Bytes())
	}

	recvEvals := make([]*big.Int, nProc)
	recvRand := make([]*big.Int, nProc)
	// TODO: sth we can check here?
	check = func(pid uint16, data []byte) error {
		if len(data) < 4 {
			return fmt.Errorf("data for pid %v is to short %v", pid, len(data))
		}
		l := binary.LittleEndian.Uint32(data[:4])
		recvEvals[pid] = new(big.Int).SetBytes(data[4 : 4+l])
		recvRand[pid] = new(big.Int).SetBytes(data[4+l:])

		return nil
	}

	if err := ads.server.Round(toSend, check); err != nil {
		return nil, err
	}

	// STEP 9. compute coefs of final polynomial F, sum respective random elements and join comms
	share := big.NewInt(0)
	shareRand := big.NewInt(0)
	shareComms := make([]*commitment.ElGamal, nProc)
	for pid, e := range recvEvals {
		shareComms[pid] = ads.egf.Neutral()
		if e == nil {
			share.Add(share, eval[pid])
			shareRand.Add(shareRand, randEval[pid])
			continue
		}
		share.Add(share, e)
		shareRand.Add(shareRand, recvRand[pid])
	}
	for _, egs := range allEgEvalRefresh {
		comms := egs
		if comms == nil {
			comms = egEvalRefresh
		}
		for pid, eg := range comms {
			shareComms[pid].Compose(shareComms[pid], eg)
		}

	}

	// STEP 10. Commit to coefs of F and EGRefresh
	toSendBuf.Reset()
	enc = gob.NewEncoder(&toSendBuf)
	var shareRandRefresh *big.Int
	if shareRandRefresh, err = rand.Int(randReader, Q); err != nil {
		return nil, err
	}
	shareComm := ads.egf.Create(share, shareRandRefresh)
	// TODO: ...
	egrefresh = zkpok.NoopZKproof{}
	if err := enc.Encode(egrefresh); err != nil {
		return nil, err
	}
	if err := enc.Encode(shareComm); err != nil {
		return nil, err
	}

	check = func(pid uint16, data []byte) error {
		buf := bytes.NewBuffer(data)
		dec := gob.NewDecoder(buf)
		var (
			egrefresh zkpok.NoopZKproof
			eg        commitment.ElGamal
		)
		if err := dec.Decode(&egrefresh); err != nil {
			return fmt.Errorf("decode: egrefresh %v", err)
		}
		if err := dec.Decode(&eg); err != nil {
			return fmt.Errorf("decode: eg %v", err)
		}
		if !egrefresh.Verify() {
			return fmt.Errorf("Wrong proof")
		}
		// After checking that eg agrees with previous commitment, replace the old one with it
		shareComms[pid] = &eg

		return nil
	}

	tds := &tdsecret{*ads, t}
	ads.secret = share
	ads.r = shareRandRefresh
	ads.eg = shareComm
	ads.egs = shareComms

	return tds, nil
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
	deg := len(f) - 1
	eval := new(big.Int).Set(f[deg])
	for i := deg - 1; i >= 0; i-- {
		eval.Mul(eval, x)
		eval.Add(eval, f[i])
	}
	return eval
}
