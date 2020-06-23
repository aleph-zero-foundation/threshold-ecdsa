package arith

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math/big"

	"gitlab.com/alephledger/threshold-ecdsa/pkg/crypto/commitment"
	"gitlab.com/alephledger/threshold-ecdsa/pkg/crypto/zkpok"
)

// Reshare transforms the arithmetic secret into a threshold secret
func (ads *ADSecret) Reshare(t uint16) (*TDSecret, error) {
	if t < 1 {
		return nil, fmt.Errorf("Cannot reshare with threshold %v", t)
	}

	nProc := len(ads.egs)
	order := ads.egf.Curve().Order()

	var err error

	// STEP 1. Publish a proof of knowledge of ads.skShare and ads.r
	toSend := [][]byte{nil}
	toSendBuf := &bytes.Buffer{}
	secretEGKnow, err := zkpok.NewZKEGKnow(ads.egf, ads.egs[ads.pid], ads.skShare, ads.r)
	if err != nil {
		return nil, err
	}
	if err = secretEGKnow.Encode(toSendBuf); err != nil {
		return nil, err
	}
	egknows := make([]zkpok.ZKEGKnow, nProc)
	check := func(pid uint16, data []byte) error {
		var egknow zkpok.ZKEGKnow
		buf := bytes.NewBuffer(data)
		if err := egknow.Decode(buf); err != nil {
			return fmt.Errorf("STEP 1: decode: egknow %v", err)
		}
		if err := egknow.Verify(ads.egf, ads.egs[pid]); err != nil {
			return fmt.Errorf("STEP 1: Wrong egknow proof: %v", err)
		}

		egknows[pid] = egknow
		return nil
	}

	toSend[0] = toSendBuf.Bytes()
	if err = ads.server.Round(toSend, check); err != nil {
		return nil, err
	}

	// STEP 2. Pick a random polynomial f of degree t such that f(0) = ads.skShare

	var f []*big.Int
	if f, err = poly(t-1, ads.skShare); err != nil {
		return nil, err
	}

	// STEP 3. Compute commitments to coefs of f, EGKnow, and EGRefresh

	var egrefresh *zkpok.ZKEGRefresh
	coefComms := make([]*commitment.ElGamal, t)
	coefEGKnows := make([]*zkpok.ZKEGKnow, t)
	coefRands := make([]*big.Int, t)
	effectiveCoefRands := make([]*big.Int, t)
	for i := range coefComms {
		var err error
		if coefRands[i], err = rand.Int(randReader, order); err != nil {
			return nil, err
		}

		if i == 0 {
			//instead of creating new commitment, we refresh the original commitment to the secret
			coefComms[i] = ads.egf.Neutral()
			coefComms[i].Compose(ads.egs[ads.pid], ads.egf.Create(big.NewInt(0), coefRands[i]))

			effectiveCoefRands[i] = big.NewInt(0)
			effectiveCoefRands[i].Add(coefRands[i], ads.r)
			effectiveCoefRands[i].Mod(effectiveCoefRands[i], order)

			coefEGKnows[i], err = zkpok.NewZKEGKnow(ads.egf, coefComms[i], f[i], effectiveCoefRands[i])
			if err != nil {
				return nil, err
			}
			egrefresh, err = zkpok.NewZKEGRefresh(ads.egf, ads.egs[ads.pid], coefComms[i], coefRands[i])
			if err != nil {
				return nil, err
			}
			continue
		}
		effectiveCoefRands[i] = coefRands[i]
		coefComms[i] = ads.egf.Create(f[i], coefRands[i])
		coefEGKnows[i], err = zkpok.NewZKEGKnow(ads.egf, coefComms[i], f[i], effectiveCoefRands[i])
		if err != nil {
			return nil, err
		}
	}

	// STEP 4. Commit to values from Step 3.

	// TODO: build proper NMC
	buildNMC := func(coefComms []*commitment.ElGamal, coefEGKnows []*zkpok.ZKEGKnow, egrefresh *zkpok.ZKEGRefresh) (*NMCtmp, error) {
		dataBuf, zkpBuf := &bytes.Buffer{}, &bytes.Buffer{}
		for _, c := range coefComms {
			if err := c.Encode(dataBuf); err != nil {
				return nil, err
			}
		}

		for _, z := range coefEGKnows {
			if err := z.Encode(zkpBuf); err != nil {
				return nil, err
			}
		}

		if err := egrefresh.Encode(zkpBuf); err != nil {
			return nil, err
		}

		// TODO: build actual nmc
		nmc := &NMCtmp{dataBuf.Bytes(), zkpBuf.Bytes()}

		return nmc, nil

	}
	nmc, err := buildNMC(coefComms, coefEGKnows, egrefresh)
	if err != nil {
		return nil, err
	}

	toSendBuf.Reset()
	if err := nmc.encode(toSendBuf); err != nil {
		return nil, err
	}

	nmcs := make([]*NMCtmp, nProc)
	check = func(pid uint16, data []byte) error {
		buf := bytes.NewBuffer(data)
		nmcs[pid] = &NMCtmp{}
		if err := nmcs[pid].decode(buf); err != nil {
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
	for _, c := range coefComms {
		if err := c.Encode(toSendBuf); err != nil {
			return nil, err
		}
	}
	for _, z := range coefEGKnows {
		if err := z.Encode(toSendBuf); err != nil {
			return nil, err
		}
	}
	if err := egrefresh.Encode(toSendBuf); err != nil {
		return nil, err
	}

	allCoefComms := make([][]*commitment.ElGamal, nProc)
	check = func(pid uint16, data []byte) error {
		buf := bytes.NewBuffer(data)
		allCoefComms[pid] = make([]*commitment.ElGamal, t)
		for i := range allCoefComms[pid] {
			allCoefComms[pid][i] = &commitment.ElGamal{}
			if err := allCoefComms[pid][i].Decode(buf); err != nil {
				return err
			}
		}

		coefEGKnows := make([]*zkpok.ZKEGKnow, t)
		for i := range coefEGKnows {
			coefEGKnows[i] = &zkpok.ZKEGKnow{}
			if err := coefEGKnows[i].Decode(buf); err != nil {
				return err
			}
			if err := coefEGKnows[i].Verify(ads.egf, allCoefComms[pid][i]); err != nil {
				return fmt.Errorf("STEP 5: Wrong egknow proof")
			}
		}

		var egrefresh zkpok.ZKEGRefresh
		if err := egrefresh.Decode(buf); err != nil {
			return err
		}
		if egrefresh.Verify(ads.egf, ads.egs[pid], allCoefComms[pid][0]) != nil {
			return fmt.Errorf("STEP 5: Wrong egrefresh proof")
		}

		nmc, err := buildNMC(allCoefComms[pid], coefEGKnows, &egrefresh)
		if err != nil {
			return err
		}

		if err := nmcs[pid].Verify(nmc.dataBytes, nmc.zkpBytes); err != nil {

			return err
		}

		return nil
	}

	toSend[0] = toSendBuf.Bytes()
	if err := ads.server.Round(toSend, check); err != nil {
		return nil, err
	}

	// STEP 6. Compute commitments to evaluations f_k(l) for k,l in [N]

	// First for your own pid (together with computation of Rands effetively used in new commitments)
	egEval := make([]*commitment.ElGamal, nProc)
	egEvalRands := make([]*big.Int, nProc)
	tmp := ads.egf.Neutral()
	tmpInt := big.NewInt(0)
	for pid := 0; pid < nProc; pid++ {
		egEvalRands[pid] = big.NewInt(0)
		egEval[pid] = ads.egf.Neutral()
		exp := big.NewInt(int64(pid + 1))
		for i := uint16(0); i < t; i++ {
			expexp := big.NewInt(int64(i))
			expexp.Exp(exp, expexp, nil)
			tmp.Exp(coefComms[i], expexp)
			tmpInt.Mul(effectiveCoefRands[i], expexp)
			egEval[pid].Compose(egEval[pid], tmp)
			egEvalRands[pid].Add(egEvalRands[pid], tmpInt)
		}
	}

	// And now for every other pid (needed to verify ZKEGRefreshes later)
	allEGEval := make([][]*commitment.ElGamal, nProc)
	for pidk := 0; pidk < nProc; pidk++ {
		allEGEval[pidk] = make([]*commitment.ElGamal, nProc)
		if allCoefComms[pidk] == nil {
			allCoefComms[pidk] = coefComms
		}
		for pidl := 0; pidl < nProc; pidl++ {
			allEGEval[pidk][pidl] = ads.egf.Neutral()
			exp := big.NewInt(int64(pidl + 1))
			for i := uint16(0); i < t; i++ {
				expexp := big.NewInt(int64(i))
				expexp.Exp(exp, expexp, nil)
				tmp.Exp(allCoefComms[pidk][i], expexp)
				allEGEval[pidk][pidl].Compose(allEGEval[pidk][pidl], tmp)
			}
		}
	}

	// STEP 7. Refresh commitment to f(l) and publish together with ZKEGRefresh

	eval := make([]*big.Int, nProc)
	randEvalRefresh := make([]*big.Int, nProc)
	effectiveRandEval := make([]*big.Int, nProc)
	evalRefreshComm := make([]*commitment.ElGamal, nProc)
	evalRefreshZK := make([]*zkpok.ZKEGRefresh, nProc)
	for pid := range eval {
		eval[pid] = polyEval(f, big.NewInt(int64(pid+1)), order)
		if randEvalRefresh[pid], err = rand.Int(randReader, order); err != nil {
			return nil, err
		}

		// Randomizing element effectively used in the commitment is mult of the initial one and rerandomizing one
		effectiveRandEval[pid] = big.NewInt(0)
		effectiveRandEval[pid].Add(randEvalRefresh[pid], egEvalRands[pid])

		evalRefreshComm[pid] = ads.egf.Neutral()
		evalRefreshComm[pid].Compose(egEval[pid], ads.egf.Create(big.NewInt(0), randEvalRefresh[pid]))
		if evalRefreshZK[pid], err = zkpok.NewZKEGRefresh(ads.egf, egEval[pid], evalRefreshComm[pid], randEvalRefresh[pid]); err != nil {
			return nil, err
		}
	}

	toSendBuf.Reset()
	for _, c := range evalRefreshComm {
		if err := c.Encode(toSendBuf); err != nil {
			return nil, err
		}
	}

	for _, z := range evalRefreshZK {
		if err := z.Encode(toSendBuf); err != nil {
			return nil, err
		}
	}

	allEvalRefreshComm := make([][]*commitment.ElGamal, nProc)
	allEvalRefreshZK := make([][]*zkpok.ZKEGRefresh, nProc)
	check = func(pid uint16, data []byte) error {
		buf := bytes.NewBuffer(data)
		allEvalRefreshComm[pid] = make([]*commitment.ElGamal, nProc)
		allEvalRefreshZK[pid] = make([]*zkpok.ZKEGRefresh, nProc)
		for i := range allEvalRefreshComm[pid] {
			allEvalRefreshComm[pid][i] = &commitment.ElGamal{}
			if err := allEvalRefreshComm[pid][i].Decode(buf); err != nil {
				return err
			}
		}

		for i := range allEvalRefreshZK[pid] {
			allEvalRefreshZK[pid][i] = &zkpok.ZKEGRefresh{}
			if err := allEvalRefreshZK[pid][i].Decode(buf); err != nil {
				return err
			}
			if allEvalRefreshZK[pid][i].Verify(ads.egf, allEGEval[pid][i], allEvalRefreshComm[pid][i]) != nil {
				return fmt.Errorf("STEP 7: Wrong Refresh proof")
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
		toSend[pid] = make([]byte, 4+len(eval[pid].Bytes())+len(effectiveRandEval[pid].Bytes()))
		binary.LittleEndian.PutUint32(toSend[pid][:4], uint32(len(eval[pid].Bytes())))
		copy(toSend[pid][4:4+len(eval[pid].Bytes())], eval[pid].Bytes())
		copy(toSend[pid][4+len(eval[pid].Bytes()):], effectiveRandEval[pid].Bytes())
	}

	recvEvals := make([]*big.Int, nProc)
	recvRand := make([]*big.Int, nProc)
	check = func(pid uint16, data []byte) error {
		if len(data) < 4 {
			return fmt.Errorf("data for pid %v is to short %v", pid, len(data))
		}
		l := binary.LittleEndian.Uint32(data[:4])
		recvEvals[pid] = new(big.Int).SetBytes(data[4 : 4+l])
		recvRand[pid] = new(big.Int).SetBytes(data[4+l:])
		if !allEvalRefreshComm[pid][ads.pid].Equal(ads.egf.Create(recvEvals[pid], recvRand[pid]), allEvalRefreshComm[pid][ads.pid]) {
			return fmt.Errorf("Payload in STEP 8 inconsistent with commitment for pid %v and ads.pid %v. Len: %v // %v // %v", pid, ads.pid, l, recvEvals[pid], recvRand[pid])
		}
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
		// While this looks risky, note that resharing is part of preprocessing which can be aborted by a single node anyway
		if e == nil {
			share.Add(share, eval[pid])
			shareRand.Add(shareRand, effectiveRandEval[pid])
			continue
		}
		share.Add(share, e)
		shareRand.Add(shareRand, recvRand[pid])
	}
	share.Mod(share, order)
	for _, egs := range allEvalRefreshComm {
		comms := egs
		if comms == nil {
			comms = evalRefreshComm
		}
		for pid, eg := range comms {
			shareComms[pid].Compose(shareComms[pid], eg)
		}

	}

	// STEP 10. Commit to coefs of F and EGRefresh

	var shareRandRefresh *big.Int
	if shareRandRefresh, err = rand.Int(randReader, order); err != nil {
		return nil, err
	}
	shareCommRefresh := ads.egf.Neutral()
	shareCommRefresh.Compose(shareComms[ads.pid], ads.egf.Create(big.NewInt(0), shareRandRefresh))
	shareRefreshZK, err := zkpok.NewZKEGRefresh(ads.egf, shareComms[ads.pid], shareCommRefresh, shareRandRefresh)
	if err != nil {
		return nil, err
	}

	toSendBuf.Reset()
	if err := shareRefreshZK.Encode(toSendBuf); err != nil {
		return nil, err
	}
	if err := shareCommRefresh.Encode(toSendBuf); err != nil {
		return nil, err
	}

	check = func(pid uint16, data []byte) error {
		buf := bytes.NewBuffer(data)
		var (
			egTemp        commitment.ElGamal
			egrefreshTemp zkpok.ZKEGRefresh
		)
		if err := egrefreshTemp.Decode(buf); err != nil {
			return fmt.Errorf("STEP 10, decode: egrefresh %v", err)
		}
		if err := egTemp.Decode(buf); err != nil {
			return fmt.Errorf("STEP 10, decode: eg %v", err)
		}
		if egrefreshTemp.Verify(ads.egf, shareComms[pid], &egTemp) != nil {
			return fmt.Errorf("STEP 10, Wrong proof")
		}
		// After checking that eg agrees with previous commitment, replace the old one with it
		shareComms[pid] = &egTemp

		return nil
	}

	toSend = [][]byte{nil}
	toSend[0] = toSendBuf.Bytes()
	if err := ads.server.Round(toSend, check); err != nil {
		return nil, err
	}

	tds := &TDSecret{*ads, t}
	ads.skShare = share
	ads.r = shareRandRefresh
	ads.egs = shareComms

	return tds, nil
}
