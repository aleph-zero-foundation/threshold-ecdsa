package arith

import (
	"bytes"
	"crypto/rand"
	"encoding/gob"
	"fmt"

	"gitlab.com/alephledger/threshold-ecdsa/pkg/crypto/zkpok"
	"gitlab.com/alephledger/threshold-ecdsa/pkg/curve"
)

var (
	reader = rand.Reader
)

//CheckDH returns function to query if two values should be accepted
func CheckDH(key *DKey) (func(*curve.Point, *curve.Point, curve.Group) (bool, error), error) {

	nProc := len(key.pks)

	// STEP 1. Publish a proof of knowledge of g^{d_k}
	toSendBuf := bytes.Buffer{}
	toSend := [][]byte{nil}
	enc := gob.NewEncoder(&toSendBuf)
	// TODO: replace the following commitment and check with RDLog
	rdlog := zkpok.NoopZKproof{}
	if err := enc.Encode(rdlog); err != nil {
		return nil, err
	}
	rdlogs := make([]zkpok.NoopZKproof, nProc)
	check := func(pid uint16, data []byte) error {
		var rdlog zkpok.NoopZKproof
		buf := bytes.NewBuffer(data)
		dec := gob.NewDecoder(buf)
		if err := dec.Decode(&rdlog); err != nil {
			return fmt.Errorf("decode: rdlog %v", err)
		}
		if !rdlog.Verify() {
			return fmt.Errorf("Wrong rdlog proof")
		}

		rdlogs[pid] = rdlog
		return nil
	}

	toSend[0] = toSendBuf.Bytes()
	if err := key.secret.server.Round(toSend, check); err != nil {
		return nil, err
	}

	return func(u, v *curve.Point, group curve.Group) (bool, error) {
		return query(u, v, group, key)
	}, nil
}

func query(u, v *curve.Point, group curve.Group, key *DKey) (bool, error) {

	nProc := len(key.pks)
	var err error

	//STEP 1 Sample values, compute uK, vK and piK, commit to them
	alpha, _ := rand.Int(reader, group.Order())
	beta, _ := rand.Int(reader, group.Order())

	testValueShare := group.Add(group.ScalarMult(u, alpha), group.ScalarMult(group.Gen, beta))
	verifyValueShare := group.Add(group.ScalarMult(v, alpha), group.ScalarMult(key.pk, beta)) //key.pk is group generator H

	toSendBuf := bytes.Buffer{}
	toSend := [][]byte{nil}
	enc := gob.NewEncoder(&toSendBuf)
	// TODO: replace the following commitment and check with RRerand
	rrerand := zkpok.NoopZKproof{}

	buildNMC := func(testValueShare, verifyValueShare *curve.Point, group curve.Group, rrerand *zkpok.NoopZKproof) (*NMCtmp, error) {
		dataBuf, zkpBuf := bytes.Buffer{}, bytes.Buffer{}

		p := group.Marshal(testValueShare)
		if _, err := dataBuf.Write(p); err != nil {
			return nil, err
		}

		p = group.Marshal(verifyValueShare)
		if _, err := dataBuf.Write(p); err != nil {
			return nil, err
		}

		p, _ = rrerand.MarshalBinary()
		if _, err := zkpBuf.Write(p); err != nil {
			return nil, err
		}
		nmc := &NMCtmp{dataBuf.Bytes(), zkpBuf.Bytes()}

		return nmc, nil
	}

	nmc, err := buildNMC(&testValueShare, &verifyValueShare, group, &rrerand)
	if err != nil {
		return false, err
	}

	enc = gob.NewEncoder(&toSendBuf)
	if err := enc.Encode(nmc); err != nil {
		return false, err
	}

	nmcs := make([]*NMCtmp, nProc)
	check := func(pid uint16, data []byte) error {
		nmcs[pid] = &NMCtmp{}
		dec := gob.NewDecoder(bytes.NewBuffer(data))
		if err := dec.Decode(nmcs[pid]); err != nil {
			return err
		}
		return nil
	}

	toSend[0] = toSendBuf.Bytes()
	if err := key.secret.server.Round(toSend, check); err != nil {
		return false, err
	}

	//STEP 2 Decommit to previously published values, verify proofs and compute (u', v')

	toSendBuf.Reset()
	enc = gob.NewEncoder(&toSendBuf)
	if err := enc.Encode(rrerand); err != nil {
		return false, err
	}
	if err := enc.Encode(verifyValueShare); err != nil {
		return false, err
	}
	if err := enc.Encode(testValueShare); err != nil {
		return false, err
	}

	testValue := group.Neutral()
	verifyValue := group.Neutral()

	check = func(pid uint16, data []byte) error {
		var rrerand zkpok.NoopZKproof
		dec := gob.NewDecoder(bytes.NewBuffer(data))
		if err := dec.Decode(&rrerand); err != nil {
			return err
		}
		if !rrerand.Verify() {
			return fmt.Errorf("Wrong rrerand proof")
		}

		var verifyValueShare *curve.Point
		if err := dec.Decode(&verifyValueShare); err != nil {
			return err
		}

		var testValueShare *curve.Point
		if err := dec.Decode(&testValueShare); err != nil {
			return err
		}

		nmc, err := buildNMC(testValueShare, verifyValueShare, group, &rrerand)
		if err != nil {
			return err
		}

		if err := nmcs[pid].Verify(nmc.DataBytes, nmc.ZkpBytes); err != nil {
			return err
		}

		testValue = group.Add(testValue, testValueShare)
		verifyValue = group.Add(verifyValue, verifyValueShare)

		return nil
	}

	toSend[0] = toSendBuf.Bytes()
	if err := key.secret.server.Round(toSend, check); err != nil {
		return false, err
	}

	testValue = group.ScalarMult(testValue, key.secret.secret)
	finalTestValue := group.Neutral()

	//STEP 3 Publish u'_k with ZKPOK

	toSendBuf.Reset()
	regexp := zkpok.NoopZKproof{}
	if err := enc.Encode(testValue); err != nil {
		return false, err
	}
	if err := enc.Encode(regexp); err != nil {
		return false, err
	}
	regexps := make([]zkpok.NoopZKproof, nProc)
	check = func(pid uint16, data []byte) error {
		var regexp zkpok.NoopZKproof
		buf := bytes.NewBuffer(data)
		dec := gob.NewDecoder(buf)

		var testValue *curve.Point
		if err := dec.Decode(&testValue); err != nil {
			return err
		}
		if err := dec.Decode(&regexp); err != nil {
			return fmt.Errorf("decode: regexp %v", err)
		}
		if !regexp.Verify() {
			return fmt.Errorf("Wrong regexp proof")
		}

		group.Add(finalTestValue, testValue)

		regexps[pid] = regexp
		return nil
	}

	toSend[0] = toSendBuf.Bytes()
	if err := key.secret.server.Round(toSend, check); err != nil {
		return false, err
	}

	//Check if everything is correct

	if !(group.Equal(finalTestValue, verifyValue)) {
		return false, fmt.Errorf("Wrong value")
	}

	return true, nil
}
