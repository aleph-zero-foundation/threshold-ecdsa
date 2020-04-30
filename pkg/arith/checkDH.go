package arith

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/gob"
	"fmt"
	"math/big"

	"gitlab.com/alephledger/threshold-ecdsa/pkg/crypto/zkpok"
	"gitlab.com/alephledger/threshold-ecdsa/pkg/curve"
)

//CheckDH returns function to query if two values should be accepted
func CheckDH(key *DKey) (func(curve.Point, curve.Point, curve.Group) error, error) {

	nProc := len(key.pkShares)

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

	return func(u, v curve.Point, group curve.Group) error {
		return query(u, v, group, key)
	}, nil
}

func query(u, v curve.Point, group curve.Group, key *DKey) error {

	nProc := len(key.pkShares)
	var err error

	//STEP 1 Sample values, compute uK, vK and piK, commit to them
	var alpha, beta *big.Int

	if alpha, err = rand.Int(randReader, group.Order()); err != nil {
		return err
	}
	if beta, err = rand.Int(randReader, group.Order()); err != nil {
		return err
	}

	testValueShare := group.Add(group.ScalarMult(u, alpha), group.ScalarMult(group.Gen(), beta))
	verifyValueShare := group.Add(group.ScalarMult(v, alpha), group.ScalarMult(key.pk, beta))

	toSendBuf := bytes.Buffer{}
	toSend := [][]byte{nil}
	enc := gob.NewEncoder(&toSendBuf)
	// TODO: replace the following commitment and check with RRerand
	rrerand := zkpok.NoopZKproof{}

	buildNMC := func(testValueShare, verifyValueShare curve.Point, group curve.Group, rrerand *zkpok.NoopZKproof) (*NMCtmp, error) {
		dataBuf, zkpBuf := bytes.Buffer{}, bytes.Buffer{}

		p := group.Marshal(testValueShare)
		if _, err := dataBuf.Write(p); err != nil {
			return nil, err
		}

		length := make([]byte, 4)
		binary.BigEndian.PutUint64(length, uint64(len(p)))
		if _, err := dataBuf.Write(length); err != nil {
			return nil, err
		}

		p = group.Marshal(verifyValueShare)
		if _, err := dataBuf.Write(p); err != nil {
			return nil, err
		}

		length = make([]byte, 4)
		binary.BigEndian.PutUint64(length, uint64(len(p)))
		if _, err := dataBuf.Write(length); err != nil {
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
		return err
	}

	enc = gob.NewEncoder(&toSendBuf)
	if err := enc.Encode(nmc); err != nil {
		return err
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
		return err
	}

	//STEP 2 Decommit to previously published values, verify proofs and compute (u', v')

	toSendBuf.Reset()
	enc = gob.NewEncoder(&toSendBuf)
	if err := enc.Encode(rrerand); err != nil {
		return err
	}
	p := group.Marshal(verifyValueShare)
	if _, err := toSendBuf.Write(p); err != nil {
		return err
	}

	length := make([]byte, 4)
	binary.BigEndian.PutUint64(length, uint64(len(p)))
	if _, err := toSendBuf.Write(length); err != nil {
		return err
	}

	p = group.Marshal(testValueShare)
	if _, err := toSendBuf.Write(p); err != nil {
		return err
	}

	length = make([]byte, 4)
	binary.BigEndian.PutUint64(length, uint64(len(p)))
	if _, err := toSendBuf.Write(length); err != nil {
		return err
	}

	testValue := group.Neutral()
	verifyValue := group.Neutral()

	testValueShares := make([]curve.Point, nProc)
	verifyValueShares := make([]curve.Point, nProc)

	check = func(pid uint16, data []byte) error {
		length := binary.BigEndian.Uint64(data[0:4])
		data = data[4:]

		var verifyValueShare, testValueShare curve.Point
		if verifyValueShare, err = group.Unmarshal(data[0:length]); err != nil {
			return err
		}
		verifyValueShares[pid] = verifyValueShare

		data = data[length:]

		length = binary.BigEndian.Uint64(data[0:4])
		data = data[4:]

		if testValueShare, err = group.Unmarshal(data[0:length]); err != nil {
			return err
		}
		testValueShares[pid] = testValueShare

		data = data[length:]

		var rrerand zkpok.NoopZKproof
		dec := gob.NewDecoder(bytes.NewBuffer(data))
		if err := dec.Decode(&rrerand); err != nil {
			return err
		}
		if !rrerand.Verify() {
			return fmt.Errorf("Wrong rrerand proof")
		}

		nmc, err := buildNMC(testValueShare, verifyValueShare, group, &rrerand)
		if err != nil {
			return err
		}

		if err := nmcs[pid].Verify(nmc.DataBytes, nmc.ZkpBytes); err != nil {
			return err
		}

		return nil
	}

	toSend[0] = toSendBuf.Bytes()
	if err := key.secret.server.Round(toSend, check); err != nil {
		return err
	}

	for i := 0; i < nProc; i++ {
		testValue = group.Add(testValue, testValueShares[i])
		verifyValue = group.Add(verifyValue, verifyValueShares[i])
	}

	testValue = group.ScalarMult(testValue, key.secret.skShare)
	finalTestValue := group.Neutral()

	//STEP 3 Publish u'_k with ZKPOK

	toSendBuf.Reset()
	regexp := zkpok.NoopZKproof{}
	p = group.Marshal(testValue)
	if _, err := toSendBuf.Write(p); err != nil {
		return err
	}
	length = make([]byte, 4)
	binary.BigEndian.PutUint64(length, uint64(len(p)))
	if _, err := toSendBuf.Write(length); err != nil {
		return err
	}
	if err := enc.Encode(regexp); err != nil {
		return err
	}
	regexps := make([]zkpok.NoopZKproof, nProc)
	testValues := make([]curve.Point, nProc)
	check = func(pid uint16, data []byte) error {
		length := binary.BigEndian.Uint64(data[0:4])
		data = data[4:]

		var testValue curve.Point
		if testValue, err = group.Unmarshal(data[0:length]); err != nil {
			return err
		}
		testValues[pid] = testValue

		data = data[length:]

		var regexp zkpok.NoopZKproof
		buf := bytes.NewBuffer(data)
		dec := gob.NewDecoder(buf)

		if err := dec.Decode(&regexp); err != nil {
			return fmt.Errorf("decode: regexp %v", err)
		}
		if !regexp.Verify() {
			return fmt.Errorf("Wrong regexp proof")
		}

		regexps[pid] = regexp
		return nil
	}

	toSend[0] = toSendBuf.Bytes()
	if err := key.secret.server.Round(toSend, check); err != nil {
		return err
	}

	for i := 0; i < nProc; i++ {
		finalTestValue = group.Add(finalTestValue, testValues[i])
	}

	//Check if everything is correct

	if !(group.Equal(finalTestValue, verifyValue)) {
		return fmt.Errorf("Wrong value")
	}

	return nil
}
