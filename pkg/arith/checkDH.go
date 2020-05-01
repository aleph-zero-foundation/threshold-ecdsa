package arith

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"math/big"

	"gitlab.com/alephledger/threshold-ecdsa/pkg/crypto/zkpok"
	"gitlab.com/alephledger/threshold-ecdsa/pkg/curve"
)

//CheckDH checks if given values are DF triple
func CheckDH(u, v curve.Point, group curve.Group, key *DKey) error {

	nProc := len(key.pkShares)
	var err error

	//STEP 1 Sample values, compute testValueShare, verifyValueShare and rrerand, commit to them
	var alpha, beta *big.Int

	if alpha, err = rand.Int(randReader, group.Order()); err != nil {
		return err
	}
	if beta, err = rand.Int(randReader, group.Order()); err != nil {
		return err
	}

	testValueShare := group.Add(group.ScalarMult(u, alpha), group.ScalarMult(group.Gen(), beta))
	verifyValueShare := group.Add(group.ScalarMult(v, alpha), group.ScalarMult(key.pk, beta))

	toSendBuf := &bytes.Buffer{}
	toSend := [][]byte{nil}
	// TODO: replace the following commitment and check with RRerand
	rrerand := zkpok.NoopZKproof{}

	buildNMC := func(testValueShare, verifyValueShare curve.Point, group curve.Group, rrerand *zkpok.NoopZKproof) (*NMCtmp, error) {
		dataBuf, zkpBuf := &bytes.Buffer{}, &bytes.Buffer{}

		if err := group.Encode(testValueShare, dataBuf); err != nil {
			return nil, err
		}

		if err := group.Encode(verifyValueShare, dataBuf); err != nil {
			return nil, err
		}

		if err := rrerand.Encode(zkpBuf); err != nil {
			return nil, err
		}
		nmc := &NMCtmp{dataBuf.Bytes(), zkpBuf.Bytes()}

		return nmc, nil
	}

	nmc, err := buildNMC(testValueShare, verifyValueShare, group, &rrerand)
	if err != nil {
		return err
	}

	if err := nmc.encode(toSendBuf); err != nil {
		return err
	}

	nmcs := make([]*NMCtmp, nProc)
	check := func(pid uint16, data []byte) error {
		buf := bytes.NewBuffer(data)
		nmcs[pid] = &NMCtmp{}
		if err := nmcs[pid].decode(buf); err != nil {
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
	if err := rrerand.Encode(toSendBuf); err != nil {
		return err
	}
	if err := group.Encode(verifyValueShare, toSendBuf); err != nil {
		return err
	}

	if err := group.Encode(testValueShare, toSendBuf); err != nil {
		return err
	}

	testValue := testValueShare
	verifyValue := verifyValueShare

	testValueShares := make([]curve.Point, nProc)
	verifyValueShares := make([]curve.Point, nProc)

	check = func(pid uint16, data []byte) error {
		buf := bytes.NewBuffer(data)
		var err error
		var verifyValueShare, testValueShare curve.Point
		if verifyValueShare, err = group.Decode(buf); err != nil {
			return err
		}
		verifyValueShares[pid] = verifyValueShare

		if testValueShare, err = group.Decode(buf); err != nil {
			return err
		}
		testValueShares[pid] = testValueShare

		var rrerand zkpok.NoopZKproof
		if err := rrerand.Decode(buf); err != nil {
			return err
		}
		if !rrerand.Verify() {
			return fmt.Errorf("Wrong rrerand proof")
		}

		nmc, err := buildNMC(testValueShare, verifyValueShare, group, &rrerand)
		if err != nil {
			return err
		}

		if err := nmcs[pid].Verify(nmc.dataBytes, nmc.zkpBytes); err != nil {
			return err
		}

		return nil
	}

	toSend[0] = toSendBuf.Bytes()
	if err := key.secret.server.Round(toSend, check); err != nil {
		return err
	}

	for i := 0; i < nProc; i++ {
		if testValueShares[i] != nil {
			testValue = group.Add(testValue, testValueShares[i])
		}
		if verifyValueShares[i] != nil {
			verifyValue = group.Add(verifyValue, verifyValueShares[i])
		}
	}

	testValue = group.ScalarMult(testValue, key.secret.skShare)
	finalTestValue := testValue

	//STEP 3 Publish u'_k with ZKPOK

	toSendBuf.Reset()
	if err := group.Encode(testValue, toSendBuf); err != nil {
		return err
	}

	regexp := zkpok.NoopZKproof{}
	if err := regexp.Encode(toSendBuf); err != nil {
		return err
	}

	testValues := make([]curve.Point, nProc)

	check = func(pid uint16, data []byte) error {
		buf := bytes.NewBuffer(data)

		var testValue curve.Point
		if testValue, err = group.Decode(buf); err != nil {
			return err
		}
		testValues[pid] = testValue

		var regexp zkpok.NoopZKproof

		if err := regexp.Decode(buf); err != nil {
			return fmt.Errorf("decode: regexp %v", err)
		}
		if !regexp.Verify() {
			return fmt.Errorf("Wrong regexp proof")
		}

		return nil
	}

	toSend[0] = toSendBuf.Bytes()
	if err := key.secret.server.Round(toSend, check); err != nil {
		return err
	}

	for i := 0; i < nProc; i++ {
		if testValues[i] != nil {
			finalTestValue = group.Add(finalTestValue, testValues[i])
		}
	}

	//Check if everything is correct

	if !(group.Equal(finalTestValue, verifyValue)) {
		return fmt.Errorf("Wrong value")
	}

	return nil
}
