package arith

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"math/big"
	stdsync "sync"

	"gitlab.com/alephledger/threshold-ecdsa/pkg/crypto/commitment"
	"gitlab.com/alephledger/threshold-ecdsa/pkg/crypto/zkpok"
	"gitlab.com/alephledger/threshold-ecdsa/pkg/curve"
	"gitlab.com/alephledger/threshold-ecdsa/pkg/sync"
)

// DSecret is a distributed secret
type DSecret struct {
	pid     uint16
	label   string
	skShare *big.Int
	server  sync.Server
}

// NewDSecret returns a pointer to new DSecret instance
func NewDSecret(pid uint16, label string, skShare *big.Int, server sync.Server) *DSecret {
	return &DSecret{
		pid:     pid,
		label:   label,
		skShare: skShare,
		server:  server,
	}
}

// Label returns the name of the variable
func (ds *DSecret) Label() string {
	return ds.label
}

// ADSecret is an arithmetic distirbuted secret
type ADSecret struct {
	DSecret
	r   *big.Int
	egf *commitment.ElGamalFactory
	egs []*commitment.ElGamal
}

// TDSecret is a thresholded distributed secret
type TDSecret struct {
	ADSecret
	t uint16
}

// Reveal computes a join secret, which share is kept in tds.
func (tds *TDSecret) Reveal() (*big.Int, error) {
	// TODO: add EGReveal
	toSend := [][]byte{tds.skShare.Bytes()}

	secrets := make([]*big.Int, len(tds.egs))
	secrets[tds.pid] = tds.skShare

	check := func(pid uint16, data []byte) error {
		// TODO: check zkpok
		secrets[pid] = new(big.Int).SetBytes(data)
		return nil
	}

	nProc := len(tds.egs)
	if err := tds.server.Round(toSend, check); err != nil {
		if rErr, ok := err.(*sync.RoundError); ok && rErr.Missing() != nil && nProc-len(rErr.Missing()) < int(tds.t) {
			return nil, err
		}
	}

	sum := big.NewInt(0)
	for _, secret := range secrets {
		if secret != nil {
			sum.Add(sum, secret)
		}
	}

	return sum, nil
}

// Exp computes a common public key and its share related to this secret
func (tds *TDSecret) Exp() (*TDKey, error) {
	// TODO: keep it somewhere
	group := curve.NewSecp256k1Group()
	pid := tds.pid
	tdk := &TDKey{}
	tdk.secret = tds
	tdk.pkShares = make([]curve.Point, len(tds.egs))
	tdk.pkShares[pid] = group.ScalarBaseMult(tds.skShare)

	// TODO: add EGRefresh
	toSendBuf := &bytes.Buffer{}
	if err := group.Encode(tdk.pkShares[pid], toSendBuf); err != nil {
		return nil, fmt.Errorf("Encoding tkd.pkShare in Exp: %v", err)
	}

	check := func(pid uint16, data []byte) error {
		// TODO: check zkpok
		buf := bytes.NewBuffer(data)
		var err error
		tdk.pkShares[pid], err = group.Decode(buf)
		if err != nil {
			return err
		}
		return nil
	}

	nProc := len(tds.egs)
	if err := tds.server.Round([][]byte{toSendBuf.Bytes()}, check); err != nil {
		if rErr, ok := err.(*sync.RoundError); ok && rErr.Missing() != nil && nProc-len(rErr.Missing()) < int(tds.t) {
			return nil, err
		}
	}

	var wg stdsync.WaitGroup
	channel := make(chan curve.Point, nProc)
	counter := tds.t

	args := make([]*big.Int, tds.t)
	values := make([]curve.Point, tds.t)
	for i, value := range tdk.pkShares {
		if value == nil {
			continue
		}
		args[i] = big.NewInt(int64(i))
		values[i] = value
		counter = counter - 1
		if counter == 0 {
			break
		}
	}

	for i, arg := range args {
		wg.Add(1)
		go func(i int, arg *big.Int) {
			defer wg.Done()
			channel <- group.ScalarMult(values[i], lagrangeCoef(arg, args, group.Order()))
		}(i, arg)
	}

	go func() {
		wg.Wait()
		close(channel)
	}()

	publicKey := group.Neutral()
	for elem := range channel {
		publicKey = group.Add(publicKey, elem)
	}

	tdk.pk = publicKey

	return tdk, nil
}

// Threshold returns the number of parties that must collude to reveal the secret
func (tds TDSecret) Threshold() uint16 {
	return tds.t
}

// Gen generates a new distributed key with given label
func Gen(label string, server sync.Server, egf *commitment.ElGamalFactory, pid, nProc uint16) (*ADSecret, error) {
	var err error
	// create a secret
	ads := &ADSecret{DSecret: DSecret{pid: pid, label: label, server: server}, egf: egf}
	if ads.skShare, err = rand.Int(randReader, Q); err != nil {
		return nil, err
	}
	if ads.r, err = rand.Int(randReader, Q); err != nil {
		return nil, err
	}

	// create a commitment and a zkpok
	ads.egs = make([]*commitment.ElGamal, nProc)
	ads.egs[ads.pid] = egf.Create(ads.skShare, ads.r)
	// TODO: replace with a proper zkpok when it's ready
	zkp := zkpok.NoopZKproof{}

	toSendBuf := &bytes.Buffer{}
	if err := ads.egs[ads.pid].Encode(toSendBuf); err != nil {
		return nil, err
	}
	if err := zkp.Encode(toSendBuf); err != nil {
		return nil, err
	}

	// TODO: reimplement after ZKPs are implemented
	check := func(pid uint16, data []byte) error {
		var (
			eg  commitment.ElGamal
			zkp zkpok.NoopZKproof
		)
		buf := bytes.NewBuffer(data)
		if err := eg.Decode(buf); err != nil {
			return fmt.Errorf("decode: eg %v", err)
		}
		if err := zkp.Decode(buf); err != nil {
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

// Lin computes locally a linear combination of the secrets
func Lin(alpha, beta *big.Int, a, b *TDSecret, cLabel string) *TDSecret {
	tds := &TDSecret{}
	tds.label = cLabel
	tds.server = a.server
	tds.egf = a.egf
	tds.t = a.t

	tds.skShare = new(big.Int).Mul(alpha, a.skShare)
	tmp := new(big.Int).Mul(beta, b.skShare)
	tds.skShare.Add(tds.skShare, tmp)

	makeEGLin := func(aeg, beg *commitment.ElGamal) *commitment.ElGamal {
		result := tds.egf.Neutral()
		result.Compose(result, aeg)
		result.Exp(result, alpha)
		tmp := tds.egf.Neutral()
		tmp.Compose(tmp, beg)
		tmp.Exp(tmp, beta)
		result.Compose(result, tmp)

		return result
	}

	tds.egs = make([]*commitment.ElGamal, len(a.egs))
	tds.egs[a.pid] = makeEGLin(a.egs[a.pid], b.egs[b.pid])
	for pid, eg := range a.egs {
		if eg != nil {
			tds.egs[pid] = makeEGLin(a.egs[pid], b.egs[pid])
		}
	}

	return tds
}
