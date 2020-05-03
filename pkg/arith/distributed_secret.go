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
	label   string
	skShare *big.Int
	server  sync.Server
}

// NewDSecret returns a pointer to new DSecret instance
func NewDSecret(label string, skShare *big.Int, server sync.Server) *DSecret {
	return &DSecret{
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
	eg  *commitment.ElGamal
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
		if secret == nil {
			sum.Add(sum, tds.skShare)
		} else {
			sum.Add(sum, secret)
		}
	}

	return sum, nil
}

// Exp computes a common public key and its share related to this secret
func (tds *TDSecret) Exp(pid uint16) (*TDKey, error) {
	// TODO: keep it somewhere
	group := curve.NewSecp256k1Group()
	tdk := &TDKey{}
	tdk.secret = tds
	tdk.pkShare = group.ScalarBaseMult(tds.skShare)

	// TODO: add EGRefresh
	toSendBuf := &bytes.Buffer{}
	if err := group.Encode(tdk.pkShare, toSendBuf); err != nil {
		return nil, fmt.Errorf("Encoding tkd.pkShare in Exp: %v", err)
	}

	tdk.pkShares = make([]curve.Point, len(tds.egs))

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

	lagrangeElement := func(index int, value curve.Point, group curve.Group, nProc uint16) curve.Point {
		numerator := big.NewInt(1)
		denominator := big.NewInt(1)

		bigIndex := big.NewInt(int64(index))

		for j := 0; j < int(nProc); j++ {
			if index != j {
				argument := big.NewInt(int64(j))

				partialNumerator := new(big.Int).Neg(new(big.Int).Add(argument, big.NewInt(1)))
				partialDenominator := new(big.Int).Sub(bigIndex, argument)

				numerator.Mul(numerator, partialNumerator)
				numerator.Mod(numerator, group.Order())

				denominator.Mul(denominator, partialDenominator)
				denominator.Mod(denominator, group.Order())
			}
		}

		denominator.ModInverse(denominator, group.Order())

		scale := new(big.Int).Mul(numerator, denominator)
		scale.Mod(scale, group.Order())

		element := group.ScalarMult(value, scale)
		return element
	}

	// TODO: Add possibility that someone didn't send his share
	var wg stdsync.WaitGroup
	channel := make(chan curve.Point, nProc)
	counter := tds.t

	for i, value := range tdk.pkShares {
		if value != nil {
			wg.Add(1)
			go func(i int, value curve.Point) {
				defer wg.Done()
				channel <- lagrangeElement(i, value, group, uint16(nProc))
			}(i, value)
			counter = counter - 1
		} else if i == int(pid) {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				channel <- lagrangeElement(i, tdk.pkShare, group, uint16(nProc))
			}(i)
			counter = counter - 1
		}
		if counter == 0 {
			break
		}
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
func Gen(label string, server sync.Server, egf *commitment.ElGamalFactory, nProc uint16) (*ADSecret, error) {
	var err error
	// create a secret
	ads := &ADSecret{DSecret: DSecret{label: label, server: server}, egf: egf}
	if ads.skShare, err = rand.Int(randReader, Q); err != nil {
		return nil, err
	}
	if ads.r, err = rand.Int(randReader, Q); err != nil {
		return nil, err
	}

	// create a commitment and a zkpok
	ads.eg = egf.Create(ads.skShare, ads.r)
	// TODO: replace with a proper zkpok when it's ready
	zkp := zkpok.NoopZKproof{}

	toSendBuf := &bytes.Buffer{}
	if err := ads.eg.Encode(toSendBuf); err != nil {
		return nil, err
	}
	if err := zkp.Encode(toSendBuf); err != nil {
		return nil, err
	}

	// TODO: reimplement after ZKPs are implemented
	ads.egs = make([]*commitment.ElGamal, nProc)
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

	tds.eg = makeEGLin(a.eg, b.eg)
	tds.egs = make([]*commitment.ElGamal, len(a.egs))
	for pid, eg := range a.egs {
		if eg != nil {
			tds.egs[pid] = makeEGLin(a.egs[pid], b.egs[pid])
		}
	}

	return tds
}
