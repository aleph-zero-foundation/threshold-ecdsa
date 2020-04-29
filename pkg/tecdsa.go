package pkg

import (
	"fmt"
	"math/big"

	"gitlab.com/alephledger/threshold-ecdsa/pkg/arith"
	"gitlab.com/alephledger/threshold-ecdsa/pkg/crypto/commitment"
	"gitlab.com/alephledger/threshold-ecdsa/pkg/curve"
	"gitlab.com/alephledger/threshold-ecdsa/pkg/sync"
)

// Signature implements a complete signature
type Signature struct {
	r, s *big.Int
}

type presig struct {
	k, rho, eta, tau *arith.TDSecret
	t                uint16
}

// ProtocolTECDSA implements the tECDSA protocol
type ProtocolTECDSA struct {
	nProc      uint16
	key, egKey *arith.DKey
	egf        *commitment.ElGamalFactory
	presig     []*presig
	network    sync.Server
	group      curve.Group
}

// InitTECDSA constructs a new instance of tECDSA protocol and
// generates a private key for signing and a secret for commitments
func InitTECDSA(nProc uint16, network sync.Server) (*ProtocolTECDSA, error) {
	p := &ProtocolTECDSA{network: network}

	var err error
	p.group = curve.NewSecp256k1Group()
	p.key, err = arith.GenExpReveal("x", p.network, p.nProc, p.group)
	if err != nil {
		return nil, err
	}
	p.egKey, err = arith.GenExpReveal("h", p.network, p.nProc, p.group)
	if err != nil {
		return nil, err
	}
	p.egf = commitment.NewElGamalFactory(p.key.PublicKey())

	return p, nil
}

// Presign generates a new presignature
func (p *ProtocolTECDSA) Presign(t uint16) error {
	var err error
	var k, rho, eta, tau *arith.ADSecret
	if k, err = arith.Gen("k", p.network, p.egf, p.nProc); err != nil {
		return err
	}
	if rho, err = arith.Gen("rho", p.network, p.egf, p.nProc); err != nil {
		return err
	}
	if eta, err = arith.Gen("eta", p.network, p.egf, p.nProc); err != nil {
		return err
	}
	if tau, err = arith.Gen("tau", p.network, p.egf, p.nProc); err != nil {
		return err
	}

	psgn := &presig{t: t}
	if psgn.k, err = k.Reshare(t); err != nil {
		return err
	}
	if psgn.rho, err = rho.Reshare(t); err != nil {
		return err
	}
	if psgn.eta, err = eta.Reshare(t); err != nil {
		return err
	}
	if psgn.tau, err = tau.Reshare(t); err != nil {
		return err
	}

	p.presig = append(p.presig, psgn)
	return nil
}

// Sign generates a signature using a presignature prepared before
func (p *ProtocolTECDSA) Sign(message *big.Int) (*Signature, error) {
	// TODO: if the amount of presignatures falls below some threshold, use p.Presign to generate new ones
	if len(p.presig) == 0 {
		return nil, fmt.Errorf("There are no more presignatures to sign the message %v", message)
	}

	ps := p.presig[0]
	p.presig = p.presig[1:]

	kKey, err := ps.k.Exp()
	if err != nil {
		return nil, err
	}

	r := HashToBigInt(p.group.Marshal(kKey.PublicKey()))
	tau, err := ps.tau.Reveal()
	if err != nil {
		return nil, err
	}

	alpha, beta := message.Div(message, tau), r.Div(r, tau)
	sTDSecret := arith.Lin(alpha, beta, ps.rho, ps.eta, "s")

	s, err := sTDSecret.Reveal()
	if err != nil {
		return nil, err
	}

	return &Signature{r, s}, nil
}
