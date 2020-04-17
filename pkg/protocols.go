package pkg

import (
	"gitlab.com/alephledger/core-go/pkg/network"
	"math/big"
)

// Signature implements a complete signature
type Signature struct {
	r, s *big.Int
}

func hash(Elem) *big.Int { return nil }

type apresig struct {
	k, rho, eta, tau ADSecret
}

func (aps *apresig) reshare(t uint16) *tpresig {
	k, _ := aps.k.Reshare(t)
	rho, _ := aps.rho.Reshare(t)
	eta, _ := aps.eta.Reshare(t)
	tau, _ := aps.k.Reshare(t)
	return &tpresig{k, rho, eta, tau, t}
}

type tpresig struct {
	k, rho, eta, tau TDSecret
	t                uint16
}

// ProtocolTECDSA implements the tECDSA protocol
type ProtocolTECDSA struct {
	secret     ADSecret
	key, egkey DKey
	presig     []*tpresig
	network    network.Server
}

// InitTECDSA constructs a new instance of tECDSA protocol
func InitTECDSA(network network.Server) *ProtocolTECDSA {
	p := &ProtocolTECDSA{network: network}
	return p
}

// GenKey generates a private key for signing and a secret for commitments
func (p *ProtocolTECDSA) GenKey() error {
	p.secret = Gen("x", p.network, "ElGamal")
	p.key, _ = p.secret.Exp()
	p.key.RevealExp()

	p.genElGamalKey()

	return nil
}

func (p *ProtocolTECDSA) genElGamalKey() error {
	p.egkey, _ = Gen("h", p.network, "Non-malleable").Exp()
	p.key.RevealExp()

	return nil
}

// Presign generates a new presignature
func (p *ProtocolTECDSA) Presign(t uint16) {
	tps := p.additivePresign().reshare(t)

	p.presig = append(p.presig, tps)
}

func (p *ProtocolTECDSA) additivePresign() *apresig {
	k := Gen("k", p.network, "ElGamal")
	rho := Gen("rho", p.network, "ElGamal")
	eta, _ := p.mul(rho, p.secret, "eta")
	tau, _ := p.mul(k, rho, "tau")

	return &apresig{k, rho, eta, tau}
}

func (*ProtocolTECDSA) mul(ADSecret, ADSecret, string) (ADSecret, error) { return nil, nil }

// Sign generates a signature using a presignature prepared before
func (p *ProtocolTECDSA) Sign(message *big.Int) Signature {
	tps := p.presig[0]
	p.presig = p.presig[1:]

	kKey, _ := tps.k.Exp()
	R, _ := kKey.RevealExp()
	r := hash(R)

	tau, _ := tps.tau.Reveal()

	a, b := message.Div(message, tau), r.Div(r, tau)
	sTDSecret := p.lin(a, tps.rho, b, tps.eta)

	s, _ := sTDSecret.Reveal()

	return Signature{r, s}
}

// Lin computes locally a linear combination of given parameters
func (p *ProtocolTECDSA) lin(*big.Int, TDSecret, *big.Int, TDSecret) TDSecret { return nil }
