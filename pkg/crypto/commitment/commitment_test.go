package commitment_test

import (
	"math/big"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"gitlab.com/alephledger/threshold-ecdsa/pkg/crypto/commitment"
	"gitlab.com/alephledger/threshold-ecdsa/pkg/curve"
)

var _ = Describe("Commitment Test", func() {
	var (
		commCreator *commitment.ElGamalFactory
		g           *commitment.ElGamal
		h           *commitment.ElGamal
		group       curve.Group
	)
	BeforeEach(func() {
		group = curve.NewSecp256k1Group()
		commCreator = commitment.NewElGamalFactory(group.ScalarBaseMult(big.NewInt(2)))
		g = commCreator.Create(big.NewInt(3), big.NewInt(5))
		h = commCreator.Create(big.NewInt(7), big.NewInt(11))
	})
	It("Cmp Diff Test", func() {
		result := commCreator.Create(new(big.Int), new(big.Int)).Cmp(g, h)
		Expect(result).To(BeFalse())
	})
	It("Cmp Same Test", func() {
		g = commCreator.Create(big.NewInt(7), big.NewInt(11))
		result := g.Cmp(g, h)
		Expect(result).To(BeTrue())
	})
	It("Compose Test", func() {
		result := commCreator.Create(new(big.Int), new(big.Int)).Compose(g, h)
		cmpResult := g.Cmp(result, commCreator.Create(big.NewInt(10), big.NewInt(16)))
		Expect(cmpResult).To(BeTrue())
	})
	It("Exp Test", func() {
		result := commCreator.Create(new(big.Int), new(big.Int)).Exp(g, big.NewInt(13))
		cmpResult := g.Cmp(result, commCreator.Create(big.NewInt(39), big.NewInt(65)))
		Expect(cmpResult).To(BeTrue())
	})
	It("Inverse Test", func() {
		result := commCreator.Create(new(big.Int), new(big.Int)).Inverse(g)
		ord, _ := new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
		cmpResult := g.Cmp(result, commCreator.Create(new(big.Int).Sub(ord, big.NewInt(3)), new(big.Int).Sub(ord, big.NewInt(5))))
		Expect(cmpResult).To(BeTrue())
	})
	It("Marshal-Unmarshal Test", func() {
		gm, _ := g.MarshalBinary()
		_ = h.UnmarshalBinary(gm)
		cmpResult := g.Cmp(h, g)
		Expect(cmpResult).To(BeTrue())
	})
})
