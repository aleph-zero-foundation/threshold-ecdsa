package commitment_test

import (
	"math/big"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"gitlab.com/alephledger/threshold-ecdsa/pkg/crypto/commitment"
	"gitlab.com/alephledger/threshold-ecdsa/pkg/group"
)

var _ = Describe("Commitment Test", func() {
	var (
		commCreator *commitment.ElGamalFactory
		g           *commitment.ElGamal
		h           *commitment.ElGamal
	)
	BeforeEach(func() {
		commCreator = commitment.NewElGamalFactory(group.NewFieldElem(big.NewInt(2)))
		g = commCreator.Create(big.NewInt(3), big.NewInt(5))
		h = commCreator.Create(big.NewInt(7), big.NewInt(11))
	})
	It("Cmp Diff Test", func() {
		result := commCreator.Create(big.NewInt(0), big.NewInt(0)).Cmp(g, h)
		Expect(result).To(BeFalse())
	})
	It("Cmp Same Test", func() {
		g = commCreator.Create(big.NewInt(7), big.NewInt(11))
		result := g.Cmp(g, h)
		Expect(result).To(BeTrue())
	})
	It("Compose Test", func() {
		result := commCreator.Create(big.NewInt(0), big.NewInt(0)).Compose(g, h)
		cmpResult := g.Cmp(result, commCreator.Create(big.NewInt(10), big.NewInt(16)))
		Expect(cmpResult).To(BeTrue())
	})
	It("Exp Test", func() {
		result := commCreator.Create(big.NewInt(0), big.NewInt(0)).Exp(g, big.NewInt(13))
		cmpResult := g.Cmp(result, commCreator.Create(big.NewInt(39), big.NewInt(65)))
		Expect(cmpResult).To(BeTrue())
	})
	It("Inverse Test", func() {
		result := commCreator.Create(big.NewInt(0), big.NewInt(0)).Inverse(g)
		cmpResult := g.Cmp(result, commCreator.Create(big.NewInt(-3), big.NewInt(-5)))
		Expect(cmpResult).To(BeTrue())
	})
	It("Marshal-Unmarshal Test", func() {
		gm, _ := g.MarshalBinary()
		_ = h.UnmarshalBinary(gm)
		cmpResult := g.Cmp(h, g)
		Expect(cmpResult).To(BeTrue())
	})
})
