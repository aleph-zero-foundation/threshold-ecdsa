package group_test

import (
	"math/big"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"gitlab.com/alephledger/threshold-ecdsa/pkg/group"
)

var _ = Describe("Elem Test", func() {
	var (
		g group.Elem
		h group.Elem
	)
	BeforeEach(func() {
		g = group.NewFieldElem(big.NewInt(2))
		h = group.NewFieldElem(big.NewInt(3))
	})
	It("Cmp Diff Test", func() {
		result := g.Cmp(g, h)
		Expect(result).To(BeFalse())
	})
	It("Cmp Same Test", func() {
		g = group.NewFieldElem(big.NewInt(3))
		result := g.Cmp(g, h)
		Expect(result).To(BeTrue())
	})
	It("Add Test", func() {
		result := group.NewFieldElem(big.NewInt(0)).Add(g, h)
		cmpResult := g.Cmp(result, group.NewFieldElem(big.NewInt(5)))
		Expect(cmpResult).To(BeTrue())
	})
	It("Mult Test", func() {
		result := group.NewFieldElem(big.NewInt(0)).Mult(g, big.NewInt(3))
		cmpResult := g.Cmp(result, group.NewFieldElem(big.NewInt(6)))
		Expect(cmpResult).To(BeTrue())
	})
	It("Inverse Test", func() {
		result := group.NewFieldElem(big.NewInt(0)).Inverse(g)
		cmpResult := g.Cmp(result, group.NewFieldElem(big.NewInt(-2)))
		Expect(cmpResult).To(BeTrue())
	})
	It("Marshal-Unmarshal Test", func() {
		result := &group.FieldElem{}
		gm, _ := g.MarshalBinary()
		_ = result.UnmarshalBinary(gm)
		cmpResult := g.Cmp(result, g)
		Expect(cmpResult).To(BeTrue())
	})
})
