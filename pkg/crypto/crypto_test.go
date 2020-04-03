package crypto_test

import (
	"math/big"

	. "."

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("groupElem Test", func() {
	var (
		g GroupElem
		h GroupElem
	)
	BeforeEach(func() {
		g = NewGroupElem(big.NewInt(2))
		h = NewGroupElem(big.NewInt(3))
	})
	It("Cmp Diff Test", func() {
		result := NewGroupElem(big.NewInt(0)).Cmp(g, h)
		Expect(result).To(Equal(false))
	})
	It("Cmp Same Test", func() {
		g = NewGroupElem(big.NewInt(3))
		result := NewGroupElem(big.NewInt(0)).Cmp(g, h)
		Expect(result).To(Equal(true))
	})
	It("Operation Test", func() {
		result := NewGroupElem(big.NewInt(0)).Operation(g, h)
		cmpResult := NewGroupElem(big.NewInt(0)).Cmp(result, NewGroupElem(big.NewInt(5)))
		Expect(cmpResult).To(Equal(true))
	})
	It("Exp Test", func() {
		result := NewGroupElem(big.NewInt(0)).Exp(g, big.NewInt(3))
		cmpResult := NewGroupElem(big.NewInt(0)).Cmp(result, NewGroupElem(big.NewInt(6)))
		Expect(cmpResult).To(Equal(true))
	})
	It("Inverse Test", func() {
		result := NewGroupElem(big.NewInt(0)).Inverse(g)
		cmpResult := NewGroupElem(big.NewInt(0)).Cmp(result, NewGroupElem(big.NewInt(-2)))
		Expect(cmpResult).To(Equal(true))
	})
	It("Marshal-Unmarshal Test", func() {
		result := NewGroupElem(big.NewInt(0)).Unmarshal(g.Marshal())
		cmpResult := NewGroupElem(big.NewInt(0)).Cmp(result, g)
		Expect(cmpResult).To(Equal(true))
	})
})

var _ = Describe("Commitment Test", func() {
	var (
		commCreator CommitmentCreator
		g           Commitment
		h           Commitment
	)
	BeforeEach(func() {
		commCreator = NewCommitmentCreator(big.NewInt(2))
		g = commCreator.Create(big.NewInt(3), big.NewInt(5))
		h = commCreator.Create(big.NewInt(7), big.NewInt(11))
	})
	It("Cmp Diff Test", func() {
		result := commCreator.Create(big.NewInt(0), big.NewInt(0)).Cmp(g, h)
		Expect(result).To(Equal(false))
	})
	It("Cmp Same Test", func() {
		g = commCreator.Create(big.NewInt(7), big.NewInt(11))
		result := commCreator.Create(big.NewInt(0), big.NewInt(0)).Cmp(g, h)
		Expect(result).To(Equal(true))
	})
	It("Compose Test", func() {
		result := commCreator.Create(big.NewInt(0), big.NewInt(0)).Compose(g, h)
		cmpResult := commCreator.Create(big.NewInt(0), big.NewInt(0)).Cmp(result, commCreator.Create(big.NewInt(10), big.NewInt(16)))
		Expect(cmpResult).To(Equal(true))
	})
	It("Exp Test", func() {
		result := commCreator.Create(big.NewInt(0), big.NewInt(0)).Exp(g, big.NewInt(13))
		cmpResult := commCreator.Create(big.NewInt(0), big.NewInt(0)).Cmp(result, commCreator.Create(big.NewInt(39), big.NewInt(65)))
		Expect(cmpResult).To(Equal(true))
	})
	It("Inverse Test", func() {
		result := commCreator.Create(big.NewInt(0), big.NewInt(0)).Inverse(g)
		cmpResult := commCreator.Create(big.NewInt(0), big.NewInt(0)).Cmp(result, commCreator.Create(big.NewInt(-3), big.NewInt(-5)))
		Expect(cmpResult).To(Equal(true))
	})
	It("Marshal-Unmarshal Test", func() {
		result := h.Unmarshal(g.Marshal())
		cmpResult := commCreator.Create(big.NewInt(0), big.NewInt(0)).Cmp(result, g)
		Expect(cmpResult).To(Equal(true))
	})
})
