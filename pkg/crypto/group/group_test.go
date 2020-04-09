package group_test

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
