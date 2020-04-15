package group_test

import (
	"math/big"

	. "."
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Elem Test", func() {
	var (
		g Elem
		h Elem
	)
	BeforeEach(func() {
		g = NewElem(big.NewInt(2))
		h = NewElem(big.NewInt(3))
	})
	It("Cmp Diff Test", func() {
		result := NewElem(big.NewInt(0)).Cmp(g, h)
		Expect(result).To(Equal(false))
	})
	It("Cmp Same Test", func() {
		g = NewElem(big.NewInt(3))
		result := NewElem(big.NewInt(0)).Cmp(g, h)
		Expect(result).To(Equal(true))
	})
	It("Add Test", func() {
		result := NewElem(big.NewInt(0)).Add(g, h)
		cmpResult := NewElem(big.NewInt(0)).Cmp(result, NewElem(big.NewInt(5)))
		Expect(cmpResult).To(Equal(true))
	})
	It("Mult Test", func() {
		result := NewElem(big.NewInt(0)).Mult(g, big.NewInt(3))
		cmpResult := NewElem(big.NewInt(0)).Cmp(result, NewElem(big.NewInt(6)))
		Expect(cmpResult).To(Equal(true))
	})
	It("Inverse Test", func() {
		result := NewElem(big.NewInt(0)).Inverse(g)
		cmpResult := NewElem(big.NewInt(0)).Cmp(result, NewElem(big.NewInt(-2)))
		Expect(cmpResult).To(Equal(true))
	})
	It("Marshal-Unmarshal Test", func() {
		result := NewElem(big.NewInt(0)).Unmarshal(g.Marshal())
		cmpResult := NewElem(big.NewInt(0)).Cmp(result, g)
		Expect(cmpResult).To(Equal(true))
	})
})
