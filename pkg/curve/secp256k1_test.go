package curve_test

import (
	"bytes"
	"crypto/rand"
	"math/big"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"gitlab.com/alephledger/threshold-ecdsa/pkg/curve"
)

var _ = Describe("Secp256k1 Test", func() {

	var (
		secp256k1 curve.Group
	)

	BeforeEach(func() {
		secp256k1 = curve.NewSecp256k1Group()
	})

	Describe("Zero points argument functions", func() {
		It("Test of Order", func() {
			orderResult := secp256k1.Order()
			ord, _ := big.NewInt(0).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
			Expect(ord.Cmp(orderResult) == 0).To(BeTrue())
		})

		It("Test of Gen", func() {
			a := secp256k1.Gen()
			b := secp256k1.ScalarBaseMult(big.NewInt(1))
			Expect(secp256k1.Equal(a, b)).To(BeTrue())
		})

		It("Test of Neutral", func() {
			a := secp256k1.Neutral()
			b := secp256k1.ScalarBaseMult(big.NewInt(0))
			Expect(secp256k1.Equal(a, b)).To(BeTrue())
		})

		It("Test of ScalarBaseMult", func() {
			a := secp256k1.Gen()
			b := secp256k1.ScalarBaseMult(big.NewInt(1))
			Expect(secp256k1.Equal(a, b)).To(BeTrue())
		})
	})

	Describe("One point argument functions", func() {
		It("Test of ScalarMult", func() {
			scalarMultResult := secp256k1.ScalarMult(secp256k1.Gen(), big.NewInt(2))
			a := secp256k1.ScalarBaseMult(big.NewInt(2))
			Expect(secp256k1.Equal(a, scalarMultResult)).To(BeTrue())
		})

		It("Test of Marshal", func() {
			r, _ := rand.Int(rand.Reader, secp256k1.Order())
			a := secp256k1.ScalarBaseMult(r)

			rw := bytes.Buffer{}
			err := secp256k1.Encode(a, &rw)
			Expect(err).NotTo(HaveOccurred())

			b, err := secp256k1.Decode(&rw)
			Expect(err).NotTo(HaveOccurred())

			Expect(secp256k1.Equal(a, b)).To(BeTrue())
		})

		It("Test of Neg", func() {
			a := secp256k1.Neg(secp256k1.Gen())
			b := secp256k1.ScalarBaseMult(big.NewInt(1).Sub(secp256k1.Order(), big.NewInt(1)))
			Expect(secp256k1.Equal(a, b)).To(BeTrue())
		})
	})

	Describe("Two points argument functions", func() {
		Describe("Test of Add", func() {
			It("Both elements are neutral", func() {
				a := secp256k1.Neutral()
				b := secp256k1.Neutral()
				Expect(secp256k1.Equal(a, secp256k1.Add(a, b))).To(BeTrue())
			})

			It("One element is neutral", func() {
				a := secp256k1.Neutral()
				b := secp256k1.Gen()
				Expect(secp256k1.Equal(b, secp256k1.Add(a, b))).To(BeTrue())
				Expect(secp256k1.Equal(b, secp256k1.Add(b, a))).To(BeTrue())
			})

			It("None element is neutral", func() {
				a := secp256k1.ScalarBaseMult(big.NewInt(1))
				b := secp256k1.ScalarBaseMult(big.NewInt(2))
				Expect(secp256k1.Equal(secp256k1.ScalarBaseMult(big.NewInt(3)), secp256k1.Add(a, b))).To(BeTrue())
			})

			It("Double element", func() {
				a := secp256k1.ScalarBaseMult(big.NewInt(1))
				b := secp256k1.ScalarBaseMult(big.NewInt(1))
				Expect(secp256k1.Equal(secp256k1.ScalarBaseMult(big.NewInt(2)), secp256k1.Add(a, b))).To(BeTrue())
			})
		})

		It("Test of Equal", func() {
			a := secp256k1.Gen()
			b := secp256k1.ScalarBaseMult(big.NewInt(1))
			c := secp256k1.ScalarBaseMult(big.NewInt(2))
			Expect(secp256k1.Equal(a, b)).To(BeTrue())
			Expect(secp256k1.Equal(a, c)).To(BeFalse())
		})
	})
})
