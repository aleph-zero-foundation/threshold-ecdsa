package zkpok_test

import (
	"bytes"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"gitlab.com/alephledger/threshold-ecdsa/pkg/crypto/commitment"
	"gitlab.com/alephledger/threshold-ecdsa/pkg/crypto/zkpok"
	"gitlab.com/alephledger/threshold-ecdsa/pkg/curve"
	"math/big"
)

var _ = Describe("ZKEGKnow", func() {
	var (
		fct        *commitment.ElGamalFactory
		c1         *commitment.ElGamal
		c2         *commitment.ElGamal
		cRefreshed *commitment.ElGamal
		g          curve.Group
		h          curve.Point
		value      *big.Int
		value2     *big.Int
		r1         *big.Int
		r2         *big.Int
		rRefresh   *big.Int
		err        error
	)
	BeforeEach(func() {
		g = curve.NewSecp256k1Group()
		h = g.Gen()
		h = g.ScalarMult(h, big.NewInt(213))
		fct = commitment.NewElGamalFactory(h)
		value = big.NewInt(5)
		value2 = big.NewInt(11)
		r1 = big.NewInt(13)
		r2 = big.NewInt(14)
		rRefresh = big.NewInt(17)
		c1 = fct.Create(value, r1)
		c2 = fct.Create(value2, r2)
		cRefreshed = fct.Neutral()
		cRefreshed.Compose(c1, fct.Create(big.NewInt(0), rRefresh))

	})

	Describe("ZKEGKnow", func() {
		var (
			z1 *zkpok.ZKEGKnow
		)
		It("Verify Correct Proof", func() {
			z1, err := zkpok.NewZKEGKnow(fct, c1, value, r1)
			Expect(err).NotTo(HaveOccurred())

			err = z1.Verify(fct, c1)
			Expect(err).NotTo(HaveOccurred())
		})
		It("Verify incorrect Proof", func() {
			z1, err = zkpok.NewZKEGKnow(fct, c1, value, r1)
			Expect(err).NotTo(HaveOccurred())

			err = z1.Verify(fct, c2)
			Expect(err).To(HaveOccurred())
		})
		It("Encode-Decode Test", func() {
			z1, err = zkpok.NewZKEGKnow(fct, c1, value, r1)
			Expect(err).NotTo(HaveOccurred())

			buf := &bytes.Buffer{}
			err = z1.Encode(buf)
			Expect(err).NotTo(HaveOccurred())

			z2 := &zkpok.ZKEGKnow{}
			err = z2.Decode(buf)
			Expect(err).NotTo(HaveOccurred())

			err = z2.Verify(fct, c1)
			Expect(err).NotTo(HaveOccurred())

			err := z2.Verify(fct, c2)
			Expect(err).To(HaveOccurred())
		})
	})

	Describe("ZKEGRefresh", func() {
		var (
			z1 *zkpok.ZKEGRefresh
		)
		It("Verify Correct Proof", func() {
			z1, err = zkpok.NewZKEGRefresh(fct, c1, cRefreshed, rRefresh)
			Expect(err).NotTo(HaveOccurred())

			err = z1.Verify(fct, c1, cRefreshed)
			Expect(err).NotTo(HaveOccurred())
		})
		It("Verify incorrect Proof", func() {
			z1, err := zkpok.NewZKEGRefresh(fct, c1, cRefreshed, rRefresh)
			Expect(err).NotTo(HaveOccurred())

			err = z1.Verify(fct, c1, c2)
			Expect(err).To(HaveOccurred())
		})
		It("Encode-Decode Test", func() {
			z1, err := zkpok.NewZKEGRefresh(fct, c1, cRefreshed, rRefresh)
			Expect(err).NotTo(HaveOccurred())

			buf := &bytes.Buffer{}
			err = z1.Encode(buf)
			Expect(err).NotTo(HaveOccurred())

			z2 := zkpok.ZKEGRefresh{}
			err = z2.Decode(buf)
			Expect(err).NotTo(HaveOccurred())

			err = z2.Verify(fct, c1, cRefreshed)
			Expect(err).NotTo(HaveOccurred())

			err = z2.Verify(fct, c2, cRefreshed)
			Expect(err).To(HaveOccurred())
		})
	})
})
