package arith_test

import (
	"math/big"
	"math/rand"
	stdsync "sync"
	"time"

	"gitlab.com/alephledger/threshold-ecdsa/pkg/arith"
	"gitlab.com/alephledger/threshold-ecdsa/pkg/crypto/commitment"
	"gitlab.com/alephledger/threshold-ecdsa/pkg/curve"
	"gitlab.com/alephledger/threshold-ecdsa/pkg/sync"

	"github.com/binance-chain/tss-lib/crypto/paillier"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"gitlab.com/alephledger/core-go/pkg/network"
	"gitlab.com/alephledger/core-go/pkg/tests"
)

var _ = Describe("Secret Test", func() {

	var (
		nProc     uint16
		netservs  []network.Server
		syncservs []sync.Server
		roundTime time.Duration
		start     time.Time
		label     string
		wg        stdsync.WaitGroup
		errors    []error
		group     curve.Group
	)

	JustBeforeEach(func() {
		wg = stdsync.WaitGroup{}
		netservs = tests.NewNetwork(int(nProc), time.Millisecond*100)
		syncservs = make([]sync.Server, int(nProc))
		start = time.Now().Add(50 * time.Millisecond)
		for i := uint16(0); i < nProc; i++ {
			syncservs[i] = sync.NewServer(i, nProc, start, roundTime, netservs[i])
			syncservs[i].Start()
		}
		errors = make([]error, nProc)
	})

	BeforeEach(func() {
		label = "x"
		roundTime = 100 * time.Millisecond
		rand.Seed(1729)
		group = curve.NewSecp256k1Group()
	})

	AfterEach(func() {
		for i := uint16(0); i < nProc; i++ {
			syncservs[i].Stop()
		}
		tests.CloseNetwork(netservs)
	})

	genSecret := func(ads []*arith.ADSecret, label string, egf *commitment.ElGamalFactory) {
		wg.Add(int(nProc))
		for i := uint16(0); i < nProc; i++ {
			go func(i uint16) {
				defer wg.Done()
				ads[i], errors[i] = arith.Gen(label, syncservs[i], egf, i, nProc)
			}(i)
		}

		wg.Wait()
		for i := uint16(0); i < nProc; i++ {
			Expect(errors[i]).NotTo(HaveOccurred())
			Expect(ads[i]).NotTo(BeNil())
		}
	}

	genKey := func(dks []*arith.DKey) {
		wg.Add(int(nProc))
		for i := uint16(0); i < nProc; i++ {
			go func(i uint16) {
				defer wg.Done()
				dks[i], errors[i] = arith.GenExpReveal(i, label, syncservs[i], nProc, group)
			}(i)
		}

		wg.Wait()
		for i := uint16(0); i < nProc; i++ {
			Expect(errors[i]).NotTo(HaveOccurred())
			Expect(dks[i]).NotTo(BeNil())
		}
	}

	reshare := func(ads []*arith.ADSecret, tds []*arith.TDSecret, t uint16) {
		wg.Add(int(nProc))
		for i := uint16(0); i < nProc; i++ {
			go func(i uint16) {
				defer wg.Done()
				tds[i], errors[i] = ads[i].Reshare(t)
			}(i)
		}
		wg.Wait()

		for i := uint16(0); i < nProc; i++ {
			Expect(errors[i]).NotTo(HaveOccurred())
			Expect(tds[i]).NotTo(BeNil())
		}
	}

	exp := func(tds []*arith.TDSecret, tdks []*arith.TDKey) {
		wg.Add(int(nProc))
		for i := uint16(0); i < nProc; i++ {
			go func(i uint16) {
				defer wg.Done()
				tdks[i], errors[i] = tds[i].Exp()
			}(i)
		}
		wg.Wait()

		for i := uint16(0); i < nProc; i++ {
			Expect(errors[i]).NotTo(HaveOccurred())
			Expect(tdks[i]).NotTo(BeNil())
		}
	}

	mult := func(a, b, c []*arith.ADSecret, cl string) {
		privs := make([]*paillier.PrivateKey, nProc)
		pubs := make([]*paillier.PublicKey, nProc)
		bitLen := 264
		timeout := 1 * time.Second

		wg.Add(int(nProc))
		for i := uint16(0); i < nProc; i++ {
			go func(i uint16) {
				defer wg.Done()
				privs[i], pubs[i], errors[i] = paillier.GenerateKeyPair(bitLen, timeout)
			}(i)
		}
		wg.Wait()

		for i := uint16(0); i < nProc; i++ {
			Expect(errors[i]).NotTo(HaveOccurred())
			Expect(privs[i]).NotTo(BeNil())
			Expect(pubs[i]).NotTo(BeNil())
		}

		wg.Add(int(nProc))
		for i := uint16(0); i < nProc; i++ {
			go func(i uint16) {
				defer wg.Done()
				c[i], errors[i] = arith.Mult(a[i], b[i], cl, privs[i], pubs[i], pubs)
			}(i)
		}
		wg.Wait()

		for i := uint16(0); i < nProc; i++ {
			Expect(errors[i]).NotTo(HaveOccurred())
			Expect(c[i]).NotTo(BeNil())
		}

	}

	Describe("Generating arithmetic distributed secrets with arith.Gen", func() {

		var (
			ads []*arith.ADSecret
			egf *commitment.ElGamalFactory
		)

		Context("Two parties", func() {

			BeforeEach(func() {
				nProc = 2
				ads = make([]*arith.ADSecret, nProc)
				egsk := group.ScalarBaseMult(big.NewInt(rand.Int63()))
				egf = commitment.NewElGamalFactory(egsk)
			})

			Context("Alice and Bob are honest and alive", func() {

				It("Should finish for alice and bob", func() {
					genSecret(ads, label, egf)
				})
			})
		})

		Context("Ten parties", func() {

			BeforeEach(func() {
				nProc = 10
				ads = make([]*arith.ADSecret, nProc)
				egsk := group.ScalarBaseMult(big.NewInt(rand.Int63()))
				egf = commitment.NewElGamalFactory(egsk)
			})

			Context("All parties are honest and alive", func() {

				It("Should finish for all parties", func() {
					genSecret(ads, label, egf)
				})
			})
		})
	})

	Describe("Generating distributed public keys with arith.GenExpReveal", func() {

		var (
			dks []*arith.DKey
		)

		Context("Two parties", func() {

			BeforeEach(func() {
				nProc = 2
				dks = make([]*arith.DKey, nProc)
			})

			Context("Alice and Bob are honest and alive", func() {

				It("Should finish for alice and bob", func() {
					genKey(dks)
				})
			})
		})

		Context("Ten parties", func() {

			BeforeEach(func() {
				nProc = 10
				dks = make([]*arith.DKey, nProc)
			})

			Context("All parties are honest and alive", func() {

				It("Should finish for all parties", func() {
					genKey(dks)
				})
			})
		})
	})

	Describe("Resharing arithmetic distributed secrets", func() {

		var (
			t   uint16
			ads []*arith.ADSecret
			tds []*arith.TDSecret
			egf *commitment.ElGamalFactory
		)

		Context("Two parties", func() {

			BeforeEach(func() {
				nProc = 2
				ads = make([]*arith.ADSecret, nProc)
				tds = make([]*arith.TDSecret, nProc)
				egsk := group.ScalarBaseMult(big.NewInt(rand.Int63()))
				egf = commitment.NewElGamalFactory(egsk)
			})

			Context("Alice and Bob are honest and alive", func() {

				Context("Threshold equals 1", func() {

					BeforeEach(func() {
						t = 1
					})

					It("Should finish for alice and bob", func() {
						genSecret(ads, label, egf)
						reshare(ads, tds, t)
					})
				})

				Context("Threshold equals 2", func() {

					BeforeEach(func() {
						t = 2
					})

					It("Should finish for alice and bob", func() {
						genSecret(ads, label, egf)
						reshare(ads, tds, t)
					})
				})
			})
		})

		Context("Ten parties", func() {

			BeforeEach(func() {
				nProc = 10
				ads = make([]*arith.ADSecret, nProc)
				tds = make([]*arith.TDSecret, nProc)
				egsk := group.ScalarBaseMult(big.NewInt(rand.Int63()))
				egf = commitment.NewElGamalFactory(egsk)
			})

			Context("All parties are honest and alive", func() {

				Context("Threshold equals 1", func() {

					BeforeEach(func() {
						t = 1
					})

					It("Should finish for all parties", func() {
						genSecret(ads, label, egf)
						reshare(ads, tds, t)
					})
				})

				Context("Threshold equals 2", func() {

					BeforeEach(func() {
						t = 2
					})

					It("Should finish for all parties", func() {
						genSecret(ads, label, egf)
						reshare(ads, tds, t)
					})
				})
			})
		})
	})

	Describe("Transforming distributed secret into distributed key with arith.TDSecret.Exp", func() {

		var (
			t    uint16
			ads  []*arith.ADSecret
			tds  []*arith.TDSecret
			tdks []*arith.TDKey
			egf  *commitment.ElGamalFactory
		)

		Context("Two parties", func() {

			BeforeEach(func() {
				nProc = 2
				ads = make([]*arith.ADSecret, nProc)
				tds = make([]*arith.TDSecret, nProc)
				tdks = make([]*arith.TDKey, nProc)
				egsk := group.ScalarBaseMult(big.NewInt(rand.Int63()))
				egf = commitment.NewElGamalFactory(egsk)
			})

			Context("Alice and Bob are honest and alive", func() {

				Context("Threshold equals 1", func() {

					BeforeEach(func() {
						t = 1
					})

					It("Should finish for alice and bob", func() {
						genSecret(ads, label, egf)
						reshare(ads, tds, t)
						exp(tds, tdks)
					})
				})

				Context("Threshold equals 2", func() {

					BeforeEach(func() {
						t = 2
					})

					It("Should finish for alice and bob", func() {
						genSecret(ads, label, egf)
						reshare(ads, tds, t)
						exp(tds, tdks)
					})
				})
			})
		})

		Context("Ten parties", func() {

			BeforeEach(func() {
				nProc = 10
				ads = make([]*arith.ADSecret, nProc)
				tds = make([]*arith.TDSecret, nProc)
				tdks = make([]*arith.TDKey, nProc)
				egsk := group.ScalarBaseMult(big.NewInt(rand.Int63()))
				egf = commitment.NewElGamalFactory(egsk)
			})

			Context("All parties are honest and alive", func() {

				Context("Threshold equals 1", func() {

					BeforeEach(func() {
						t = 1
					})

					It("Should finish for all parties", func() {
						genSecret(ads, label, egf)
						reshare(ads, tds, t)
						exp(tds, tdks)
					})
				})

				Context("Threshold equals 2", func() {

					BeforeEach(func() {
						t = 2
					})

					It("Should finish for all parties", func() {
						genSecret(ads, label, egf)
						reshare(ads, tds, t)
						exp(tds, tdks)
					})
				})
			})
		})
	})

	Describe("Multiplying two secrets with arith.Mul", func() {

		var (
			a          []*arith.ADSecret
			b          []*arith.ADSecret
			c          []*arith.ADSecret
			al, bl, cl string
			egf        *commitment.ElGamalFactory
		)

		JustBeforeEach(func() {
			a = make([]*arith.ADSecret, nProc)
			b = make([]*arith.ADSecret, nProc)
			c = make([]*arith.ADSecret, nProc)
			al = "a"
			bl = "b"
			cl = "c"

			egsk := group.ScalarBaseMult(big.NewInt(rand.Int63()))
			egf = commitment.NewElGamalFactory(egsk)
		})

		Context("Two parties", func() {

			BeforeEach(func() {
				nProc = 2
			})
			Context("Alice and Bob are honest and alive", func() {

				It("Should finish for alice and bob", func() {
					wgm := stdsync.WaitGroup{}

					wgm.Add(2)
					go func() {
						defer wgm.Done()
						genSecret(a, al, egf)
					}()
					go func() {
						defer wgm.Done()
						genSecret(b, bl, egf)
					}()
					wgm.Wait()
					mult(a, b, c, cl)
				})
			})
		})

		Context("Ten parties", func() {

			BeforeEach(func() {
				nProc = 10
			})
			Context("All parties are honest and alive", func() {

				It("Should finish for all parties", func() {
					wgm := stdsync.WaitGroup{}

					wgm.Add(2)
					go func() {
						defer wgm.Done()
						genSecret(a, al, egf)
					}()
					go func() {
						defer wgm.Done()
						genSecret(b, bl, egf)
					}()
					wgm.Wait()
					mult(a, b, c, cl)
				})
			})
		})
	})
})
