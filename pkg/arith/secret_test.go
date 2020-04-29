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
		netservs = tests.NewNetwork(int(nProc))
		syncservs = make([]sync.Server, int(nProc))
		for i := uint16(0); i < nProc; i++ {
			syncservs[i] = sync.NewServer(i, nProc, start, roundTime, netservs[i])
		}
	})

	BeforeEach(func() {
		start = time.Now().Add(time.Millisecond * 10)
		roundTime = 100 * time.Millisecond
		rand.Seed(1729)
		group = curve.NewSecp256k1Group()
	})

	JustAfterEach(func() {
		tests.CloseNetwork(netservs)
	})

	Describe("Two parties", func() {

		var (
			alice, bob uint16
		)

		gen := func(ads []*arith.ADSecret, label string, egf *commitment.ElGamalFactory) {
			wg.Add(int(nProc))
			go func() {
				defer wg.Done()
				ads[alice], errors[alice] = arith.Gen(label, syncservs[alice], egf, nProc)
			}()
			go func() {
				defer wg.Done()
				ads[bob], errors[bob] = arith.Gen(label, syncservs[bob], egf, nProc)
			}()
			wg.Wait()

			Expect(errors[alice]).NotTo(HaveOccurred())
			Expect(errors[bob]).NotTo(HaveOccurred())
		}

		BeforeEach(func() {
			alice = 0
			bob = 1
			nProc = 2
			label = "x"
		})

		Describe("Generating arithmetic distributed secrets with arith.Gen", func() {

			var (
				ads []*arith.ADSecret
				egf *commitment.ElGamalFactory
			)

			Context("Alice and Bob are honest and alive", func() {

				BeforeEach(func() {
					ads = make([]*arith.ADSecret, nProc)
					errors = make([]error, nProc)
					egsk := group.ScalarBaseMult(big.NewInt(rand.Int63()))
					egf = commitment.NewElGamalFactory(egsk)
				})

				It("Should finish for alice and bob", func() {
					gen(ads, label, egf)
				})
			})
		})

		Describe("Generating distributed public keys with arith.GenExpReveal", func() {
			var (
				dks []*arith.DKey
			)

			Context("Alice and Bob are honest and alive", func() {

				BeforeEach(func() {
					dks = make([]*arith.DKey, nProc)
					errors = make([]error, nProc)
				})

				It("Should finish for alice and bob", func() {
					wg.Add(int(nProc))
					go func() {
						defer wg.Done()
						dks[alice], errors[alice] = arith.GenExpReveal(label, syncservs[alice], nProc, group)
					}()
					go func() {
						defer wg.Done()
						dks[bob], errors[bob] = arith.GenExpReveal(label, syncservs[bob], nProc, group)
					}()
					wg.Wait()

					Expect(errors[alice]).NotTo(HaveOccurred())
					Expect(errors[bob]).NotTo(HaveOccurred())

				})
			})
		})

		Describe("Resharing arithmetic distributed secrets", func() {

			var (
				t    uint16
				ads  []*arith.ADSecret
				tds  []*arith.TDSecret
				egsk curve.Point
				egf  *commitment.ElGamalFactory
			)

			Context("Alice and Bob are honest and alive", func() {

				BeforeEach(func() {
					ads = make([]*arith.ADSecret, nProc)
					tds = make([]*arith.TDSecret, nProc)
					errors = make([]error, nProc)
					egsk = group.ScalarBaseMult(big.NewInt(rand.Int63()))
					egf = commitment.NewElGamalFactory(egsk)
				})

				Context("Threshold equals 1", func() {
					BeforeEach(func() {
						t = 1
					})
					It("Should finish for alice and bob", func() {
						wg.Add(int(nProc))
						go func() {
							defer wg.Done()
							ads[alice], errors[alice] = arith.Gen(label, syncservs[alice], egf, nProc)
						}()
						go func() {
							defer wg.Done()
							ads[bob], errors[bob] = arith.Gen(label, syncservs[bob], egf, nProc)
						}()
						wg.Wait()

						Expect(errors[alice]).NotTo(HaveOccurred())
						Expect(errors[bob]).NotTo(HaveOccurred())
						Expect(ads[alice]).NotTo(BeNil())
						Expect(ads[bob]).NotTo(BeNil())

						wg.Add(int(nProc))
						go func() {
							defer wg.Done()
							tds[alice], errors[alice] = ads[alice].Reshare(t)
						}()
						go func() {
							defer wg.Done()
							tds[bob], errors[bob] = ads[bob].Reshare(t)
						}()
						wg.Wait()

						Expect(errors[alice]).NotTo(HaveOccurred())
						Expect(errors[bob]).NotTo(HaveOccurred())
						Expect(tds[alice]).NotTo(BeNil())
						Expect(tds[bob]).NotTo(BeNil())
					})
				})

				Context("Threshold equals 2", func() {
					BeforeEach(func() {
						t = 2
					})
					It("Should finish for alice and bob", func() {
						wg.Add(int(nProc))
						go func() {
							defer wg.Done()
							ads[alice], errors[alice] = arith.Gen(label, syncservs[alice], egf, nProc)
						}()
						go func() {
							defer wg.Done()
							ads[bob], errors[bob] = arith.Gen(label, syncservs[bob], egf, nProc)
						}()
						wg.Wait()

						Expect(errors[alice]).NotTo(HaveOccurred())
						Expect(errors[bob]).NotTo(HaveOccurred())
						Expect(ads[alice]).NotTo(BeNil())
						Expect(ads[bob]).NotTo(BeNil())

						wg.Add(int(nProc))
						go func() {
							defer wg.Done()
							tds[alice], errors[alice] = ads[alice].Reshare(t)
						}()
						go func() {
							defer wg.Done()
							tds[bob], errors[bob] = ads[bob].Reshare(t)
						}()
						wg.Wait()

						Expect(errors[alice]).NotTo(HaveOccurred())
						Expect(errors[bob]).NotTo(HaveOccurred())
						Expect(tds[alice]).NotTo(BeNil())
						Expect(tds[bob]).NotTo(BeNil())
					})
				})
			})

		})

		Describe("Multiplying two secrets with arith.Mul", func() {

			var (
				a, b, c    []*arith.ADSecret
				al, bl, cl string
				egf        *commitment.ElGamalFactory
			)

			Context("Alice and Bob are honest and alive", func() {

				BeforeEach(func() {
					a = make([]*arith.ADSecret, nProc)
					b = make([]*arith.ADSecret, nProc)
					c = make([]*arith.ADSecret, nProc)
					al = "a"
					bl = "b"
					cl = "c"

					errors = make([]error, nProc)
					egsk := group.ScalarBaseMult(big.NewInt(rand.Int63()))
					egf = commitment.NewElGamalFactory(egsk)
				})

				It("Should finish for alice and bob", func() {
					gen(a, al, egf)
					gen(b, bl, egf)
					wg.Add(int(nProc))
					go func() {
						defer wg.Done()
						c[alice], errors[alice] = arith.Mult(a[alice], b[alice], cl)
					}()
					go func() {
						defer wg.Done()
						c[bob], errors[bob] = arith.Mult(a[bob], b[bob], cl)
					}()
					wg.Wait()

					Expect(errors[alice]).NotTo(HaveOccurred())
					Expect(errors[bob]).NotTo(HaveOccurred())
				})
			})
		})
	})
})
