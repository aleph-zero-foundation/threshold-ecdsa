package arith_test

import (
	"math/big"
	"math/rand"
	stdsync "sync"
	"time"

	"gitlab.com/alephledger/threshold-ecdsa/pkg/arith"
	"gitlab.com/alephledger/threshold-ecdsa/pkg/crypto/commitment"
	"gitlab.com/alephledger/threshold-ecdsa/pkg/group"
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
	)

	JustBeforeEach(func() {
		wg = stdsync.WaitGroup{}
		netservs = tests.NewNetwork(int(nProc))
		syncservs = make([]sync.Server, int(nProc))
		for i := uint16(0); i < nProc; i++ {
			syncservs[i] = sync.NewServer(i, nProc, roundTime, netservs[i])
		}
	})

	BeforeEach(func() {
		start = time.Now().Add(time.Millisecond * 10)
		roundTime = 100 * time.Millisecond
		rand.Seed(1729)
	})

	JustAfterEach(func() {
		tests.CloseNetwork(netservs)
	})

	Describe("Two parties", func() {

		var (
			alice, bob uint16
		)

		BeforeEach(func() {
			alice = 0
			bob = 1
			nProc = 2
			label = "x"
		})

		Describe("Generating a distributed secret with arith.Gen", func() {

			var (
				ads  []arith.ADSecret
				egsk *group.CurvePoint
				egf  *commitment.ElGamalFactory
			)

			Context("Alice and bob are honest and alive", func() {

				BeforeEach(func() {
					ads = make([]arith.ADSecret, nProc)
					errors = make([]error, nProc)
					egsk = group.NewCurvePoint(big.NewInt(rand.Int63()))
					egf = commitment.NewElGamalFactory(egsk)
				})

				It("Should finish for alice and bob", func() {
					wg.Add(int(nProc))
					go func() {
						defer wg.Done()
						ads[alice], errors[alice] = arith.Gen(label, syncservs[alice], egf, start)
					}()
					go func() {
						defer wg.Done()
						ads[bob], errors[bob] = arith.Gen(label, syncservs[bob], egf, start)
					}()
					wg.Wait()

					Expect(errors[alice]).NotTo(HaveOccurred())
					Expect(errors[bob]).NotTo(HaveOccurred())

				})
			})
		})

		Describe("Generating a distributed public key with arith.GenExpReveal", func() {
			var (
				dks []arith.DKey
			)

			Context("Alice and bob are honest and alive", func() {

				BeforeEach(func() {
					dks = make([]arith.DKey, nProc)
					errors = make([]error, nProc)
				})

				It("Should finish for alice and bob", func() {
					wg.Add(int(nProc))
					go func() {
						defer wg.Done()
						dks[alice], errors[alice] = arith.GenExpReveal(label, syncservs[alice], start)
					}()
					go func() {
						defer wg.Done()
						dks[bob], errors[bob] = arith.GenExpReveal(label, syncservs[bob], start)
					}()
					wg.Wait()

					Expect(errors[alice]).NotTo(HaveOccurred())
					Expect(errors[bob]).NotTo(HaveOccurred())

				})
			})
		})
	})
})
