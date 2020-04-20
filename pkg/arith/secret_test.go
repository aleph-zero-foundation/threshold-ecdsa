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
		ads       []arith.ADSecret
		egsk      *group.CurvePoint
		egf       *commitment.ElGamalFactory
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
			roundTime = 2 * time.Second
			start = time.Now().Add(time.Millisecond * 100)
			label = "x"
			egsk = group.NewCurvePoint(big.NewInt(rand.Int63()))
			egf = commitment.NewElGamalFactory(egsk)
		})

		Describe("One round", func() {

			Context("Alice and bob are honest and alive", func() {

				BeforeEach(func() {
					ads = make([]arith.ADSecret, nProc)
					errors = make([]error, nProc)
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
	})
})
