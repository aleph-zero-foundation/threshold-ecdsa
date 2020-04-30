package arith_test

import (
	"math/big"
	"math/rand"
	"time"

	"gitlab.com/alephledger/core-go/pkg/network"
	"gitlab.com/alephledger/core-go/pkg/tests"
	"gitlab.com/alephledger/threshold-ecdsa/pkg/arith"
	"gitlab.com/alephledger/threshold-ecdsa/pkg/crypto/commitment"
	"gitlab.com/alephledger/threshold-ecdsa/pkg/curve"
	"gitlab.com/alephledger/threshold-ecdsa/pkg/sync"
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

		BeforeEach(func() {
			alice = 0
			bob = 1
			nProc = 2
		})

		Describe("Checking values with CheckDH", func() {

			var (
				keys []*arith.DKey
				u    curve.Point
				v    curve.Point
			)

			Context("Alice and bob are honest and alive", func() {

				BeforeEach(func() {
					keys = make([]*arith.DKey, nProc)
					errors = make([]error, nProc)
					egsk = group.ScalarBaseMult(big.NewInt(rand.Int63()))
					egf = commitment.NewElGamalFactory(egsk)

					//How to create DKEY

					u = group.ScalarBaseMult(big.NewInt(rand.Int63()))
					v = group.ScalarBaseMult(big.NewInt(rand.Int63()))

				})

				It("Should finish for alice and bob", func() {
					wg.Add(int(nProc))
					go func() {
						defer wg.Done()
						query[alice], errors[alice] = arith.CheckDH(keys[alice])
					}()
					go func() {
						defer wg.Done()
						query[bob], errors[bob] = arith.CheckDH(keys[bob])
					}()
					wg.Wait()

					Expect(errors[alice]).NotTo(HaveOccurred())
					Expect(errors[bob]).NotTo(HaveOccurred())

					wg.Add(int(nProc))
					go func() {
						defer wg.Done()
						errors[alice] = query[alice](u, v, group)
					}()
					go func() {
						defer wg.Done()
						errors[bob] = query[bob](u, v, group)
					}()
					wg.Wait()

					Expect(errors[alice]).NotTo(HaveOccurred())
					Expect(errors[bob]).NotTo(HaveOccurred())

				})
			})
		})
	})
})
