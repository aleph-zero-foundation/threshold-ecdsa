package arith_test

import (
	"math/big"
	"math/rand"
	stdsync "sync"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"gitlab.com/alephledger/threshold-ecdsa/pkg/arith"
	"gitlab.com/alephledger/threshold-ecdsa/pkg/curve"
	"gitlab.com/alephledger/threshold-ecdsa/pkg/sync"

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

				It("Should finish for alice and bob", func() {
					keys = make([]*arith.DKey, nProc)
					errors = make([]error, nProc)

					aSecret := arith.NewDSecret("alice", big.NewInt(1), syncservs[alice])
					bSecret := arith.NewDSecret("alice", big.NewInt(1), syncservs[bob])

					keys[alice] = arith.NewDKey(aSecret, group.Gen(), []curve.Point{nil, group.Gen()}, group)
					keys[bob] = arith.NewDKey(bSecret, group.Gen(), []curve.Point{group.Gen(), nil}, group)

					u = group.ScalarBaseMult(big.NewInt(rand.Int63()))
					v = group.ScalarMult(u, big.NewInt(2))

					wg.Add(int(nProc))
					go func() {
						defer wg.Done()
						errors[alice] = arith.CheckDH(u, v, group, keys[alice])
					}()
					go func() {
						defer wg.Done()
						errors[bob] = arith.CheckDH(u, v, group, keys[bob])
					}()
					wg.Wait()

					Expect(errors[alice]).NotTo(HaveOccurred())
					Expect(errors[bob]).NotTo(HaveOccurred())

				})
			})
		})
	})
})
