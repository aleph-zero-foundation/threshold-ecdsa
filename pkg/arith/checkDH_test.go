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
				keys    []*arith.DKey
				queries []func(u, v curve.Point, group curve.Group) error
				u       curve.Point
				v       curve.Point
			)

			Context("Alice and bob are honest and alive", func() {

				BeforeEach(func() {
					keys = make([]*arith.DKey, nProc)
					errors = make([]error, nProc)

					keys[alice] = arith.NewDKey(arith.NewDSecret("alice", big.NewInt(1), syncservs[alice]), group.Gen(), []curve.Point{nil, group.Gen()}, group)
					keys[bob] = arith.NewDKey(arith.NewDSecret("alice", big.NewInt(1), syncservs[bob]), group.Gen(), []curve.Point{group.Gen(), nil}, group)

					u = group.ScalarBaseMult(big.NewInt(rand.Int63()))
					v = group.ScalarBaseMult(big.NewInt(rand.Int63()))

				})

				It("Should finish for alice and bob", func() {
					wg.Add(int(nProc))
					go func() {
						defer wg.Done()
						queries[alice], errors[alice] = arith.CheckDH(keys[alice])
					}()
					go func() {
						defer wg.Done()
						queries[bob], errors[bob] = arith.CheckDH(keys[bob])
					}()
					wg.Wait()

					Expect(errors[alice]).NotTo(HaveOccurred())
					Expect(errors[bob]).NotTo(HaveOccurred())

					wg.Add(int(nProc))
					go func() {
						defer wg.Done()
						errors[alice] = queries[alice](u, v, group)
					}()
					go func() {
						defer wg.Done()
						errors[bob] = queries[bob](u, v, group)
					}()
					wg.Wait()

					Expect(errors[alice]).NotTo(HaveOccurred())
					Expect(errors[bob]).NotTo(HaveOccurred())

				})
			})
		})
	})
})
