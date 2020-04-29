package tecdsa_test

import (
	"math/rand"
	stdsync "sync"
	"time"

	"gitlab.com/alephledger/threshold-ecdsa/pkg/sync"
	"gitlab.com/alephledger/threshold-ecdsa/pkg/tecdsa"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"gitlab.com/alephledger/core-go/pkg/network"
	"gitlab.com/alephledger/core-go/pkg/tests"
)

var _ = Describe("Secret Test", func() {

	var (
		nProc     uint16
		protos    []*tecdsa.Protocol
		netservs  []network.Server
		syncservs []sync.Server
		roundTime time.Duration
		start     time.Time
		wg        stdsync.WaitGroup
		errors    []error
	)
	JustBeforeEach(func() {
		wg = stdsync.WaitGroup{}
		netservs = tests.NewNetwork(int(nProc))
		syncservs = make([]sync.Server, nProc)
		for i := uint16(0); i < nProc; i++ {
			syncservs[i] = sync.NewServer(i, nProc, start, roundTime, netservs[i])
		}
		protos = make([]*tecdsa.Protocol, nProc)
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
		})

		Describe("Generating arithmetic distributed secrets with arith.Gen", func() {

			init := func() {
				wg.Add(int(nProc))
				go func() {
					defer wg.Done()
					protos[alice], errors[alice] = tecdsa.Init(nProc, syncservs[alice])
				}()
				go func() {
					defer wg.Done()
					protos[bob], errors[bob] = tecdsa.Init(nProc, syncservs[bob])
				}()

				wg.Wait()

				Expect(errors[alice]).NotTo(HaveOccurred())
				Expect(errors[bob]).NotTo(HaveOccurred())
				Expect(protos[alice]).NotTo(BeNil())
				Expect(protos[bob]).NotTo(BeNil())
			}

			Context("Alice and Bob are honest and alive", func() {

				BeforeEach(func() {
					errors = make([]error, nProc)
				})

				It("Init should finish for alice and bob", func() {
					init()

				})
			})
		})
	})

})
