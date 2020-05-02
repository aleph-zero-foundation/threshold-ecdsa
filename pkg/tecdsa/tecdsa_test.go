package tecdsa_test

import (
	"math/big"
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

var _ = Describe("TECDSA Test", func() {

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
		start = time.Now().Add(time.Millisecond * 10)
		for i := uint16(0); i < nProc; i++ {
			syncservs[i] = sync.NewServer(i, nProc, start, roundTime, netservs[i])
		}
		protos = make([]*tecdsa.Protocol, nProc)
		errors = make([]error, nProc)
	})

	BeforeEach(func() {
		roundTime = 50 * time.Millisecond
		rand.Seed(1729)
	})

	AfterEach(func() {
		tests.CloseNetwork(netservs)
	})

	init := func() {
		wg.Add(int(nProc))
		for i := uint16(0); i < nProc; i++ {
			go func(i uint16) {
				defer wg.Done()
				protos[i], errors[i] = tecdsa.Init(nProc, syncservs[i])
			}(i)
		}

		wg.Wait()

		for i := uint16(0); i < nProc; i++ {
			Expect(errors[i]).NotTo(HaveOccurred())
			Expect(protos[i]).NotTo(BeNil())
		}
	}

	Describe("Initialization", func() {

		Context("Two parties", func() {

			BeforeEach(func() {
				nProc = 2
			})

			Context("Alice and Bob are honest and alive", func() {

				It("Should init the protocol successfully", func() {
					init()
				})
			})
		})
	})

	Describe("Signing", func() {
		var (
			t     uint16
			msg   *big.Int
			signs []*tecdsa.Signature
		)

		presig := func() {
			wg.Add(int(nProc))
			for i := uint16(0); i < nProc; i++ {
				go func(i uint16) {
					defer wg.Done()
					errors[i] = protos[i].Presign(t)
				}(i)
			}

			wg.Wait()

			for i := uint16(0); i < nProc; i++ {
				Expect(errors[i]).NotTo(HaveOccurred())
			}
		}

		sign := func() {
			wg.Add(int(nProc))
			for i := uint16(0); i < nProc; i++ {
				go func(i uint16) {
					defer wg.Done()
					signs[i], errors[i] = protos[i].Sign(msg)
				}(i)
			}
			wg.Wait()

			for i := uint16(0); i < nProc; i++ {
				Expect(errors[i]).NotTo(HaveOccurred())
				Expect(signs[i]).NotTo(BeNil())
			}

		}

		Context("Two parties", func() {

			Context("Threshold equal 1", func() {

				BeforeEach(func() {
					t = 1
					msg = big.NewInt(rand.Int63())
					signs = make([]*tecdsa.Signature, nProc)
				})

				Context("Alice and Bob are honest and alive", func() {

					It("Should generate a presignature successfully", func() {
						init()
						presig()
					})

					It("Should sign a message successfully", func() {
						init()
						presig()
						sign()
					})
				})
			})

			Context("Threshold equal 2", func() {

				BeforeEach(func() {
					t = 2
					msg = big.NewInt(rand.Int63())
					signs = make([]*tecdsa.Signature, nProc)
				})

				Context("Alice and Bob are honest and alive", func() {

					It("Should generate a presignature successfully", func() {
						init()
						presig()
					})

					It("Should sign a message successfully", func() {
						init()
						presig()
						sign()
					})
				})
			})
		})
	})
})
