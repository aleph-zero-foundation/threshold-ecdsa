package sync_test

import (
	"bytes"
	"fmt"
	stdsync "sync"
	"time"

	"gitlab.com/alephledger/threshold-ecdsa/pkg/sync"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"gitlab.com/alephledger/core-go/pkg/network"
	"gitlab.com/alephledger/core-go/pkg/tests"
)

var _ = Describe("Sync Server", func() {

	var (
		nProc     uint16
		netservs  []network.Server
		syncservs []sync.Server
		data      [][][]byte
		missing   [][]uint16
		errors    []error
		wg        stdsync.WaitGroup
		roundTime time.Duration

		toSend [][]byte
		check  []func([]byte) error
		start  time.Time
	)

	JustBeforeEach(func() {
		wg = stdsync.WaitGroup{}
		netservs = tests.NewNetwork(int(nProc))
		syncservs = make([]sync.Server, int(nProc))
		for i := uint16(0); i < nProc; i++ {
			syncservs[i] = sync.NewServer(i, nProc, roundTime, netservs[i])
		}
	})

	AfterEach(func() {
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
			toSend = make([][]byte, 2)
			check = make([]func([]byte) error, 2)
			data = make([][][]byte, 2)
			missing = make([][]uint16, 2)
			errors = make([]error, 2)
		})

		Describe("First round", func() {

			Context("Alice and bob are honest and alive", func() {
				var (
					aliceData, bobData []byte
				)

				BeforeEach(func() {
					aliceData = []byte("alice")
					bobData = []byte("bob")
					toSend[alice] = aliceData
					toSend[bob] = bobData
					checkDataFactory := func(expected []byte) func([]byte) error {
						return func(data []byte) error {
							if !bytes.Equal(data, expected) {
								return fmt.Errorf("received wrong bytes: expected \n%v\n, got\n%v", expected, data)
							}
							return nil
						}
					}
					check[alice] = checkDataFactory(bobData)
					check[bob] = checkDataFactory(aliceData)
					start = time.Now().Add(time.Second)
				})

				It("Should finish for alice and bob", func() {
					wg.Add(2)
					go func() {
						defer wg.Done()
						data[alice], missing[alice], errors[alice] = syncservs[alice].Round(toSend[alice], check[alice], start)
					}()
					go func() {
						defer wg.Done()
						data[bob], missing[bob], errors[bob] = syncservs[bob].Round(toSend[bob], check[bob], start)
					}()
					wg.Wait()

					Expect(errors[alice]).NotTo(HaveOccurred())
					Expect(errors[bob]).NotTo(HaveOccurred())
					Expect(missing[alice]).To(BeNil())
					Expect(missing[bob]).To(BeNil())
					Expect(data[alice]).To(Equal([][]byte{nil, bobData}))
					Expect(data[bob]).To(Equal([][]byte{aliceData, nil}))
				})
			})
		})
	})
})
