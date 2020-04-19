package sync_test

import (
	"bytes"
	"encoding/binary"
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
		check  []func(uint16, []byte) error
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
			toSend = make([][]byte, nProc)
			check = make([]func(uint16, []byte) error, nProc)
			data = make([][][]byte, nProc)
			missing = make([][]uint16, nProc)
			errors = make([]error, nProc)
		})

		Describe("One round", func() {

			Context("Alice and bob are honest and alive", func() {
				var (
					aliceData, bobData []byte
				)

				BeforeEach(func() {
					aliceData = []byte("alice")
					bobData = []byte("bob")
					toSend[alice] = aliceData
					toSend[bob] = bobData
					checkDataFactory := func(expected []byte) func(uint16, []byte) error {
						return func(_ uint16, data []byte) error {
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
					wg.Add(int(nProc))
					go func() {
						defer wg.Done()
						data[alice], missing[alice], errors[alice] = syncservs[alice].Round(toSend[alice], check[alice], start, 0)
					}()
					go func() {
						defer wg.Done()
						data[bob], missing[bob], errors[bob] = syncservs[bob].Round(toSend[bob], check[bob], start, 0)
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

	Describe("Ten parties", func() {

		BeforeEach(func() {
			nProc = 10
			roundTime = 2 * time.Second
			toSend = make([][]byte, nProc)
			check = make([]func(uint16, []byte) error, nProc)
			data = make([][][]byte, nProc)
			missing = make([][]uint16, nProc)
			errors = make([]error, nProc)
		})

		Describe("One round", func() {

			Context("All parties are honest and alive", func() {

				var expected [][][]byte

				BeforeEach(func() {
					for i := uint16(0); i < nProc; i++ {
						toSend[i] = make([]byte, 2)
						binary.LittleEndian.PutUint16(toSend[i], i)
					}
					checkDataFactory := func(expected [][]byte) func(uint16, []byte) error {
						return func(pid uint16, data []byte) error {
							if !bytes.Equal(data, expected[pid]) {
								return fmt.Errorf("received wrong bytes: expected \n%v\n, got\n%v", expected[pid], data)
							}
							return nil
						}
					}
					for i := uint16(0); i < nProc; i++ {
						check[i] = checkDataFactory(toSend)
					}

					expected = make([][][]byte, nProc)
					for i := uint16(0); i < nProc; i++ {
						expected[i] = make([][]byte, nProc)
						copy(expected[i], toSend)
						expected[i][i] = nil
					}

					start = time.Now().Add(time.Second)
				})

				It("Should finish for all parties", func() {
					wg.Add(int(nProc))
					for i := uint16(0); i < nProc; i++ {
						go func(i uint16) {
							defer wg.Done()
							data[i], missing[i], errors[i] = syncservs[i].Round(toSend[i], check[i], start, 0)
						}(i)
					}
					wg.Wait()

					for i := uint16(0); i < nProc; i++ {
						Expect(errors[i]).NotTo(HaveOccurred())
						Expect(missing[i]).To(BeNil())
						Expect(data[i]).To(Equal(expected[i]))
					}
				})
			})
		})
	})
})
