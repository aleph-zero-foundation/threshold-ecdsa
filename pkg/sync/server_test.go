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
		allData   [][][]byte
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
		start = time.Now().Add(10 * time.Millisecond)
		for i := uint16(0); i < nProc; i++ {
			syncservs[i] = sync.NewServer(i, nProc, start, roundTime, netservs[i])
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
			roundTime = 300 * time.Millisecond
			toSend = make([][]byte, nProc)
			check = make([]func(uint16, []byte) error, nProc)
			allData = make([][][]byte, nProc)
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
					for i := range allData {
						allData[i] = make([][]byte, nProc)
					}
					checkDataFactory := func(id uint16, expected []byte) func(uint16, []byte) error {
						return func(pid uint16, data []byte) error {
							if !bytes.Equal(data, expected) {
								return fmt.Errorf("received wrong bytes: expected \n%v\n, got\n%v", expected, data)
							}
							allData[id][pid] = data
							return nil
						}
					}
					check[alice] = checkDataFactory(alice, bobData)
					check[bob] = checkDataFactory(bob, aliceData)
				})

				It("Should finish for alice and bob", func() {
					wg.Add(int(nProc))
					go func() {
						defer wg.Done()
						errors[alice] = syncservs[alice].Round([][]byte{toSend[alice]}, check[alice])
					}()
					go func() {
						defer wg.Done()
						errors[bob] = syncservs[bob].Round([][]byte{toSend[bob]}, check[bob])
					}()
					wg.Wait()

					Expect(errors[alice]).NotTo(HaveOccurred())
					Expect(errors[bob]).NotTo(HaveOccurred())
					Expect(allData[alice]).To(Equal([][]byte{nil, bobData}))
					Expect(allData[bob]).To(Equal([][]byte{aliceData, nil}))
				})
			})
		})
	})

	Describe("Ten parties", func() {

		BeforeEach(func() {
			nProc = 10
			roundTime = 300 * time.Millisecond
			toSend = make([][]byte, nProc)
			check = make([]func(uint16, []byte) error, nProc)
			allData = make([][][]byte, nProc)
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
					for i := range allData {
						allData[i] = make([][]byte, nProc)
					}
					checkDataFactory := func(id uint16, expected [][]byte) func(uint16, []byte) error {
						return func(pid uint16, data []byte) error {
							if !bytes.Equal(data, expected[pid]) {
								return fmt.Errorf("received wrong bytes: expected \n%v\n, got\n%v", expected, data)
							}
							allData[id][pid] = data
							return nil
						}
					}
					for i := uint16(0); i < nProc; i++ {
						check[i] = checkDataFactory(i, toSend)
					}

					expected = make([][][]byte, nProc)
					for i := uint16(0); i < nProc; i++ {
						expected[i] = make([][]byte, nProc)
						copy(expected[i], toSend)
						expected[i][i] = nil
					}
				})

				It("Should finish for all parties", func() {
					wg.Add(int(nProc))
					for i := uint16(0); i < nProc; i++ {
						go func(i uint16) {
							defer wg.Done()
							errors[i] = syncservs[i].Round([][]byte{toSend[i]}, check[i])
						}(i)
					}
					wg.Wait()

					for i := uint16(0); i < nProc; i++ {
						Expect(errors[i]).NotTo(HaveOccurred())
						Expect(allData[i]).To(Equal(expected[i]))
					}
				})
			})
		})
	})
})
