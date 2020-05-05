// Package sync in it current form works only for one round going on at a time
package sync

import (
	"encoding/binary"
	"fmt"

	"os"
	"strings"
	"sync"
	"time"

	"gitlab.com/alephledger/core-go/pkg/network"
)

// Server implements
type Server interface {
	Start()
	Stop()
	Round([][]byte, func(uint16, []byte) error) error
}

type server struct {
	pid, nProc              uint16
	startTime               time.Time
	roundDuration           time.Duration
	roundID                 int64
	net                     network.Server
	inDataConn, outDataConn []network.Connection
	prevRoundEnd            time.Time
	startWG                 sync.WaitGroup
}

// NewServer construcs a SyncServer object
func NewServer(pid, nProc uint16, startTime time.Time, roundDuration time.Duration, net network.Server) Server {
	s := &server{
		pid:           pid,
		nProc:         nProc,
		startTime:     startTime,
		roundDuration: roundDuration,
		roundID:       -1,
		net:           net,
	}
	s.inDataConn = make([]network.Connection, nProc)
	s.outDataConn = make([]network.Connection, nProc)

	return s
}

func (s *server) Start() {
	s.startWG.Add(2*int(s.nProc) - 2)
	go func() {
		timeout := 100 * time.Millisecond
		for pid := range s.inDataConn {
			if pid == int(s.pid) {
				continue
			}
			go func() {
				defer s.startWG.Done()
				for {
					conn, err := s.net.Listen(timeout)
					if err != nil {
						continue
					}

					buf := make([]byte, 2)
					_, err = conn.Read(buf)
					if err != nil {
						panic(err.Error())
					}

					pid := binary.LittleEndian.Uint16(buf)
					if s.inDataConn[pid] != nil {
						panic(fmt.Sprintf("Connection with %d already established (my pid:%v)!", pid, s.pid))
					}
					s.inDataConn[pid] = conn
					return
				}
			}()
		}

		for i := range s.outDataConn {
			pid := uint16(i)

			if pid == s.pid {
				continue
			}
			go func(pid uint16) {
				defer s.startWG.Done()
				for {
					conn, err := s.net.Dial(pid, timeout)
					if err != nil {
						continue
					}
					buf := make([]byte, 2)
					binary.LittleEndian.PutUint16(buf, s.pid)
					if _, err = conn.Write(buf); err != nil {
						panic(fmt.Sprintf("succesfully dialed %v but then %v", pid, err))
					}
					if err = conn.Flush(); err != nil {
						panic(fmt.Sprintf("succesfully written %v but then %v", pid, err))
					}
					s.outDataConn[pid] = conn
					return
				}
			}(pid)
		}
	}()
}

func (s *server) Stop() {
	s.startWG.Wait()
	for pid := uint16(0); pid < s.nProc; pid++ {
		if pid == s.pid {
			continue
		}
		s.inDataConn[pid].Close()
		s.outDataConn[pid].Close()
	}
}

func (s *server) Round(toSend [][]byte, check func(uint16, []byte) error) error {
	s.startWG.Wait()
	defer func() { s.prevRoundEnd = time.Now() }()

	s.roundID++
	if s.roundID == 0 {
		// TODO: temporary solution for scheduling the start, rewrite this ugly sleep
		d := time.Until(s.startTime)
		if d < 0 {
			return wrap(fmt.Errorf("the start time has passed %v ago", d))
		}
		time.Sleep(d)

	} else {
		// TODO: This is rather dirty hack for ensuring that rounds dont interlace
		if time.Since(s.prevRoundEnd) < time.Millisecond {
			time.Sleep(time.Millisecond)
		}
	}

	endRound := time.Now().Add(s.roundDuration)
	var wg sync.WaitGroup
	var errSend error
	wg.Add(1)
	go func() {
		defer wg.Done()
		errSend = s.sendToAll(toSend)
	}()

	data, missing, err := s.receiveFromAll(endRound)
	if err != nil {
		return wrap(err)
	}

	if len(missing) > 0 {
		return newRoundError("Missing data from some parties", missing)
	}

	wg.Wait()

	if errSend != nil {
		return wrap(errSend)
	}

	errors := []error{}
	wrong := []uint16{}
	for pid := uint16(0); pid < s.nProc; pid++ {
		if pid == s.pid {
			continue
		}
		err = check(pid, data[pid])
		if err != nil {
			errors = append(errors, err)
			wrong = append(wrong, pid)
		}
	}

	if len(wrong) > 0 {
		return newRoundError(fmt.Errorf("rid:%v: Data sent by the parties %v is wrong with errors %v", s.roundID, wrong, errors).Error(), wrong)
	}

	// TODO: better timeout handling
	d := time.Until(endRound)
	if d > time.Second {
		fmt.Fprintf(os.Stderr, "rid:%v: Round: receiving took too long %v\n", s.roundID, d)
	}

	return nil
}

func (s *server) sendToAll(toSend [][]byte) error {
	var data []byte
	// Check if we send the same data to all parties
	if len(toSend) == 1 {
		data = make([]byte, 10+len(toSend[0]))
		binary.LittleEndian.PutUint16(data[:2], s.pid)
		binary.LittleEndian.PutUint64(data[2:10], uint64(s.roundID))
		copy(data[10:], toSend[0])
	}
	wg := sync.WaitGroup{}
	wg.Add(int(s.nProc) - 1)
	errors := make([]error, s.nProc)
	for pid := uint16(0); pid < s.nProc; pid++ {
		if pid == s.pid {
			continue
		}
		go func(pid uint16) {
			defer wg.Done()
			var d []byte
			if data == nil {
				d = make([]byte, 10+len(toSend[pid]))
				binary.LittleEndian.PutUint16(d[:2], s.pid)
				binary.LittleEndian.PutUint64(d[2:10], uint64(s.roundID))
				copy(d[10:], toSend[pid])
			} else {
				d = data
			}
			conn := s.outDataConn[pid]
			dataLen := make([]byte, 8)
			binary.LittleEndian.PutUint64(dataLen, uint64(len(d)))
			_, err := conn.Write(dataLen)
			if err != nil {
				errors[pid] = err
				return
			}
			err = conn.Flush()
			if err != nil {
				errors[pid] = err
				return
			}
			_, err = conn.Write(d)
			if err != nil {
				errors[pid] = err
				return
			}
			err = conn.Flush()
			if err != nil {
				errors[pid] = err
				return
			}
		}(pid)
	}

	wg.Wait()

	var b strings.Builder
	for pid := uint16(0); pid < s.nProc; pid++ {
		if pid == s.pid {
			continue
		}
		if errors[pid] != nil {
			fmt.Fprintf(&b, "[sendToAll] pid: %d, error: %v\n", pid, errors[pid])
		}
	}

	if b.Len() > 0 {
		return fmt.Errorf("rid:%v: %v", s.roundID, b.String())
	}

	return nil
}

func (s *server) receiveFromAll(endRound time.Time) ([][]byte, []uint16, error) {
	data := make([][]byte, s.nProc)
	missing := []uint16{}

	wg := sync.WaitGroup{}
	wg.Add(int(s.nProc) - 1)
	errors := make([]error, s.nProc)
	for pid := uint16(0); pid < s.nProc; pid++ {
		if pid == s.pid {
			continue
		}
		go func(pid uint16) {
			defer wg.Done()

			dataLen := make([]byte, 8)
			if n, err := s.inDataConn[pid].Read(dataLen); err != nil {
				errors[pid] = fmt.Errorf("receiveFromAll dataLen err: %v, %v", n, err)
				return
			}
			l := int(binary.LittleEndian.Uint64(dataLen))
			buf := make([]byte, l)
			nRead := 0
			for {
				n, err := s.inDataConn[pid].Read(buf[nRead:])
				if err != nil {
					errors[pid] = fmt.Errorf("receiveFromAll buf err: %v", err)
					return
				}
				nRead += n
				if nRead == l {
					break
				}

			}

			if len(buf) < 10 {
				errors[pid] = fmt.Errorf("rid:%v: received too short data from %v", s.roundID, pid)
				return
			}
			id := binary.LittleEndian.Uint16(buf[:2])
			if id != pid {
				panic(fmt.Sprintf("some party uses wrong outDataConn: Expected %v, got %v", pid, id))
			}
			roundID := binary.LittleEndian.Uint64(buf[2:10])
			if int64(roundID) != s.roundID {
				errors[pid] = fmt.Errorf("received data for wrong round from pid:%v. Expected %d, got %d", pid, s.roundID, roundID)
				return
			}

			data[pid] = buf[10:]
		}(pid)
	}

	wg.Wait()

	// TODO: better timeout handling
	d := time.Until(endRound)
	if d > time.Second {
		fmt.Fprintf(os.Stderr, "rid:%v: Round: receiving took too long %v\n", s.roundID, d)
	}

	var b strings.Builder
	for pid := uint16(0); pid < s.nProc; pid++ {
		if pid == s.pid {
			continue
		}
		if errors[pid] != nil {
			fmt.Fprintf(&b, "[receiveFromAll] pid: %d, error: %v\n", pid, errors[pid])
			// TODO: not all erros should be treated as missing
			missing = append(missing, pid)
		}
	}

	if b.Len() > 0 {
		return nil, missing, fmt.Errorf("rid:%v: %v", s.roundID, b.String())
	}

	return data, nil, nil
}
