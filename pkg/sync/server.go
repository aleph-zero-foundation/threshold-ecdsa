// Package sync in it current form works only for one round going on at a time
package sync

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
	"sync"
	"time"

	"gitlab.com/alephledger/core-go/pkg/network"
)

const (
	timeout = time.Second
)

// Server implements
type Server interface {
	Round([]byte, func(uint16, []byte) error, time.Time) ([][]byte, []uint16, error)
}

type server struct {
	sync.Mutex
	pid, nProc uint16
	roundTime  time.Duration
	net        network.Server
}

// NewServer construcs a SyncServer object
func NewServer(pid, nProc uint16, roundTime time.Duration, net network.Server) Server {
	return &server{
		pid:       pid,
		nProc:     nProc,
		roundTime: roundTime,
		net:       net,
	}
}

// TODO: return only important data in [][]byte without bytes corresponding to proofs
func (s *server) Round(toSend []byte, check func(uint16, []byte) error, start time.Time) ([][]byte, []uint16, error) {
	s.Lock()
	defer s.Unlock()

	// TODO: temporary solution for scheduling the start, rewrite this ugly sleep
	d := time.Until(start)
	if d < 0 {
		return nil, nil, fmt.Errorf("the start time has passed %v ago", -d)
	}
	time.Sleep(d)

	roundDeadline := start.Add(s.roundTime)
	var wg sync.WaitGroup
	var errSend error
	wg.Add(1)
	go func() {
		defer wg.Done()
		errSend = s.sendToAll(toSend)
	}()

	data, missing, err := s.receiveFromAll(roundDeadline)
	if err != nil {
		return nil, missing, err
	}

	if errSend != nil {
		return nil, nil, errSend
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
		return nil, wrong, fmt.Errorf("Data sent by the parties %v is wrong with errors %v", wrong, errors)
	}

	// TODO: better timeout handling
	d = time.Until(roundDeadline)
	if d < 0 {
		return nil, nil, fmt.Errorf("receiving took to long %v", -d)
	}

	return data, nil, nil
}

func (s *server) sendToAll(toSend []byte) error {
	data := make([]byte, 2+len(toSend))
	binary.LittleEndian.PutUint16(data[:2], s.pid)
	copy(data[2:], toSend)
	wg := sync.WaitGroup{}
	wg.Add(int(s.nProc) - 1)
	errors := make([]error, s.nProc)
	for pid := uint16(0); pid < s.nProc; pid++ {
		if pid == s.pid {
			continue
		}
		go func(pid uint16) {
			defer wg.Done()
			conn, err := s.net.Dial(pid, timeout)
			if err != nil {
				errors[pid] = err
				return
			}
			conn.TimeoutAfter(timeout)
			_, err = conn.Write(data)
			if err != nil {
				errors[pid] = err
				return
			}
			err = conn.Flush()
			if err != nil {
				errors[pid] = err
				return
			}
			err = conn.Close()
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
		return fmt.Errorf(b.String())
	}

	return nil
}

func (s *server) receiveFromAll(roundDeadline time.Time) ([][]byte, []uint16, error) {
	data := make([][]byte, s.nProc)
	missing := []uint16{}

	wg := sync.WaitGroup{}
	wg.Add(int(s.nProc) - 1)
	errors := make([]error, s.nProc)
	for i := uint16(0); i < s.nProc; i++ {
		if i == s.pid {
			continue
		}
		go func(i uint16) {
			defer wg.Done()
			conn, err := s.net.Listen(timeout)
			if err != nil {
				errors[i] = err
				return
			}
			conn.TimeoutAfter(timeout)
			buf := bytes.Buffer{}
			_, err = buf.ReadFrom(conn)
			if err != nil {
				errors[i] = err
				return
			}
			if len(buf.Bytes()) < 2 {
				errors[i] = fmt.Errorf("received too short data")
				return
			}
			pid := binary.LittleEndian.Uint16(buf.Bytes()[:2])
			data[pid] = buf.Bytes()[2:]
			err = conn.Close()
			if err != nil {
				errors[pid] = err
				return
			}
		}(i)
	}

	wg.Wait()

	// TODO: better timeout handling
	d := time.Until(roundDeadline)
	if d < 0 {
		return nil, nil, fmt.Errorf("receiving took to long %v", -d)
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
		return nil, missing, fmt.Errorf(b.String())
	}

	return data, missing, nil
}