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

// Server implements
type Server interface {
	Start()
	Stop()
	Round([][]byte, func(uint16, []byte) error) error
}

type server struct {
	pid, nProc    uint16
	startTime     time.Time
	roundDuration time.Duration
	roundID       int64
	net           network.Server
	dataChan      []chan ([]byte)
	mx            sync.RWMutex
	quit          bool
	prevRoundEnd  time.Time
}

// NewServer construcs a SyncServer object
func NewServer(pid, nProc uint16, startTime time.Time, roundDuration time.Duration, net network.Server) Server {
	chans := make([]chan []byte, nProc)
	for i := range chans {
		// TODO: to bu or not to bu
		chans[i] = make(chan []byte, 2)
	}
	return &server{
		pid:           pid,
		nProc:         nProc,
		startTime:     startTime,
		roundDuration: roundDuration,
		roundID:       -1,
		net:           net,
		dataChan:      chans,
	}
}

func (s *server) Start() {
	for range s.dataChan {
		go func() {
			for {
				s.mx.RLock()
				if s.quit {
					s.mx.RUnlock()
					return
				}
				conn, err := s.net.Listen(10 * time.Millisecond)
				if err != nil {
					s.mx.RUnlock()
					continue
				}

				defer conn.Close()
				conn.TimeoutAfter(s.roundDuration)
				buf := bytes.Buffer{}
				_, err = buf.ReadFrom(conn)
				if err != nil {
					s.mx.RUnlock()
					panic(err.Error())
				}

				pid := binary.LittleEndian.Uint16(buf.Bytes()[:2])
				select {
				case s.dataChan[pid] <- buf.Bytes()[2:]:
				default:
					s.mx.RUnlock()
					panic("buffer server.dataChan overloaded")
				}
				s.mx.RUnlock()
			}
		}()
	}
}

func (s *server) Stop() {
	s.mx.Lock()
	defer s.mx.Unlock()
	s.quit = true
	for _, c := range s.dataChan {
		close(c)
	}
}

func (s *server) Round(toSend [][]byte, check func(uint16, []byte) error) error {
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
	if d < 0 {
		return wrap(fmt.Errorf("rid:%v: Round: receiving took too long %v", s.roundID, d))
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
			conn, err := s.net.Dial(pid, s.roundDuration)
			if err != nil {
				errors[pid] = err
				return
			}
			defer conn.Close()
			conn.TimeoutAfter(s.roundDuration)
			var d []byte
			if data == nil {
				d = make([]byte, 10+len(toSend[pid]))
				binary.LittleEndian.PutUint16(d[:2], s.pid)
				binary.LittleEndian.PutUint64(d[2:10], uint64(s.roundID))
				copy(d[10:], toSend[pid])
			} else {
				d = data
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
	for i := uint16(0); i < s.nProc; i++ {
		if i == s.pid {
			continue
		}
		go func(i uint16) {
			defer wg.Done()
			ticker := time.NewTicker(s.roundDuration)
			defer ticker.Stop()

			var buf []byte
			select {
			case <-ticker.C:
				errors[i] = fmt.Errorf("timeout in roundID:%v for pid:%v", s.roundID, i)
				return
			case buf = <-s.dataChan[i]:

			}
			if len(buf) < 8 {
				errors[i] = fmt.Errorf("rid:%v: received too short data", s.roundID)
				return
			}
			roundID := binary.LittleEndian.Uint64(buf[:8])
			if int64(roundID) != s.roundID {
				errors[i] = fmt.Errorf("received data for wrong round from pid:%v. Expected %d, got %d", i, s.roundID, roundID)
				return
			}

			data[i] = buf[8:]
		}(i)
	}

	wg.Wait()

	// TODO: better timeout handling
	d := time.Until(endRound)
	if d < 0 {
		return nil, nil, fmt.Errorf("rid:%v: receiveFromAll: receiving took to long %v", s.roundID, d)
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
