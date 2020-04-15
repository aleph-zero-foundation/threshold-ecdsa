// Package sync in it current form works only for one round going on at a time
package sync

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"gitlab.com/alephledger/core-go/pkg/network"
	"gitlab.com/alephledger/core-go/pkg/network/tcp"
)

const (
	timeout = time.Second
)

/*
GER
    sample a_k,
    NMC(g^{a_k}, pi_k)
    round
    decommit
    round

GEN
    sample a_k, r_k
    ElGamal(a_k, r_k), R
    round
*/

// Server implements
type Server interface {
	Round([]byte, func([]byte) error, time.Time)
}

type server struct {
	sync.Mutex
	pid, nProc uint16
	roundTime  time.Duration
	net        network.Server
}

// New construcs a SyncServer object
func New(pid, nProc uint16, roundTime time.Duration, localAddr string, remoteAddrs []string) Server {
	return &server{
		pid:       pid,
		nProc:     nProc,
		roundTime: roundTime,
		net:       tcp.NewServer(localAddr, remoteAddrs),
	}
}

// TODO: return only important data in [][]byte without bytes corresponding to proofs
func (n *network) Round(toSend []byte, check func(data []byte) error, start time.Time) ([][]byte, []uint16, error) {
	n.Lock()
	defer n.Unlock()

	// TODO: temporary solution for scheduling the start, rewrite this ugly sleep
	d := start.Sub(time.Now())
	if d < 0 {
		return nil, nil, fmt.Errorf("the start time has passed %v ago", -d)
	}
	time.sleep(d)

	err := sendToAll(toSend)
	if err != nil {
		return nil, err
	}

	roundDeadline := start.Add(n.roundTime)
	data, missing, err := receiveFromAll(roundDeadline)
	if err != nil {
		return nil, missing, err
	}

	errors := []error{}
	wrong := []uint16{}
	for pid := uint16(0); pid < n.nProc; pid++ {
		if pid == n.Pid {
			continue
		}
		err = check(data[pid])
		if err != nil {
			errors = append(error, err)
			wrong = append(wrong, pid)
		}
	}

	if len(wrong) > 0 {
		return nil, wrong, fmt.Fprint("Data sent by the parties %v is wrong with errors %v", wrong, errors)
	}

	// TODO: better timeout handling
	d = roundDeadline.Sub(time.Now())
	if d < 0 {
		return nil, nil, fmt.Errorf("receiving took to long %v", -d)
	}

	return data, nil
}

func (n *network) sendToAll(toSend []byte) error {
	wg := sync.WaitGroup{}
	wg.Add(nProc - 1)
	errors := make([]error, n.nProc)
	for pid := uint16(0); pid < n.nProc; pid++ {
		if pid == n.pid {
			continue
		}
		go func(pid uint16) {
			defer wg.Done()
			conn, err := n.net.Dial(pid, timeout)
			if err != nil {
				errors[pid] = err
				return
			}
			conn.TimeoutAfter(timeout)
			_, err = conn.Write(toSend)
			if err != nil {
				errors[pid] = err
				return
			}
			_, err = conn.Flush()
			if err != nil {
				errors[pid] = err
				return
			}
			_, err = conn.Close()
			if err != nil {
				errors[pid] = err
				return
			}
		}(pid)
	}

	wg.Wait()

	var b strings.Builder
	for pid := uint16(0); pid < n.nProc; pid++ {
		if pid == n.pid {
			continue
		}
		if errors[pid] != nil {
			fmt.Fprintf(b, "pid: %d, error: %v\n", pid, errors[pid])
		}
	}

	if b.Len() > 0 {
		return fmt.Errorf(b.String())
	}

	return nil
}

func (n *network) receiveFromAll(roundDeadline) ([][]byte, []uint16, error) {
	data := make([][]byte, n.nProc)
	missing := []uint16{}

	wg := sync.WaitGroup{}
	wg.Add(nProc - 1)
	errors := make([]error, n.nProc)
	for pid := uint16(0); pid < n.nProc; pid++ {
		go func(pid uint16) {
			defer wg.Done()
			conn, err := n.net.Listen(timeout)
			if err != nil {
				errors[pid] = err
				return
			}
			conn.TimeoutAfter(timeout)
			_, err = conn.Read(data[pid])
			if err != nil {
				errors[pid] = err
				return
			}
			_, err = conn.Close()
			if err != nil {
				errors[pid] = err
				return
			}
		}(pid)
	}

	wg.Wait()

	// TODO: better timeout handling
	d := roundDeadline.Sub(time.Now())
	if d < 0 {
		return nil, nil, fmt.Errorf("receiving took to long %v", -d)
	}

	var b strings.Builder
	for pid := uint16(0); pid < n.nProc; pid++ {
		if pid == n.pid {
			continue
		}
		if errors[pid] != nil {
			fmt.Fprintf(b, "pid: %d, error: %v\n", pid, errors[pid])
			// TODO: not all erros should be treated as missing
			missing = append(missing, pid)
		}
	}

	if b.Len() > 0 {
		return nil, missing, fmt.Errorf(b.String())
	}

	return data, missing, nil
}
