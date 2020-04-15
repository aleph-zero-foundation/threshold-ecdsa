package network

import (
	"fmt"
	"gitlab.com/alephledger/core-go/pkg/network"
	"time"
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

// Network represents
type Network interface {
	Round([]byte, func([]byte) error, time.Time)
}

type network struct {
	pid, nProc uint16
	requests   []chan []byte
	roundTime  time.Duration
	net        network.Server
}

func (n *network) Round(toSend []byte, check func(data []byte) error, start time.Time) ([][]byte, []uint16, error) {
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

	return data, nil
}

func (n *network) sendToAll(toSend []byte) error {

}
