package main

import (
	"bufio"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/binance-chain/tss-lib/crypto/paillier"

	"gitlab.com/alephledger/core-go/pkg/network/tcp"

	"gitlab.com/alephledger/threshold-ecdsa/pkg/sync"
	"gitlab.com/alephledger/threshold-ecdsa/pkg/tecdsa"
)

type member struct {
	pid        int
	privateKey *paillier.PrivateKey
}

type committee struct {
	publicKeys []*paillier.PublicKey
	addresses  []string
}

func decodeBigInt(data []byte, name string) (*big.Int, error) {
	lenX := binary.LittleEndian.Uint16(data[:2])
	if len(data) < 2+int(lenX) {
		return nil, fmt.Errorf("wrong encoding, data is too short. len(%s) is %d, while len(data) is %d", name, lenX, len(data[2:]))
	}
	return new(big.Int).SetBytes(data[2 : 2+lenX]), nil
}

func decodePaillierPrivateKey(enc string) (*paillier.PrivateKey, error) {
	data, err := base64.StdEncoding.DecodeString(enc)

	pk := &paillier.PrivateKey{}
	pk.PublicKey.N, err = decodeBigInt(data, "N")
	if err != nil {
		return nil, err
	}
	data = data[2+len(pk.PublicKey.N.Bytes()):]

	pk.LambdaN, err = decodeBigInt(data, "LambdaN")
	if err != nil {
		return nil, err
	}
	data = data[2+len(pk.LambdaN.Bytes()):]

	pk.PhiN, err = decodeBigInt(data, "PhiN")
	if err != nil {
		return nil, err
	}

	return pk, nil
}

func parseCommitteeLine(line string) (*paillier.PublicKey, string, error) {
	s := strings.Split(line, "|")

	if len(s) < 2 {
		return nil, "", errors.New("commitee line should be of the form:\npaillierKey|address")
	}
	pkEnc, addr := s[0], s[1]

	if len(pkEnc) == 0 {
		return nil, "", errors.New("empty paillier key")
	}
	if len(addr) == 0 {
		return nil, "", errors.New("empty address")
	}
	if len(strings.Split(addr, ":")) < 2 {
		return nil, "", errors.New("malformed address")
	}

	pk := &paillier.PublicKey{}
	pkBytes, err := base64.StdEncoding.DecodeString(pkEnc)
	if err != nil {
		return nil, "", errors.New("malformed address")
	}
	pk.N = new(big.Int).SetBytes(pkBytes)

	return pk, addr, nil
}

func getCommittee(filename string) (*committee, error) {
	if filename == "" {
		return nil, errors.New("provided keys_adds filename is empty")
	}

	c := &committee{}

	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanWords)
	for scanner.Scan() {
		pk, addr, err := parseCommitteeLine(scanner.Text())
		if err != nil {
			return nil, err
		}

		c.publicKeys = append(c.publicKeys, pk)
		c.addresses = append(c.addresses, addr)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(c.publicKeys) < 2 {
		return nil, errors.New("the protocol needs at least 2 parties")
	}

	return c, nil
}

func getMember(filename string) (*member, error) {
	if filename == "" {
		return nil, errors.New("provided pk filename is empty")
	}

	m := &member{}

	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanWords)
	// read private paillier key and pid. Assumes one line of the form "key pid"
	if !scanner.Scan() {
		return nil, errors.New("empty member file")
	}
	m.privateKey, err = decodePaillierPrivateKey(scanner.Text())
	if err != nil {
		return nil, err
	}

	if !scanner.Scan() {
		return nil, errors.New("pid missing")
	}
	m.pid, err = strconv.Atoi(scanner.Text())
	if err != nil {
		return nil, err
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return m, nil
}

type cliOptions struct {
	pkPidFilename     string
	keysAddrsFilename string
	startTime         string
	roundDuration     string
	presigNumber      int
	threshold         int
}

func getOptions() *cliOptions {
	var options cliOptions
	flag.StringVar(&options.pkPidFilename, "pk", "", "a file with a private key and process id")
	flag.StringVar(&options.keysAddrsFilename, "keys_addrs", "", "a file with keys and associated addresses")
	flag.StringVar(&options.startTime, "startTime", "", "time at which start the protocol")
	flag.StringVar(&options.roundDuration, "roundDuration", "", "duration of a round")
	flag.IntVar(&options.presigNumber, "presigNumber", 1, "number of presignatures generated during init")
	flag.IntVar(&options.threshold, "threshold", 1, "number of parties that must cooperate to sign a message")

	flag.Parse()

	return &options
}

func main() {
	fmt.Fprintf(os.Stdout, "Starting!\n")
	options := getOptions()

	member, err := getMember(options.pkPidFilename)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}

	committee, err := getCommittee(options.keysAddrsFilename)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid keys_adds file \"%s\", because: %v.\n", options.keysAddrsFilename, err)
		return
	}

	if member.pid >= len(committee.addresses) {
		fmt.Fprintf(os.Stderr, "Wrong pid: %d.\n", member.pid)
		return
	}

	net, err := tcp.NewServer(committee.addresses[member.pid], committee.addresses)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not init tcp server due to %v.\n", err)
		return
	}

	startTime, err := time.Parse(time.UnixDate, options.startTime)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error in parsing startTime with layout %v: %v\n", time.UnixDate, err)
		return
	}
	roundDuration, err := time.ParseDuration(options.roundDuration)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error in parsing roundDuration: %v\n.", err)
		return
	}
	nProc := uint16(len(committee.addresses))
	server := sync.NewServer(uint16(member.pid), nProc, startTime, roundDuration, net)

	proto, err := tecdsa.Init(nProc, server)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error during tecdsa initialization: %v\n.", err)
		return
	}

	if err = proto.Presign(uint16(options.threshold)); err != nil {
		fmt.Fprintf(os.Stderr, "error during tecdsa initialization: %v\n.", err)
		return
	}

	fmt.Fprintf(os.Stdout, "All done!\n")
}
