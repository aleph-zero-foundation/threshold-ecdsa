package main

import (
	"bufio"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"
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
	sigNumber         int
	threshold         int
}

func getOptions() *cliOptions {
	var options cliOptions
	flag.StringVar(&options.pkPidFilename, "pk", "", "a file with a private key and process id")
	flag.StringVar(&options.keysAddrsFilename, "keys_addrs", "", "a file with keys and associated addresses")
	flag.StringVar(&options.startTime, "startTime", "", "time at which start the protocol")
	flag.StringVar(&options.roundDuration, "roundDuration", "", "duration of a round")
	flag.IntVar(&options.sigNumber, "sigNumber", 1, "number of signatures to generate")
	flag.IntVar(&options.threshold, "threshold", 1, "number of parties that must cooperate to sign a message")

	flag.Parse()

	return &options
}

func bench(w io.Writer, name string, totalTime *int64, job func()) {
	start := time.Now()
	job()
	ellapsed := time.Since(start)
	if totalTime != nil {
		*totalTime += ellapsed.Nanoseconds()
	}
	fmt.Fprintf(w, "job %s took %v\n", name, ellapsed)

}

func main() {
	// temporary trick to capture stdout and stderr on remote instances
	logFile, _ := os.OpenFile("aleph.log", os.O_WRONLY|os.O_CREATE|os.O_SYNC|os.O_APPEND, 0644)
	syscall.Dup2(int(logFile.Fd()), 1)
	syscall.Dup2(int(logFile.Fd()), 2)
	go func() {
		out, _ := os.Create("out")
		defer out.Close()
		s := make(chan os.Signal, 1)
		signal.Notify(s, syscall.SIGQUIT)
		<-s
		buf := make([]byte, 1<<25)
		stackSize := runtime.Stack(buf, true)
		out.Write(buf[:stackSize])
		out.Sync()

		panic("wrote stack, time to panic!")
	}()

	options := getOptions()

	member, err := getMember(options.pkPidFilename)
	if err != nil {
		fmt.Fprintln(logFile, err)
		return
	}

	committee, err := getCommittee(options.keysAddrsFilename)
	if err != nil {
		fmt.Fprintf(logFile, "Invalid keys_adds file \"%s\", because: %v.\n", options.keysAddrsFilename, err)
		return
	}

	if member.pid >= len(committee.addresses) {
		fmt.Fprintf(logFile, "Wrong pid: %d.\n", member.pid)
		return
	}

	net, err := tcp.NewServer(committee.addresses[member.pid], committee.addresses)
	if err != nil {
		fmt.Fprintf(logFile, "Could not init tcp server due to %v.\n", err)
		return
	}

	start := strings.ReplaceAll(options.startTime, "-", " ")
	startTime, err := time.Parse(time.UnixDate, start)
	if err != nil {
		fmt.Fprintf(logFile, "Error in parsing startTime with layout %v: %v\n", time.UnixDate, err)
		return
	}
	roundDuration, err := time.ParseDuration(options.roundDuration)
	if err != nil {
		fmt.Fprintf(logFile, "Error in parsing roundDuration: %v\n.", err)
		return
	}

	nProc := uint16(len(committee.addresses))
	fmt.Fprintf(logFile, "nProc:%v\nsigNumber:%v\nthreshold:%v\ncurrentTime:%v\nstartTime:%v\nroundDuration:%v\n", nProc, options.sigNumber, options.threshold, time.Now().UTC().Format(time.UnixDate), start, roundDuration)

	server := sync.NewServer(uint16(member.pid), nProc, startTime, roundDuration, net)
	server.Start()
	fmt.Fprintf(logFile, "Starting!\n")

	var proto *tecdsa.Protocol
	bench(logFile, "tecdsa.Init", nil, func() {
		proto, err = tecdsa.Init(uint16(member.pid), nProc, server)
		if err != nil {
			fmt.Fprintf(logFile, "error during tecdsa initialization: %v\n.", err)
			os.Exit(1)
		}
	})

	totalTime := int64(0)
	for i := 0; i < options.sigNumber; i++ {
		logMsg := fmt.Sprintf("Generating a presignature; round %d", i)
		bench(logFile, logMsg, &totalTime, func() {
			if err = proto.Presign(uint16(options.threshold)); err != nil {
				fmt.Fprintf(logFile, "error during generating a presignature: %v\n", err)
				os.Exit(1)
				return
			}
		})
	}
	tot, ave := time.Duration(totalTime), time.Duration(totalTime/int64(options.sigNumber))
	fmt.Fprintf(logFile, "Presignature stats: total = %v, average = %v\n", tot, ave)

	totalTime = int64(0)
	for i := 0; i < options.sigNumber; i++ {
		logMsg := fmt.Sprintf("Signing; round %d", i)
		bench(logFile, logMsg, &totalTime, func() {
			if _, err := proto.Sign(big.NewInt(int64(i))); err != nil {
				fmt.Fprintf(logFile, "error during signing: %v\n", err)
				return
			}
		})
	}

	tot, ave = time.Duration(totalTime), time.Duration(totalTime/int64(options.sigNumber))
	fmt.Fprintf(logFile, "Signing stats: total = %v, average = %v\n", tot, ave)

	server.Stop()
	fmt.Fprintf(logFile, "All done!\n")
}
