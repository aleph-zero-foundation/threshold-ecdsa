package main

import (
	"bufio"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/binance-chain/tss-lib/crypto/paillier"
)

type proc struct {
	publicKey  *paillier.PublicKey
	privateKey *paillier.PrivateKey
	localAddr  string
}

func makeProcess(localAddr string) (*proc, error) {
	bitLen := 256
	timout := 100 * time.Millisecond
	privKey, pubKey, err := paillier.GenerateKeyPair(bitLen, timout)
	if err != nil {
		return nil, err
	}

	return &proc{pubKey, privKey, localAddr}, nil
}

func encodePaillierPrivateKey(pk *paillier.PrivateKey) string {
	lenN := len(pk.PublicKey.N.Bytes())
	lenLambdaN := len(pk.LambdaN.Bytes())
	lenPhiN := len(pk.PhiN.Bytes())
	buf := make([]byte, 6+lenN+lenLambdaN+lenPhiN)

	binary.LittleEndian.PutUint16(buf[:2], uint16(lenN))
	copy(buf[2:2+lenN], pk.PublicKey.N.Bytes())

	binary.LittleEndian.PutUint16(buf[2+lenN:4+lenN], uint16(lenLambdaN))
	copy(buf[4+lenN:4+lenN+lenLambdaN], pk.PublicKey.N.Bytes())

	binary.LittleEndian.PutUint16(buf[4+lenN+lenLambdaN:6+lenN+lenLambdaN], uint16(lenN))
	copy(buf[6+lenN+lenLambdaN:], pk.PublicKey.N.Bytes())

	return base64.StdEncoding.EncodeToString(buf)
}

// This program generates files with random keys and addresses for a committee of the specified size.
// These files are intended to be used for local and aws tests of the tecdsa binary.
func main() {
	usageMsg := "Usage: gen_keys <number> [<addresses_file>]."
	if len(os.Args) != 2 && len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, usageMsg)
		return
	}

	nProc, err := strconv.Atoi(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, usageMsg)
		return
	}
	if nProc < 2 {
		fmt.Fprintln(os.Stderr, "Cannot have less than 2 processes.")
		return
	}

	addresses := make([]string, nProc)
	if len(os.Args) == 2 {
		for i := 0; i < nProc; i++ {
			addresses[i] = "127.0.0.1:" + strconv.Itoa(10000+i)
		}
	} else {
		f, err := os.Open(os.Args[2])
		if err != nil {
			fmt.Fprintln(os.Stderr, "Cannot open file ", os.Args[2])
			return
		}
		defer f.Close()
		scanner := bufio.NewScanner(f)
		for pid := 0; pid < nProc && scanner.Scan(); pid++ {
			addresses[pid] = scanner.Text()
		}
	}
	processes := make([]*proc, nProc)
	for i := 0; i < nProc; i++ {
		processes[i], err = makeProcess(addresses[i])
		if err != nil {
			return
		}
	}

	// Write pk files
	for pid, p := range processes {
		f, err := os.Create(strconv.Itoa(pid) + ".pk")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
		defer f.Close()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}

		if _, err = f.WriteString(encodePaillierPrivateKey(p.privateKey)); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
		if _, err = f.WriteString(" "); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
		if _, err = f.WriteString(strconv.Itoa(pid)); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
		if _, err = f.WriteString("\n"); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
	}

	f, err := os.Create("keys_addrs")
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		return
	}
	defer f.Close()
	for _, p := range processes {

		if _, err := f.WriteString(base64.StdEncoding.EncodeToString((p.publicKey.N.Bytes()))); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
		if _, err = f.WriteString("|"); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
		if _, err = f.WriteString(p.localAddr); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
		if _, err = f.Write([]byte("\n")); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
	}
}
