#!/bin/bash
set -e

go get -v  github.com/onsi/ginkgo/ginkgo
go get -v github.com/onsi/gomega/...
go get -v -u golang.org/x/lint/golint
go get -v github.com/ethereum/go-ethereum/crypto/secp256k1
# go get -v -d -t ./...
