#! /bin/bash

echo update > setup.log
sudo apt update

echo upgrade >> setup.log
sudo apt -y upgrade

echo install gcc >> setup.log
sudo apt -y install gcc zip

echo install go from snap >> setup.log
sudo snap install go --classic

echo install dependencies >> setup.log
go get github.com/onsi/ginkgo/ginkgo
go get github.com/onsi/gomega/...
go get golang.org/x/crypto/...
go get github.com/rs/zerolog

go get github.com/binance-chain/tss-lib/crypto/paillier
go get github.com/ethereum/go-ethereum/crypto/secp256k1

echo create aleph dir >> setup.log
mkdir -p go/src/gitlab.com/alephledger

echo done >> setup.log
