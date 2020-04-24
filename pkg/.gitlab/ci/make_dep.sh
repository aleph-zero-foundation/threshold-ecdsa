#!/bin/bash
set -e

go get github.com/onsi/ginkgo/ginkgo
go get github.com/onsi/gomega/...
go get -u golang.org/x/lint/golint
go get -v -d -t ./...
