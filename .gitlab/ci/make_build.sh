#!/bin/bash
set -e

PKG=$1
GOPATH=$2

go build ${PKG}/...
find ${GOPATH%/}/src/${PKG} -iname "*_test.go" -printf "%h\n" | sort -u | xargs -n1 go test -c
