#!/bin/bash
set -e

PKG=$1

PKG_LIST=$(go list ${PKG}/... | grep -v /vendor/)

echo $1
go test -v -short ${PKG_LIST} -ginkgo.skip Multiplying
