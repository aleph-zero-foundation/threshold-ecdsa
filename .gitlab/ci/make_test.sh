#!/bin/bash
set -e

PKG=$1

PKG_LIST=$(go list ${PKG}/... | grep -v /vendor/)

go test -ginkgo.skip Multiplying -short ${PKG_LIST}
