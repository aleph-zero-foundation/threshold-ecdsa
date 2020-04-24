#!/bin/bash
set -e

PKG=$1

PKG_LIST=$(go list ${PKG}/... | grep -v /vendor/)

go test -race -short ${PKG_LIST}
