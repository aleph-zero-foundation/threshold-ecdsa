#!/bin/bash
set -e

PKG=$1

PKG_LIST=$(go list ${PKG}/... | grep -v /vendor/)

diff -u <(echo -n) <(go fmt ${PKG_LIST})
