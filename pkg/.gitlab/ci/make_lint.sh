#!/bin/bash
#
# parameters: <required linter output file>
set -e

PKG=$1
LINTER_OUTPUT=$2

PKG_LIST=$(go list ${PKG}/... | grep -v /vendor/)

golint -set_exit_status ${PKG_LIST} | tee ${LINTER_OUTPUT}
stat=${PIPESTATUS[0]}
if [ $stat -ne 0 ]; then
 exit $stat
fi
exit $stat
