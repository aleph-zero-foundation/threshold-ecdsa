#!/bin/bash
#
# Code coverage generation
#
# parameters: <required pkg name> <required coverage output file> <optional html output file>
set -e

PKG=$1
COV_FILE=$2
REPORT_OUTPUT=$3
HTML_REPORT_OUTPUT=$4

COVERAGE_DIR=${COVERAGE_DIR:-coverage}
PKG_LIST=$(go list ${PKG}/... | grep -v /vendor/)

# Create the coverage files directory
mkdir -p ${COVERAGE_DIR};

# Create a coverage file for each package
for package in ${PKG_LIST}; do
    go test -covermode=count -coverprofile "${COVERAGE_DIR}/${package##*/}.cov" ${package} ;
done ;

# Merge the coverage profile files
echo 'mode: count' > "${COV_FILE}" ;
tail -q -n +2 "${COVERAGE_DIR}"/*.cov >> "${COV_FILE}" ;

# Display and store the global code coverage
go tool cover -func="${COV_FILE}" | tee ${REPORT_OUTPUT} ;

# If needed, generate HTML report
if [ ! -z "$HTML_REPORT_OUTPUT" ]; then
    go tool cover -html="${COV_FILE}" -o ${HTML_REPORT_OUTPUT} ;
fi
