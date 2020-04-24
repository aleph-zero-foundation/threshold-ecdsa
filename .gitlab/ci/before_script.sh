#!/bin/bash
set -e

GOPATH=$1
MAIN_FOLDER=$2
PKG=$3
VENDOR_NAME=$4
CI_PROJECT_DIR=$5

# this line should allow access to all needed repos
echo -e "machine gitlab.com\nlogin gitlab-ci-token\npassword ${CI_JOB_TOKEN}" > ~/.netrc
mkdir -p ${GOPATH}/src/${MAIN_FOLDER} ${GOPATH}/src/_/builds
cp -r ${CI_PROJECT_DIR} ${GOPATH}/src/${PKG}
ln -s ${GOPATH}/src/${MAIN_FOLDER} ${GOPATH}/src/_/builds/${VENDOR_NAME}
chmod +x .gitlab/ci/make_*.sh
.gitlab/ci/make_dep.sh
