#!/bin/bash
set -o errexit
set -o nounset
set -o pipefail

which protoc>/dev/null
if [[ $? != 0 ]]; then
    echo "Please install grpc from www.grpc.io"
    exit 1
fi

KUBESTACK_ROOT=$(dirname "${BASH_SOURCE}")/..
KUBESTACK_ROOT_ABS=$(cd ${KUBESTACK_ROOT}; pwd)
cd ${KUBESTACK_ROOT_ABS}/cmds/protoc-gen-gogo
go build

