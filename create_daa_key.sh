#!/bin/bash

set -e

TOPLEVEL_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null && pwd )"
TSS_DIR=${TOPLEVEL_DIR}/tss

if [[ $# -ne 2 ]]; then
        echo "usage: $0 <public key output file> <key handle output file>"
        exit 1
fi

KEY_FILE="$1"
HANDLE_FILE="$2"

PUB_KEY_RAW_FILE=/tmp/tpm-sim-pub-raw.bin
PUB_KEY_BIN_FILE=/tmp/tpm-sim-pub.bin
PRIV_KEY_RAW_FILE=/tmp/tpm-sim-priv-raw.bin
HIERARCHY=e     # we create key in endorsement hierarchy
HANDLE=81010000

function create_key()
{
        pushd $TSS_DIR

        # Clear TPM
        ./clear -hi p   # use platform hierarchy to clear

        # Create parent key
        parent_handle_raw=$(./createprimary -hi $HIERARCHY)
        parent_handle_arr=($parent_handle_raw)
        parent_handle=${parent_handle_arr[1]}

        # Create child DAA signing key
        ./create -hp $parent_handle -ecc bnp256 -dau -opu $PUB_KEY_RAW_FILE -opr $PRIV_KEY_RAW_FILE
        child_ephemeral_handle_raw=$(./load -hp $parent_handle -ipu $PUB_KEY_RAW_FILE -ipr $PRIV_KEY_RAW_FILE)
        child_ephemeral_handle_arr=($child_ephemeral_handle_raw)
        child_ephemeral_handle=${child_ephemeral_handle_arr[1]}
        ./evictcontrol -hi o -ho $child_ephemeral_handle -hp $HANDLE

        popd
}

function save_key()
{
        # Raw key file is a TPM2B_PUBLIC structure, which has the public key at the very end (at byte offset 24).
        # The format of the public key at the end of that structure is:
        #       0x0020  (two bytes for size of x-coord)
        #       x-coord (32 bytes)
        #       0x0020  (two bytes for size of y-coord)
        #       y-coord (32 bytes)
        echo -n 04 > $KEY_FILE
        dd if=$PUB_KEY_RAW_FILE skip=26 count=32 bs=1 | xxd -p -c 256 - | tr -d '\n' >> $KEY_FILE
        dd if=$PUB_KEY_RAW_FILE skip=60 count=32 bs=1 | xxd -p -c 256 - | tr -d '\n' >> $KEY_FILE
}

function save_handle()
{
        # Save the handle to file
        echo $HANDLE > $HANDLE_FILE
}

create_key
save_key
save_handle
