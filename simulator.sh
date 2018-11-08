#!/bin/bash

set -e

TOPLEVEL_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null && pwd )"
TPM_DIR=${TOPLEVEL_DIR}/tpm
TSS_DIR=${TOPLEVEL_DIR}/tss
PID_FILE=${TOPLEVEL_DIR}/.server_pid

if [[ $# -ne 1 ]]; then
        echo "usage: $0 start|stop"
        exit 1
fi

case "$1" in
        "start" )
                echo "Starting TPM simulator..."
                ${TPM_DIR}/tpm_server &
                echo $! > $PID_FILE
                sleep 1
                pushd $TSS_DIR
                ./powerup
                ./startup
                ;;
        "stop" )
                if [[ -r $PID_FILE ]]; then
                        echo "Stopping TPM simulator..."
                        kill $(cat $PID_FILE) || true
                        rm -f $PID_FILE
                else
                        echo "No simulator PID file found. Unable to stop simulator"
                fi
                ;;
esac
