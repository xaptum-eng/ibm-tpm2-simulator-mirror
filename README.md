# ibm-tpm2-simulator-mirror

A mirror of IBM's TPM2.0 simulator, for Xaptum's continuous integration testing.

TPM simulator version 1637, and TSS version 1.5.0.

## Building

From the root directory of this project, run:
```
make
```
This builds in-source.
Due to the structure of the underlying IBM source code, out-of-source builds aren't possible.


## Usage

### Simulator

To stop or start the simulator (which listens on a local TCP port):
```
./simulator.sh start
```
or
```
./simulator.sh stop
```
This uses a local PID-file to track the simulator process, for later stopping it.

### Key Creation

To create a DAA key for use in the Xaptum project `ecdaa` or `xtt`:
```
./create_daa_key.sh <pub-key-output-file> <key-handle-output-file>
```
where the public key is output in x9.62 textual format, and the handle is output as ASCII hex.
