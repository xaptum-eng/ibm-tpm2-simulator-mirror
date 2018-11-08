TOPLEVEL_DIR := $(shell dirname $(abspath $(lastword $(MAKEFILE_LIST))))
TPM_DIR := $(TOPLEVEL_DIR)/tpm
TSS_DIR := $(TOPLEVEL_DIR)/tss

all: build

build:
	make -C $(TPM_DIR)
	make -C $(TSS_DIR)

clean:
	make -C $(TPM_DIR) clean
	make -C $(TSS_DIR) clean
