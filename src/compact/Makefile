MACHINE := $(shell uname -m)
GCC_TARGET := $(shell gcc -dumpmachine)
ASM_WINDOWS_TARGET := $(filter %mingw32 %cygwin %msys,$(GCC_TARGET))
# GNU-stack notes are an ELF feature, not a PE/COFF assembler option.
ASM_STACK_FLAGS := $(if $(ASM_WINDOWS_TARGET),,--noexecstack)
ASM_CC_STACK_FLAGS := $(if $(ASM_WINDOWS_TARGET),,-Wa,--noexecstack)

ifneq ($(filter i386 i486 i586 i686,$(MACHINE)),)
    SRC := asm/i386/ax.s
    ASM_CTR_FLAGS := --defsym CTR=1
    ASM_TEST_DEFINES := -DAES_ASM_CTR=1
else ifeq ($(MACHINE), x86_64)
    SRC := asm/x86_64/ax.s
    # Use gcc's target ABI, including MinGW compilers running under MSYS.
    ifneq ($(ASM_WINDOWS_TARGET),)
        ASM_ABI_FLAGS := --defsym WIN=1
    endif
    ASM_CTR_FLAGS := --defsym CTR=1
    ASM_TEST_DEFINES := -DAES_ASM_CTR=1 -DAES_ASM_ABI_PROBE=1
    ASM_TEST_PROBE_OBJECT = $(ASM_TEST_DIR)/$(ASM_TEST_MODE)/assembly_abi.o
else ifeq ($(MACHINE), armv7l)
    SRC := asm/arm32/ax.s
else ifeq ($(MACHINE), aarch64)
    SRC := asm/arm64/ax.s
else ifeq ($(MACHINE), loongarch64)
    SRC := asm/loongarch64/ax.s
else
    # Only assembly recipes expand SRC; portable C targets work everywhere.
    SRC = $(error Unsupported MACHINE '$(MACHINE)')
endif

.PHONY: all mc ecb asm dyn_asm clean test-asm test-dyn-asm _test-asm

all: clean
	gcc -I. -Wall -Os test128.c aes.c -otest128
mc: clean
	gcc -I. -Wall -Os mctest.c aes.c -omctest
ecb: clean
	gcc -I. -Wall -fPIC -DCTR -Os -c aes.c
	gcc -I. -Wall -Os test128.c aes.o -otest128
	ar rcs libaes.a aes.o
asm: clean
	as $(ASM_ABI_FLAGS) $(SRC) $(ASM_STACK_FLAGS) -oax.o
	ar rcs libaes.a ax.o
	gcc -I. -Wall -DASM -Os mctest.c ax.o -omctest $(ASM_CC_STACK_FLAGS)
	gcc -I. -Wall -DASM -Os test128.c ax.o -otest128 $(ASM_CC_STACK_FLAGS)
dyn_asm: clean
	as $(ASM_ABI_FLAGS) --defsym DYNAMIC=1 $(SRC) $(ASM_STACK_FLAGS) -oax.o
	ar rcs libaes.a ax.o
	gcc -I. -Wall -fPIC -DASM -Os mctest.c ax.o -omctest $(ASM_CC_STACK_FLAGS)
	gcc -I. -Wall -fPIC -DCTR -DASM -Os test128.c ax.o -otest128 $(ASM_CC_STACK_FLAGS)

# Keep verification artifacts outside the source tree. These targets execute
# the tests; the historic asm/dyn_asm targets above only build their drivers.
ASM_TEST_DIR ?= ../../build/assembly
ASM_TEST_MODE ?= STATIC
test-asm:
	$(MAKE) --no-print-directory _test-asm ASM_TEST_MODE=STATIC
test-dyn-asm:
	$(MAKE) --no-print-directory _test-asm ASM_TEST_MODE=DYNAMIC
_test-asm:
	mkdir -p "$(ASM_TEST_DIR)/$(ASM_TEST_MODE)"
	as $(ASM_ABI_FLAGS) $(ASM_CTR_FLAGS) --defsym $(ASM_TEST_MODE)=1 $(SRC) $(ASM_STACK_FLAGS) -o "$(ASM_TEST_DIR)/$(ASM_TEST_MODE)/ax.o"
ifeq ($(MACHINE),x86_64)
	gcc -c ../../tests/assembly_abi_x86_64.S -o "$(ASM_TEST_PROBE_OBJECT)"
endif
	gcc -std=c99 -Wall -Wextra -Wpedantic -Werror -Os $(ASM_TEST_DEFINES) test_asm.c "$(ASM_TEST_DIR)/$(ASM_TEST_MODE)/ax.o" $(if $(ASM_TEST_PROBE_OBJECT),"$(ASM_TEST_PROBE_OBJECT)") -o "$(ASM_TEST_DIR)/$(ASM_TEST_MODE)/test_asm" $(ASM_CC_STACK_FLAGS)
	"$(ASM_TEST_DIR)/$(ASM_TEST_MODE)/test_asm"
clean:
	rm -rf ax.o aes.o mctest.o test128.o mctest test128 libaes.a
