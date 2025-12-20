MACHINE := $(shell uname -m)

ifeq ($(MACHINE), i386)
    SRC := asm/i386/ax.s
else ifeq ($(MACHINE), x86_64)
    SRC := asm/x86_64/ax.s
else ifeq ($(MACHINE), armv7l)
    SRC := asm/arm32/ax.s
else ifeq ($(MACHINE), aarch64)
    SRC := asm/arm64/ax.s
else ifeq ($(MACHINE), loongarch64)
    SRC := asm/loongarch64/ax.s
else
    $(error Unsupported MACHINE '$(MACHINE)')
endif

all: clean
	gcc -I. -Wall -Os test128.c aes.c -otest128
mc: clean
	gcc -I. -Wall -Os mctest.c aes.c -omctest
ecb: clean
	gcc -I. -Wall -fPIC -DCTR -Os -c aes.c
	gcc -I. -Wall -Os test128.c aes.o -otest128
	ar rcs libaes.a aes.o
asm: clean
	as $(SRC) --noexecstack -oax.o
	ar rcs libaes.a ax.o
	gcc -I. -Wall -DASM -Os mctest.c ax.o -omctest -Wa,--noexecstack
	gcc -I. -Wall -DASM -Os test128.c ax.o -otest128 -Wa,--noexecstack
dyn_asm: clean
	as --defsym DYNAMIC=1 $(SRC) --noexecstack -oax.o
	ar rcs libaes.a ax.o
	gcc -I. -Wall -fPIC -DASM -Os mctest.c ax.o -omctest -Wa,--noexecstack
	gcc -I. -Wall -fPIC -DCTR -DASM -Os test128.c ax.o -otest128 -Wa,--noexecstack
clean:
	rm -rf ax.o aes.o mctest.o test128.o mctest test128 libaes.a
