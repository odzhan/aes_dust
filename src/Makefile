MACHINE := $(shell uname -m)

ifeq ($(MACHINE), i386)
	SRC := asm/x86/ax.s
else ifeq ($(MACHINE), x86_64)
	SRC := asm/amd64/ax.s
else ifeq ($(MACHINE), armv7l)
	SRC := asm/arm32/ax.s
else ifeq ($(MACHINE), aarch64)
	SRC := asm/arm64/ax.s
endif

all: clean
	gcc -Wall -Os -DCTR -DOFB test128.c aes.c -otest128
mc: clean
	gcc -Wall -Os mctest.c aes.c -omctest
ecb: clean
	gcc -Wall -fPIC -DCTR -Os -c aes.c
	gcc -Wall -Os test128.c aes.o -otest128
	ar rcs libaes.a aes.o
ctr: clean
	gcc -Wall -fPIC -DCTR -Os -c aes.c
	gcc -Wall -DCTR -Os test128.c aes.o -otest128
	ar rcs libaes.a aes.o
ecb_asm: clean
	as $(SRC) -oax.o
	ar rcs libaes.a ax.o
	gcc -Wall -DASM -Os mctest.c ax.o -omctest	
	gcc -Wall -DASM -Os test128.c ax.o -otest128
ctr_asm: clean
	as --defsym CTR=1 $(SRC) -oax.o
	ar rcs libaes.a ax.o
	gcc -Wall -DASM -Os mctest.c ax.o -omctest	
	gcc -Wall -DCTR -DASM -Os test128.c ax.o -otest128
dyn_asm: clean
	as --defsym DYNAMIC=1 --defsym CTR=1 $(SRC) -oax.o
	ar rcs libaes.a ax.o
	gcc -Wall -fPIC -DASM -Os mctest.c ax.o -omctest	
	gcc -Wall -fPIC -DCTR -DASM -Os test128.c ax.o -otest128	
clean:
	rm -rf ax.o aes.o mctest.o test128.o mctest test128 libaes.a
