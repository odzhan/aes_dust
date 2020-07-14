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

mc: clean
	gcc -Wall -Os mctest.c aes.c -omctest
ecb: clean
	gcc -Wall -Os test128.c aes.c -otest128
ctr: clean
	gcc -Wall -DCTR -Os test128.c aes.c -otest128
ecb_asm: clean
	as $(SRC) -oax.o
	gcc -Wall -DASM -Os mctest.c ax.o -omctest	
	gcc -Wall -DASM -Os test2.c ax.o -otest2
ctr_asm: clean
	as --defsym CTR=1 $(SRC) -oax.o
	gcc -Wall -fPIC -DASM -Os mctest.c ax.o -omctest	
	gcc -Wall -fPIC -DCTR -DASM -Os test2.c ax.o -otest2
dyn_asm: clean
	as --defsym DYNAMIC=1 --defsym CTR=1 $(SRC) -oax.o
	gcc -Wall -fPIC -DASM -Os mctest.c ax.o -omctest	
	gcc -Wall -fPIC -DCTR -DASM -Os test128.c ax.o -otest128	
clean:
	rm -rf *.o mctest test128
