MACHINE := $(shell uname -m)

ifeq ($(MACHINE), i386)
	SRC := asm/ax.asm
else ifeq ($(MACHINE), x86_64)
	SRC := asm/axx.asm
else ifeq ($(MACHINE), armv7l)
	SRC := asm/ax.s
else ifeq ($(MACHINE), aarch64)
	SRC := asm/axx.s
endif

test:
	as $(SRC) -oax.o
	gcc -Wall -Os test2.c aes.c -otest2
	gcc -Wall -O2 test.c aes.c -otest
clean:
	rm *.o test test2
