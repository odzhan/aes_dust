# Makefile for Arduino Uno
# 2019-24-02 odzhan 

PROJ		= aes-avr
TARGET		= atmega328p
CPUFREQ		= 16000000
WIRE		= arduino
DEVICE		= /dev/ttyACM1
CC		= avr-gcc
OBJCOPY		= avr-objcopy
AR		= avr-ar
STRIP		= avr-strip
AVRDUDE		= avrdude

CFLAGS  	= -DCTR -Wall -Ofast -mmcu=$(TARGET) -DF_CPU=$(CPUFREQ)

OBJS 		= obj/aes.o

$(PROJ):	test.c ser_print.c obj/$(PROJ).a
		$(CC) $(CFLAGS) $^ -o $@

%.hex:		%
		$(OBJCOPY) -O ihex -R .eeprom $^ $@

obj/$(PROJ).a: 	$(OBJS)
		$(AR) -ar cr $@ $^

obj/%.o: %.[cS]
		mkdir -p obj/
		$(CC) $(CFLAGS) -c $^ -o $@

obj/%.S: %.c
		$(CC) $(CFLAGS) -S $^ -o $@

clean:
		rm -rf obj $(PROJ) $(PROJ).hex $(PROJ)-*.tgz

dist:		clean
		cd ..; \
		tar cfvz $(PROJ)/$(PROJ)-`date "+%Y%m%d%H%M"`.tgz $(PROJ)/*

# simulate with simavr
sim:		$(PROJ)
		simavr -v -v -v -m $(TARGET) $(PROJ)

# flash on device, dump serial output
flash:		$(PROJ).hex
		$(AVRDUDE) -v -c $(WIRE) -p m328p -P $(DEVICE) \
			-U flash:w:$(PROJ).hex
		stty -F $(DEVICE) raw icanon eof \^d 38400
		cat < $(DEVICE)
