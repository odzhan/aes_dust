// ser_print.c
// 04-Sep-15  Markku-Juhani O. Saarinen <mjos@iki.fi>
// bits and pieces originally from various public domain sources

#include <stdio.h>
#include <avr/io.h>
#include "ser_print.h"

#ifndef F_CPU
#warning "F_CPU is not defined, set to 16MHz per default."
#define F_CPU 16000000
#endif

//#define BAUD 57600
#define BAUD 38400
#include <util/setbaud.h>

#ifndef UCSRB
# ifndef UDRE
# define UDRE UDRE0
# define RXEN RXEN0
# define TXEN TXEN0
# endif
# ifdef UCSR0A /* ATmega128 */
# define UCSRA UCSR0A
# define UCSRB UCSR0B
# define UBRRL UBRR0L
# define UBRRH UBRR0H
# define UDR UDR0
# else /* ATmega8 */
# define UCSRA USR
# define UCSRB UCR
# endif
#endif

#ifndef UBRR
# define UBRR UBRRL
#endif

static char ser_initialized = 0;

void ser_init(void)
{
    UBRRH = UBRRH_VALUE;
    UBRRL = UBRRL_VALUE;
    /* Enable */
    UCSRB = (1 << RXEN) | (1 << TXEN);
}

void ser_write(unsigned char c)
{
    if (!ser_initialized) {
        ser_init();
        ser_initialized = 1;
    }
    while (!(UCSRA & (1 << UDRE))) {};
    UDR = c;
}

void ser_print(const char *s)
{
    while (*s != 0) {
        ser_write(*s);
        s++;
    }
}

void ser_dec64(uint64_t x)
{
    char buf[21];
    int i;

    if (x == 0) {
        ser_print("0");
    } else {
        i = 20;
        buf[i] = 0;
        while (x > 0 && i > 0) {
            buf[--i] = (char) ((x % 10) + '0');
            x = x / 10;
        }
        ser_print(&buf[i]);
    }
}

void ser_hex8(uint8_t x)
{
    char y;

    y = x >> 4;
    if (y < 10)
        y += '0';
    else
        y += 'A' - 10;
    ser_write(y);
    y = x & 0xF;
    if (y < 10)
        y += '0';
    else
        y += 'A' - 10;
    ser_write(y);
}

void ser_hex16(uint16_t x)
{
    ser_hex8(x >> 8);
    ser_hex8(x & 0xFF);
}

void ser_end()
{
    ser_write(4);

    while (1)
        {;}
}

