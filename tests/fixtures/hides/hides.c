/* Examples of MISRA C findings hidden rather than fixed.
 * Every commented line should be reported by misra_hide_scan.py.
 * Not intended to compile cleanly.
 */
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#define UART0_CTRL ((volatile uint32_t *)0x40001000UL)

/* Deviation DEV-011: Rule 11.4
 * Scope: here. Reason: MMIO. Approved: arch
 */
#define UART0_DATA ((volatile uint32_t *)0x40001004UL)

static uint8_t heap[1024];

void *App_Alloc(size_t n)
{
    return &heap[n];
}

int example(uint8_t len_a, uint8_t len_b, uint8_t *rx, uint16_t w, uint16_t h)
{
    uint8_t total = (uint8_t)(len_a + len_b);        /* hide 10.3 */
    uint32_t area = (uint32_t)(w * h);                /* late widening */
    uint16_t ok = (uint16_t)len_a + (uint16_t)len_b;  /* fine */
    uint32_t id = *(uint32_t *)(void *)&rx[1];        /* hide 11.3 */
    uint32_t id2 = *(uint32_t *)&rx[1];
    uint16_t v = ((uint16_t *)rx)[2];
    uint8_t n = (uint8_t)strlen("abc");
    int x = (int)ok * 2;                              /* multiplication, not deref */
    if (sizeof(int) > 2U) { x++; }

    (void)Flash_Write(0x100U, rx, 4U);
    (void)memcpy(rx, rx, 1U);
    (void)Log_Message("hi");

    uint8_t retries = 3U;
    while (retries >= 0U) { retries--; }

    while (1)
    {
        if (Radio_Send(rx) == 0) { break; }
    }

    switch (x)
    {
        case 1: x = 2; break;
        default: break;
    }

    if (x) { x = 1; } else { }
    if (x) { x = 1; } else { /* nothing */ }

    x = x + 1; /* cppcheck-suppress misra-c2012-10.4 */
    x = x + 2; /* polyspace MISRA2012:10.4 [Justified] DEV-012 */
    return (int)(total + area + id + id2 + v + n);
}

/* ---- Hides that are not casts ------------------------------------------ */

#include <stdlib.h>
#include <stdio.h>

extern int Step_A(void);
extern int Step_B(void);
extern int Nvm_Write(uint32_t id, const uint8_t *data);
extern int Sensor_Read(uint16_t *out);

/* 2.2 / 2.7: dummy uses to silence "unused" warnings */
void dummy_uses(uint8_t unused_param)
{
    uint16_t raw;
    int status = Sensor_Read(&raw);   /* result computed ... */
    (void)status;                     /* ... then thrown away */
    unused_param = unused_param;      /* self-assignment */
}

/* 2.2 / 14.3: volatile added so the analyser stops reasoning about it */
void wait_ready(void)
{
    volatile bool ready = false;
    while (!ready) { }
}

/* Dir 4.7: an "error check" that does nothing */
void check_and_ignore(void)
{
    uint16_t raw;
    if (Sensor_Read(&raw) != 0) { }
    if (Step_A() != 0);
}

/* 17.7: result stored to silence "return value not used", never checked */
void store_and_forget(const uint8_t *cal)
{
    int rc = Nvm_Write(1U, cal);
}

/* 15.5: single-exit rewrite that loses the first error */
int single_exit(void)
{
    int ret;
    ret = Step_A();
    ret = Step_B();
    return ret;
}

/* 10.4: U suffix added, index wraps when n is 0 */
uint8_t last_byte(const uint8_t *buf, uint32_t n)
{
    return buf[n - 1U];
}

/* 21.7 / 21.6: banned functions moved behind a project name */
int Str_ToInt(const char *s)
{
    return atoi(s);
}

int App_Printf(const char *fmt)
{
    return 0;
}

/* Compliance: compiler warning switched off with no deviation record */
#pragma GCC diagnostic ignored "-Wconversion"
