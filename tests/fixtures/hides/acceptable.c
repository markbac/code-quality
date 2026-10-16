/* Legitimate uses of casts and related constructs.
 *
 * Every function here uses a language feature that misra_hide_scan.py also
 * looks at, in a way that does NOT hide a hazard. The scanner must report
 * no findings for this file. If a change to the scanner makes it report
 * anything here, that change has introduced a false positive.
 */
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

typedef float float32_t;

typedef struct
{
    uint16_t id;
    uint16_t len;
} header_t;

extern void Fault_Report(uint32_t code);

/* Widening an operand BEFORE the arithmetic, so the operation is done in
 * the wider type. This is the fix for Rule 10.3/10.8, not a hide.
 */
uint16_t total_length(uint8_t a, uint8_t b)
{
    return (uint16_t)a + (uint16_t)b;
}

uint32_t area(uint16_t w, uint16_t h)
{
    return (uint32_t)w * h;
}

/* Byte extraction. A right shift or a mask cannot make the value larger,
 * so narrowing the result is intentional and safe.
 */
void put_u16_be(uint8_t out[2], uint16_t v)
{
    out[0] = (uint8_t)(v >> 8U);
    out[1] = (uint8_t)(v & 0xFFU);
}

/* Assembling a value from bytes, the fix for Rule 11.3 type punning.
 * The outermost operator is '|', and each operand is widened first.
 */
uint16_t get_u16_be(const uint8_t in[2])
{
    return (uint16_t)(((uint16_t)in[0] << 8U) | (uint16_t)in[1]);
}

/* Narrowing a single value after an explicit range check. The scanner
 * cannot see the check, so it never reports a cast of a plain variable.
 */
uint8_t clamp_to_u8(uint32_t v)
{
    uint32_t limited = (v > 255U) ? 255U : v;
    return (uint8_t)limited;
}

/* Enum to integer for an interface that takes an integer code. */
typedef enum { FAULT_NONE, FAULT_OVERTEMP } fault_t;

void report(fault_t f)
{
    Fault_Report((uint32_t)f);
}

/* Integer to floating point before a division, so it is not integer
 * division. Casting an operand, not a result.
 */
float32_t average(uint32_t sum, uint32_t count)
{
    return (float32_t)sum / (float32_t)count;
}

/* (void) on an unused parameter: not a function call, nothing discarded. */
void callback(void *context)
{
    (void)context;
}

/* (void) on memcpy and memset: their return is just the destination
 * pointer and carries no error information.
 */
void copy_header(header_t *dst, const header_t *src)
{
    (void)memcpy(dst, src, sizeof(*dst));
}

/* Viewing an object as bytes. C permits access to any object through a
 * character type, and bytes have no alignment requirement.
 */
uint8_t checksum(const header_t *h)
{
    const uint8_t *p = (const uint8_t *)h;
    uint8_t sum = 0U;

    for (size_t i = 0U; i < sizeof(*h); i++)
    {
        sum ^= p[i];
    }
    return sum;
}

/* Reading an unaligned value safely through memcpy, then using it. The
 * casts here are to void and to a byte pointer, neither of which is a
 * reinterpretation hazard.
 */
uint32_t read_u32_native(const uint8_t *buf)
{
    uint32_t v;
    (void)memcpy(&v, (const void *)&buf[1], sizeof(v));
    return v;
}

/* A memory-mapped register with a proper deviation record. */
/* Deviation DEV-011: Rule 11.4
 * Scope:     this macro only
 * Reason:    Memory-mapped peripheral register at a fixed address.
 * Risk:      Address fixed by the device datasheet and checked at review.
 * Approved:  <architect>, <date>
 */
#define UART0_CTRL ((volatile uint32_t *)0x40001000UL)

/* An analyser suppression that cites its deviation record. */
uint32_t uart_status(void)
{
    return *UART0_CTRL; /* polyspace MISRA2012:11.4 [Justified] DEV-011 */
}

/* A superloop with no exit: intentionally endless, not a replaced
 * condition, so not reported.
 */
extern void Scheduler_Tick(void);

void main_loop(void)
{
    while (1)
    {
        Scheduler_Tick();
    }
}

/* A default that handles the unexpected value. */
void step(uint8_t state)
{
    switch (state)
    {
        case 0U:
            Scheduler_Tick();
            break;
        default:
            Fault_Report((uint32_t)state);
            break;
    }
}

/* Code inside comments and strings is ignored by the cast checks:
 *   uint8_t t = (uint8_t)(a + b);
 * (Suppression comments are the exception: they are comments by nature,
 * so the suppression check reads comments deliberately.)
 */
const char *const HELP = "(uint8_t)(a + b) and (void)Flash_Write() in a string";

/* ---- Look-alikes of the non-cast hides, used legitimately -------------- */

extern int Step_A(void);
extern int Step_B(void);
extern int Sensor_Read(uint16_t *out);
extern volatile uint32_t * const WDT_REG;

/* (void) on a parameter is the normal unused-parameter idiom. */
void on_event(uint8_t unused_param)
{
    (void)unused_param;
}

/* Pointer to volatile for a hardware register is what volatile is for. */
void kick_watchdog(void)
{
    volatile uint32_t *reg = WDT_REG;
    *reg = 0xA5A5U;
}

/* The result is stored, then checked. */
int read_sensor(uint16_t *out)
{
    int rc = Sensor_Read(out);
    if (rc != 0)
    {
        Fault_Report(1U);
    }
    return rc;
}

/* Stop at the first failure: each result is checked before the next step. */
int run_steps(void)
{
    int ret = Step_A();

    if (ret == 0)
    {
        ret = Step_B();
    }
    return ret;
}

/* Writes in sibling branches are not overwrites. */
int classify(uint8_t v)
{
    int result;

    if (v > 10U)
    {
        result = 2;
    }
    else
    {
        result = 1;
    }
    return result;
}

/* Overwriting a constant initial value is normal. */
int with_default(void)
{
    int status = -1;
    status = Step_A();
    return status;
}

/* Polling loop: the value is read by the loop condition. */
int poll_until_ready(void)
{
    int rc = 1;

    while (rc != 0)
    {
        rc = Step_A();
    }
    return rc;
}

/* Assignment inside a condition is read immediately. */
int checked_inline(void)
{
    int ret;

    if ((ret = Step_A()) != 0)
    {
        return ret;
    }
    return 0;
}

/* Guarded index: n - 1U cannot wrap. */
uint8_t last_or_zero(const uint8_t *buf, uint32_t n)
{
    uint8_t v = 0U;

    if (n > 0U)
    {
        v = buf[n - 1U];
    }
    return v;
}

/* Pragmas that do not switch diagnostics off. */
#pragma once
#pragma pack(push, 1)
#pragma pack(pop)

/* A wrapper with a deviation record. */
/* Deviation DEV-020: Rule 21.6
 * Scope:     Debug_Log only; compiled out in release builds.
 * Reason:    Bench diagnostics over semihosting.
 * Approved:  <architect>, <date>
 */
int Debug_Log(const char *msg)
{
    return puts(msg);
}
