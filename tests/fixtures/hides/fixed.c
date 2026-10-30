/* The hazards from hides.c, fixed rather than hidden.
 * The scanner should report nothing here at low severity
 * except the documented MMIO deviation being accepted.
 */
#include <stdint.h>
#include <stdbool.h>

#define BUFFER_SIZE  256U
#define MAX_RETRIES  3U
#define ERR_OK        0
#define ERR_TOO_LARGE 1
#define ERR_RADIO     2
#define ERR_PERSIST   3
#define FLASH_OK      0
#define RADIO_OK      0
#define FAULT_CAL_WRITE 7U

extern int  Flash_Write(uint32_t addr, const uint8_t *data, uint32_t len);
extern int  Radio_Send(const uint8_t *frame);
extern void Fault_Report(uint32_t code);
extern void Enter_Safe_State(void);

/* Deviation DEV-011: Rule 11.4
 * Scope:     this macro only
 * Reason:    Memory-mapped peripheral register at a fixed address.
 * Risk:      Address fixed by the device datasheet and checked at review.
 * Approved:  <architect>, <date>
 */
#define UART0_CTRL ((volatile uint32_t *)0x40001000UL)

/* Rule 10.3: widen before adding, then range-check. */
int check_length(uint8_t len_a, uint8_t len_b)
{
    uint16_t total = (uint16_t)len_a + (uint16_t)len_b;
    int result = ERR_OK;

    if (total > BUFFER_SIZE)
    {
        result = ERR_TOO_LARGE;
    }
    return result;
}

/* Rule 10.8: widen an operand so the multiply is done in 32 bits. */
uint32_t area(uint16_t w, uint16_t h)
{
    return (uint32_t)w * h;
}

/* Rule 11.3: assemble a little-endian value from bytes. */
uint32_t frame_id(const uint8_t rx[16])
{
    return ((uint32_t)rx[1])
         | ((uint32_t)rx[2] << 8)
         | ((uint32_t)rx[3] << 16)
         | ((uint32_t)rx[4] << 24);
}

/* Rule 17.7 / Dir 4.7: handle the failure. */
int save_calibration(uint32_t addr, const uint8_t *cal, uint32_t len)
{
    int result = ERR_OK;

    if (Flash_Write(addr, cal, len) != FLASH_OK)
    {
        Fault_Report(FAULT_CAL_WRITE);
        result = ERR_PERSIST;
    }
    return result;
}

/* Rule 14.3: bounded retries with an explicit failure path. */
int send_frame(const uint8_t *frame)
{
    bool sent = false;
    int result = ERR_OK;

    for (uint8_t attempt = 0U; (attempt < MAX_RETRIES) && !sent; attempt++)
    {
        sent = (Radio_Send(frame) == RADIO_OK);
    }

    if (!sent)
    {
        result = ERR_RADIO;
    }
    return result;
}

/* Rule 16.4: default says what an unexpected state means. */
typedef enum { STATE_IDLE, STATE_RUN } state_t;
extern void Do_Idle(void);
extern void Do_Run(void);

void step(state_t state)
{
    switch (state)
    {
        case STATE_IDLE:
            Do_Idle();
            break;
        case STATE_RUN:
            Do_Run();
            break;
        default:
            /* Only reachable through corruption. */
            Fault_Report((uint32_t)state);
            Enter_Safe_State();
            break;
    }
}
