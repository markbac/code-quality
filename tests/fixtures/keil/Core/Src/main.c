#include "board.h"

#ifdef STM32F407xx
#define CLOCK_MHZ 168
#else
#define CLOCK_MHZ 16
#endif

int board_clock_mhz(void)
{
    return CLOCK_MHZ;
}

int main(void)
{
    return board_clock_mhz() > 100 ? 0 : 1;
}
