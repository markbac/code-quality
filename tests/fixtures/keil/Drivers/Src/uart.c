#include "board.h"

int uart_baud(void)
{
    return board_clock_mhz() * 1000;
}
