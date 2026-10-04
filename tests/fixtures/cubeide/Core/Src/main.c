#include "app.h"
#include "hal.h"

#ifdef USE_HAL_DRIVER
#define STEP 2
#else
#define STEP 1
#endif

int app_step(int v)
{
    return hal_tick() + v * STEP;
}

int main(void)
{
    return app_step(1);
}
