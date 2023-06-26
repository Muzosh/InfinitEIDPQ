#include "randombytes.h"
#include <esp_random.h>

int randombytes(uint8_t* output, size_t n)
{
    void* buf = (void*)output;
    esp_fill_random(buf, n);
    return 0;
}
