#include "utils/helper.h"

bool isLittleEndian()
{
    uint16_t x = 0x0102;
    uint8_t* ptr = reinterpret_cast<uint8_t*>(&x);
    return *ptr == 0x02;
}

// some devices work in little_endian mode (bytes are sent in reverse order)
// most PCs work in big_endian mode, so we need to reverse the bytes
std::array<uint8_t, 2> getBigEndianSwBytes(unsigned short sw)
{
    if (isLittleEndian()) {
        return std::array<uint8_t, 2> {static_cast<uint8_t>(sw >> 8), static_cast<uint8_t>(sw)};
    } else {
        return std::array<uint8_t, 2> {static_cast<uint8_t>(sw), static_cast<uint8_t>(sw >> 8)};
    }
}