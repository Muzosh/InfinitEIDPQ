#ifndef HELPER_H
#define HELPER_H

#include <Arduino.h>

bool isLittleEndian();

std::array<uint8_t, 2> getBigEndianSwBytes(unsigned short sw);

#endif