#ifndef LOGGING_H
#define LOGGING_H
#include <Arduino.h>
#include <randombytes.h>
#include <nvs.h>

#define DEBUG_ON 0

void debugMsg(const char* msg);

void log_error(const char* msg);

#endif