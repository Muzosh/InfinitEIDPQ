#ifndef LOGGING_H
#define LOGGING_H
#include <Arduino.h>
#include <randombytes.h>
#include <nvs.h>

#include "exceptions.h"

#define DEBUG_ON 0

void debugMsg(const String msg);

#define debugVar(var) (debugMsg(String("[D] ") + String(#var) + String(": ") + String(var)))
#define debugBoth(msg, var) (debugMsg(String(msg) + String(": ") + String(var)))

void print_and_erase_debug_logs();

void log_error(const String msg);

void print_and_erase_error_logs();

#endif