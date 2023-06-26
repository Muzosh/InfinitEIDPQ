#ifndef COMMON_VARIABLES_H
#define COMMON_VARIABLES_H

#include <vector>
#include <nvs.h>
#include "encryption/symmetric.h"

extern std::vector<uint8_t> tempPIN;
extern uint8_t globalSalt[];
extern nvs_handle_t global_nvs_handle;
#endif