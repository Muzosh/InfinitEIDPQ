#include "common_variables.h"

std::vector<uint8_t> tempPIN;
uint8_t globalSalt[SALT_LENGTH] = {0};
nvs_handle_t global_nvs_handle;