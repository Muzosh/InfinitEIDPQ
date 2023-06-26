#ifndef OWNER_PIN_H
#define OWNER_PIN_H

#include <Arduino.h>
#include <nvs_flash.h>

#include "storage/storage-handler-NVS.h"
#include "utils/supported-instructions.h"

#define PIN_PATH(mode) ("P" + String(mode))
#define PIN_IV_PATH(mode) (PIN_PATH(mode) + "_iv")
#define PIN_STATE_PATH(mode) (PIN_PATH(mode) + "_state") // 0 = not validated, 1 = validated
#define PIN_TRIES_LEFT_PATH(mode) (PIN_PATH(mode) + "_tries_left")

#define PIN_STATE_INVALIDATED 0
#define PIN_STATE_VALIDATED 1

#define PIN_PADDING_LENGTH 256
#define PIN_MIN_SIZE 6
#define PIN_MAX_SIZE 256
#define USER_PIN_MAX_TRIES 3
#define ADMIN_PIN_MAX_TRIES 3
#define PIN_MAX_TRIES(mode) (mode == MODE_ADMIN ? ADMIN_PIN_MAX_TRIES : USER_PIN_MAX_TRIES)

bool adminPinExists();

class OwnerPin
{
public:
    OwnerPin(uint8_t mode);

    void changePin(const uint8_t* pin, const size_t pinSize);
    bool check(const uint8_t* pin, const size_t pinSize);
    bool isValidated();
    void invalidate();
    void reset();
    void resetAndUnblock();
    uint8_t getTriesLeft();
    bool isBlocked();

private:
    bool comparePins(const uint8_t* pin, const size_t pinSize, const uint8_t* storedPin);
    const uint8_t _mode;
};

#endif