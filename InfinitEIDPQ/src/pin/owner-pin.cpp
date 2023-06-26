#include "owner-pin.h"

bool adminPinExists()
{
    uint8_t storedPin[PIN_PADDING_LENGTH];

    // Get stored PIN
    nvs_storage::obtainBlob(storedPin, PIN_PADDING_LENGTH, PIN_PATH(MODE_ADMIN));

    debugMsg("[I] PIN obtained");
    debugMsg("[O] Checking if PIN is default");

    // Check if PIN is default
    for (size_t i = 0; i < PIN_PADDING_LENGTH; i++) {
        if (storedPin[i] != 0xFF) {
            debugMsg("[I] PIN is not default");
            return true;
        }
    }

    debugMsg("[I] PIN is default");
    return false;
}

bool OwnerPin::comparePins(const uint8_t* pin, const size_t pinSize, const uint8_t* storedPin)
{
    debugBoth("Comparing PINs, mode", _mode);
    for (size_t i = 0; i < pinSize; i++) {
        if (pin[i] != storedPin[i]) {
            return false;
        }
    }
    return true;
}

OwnerPin::OwnerPin(uint8_t mode) : _mode(mode)
{
    uint8_t dummy;
    esp_err_t err = nvs_get_u8(global_nvs_handle, PIN_STATE_PATH(_mode).c_str(), &dummy);
    if (err == ESP_ERR_NVS_NOT_FOUND) {
        uint8_t defaultPin[PIN_PADDING_LENGTH];
        memset(defaultPin, 0xFF, PIN_PADDING_LENGTH);

        nvs_storage::storeBlob(defaultPin, PIN_PADDING_LENGTH,
                               PIN_PATH(_mode)); // Empty PIN
        nvs_storage::storeByte(PIN_STATE_INVALIDATED,
                               PIN_STATE_PATH(_mode)); // Not validated
        nvs_storage::storeByte(
            0,
            PIN_TRIES_LEFT_PATH(_mode)); // 0 tries left = blocked -> resetAndUnblock() needed first
    }
}

uint8_t OwnerPin::getTriesLeft()
{
    debugBoth("[O] Getting tries left, mode", _mode);
    uint8_t tries_left;
    nvs_storage::obtainByte(tries_left, PIN_TRIES_LEFT_PATH(_mode));
    return tries_left;
}

bool OwnerPin::isBlocked()
{
    debugBoth("[O] Checking if PIN is blocked, mode", _mode);
    return getTriesLeft() == 0;
}

void OwnerPin::changePin(const uint8_t* pin, const size_t pinSize)
{
    debugBoth("[O] Changing PIN, mode", _mode);

    if (pinSize > PIN_MAX_SIZE) {
        debugBoth("[E] PIN too long", pinSize);
        throw SecurityError(String(_mode).c_str());
    }

    if (pinSize < PIN_MIN_SIZE) {
        debugBoth("[E] PIN too short", pinSize);
        throw SecurityError(String(_mode).c_str());
    }

    for (size_t i = 0; i < pinSize; i++) {
        if (pin[i] < 0x30 || pin[i] > 0x39) {
            debugBoth("[E] PIN contains non-numeric characters (ascii)", pin[i]);
            throw SecurityError(String(_mode).c_str());
        }
    }

    // Pad PIN with 0xFF
    uint8_t paddedPin[PIN_PADDING_LENGTH];
    memset(paddedPin, 0xFF, PIN_PADDING_LENGTH);
    memcpy(paddedPin, pin, pinSize);

    // Encrypt and store PIN
    nvs_storage::encryptAndStoreBlob(paddedPin, PIN_PADDING_LENGTH, PIN_PATH(_mode), pin, pinSize);
}

bool OwnerPin::check(const uint8_t* pin, const size_t pinSize)
{
    debugBoth("[O] Checking PIN, mode", _mode);

    // Check if PIN is blocked
    uint8_t triesLeft = getTriesLeft();

    if (triesLeft == 0) {
        throw SecurityError(String(_mode).c_str());
    }

    // Get stored PIN
    uint8_t storedPin[PIN_PADDING_LENGTH];

    nvs_storage::decryptAndObtainBlob(storedPin, PIN_PADDING_LENGTH, PIN_PATH(_mode), pin, pinSize);

    // Pad input PIN with 0xFF
    uint8_t paddedPin[PIN_PADDING_LENGTH];
    memset(paddedPin, 0xFF, PIN_PADDING_LENGTH);
    memcpy(paddedPin, pin, pinSize);

    // Compare PINs
    if (comparePins(pin, pinSize, storedPin)) {
        // If PIN is correct, reset tries left and set state to validated
        nvs_storage::storeByte(PIN_STATE_VALIDATED, PIN_STATE_PATH(_mode));
        nvs_storage::storeByte(PIN_MAX_TRIES(_mode), PIN_TRIES_LEFT_PATH(_mode));
        return true;
    } else {
        // If PIN is incorrect, decrement tries left
        nvs_storage::storeByte(triesLeft - 1, PIN_TRIES_LEFT_PATH(_mode));
        return false;
    }
}

bool OwnerPin::isValidated()
{
    debugBoth("[O] Checking if PIN is validated, mode", _mode);
    uint8_t state;
    nvs_storage::obtainByte(state, PIN_STATE_PATH(_mode));
    return state == PIN_STATE_VALIDATED;
}

void OwnerPin::invalidate()
{
    debugBoth("[O] Invalidating PIN, mode", _mode);
    nvs_storage::storeByte(PIN_STATE_INVALIDATED, PIN_STATE_PATH(_mode));
}

void OwnerPin::reset()
{
    debugBoth("[O] Resetting PIN, mode", _mode);
    // Cant use reset if PIN is blocked
    if (isBlocked()) {
        SecurityError(String(_mode).c_str());
    }

    resetAndUnblock();
}

void OwnerPin::resetAndUnblock()
{
    debugBoth("[O] Resetting and unblocking PIN, mode", _mode);
    uint8_t state;
    nvs_storage::obtainByte(state, PIN_STATE_PATH(_mode));

    if (state == PIN_STATE_VALIDATED) {
        invalidate();
    }

    nvs_storage::storeByte(PIN_MAX_TRIES(_mode), PIN_TRIES_LEFT_PATH(_mode));
}