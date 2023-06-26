#include "logging.h"

void debugMsg(const String msg)
{
#ifdef DEBUG_ON
    nvs_handle_t nvs_handle;
    nvs_open("debug_logs", NVS_READWRITE, &nvs_handle);

    uint8_t buf[10];
    randombytes(buf, 10);
    String key = "";
    for (int i = 0; i < 10; i++) {
        key += String(buf[i]);
    }

    esp_err_t err = nvs_set_str(nvs_handle, key.substring(0, 15).c_str(), msg.c_str());
    if (err != ESP_OK) {
        throw FileError("Failed to write error log with message");
    }

    err = nvs_commit(nvs_handle);
    if (err != ESP_OK) {
        throw FileError("Failed to write error log with message");
    }
    nvs_close(nvs_handle);
#else
    return;
#endif
}

void print_and_erase_debug_logs()
{
    Serial.println("--------- Debug logs ---------");
    nvs_handle_t nvs_handle;
    esp_err_t err = nvs_open("debug_logs", NVS_READWRITE, &nvs_handle);
    if (err != ESP_OK) {
        Serial.println("Failed to open debug logs" + String(esp_err_to_name(err)));
    }

    nvs_iterator_t it = nvs_entry_find(NVS_DEFAULT_PART_NAME, "debug_logs", NVS_TYPE_ANY);
    while (it != NULL) {
        nvs_entry_info_t info;
        nvs_entry_info(it, &info);

        size_t length;
        err = nvs_get_str(nvs_handle, info.key, 0, &length);
        if (err != ESP_OK) {
            Serial.println("Failed to get message length");
        }
        char value[length];
        err = nvs_get_str(nvs_handle, info.key, value, &length);

        if (err != ESP_OK) {
            Serial.println("Failed to get debug log with message");
        }

        Serial.println(String(value));
        err = nvs_erase_key(nvs_handle, info.key);
        if (err != ESP_OK) {
            Serial.println("Failed to erase debug log with message");
        }
        it = nvs_entry_next(it);
    }
    nvs_commit(nvs_handle);
    nvs_release_iterator(it);
    nvs_close(nvs_handle);
    Serial.println("-------------------------------");
}

void log_error(const String msg)
{
    nvs_handle_t nvs_handle;
    nvs_open("error_logs", NVS_READWRITE, &nvs_handle);

    uint8_t buf[10];
    randombytes(buf, 10);
    String key = "";
    for (int i = 0; i < 10; i++) {
        key += String(buf[i]);
    }

    esp_err_t err = nvs_set_str(nvs_handle, key.substring(0, 15).c_str(), msg.c_str());
    if (err != ESP_OK) {
        throw FileError("Failed to write error log with message");
    }

    err = nvs_commit(nvs_handle);
    if (err != ESP_OK) {
        throw FileError("Failed to write error log with message");
    }
    nvs_close(nvs_handle);
}

void print_and_erase_error_logs()
{
    Serial.println("--------- Error logs ---------");
    nvs_handle_t nvs_handle;
    esp_err_t err = nvs_open("error_logs", NVS_READWRITE, &nvs_handle);
    if (err != ESP_OK) {
        Serial.println("Failed to open error logs" + String(esp_err_to_name(err)));
    }

    nvs_iterator_t it = nvs_entry_find(NVS_DEFAULT_PART_NAME, "error_logs", NVS_TYPE_ANY);
    while (it != NULL) {
        nvs_entry_info_t info;
        nvs_entry_info(it, &info);

        size_t length;
        err = nvs_get_str(nvs_handle, info.key, 0, &length);
        if (err != ESP_OK) {
            Serial.println("Failed to get message length");
        }
        char value[length];
        err = nvs_get_str(nvs_handle, info.key, value, &length);

        if (err != ESP_OK) {
            Serial.println("Failed to get error log with message");
        }

        Serial.println("Error log: " + String(value));
        err = nvs_erase_key(nvs_handle, info.key);
        if (err != ESP_OK) {
            Serial.println("Failed to erase error log with message");
        }
        it = nvs_entry_next(it);
    }
    nvs_commit(nvs_handle);
    nvs_release_iterator(it);
    nvs_close(nvs_handle);
    Serial.println("-------------------------------");
}