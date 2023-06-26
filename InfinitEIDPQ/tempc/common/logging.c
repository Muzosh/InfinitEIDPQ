#include "logging.h"

void debugMsg(const char* msg)
{
#ifdef DEBUG_ON
    nvs_handle_t nvs_handle;
    nvs_open("debug_logs", NVS_READWRITE, &nvs_handle);

    uint8_t buf[10];
    randombytes(buf, 10);

    esp_err_t err = nvs_set_str(nvs_handle, buf, msg);
    if (err != ESP_OK) {
        esp_restart();
    }

    err = nvs_commit(nvs_handle);
    if (err != ESP_OK) {
        esp_restart();
    }
    nvs_close(nvs_handle);
#else
    return;
#endif
}

void log_error(const char* msg)
{
    nvs_handle_t nvs_handle;
    nvs_open("error_logs", NVS_READWRITE, &nvs_handle);

    uint8_t buf[10];
    randombytes(buf, 10);

    esp_err_t err = nvs_set_str(nvs_handle, buf, msg);
    if (err != ESP_OK) {
        esp_restart();
    }

    err = nvs_commit(nvs_handle);
    if (err != ESP_OK) {
        esp_restart();
    }
    nvs_close(nvs_handle);
}
