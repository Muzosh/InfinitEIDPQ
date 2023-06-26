#include "loggingcpp.h"

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

    err = nvs_commit(nvs_handle);
    nvs_close(nvs_handle);
#else
    return;
#endif
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

    err = nvs_commit(nvs_handle);
    nvs_close(nvs_handle);
}
