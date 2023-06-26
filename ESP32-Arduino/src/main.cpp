#include <Arduino.h>
#include "instruction/ins-handler.h"
#include <base64.h>
#include "esp_core_dump.h"

// TDISPLAY
const int LED_PIN = 38; // LED pin
const int BUTTON_PIN = BUTTON_2; // User button pin

// DFRobot
// const int LED_PIN = D9; // LED pin
// const int BUTTON_PIN = D4; // User button pin

bool canOperate = true;
String runtimeID;

void blink(int delay_ms = 50);
void blink_three_times(int delay_ms = 50);

#include <sstream>
#include <iomanip>
#define BUFFER_SIZE 4096
#define PARTITION_NAME "coredump"

const esp_partition_t* findCoreDumpPartition()
{
    esp_partition_type_t p_type = ESP_PARTITION_TYPE_DATA;
    esp_partition_subtype_t p_subtype = ESP_PARTITION_SUBTYPE_DATA_COREDUMP;
    const char* label = PARTITION_NAME;

    return esp_partition_find_first(p_type, p_subtype, label);
}

void readCoreDump(const esp_partition_t* part_CoreDump, char* content, long offset, long size)
{
    esp_partition_read(part_CoreDump, offset, content, size);
}

void setup()
{
    // Initialize serial communication
    Serial.setRxBufferSize(8192);
    Serial.begin(115200);

    // Initialize pins
    pinMode(LED_PIN, OUTPUT);
    pinMode(BUTTON_PIN, INPUT_PULLUP);

    // Initialize NVS storage
    esp_err_t err = nvs_flash_init();
    if (err != ESP_OK) {
        canOperate = false;
        return;
    }

    // Open NVS storage
    err = nvs_open("nvs_storage", NVS_READWRITE, &global_nvs_handle);
    if (err != ESP_OK) {
        canOperate = false;
        return;
    }

    // Create runtime ID
    uint8_t buf[5];
    randombytes(buf, 5);
    runtimeID = "";
    for (int i = 0; i < 5; i++) {
        runtimeID += String(buf[i]);
    }
    runtimeID = runtimeID.substring(0, 5);

    debugBoth("[O] SETUP STARTED", runtimeID);

    // Load salt to RAM globally
    debugMsg("[O] Loading salt");
    size_t saltLength = SALT_LENGTH;
    err = nvs_get_blob(global_nvs_handle, SALT_KEY, globalSalt, &saltLength);

    if (err == ESP_ERR_NVS_NOT_FOUND) {
        // Create salt - load it to RAM globally
        randombytes(globalSalt, SALT_LENGTH);

        // Store salt
        nvs_storage::storeBlob(globalSalt, SALT_LENGTH, SALT_KEY);
        debugMsg("[I] Salt created");
    }

    try {
        debugMsg("[O] Invalidating pins");
        OwnerPin(MODE_ADMIN).invalidate();
        OwnerPin(MODE_AUTH).invalidate();
        OwnerPin(MODE_SIGN).invalidate();
    } catch (const FileError& e) {
        log_error("[E] Could not invalidate pins");
        canOperate = false;
        return;
    }

    // Blink three times to indicate setup is complete
    if (canOperate) {
        blink_three_times();
        debugBoth("[O] SETUP WAS SUCCESSFULL", runtimeID);
    }

    // If user button is held during setup (RST button), print storage info and logs
    if (digitalRead(BUTTON_PIN) == LOW) {
        nvs_storage::printStorageInfo();
        print_and_erase_debug_logs();
        print_and_erase_error_logs();

        size_t out_cd_addr;
        size_t out_cd_size;
        esp_core_dump_image_get(&out_cd_addr, &out_cd_size);

        Serial.println("Core dump address: " + String(out_cd_addr));
        Serial.println("Core dump size: " + String(out_cd_size));

        const esp_partition_t* partition = findCoreDumpPartition();

        if (NULL != partition) {
            Serial.println("[E] partition found with size: " + String(partition->size));

            std::unique_ptr<esp_core_dump_summary_t> s(new esp_core_dump_summary_t);
            if (s) {
                if (esp_core_dump_get_summary(s.get()) == ESP_OK) {

                    Serial.println("Summary:");
                    Serial.println("exc_tcb: " + String(s->exc_tcb));

                    std::unique_ptr<char> null_terminated(new char[17]);
                    if (null_terminated) {
                        memcpy(null_terminated.get(), s->exc_task, 16);
                        null_terminated.get()[16] = '\0';
                    }

                    Serial.println("exc_task: " + String(null_terminated.get()));

                    Serial.println("exc_pc: " + String(s->exc_pc));

                    Serial.println("core_dump_version: " + String(s->core_dump_version));

                    null_terminated.reset(new char[18]);
                    if (null_terminated) {
                        memcpy(null_terminated.get(), s->app_elf_sha256, 17);
                        null_terminated.get()[17] = '\0';
                    }

                    Serial.println("app_elf_sha256: " + String(null_terminated.get()));

                    null_terminated.reset(new char[17]);
                    if (null_terminated) {
                        memcpy(null_terminated.get(), s->exc_bt_info.bt, 16);
                        null_terminated.get()[16] = '\0';
                    }

                    Serial.println("exc_bt_info->bt:" + String(null_terminated.get()));

                    Serial.println("exc_bt_info->depth: " + String(s->exc_bt_info.depth));

                    Serial.println("exc_bt_info->corrupted: " + String(s->exc_bt_info.corrupted));

                    Serial.println("exc_info->exc_cause: " + String(s->ex_info.exc_cause));

                    Serial.println("exc_info->exc_vaddr: " + String(s->ex_info.exc_vaddr));

                    null_terminated.reset(new char[17]);
                    if (null_terminated) {
                        memcpy(null_terminated.get(), s->ex_info.exc_a, 16);
                        null_terminated.get()[16] = '\0';
                    }

                    Serial.println("ex_info->exc_a:" + String(null_terminated.get()));

                    null_terminated.reset(new char[7]);
                    if (null_terminated) {
                        memcpy(null_terminated.get(), s->ex_info.epcx, 6);
                        null_terminated.get()[6] = '\0';
                    }

                    Serial.println("ex_info->epcx:" + String(null_terminated.get()));
                } else {
                    Serial.println("Summary not found");
                }
            } else {
                Serial.println("Summary Null");
            }
        } else {
            Serial.println("partition not found");
        }
    }
}

void loop()
{
    if (!Serial) {
        blink(100);
        return;
    }

    // handleIncomingData() is blocking until 5 bytes are received
    if (canOperate) {
        debugBoth("[I] INS_HANDLER STARTED", runtimeID);
        handleIncomingData();
        debugBoth("[I] INS_HANDLER ENDED", runtimeID);
    } else {
        Serial.write(getBigEndianSwBytes(SW_INTERNAL_ERROR).data(), 2);
        blink();
        delay(20);
    }
}

void blink(int delay_ms)
{
    digitalWrite(LED_PIN, HIGH); // Turn on LED
    delay(delay_ms);
    digitalWrite(LED_PIN, LOW); // Turn off LED
}

void blink_three_times(int delay_ms)
{
    blink();
    delay(delay_ms);
    blink();
    delay(delay_ms);
    blink();
}
