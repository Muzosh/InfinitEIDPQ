#include "storage/storage-handler-NVS.h"

namespace nvs_storage
{
void encryptAndStoreBlob(const uint8_t* object, const size_t objectLen, const String key,
                         const uint8_t* pin, const size_t pinLen)
{
    debugMsg("[O] Encrypting and storing blob at: " + key);

    // Derive aesKey from PIN
    uint8_t aesKey[32];
    derivateKey(aesKey, 32, pin, pinLen);
    debugMsg("[I] AES key derived");
    // debugVar(aesKey[0]);
    // debugVar(aesKey[1]);
    // debugVar(aesKey[2]);
    // debugVar(aesKey[3]);

    // Create IV
    uint8_t iv[IV_LENGTH];
    randombytes(iv, IV_LENGTH);

    // Encrypt object
    uint8_t encryptedObject[objectLen];

    aes256Encrypt(object, objectLen, encryptedObject, iv, aesKey, 32);
    debugMsg("[O] Object encrypted");

    // Store encrypted object
    storeBlob(encryptedObject, objectLen, key);

    // Store IV and offset
    storeBlob(iv, IV_LENGTH, key + "_iv");
}

void storeBlob(const uint8_t* object, const size_t objectLen, const String key)
{
    debugMsg("[O] Setting blob at: " + key);
    esp_err_t err = nvs_set_blob(global_nvs_handle, key.c_str(), object, objectLen);

    if (err != ESP_OK) {
        debugMsg("[E] Failed to set blob at " + key + ", error: " + String(esp_err_to_name(err)));
        throw FileError(
            ("Failed to set blob at " + key + ", error: " + String(esp_err_to_name(err))).c_str());
    }

    debugMsg("[O] Blob set, comminting changes");
    err = nvs_commit(global_nvs_handle);
    if (err != ESP_OK) {
        debugMsg("[E] Failed to commit changes, error: " + String(esp_err_to_name(err)));
        throw FileError(
            ("Failed to commit changes, error: " + String(esp_err_to_name(err))).c_str());
    }
}

void storeByte(const uint8_t object, const String key)
{
    debugMsg("[O] Setting byte at: " + key);
    esp_err_t err = nvs_set_u8(global_nvs_handle, key.c_str(), object);

    if (err != ESP_OK) {
        debugMsg("[E] Failed to set byte at " + key + ", error: " + String(esp_err_to_name(err)));
        throw FileError(
            ("Failed to set byte at " + key + ", error: " + String(esp_err_to_name(err))).c_str());
    }

    debugMsg("[I] Byte set, commiting changes");
    err = nvs_commit(global_nvs_handle);
    if (err != ESP_OK) {
        debugMsg("[E] Failed to commit changes, error: " + String(esp_err_to_name(err)));
        throw FileError(
            ("Failed to commit changes, error: " + String(esp_err_to_name(err))).c_str());
    }
}

void decryptAndObtainBlob(uint8_t* object, const size_t objectLen, const String key,
                          const uint8_t* pin, const size_t pinLen)
{
    debugMsg("[O] Decrypting and obtaining blob at: " + key);
    // Derive aesKey from PIN
    uint8_t aesKey[32];
    derivateKey(aesKey, 32, pin, pinLen);
    debugMsg("[I] AES key derived");
    // debugVar(aesKey[0]);
    // debugVar(aesKey[1]);
    // debugVar(aesKey[2]);
    // debugVar(aesKey[3]);

    // Obtain encrypted object
    uint8_t encryptedObject[objectLen];
    obtainBlob(encryptedObject, objectLen, key);

    // Obtain IV and IV offset
    uint8_t iv[IV_LENGTH];
    obtainBlob(iv, IV_LENGTH, key + "_iv");

    // Decrypt object
    aes256Decrypt(encryptedObject, objectLen, object, iv, aesKey, 32);
    debugMsg("[S] Object decrypted");
}

void obtainBlob(uint8_t* object, const size_t objectLen, const String key)
{
    debugMsg("[O] Getting blob at: " + key);
    size_t returnedLen = objectLen;
    esp_err_t err = nvs_get_blob(global_nvs_handle, key.c_str(), object, &returnedLen);

    debugBoth("[D] Returned length", objectLen);

    if (err != ESP_OK) {
        debugMsg("[E] Failed to get blob at " + key + ", error: " + String(esp_err_to_name(err)));
        throw FileError(
            ("Failed to get blob at " + key + ", error: " + String(esp_err_to_name(err))).c_str());
    }

    if (returnedLen != objectLen) {
        debugMsg("[E] Returned length does not match expected length");
        throw WrongLeError("Returned length does not match expected length");
    }

    debugMsg("[S] Blob obtained");
}

void obtainBlobAndLength(uint8_t* object, size_t& objectLen, const String key)
{
    debugMsg("[O] Getting blob and length at: " + key);
    esp_err_t err = nvs_get_blob(global_nvs_handle, key.c_str(), object, &objectLen);

    debugBoth("[D] Returned length", objectLen);

    if (err != ESP_OK) {
        debugMsg("[E] Failed to get blob at " + key + ", error: " + String(esp_err_to_name(err)));
        throw FileError(
            ("Failed to get blob at " + key + ", error: " + String(esp_err_to_name(err))).c_str());
    }

    debugMsg("[S] Blob obtained");
}

void obtainByte(uint8_t& object, const String key)
{
    debugMsg("[O] Getting byte at: " + key);
    esp_err_t err = nvs_get_u8(global_nvs_handle, key.c_str(), &object);

    if (err != ESP_OK) {
        debugMsg("[E] Failed to get byte at " + key + ", error: " + String(esp_err_to_name(err)));
        throw FileError(
            ("Failed to get byte at " + key + ", error: " + String(esp_err_to_name(err))).c_str());
    }

    debugBoth("[S] Byte obtained, value", object);
}

bool hasCertificateStored(uint8_t algorithmID, uint8_t mode)
{
    debugMsg("[O] Checking if certificate is stored: " + CERT_PATH(algorithmID, mode));
    size_t dummyLen;
    esp_err_t err =
        nvs_get_blob(global_nvs_handle, CERT_PATH(algorithmID, mode).c_str(), NULL, &dummyLen);
    if (err == ESP_ERR_NVS_NOT_FOUND) {
        debugMsg("[I] Certificate not found");
        return false;
    }
    debugMsg("[I] Certificate found");
    return true;
}

void printStorageInfo()
{
    nvs_stats_t stats;
    esp_err_t err = nvs_get_stats(NVS_DEFAULT_PART_NAME, &stats);
    if (err != ESP_OK) {
        debugMsg("[E] Failed to get stats, error: " + String(esp_err_to_name(err)));
        throw FileError(("Failed to get stats, error: " + String(esp_err_to_name(err))).c_str());
    }
    Serial.println("--------- NVS Storage info ---------");
    Serial.println("Total entries: " + String(stats.total_entries));
    Serial.println("Used entries: " + String(stats.used_entries));
    Serial.println("Free entries: " + String(stats.free_entries));
    listKeysAndValues();
    Serial.println("--------------------------------");
}

void listKeysAndValues()
{
    nvs_iterator_t it = nvs_entry_find(NVS_DEFAULT_PART_NAME, "nvs_storage", NVS_TYPE_ANY);
    while (it != NULL) {
        nvs_entry_info_t info;
        nvs_entry_info(it, &info);
        if (info.type == NVS_TYPE_BLOB) {
            size_t len;
            nvs_get_blob(global_nvs_handle, info.key, NULL, &len);
            Serial.println("- Key: " + String(info.key) + " (" + String(len) + " B)");
        } else {
            Serial.println("- Key: " + String(info.key));
        }
        it = nvs_entry_next(it);
    }
    nvs_release_iterator(it);
}
} // namespace nvs_storage