#include "instruction/instructions.h"
#include <esp32-hal.h>

const uint8_t VERSION[3] = {0x00, 0x00, 0x01};
const uint8_t SERIALID[10] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10};

// SERIALID[10] HAS_PINPAD{0x00 or 0x01} VERSION[3] 0xFF 0x01 [SUPPORTED_SIGNATURE_ALGORITHMS] 0xFF
// 0x02 [INITIALIZED_SIGNATURE_ALGORITHMS] 0xFF 0x00
unsigned short getStatus(uint8_t* responseBuffer, const uint16_t Le)
{
    if (Le != 0xFF) {
        debugBoth("[E] Le != 0xFF", Le);
        return SW_WRONG_LENGTH_EXPECTED;
    }

    std::vector<uint8_t> status;

    // Add serial ID
    status.insert(status.begin(), SERIALID, SERIALID + sizeof(SERIALID));

    // Add PIN pad support
    status.push_back(0x00);

    // Add version
    status.insert(status.end(), VERSION, VERSION + sizeof(VERSION));

    // Add supported signature algorithms
    status.push_back(0xFF);
    status.push_back(0x01);
    status.push_back(SUPPORTED_SIGNATURE_ALGORITHMS.size());
    for (auto const& algo : SUPPORTED_SIGNATURE_ALGORITHMS) {
        status.push_back(algo.first);
    }

    // Add initialized signature algorithms (i.e. has certificate)
    status.push_back(0xFF);
    status.push_back(0x02);

    std::vector<uint8_t> initializedAlgorithms;
    for (auto const& algo : SUPPORTED_SIGNATURE_ALGORITHMS) {
        bool authCert = nvs_storage::hasCertificateStored(algo.first, MODE_AUTH);
        bool signCert = nvs_storage::hasCertificateStored(algo.first, MODE_SIGN);

        if (authCert || signCert) {
            initializedAlgorithms.push_back(algo.first);

            uint8_t mode = 0x00;
            mode |= authCert ? MODE_AUTH : 0x00;
            mode |= signCert ? MODE_SIGN : 0x00;

            initializedAlgorithms.push_back(mode);
        }
    }

    status.push_back(initializedAlgorithms.size());
    for (auto const& byte : initializedAlgorithms) {
        status.push_back(byte);
    }

    // Check if status is not too big
    if (status.size() > Le) {
        debugBoth("[E] Status overexceeded maximum size of 256B", status.size());
        return SW_INTERNAL_ERROR;
    }

    // Copy status to response buffer
    std::copy(status.begin(), status.end(), responseBuffer);
    std::memset(responseBuffer + status.size(), 0xFF, Le - status.size());
    return SW_SUCCESS;
}

unsigned short verifyPin(const uint8_t* dataBuffer, const size_t dataLength, const uint8_t mode,
                         const uint16_t Le)
{
    tempPIN.clear();
    tempPIN.resize(0);
    debugMsg("[I] tempPin reset");

    LE_MUST_BE_0

    try {
        OwnerPin pin(mode);

        if (pin.isBlocked()) {
            debugMsg("[E] PIN is blocked");
            return SW_PIN_BLOCKED;
        }

        try {
            if (!pin.check(dataBuffer, dataLength)) {
                debugMsg("[E] PIN is incorrect");
                return SW_WRONG_PIN_X_TRIES_LEFT | pin.getTriesLeft();
            }
        } catch (const SecurityError& e) {
            debugMsg("[E] PIN is blocked");
            return SW_PIN_BLOCKED;
        }

        debugMsg("[S] PIN verified: " + String(mode));

        tempPIN.clear();
        tempPIN.resize(dataLength);
        std::memcpy(tempPIN.data(), dataBuffer, dataLength);

        debugMsg("[I] PIN copied to tempPIN");
    }
    CATCH_CUSTOM_ERRORS_AND_RETURN_SW

    return SW_SUCCESS;
}

unsigned short pinRetriesLeft(uint8_t* responseBuffer, const uint8_t mode, const uint16_t Le)
{
    tempPIN.clear();
    tempPIN.resize(0);
    debugMsg("[I] tempPin reset");

    if (Le != 2) {
        debugBoth("[E] Le != 2", Le);
        return SW_WRONG_LENGTH_EXPECTED;
    }

    try {
        OwnerPin pin(mode);

        responseBuffer[0] = pin.getTriesLeft();
        responseBuffer[1] = PIN_MAX_TRIES(mode);
    }
    CATCH_CUSTOM_ERRORS_AND_RETURN_SW

    return SW_SUCCESS;
}

unsigned short changePin(const uint8_t* dataBuffer, const size_t dataLength, const uint8_t mode,
                         const uint16_t Le)
{
    tempPIN.clear();
    tempPIN.resize(0);
    debugMsg("[I] tempPin reset");

    LE_MUST_BE_0

    if (mode == MODE_ADMIN) {
        debugMsg("[E] Admin PIN cannot be changed");
        return SW_SECURITY_STATUS_NOT_SATISFIED;
    }

    try {
        OwnerPin pin(mode);

        if (!pin.isValidated()) {
            debugMsg("[E] PIN is not validated");
            return SW_SECURITY_STATUS_NOT_SATISFIED;
        }

        pin.changePin(dataBuffer, dataLength);
        pin.reset();
    }
    CATCH_CUSTOM_ERRORS_AND_RETURN_SW

    return SW_SUCCESS;
}

unsigned short setPin(const uint8_t* dataBuffer, const size_t dataLength, const uint8_t mode,
                      const uint16_t Le)
{
    tempPIN.clear();
    tempPIN.resize(0);
    debugMsg("[I] tempPin reset");

    LE_MUST_BE_0

    try {
        if (adminPinExists() && !OwnerPin(MODE_ADMIN).isValidated()) {
            debugMsg("[E] Admin PIN was previously set and currently is not validated");
            return SW_SECURITY_STATUS_NOT_SATISFIED;
        }

        OwnerPin pin(mode);
        pin.changePin(dataBuffer, dataLength);
        pin.resetAndUnblock();

        OwnerPin(MODE_ADMIN).reset();
    }
    CATCH_CUSTOM_ERRORS_AND_RETURN_SW

    return SW_SUCCESS;
}

// Struct that is passed to created task (i.e. new thread)
struct GenerateKeypairParameters
{
    const SignatureAlgorithm algorithm;
    uint8_t* pk;
    uint8_t* sk;
    const TaskHandle_t callingTaskHandle;
};

void generate_keypair_task(void* pvParameters)
{
    GenerateKeypairParameters* params = (GenerateKeypairParameters*)pvParameters;
    debugMsg("[F] generate_keypair_task started");

    // debugMsg("[D] Before task");
    // debugVar(*params->pk);
    // debugVar(*(params->pk + 1));
    // debugVar(*(params->pk + 2));

    params->algorithm.generateKeypair(params->pk, params->sk);

    // debugMsg("[D] after task");
    // debugVar(*params->pk);
    // debugVar(*(params->pk + 1));
    // debugVar(*(params->pk + 2));

    // Notify the calling task that this task is done and code execution can continue
    xTaskNotifyGive(params->callingTaskHandle);

    debugMsg("[S] Generating keypair task finished");

    // Delete this task, so it doesn't take up resources
    vTaskDelete(NULL);
}

unsigned short generateKeypair(const SignatureAlgorithm algorithm, const uint8_t mode,
                               const uint16_t Le)
{
    // Lenght expected should be 0 since this function does not return any data, generation is
    // on-device
    LE_MUST_BE_0

    try {
        if (!OwnerPin(MODE_ADMIN).isValidated() || !OwnerPin(mode).isValidated()) {
            debugMsg("[E] Admin and user PIN are not validated");
            return SW_PIN_VERIFICATION_REQUIRED;
        }

        OwnerPin(MODE_ADMIN).reset();
        OwnerPin(mode).reset();
    }
    CATCH_CUSTOM_ERRORS_AND_RETURN_SW

    // Prepare variables in heap
    std::unique_ptr<uint8_t> pk(new uint8_t[algorithm.pklen]);
    std::unique_ptr<uint8_t> sk(new uint8_t[algorithm.sklen]);
    std::memset(pk.get(), 0, algorithm.pklen);
    std::memset(sk.get(), 0, algorithm.sklen);

    // Generate keypair
    // Even with modified (by moving variables to the heap) PQClean implementation,
    // 8MB of stack in looptask might still not be enough, so we create a new task with higher stack
    // size
    TaskHandle_t taskHandle;
    BaseType_t taskStatus;
    uint32_t free_internal_heap = esp_get_free_internal_heap_size();
    debugVar(free_internal_heap);
    debugVar(esp_get_free_heap_size());

    // void* ptr = heap_caps_malloc(100000, MALLOC_CAP_DEFAULT);
    // std::unique_ptr<uint8_t[]> ptr(new uint8_t[100000]);
    // debugMsg("ptr allocated 100000");
    // debugVar(esp_get_free_internal_heap_size());
    // debugVar(esp_get_free_heap_size());
    // heap_caps_free(ptr);
    // debugMsg("ptr freed");
    // debugVar(esp_get_free_internal_heap_size());
    // debugVar(esp_get_free_heap_size());
    // ptr.reset();

    uint32_t stack_size_bytes = (uint32_t)floor((double)free_internal_heap * 0.5);

    // Prepare parameters for the task
    GenerateKeypairParameters params = {algorithm, pk.get(), sk.get(), xTaskGetCurrentTaskHandle()};

    // Create the task and run it
    taskStatus = xTaskCreate(generate_keypair_task, "GenerateKeypairTask", stack_size_bytes,
                             (void*)&params, configMAX_PRIORITIES - 1, &taskHandle);

    // Check if the task was created successfully
    if (taskStatus != pdPASS) {
        debugMsg("[E] Task creation failed");
        debugVar(taskStatus);
        return SW_INTERNAL_ERROR;
    }

    // Wait for the keypair generation task to complete
    // xTaskNotifyWait() will block the calling task until the notification is received
    uint32_t ulNotificationValue;
    BaseType_t xResult = xTaskNotifyWait(0, ULONG_MAX, &ulNotificationValue, portMAX_DELAY);

    // Check if the task completed successfully
    if (xResult != pdPASS) {
        // Timeout occurred
        debugMsg("[E] Waiting for task timeout occurred or some other error");
        vTaskDelete(taskHandle);
        return SW_INTERNAL_ERROR;
    }
    debugMsg("[S] Keypair generated");

    // Store new keys in non-volatile memory
    try {
        nvs_storage::storeBlob(pk.get(), algorithm.pklen, PK_PATH(algorithm.ID, mode));
        nvs_storage::encryptAndStoreBlob(sk.get(), algorithm.sklen, SK_PATH(algorithm.ID, mode),
                                         tempPIN.data(), tempPIN.size());

        tempPIN.clear();
        tempPIN.resize(0);
        debugMsg("[I] tempPin reset");
    }
    CATCH_CUSTOM_ERRORS_AND_RETURN_SW

    // Return OK
    debugMsg("[S] Keypair stored");
    return SW_SUCCESS;
}

unsigned short getPublicKey(uint8_t* responseBuffer, const SignatureAlgorithm algorithm,
                            const uint8_t mode, const uint16_t Le)
{
    tempPIN.clear();
    tempPIN.resize(0);
    debugMsg("[I] tempPin reset");

    // Length expected should be the same as the public key length
    if ((size_t)Le != algorithm.pklen) {
        debugBoth("[E] Le is not pklen", Le);
        return SW_WRONG_LENGTH_EXPECTED;
    }

    // Prepare variables
    std::unique_ptr<uint8_t> pk(new uint8_t[algorithm.pklen]);

    // Obtain public key from non-volatile memory
    try {
        nvs_storage::obtainBlob(pk.get(), algorithm.pklen, PK_PATH(algorithm.ID, mode));
    }
    CATCH_CUSTOM_ERRORS_AND_RETURN_SW

    // Return OK and the key
    // Copy pk to responseBuffer
    std::memcpy(responseBuffer, pk.get(), algorithm.pklen);
    debugMsg("[S] Public key copied to response buffer");
    return SW_SUCCESS;
}

// TEMP - we should really be able to get the private key from the device since it is on-device
// generated, it's only here for debugging purposes
// TODO: remove this function
unsigned short getPrivateKey(uint8_t* responseBuffer, const SignatureAlgorithm algorithm,
                             const uint8_t mode, const uint16_t Le)
{
    // Lenght expected should be the same as the private key length
    if ((size_t)Le != algorithm.sklen) {
        debugBoth("[E] Le is not sklen", Le);
        return SW_WRONG_LENGTH_EXPECTED;
    }

    try {
        if (!OwnerPin(MODE_ADMIN).isValidated() || !OwnerPin(mode).isValidated()) {
            debugMsg("[E] Admin and User PIN are not validated");
            return SW_PIN_VERIFICATION_REQUIRED;
        }

        OwnerPin(MODE_ADMIN).reset();
        OwnerPin(mode).reset();
    }
    CATCH_CUSTOM_ERRORS_AND_RETURN_SW

    // Prepare variables
    std::unique_ptr<uint8_t> sk(new uint8_t[algorithm.sklen]);

    // Obtain private key from non-volatile memory
    try {
        nvs_storage::decryptAndObtainBlob(sk.get(), algorithm.sklen, SK_PATH(algorithm.ID, mode),
                                          tempPIN.data(), tempPIN.size());

        tempPIN.clear();
        tempPIN.resize(0);
        debugMsg("[I] tempPin reset");
    }
    CATCH_CUSTOM_ERRORS_AND_RETURN_SW

    // Return OK and the key
    std::memcpy(responseBuffer, sk.get(), algorithm.sklen);
    debugMsg("[S] Private key copied to response buffer");
    return SW_SUCCESS;
}

unsigned short getCertificate(uint8_t* responseBuffer, const SignatureAlgorithm algorithm,
                              const uint8_t mode, const uint16_t Le)
{
    tempPIN.clear();
    tempPIN.resize(0);
    debugMsg("[I] tempPin reset");

    // Prepare variables - we use vector here because we don't know the size of the certificate yet,
    // let filesystem determine the size (vector is a dynamic array, so we can resize it later in
    // obtainObjectAndLength function)
    std::vector<uint8_t> certificate = std::vector<uint8_t>(0);
    size_t certificateLen = 0;

    // Obtain certificate and its length from non-volatile memory
    try {
        debugMsg("[O] Calling obtainBlob with 0 object to obtain length");
        nvs_storage::obtainBlobAndLength(0, certificateLen,
                                         CERT_PATH(algorithm.ID, mode)); // Get length
        certificate.resize(certificateLen);
        debugMsg("[O] Calling obtainBlob to obtain certificate");
        nvs_storage::obtainBlob(certificate.data(), certificateLen,
                                CERT_PATH(algorithm.ID, mode)); // Get length
    }
    CATCH_CUSTOM_ERRORS_AND_RETURN_SW

    debugMsg("[I] Obtained certificate and its length");
    // debugVar(certificateLen);
    // debugVar(certificate.size());
    // debugVar(certificate.at(0));
    // debugVar(certificate.at(1));
    // debugVar(certificate.at(2));

    // Lenght expected should be the same as the certificate length
    // NOTE: It can also be smaller, in which case we return the first Le bytes (this is commonly
    // used to get the ASN1 length and call command again with proper size)
    if (Le > certificateLen) {
        debugMsg("[E] Le is higher than certificate length");
        debugVar(Le);
        debugVar(certificateLen);
        return SW_WRONG_LENGTH_EXPECTED;
    }

    // Return OK and the certificate
    std::memcpy(responseBuffer, certificate.data(), Le);
    return SW_SUCCESS;
}

unsigned short setCertificate(const uint8_t* dataBuffer, const size_t dataLength,
                              const SignatureAlgorithm algorithm, const uint8_t mode,
                              const uint16_t Le)
{
    tempPIN.clear();
    tempPIN.resize(0);
    debugMsg("[I] tempPin reset");

    // Lenght expected should be 0x00, because we don't expect any data
    if (Le != 0x00) {
        debugBoth("[E] Le is not 0x00", Le);
        return SW_WRONG_LENGTH_EXPECTED;
    }

    try {
        if (!OwnerPin(MODE_ADMIN).isValidated() || !OwnerPin(mode).isValidated()) {
            debugMsg("[E] Admin and user PIN are not validated");
            return SW_PIN_VERIFICATION_REQUIRED;
        }

        OwnerPin(MODE_ADMIN).reset();
        OwnerPin(mode).reset();
    }
    CATCH_CUSTOM_ERRORS_AND_RETURN_SW

    debugMsg("[O] Storing certificate");
    // Store certificate in non-volatile memory
    try {
        nvs_storage::storeBlob(dataBuffer, dataLength, CERT_PATH(algorithm.ID, mode));
    }
    CATCH_CUSTOM_ERRORS_AND_RETURN_SW

    debugMsg("[S] Certificate stored");

    // Return OK
    return SW_SUCCESS;
}

// Struct that is passed to created task (i.e. new thread)
struct CreateSignatureParameters
{
    const SignatureAlgorithm algorithm;
    uint8_t* sig;
    size_t* siglen;
    const uint8_t* msg;
    const size_t msglen;
    const uint8_t* sk;
    const TaskHandle_t callingTaskHandle;
};

void create_signature_task(void* pvParameters)
{
    CreateSignatureParameters* params = (CreateSignatureParameters*)pvParameters;

    // debugMsg("[D] before task");
    // debugVar(*params->sig);
    // debugVar(*(params->sig + 1));
    // debugVar(*(params->sig + 2));

    params->algorithm.signature(params->sig, params->siglen, params->msg, params->msglen,
                                params->sk);

    // debugMsg("[D] after task");
    // debugVar(*params->sig);
    // debugVar(*(params->sig + 1));
    // debugVar(*(params->sig + 2));

    // Notify the calling task that we are done and code execution can continue
    xTaskNotifyGive(params->callingTaskHandle);

    debugMsg("[S] Signature task finished");

    // Delete this task, so it doesn't take up resources
    vTaskDelete(NULL);
}

unsigned short createSignature(uint8_t* responseBuffer, const uint8_t* dataBuffer,
                               const size_t dataLength, const SignatureAlgorithm algorithm,
                               const uint8_t mode, const uint16_t Le)
{
    // Lenght expected should be the same as the signature length
    if (Le != algorithm.siglen) {
        debugBoth("[E] Le is not siglen", Le);
        return SW_WRONG_LENGTH_EXPECTED;
    }

    try {
        if (!OwnerPin(mode).isValidated()) {
            debugMsg("[E] USER PIN is not validated");
            return SW_PIN_VERIFICATION_REQUIRED;
        }

        OwnerPin(mode).reset();
    }
    CATCH_CUSTOM_ERRORS_AND_RETURN_SW

    // Prepare variables in heap
    std::unique_ptr<uint8_t> sk(new uint8_t[algorithm.sklen]);
    std::unique_ptr<uint8_t> sig(new uint8_t[algorithm.siglen]);
    std::unique_ptr<size_t> siglen(new size_t);
    std::memset(sk.get(), 0, algorithm.sklen);
    std::memset(sig.get(), 0, algorithm.siglen);
    *siglen = 0;

    // Get secret key from non-volatile memory
    try {
        nvs_storage::decryptAndObtainBlob(sk.get(), algorithm.sklen, SK_PATH(algorithm.ID, mode),
                                          tempPIN.data(), tempPIN.size());

        tempPIN.clear();
        tempPIN.resize(0);
        debugMsg("[I] tempPin reset");
    }
    CATCH_CUSTOM_ERRORS_AND_RETURN_SW

    debugMsg("[I] Secret key obtained");

    // Sign the message
    // Even with modified (by moving variables to the heap) PQClean implementation,
    // 8MB of stack in looptask might still not be enough, so we create a new task with higher stack
    // size
    TaskHandle_t taskHandle;
    BaseType_t taskStatus;
    uint32_t free_internal_heap = esp_get_free_internal_heap_size();
    debugVar(free_internal_heap);
    debugVar(esp_get_free_heap_size());

    // Get free memory, use 90 % of it
    uint32_t stack_size_bytes = (uint32_t)floor((double)free_internal_heap * 0.1);
    // Prepare parameters for the task
    CreateSignatureParameters params = {algorithm,
                                        sig.get(),
                                        siglen.get(),
                                        dataBuffer,
                                        dataLength,
                                        sk.get(),
                                        xTaskGetCurrentTaskHandle()};

    // Create the task and run it
    taskStatus = xTaskCreate(create_signature_task, "CreateSignatureTask", 32768,
                             (void*)&params, configMAX_PRIORITIES - 1, &taskHandle);

    // Check if the task was created successfully
    if (taskStatus != pdPASS) {
        debugMsg("[E] Task creation failed");
        debugVar(taskStatus);
        return SW_INTERNAL_ERROR;
    }

    // Wait for the keypair generation task to complete
    uint32_t ulNotificationValue;
    BaseType_t xResult = xTaskNotifyWait(0, ULONG_MAX, &ulNotificationValue, portMAX_DELAY);

    // Check if the task completed successfully
    if (xResult != pdPASS) {
        // Timeout occurred
        debugMsg("[E] Waiting for task timeout occurred or some other error");
        vTaskDelete(taskHandle);
        return SW_INTERNAL_ERROR;
    }
    debugMsg("[S] Signature created");

    // Check if the signature length is correct
    if ((algorithm.ID != FALCON1024.ID && *siglen.get() != algorithm.siglen)
        || (algorithm.ID == FALCON1024.ID && *siglen.get() > algorithm.siglen)) {
        debugMsg("[E] Signature length is not siglen");
        debugVar(*siglen.get());
        return SW_WRONG_DATA;
    }

    // Return OK and the signature
    std::memcpy(responseBuffer, sig.get(), algorithm.siglen);
    return SW_SUCCESS;
}