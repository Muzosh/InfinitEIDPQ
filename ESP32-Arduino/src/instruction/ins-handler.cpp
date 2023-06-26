#include "ins-handler.h"

void handleIncomingData()
{
    // read the incoming data header (first 5 bytes)
    debugMsg("[O] Waiting for 5 bytes of header...");
    // set timeout to -1 to wait forever
    Serial.setTimeout(-1);
    uint8_t header[5];
    Serial.readBytes(header, 5);
    // set timeout to 3 seconds in case something goes wrong, so we don't get stuck but handle the
    // error
    Serial.setTimeout(3000);

    debugMsg("-------- New packet --------");
    const uint8_t INS = header[0];
    const uint8_t MODE = header[1];
    const uint8_t AL = header[2];
    const uint8_t Lc1 = header[3];
    const uint8_t Lc2 = header[4];
    uint16_t Lc;
    uint16_t Le;

    debugVar(INS);
    debugVar(MODE);
    debugVar(AL);
    debugVar(Lc1);
    debugVar(Lc2);

    // compute the length of the incoming data (Lc = Length contained)
    Lc = (((uint16_t)Lc1) << 8) | Lc2;
    debugVar(Lc);

    // read the full incoming data
    std::unique_ptr<uint8_t> dataBuffer(new uint8_t[Lc]);
    size_t rb = Serial.readBytes(dataBuffer.get(), Lc);
    debugBoth("Read bytes", rb);

    if (rb != Lc) {
        debugMsg("Didn't read all bytes");
        Serial.write(getBigEndianSwBytes(SW_INTERNAL_ERROR).data(), 2);
        return;
    }

    // read the last two bytes (Le = Length of Expected response)
    uint8_t Le1 = Serial.read();
    uint8_t Le2 = Serial.read();

    if (Le1 == -1 || Le2 == -1) {
        debugMsg("Le1 or Le2 was not present");
        Serial.write(getBigEndianSwBytes(SW_WRONG_LENGTH_EXPECTED).data(), 2);
        return;
    } else {
        // compute the length of the expected response (Le = Length expected)
        // from two bytes
        Le = (((uint16_t)Le1) << 8) | Le2;
    }

    debugVar(Le);

    // prepare the response buffer (+ 2 is for status words)
    std::unique_ptr<uint8_t[]> responseBuffer(new uint8_t[Le + 2]());
    debugMsg("[I] Response buffer allocated");

    unsigned short resultSW;

    // GET_STATUS requires ADMIN mode and AL = 0x00
    if (INS == INS_GET_STATUS) {
        if (MODE != MODE_ADMIN) {
            debugMsg("[E] MODE must be 0x00 for INS_GET_STATUS");
            Serial.write(getBigEndianSwBytes(SW_WRONG_ALGORITHM).data(), 2);
            return;
        }

        if (AL != 0x00) {
            debugMsg("[E] AL must be 0x00 for INS_GET_STATUS");
            Serial.write(getBigEndianSwBytes(SW_WRONG_ALGORITHM).data(), 2);
            return;
        }

        debugMsg("[O] Getting status");
        resultSW = getStatus(responseBuffer.get(), Le);
    }
    // All PIN instructions are 0xB. and require AL == 0
    else if ((INS & 0xB0) == 0xB0) {
        if (AL != 0x00) {
            debugMsg("[E] AL must be 0x00 for PIN instructions");
            Serial.write(getBigEndianSwBytes(SW_WRONG_ALGORITHM).data(), 2);
            return;
        }

        switch (INS) {
        case INS_VERIFY_PIN:
            debugBoth("[O] Verifying PIN", MODE);
            resultSW = verifyPin(dataBuffer.get(), Lc, MODE, Le);
            break;
        case INS_PIN_RETRIES_LEFT:
            debugBoth("[O] Getting PIN retries left", MODE);
            resultSW = pinRetriesLeft(responseBuffer.get(), MODE, Le);
            break;
        case INS_CHANGE_PIN:
            debugBoth("[O] Changing PIN", MODE);
            resultSW = changePin(dataBuffer.get(), Lc, MODE, Le);
            break;
        case INS_SET_PIN:
            debugBoth("[O] Setting PIN", MODE);
            resultSW = setPin(dataBuffer.get(), Lc, MODE, Le);
            break;
        }
    }
    // All other instruction require AUTH or SIGN mode and known AL
    else {
        // check if the mode is supported
        if (MODE != MODE_AUTH && MODE != MODE_SIGN) {
            debugBoth("[E] Unsupported mode", MODE);
            Serial.write(getBigEndianSwBytes(SW_WRONG_MODE).data(), 2);
            return;
        }

        // check if the algorithm is supported
        if (SUPPORTED_SIGNATURE_ALGORITHMS.find(AL) == SUPPORTED_SIGNATURE_ALGORITHMS.end())
        // in case we add KEM later:|| (SUPPORTED_KEY_ENCAPSULATION_ALGORITHMS.find(AL) ==
        // SUPPORTED_KEY_ENCAPSULATION_ALGORITHMS.end()))
        {
            debugBoth("[E] Unsupported algorithm", AL);
            Serial.write(getBigEndianSwBytes(SW_WRONG_ALGORITHM).data(), 2);
            return;
        }

        const SignatureAlgorithm algorithm = SUPPORTED_SIGNATURE_ALGORITHMS.at(AL);

        switch (INS) {
        case INS_GET_STATUS:
            debugMsg("[O] Getting status");
            resultSW = getStatus(responseBuffer.get(), Le);
            break;
        case INS_GENERATE_KEYPAIR:
            debugMsg("[O] Generating keypair");
            resultSW = generateKeypair(algorithm, MODE, Le);
            break;
        case INS_GET_PUBLIC_KEY:
            debugMsg("[O] Getting public key");
            resultSW = getPublicKey(responseBuffer.get(), algorithm, MODE, Le);
            break;
        case INS_GET_PRIVATE_KEY:
            debugMsg("[O] Getting private key");
            resultSW = getPrivateKey(responseBuffer.get(), algorithm, MODE, Le);
            break;
        case INS_GET_CERTIFICATE: {
            debugMsg("[O] Getting certificate");
            resultSW = getCertificate(responseBuffer.get(), algorithm, MODE, Le);
            break;
        }
        case INS_SET_CERTIFICATE:
            debugMsg("[O] Setting certificate");
            resultSW = setCertificate(dataBuffer.get(), Lc, algorithm, MODE, Le);
            break;
        case INS_CREATE_SIGNATURE:
            debugMsg("[O] Creating signature");
            resultSW =
                createSignature(responseBuffer.get(), dataBuffer.get(), Lc, algorithm, MODE, Le);
            break;
        default:
            debugBoth("[E] Unsupported instruction", INS);
            Serial.write(getBigEndianSwBytes(SW_INSTRUCTION_NOT_ALLOWED).data(), 2);
            return;
            break;
        }
    }

    // check if an error occured, if so, send the status words (just 2 bytes) and return
    if (resultSW != SW_SUCCESS) {
        debugBoth("[E] Error occured", resultSW);
        Serial.write(getBigEndianSwBytes(resultSW).data(), 2);
    } else {
        // write the status words at the start of the response buffer
        std::array<uint8_t, 2> sw = getBigEndianSwBytes(resultSW);

        debugMsg("[O] Sending response\n");
        if (Le == 0) {
            // program doesn't expect any response, just send the status words
            Serial.write(sw.data(), 2);
            return;
        } else {
            // program expects a response, send the status words and the response
            // shift the response to the right by 2 bytes
            std::memmove(responseBuffer.get() + 2, responseBuffer.get(), Le);
            // add the status words at the first two bytes
            responseBuffer.get()[0] = sw[0];
            responseBuffer.get()[1] = sw[1];
            // send the response
            Serial.write(responseBuffer.get(), Le + 2);
        }
        debugMsg("[S] Response sent");
    }
    debugMsg("-------- End packet --------");
}
