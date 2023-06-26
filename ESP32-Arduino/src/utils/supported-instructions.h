#ifndef SUPPORTED_INSTRUCTIONS_H
#define SUPPORTED_INSTRUCTIONS_H

// Command structure:
// > INS : MODE : ALGO : LC1 : LC2 : [DATA]* : LE1 : LE2
// < SW1 : SW2 : [DATA]*

// MODE
const uint8_t MODE_ADMIN = 0x00;
const uint8_t MODE_AUTH = 0x01;
const uint8_t MODE_SIGN = 0x02;

// Instructions
const uint8_t INS_GET_STATUS = 0xA0;
const uint8_t INS_GENERATE_KEYPAIR = 0xA1;
const uint8_t INS_GET_PUBLIC_KEY = 0xA2;
const uint8_t INS_GET_PRIVATE_KEY = 0xA3;
const uint8_t INS_GET_CERTIFICATE = 0xA4;
const uint8_t INS_SET_CERTIFICATE = 0xA5;
const uint8_t INS_CREATE_SIGNATURE = 0xA6;
const uint8_t INS_VERIFY_PIN = 0xB1;
const uint8_t INS_PIN_RETRIES_LEFT = 0xB2;
const uint8_t INS_CHANGE_PIN = 0xB3;
const uint8_t INS_SET_PIN = 0xB4;

#endif