#ifndef INFINITEIDPQ_H
#define INFINITEIDPQ_H

#include <stdio.h>
#include <string.h>

/*
 *  Copyright 2015-2017 The Pkcs11Interop Project
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

/*
 *  Written for the Pkcs11Interop project by:
 *  Jaroslav IMRICH <jimrich@jimrich.sk>
 */
#ifdef _WIN32
// PKCS#11 related stuff
#pragma pack(push, cryptoki, 1)

#define CK_IMPORT_SPEC __declspec(dllimport) 
#ifdef CRYPTOKI_EXPORTS 
#define CK_EXPORT_SPEC __declspec(dllexport) 
#else 
#define CK_EXPORT_SPEC CK_IMPORT_SPEC 
#endif 
#define CK_CALL_SPEC __cdecl 

#define CK_PTR *
#define CK_DEFINE_FUNCTION(returnType, name) returnType CK_EXPORT_SPEC CK_CALL_SPEC name
#define CK_DECLARE_FUNCTION(returnType, name) returnType CK_EXPORT_SPEC CK_CALL_SPEC name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType CK_IMPORT_SPEC (CK_CALL_SPEC CK_PTR name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType (CK_CALL_SPEC CK_PTR name)

#ifndef NULL_PTR
#define NULL_PTR 0
#endif

#include <cryptoki\pkcs11.h>

#pragma pack(pop, cryptoki)

#else // #ifdef _WIN32

// PKCS#11 related stuff
#define CK_PTR *
#define CK_DEFINE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType (* name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType (* name)

#ifndef NULL_PTR
#define NULL_PTR 0
#endif

#include <cryptoki/pkcs11.h>
#endif // #ifdef _WIN32

#define IGNORE(P) (void)(P)




#define INFINITEIDPQ_PKCS11_CK_INFO_MANUFACTURER_ID "INFINITEIDPQ Project"
#define INFINITEIDPQ_PKCS11_CK_INFO_LIBRARY_DESCRIPTION "This library implements PKCS11 interface for InfinitEIDPQ"
#define INFINITEIDPQ_PKCS11_CK_INFO_LIBRARY_VERSION_MAJOR 0x01
#define INFINITEIDPQ_PKCS11_CK_INFO_LIBRARY_VERSION_MINOR 0x00

#define INFINITEIDPQ_PKCS11_CK_SLOT_ID 1
#define INFINITEIDPQ_PKCS11_CK_SLOT_INFO_SLOT_DESCRIPTION "USB Serial Slot"
#define INFINITEIDPQ_PKCS11_CK_SLOT_INFO_MANUFACTURER_ID "INFINITEIDPQ Project"

#define INFINITEIDPQ_PKCS11_CK_TOKEN_INFO_LABEL "INFINITEIDPQ"
#define INFINITEIDPQ_PKCS11_CK_TOKEN_INFO_MANUFACTURER_ID "INFINITEIDPQ Project"
#define INFINITEIDPQ_PKCS11_CK_TOKEN_INFO_MODEL "InfinitEIDPQ Token"
#define INFINITEIDPQ_PKCS11_CK_TOKEN_INFO_SERIAL_NUMBER "0123456789A"
#define INFINITEIDPQ_PKCS11_CK_TOKEN_INFO_MAX_PIN_LEN 256
#define INFINITEIDPQ_PKCS11_CK_TOKEN_INFO_MIN_PIN_LEN 6

#define INFINITEIDPQ_PKCS11_CK_SESSION_ID 1

#define INFINITEIDPQ_PKCS11_CK_OBJECT_CKA_LABEL "INFINITEIDPQ"
#define INFINITEIDPQ_PKCS11_CK_OBJECT_CKA_VALUE "Hello world!"
#define INFINITEIDPQ_PKCS11_CK_OBJECT_SIZE 256
#define INFINITEIDPQ_PKCS11_CK_OBJECT_HANDLE_DATA 1
#define INFINITEIDPQ_PKCS11_CK_OBJECT_HANDLE_SECRET_KEY 2
#define INFINITEIDPQ_PKCS11_CK_OBJECT_HANDLE_PUBLIC_KEY 3
#define INFINITEIDPQ_PKCS11_CK_OBJECT_HANDLE_PRIVATE_KEY 4

typedef enum
{
	INFINITEIDPQ_PKCS11_CK_OPERATION_NONE,
	INFINITEIDPQ_PKCS11_CK_OPERATION_FIND,
	INFINITEIDPQ_PKCS11_CK_OPERATION_ENCRYPT,
	INFINITEIDPQ_PKCS11_CK_OPERATION_DECRYPT,
	INFINITEIDPQ_PKCS11_CK_OPERATION_DIGEST,
	INFINITEIDPQ_PKCS11_CK_OPERATION_SIGN,
	INFINITEIDPQ_PKCS11_CK_OPERATION_SIGN_RECOVER,
	INFINITEIDPQ_PKCS11_CK_OPERATION_VERIFY,
	INFINITEIDPQ_PKCS11_CK_OPERATION_VERIFY_RECOVER,
	INFINITEIDPQ_PKCS11_CK_OPERATION_DIGEST_ENCRYPT,
	INFINITEIDPQ_PKCS11_CK_OPERATION_DECRYPT_DIGEST,
	INFINITEIDPQ_PKCS11_CK_OPERATION_SIGN_ENCRYPT,
	INFINITEIDPQ_PKCS11_CK_OPERATION_DECRYPT_VERIFY
}
INFINITEIDPQ_PKCS11_CK_OPERATION;

#endif // INFINITEIDPQ_H