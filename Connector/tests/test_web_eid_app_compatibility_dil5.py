"""
MIT License

Copyright (c) 2022 Petr Muzikant

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""
from hashlib import sha512

import pytest
import serial
from asn1crypto import pem, x509
from pqconnector.oqspython import oqspython

from pqconnector import CONFIG
from pqconnector import CONSTANTS as C
from pqconnector.connector import connect, send_and_receive
from pqconnector.util import (
    build_command,
    change_pin,
    get_certificate,
    set_pin,
    verify_pin,
)


@pytest.fixture
def ser():
    return connect()


@pytest.fixture
def sig():
    return oqspython.OQS_SIGNATURE(oqspython.OQS_SIG_alg_dilithium_5)


class TestWebEidAppCompatibility:
    def test_status(self, ser: serial.Serial):
        # GET STATUS
        result: list = send_and_receive(
            ser,
            build_command(
                C["INS_GET_STATUS"],
                C["MODE_ADMIN"],
                0x00,
                le=0xFF,
            ),
        )

        # FORMAT:
        #      SERIALID[10]
        #      HAS_PINPAD{0x00 or 0x01}
        #      VERSION[3]
        #      SEPARATOR{0xFF, 0x01}
        #      SSA_SIZE{SIZE}
        #      SUPPORTED_SIGNATURE_ALGORITHMS[SSA_SIZE]
        #      SEPARATOR{0xFF, 0x02}
        #      ISA_SIZE{SIZE}
        #      {INITIALIZED_SIGNATURE_ALGORITHM, MODE(AUTH | SIGN)}[ISA_SIZE]

        # SERIALID[10]
        serialID = result[0:10]

        # HAS_PINPAD{0x00 or 0x01}
        hasPinPad = result[10] == 0x01

        # VERSION[3]
        firmwareVersion = result[11:14]

        # SEPARATOR{0xFF, 0x01}
        assert (
            result[14] == 0xFF and result[15] == 0x01
        ), "Wrong format in response to GET STATUS command"

        # SIZE{SIZE}
        ssa_size = result[16]

        # SUPPORTED_SIGNATURE_ALGORITHMS[SSA_SIZE]
        supported_signature_algorithms = result[
            17 : 17 + ssa_size  # noqa: E203
        ]

        # SEPARATOR{0xFF, 0x02}
        assert (
            result[17 + ssa_size] == 0xFF and result[18 + ssa_size] == 0x02
        ), "Wrong format in response to GET STATUS command"

        # ISA_SIZE{SIZE}
        isa_size = result[19 + ssa_size]

        # {INITIALIZED_SIGNATURE_ALGORITHM, MODE(AUTH | SIGN)}[ISA_SIZE]
        initialized_signature_algorithms = result[
            20 + ssa_size : 20 + ssa_size + isa_size  # noqa: E203
        ]

        # Check if the rest is 0xFF
        rest = result[20 + ssa_size + isa_size :]  # noqa: E203
        assert all(
            [x == 0xFF for x in rest]
        ), "Wrong format in response to GET STATUS command"

        print(f"{serialID = }")
        print(f"{hasPinPad = }")
        print(f"{firmwareVersion = }")
        print(f"{supported_signature_algorithms = }")
        print(f"{initialized_signature_algorithms = }")
        print("[>] Status OK")

    def test_certificates(
        self, ser: serial.Serial, sig: oqspython.OQS_SIGNATURE
    ):
        for mode in [C["MODE_AUTH"], C["MODE_SIGN"]]:
            mode_str = "auth" if mode == C["MODE_AUTH"] else "sign"
            print(f"[>] Get {mode_str} public key")
            public_key: bytes = bytes(
                send_and_receive(
                    ser,
                    build_command(
                        C["INS_GET_PUBLIC_KEY"],
                        mode,
                        C["OQS_SIG_alg_dilithium_5"],
                        le=sig.length_public_key,
                    ),
                )
            )

            cert_from_device = get_certificate(
                ser, mode, C["OQS_SIG_alg_dilithium_5"]
            )

            x509_cert = x509.Certificate.load(bytes(cert_from_device))

            assert (
                public_key
                == x509_cert.native["tbs_certificate"][
                    "subject_public_key_info"
                ]["public_key"]
            )

            # cert_directory = Path(CONFIG["ROOT_CA_DIRECTORY_FULL_PATH"])
            with open("data/rootcertificate.crt", "rb") as f1:
                root_certificate = f1.read()

            _, _, root_certificate_der = pem.unarmor(root_certificate)
            root_certificate_public_key = x509.Certificate.load(
                root_certificate_der
            ).native["tbs_certificate"]["subject_public_key_info"][
                "public_key"
            ]

            tbs_cert_bytes_hash = sha512(x509_cert.children[0].dump()).digest()

            result = sig.verify(
                tbs_cert_bytes_hash,
                len(tbs_cert_bytes_hash),
                x509_cert.children[2].native,
                sig.length_signature,
                root_certificate_public_key,
            )
            assert result == oqspython.OQS_SUCCESS
        print("[>] Certificates OK")

    def test_internal_authenticate(
        self, ser: serial.Serial, sig: oqspython.OQS_SIGNATURE
    ):
        origin_hash = sha512(b"https://ria.ee").digest()
        nonce_hash = sha512(
            b"12345678901234567890123456789012345678901234"
        ).digest()
        hash_to_be_signed = sha512(origin_hash + nonce_hash).digest()
        mode = C["MODE_AUTH"]

        # verify_pin(ser, CONFIG["USER_AUTH_PIN"], "auth")

        cert_from_device = get_certificate(
            ser, mode, C["OQS_SIG_alg_dilithium_5"]
        )

        x509_cert = x509.Certificate.load(bytes(cert_from_device))

        verify_pin(ser, CONFIG["USER_AUTH_PIN"], C["MODE_AUTH"])

        signature = send_and_receive(
            ser,
            build_command(
                C["INS_CREATE_SIGNATURE"],
                mode,
                C["OQS_SIG_alg_dilithium_5"],
                list(hash_to_be_signed),
                sig.length_signature,
            ),
        )

        result = sig.verify(
            hash_to_be_signed,
            len(hash_to_be_signed),
            bytes(signature),
            sig.length_signature,
            x509_cert.native["tbs_certificate"]["subject_public_key_info"][
                "public_key"
            ],
        )
        assert result == oqspython.OQS_SUCCESS
        print("[>] Internal authenticate OK")

    def test_create_signature(
        self, ser: serial.Serial, sig: oqspython.OQS_SIGNATURE
    ):
        preomputed_hash = sha512(b"fake document").digest()
        mode = C["MODE_SIGN"]

        # verify_pin(ser, CONFIG["USER_SIGN_PIN"], "sign")

        cert_from_device = get_certificate(
            ser, mode, C["OQS_SIG_alg_dilithium_5"]
        )

        x509_cert = x509.Certificate.load(bytes(cert_from_device))

        verify_pin(ser, CONFIG["USER_SIGN_PIN"], C["MODE_SIGN"])

        signature = send_and_receive(
            ser,
            build_command(
                C["INS_CREATE_SIGNATURE"],
                mode,
                C["OQS_SIG_alg_dilithium_5"],
                list(preomputed_hash),
                sig.length_signature,
            ),
        )

        result = sig.verify(
            preomputed_hash,
            len(preomputed_hash),
            bytes(signature),
            sig.length_signature,
            x509_cert.native["tbs_certificate"]["subject_public_key_info"][
                "public_key"
            ],
        )
        assert result == oqspython.OQS_SUCCESS
        print("[>] Create signature OK")

    def test_user_pin_manipulation(self, ser: serial.Serial):
        for operation in ["AUTH", "SIGN"]:
            # Set PIN to default value and verify it
            verify_pin(ser, CONFIG["ADMIN_PIN"], C["MODE_ADMIN"])
            set_pin(
                ser, CONFIG[f"USER_{operation}_PIN"], C[f"MODE_{operation}"]
            )
            verify_pin(
                ser, CONFIG[f"USER_{operation}_PIN"], C[f"MODE_{operation}"]
            )

            # Get remaining tries before, input invalid PIN and
            # check if tries decreased
            tries_max_before = send_and_receive(
                ser,
                build_command(
                    C["INS_PIN_RETRIES_LEFT"],
                    C[f"MODE_{operation}"],
                    0x00,
                    [],
                    0x02,
                ),
            )
            verify_pin(
                ser,
                [0, 0, 0, 0],
                C[f"MODE_{operation}"],
                False,
            )
            tries_max_after = send_and_receive(
                ser,
                build_command(
                    C["INS_PIN_RETRIES_LEFT"],
                    C[f"MODE_{operation}"],
                    0x00,
                    [],
                    0x02,
                ),
            )
            assert (
                tries_max_before[0] == tries_max_after[0] + 1
                and tries_max_before[1] == tries_max_after[1]
            )

            # Input invalid PIN multiple times to block the device
            for _ in range(tries_max_after[0]):
                verify_pin(
                    ser,
                    [0, 0, 0, 0],
                    C[f"MODE_{operation}"],
                    False,
                )

            # Next correct PIN should not work since device is blocked
            with pytest.raises(RuntimeError):
                verify_pin(
                    ser,
                    CONFIG[f"USER_{operation}_PIN"],
                    C[f"MODE_{operation}"],
                    True,
                )

            # See that device is indeed blocked by remaining tries set to 0
            tries_max_after = send_and_receive(
                ser,
                build_command(
                    C["INS_PIN_RETRIES_LEFT"],
                    C[f"MODE_{operation}"],
                    0x00,
                    [],
                    0x02,
                ),
            )
            assert tries_max_after[0] == 0

            # Unblock PIN by setting it to default value by admin
            verify_pin(ser, CONFIG["ADMIN_PIN"], C["MODE_ADMIN"])
            set_pin(
                ser, CONFIG[f"USER_{operation}_PIN"], C[f"MODE_{operation}"]
            )
            verify_pin(
                ser, CONFIG[f"USER_{operation}_PIN"], C[f"MODE_{operation}"]
            )

            # Change PIN
            change_pin(ser, [9, 8, 7, 6, 5, 4], C[f"MODE_{operation}"])

            # Previous PIN should not work since it was changed
            with pytest.raises(RuntimeError):
                verify_pin(
                    ser,
                    CONFIG[f"USER_{operation}_PIN"],
                    C[f"MODE_{operation}"],
                )

            # Verify changed PIN
            verify_pin(ser, [9, 8, 7, 6, 5, 4], C[f"MODE_{operation}"])

            # Set PIN back to default
            verify_pin(ser, CONFIG["ADMIN_PIN"], C["MODE_ADMIN"])
            set_pin(
                ser,
                CONFIG[f"USER_{operation}_PIN"],
                C[f"MODE_{operation}"],
            )


if __name__ == "__main__":
    test_ser = connect()
    test_sig = oqspython.OQS_SIGNATURE(oqspython.OQS_SIG_alg_dilithium_5)
    test = TestWebEidAppCompatibility()
    test.test_status(test_ser)
    test.test_certificates(test_ser, test_sig)
    test.test_internal_authenticate(test_ser, test_sig)
    test.test_create_signature(test_ser, test_sig)
    test.test_user_pin_manipulation(test_ser)
    print("[>] All tests passed")
