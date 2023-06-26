import os
from datetime import datetime, timedelta, timezone
from hashlib import sha512

import serial
from asn1crypto import core, keys, pem, x509, algos

from . import CONFIG
from . import CONSTANTS as C
from .connector import connect, send_and_receive
from .oqspython import oqspython


def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")


def build_command(
    ins: int, mode: int, algo: int, data: list | None = None, le: int = 0
):
    # prepare header
    command = [ins, mode, algo]

    # if data is present, append its length before data
    # else append zero Length Contained
    if data is not None:
        command = command + list(len(data).to_bytes(2, "big")) + data
    else:
        command = command + [0x00, 0x00]

    # append Length Expected
    command = command + list(le.to_bytes(2, "big"))

    return command


def read_data_length_from_asn1(
    ser: serial.Serial, mode: int, algo: int, throw_exception=True
):
    command = build_command(C["INS_GET_CERTIFICATE"], mode, algo, le=4)

    result = send_and_receive(ser, command, throw_exception)

    assert result[0] == 0x30
    assert result[1] == 0x82
    return (result[2] << 8) + result[3] + 4


def get_certificate(
    ser: serial.Serial, mode: int, algo: int, throw_exception=True
):
    length = read_data_length_from_asn1(ser, mode, algo, throw_exception)

    return bytes(
        send_and_receive(
            ser,
            build_command(C["INS_GET_CERTIFICATE"], mode, algo, le=length),
            throw_exception,
        )
    )


def create_cert(
    nextcloud_id: str,
    public_key_to_sign: bytes,
    root_certificate: bytes,
    root_private_key: bytes,
) -> bytes:
    # Prepare PQC module
    sig = oqspython.OQS_SIGNATURE(oqspython.OQS_SIG_alg_dilithium_5)

    # Load public key into SubjectPublicKeyInfo
    # (so ASN1 structre of x509 holds)
    public_key: keys.PublicKeyInfo = keys.PublicKeyInfo(
        {
            "algorithm": keys.PublicKeyAlgorithm(
                {
                    "algorithm": keys.PublicKeyAlgorithmId(
                        "1.3.6.1.4.1.2.267.7.8.7"
                    )
                }
            ),
            "public_key": keys.OctetBitString(public_key_to_sign),
        }
    )

    # Set cert validity
    validity = timedelta(CONFIG["CARD_CERT_VALIDITY_DAYS"], 0, 0)

    # Obtain root certificate subject
    _, _, root_certificate_der = pem.unarmor(root_certificate)
    root_certificate_subject = x509.Name.build(
        x509.Certificate.load(root_certificate_der).native["tbs_certificate"][
            "subject"
        ]
    )

    # Prepare x509 asn1 structure
    tbs_cert = x509.TbsCertificate(
        {
            "version": "v3",
            "serial_number": int.from_bytes(os.urandom(20), "big") >> 1,
            "signature": {
                "algorithm": "1.3.6.1.4.1.2.267.7.8.7"  # Dilithium 5
            },
            "issuer": root_certificate_subject,
            "validity": {
                "not_before": x509.Time(
                    name="utc_time", value=datetime.now(timezone(timedelta(0)))
                ),
                "not_after": x509.Time(
                    name="utc_time",
                    value=datetime.now(timezone(timedelta(0))) + validity,
                ),
            },
            "subject": x509.Name.build(
                {
                    "country_name": "CZ",
                    "state_or_province_name": "Czechia",
                    "locality_name": "Brno",
                    "organization_name": "Cybernetica AS",
                    "common_name": nextcloud_id,
                }
            ),
            "subject_public_key_info": public_key,
            "extensions": [
                {
                    "extn_id": "extended_key_usage",
                    "critical": True,
                    "extn_value": ["client_auth"],
                }
            ],
        }
    )

    # Prepare the private key
    # PQC-OpenSSL encodes privates keys as
    # 0x04 or 0x03 || length || private_key || public_key
    # We need to extract private_key only
    _, _, private_key = pem.unarmor(root_private_key)
    private_key = keys.PrivateKeyInfo.load(private_key)
    private_key_raw = private_key.native["private_key"]
    if len(private_key_raw) > sig.length_private_key:
        # if it still has ASN1 type and length
        offset = 0
        if private_key_raw[0] == 0x04 or private_key_raw[0] == 0x03:
            # 0x80 indicates that second byte encodes
            # number of bytes containing length
            len_bytes = (
                1
                if (private_key_raw[1] & 0x80) != 0x80
                else 1 + (private_key_raw[1] & 0x7F)
            )
            # 1 is for type 0x04 or 0x03, rest is length_bytes
            offset = 1 + len_bytes
        private_key_raw = private_key_raw[
            offset : offset + sig.length_private_key  # noqa: E203
        ]
    assert len(private_key_raw) == sig.length_private_key

    # Prepare message hash and signature bytes object
    tbs_cert_bytes_hash = sha512(tbs_cert.dump()).digest()
    signature = bytes(sig.length_signature)
    signature_len = oqspython.size_t_p()

    # Perform signature of tbs_cert part
    result = sig.sign(
        signature,
        signature_len,
        tbs_cert_bytes_hash,
        len(tbs_cert_bytes_hash),
        private_key_raw,
    )
    assert result == oqspython.OQS_SUCCESS
    assert len(signature) == sig.length_signature

    # Verify the signature
    result = sig.verify(
        tbs_cert_bytes_hash,
        len(tbs_cert_bytes_hash),
        signature,
        signature_len.value(),
        x509.Certificate.load(root_certificate_der).native["tbs_certificate"][
            "subject_public_key_info"
        ]["public_key"],
    )
    assert result == oqspython.OQS_SUCCESS

    cert = x509.Certificate(
        {
            "tbs_certificate": tbs_cert,
            "signature_algorithm": {
                "algorithm": "1.3.6.1.4.1.2.267.7.8.7"  # Dilithium 5
            },
            "signature_value": core.OctetBitString(signature),
        }
    )

    return cert.dump()


def set_pins(ser, admin_pin_set=False):
    if not admin_pin_set:
        set_pin(ser, CONFIG["ADMIN_PIN"], C["MODE_ADMIN"])
    verify_pin(ser, CONFIG["ADMIN_PIN"], C["MODE_ADMIN"])

    set_pin(ser, CONFIG["USER_AUTH_PIN"], C["MODE_AUTH"])
    verify_pin(ser, CONFIG["USER_AUTH_PIN"], C["MODE_AUTH"])

    verify_pin(ser, CONFIG["ADMIN_PIN"], C["MODE_ADMIN"])

    set_pin(ser, CONFIG["USER_SIGN_PIN"], C["MODE_SIGN"])
    verify_pin(ser, CONFIG["USER_SIGN_PIN"], C["MODE_SIGN"])


def set_pin(
    ser: serial.Serial,
    pin: list,
    mode: int,
    throw_exception=True,
):
    mode_str = {
        0: "ADMIN",
        1: "AUTH",
        2: "SIGN",
    }[mode]

    print(f"[>] Set {mode_str} pin")

    send_and_receive(
        ser,
        build_command(
            C["INS_SET_PIN"],
            mode,
            0x00,
            encode_pin(pin),
            0x00,
        ),
        throw_exception,
    )


def verify_pin(
    ser: serial.Serial,
    pin: list,
    mode: int,
    throw_exception=True,
):
    mode_str = {
        0: "ADMIN",
        1: "AUTH",
        2: "SIGN",
    }[mode]

    print(f"[>] Verify {mode_str} pin")

    send_and_receive(
        ser,
        build_command(
            C["INS_VERIFY_PIN"],
            mode,
            0x00,
            encode_pin(pin),
            0x00,
        ),
        throw_exception,
    )


def change_pin(
    ser: serial.Serial,
    pin: list,
    mode: int,
    throw_exception=True,
):
    mode_str = {
        0: "ADMIN",
        1: "AUTH",
        2: "SIGN",
    }[mode]
    print(f"[>] Change {mode_str} pin")

    send_and_receive(
        ser,
        build_command(
            C["INS_CHANGE_PIN"],
            mode,
            0x00,
            encode_pin(pin),
            0x00,
        ),
        throw_exception,
    )


def encode_pin(pin):
    return [ord(str(num)) for num in pin]


def handle_pk_and_cert_init(
    ser: serial.Serial,
    nextcloud_id: str,
    mode: int,
    algo: int,
    algo_name: str,
    throw_exception=True,
):
    # generate keypairs
    mode_str = "AUTH" if mode == 1 else "SIGN"

    verify_pin(ser, CONFIG["ADMIN_PIN"], C["MODE_ADMIN"])
    verify_pin(ser, CONFIG[f"USER_{mode_str}_PIN"], C[f"MODE_{mode_str}"])

    print(f"[>] Generate {mode_str} keypair")
    send_and_receive(
        ser,
        build_command(C["INS_GENERATE_KEYPAIR"], mode, algo),
        throw_exception,
    )

    # obtain public key from device so we can create certificate of it
    # TODO: handle different algorithms
    sig = oqspython.OQS_SIGNATURE(getattr(oqspython, algo_name))
    print(f"[>] Get {mode_str} public key")
    public_key: bytes = bytes(
        send_and_receive(
            ser,
            build_command(
                C["INS_GET_PUBLIC_KEY"], mode, algo, le=sig.length_public_key
            ),
            throw_exception,
        )
    )

    # load root CA and root private key
    print("[.] Loading root certificate and root private key")
    # cert_directory = Path(CONFIG["ROOT_CA_DIRECTORY_FULL_PATH"])
    with (
        open("data/rootcertificate.crt", "rb") as f1,
        open("data/rootkey.key", "rb") as f2,
    ):
        root_certificate = f1.read()
        root_key = f2.read()

    # create new certificate and store it on device
    print("[.] Creating user certificate")
    created_cert_der = create_cert(
        nextcloud_id,
        public_key,  # type: ignore
        root_certificate,
        root_key,
    )

    verify_pin(ser, CONFIG["ADMIN_PIN"], C["MODE_ADMIN"])
    verify_pin(ser, CONFIG[f"USER_{mode_str}_PIN"], C[f"MODE_{mode_str}"])
    print(f"[>] Store {mode_str} user certificate")
    send_and_receive(
        ser,
        build_command(
            C["INS_SET_CERTIFICATE"], mode, algo, list(created_cert_der)
        ),
        throw_exception,
    )

    # load certificate from device with get_certificate command and
    # check if it is the same as created certificate
    cert_from_device = get_certificate(ser, mode, algo, throw_exception)
    length = (cert_from_device[2] << 8) + cert_from_device[3] + 4
    cert_from_device = cert_from_device[:length]
    assert created_cert_der == bytes(cert_from_device), (
        "Something went wrong with storing certificate on device"
        "Please store it manually or reload whole applet and"
        "run initialization again."
    )


def get_status(ser: serial.Serial) -> dict:
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
    supported_signature_algorithms = result[17 : 17 + ssa_size]  # noqa: E203

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

    return {
        "serialID": serialID,
        "hasPinPad": hasPinPad,
        "firmwareVersion": firmwareVersion,
        "supported_signature_algorithms": supported_signature_algorithms,
        "initialized_signature_algorithms": initialized_signature_algorithms,
    }


def get_alg_lengths():
    for alg in [C["ALG_DILITHIUM5"]]:
        sig = oqspython.OQS_SIGNATURE(alg)
        print(
            f"Alg {alg}: {sig.length_public_key} {sig.length_private_key} {sig.length_signature}"
        )


if __name__ == "__main__":
    ser = connect()
    handle_pk_and_cert_init(
        ser,
        "ncadmin",
        C["MODE_AUTH"],
        C["ALG_DILITHIUM5"],
        oqspython.OQS_SIG_alg_dilithium_5,
        True,
    )
