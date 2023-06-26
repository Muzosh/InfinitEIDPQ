#!python

import os
import pathlib
import time
from hashlib import sha512

from pqconnector import CONFIG, CONSTANTS as C
from pqconnector.connector import connect, send_and_receive
from pqconnector.oqspython.oqspython import (
    OQS_SIGNATURE,
    OQS_SIG_alg_dilithium_5,
)
from pqconnector.util import build_command, verify_pin

ITERATIONS = 100
SERIAL = connect()
ORIGIN = "https://example.com"
MODE_AUTH = C["MODE_AUTH"]
ALG_DILITHIUM5 = C["OQS_SIG_alg_dilithium_5"]
SIGNATURE_LENGTH = OQS_SIGNATURE(OQS_SIG_alg_dilithium_5).length_signature

measurement_directory = (
    pathlib.Path(__file__).parent.absolute() / "measurements"
)
measurement_directory.mkdir(exist_ok=True)

final_string = ""
duration_sum = 0

print("[>] Measurement of digital signature started:")
for i in range(ITERATIONS):
    print("[>] Iteration:", i + 1)
    challenge_nonce = os.urandom(32)
    origin_hash = sha512(ORIGIN.encode("utf-8")).digest()
    nonce_hash = sha512(challenge_nonce).digest()

    hash_to_be_signed = sha512(origin_hash + nonce_hash).digest()

    verify_pin(SERIAL, CONFIG["USER_AUTH_PIN"], C["MODE_AUTH"])

    # measure digital signature generation
    start_time = time.time()
    signature = send_and_receive(
        SERIAL,
        build_command(
            C["INS_CREATE_SIGNATURE"],
            MODE_AUTH,
            ALG_DILITHIUM5,
            data=list(hash_to_be_signed),
            le=SIGNATURE_LENGTH,
        ),
    )
    end_time = time.time()
    duration = end_time - start_time

    final_string += f"{duration}\n"
    duration_sum += duration

final_string = f"Average: {duration_sum / ITERATIONS}\n" + final_string
final_string = final_string.replace(".", ",")

measurement_file = (
    measurement_directory / f"TDisplay_dil5_{ITERATIONS}_{int(time.time())}.txt"
)
measurement_file.write_text(final_string)
print(f"[>] Measurement file saved to: {measurement_file}")
