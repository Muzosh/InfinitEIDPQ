import serial

from . import CONFIG
from . import CONSTANTS as C
from .util import handle_pk_and_cert_init, set_pins, get_status
from .connector import connect


def init_device(
    ser: serial.Serial,
    nextcloud_id: str | None = None,
    admin_pin_set=False,
    reset=False,
    throw_exception=True,
):
    print("[+] Device initialization started")
    print("[+] Setting up PIN codes")
    set_pins(ser, admin_pin_set)

    status = get_status(ser)
    for algo_id in sorted(
        [
            algo
            for algo in status["supported_signature_algorithms"]
            if reset or algo not in status["initialized_signature_algorithms"]
        ],
        reverse=False,
    ):
        algo_name = next(
            key
            for key, value in C.items()
            if key.startswith("OQS_SIG_") and value == algo_id
        )
        print(
            f"[+] Creating AUTH-{algo_name} keypair, obtaining",
            "public key and storing certificate",
        )
        handle_pk_and_cert_init(
            ser,
            nextcloud_id or CONFIG["NEXTCLOUD_ID"],
            C["MODE_AUTH"],
            algo_id,
            algo_name,
            throw_exception,
        )
        print(
            f"[+] Creating SIGN-{algo_name} keypair, obtaining",
            "public key and storing certificate",
        )
        handle_pk_and_cert_init(
            ser,
            nextcloud_id or CONFIG["NEXTCLOUD_ID"],
            C["MODE_SIGN"],
            algo_id,
            algo_name,
            throw_exception,
        )

    print("[+] Successfully finished!")


if __name__ == "__main__":
    init_device(connect(), admin_pin_set=True)
