#!python

import os

from asn1crypto import keys, x509
from asn1crypto.pem import armor
from simple_term_menu import TerminalMenu

from pqconnector import CONFIG
from pqconnector import CONSTANTS as C
from pqconnector.connector import connect, send_and_receive
from pqconnector.init_device import init_device
from pqconnector.oqspython import oqspython
from pqconnector.util import (
    build_command,
    clear_screen,
    get_certificate,
    set_pin,
    verify_pin,
    get_status,
)

SERIAL = connect()
STATUS = get_status(SERIAL)


def init_menu():
    while " " in (
        nextcloud_id := input(
            (
                "Input Nextcloud user ID (default from config"
                f"file: {CONFIG['NEXTCLOUD_ID']}, q to quit): "
            )
        )
    ):
        print("User ID cannot contain space!")

    if nextcloud_id == "q":
        return

    admin_pin_set = input("Was admin PIN already set? ({0, 1}, default 0:)")

    init_device(
        SERIAL,
        nextcloud_id or CONFIG["NEXTCLOUD_ID"],
        bool(admin_pin_set or 0),
        False,
    )


def get_public_key_menu():
    while (
        choice := input(
            (
                "Input which type of public key to obtain"
                "({0 = auth, 1 = sign}, default 0, q to quit): "
            )
        )
    ) not in ["0", "1", "", "q"]:
        print("Value must be 0, 1 or empty!")

    if choice == "q":
        return

    mode = ["auth", "sign"][int(choice or "0")]

    clear_screen()
    algos = [
        (k, v)
        for (k, v) in C.items()
        if k.startswith("OQS_SIG_")
        and v in STATUS["initialized_signature_algorithms"]
    ]

    while (
        (
            choice := input(
                (
                    "Choose which initialized alg to use:\n"
                    + "\n".join(
                        f"{i :3}: {k:30} ({hex(v)})"
                        for i, (k, v) in enumerate(algos)
                    )
                    + "\nYour choice (q to quit): "
                )
            )
        )
        != "q"
        and not choice.isnumeric()
    ) or not 0 <= (int(choice) if choice != "q" else 0) < len(algos):
        clear_screen()
        print(
            "Value must be numeric and in "
            f"range [0, ..., {len(algos)-1}]!"
        )

    if choice == "q":
        return

    algo = algos[int(choice)]

    print(f"[>] Get {mode} public key")
    public_key = send_and_receive(
        SERIAL,
        build_command(
            C["INS_GET_PUBLIC_KEY"],
            C[f"MODE_{mode.upper()}"],
            algo[1],
            le=oqspython.OQS_SIGNATURE(
                algo[0]
            ).length_public_key,
        ),
        False,
    )

    public_key_info: keys.PublicKeyInfo = keys.PublicKeyInfo(
        {
            "algorithm": keys.PublicKeyAlgorithm(
                {
                    "algorithm": keys.PublicKeyAlgorithmId(
                        "1.3.6.1.4.1.2.267.7.8.7"
                    )
                }
            ),
            "public_key": keys.OctetBitString(bytes(public_key)),
        }
    )

    public_key_pem = armor("PUBLIC KEY", public_key_info.dump())
    print(public_key_pem.decode("utf-8"))


def get_certificate_menu():
    while (
        choice := input(
            (
                "Input which type of certificate to obtain"
                "({0 = auth, 1 = sign}, default 0, q to quit): "
            )
        )
    ) not in ["0", "1", "", "q"]:
        print("Value must be 0, 1 or empty!")

    if choice == "q":
        return

    mode = ["auth", "sign"][int(choice or 0)]

    clear_screen()
    algos = [
        (k, v)
        for (k, v) in C.items()
        if k.startswith("OQS_SIG_")
        and v in STATUS["initialized_signature_algorithms"]
    ]

    while (
        (
            choice := input(
                (
                    "Choose which initialized alg to use:\n"
                    + "\n".join(
                        f"{i :3}: {k:30} ({hex(v)})"
                        for i, (k, v) in enumerate(algos)
                    )
                    + "\nYour choice (q to quit): "
                )
            )
        )
        != "q"
        and not choice.isnumeric()
    ) or not 0 <= (int(choice) if choice != "q" else 0) < len(algos):
        clear_screen()
        print(
            "Value must be numeric and in "
            f"range [0, ..., {len(algos)-1}]!"
        )

    if choice == "q":
        return

    algo = algos[int(choice)]

    print(f"[>] Get {mode} certificate")
    cert_from_device = get_certificate(
        SERIAL, C[f"MODE_{mode.upper()}"], algo[1], False
    )
    cert_from_device = x509.Certificate.load(cert_from_device)
    cert_from_device_pem = armor("CERTIFICATE", cert_from_device.dump())
    print(cert_from_device_pem.decode("utf-8"))


def verify_pin_menu():
    while (
        choice := input(
            (
                "Input which type of pin to verify"
                "({0 = auth, 1 = sign, 2 = admin}, default 0, q to quit): "
            )
        )
    ) not in ["0", "1", "2", "", "q"]:
        print("Value must be 0, 1, 2 or empty!")

    if choice == "q":
        return

    mode = ["auth", "sign", "admin"][int(choice or 0)]

    while not (pin := input("Input PIN: ")).isnumeric():
        print("Value must numeric!")

    pin = [int(pin_number) for pin_number in pin]

    print(f"[>] Verifying {mode} PIN")
    verify_pin(SERIAL, pin, C[f"MODE_{mode.upper()}"], False)


def set_pin_menu():
    while (
        choice := input(
            (
                "Input which type of pin to set"
                "({0 = auth, 1 = sign, 2 = admin}, default 0, q to quit): "
            )
        )
    ) not in ["0", "1", "2", "", "q"]:
        print("Value must be 0, 1, 2 or empty!")

    if choice == "q":
        return

    mode = ["auth", "sign", "admin"][int(choice or 0)]

    while not (pin := input("Input PIN: ")).isnumeric():
        print("Value must numeric!")

    pin = [int(pin_number) for pin_number in pin]

    print(f"[>] Setting {mode} PIN")
    set_pin(SERIAL, pin, C[f"MODE_{mode.upper()}"], False)


def run_command_menu():
    ins_commands = [(k, v) for (k, v) in C.items() if k.startswith("INS_")]
    clear_screen()
    while (
        (
            choice := input(
                (
                    "Choose which instruction to run:\n"
                    + "\n".join(
                        f"{i :3}: {k:30} ({hex(v)})"
                        for i, (k, v) in enumerate(ins_commands)
                    )
                    + "\nYour choice (q to quit): "
                )
            )
        )
        != "q"
        and not choice.isnumeric()
    ) or not 0 <= (int(choice) if choice != "q" else 0) < len(ins_commands):
        clear_screen()
        print(
            "Value must be numeric and in "
            f"range [0, ..., {len(ins_commands)-1}]!"
        )

    if choice == "q":
        return

    ins = ins_commands[int(choice)]

    clear_screen()
    mode_commands = [(k, v) for (k, v) in C.items() if k.startswith("MODE_")]
    while (
        (
            choice := input(
                (
                    "Choose which mode to run:\n"
                    + "\n".join(
                        f"{i :3}: {k:30} ({hex(v)})"
                        for i, (k, v) in enumerate(mode_commands)
                    )
                    + "\nYour choice (q to quit): "
                )
            )
        )
        != "q"
        and not choice.isnumeric()
    ) or not 0 <= (int(choice) if choice != "q" else 0) < len(mode_commands):
        clear_screen()
        print(
            "Value must be numeric and in "
            f"range [0, ..., {len(mode_commands)-1}]!"
        )

    if choice == "q":
        return

    mode = mode_commands[int(choice)]

    algo_commands = [("NONE", 0)] + [
        (k, v) for (k, v) in C.items() if k.startswith("OQS_SIG_")
    ]
    clear_screen()
    while (
        (
            choice := input(
                (
                    "Choose which alg to use:\n"
                    + "\n".join(
                        f"{i :3}: {k:30} ({hex(v)})"
                        for i, (k, v) in enumerate(algo_commands)
                    )
                    + "\nYour choice (q to quit): "
                )
            )
        )
        != "q"
        and not choice.isnumeric()
    ) or not 0 <= (int(choice) if choice != "q" else 0) < len(algo_commands):
        clear_screen()
        print(
            "Value must be numeric and in "
            f"range [0, ..., {len(algo_commands)-1}]!"
        )

    if choice == "q":
        return

    algo = algo_commands[int(choice)]
    clear_screen()
    while (
        (
            data := input(
                (
                    "\nInput data in format '010203FF...' (empty for no data)"
                    + "\nYour choice (q to quit): "
                )
            )
        )
        != "q"
        and not data.isalnum()
        and data != ""
    ):
        clear_screen()
        print("Value must be alpha-numeric or empty!")

    if choice == "q":
        return

    data = list(bytes.fromhex(data)) if data != "" else None
    lc = len(data) if data else 0
    clear_screen()
    while (
        (
            le := input(
                (
                    "\nInput Le in integer number (empty for no Le)"
                    + "\nYour choice (q to quit): "
                )
            )
        )
        != "q"
        and not le.isnumeric()
        and le != ""
    ):
        clear_screen()
        print("Value must be numeric or empty!")

    if choice == "q":
        return

    le = int(le) if le != "" else 0

    print("Builded command:")
    print(f"INS: {ins[1]} ({ins[0]})")
    print(f"MODE: {mode[1]} ({mode[0]})")
    print(f"ALGO: {algo[1]} ({algo[0]})")
    print(f"LC: {lc}")

    command = build_command(
        ins[1],
        mode[1],
        algo[1],
        data,
        le,
    )

    print("[>] Running selected command")
    returned = send_and_receive(SERIAL, command, False)

    print(f"[>] Returned: {returned}")


def mainmenu():
    main_menu_title = "#" * 20 + " PQC-Connector " + "#" * 20
    main_menu_items = [
        "[i] Initialize currently connected device",
        "[p] Obtain public key from device",
        "[c] Obtain certificate from device",
        "[s] Set PIN",
        "[v] Verify PIN",
        "[r] Run specific command",
        "[q] Quit",
    ]
    main_menu_cursor = "> "
    main_menu_cursor_style = ("fg_red", "bold")
    main_menu_style = ("bg_red", "fg_yellow")
    main_menu_exit = False

    main_menu = TerminalMenu(
        menu_entries=main_menu_items,
        title=main_menu_title,
        menu_cursor=main_menu_cursor,
        menu_cursor_style=main_menu_cursor_style,
        menu_highlight_style=main_menu_style,
        cycle_cursor=True,
        clear_screen=False,
        clear_menu_on_exit=False,
        status_bar_below_preview=True,
    )

    while not main_menu_exit:
        main_selection = main_menu.show()
        clear_screen()

        if main_selection == 0:
            init_menu()
        elif main_selection == 1:
            get_public_key_menu()
        elif main_selection == 2:
            get_certificate_menu()
        elif main_selection == 3:
            set_pin_menu()
        elif main_selection == 4:
            verify_pin_menu()
        elif main_selection == 5:
            run_command_menu()
        elif main_selection == 6 or main_selection is None:
            main_menu_exit = True


if __name__ == "__main__":
    os.system("stty sane")
    clear_screen()
    mainmenu()
