import serial
import serial.tools.list_ports

from . import CONFIG, CONSTANTS


def choose_serial_port():
    while True:
        try:
            ports = serial.tools.list_ports.comports()
            print("Available serial ports:")
            for i, port in enumerate(ports):
                print(f"{i}: {port.device} ({port.manufacturer})")

            port = ports[int(input("Choose port: "))]
            break
        except (ValueError, IndexError):
            print("Invalid choice!")

    return port.device


def connect() -> serial.Serial:
    return serial.Serial(
        port=choose_serial_port(),
        baudrate=CONFIG["SERIAL_BAUDRATE"],
        timeout=3000,
        write_timeout=None,
    )


DEBUG = False


def send_and_receive(
    ser: serial.Serial, command: list, throw_exception=True
) -> list:
    ser.write(bytes(command))
    if DEBUG:
        sw = [0x90, 0x00]
    else:
        sw = ser.read(2)
    if sw[0] != 0x90 or sw[1] != 0x00:
        try:
            error_msg = CONSTANTS["STATUS_WORDS"][
                int.from_bytes(sw[0:2], "big")
            ]
        except KeyError:
            error_msg = "Unknown error"

        if not throw_exception:
            print(f"[!] Device returned error code: {sw.hex()} ({error_msg})")
        else:
            raise RuntimeError(
                f"Device returned error code: {sw.hex()} ({error_msg})"
            )
    le = int.from_bytes(bytes(command[-2:]), "big")
    if le > 0:
        data = ser.read(le)
        return list(data)

    return []
