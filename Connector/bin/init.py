#!python

from pqconnector.connector import connect
from pqconnector.init_device import init_device

ADMIN_PIN_SET = 0
RESET = 0

if __name__ == "__main__":
    init_device(
        connect(), admin_pin_set=bool(ADMIN_PIN_SET), reset=bool(RESET)
    )
