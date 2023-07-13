import serial
import time, os
from infiniteidpq_device_manager.connector import connect, send_and_receive, choose_serial_port
from infiniteidpq_device_manager import CONFIG, CONSTANTS as C
from infiniteidpq_device_manager.util import build_command, get_status

ser = serial.Serial(
    port=None,
    baudrate=CONFIG["SERIAL_BAUDRATE"],
    timeout=2,
    write_timeout=None,
    xonxoff=False,
    rtscts=False,
)

ser.port = choose_serial_port()
command = build_command(
    C["INS_GET_STATUS"],
    C["MODE_ADMIN"],
    0x00,
    le=0xFF,
)

ser.open() 
status = get_status(ser)
ser.close()

while True:
    print("----------------------")
    try:
        # ser.dsrdtr = False
        # ser.setDTR(False)

        # modification_time = os.stat(CONFIG["SERIAL_PORT"]).st_ctime
        # if time.time() - modification_time <= 2.5:
        #     print("Serial port not ready")
        #     time.sleep(1)
        #     continue
        ser.open()

        # ser.send_break(0.25)
        # ser.reset_input_buffer()
        # ser.reset_output_buffer()
        # time.sleep(2)

        print("Opened serial port")
        bw = ser.write(bytes(command))
        print("Wrote command " + str(bw))

        br = ser.read(256)
        print("Read response " + str(len(br)) + " bytes: " + str(br))
        if len(br) != 256:
            print("Response too short " + str(len(br)) + " bytes: " + str(br))
    except (serial.SerialException, FileNotFoundError) as ex:
        print("Ex: " + str(ex))
    finally:
        ser.close()
        time.sleep(1)
