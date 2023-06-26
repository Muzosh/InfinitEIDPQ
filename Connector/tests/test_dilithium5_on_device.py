# from pqc_connector.oqspython import oqspython
from pqconnector.oqspython import oqspython
from pqconnector.connector import connect
from pqconnector.util import send_and_receive, verify_pin

# Set the serial port name and baud rate
ser = connect()
oqs = oqspython.OQS_SIGNATURE(oqspython.OQS_SIG_alg_dilithium_5)

# Get public key
public_key = send_and_receive(
    ser,
    [0xA2, 0x01, 0xD5, 0x00, 0x00]
    + list(oqs.length_public_key.to_bytes(2, "big")),
)

# Create on device signature and verify it
message = "This is the message to sign"

verify_pin(ser, [1, 2, 3, 4, 5, 6], 0x01)

signature = send_and_receive(
    ser,
    [0xA6, 0x01, 0xD5]
    + list(len(message).to_bytes(2, "big"))
    + list(message.encode())
    + list(oqs.length_signature.to_bytes(2, "big")),
)

result = oqs.verify(
    message.encode(), len(message), bytes(signature), oqs.length_signature, bytes(public_key)
)
if result != oqspython.OQS_SUCCESS:
    print("Error verifying signature")
else:
    print("Finished successfully")
ser.close()
