# from infiniteidpq_device_manager.oqspython import oqspython
from infiniteidpq_device_manager.oqspython import oqspython
from infiniteidpq_device_manager.connector import connect
from infiniteidpq_device_manager.util import send_and_receive, verify_pin


# Set the serial port name and baud rate
ser = connect()
oqs = oqspython.OQS_SIGNATURE(oqspython.OQS_SIG_alg_falcon_1024)

# Get public key
public_key = send_and_receive(
    ser,
    [0xA2, 0x01, 0xF1, 0x00, 0x00]
    + list(oqs.length_public_key.to_bytes(2, "big")),
)


verify_pin(ser, [9, 8, 7, 6, 5, 4], 0x00)
verify_pin(ser, [1, 2, 3, 4, 5, 6], 0x01)
# Get private key
private_key = send_and_receive(
    ser,
    [0xA3, 0x01, 0xF1, 0x00, 0x00]
    + list(oqs.length_private_key.to_bytes(2, "big")),
)

# Create on device signature and verify it
message = "This is the message to sign"

verify_pin(ser, [1, 2, 3, 4, 5, 6], 0x01)

signature = send_and_receive(
    ser,
    [0xA6, 0x01, 0xF1]
    + list(len(message).to_bytes(2, "big"))
    + list(message.encode())
    + list(oqs.length_signature.to_bytes(2, "big")),
)

# signature_pc = bytes(oqs.length_signature)
# signature_pc_len = oqspython.size_t_p()

# result_pc = oqs.sign(
#     signature_pc,
#     signature_pc_len,
#     message.encode(),
#     len(message),
#     bytes(private_key),
# )
# result_pc = oqs.verify(
#     message.encode(),
#     len(message),
#     bytes(signature_pc),
#     signature_pc_len.value(),
#     bytes(public_key),
# )

# remove traling zeroes from signature
while signature[-1] == 0:
    signature = signature[:-1]

result = oqs.verify(
    message.encode(),
    len(message),
    bytes(signature),
    len(signature),
    bytes(public_key),
)

if result != oqspython.OQS_SUCCESS:
    print("Error verifying signature")
else:
    print("Finished successfully")
ser.close()
