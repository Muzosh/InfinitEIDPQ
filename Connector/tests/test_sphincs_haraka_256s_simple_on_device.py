# from pqc_connector.oqspython import oqspython
from pqconnector.oqspython import oqspython
from pqconnector.connector import connect
from pqconnector.util import send_and_receive, verify_pin

# Set the serial port name and baud rate
ser = connect()
oqs = oqspython.OQS_SIGNATURE(oqspython.OQS_SIG_alg_sphincs_haraka_256s_simple)

# Get public key
public_key = send_and_receive(
    ser,
    [0xA2, 0x01, 0x65, 0x00, 0x00]
    + list(oqs.length_public_key.to_bytes(2, "big")),
)


verify_pin(ser, [9, 8, 7, 6, 5, 4], 0x00)
verify_pin(ser, [1, 2, 3, 4, 5, 6], 0x01)
# Get private key
private_key = send_and_receive(
    ser,
    [0xA3, 0x01, 0x65, 0x00, 0x00]
    + list(oqs.length_private_key.to_bytes(2, "big")),
)

# Create on device signature and verify it
message = "This is the message to sign"

verify_pin(ser, [1, 2, 3, 4, 5, 6], 0x01)

signature = send_and_receive(
    ser,
    [0xA6, 0x01, 0x65]
    + list(len(message).to_bytes(2, "big"))
    + list(message.encode())
    + list(oqs.length_signature.to_bytes(2, "big")),
)

signature_pc = bytes(oqs.length_signature)
signature_len = oqspython.size_t_p()
result = oqs.sign(
    signature_pc, signature_len, message.encode(), len(message), bytes(private_key)
)

result_pc = oqs.verify(
    message.encode(), len(message), bytes(signature_pc), signature_len.value(), bytes(public_key)
)

result = oqs.verify(
    message.encode(), len(message), bytes(signature), signature_len.value(), bytes(public_key)
)

if result != oqspython.OQS_SUCCESS:
    print("Error verifying signature")
else:
    print("Finished successfully")
ser.close()