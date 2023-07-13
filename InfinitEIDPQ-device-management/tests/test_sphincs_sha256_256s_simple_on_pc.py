from hashlib import sha512
from infiniteidpq_device_manager.oqspython import oqspython

# Set the serial port name and baud rate
oqs = oqspython.OQS_SIGNATURE(oqspython.OQS_SIG_alg_sphincs_sha256_256s_simple)

# Prepare message
origin = "https://ria.ee"
challengeNonce = "12345678901234567890123456789012345678901234"
originHash = sha512(origin.encode()).digest()
challengeNonceHash = sha512(challengeNonce.encode()).digest()
hashToBeSigned = sha512(originHash + challengeNonceHash).digest()

# Generate keypair
pk = bytes(oqs.length_public_key)
sk = bytes(oqs.length_private_key)
assert oqspython.OQS_SUCCESS == oqs.keypair(pk, sk)

# Crete signature
signature = bytes(oqs.length_signature)
signature_len = oqspython.size_t_p()
assert oqspython.OQS_SUCCESS == oqs.sign(
    signature, signature_len, hashToBeSigned, len(hashToBeSigned), sk
)

assert oqspython.OQS_SUCCESS == oqs.verify(
    hashToBeSigned,
    len(hashToBeSigned),
    signature,
    signature_len.value(),
    pk
)

print("Finished successfully")
