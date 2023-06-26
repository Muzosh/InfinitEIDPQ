from pqconnector.oqspython import oqspython

sig = oqspython.OQS_SIGNATURE(oqspython.OQS_SIG_alg_dilithium_5)

public_key = bytes(sig.length_public_key)
private_key = bytes(sig.length_private_key)

message = b"This is the message to sign"

result = sig.keypair(public_key, private_key)
assert result == oqspython.OQS_SUCCESS

signature = bytes(sig.length_signature)
signature_len = oqspython.size_t_p()
result = sig.sign(signature, signature_len, message, len(message), private_key)
assert result == oqspython.OQS_SUCCESS

result = sig.verify(message, len(message), signature, signature_len.value(), public_key)
assert result == oqspython.OQS_SUCCESS

kem = oqspython.OQS_KEYENCAPSULATION(oqspython.OQS_KEM_alg_kyber_1024)

public_key = bytes(kem.length_public_key)
private_key = bytes(kem.length_private_key)

result = kem.keypair(public_key, private_key)
assert result == oqspython.OQS_SUCCESS

shared_secret = bytes(kem.length_shared_secret)
ciphertext = bytes(kem.length_ciphertext)
result = kem.encapsulate(ciphertext, shared_secret, public_key)
assert result == oqspython.OQS_SUCCESS

shared_secret2 = bytes(kem.length_shared_secret)
result = kem.decapsulate(shared_secret2, ciphertext, private_key)
assert result == oqspython.OQS_SUCCESS

assert shared_secret == shared_secret2

print("Finished successfully")
