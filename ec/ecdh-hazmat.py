from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import binascii
import sys


Bob_private_key = ec.generate_private_key(ec.SECP384R1())
Alice_private_key = ec.generate_private_key(ec.SECP384R1())

size = 32

Bob_shared_key = Bob_private_key.exchange(ec.ECDH(), Alice_private_key.public_key())

Bob_dervied_key = HKDF(hashes.SHA256(), length = size, salt = None,   info = b'').derive(Bob_shared_key)

Alice_shared_key = Alice_private_key.exchange(ec.ECDH(), Bob_private_key.public_key())

Alice_derived_key = HKDF(hashes.SHA256(), length = size, salt = None, info = b'').derive(Alice_shared_key)


print ("Name of curve: ",Bob_private_key.public_key().curve.name)
print (f"Generated key size: {size} bytes ({size*8} bits)")


vals = Bob_private_key.private_numbers()
print (f"\nBob private key value: {vals.private_value}")
vals=Bob_private_key.public_key().public_numbers()
enc_point=binascii.b2a_hex(vals.encode_point()).decode()
print("Bob's public key: ",enc_point)

vals = Alice_private_key.private_numbers()
print (f"\nAlice private key value: {vals.private_value}")
vals=Alice_private_key.public_key().public_numbers()
enc_point=binascii.b2a_hex(vals.encode_point()).decode()
print("Alice's public key: ",enc_point)


print ("\nBob's derived key: ",binascii.b2a_hex(Bob_dervied_key).decode())
print("Alice's derived key: ",binascii.b2a_hex(Alice_derived_key).decode())




