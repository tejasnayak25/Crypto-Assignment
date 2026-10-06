import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

BLOCK_SIZE = 16  # AES block size in bytes

# Single-block AES Encryption (primitive used to generate keystream)
def aes_encrypt_block(key, block):
    encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return encryptor.update(block) + encryptor.finalize()

_aes_encrypt_block = aes_encrypt_block

# CFB Mode Encryption
def cfb_encrypt(key, iv, plaintext):
    if len(iv) != BLOCK_SIZE:
        raise ValueError(f"IV must be {BLOCK_SIZE} bytes")

    ciphertext = bytearray()
    prev = iv
    for offset in range(0, len(plaintext), BLOCK_SIZE):
        segment = plaintext[offset:offset + BLOCK_SIZE]
        keystream = aes_encrypt_block(key, prev)
        c_block = bytes(a ^ b for a, b in zip(segment, keystream))
        ciphertext.extend(c_block)
        prev = c_block if len(c_block) == BLOCK_SIZE else (c_block + keystream[len(c_block):])
    return bytes(ciphertext)

# CFB Mode Decryption
def cfb_decrypt(key, iv, ciphertext):
    if len(iv) != BLOCK_SIZE:
        raise ValueError(f"IV must be {BLOCK_SIZE} bytes")

    plaintext = bytearray()
    prev = iv
    for offset in range(0, len(ciphertext), BLOCK_SIZE):
        segment = ciphertext[offset:offset + BLOCK_SIZE]
        keystream = aes_encrypt_block(key, prev)
        p_block = bytes(a ^ b for a, b in zip(segment, keystream))
        plaintext.extend(p_block)
        prev = segment if len(segment) == BLOCK_SIZE else (segment + keystream[len(segment):])
    return bytes(plaintext)

# Generate 128-bit key and initialization vector (IV)
key = os.urandom(16)
iv = os.urandom(16)
print("\nSecret Key (hex) :", key.hex())
print("IV (hex)         :", iv.hex())

# User Input Message
user_text = input("\nEnter plaintext message: ")
message = user_text.encode()

# Encrypt the message
ciphertext = cfb_encrypt(key, iv, message)
print("\nEncrypted (hex)  :", ciphertext.hex())

# Decrypt the ciphertext
decrypted_message = cfb_decrypt(key, iv, ciphertext)
print("Decrypted Message:", decrypted_message.decode())

# Verify correctness
if message == decrypted_message:
    print("\nTEST PASSED")
    print("CFB encryption and decryption is successful.")
else:
    print("\nTEST FAILED")