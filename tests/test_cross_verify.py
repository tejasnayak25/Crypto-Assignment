"""
Cross-verification tests comparing custom pure-Python CFB implementation
against the Python `cryptography` library (OpenSSL-backed reference).
"""

import os
import unittest
import warnings
from cfb.aes import AES128
from cfb.cipher_mode import CFBMode

# Import cryptography library CFB modes
with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class TestCrossVerify(unittest.TestCase):
    """Verifies that our CFB implementation matches standard cryptography library outputs."""

    def test_cross_verify_cfb128_multiple_payload_lengths(self):
        """Tests varying payload lengths in CFB-128 against OpenSSL/cryptography."""
        lengths = [1, 7, 16, 23, 32, 45, 64, 128, 250, 1024]
        for length in lengths:
            with self.subTest(length=length):
                key = os.urandom(16)
                iv = os.urandom(16)
                plaintext = os.urandom(length)

                # 1. Custom pure-Python CFB
                custom_cfb = CFBMode(AES128(key), segment_bits=128)
                custom_ct = custom_cfb.encrypt(plaintext, iv)
                custom_recovered = custom_cfb.decrypt(custom_ct, iv)

                # 2. Reference library CFB
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore")
                    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
                    encryptor = cipher.encryptor()
                    ref_ct = encryptor.update(plaintext) + encryptor.finalize()

                    decryptor = cipher.decryptor()
                    ref_recovered = decryptor.update(ref_ct) + decryptor.finalize()

                # Comparisons
                self.assertEqual(custom_ct, ref_ct, f"Ciphertext mismatch at length {length}")
                self.assertEqual(custom_recovered, plaintext)
                self.assertEqual(ref_recovered, plaintext)

    def test_cross_verify_cfb8(self):
        """Tests CFB-8 byte-stream mode against OpenSSL/cryptography CFB8."""
        key = os.urandom(16)
        iv = os.urandom(16)
        plaintext = b"Testing CFB-8 against standard reference implementation!"

        # Custom CFB-8
        custom_cfb8 = CFBMode(AES128(key), segment_bits=8)
        custom_ct = custom_cfb8.encrypt(plaintext, iv)

        # Reference CFB8
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            cipher = Cipher(algorithms.AES(key), modes.CFB8(iv))
            encryptor = cipher.encryptor()
            ref_ct = encryptor.update(plaintext) + encryptor.finalize()

        self.assertEqual(custom_ct, ref_ct)


if __name__ == "__main__":
    unittest.main()
