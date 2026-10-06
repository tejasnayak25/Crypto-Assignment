"""
Property and Behavioral Tests for CFB (Cipher Feedback) Mode.
Demonstrating:
1. Arbitrary-length streaming without padding.
2. Perfect invertibility (Round-trip Decrypt(Encrypt(P)) == P).
3. Self-synchronization and error propagation dynamics (CFB-128 and CFB-8).
4. Decryption using only the block cipher's encryption function.
"""

import os
import unittest
from cfb.aes import AES128
from cfb.cipher_mode import CFBMode
from cfb.utils import bit_flip, hamming_distance


class TestCFBProperties(unittest.TestCase):
    """Tests behavioral invariants, error propagation, and self-synchronization in CFB mode."""

    def setUp(self):
        self.key = os.urandom(16)
        self.iv = os.urandom(16)
        self.aes = AES128(self.key)
        self.cfb128 = CFBMode(self.aes, segment_bits=128)
        self.cfb8 = CFBMode(self.aes, segment_bits=8)

    def test_arbitrary_lengths_without_padding(self):
        """CFB mode acts as a stream cipher; ciphertext length equals plaintext length."""
        test_lengths = [0, 1, 2, 7, 15, 16, 17, 31, 32, 33, 100, 255, 512, 1024]
        for length in test_lengths:
            with self.subTest(length=length):
                pt = os.urandom(length)
                ct = self.cfb128.encrypt(pt, self.iv)
                self.assertEqual(len(ct), len(pt), f"Length mismatch for length {length}")
                dec = self.cfb128.decrypt(ct, self.iv)
                self.assertEqual(dec, pt, f"Round-trip failed for length {length}")

    def test_unicode_and_text_roundtrip(self):
        """Verifies text strings with multibyte Unicode characters."""
        messages = [
            "Cryptography and Network Security - Block Cipher Modes of Operation",
            "SMVITM Department of Computer Science & Engineering 🎓 🚀 🔐",
            "Special characters: !@#$%^&*()_+-=[]{}|;':,.<>/?~`\n\t\r",
            "日本語テキスト暗号化テスト (Japanese Unicode Test)",
        ]
        for msg in messages:
            pt = msg.encode("utf-8")
            ct = self.cfb128.encrypt(pt, self.iv)
            recovered = self.cfb128.decrypt(ct, self.iv).decode("utf-8")
            self.assertEqual(recovered, msg)

    def test_cfb128_error_propagation_and_self_sync(self):
        """
        In CFB-128 (s = 128 bits):
        A 1-bit error in ciphertext block C_1 causes:
          - Exactly a 1-bit error in decrypted block P_1 (at the identical bit position).
          - Complete scrambling of decrypted block P_2 (since C_1 corrupted the shift register I_2).
          - 100% perfect self-synchronization recovery in block P_3 and all subsequent blocks!
        """
        # Create 4 distinct 16-byte blocks (64 bytes total)
        b1 = b"AAAAAAAAAAAAAAAA"  # Block 1
        b2 = b"BBBBBBBBBBBBBBBB"  # Block 2
        b3 = b"CCCCCCCCCCCCCCCC"  # Block 3
        b4 = b"DDDDDDDDDDDDDDDD"  # Block 4
        plaintext = b1 + b2 + b3 + b4

        ciphertext = self.cfb128.encrypt(plaintext, self.iv)

        # Introduce a 1-bit flip in Block 1 (at byte 3, bit 2)
        corrupted_ct = bit_flip(ciphertext, byte_index=3, bit_index=2)

        # Decrypt corrupted ciphertext
        decrypted = self.cfb128.decrypt(corrupted_ct, self.iv)

        dec_b1 = decrypted[0:16]
        dec_b2 = decrypted[16:32]
        dec_b3 = decrypted[32:48]
        dec_b4 = decrypted[48:64]

        # 1. Block 1: Exactly 1 bit should differ
        h1 = hamming_distance(b1, dec_b1)
        self.assertEqual(h1, 1, f"Expected 1-bit error in P_1, got {h1} bits")
        # Ensure only byte 3 differs
        self.assertEqual(b1[:3], dec_b1[:3])
        self.assertEqual(b1[4:], dec_b1[4:])
        self.assertEqual(b1[3] ^ dec_b1[3], 1 << 2)

        # 2. Block 2: Garbled / scrambled due to bad I_2 input to AES
        h2 = hamming_distance(b2, dec_b2)
        self.assertGreater(h2, 30, f"Expected garbled P_2 with high Hamming distance, got {h2}")

        # 3. Block 3 & 4: Self-synchronization restored! 0 errors
        self.assertEqual(dec_b3, b3, "Block 3 must self-synchronize and match exactly")
        self.assertEqual(dec_b4, b4, "Block 4 must self-synchronize and match exactly")

    def test_cfb8_error_propagation_and_self_sync(self):
        """
        In CFB-8 (s = 8 bits):
        A 1-bit error in ciphertext byte k causes:
          - Exactly a 1-bit error in decrypted byte k.
          - Next 16 decrypted bytes (k+1 .. k+16) are scrambled (since register size is 16 bytes).
          - From byte k+17 onward, perfect self-synchronization recovery!
        """
        plaintext = b"This is an extended demonstration of CFB-8 byte-stream self-synchronization recovery."
        ciphertext = self.cfb8.encrypt(plaintext, self.iv)

        # Flip 1 bit in byte 5
        corrupt_idx = 5
        corrupted_ct = bit_flip(ciphertext, byte_index=corrupt_idx, bit_index=0)

        decrypted = self.cfb8.decrypt(corrupted_ct, self.iv)

        # Byte 5: exactly 1 bit difference
        self.assertEqual(plaintext[:corrupt_idx], decrypted[:corrupt_idx])
        self.assertEqual(plaintext[corrupt_idx] ^ decrypted[corrupt_idx], 1)

        # Bytes 6..21 (next 16 bytes): scrambled
        scrambled_pt = plaintext[corrupt_idx + 1 : corrupt_idx + 17]
        scrambled_dec = decrypted[corrupt_idx + 1 : corrupt_idx + 17]
        self.assertNotEqual(scrambled_pt, scrambled_dec)

        # Bytes 22 onward: perfectly restored!
        restored_pt = plaintext[corrupt_idx + 17 :]
        restored_dec = decrypted[corrupt_idx + 17 :]
        self.assertEqual(restored_dec, restored_pt, "Self-synchronization failed after 16 bytes")

    def test_iv_uniqueness_requirement(self):
        """
        Using identical key and IV produces identical keystream.
        XORing two ciphertexts reveals XOR of plaintexts (keystream reuse attack).
        """
        pt1 = b"SensitiveSecretA"
        pt2 = b"SensitiveSecretB"
        ct1 = self.cfb128.encrypt(pt1, self.iv)
        ct2 = self.cfb128.encrypt(pt2, self.iv)

        # Keystream is identical for block 1:
        # ct1 ^ ct2 = (pt1 ^ S1) ^ (pt2 ^ S1) = pt1 ^ pt2
        xor_ct = bytes(x ^ y for x, y in zip(ct1, ct2))
        xor_pt = bytes(x ^ y for x, y in zip(pt1, pt2))
        self.assertEqual(xor_ct, xor_pt)


if __name__ == "__main__":
    unittest.main()
