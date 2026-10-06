"""
Formal Test Cases: Verification against NIST FIPS PUB 197 & NIST SP 800-38A.
"""

import unittest
from cfb.aes import AES128
from cfb.cipher_mode import CFBMode


class TestNISTVectors(unittest.TestCase):
    """Verifies core primitive and CFB mode against official NIST test vectors."""

    def test_fips_197_aes128_single_block(self):
        """
        NIST FIPS 197 Appendix B Test Vector.
        Key:        2b7e151628aed2a6abf7158809cf4f3c
        Plaintext:  3243f6a8885a308d313198a2e0370734
        Ciphertext: 3925841d02dc09fbdc118597196a0b32
        """
        key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
        pt = bytes.fromhex("3243f6a8885a308d313198a2e0370734")
        expected_ct = bytes.fromhex("3925841d02dc09fbdc118597196a0b32")

        aes = AES128(key)
        ct = aes.encrypt_block(pt)
        self.assertEqual(ct, expected_ct)

    def test_nist_sp800_38a_cfb128_aes128(self):
        """
        NIST SP 800-38A Section F.3.13: CFB128-AES128 Test Vectors.
        Key: 2b7e151628aed2a6abf7158809cf4f3c
        IV:  000102030405060708090a0b0c0d0e0f
        """
        key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
        iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")

        blocks_pt = [
            bytes.fromhex("6bc1bee22e409f96e93d7e117393172a"),  # Block 1
            bytes.fromhex("ae2d8a571e03ac9c9eb76fac45af8e51"),  # Block 2
            bytes.fromhex("30c81c46a35ce411e5fbc1191a0a52ef"),  # Block 3
            bytes.fromhex("f69f2445df4f9b17ad2b417be66c3710"),  # Block 4
        ]

        expected_blocks_ct = [
            bytes.fromhex("3b3fd92eb72dad20333449f8e83cfb4a"),  # Block 1
            bytes.fromhex("c8a64537a0b3a93fcde3cdad9f1ce58b"),  # Block 2
            bytes.fromhex("26751f67a3cbb140b1808cf187a4f4df"),  # Block 3
            bytes.fromhex("c04b05357c5d1c0eeac4c66f9ff7f2e6"),  # Block 4
        ]

        full_pt = b"".join(blocks_pt)
        expected_full_ct = b"".join(expected_blocks_ct)

        cfb = CFBMode(AES128(key), segment_bits=128)
        
        # 1. Test full multi-block encryption
        ct = cfb.encrypt(full_pt, iv)
        self.assertEqual(ct, expected_full_ct)

        # 2. Test decryption
        recovered_pt = cfb.decrypt(ct, iv)
        self.assertEqual(recovered_pt, full_pt)

        # 3. Test block-by-block trace validation
        _, traces = cfb.encrypt_with_trace(full_pt, iv)
        self.assertEqual(len(traces), 4)
        for idx, trace in enumerate(traces):
            self.assertEqual(trace.output_data, expected_blocks_ct[idx])
            self.assertEqual(trace.input_data, blocks_pt[idx])

    def test_nist_sp800_38a_cfb8_aes128(self):
        """
        NIST SP 800-38A Section F.3.7: CFB8-AES128 Test Vectors.
        Key: 2b7e151628aed2a6abf7158809cf4f3c
        IV:  000102030405060708090a0b0c0d0e0f
        """
        key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
        iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        pt = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")

        # NIST SP 800-38A CFB8-AES128 first 16 octets
        expected_ct = bytes.fromhex("3b79424c9c0dd436bace9e0ed4586a4f")

        cfb8 = CFBMode(AES128(key), segment_bits=8)
        ct = cfb8.encrypt(pt, iv)
        self.assertEqual(ct, expected_ct)

        # Decrypt check
        recovered_pt = cfb8.decrypt(ct, iv)
        self.assertEqual(recovered_pt, pt)


if __name__ == "__main__":
    unittest.main()
