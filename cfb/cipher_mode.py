"""
Cipher Feedback (CFB) Block Cipher Mode Implementation.
Conforming to NIST SP 800-38A Section 6.3.

Supports:
- Standard full-block CFB-128 (s = 128 bits / 16 bytes)
- Byte-stream CFB-8 (s = 8 bits / 1 byte)
- Streaming arbitrary byte lengths without padding
- Detailed intermediate state trace generation for cryptographic analysis
"""

from dataclasses import dataclass
from typing import Protocol, runtime_checkable
from .utils import xor_bytes


@runtime_checkable
class BlockCipher(Protocol):
    BLOCK_SIZE: int

    def encrypt_block(self, block: bytes) -> bytes:
        """Encrypts a single block of length BLOCK_SIZE."""
        ...


@dataclass
class CFBStepTrace:
    """Detailed cryptographic trace for one CFB step/block."""
    step: int
    input_register: bytes      # I_j: Shift register / input to cipher
    cipher_output: bytes       # O_j = CIPH_K(I_j)
    keystream_segment: bytes   # S_j = MSB_s(O_j)
    input_data: bytes          # P_j (during enc) or C_j (during dec)
    output_data: bytes         # C_j (during enc) or P_j (during dec)
    next_register: bytes       # I_{j+1} = LSB_{b-s}(I_j) || C_j


class CFBMode:
    """
    Cipher Feedback (CFB) Mode of Operation.
    
    Attributes:
        cipher: The underlying block cipher instance (e.g. AES128).
        segment_bits: Segment size s in bits (128 for CFB-128, 8 for CFB-8).
    """

    def __init__(self, cipher: BlockCipher, segment_bits: int = 128):
        if segment_bits not in (8, 128):
            raise ValueError(f"segment_bits must be 8 or 128, got {segment_bits}")
        self.cipher = cipher
        self.segment_bits = segment_bits
        self.segment_bytes = segment_bits // 8
        self.block_size = cipher.BLOCK_SIZE

    def encrypt(self, plaintext: bytes, iv: bytes) -> bytes:
        """Encrypts arbitrary-length plaintext using CFB mode."""
        ciphertext, _ = self._process(plaintext, iv, is_encrypt=True, capture_trace=False)
        return ciphertext

    def decrypt(self, ciphertext: bytes, iv: bytes) -> bytes:
        """Decrypts arbitrary-length ciphertext using CFB mode."""
        plaintext, _ = self._process(ciphertext, iv, is_encrypt=False, capture_trace=False)
        return plaintext

    def encrypt_with_trace(self, plaintext: bytes, iv: bytes) -> tuple[bytes, list[CFBStepTrace]]:
        """Encrypts and returns (ciphertext, list_of_step_traces)."""
        return self._process(plaintext, iv, is_encrypt=True, capture_trace=True)

    def decrypt_with_trace(self, ciphertext: bytes, iv: bytes) -> tuple[bytes, list[CFBStepTrace]]:
        """Decrypts and returns (plaintext, list_of_step_traces)."""
        return self._process(ciphertext, iv, is_encrypt=False, capture_trace=True)

    def _process(
        self,
        data: bytes,
        iv: bytes,
        is_encrypt: bool,
        capture_trace: bool
    ) -> tuple[bytes, list[CFBStepTrace]]:
        """
        Core CFB processing loop for both encryption and decryption.
        
        Per NIST SP 800-38A:
          I_1 = IV
          For j = 1..n:
            O_j = CIPH_K(I_j)
            S_j = MSB_s(O_j)
            If encrypt: C_j = P_j ^ S_j, feedback is C_j
            If decrypt: P_j = C_j ^ S_j, feedback is C_j
            I_{j+1} = LSB_{b-s}(I_j) || C_j
        """
        if len(iv) != self.block_size:
            raise ValueError(
                f"IV length must match block size ({self.block_size} bytes), got {len(iv)} bytes."
            )

        if not data:
            return b"", []

        output_chunks: list[bytes] = []
        traces: list[CFBStepTrace] = []

        register = iv  # I_1 = IV
        step = 1

        # Break data into segment_bytes chunks
        for offset in range(0, len(data), self.segment_bytes):
            chunk = data[offset : offset + self.segment_bytes]
            chunk_len = len(chunk)

            # O_j = CIPH_K(I_j)
            cipher_output = self.cipher.encrypt_block(register)

            # S_j = MSB(O_j) truncated to chunk length
            keystream_segment = cipher_output[:chunk_len]

            # XOR to produce output
            transformed = xor_bytes(chunk, keystream_segment)
            output_chunks.append(transformed)

            # In CFB, the ciphertext segment is always fed back into the shift register
            if is_encrypt:
                ciphertext_segment = transformed
                plaintext_segment = chunk
            else:
                ciphertext_segment = chunk
                plaintext_segment = transformed

            # I_{j+1} = Shift left by chunk_len and append ciphertext segment
            next_register = register[chunk_len:] + ciphertext_segment

            if capture_trace:
                traces.append(
                    CFBStepTrace(
                        step=step,
                        input_register=register,
                        cipher_output=cipher_output,
                        keystream_segment=keystream_segment,
                        input_data=chunk,
                        output_data=transformed,
                        next_register=next_register,
                    )
                )

            register = next_register
            step += 1

        return b"".join(output_chunks), traces
