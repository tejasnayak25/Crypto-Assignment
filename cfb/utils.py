"""
Utility functions for CFB Mode and cryptographic operations.
Includes hex formatting, bit manipulation, XOR operations, and visual printing.
"""

from typing import Iterable


def xor_bytes(a: bytes, b: bytes) -> bytes:
    """XORs two byte sequences of equal or unequal length up to min(len(a), len(b))."""
    return bytes(x ^ y for x, y in zip(a, b))


def bytes_to_hex(data: bytes, separator: str = " ") -> str:
    """Formats bytes as spaced hex string."""
    return separator.join(f"{b:02x}" for b in data)


def bit_flip(data: bytes, byte_index: int, bit_index: int = 0) -> bytes:
    """
    Flips a specific bit in a byte string to simulate communication channel error
    or transmission bit-flip.
    """
    if byte_index < 0 or byte_index >= len(data):
        raise IndexError(f"Byte index {byte_index} out of range (length {len(data)})")
    if not (0 <= bit_index < 8):
        raise ValueError("bit_index must be between 0 and 7")

    ba = bytearray(data)
    ba[byte_index] ^= (1 << bit_index)
    return bytes(ba)


def hamming_distance(a: bytes, b: bytes) -> int:
    """Computes bit-level Hamming distance between two equal-length byte sequences."""
    if len(a) != len(b):
        raise ValueError("Hamming distance requires equal length byte sequences")
    return sum(bin(x ^ y).count('1') for x, y in zip(a, b))


def format_hex_block(data: bytes, label: str = "", indent: int = 4) -> str:
    """Pretty prints a byte buffer in 16-byte hex rows."""
    indent_str = " " * indent
    lines = []
    if label:
        lines.append(f"{indent_str}{label}:")
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_str = " ".join(f"{b:02x}" for b in chunk)
        ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{indent_str}  {i:04x}:  {hex_str:<48}  |{ascii_str}|")
    return "\n".join(lines)
