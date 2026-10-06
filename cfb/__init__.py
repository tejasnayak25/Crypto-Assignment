"""
CFB (Cipher Feedback) Block Cipher Mode Package.
Includes pure-Python AES-128 and configurable CFB mode (CFB-128 & CFB-8).
"""

from .aes import AES128
from .cipher_mode import CFBMode, CFBStepTrace, BlockCipher
from .utils import bit_flip, hamming_distance, format_hex_block, bytes_to_hex

__all__ = [
    "AES128",
    "CFBMode",
    "CFBStepTrace",
    "BlockCipher",
    "bit_flip",
    "hamming_distance",
    "format_hex_block",
    "bytes_to_hex",
]
