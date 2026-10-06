"""
AES-128 Pure Python Implementation
Conforming to NIST FIPS PUB 197 (Advanced Encryption Standard).
Designed for educational clarity, transparency, and correctness.
"""

# Rijndael S-box (Substitution Box)
S_BOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
]

# Round constants (Rcon) for Key Expansion
RCON = [
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
]


def xtime(a: int) -> int:
    """Galois Field GF(2^8) multiplication by 2 modulo irreducible polynomial x^8 + x^4 + x^3 + x + 1 (0x11B)."""
    return ((a << 1) ^ 0x1B) & 0xFF if (a & 0x80) else (a << 1) & 0xFF


class AES128:
    """
    AES-128 Encryption Core (128-bit key, 128-bit block, 10 rounds).
    Note: CFB mode only requires the ENCRYPT function of the block cipher!
    """
    BLOCK_SIZE = 16  # 128 bits = 16 bytes
    KEY_SIZE = 16    # 128 bits = 16 bytes
    ROUNDS = 10

    def __init__(self, key: bytes):
        if len(key) != self.KEY_SIZE:
            raise ValueError(f"AES-128 requires a 16-byte key, got {len(key)} bytes.")
        self.key = key
        self.round_keys = self._key_expansion(key)

    def _key_expansion(self, key: bytes) -> list[list[int]]:
        """
        Expands the 16-byte key into 11 round keys (44 32-bit words).
        Returns a list of 11 round keys, each represented as a 4x4 matrix of bytes.
        """
        # Form initial words w[0..3]
        w = [list(key[4 * i : 4 * i + 4]) for i in range(4)]

        for i in range(4, 44):
            temp = list(w[i - 1])
            if i % 4 == 0:
                # RotWord: [a0, a1, a2, a3] -> [a1, a2, a3, a0]
                temp = temp[1:] + temp[:1]
                # SubWord using S-box
                temp = [S_BOX[b] for b in temp]
                # XOR with Rcon
                temp[0] ^= RCON[i // 4]
            
            # w[i] = w[i-4] ^ temp
            new_word = [w[i - 4][b] ^ temp[b] for b in range(4)]
            w.append(new_word)

        # Reshape into 11 round keys of 4x4 column-major state matrices
        round_keys = []
        for r in range(self.ROUNDS + 1):
            state = [[0] * 4 for _ in range(4)]
            for col in range(4):
                for row in range(4):
                    state[row][col] = w[r * 4 + col][row]
            round_keys.append(state)
        return round_keys

    @staticmethod
    def _sub_bytes(state: list[list[int]]) -> None:
        """Applies non-linear S-box substitution to each byte of the state."""
        for r in range(4):
            for c in range(4):
                state[r][c] = S_BOX[state[r][c]]

    @staticmethod
    def _shift_rows(state: list[list[int]]) -> None:
        """Cyclically shifts the rows of the state over different offsets."""
        state[1] = state[1][1:] + state[1][:1]      # Shift 1 byte left
        state[2] = state[2][2:] + state[2][:2]      # Shift 2 bytes left
        state[3] = state[3][3:] + state[3][:3]      # Shift 3 bytes left

    @staticmethod
    def _mix_columns(state: list[list[int]]) -> None:
        """Multiplies each column by a fixed polynomial matrix in GF(2^8)."""
        for c in range(4):
            s0 = state[0][c]
            s1 = state[1][c]
            s2 = state[2][c]
            s3 = state[3][c]
            state[0][c] = xtime(s0) ^ xtime(s1) ^ s1 ^ s2 ^ s3
            state[1][c] = s0 ^ xtime(s1) ^ xtime(s2) ^ s2 ^ s3
            state[2][c] = s0 ^ s1 ^ xtime(s2) ^ xtime(s3) ^ s3
            state[3][c] = xtime(s0) ^ s0 ^ s1 ^ s2 ^ xtime(s3)

    @staticmethod
    def _add_round_key(state: list[list[int]], round_key: list[list[int]]) -> None:
        """XORs the state with the 128-bit round key."""
        for r in range(4):
            for c in range(4):
                state[r][c] ^= round_key[r][c]

    def encrypt_block(self, block: bytes) -> bytes:
        """
        Encrypts a single 16-byte block using AES-128.
        Returns the encrypted 16-byte block.
        """
        if len(block) != self.BLOCK_SIZE:
            raise ValueError(f"Block size must be {self.BLOCK_SIZE} bytes, got {len(block)} bytes.")

        # Initialize State Matrix (column-major order as defined in FIPS 197)
        state = [[block[r + 4 * c] for c in range(4)] for r in range(4)]

        # Initial Round
        self._add_round_key(state, self.round_keys[0])

        # Main Rounds (1 to 9)
        for r in range(1, self.ROUNDS):
            self._sub_bytes(state)
            self._shift_rows(state)
            self._mix_columns(state)
            self._add_round_key(state, self.round_keys[r])

        # Final Round (Round 10, no MixColumns)
        self._sub_bytes(state)
        self._shift_rows(state)
        self._add_round_key(state, self.round_keys[self.ROUNDS])

        # Output column-major byte sequence
        out = bytearray(self.BLOCK_SIZE)
        for c in range(4):
            for r in range(4):
                out[r + 4 * c] = state[r][c]
        return bytes(out)
