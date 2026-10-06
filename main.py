"""
Cipher Feedback (CFB) Mode - Interactive Demonstration & Analysis CLI.
Designed for cryptography analysis, demonstration of correctness, and error propagation studies.
"""

import argparse
import os
import sys
import unittest
from cfb.aes import AES128
from cfb.cipher_mode import CFBMode, CFBStepTrace
from cfb.utils import bit_flip, hamming_distance, format_hex_block, bytes_to_hex


def banner():
    print("=" * 76)
    print("  BLOCK CIPHER MODE OF OPERATION: CIPHER FEEDBACK (CFB)")
    print("  Underlying Primitive: AES-128 (FIPS PUB 197) | Standard: NIST SP 800-38A")
    print("=" * 76)


def print_step_trace(trace: CFBStepTrace, is_encrypt: bool = True):
    """Nicely formats and prints one block's internal state transformation."""
    action = "ENCRYPTION" if is_encrypt else "DECRYPTION"
    input_lbl = "Plaintext P_j " if is_encrypt else "Ciphertext C_j"
    output_lbl = "Ciphertext C_j" if is_encrypt else "Plaintext P_j "

    print(f"\n  [STEP {trace.step}] --- ({action})")
    print(f"    1. Input Shift Register (I_{trace.step}) : {bytes_to_hex(trace.input_register)}")
    print(f"    2. AES-128 Output       (O_{trace.step}) : {bytes_to_hex(trace.cipher_output)}")
    print(f"    3. Keystream Segment    (S_{trace.step}) : {bytes_to_hex(trace.keystream_segment)}")
    print(f"    4. Input Data ({input_lbl})     : {bytes_to_hex(trace.input_data)}")
    print(f"    5. Output Data({output_lbl})    : {bytes_to_hex(trace.output_data)}")
    print(f"    6. Next Shift Register  (I_{trace.step + 1}) : {bytes_to_hex(trace.next_register)}")


def run_interactive_trace_demo():
    """Runs a complete walkthrough demonstration showing internal cryptographic states."""
    banner()
    print("\n[+] 1. STEP-BY-STEP CRYPTOGRAPHIC STATE TRACE (CFB-128)")
    print("Demonstrating shift-register updates, keystream generation, and XOR feedback.\n")

    # Use deterministic sample key and IV for demonstration
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    message = "Cryptography assignment at SMVITM: Exploring Cipher Feedback mode!"
    plaintext = message.encode("utf-8")

    print(f"Key (Hex)       : {bytes_to_hex(key)}")
    print(f"IV (Hex)        : {bytes_to_hex(iv)}")
    print(f"Original Text   : \"{message}\"")
    print(f"Length in Bytes : {len(plaintext)} bytes (Note: Not a multiple of 16! CFB handles this seamlessly without padding)\n")

    aes = AES128(key)
    cfb = CFBMode(aes, segment_bits=128)

    # Encrypt with full trace
    ciphertext, enc_traces = cfb.encrypt_with_trace(plaintext, iv)

    print("-" * 76)
    print("ENCRYPTION PROCESS TRACE:")
    for trace in enc_traces:
        print_step_trace(trace, is_encrypt=True)

    print("\n" + "-" * 76)
    print(f"Generated Ciphertext ({len(ciphertext)} bytes):")
    print(format_hex_block(ciphertext))

    # Decrypt with full trace
    print("\n" + "-" * 76)
    print("DECRYPTION PROCESS TRACE (Notice: Uses AES ENCRYPT function O_j = E_K(I_j)!):")
    recovered_bytes, dec_traces = cfb.decrypt_with_trace(ciphertext, iv)
    for trace in dec_traces:
        print_step_trace(trace, is_encrypt=False)

    recovered_text = recovered_bytes.decode("utf-8")
    print("\n" + "-" * 76)
    print(f"Recovered Text : \"{recovered_text}\"")
    print(f"Correctness Verification: {'PASSED (Exact Match)' if recovered_text == message else 'FAILED'}")


def run_error_propagation_demo():
    """Demonstrates CFB error propagation and self-synchronization properties."""
    banner()
    print("\n[+] 2. ERROR PROPAGATION & SELF-SYNCHRONIZATION EXPERIMENT")
    print("Investigating the impact of a 1-bit transmission error in Ciphertext Block 1.\n")

    key = os.urandom(16)
    iv = os.urandom(16)

    # 4 blocks (64 bytes total)
    b1 = b"[Block 1 Header]"
    b2 = b"[Block 2 Payload"
    b3 = b"[Block 3 Content"
    b4 = b"[Block 4 Trailor"
    plaintext = b1 + b2 + b3 + b4

    aes = AES128(key)
    cfb = CFBMode(aes, segment_bits=128)

    ciphertext = cfb.encrypt(plaintext, iv)

    print(f"Plaintext (64 bytes, 4 blocks):")
    for i in range(4):
        chunk = plaintext[i*16:(i+1)*16]
        print(f"  Block #{i+1}: {chunk} (Hex: {chunk.hex()})")

    # Flip 1 bit in block 1 (byte 4, bit 0)
    flip_byte = 4
    flip_bit = 0
    corrupted_ct = bit_flip(ciphertext, byte_index=flip_byte, bit_index=flip_bit)

    print(f"\n[!] INJECTING 1-BIT ERROR:")
    print(f"    Target : Block 1, Byte index {flip_byte}, Bit index {flip_bit}")
    print(f"    Original CT byte : 0x{ciphertext[flip_byte]:02x} ({bin(ciphertext[flip_byte])[2:].zfill(8)})")
    print(f"    Corrupted CT byte: 0x{corrupted_ct[flip_byte]:02x} ({bin(corrupted_ct[flip_byte])[2:].zfill(8)})")

    # Decrypt corrupted ciphertext
    decrypted = cfb.decrypt(corrupted_ct, iv)

    print("\n" + "-" * 76)
    print("DECRYPTED RESULT ANALYSIS:")
    print("-" * 76)

    for i in range(4):
        orig_blk = plaintext[i*16:(i+1)*16]
        dec_blk = decrypted[i*16:(i+1)*16]
        h_dist = hamming_distance(orig_blk, dec_blk)
        match_status = "PERFECT MATCH" if h_dist == 0 else f"CORRUPTED ({h_dist} bits changed)"

        print(f"\n  Block #{i+1} [{match_status}]:")
        print(f"    Original  : {orig_blk} (Hex: {orig_blk.hex()})")
        print(f"    Decrypted : {dec_blk} (Hex: {dec_blk.hex()})")
        print(f"    Hamming Distance: {h_dist} bits")

        if i == 0:
            print("    -> Observation: Exactly 1 bit changed in P_1, matching the flipped bit in C_1.")
        elif i == 1:
            print("    -> Observation: P_2 is completely scrambled because corrupted C_1 was fed into shift register I_2.")
        elif i >= 2:
            print("    -> Observation: SELF-SYNCHRONIZATION ACHIEVED! Shift register cleared the error.")


def run_tests():
    """Runs the full unittest test suite."""
    loader = unittest.TestLoader()
    suite = loader.discover("tests")
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)


def main():
    parser = argparse.ArgumentParser(
        description="Cipher Feedback (CFB) Mode Analysis & Implementation Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--demo", action="store_true", help="Run interactive cryptographic state trace demo")
    parser.add_argument("--error-demo", action="store_true", help="Run error propagation & self-sync demonstration")
    parser.add_argument("--test", action="store_true", help="Execute all unit test cases (NIST vectors, properties, cross-verify)")
    parser.add_argument("--encrypt", type=str, metavar="PLAINTEXT", help="Encrypt an input text string")
    parser.add_argument("--decrypt", type=str, metavar="HEX_CIPHERTEXT", help="Decrypt hex-encoded ciphertext")
    parser.add_argument("--key", type=str, help="16-byte hex key (default: random)")
    parser.add_argument("--iv", type=str, help="16-byte hex IV (default: random)")
    parser.add_argument("--segment", type=int, default=128, choices=[8, 128], help="CFB segment size (8 or 128 bits, default: 128)")

    args = parser.parse_args()

    if args.test:
        run_tests()
    elif args.demo:
        run_interactive_trace_demo()
    elif args.error_demo:
        run_error_propagation_demo()
    elif args.encrypt:
        key = bytes.fromhex(args.key) if args.key else os.urandom(16)
        iv = bytes.fromhex(args.iv) if args.iv else os.urandom(16)
        aes = AES128(key)
        cfb = CFBMode(aes, segment_bits=args.segment)
        ct = cfb.encrypt(args.encrypt.encode("utf-8"), iv)
        print(f"Key (Hex)       : {key.hex()}")
        print(f"IV (Hex)        : {iv.hex()}")
        print(f"Ciphertext (Hex): {ct.hex()}")
    elif args.decrypt:
        if not args.key or not args.iv:
            print("Error: Both --key and --iv (hex format) are required for decryption.", file=sys.stderr)
            sys.exit(1)
        key = bytes.fromhex(args.key)
        iv = bytes.fromhex(args.iv)
        ct = bytes.fromhex(args.decrypt)
        aes = AES128(key)
        cfb = CFBMode(aes, segment_bits=args.segment)
        pt = cfb.decrypt(ct, iv)
        print(f"Decrypted (Bytes): {pt}")
        try:
            print(f"Decrypted (UTF-8): {pt.decode('utf-8')}")
        except UnicodeDecodeError:
            pass
    else:
        # Default: run both demos
        run_interactive_trace_demo()
        print("\n\n")
        run_error_propagation_demo()
        print("\n\nTip: Run 'python main.py --test' to run official NIST test vectors and property tests.")


if __name__ == "__main__":
    main()
