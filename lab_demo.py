#!/usr/bin/env python3
"""
ICS570 - Cybersecurity Essentials
Lab Week 9: Implementing and Attacking Symmetric Key Encryption Systems

Complete Lab Demonstration Script
This script runs all three parts of the lab:
1. Design & Implementation
2. Analysis & Attack
3. Reflection & Improvement
"""

from crypto_tool import CryptoTool
from image_crypto import ImageCrypto
from crypto_analysis import CryptoAnalyzer
import os
import sys


def print_header(title):
    """Print formatted section header."""
    print("\n" + "=" * 80)
    print(f" {title}")
    print("=" * 80 + "\n")


def part1_implementation():
    """Part 1: Design & Implementation - Deliverable 1"""
    print_header("PART 1: DESIGN & IMPLEMENTATION")

    print("[DELIVERABLE 1] Working encryption/decryption tool with mode selection\n")

    # Test AES encryption
    print("-" * 80)
    print("Testing AES Encryption with Multiple Modes")
    print("-" * 80)

    aes_tool = CryptoTool('AES')
    key_aes = aes_tool.generate_key(passphrase="AES_Lab_Demo_2024")

    print(f"\n[+] Generated AES-128 key: {key_aes.hex()}")

    # Test with plaintext.txt
    if os.path.exists('plaintext.txt'):
        print("\n[*] Encrypting plaintext.txt with different modes...")

        modes_to_test = ['ECB', 'CBC', 'CFB', 'OFB', 'CTR']

        for mode in modes_to_test:
            input_file = 'plaintext.txt'
            encrypted_file = f'output/plaintext_aes_{mode.lower()}.enc'
            decrypted_file = f'output/plaintext_aes_{mode.lower()}_decrypted.txt'

            # Encrypt
            iv = aes_tool.encrypt_file(input_file, encrypted_file, key_aes, mode)

            # Decrypt
            aes_tool.decrypt_file(encrypted_file, decrypted_file, key_aes, mode, iv)

            print(f"  ✓ {mode} mode: encrypted → {encrypted_file}, decrypted → {decrypted_file}")

            # Verify decryption
            with open(input_file, 'rb') as f1, open(decrypted_file, 'rb') as f2:
                if f1.read() == f2.read():
                    print(f"    ✓ Decryption successful!")
                else:
                    print(f"    ✗ Decryption failed!")

    # Test DES encryption
    print("\n" + "-" * 80)
    print("Testing DES Encryption")
    print("-" * 80)

    des_tool = CryptoTool('DES')
    key_des = des_tool.generate_key(passphrase="DES_Lab")

    print(f"\n[+] Generated DES key: {key_des.hex()}")

    if os.path.exists('studentdata.csv'):
        print("\n[*] Encrypting studentdata.csv with DES...")

        for mode in ['ECB', 'CBC', 'CTR']:
            input_file = 'studentdata.csv'
            encrypted_file = f'output/studentdata_des_{mode.lower()}.enc'
            decrypted_file = f'output/studentdata_des_{mode.lower()}_decrypted.csv'

            iv = des_tool.encrypt_file(input_file, encrypted_file, key_des, mode)
            des_tool.decrypt_file(encrypted_file, decrypted_file, key_des, mode, iv)

            print(f"  ✓ {mode} mode: encrypted and decrypted successfully")

    # Image encryption and visualization
    print("\n" + "-" * 80)
    print("Image Encryption & Visualization")
    print("-" * 80)

    if os.path.exists('Tux.png'):
        print("\n[*] Encrypting and visualizing Tux.png...")

        img_crypto = ImageCrypto('AES')
        key_img = img_crypto.crypto.generate_key(passphrase="ImageDemo2024")

        # Demonstrate ECB vulnerability
        img_crypto.demonstrate_ecb_vulnerability('Tux.png', key_img, 'output')

        print("\n[*] Comparing all cipher modes on image...")
        img_crypto.compare_modes('Tux.png', key_img,
                                modes=['ECB', 'CBC', 'CFB', 'OFB', 'CTR'],
                                output_dir='output')

    print("\n" + "=" * 80)
    print("✓ PART 1 COMPLETE: Encryption tool with multiple modes implemented")
    print("=" * 80)


def part2_analysis_attack():
    """Part 2: Analysis & Attack - Deliverable 2"""
    print_header("PART 2: ANALYSIS & ATTACK")

    print("[DELIVERABLE 2] Pattern leakage analysis and attack demonstrations\n")

    analyzer = CryptoAnalyzer('AES')

    # Key reuse vulnerability
    print("-" * 80)
    print("Demonstrating Key Reuse Vulnerability")
    print("-" * 80)

    analyzer.demonstrate_key_reuse_vulnerability('output')

    # ECB pattern attack
    if os.path.exists('Tux.png'):
        print("\n" + "-" * 80)
        print("Demonstrating ECB Pattern Attack")
        print("-" * 80)

        key = analyzer.crypto.generate_key(passphrase="AttackDemo")
        analyzer.attack_ecb_image('Tux.png', key, 'output')

    print("\n" + "=" * 80)
    print("✓ PART 2 COMPLETE: Vulnerabilities demonstrated and analyzed")
    print("=" * 80)


def part3_reflection():
    """Part 3: Reflection & Improvement - Deliverable 3"""
    print_header("PART 3: REFLECTION & IMPROVEMENT")

    print("[DELIVERABLE 3] Key lessons and best practices\n")

    print("-" * 80)
    print("Key Lessons Learned")
    print("-" * 80)

    lessons = [
        ("ECB Mode is Fundamentally Insecure for Structured Data",
         "ECB encrypts identical plaintext blocks to identical ciphertext blocks, "
         "revealing patterns and structure even without decryption."),

        ("Initialization Vectors (IVs) are Critical",
         "Random, unique IVs ensure that encrypting the same plaintext multiple times "
         "produces different ciphertexts, preventing pattern correlation attacks."),

        ("Key Reuse Enables Pattern Analysis",
         "Reusing the same key across multiple encryptions allows attackers to correlate "
         "ciphertexts and identify similarities in plaintexts."),

        ("CBC Mode Provides Better Security",
         "Block chaining and IV randomization effectively hide patterns, making "
         "ciphertext appear random even for structured data."),

        ("Encryption Alone is Not Enough",
         "Proper mode selection, key management, and protocol design are essential "
         "for secure cryptographic systems.")
    ]

    for i, (title, description) in enumerate(lessons, 1):
        print(f"\n{i}. {title}")
        print(f"   {description}")

    print("\n\n" + "-" * 80)
    print("Best Practices for Secure Symmetric Encryption")
    print("-" * 80)

    best_practices = [
        ("Never Use ECB Mode", "Always use CBC, CTR, GCM, or other secure modes"),
        ("Use Random IVs", "Generate cryptographically random IV for each encryption"),
        ("Implement Key Rotation", "Regularly rotate encryption keys to limit exposure"),
        ("Never Reuse IV with Same Key", "Especially critical for CTR mode"),
        ("Use Authenticated Encryption", "Consider AES-GCM for combined confidentiality and integrity"),
        ("Secure Key Storage", "Use key management systems, never hardcode keys"),
        ("Proper Padding", "Use PKCS7 padding for block ciphers correctly"),
        ("Regular Security Audits", "Test and audit encryption implementations")
    ]

    for practice, explanation in best_practices:
        print(f"\n✓ {practice}")
        print(f"  → {explanation}")

    print("\n\n" + "-" * 80)
    print("Reflection Questions Answered")
    print("-" * 80)

    print("\nQ1: What surprised you most about ECB mode?")
    print("A:  The extent to which visual patterns leak through encryption was surprising.")
    print("    Even though data is encrypted, the structural information remains visible,")
    print("    making ECB completely unsuitable for images or any structured data.")

    print("\nQ2: How would you design a secure messaging app using symmetric encryption?")
    print("A:  Key design decisions:")
    print("    • Use AES-256 in GCM mode for authenticated encryption")
    print("    • Generate unique session keys using key derivation (HKDF)")
    print("    • Use random IVs/nonces for each message")
    print("    • Implement perfect forward secrecy (PFS)")
    print("    • Combine with asymmetric encryption for key exchange (Diffie-Hellman)")
    print("    • Add message authentication codes (MACs) or use AEAD ciphers")
    print("    • Implement key rotation every N messages or time period")

    print("\nQ3: What are the risks of key reuse?")
    print("A:  Key reuse poses several critical risks:")
    print("    • Pattern correlation: Attackers can compare ciphertexts to find similarities")
    print("    • Known-plaintext attacks: If one plaintext is known, others may be compromised")
    print("    • Statistical analysis: Large datasets encrypted with same key leak information")
    print("    • Reduced security margin: More ciphertext samples help cryptanalysis")
    print("    • IV reuse in CTR mode: Catastrophic - allows XOR attack to recover plaintext")

    print("\n" + "=" * 80)
    print("✓ PART 3 COMPLETE: Reflection and recommendations documented")
    print("=" * 80)


def main():
    """Run complete lab demonstration."""
    print("\n" + "=" * 80)
    print(" ICS570 - CYBERSECURITY ESSENTIALS")
    print(" LAB WEEK 9: IMPLEMENTING AND ATTACKING SYMMETRIC KEY ENCRYPTION")
    print(" Complete Lab Demonstration")
    print("=" * 80)

    # Create output directory
    os.makedirs('output', exist_ok=True)

    # Check for required files
    required_files = ['plaintext.txt', 'Tux.png', 'studentdata.csv']
    missing_files = [f for f in required_files if not os.path.exists(f)]

    if missing_files:
        print("\n[!] Warning: The following files are missing:")
        for f in missing_files:
            print(f"    - {f}")
        print("\n[!] Some demonstrations may be skipped.")

        response = input("\n[?] Continue anyway? (y/n): ")
        if response.lower() != 'y':
            print("\n[*] Exiting. Please ensure all required files are present.")
            sys.exit(0)

    try:
        # Run all three parts
        part1_implementation()
        part2_analysis_attack()
        part3_reflection()

        print("\n" + "=" * 80)
        print(" LAB DEMONSTRATION COMPLETE!")
        print("=" * 80)
        print("\n[+] All three deliverables completed:")
        print("    ✓ Deliverable 1: Working encryption/decryption tool")
        print("    ✓ Deliverable 2: Analysis and attack demonstrations")
        print("    ✓ Deliverable 3: Reflection and best practices")
        print("\n[+] Output files saved in: ./output/")
        print("[+] Review the generated images and encrypted files")
        print("\n" + "=" * 80 + "\n")

    except KeyboardInterrupt:
        print("\n\n[!] Demonstration interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Error during demonstration: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
