#!/usr/bin/env python3
"""
ICS570 - Cybersecurity Essentials
Lab Week 9: Implementing and Attacking Symmetric Key Encryption Systems

Complete Lab Demonstration Script
This script runs all three parts of the lab:
1. Design & Implementation
2. Analysis & Attack
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

            print(f"   {mode} mode: encrypted → {encrypted_file}, decrypted → {decrypted_file}")

            # Verify decryption
            with open(input_file, 'rb') as f1, open(decrypted_file, 'rb') as f2:
                if f1.read() == f2.read():
                    print(f"     Decryption successful!")
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

            print(f"   {mode} mode: encrypted and decrypted successfully")

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
    print(" PART 1 COMPLETE: Encryption tool with multiple modes implemented")
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
    print(" PART 2 COMPLETE: Vulnerabilities demonstrated and analyzed")
    print("=" * 80)
    
def main():
    """Run complete lab demonstration."""
    print("\n" + "=" * 80)
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
        part1_implementation()
        part2_analysis_attack()

        print("\n" + "=" * 80)
        print(" LAB DEMONSTRATION COMPLETE!")
        print("=" * 80)

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
