#!/usr/bin/env python3
"""
Cryptographic Analysis and Attack Module
Demonstrates pattern leakage, key reuse vulnerabilities, and ciphertext analysis
"""

import numpy as np
import matplotlib.pyplot as plt
from crypto_tool import CryptoTool
from image_crypto import ImageCrypto
import os


class CryptoAnalyzer:
    """Analyze encryption weaknesses and demonstrate attacks."""

    def __init__(self, algorithm='AES'):
        """Initialize analyzer with encryption algorithm."""
        self.crypto = CryptoTool(algorithm)
        self.img_crypto = ImageCrypto(algorithm)
        self.algorithm = algorithm

    def calculate_histogram_similarity(self, data1, data2, bins=256):
        """
        Calculate histogram-based similarity between two byte arrays.

        Args:
            data1 (bytes): First data set
            data2 (bytes): Second data set
            bins (int): Number of histogram bins

        Returns:
            float: Similarity score (0-1, higher means more similar)
        """
        # Convert to numpy arrays
        arr1 = np.frombuffer(data1, dtype=np.uint8)
        arr2 = np.frombuffer(data2, dtype=np.uint8)

        # Calculate histograms
        hist1, _ = np.histogram(arr1, bins=bins, range=(0, 256), density=True)
        hist2, _ = np.histogram(arr2, bins=bins, range=(0, 256), density=True)

        # Calculate correlation (Pearson coefficient)
        correlation = np.corrcoef(hist1, hist2)[0, 1]

        return correlation

    def calculate_xor_similarity(self, data1, data2):
        """
        Calculate XOR-based similarity (Hamming distance).

        Args:
            data1 (bytes): First data set
            data2 (bytes): Second data set

        Returns:
            dict: Similarity metrics including hamming distance and ratio
        """
        # Ensure same length
        min_len = min(len(data1), len(data2))
        data1 = data1[:min_len]
        data2 = data2[:min_len]

        # XOR the bytes
        xor_result = bytes(a ^ b for a, b in zip(data1, data2))

        # Count differing bits (Hamming distance)
        hamming_distance = sum(bin(byte).count('1') for byte in xor_result)

        # Total possible bits
        total_bits = min_len * 8

        # Similarity ratio (0 = completely different, 1 = identical)
        similarity_ratio = 1 - (hamming_distance / total_bits)

        # Different bytes count
        different_bytes = sum(1 for a, b in zip(data1, data2) if a != b)

        return {
            'hamming_distance': hamming_distance,
            'total_bits': total_bits,
            'similarity_ratio': similarity_ratio,
            'different_bytes': different_bytes,
            'total_bytes': min_len,
            'byte_difference_ratio': different_bytes / min_len
        }

    def demonstrate_key_reuse_vulnerability(self, output_dir='output'):
        """
        Demonstrate security risks of reusing encryption keys.

        Args:
            output_dir (str): Directory to save results
        """
        print("\n" + "=" * 70)
        print("DEMONSTRATING KEY REUSE VULNERABILITY")
        print("=" * 70)

        os.makedirs(output_dir, exist_ok=True)

        # Generate a single key
        key = self.crypto.generate_key(passphrase="ReusedKey123")
        print(f"\n[+] Using single key (INSECURE practice): {key.hex()}")

        # Two different plaintexts
        plaintext1 = b"Secret message number ONE for testing encryption patterns!"
        plaintext2 = b"Secret message number TWO for testing encryption patterns!"

        print(f"\n[+] Plaintext 1: {plaintext1.decode()}")
        print(f"[+] Plaintext 2: {plaintext2.decode()}")

        # Test ECB mode (most vulnerable)
        print("\n" + "-" * 70)
        print("Testing ECB Mode with Key Reuse:")
        print("-" * 70)

        cipher1_ecb, _ = self.crypto.encrypt(plaintext1, key, 'ECB')
        cipher2_ecb, _ = self.crypto.encrypt(plaintext2, key, 'ECB')

        print(f"Ciphertext 1 (hex): {cipher1_ecb.hex()[:64]}...")
        print(f"Ciphertext 2 (hex): {cipher2_ecb.hex()[:64]}...")

        # Analyze similarity
        hist_sim_ecb = self.calculate_histogram_similarity(cipher1_ecb, cipher2_ecb)
        xor_sim_ecb = self.calculate_xor_similarity(cipher1_ecb, cipher2_ecb)

        print(f"\n[!] ECB Mode Analysis:")
        print(f"  Histogram Correlation: {hist_sim_ecb:.4f}")
        print(f"  XOR Similarity Ratio: {xor_sim_ecb['similarity_ratio']:.4f}")
        print(f"  Different Bytes: {xor_sim_ecb['different_bytes']}/{xor_sim_ecb['total_bytes']}")
        print(f"  Hamming Distance: {xor_sim_ecb['hamming_distance']} bits")

        # Identify identical blocks
        block_size = self.crypto.block_size
        identical_blocks = 0
        for i in range(0, min(len(cipher1_ecb), len(cipher2_ecb)), block_size):
            block1 = cipher1_ecb[i:i+block_size]
            block2 = cipher2_ecb[i:i+block_size]
            if block1 == block2:
                identical_blocks += 1

        print(f"  Identical Ciphertext Blocks: {identical_blocks}")
        print(f"  VULNERABILITY: Identical plaintext blocks encrypt to")
        print(f"      identical ciphertext blocks, revealing patterns!")

        # Test CBC mode (more secure with different IVs)
        print("\n" + "-" * 70)
        print("Testing CBC Mode with Key Reuse (but different IVs):")
        print("-" * 70)

        cipher1_cbc, iv1 = self.crypto.encrypt(plaintext1, key, 'CBC')
        cipher2_cbc, iv2 = self.crypto.encrypt(plaintext2, key, 'CBC')

        print(f"Ciphertext 1 (hex): {cipher1_cbc.hex()[:64]}...")
        print(f"Ciphertext 2 (hex): {cipher2_cbc.hex()[:64]}...")
        print(f"IV1: {iv1.hex()}")
        print(f"IV2: {iv2.hex()}")

        hist_sim_cbc = self.calculate_histogram_similarity(cipher1_cbc, cipher2_cbc)
        xor_sim_cbc = self.calculate_xor_similarity(cipher1_cbc, cipher2_cbc)

        print(f"\n[+] CBC Mode Analysis:")
        print(f"  Histogram Correlation: {hist_sim_cbc:.4f}")
        print(f"  XOR Similarity Ratio: {xor_sim_cbc['similarity_ratio']:.4f}")
        print(f"  Different Bytes: {xor_sim_cbc['different_bytes']}/{xor_sim_cbc['total_bytes']}")
        print(f"   MORE SECURE: Random IVs prevent pattern correlation")

        # Visualize
        self._visualize_key_reuse(cipher1_ecb, cipher2_ecb, cipher1_cbc, cipher2_cbc,
                                   output_dir)

        print("\n" + "=" * 70)
        print("KEY REUSE ANALYSIS SUMMARY:")
        print("-" * 70)
        print("ECB Mode:")
        print("    Same key + same plaintext block = same ciphertext block")
        print("    Attackers can detect repeated patterns across encryptions")
        print("    Vulnerable to pattern analysis attacks")
        print("\nCBC Mode:")
        print("    Different IVs ensure different ciphertexts")
        print("    Much harder to correlate encrypted messages")
        print("    Still not ideal - key rotation is recommended")
        print("\nBEST PRACTICE:")
        print("    Use unique keys for different encryption operations")
        print("    Always use random IVs for CBC, CFB, OFB modes")
        print("    Implement key rotation policies")
        print("    Never reuse IV with the same key in CTR mode")
        print("=" * 70)

    def _visualize_key_reuse(self, cipher1_ecb, cipher2_ecb, cipher1_cbc, cipher2_cbc,
                            output_dir):
        """Create visualization comparing key reuse in different modes."""
        fig, axes = plt.subplots(2, 3, figsize=(15, 10))

        # Convert to numpy for visualization
        c1_ecb = np.frombuffer(cipher1_ecb, dtype=np.uint8)
        c2_ecb = np.frombuffer(cipher2_ecb, dtype=np.uint8)
        c1_cbc = np.frombuffer(cipher1_cbc, dtype=np.uint8)
        c2_cbc = np.frombuffer(cipher2_cbc, dtype=np.uint8)

        # ECB histograms
        axes[0, 0].hist(c1_ecb, bins=50, alpha=0.7, label='Ciphertext 1', color='blue')
        axes[0, 0].hist(c2_ecb, bins=50, alpha=0.7, label='Ciphertext 2', color='red')
        axes[0, 0].set_title('ECB: Ciphertext Histograms\n(Same Key)', fontweight='bold')
        axes[0, 0].set_xlabel('Byte Value')
        axes[0, 0].set_ylabel('Frequency')
        axes[0, 0].legend()
        axes[0, 0].grid(True, alpha=0.3)

        # ECB XOR
        xor_ecb = bytes(a ^ b for a, b in zip(cipher1_ecb, cipher2_ecb))
        xor_ecb_arr = np.frombuffer(xor_ecb, dtype=np.uint8)
        axes[0, 1].plot(xor_ecb_arr[:200], color='purple', linewidth=1)
        axes[0, 1].set_title('ECB: XOR of Ciphertexts\n Shows Correlation', fontweight='bold', color='red')
        axes[0, 1].set_xlabel('Byte Position')
        axes[0, 1].set_ylabel('XOR Value')
        axes[0, 1].grid(True, alpha=0.3)

        # ECB scatter
        axes[0, 2].scatter(c1_ecb, c2_ecb, alpha=0.3, s=1)
        axes[0, 2].set_title('ECB: Byte-by-Byte Comparison', fontweight='bold')
        axes[0, 2].set_xlabel('Ciphertext 1 Byte Value')
        axes[0, 2].set_ylabel('Ciphertext 2 Byte Value')
        axes[0, 2].grid(True, alpha=0.3)

        # CBC histograms
        axes[1, 0].hist(c1_cbc, bins=50, alpha=0.7, label='Ciphertext 1', color='blue')
        axes[1, 0].hist(c2_cbc, bins=50, alpha=0.7, label='Ciphertext 2', color='red')
        axes[1, 0].set_title('CBC: Ciphertext Histograms\n(Same Key, Different IVs)', fontweight='bold')
        axes[1, 0].set_xlabel('Byte Value')
        axes[1, 0].set_ylabel('Frequency')
        axes[1, 0].legend()
        axes[1, 0].grid(True, alpha=0.3)

        # CBC XOR
        xor_cbc = bytes(a ^ b for a, b in zip(cipher1_cbc, cipher2_cbc))
        xor_cbc_arr = np.frombuffer(xor_cbc, dtype=np.uint8)
        axes[1, 1].plot(xor_cbc_arr[:200], color='green', linewidth=1)
        axes[1, 1].set_title('CBC: XOR of Ciphertexts\n Random Pattern', fontweight='bold', color='green')
        axes[1, 1].set_xlabel('Byte Position')
        axes[1, 1].set_ylabel('XOR Value')
        axes[1, 1].grid(True, alpha=0.3)

        # CBC scatter
        axes[1, 2].scatter(c1_cbc, c2_cbc, alpha=0.3, s=1)
        axes[1, 2].set_title('CBC: Byte-by-Byte Comparison', fontweight='bold')
        axes[1, 2].set_xlabel('Ciphertext 1 Byte Value')
        axes[1, 2].set_ylabel('Ciphertext 2 Byte Value')
        axes[1, 2].grid(True, alpha=0.3)

        plt.tight_layout()
        output_file = os.path.join(output_dir, 'key_reuse_analysis.png')
        plt.savefig(output_file, dpi=300, bbox_inches='tight')
        print(f"\n[+] Key reuse analysis chart saved: {output_file}")
        plt.close()

    def attack_ecb_image(self, image_path, key, output_dir='output'):
        """
        Demonstrate ECB pattern attack on encrypted images.

        Args:
            image_path (str): Path to image file
            key (bytes): Encryption key
            output_dir (str): Directory to save results
        """
        print("\n" + "=" * 70)
        print("SIMULATING ECB PATTERN ATTACK")
        print("=" * 70)

        os.makedirs(output_dir, exist_ok=True)

        print("\n[*] Scenario: Attacker intercepts encrypted image")
        print("[*] Goal: Recover information without knowing the key")

        # Encrypt with ECB
        ciphertext, _, shape, mode = self.img_crypto.encrypt_image(
            image_path, key, 'ECB'
        )

        print(f"\n[+] Image encrypted with ECB mode")
        print(f"[+] Image shape: {shape}")
        print(f"[+] Ciphertext size: {len(ciphertext)} bytes")

        # Visualize what attacker sees
        encrypted_display = self.img_crypto.visualize_encrypted_image(ciphertext, shape)

        fig, axes = plt.subplots(1, 2, figsize=(12, 5))

        # Show ciphertext
        axes[0].imshow(encrypted_display)
        axes[0].set_title('Intercepted Ciphertext\n(What Attacker Sees)', fontweight='bold', fontsize=12)
        axes[0].axis('off')

        # Apply simple edge detection to reveal structure
        # Convert to grayscale
        if len(encrypted_display.shape) == 3:
            gray = encrypted_display.mean(axis=2)
        else:
            gray = encrypted_display

        # Simple Sobel-like edge detection using numpy
        kernel_x = np.array([[-1, 0, 1], [-2, 0, 2], [-1, 0, 1]])
        kernel_y = np.array([[-1, -2, -1], [0, 0, 0], [1, 2, 1]])

        # Pad the array
        padded = np.pad(gray, 1, mode='edge')

        # Compute gradients
        height, width = gray.shape
        edges = np.zeros_like(gray)

        for i in range(height):
            for j in range(width):
                patch = padded[i:i+3, j:j+3]
                gx = np.sum(patch * kernel_x)
                gy = np.sum(patch * kernel_y)
                edges[i, j] = np.sqrt(gx**2 + gy**2)

        axes[1].imshow(edges, cmap='gray')
        axes[1].set_title('Pattern Analysis\n Structure Revealed!', fontweight='bold', fontsize=12, color='red')
        axes[1].axis('off')

        plt.tight_layout()
        attack_file = os.path.join(output_dir, 'ecb_pattern_attack.png')
        plt.savefig(attack_file, dpi=300, bbox_inches='tight')
        print(f"\n[+] Attack visualization saved: {attack_file}")
        plt.close()

        print("\n" + "=" * 70)
        print("ATTACK RESULTS:")
        print("-" * 70)
        print("  Successfully extracted structural information")
        print("  Image outline and patterns visible without decryption")
        print("  Attacker can identify objects, text, or sensitive content")
        print("\n  CRITICAL VULNERABILITY:")
        print("    ECB mode does NOT provide confidentiality for structured data!")
        print("=" * 70)


def main():
    """Run comprehensive cryptographic analysis demonstrations."""
    print("=" * 70)
    print("CRYPTOGRAPHIC ANALYSIS & ATTACK DEMONSTRATIONS")
    print("=" * 70)

    analyzer = CryptoAnalyzer('AES')

    # Demonstrate key reuse vulnerability
    analyzer.demonstrate_key_reuse_vulnerability()

    # Attack ECB encrypted image
    if os.path.exists('Tux.png'):
        key = analyzer.crypto.generate_key(passphrase="AttackDemo2024")
        analyzer.attack_ecb_image('Tux.png', key)
    else:
        print("\n[!] Tux.png not found - skipping image attack demo")

    print("\n[+] All analysis demonstrations completed!")
    print("[+] Check the 'output' directory for visualizations")


if __name__ == "__main__":
    main()
