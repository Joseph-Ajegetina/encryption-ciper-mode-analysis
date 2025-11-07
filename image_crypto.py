#!/usr/bin/env python3
"""
Image Encryption and Visualization Module
Demonstrates pattern leakage in ECB mode vs other secure modes
"""

from PIL import Image
import numpy as np
import matplotlib.pyplot as plt
from crypto_tool import CryptoTool
import os


class ImageCrypto:
    """Handle image encryption and visualize ciphertext patterns."""

    def __init__(self, algorithm='AES'):
        """Initialize with specified encryption algorithm."""
        self.crypto = CryptoTool(algorithm)
        self.algorithm = algorithm

    def encrypt_image(self, image_path, key, mode='ECB', iv=None):
        """
        Encrypt an image file and return encrypted byte data with metadata.

        Args:
            image_path (str): Path to image file
            key (bytes): Encryption key
            mode (str): Cipher mode
            iv (bytes): Initialization vector

        Returns:
            tuple: (encrypted_data, iv, image_shape, image_mode)
        """
        # Load image
        img = Image.open(image_path)
        img_array = np.array(img)

        # Store metadata
        image_shape = img_array.shape
        image_mode = img.mode

        # Convert to bytes
        img_bytes = img_array.tobytes()

        # Encrypt
        ciphertext, used_iv = self.crypto.encrypt(img_bytes, key, mode, iv)

        return ciphertext, used_iv, image_shape, image_mode

    def decrypt_image(self, ciphertext, key, mode, iv, image_shape, image_mode='RGB'):
        """
        Decrypt image data and reconstruct the image.

        Args:
            ciphertext (bytes): Encrypted image data
            key (bytes): Decryption key
            mode (str): Cipher mode
            iv (bytes): Initialization vector
            image_shape (tuple): Original image dimensions
            image_mode (str): Image mode (e.g., 'RGB', 'RGBA')

        Returns:
            PIL.Image: Decrypted image
        """
        # Decrypt
        plaintext = self.crypto.decrypt(ciphertext, key, mode, iv)

        # Reconstruct image array
        # Handle potential padding by truncating to expected size
        expected_size = np.prod(image_shape)
        plaintext = plaintext[:expected_size]

        img_array = np.frombuffer(plaintext, dtype=np.uint8)
        img_array = img_array.reshape(image_shape)

        # Create image
        img = Image.fromarray(img_array, mode=image_mode)
        return img

    def visualize_encrypted_image(self, ciphertext, image_shape, title="Encrypted Image"):
        """
        Visualize encrypted image data to show patterns.

        Args:
            ciphertext (bytes): Encrypted data
            image_shape (tuple): Original image dimensions
            title (str): Title for the plot

        Returns:
            numpy.ndarray: Array suitable for display
        """
        # Convert ciphertext to numpy array
        expected_size = np.prod(image_shape)

        # Truncate or pad ciphertext to match expected size
        if len(ciphertext) > expected_size:
            cipher_array = np.frombuffer(ciphertext[:expected_size], dtype=np.uint8)
        else:
            # Pad with zeros if needed
            cipher_bytes = ciphertext + b'\x00' * (expected_size - len(ciphertext))
            cipher_array = np.frombuffer(cipher_bytes, dtype=np.uint8)

        # Reshape to image dimensions
        encrypted_img = cipher_array.reshape(image_shape)

        return encrypted_img

    def compare_modes(self, image_path, key, modes=['ECB', 'CBC', 'CTR'], output_dir='output'):
        """
        Encrypt image with different modes and create comparison visualization.

        Args:
            image_path (str): Path to image file
            key (bytes): Encryption key
            modes (list): List of cipher modes to compare
            output_dir (str): Directory to save results
        """
        # Create output directory
        os.makedirs(output_dir, exist_ok=True)

        # Load original image
        original_img = Image.open(image_path)
        img_array = np.array(original_img)

        # Setup plot
        num_images = len(modes) + 1  # +1 for original
        fig, axes = plt.subplots(1, num_images, figsize=(5 * num_images, 5))

        if num_images == 1:
            axes = [axes]

        # Show original
        axes[0].imshow(img_array)
        axes[0].set_title('Original Image', fontsize=12, fontweight='bold')
        axes[0].axis('off')

        # Encrypt and visualize each mode
        for idx, mode in enumerate(modes, 1):
            print(f"[*] Encrypting with {mode} mode...")

            # Encrypt
            ciphertext, iv, shape, img_mode = self.encrypt_image(
                image_path, key, mode, None
            )

            # Visualize encrypted data
            encrypted_display = self.visualize_encrypted_image(ciphertext, shape)

            # Display
            axes[idx].imshow(encrypted_display)
            axes[idx].set_title(f'{mode} Mode Encrypted', fontsize=12, fontweight='bold')
            axes[idx].axis('off')

            # Save encrypted data
            output_file = os.path.join(output_dir, f'encrypted_{mode.lower()}.bin')
            with open(output_file, 'wb') as f:
                f.write(ciphertext)

            # Test decryption
            decrypted_img = self.decrypt_image(ciphertext, key, mode, iv, shape, img_mode)
            decrypted_file = os.path.join(output_dir, f'decrypted_{mode.lower()}.png')
            decrypted_img.save(decrypted_file)
            print(f"  ✓ Encrypted data saved: {output_file}")
            print(f"  ✓ Decrypted image saved: {decrypted_file}")

        plt.tight_layout()
        comparison_file = os.path.join(output_dir, 'mode_comparison.png')
        plt.savefig(comparison_file, dpi=300, bbox_inches='tight')
        print(f"\n[+] Comparison chart saved: {comparison_file}")

        plt.show()

    def demonstrate_ecb_vulnerability(self, image_path, key, output_dir='output'):
        """
        Specifically demonstrate ECB mode pattern leakage vulnerability.

        Args:
            image_path (str): Path to image file
            key (bytes): Encryption key
            output_dir (str): Directory to save results
        """
        print("\n" + "=" * 70)
        print("DEMONSTRATING ECB MODE VULNERABILITY - Pattern Leakage")
        print("=" * 70)

        os.makedirs(output_dir, exist_ok=True)

        # Load image
        original_img = Image.open(image_path)
        img_array = np.array(original_img)

        # Create figure with 3 subplots
        fig, axes = plt.subplots(1, 3, figsize=(15, 5))

        # Original
        axes[0].imshow(img_array)
        axes[0].set_title('Original Image\n(Plaintext)', fontsize=14, fontweight='bold')
        axes[0].axis('off')

        # ECB - INSECURE
        print("\n[!] Encrypting with ECB mode (INSECURE)...")
        ciphertext_ecb, _, shape, mode = self.encrypt_image(image_path, key, 'ECB')
        encrypted_ecb = self.visualize_encrypted_image(ciphertext_ecb, shape)

        axes[1].imshow(encrypted_ecb)
        axes[1].set_title('ECB Mode - INSECURE\n⚠️ Pattern Leakage Visible!',
                         fontsize=14, fontweight='bold', color='red')
        axes[1].axis('off')

        # CBC - SECURE
        print("[+] Encrypting with CBC mode (SECURE)...")
        ciphertext_cbc, _, _, _ = self.encrypt_image(image_path, key, 'CBC')
        encrypted_cbc = self.visualize_encrypted_image(ciphertext_cbc, shape)

        axes[2].imshow(encrypted_cbc)
        axes[2].set_title('CBC Mode - SECURE\n✓ No Pattern Leakage',
                         fontsize=14, fontweight='bold', color='green')
        axes[2].axis('off')

        plt.tight_layout()
        vuln_file = os.path.join(output_dir, 'ecb_vulnerability_demo.png')
        plt.savefig(vuln_file, dpi=300, bbox_inches='tight')
        print(f"\n[+] Vulnerability demonstration saved: {vuln_file}")

        plt.show()

        print("\n" + "=" * 70)
        print("ANALYSIS:")
        print("-" * 70)
        print("ECB Mode (Electronic Codebook):")
        print("  ⚠️  Each block of plaintext encrypts to the same ciphertext")
        print("  ⚠️  Identical plaintext blocks → Identical ciphertext blocks")
        print("  ⚠️  Visual patterns in images are preserved in ciphertext")
        print("  ⚠️  An attacker can see the structure without decrypting!")
        print("\nCBC Mode (Cipher Block Chaining):")
        print("  ✓  Each block is XORed with previous ciphertext before encryption")
        print("  ✓  Uses random IV, so same plaintext → different ciphertext")
        print("  ✓  Patterns are completely hidden")
        print("  ✓  Provides confidentiality for structured data")
        print("=" * 70)


def main():
    """Demonstrate image encryption with different modes."""
    print("=" * 70)
    print("IMAGE ENCRYPTION DEMONSTRATION")
    print("=" * 70)

    # Initialize
    img_crypto = ImageCrypto('AES')

    # Generate key
    key = img_crypto.crypto.generate_key(passphrase="ImageEncryptionDemo2024")
    print(f"\n[+] Using encryption key: {key.hex()}")

    # Check if tux.png exists
    if not os.path.exists('Tux.png'):
        print("\n[!] Error: Tux.png not found in current directory")
        print("[!] Please ensure the image file is available")
        return

    # Demonstrate ECB vulnerability
    img_crypto.demonstrate_ecb_vulnerability('Tux.png', key)

    print("\n" + "=" * 70)
    print("COMPARING ALL CIPHER MODES")
    print("=" * 70)

    # Compare all modes
    img_crypto.compare_modes('Tux.png', key, modes=['ECB', 'CBC', 'CFB', 'OFB', 'CTR'])

    print("\n[+] All visualizations completed!")
    print("[+] Check the 'output' directory for saved images")


if __name__ == "__main__":
    main()
