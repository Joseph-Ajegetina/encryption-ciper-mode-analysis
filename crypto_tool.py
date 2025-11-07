#!/usr/bin/env python3
"""
Symmetric Key Encryption Tool

This tool demonstrates AES and DES encryption with multiple cipher modes
and highlights security vulnerabilities in ECB mode and key reuse.
"""

from Crypto.Cipher import AES, DES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import hashlib
import os


class CryptoTool:
    """Main encryption/decryption engine supporting AES and DES with multiple modes."""

    # Supported algorithms and their block sizes
    ALGORITHMS = {
        'AES': {'cipher': AES, 'key_size': 16, 'block_size': 16},  # AES-128
        'DES': {'cipher': DES, 'key_size': 8, 'block_size': 8}
    }

    # Cipher modes that require IV
    IV_MODES = [AES.MODE_CBC, AES.MODE_CFB, AES.MODE_OFB, AES.MODE_CTR]

    def __init__(self, algorithm='AES'):
        """
        Initialize the crypto tool with specified algorithm.

        Args:
            algorithm (str): Either 'AES' or 'DES'
        """
        if algorithm not in self.ALGORITHMS:
            raise ValueError(f"Algorithm must be one of {list(self.ALGORITHMS.keys())}")

        self.algorithm = algorithm
        self.algo_config = self.ALGORITHMS[algorithm]
        self.cipher_class = self.algo_config['cipher']
        self.key_size = self.algo_config['key_size']
        self.block_size = self.algo_config['block_size']

    def generate_key(self, passphrase=None):
        """
        Generate or derive a key for encryption.

        Args:
            passphrase (str): Optional passphrase to derive key from

        Returns:
            bytes: Encryption key
        """
        if passphrase:
            # Derive key from passphrase using SHA-256
            return hashlib.sha256(passphrase.encode()).digest()[:self.key_size]
        else:
            # Generate random key
            return get_random_bytes(self.key_size)

    def generate_iv(self):
        """
        Generate a random initialization vector.

        Returns:
            bytes: Random IV
        """
        return get_random_bytes(self.block_size)

    def encrypt(self, plaintext, key, mode='CBC', iv=None):
        """
        Encrypt data using specified mode.

        Args:
            plaintext (bytes): Data to encrypt
            key (bytes): Encryption key
            mode (str): Cipher mode ('ECB', 'CBC', 'CFB', 'OFB', 'CTR')
            iv (bytes): Initialization vector (required for non-ECB modes)

        Returns:
            tuple: (ciphertext, iv) where iv is None for ECB mode
        """
        # Map mode string to Crypto constant
        mode_map = {
            'ECB': self.cipher_class.MODE_ECB,
            'CBC': self.cipher_class.MODE_CBC,
            'CFB': self.cipher_class.MODE_CFB,
            'OFB': self.cipher_class.MODE_OFB,
            'CTR': self.cipher_class.MODE_CTR
        }

        if mode not in mode_map:
            raise ValueError(f"Mode must be one of {list(mode_map.keys())}")

        cipher_mode = mode_map[mode]

        # Prepare plaintext with padding for ECB and CBC modes
        if mode in ['ECB', 'CBC']:
            plaintext = pad(plaintext, self.block_size)

        # Create cipher object
        if cipher_mode == self.cipher_class.MODE_ECB:
            cipher = self.cipher_class.new(key, cipher_mode)
            ciphertext = cipher.encrypt(plaintext)
            return ciphertext, None

        elif cipher_mode == self.cipher_class.MODE_CTR:
            # CTR mode uses a counter, not IV
            if iv is None:
                iv = get_random_bytes(self.block_size // 2)
            from Crypto.Util import Counter
            ctr = Counter.new(self.block_size * 4, prefix=iv)
            cipher = self.cipher_class.new(key, cipher_mode, counter=ctr)
            ciphertext = cipher.encrypt(plaintext)
            return ciphertext, iv

        else:  # CBC, CFB, OFB
            if iv is None:
                iv = self.generate_iv()
            cipher = self.cipher_class.new(key, cipher_mode, iv=iv)
            ciphertext = cipher.encrypt(plaintext)
            return ciphertext, iv

    def decrypt(self, ciphertext, key, mode='CBC', iv=None):
        """
        Decrypt data using specified mode.

        Args:
            ciphertext (bytes): Data to decrypt
            key (bytes): Decryption key
            mode (str): Cipher mode ('ECB', 'CBC', 'CFB', 'OFB', 'CTR')
            iv (bytes): Initialization vector (required for non-ECB modes)

        Returns:
            bytes: Decrypted plaintext
        """
        mode_map = {
            'ECB': self.cipher_class.MODE_ECB,
            'CBC': self.cipher_class.MODE_CBC,
            'CFB': self.cipher_class.MODE_CFB,
            'OFB': self.cipher_class.MODE_OFB,
            'CTR': self.cipher_class.MODE_CTR
        }

        cipher_mode = mode_map[mode]

        # Create cipher object
        if cipher_mode == self.cipher_class.MODE_ECB:
            cipher = self.cipher_class.new(key, cipher_mode)
            plaintext = cipher.decrypt(ciphertext)
            return unpad(plaintext, self.block_size)

        elif cipher_mode == self.cipher_class.MODE_CTR:
            from Crypto.Util import Counter
            ctr = Counter.new(self.block_size * 4, prefix=iv)
            cipher = self.cipher_class.new(key, cipher_mode, counter=ctr)
            plaintext = cipher.decrypt(ciphertext)
            return plaintext

        else:  # CBC, CFB, OFB
            cipher = self.cipher_class.new(key, cipher_mode, iv=iv)
            plaintext = cipher.decrypt(ciphertext)
            # Unpad only for CBC mode
            if mode == 'CBC':
                plaintext = unpad(plaintext, self.block_size)
            return plaintext

    def encrypt_file(self, input_file, output_file, key, mode='CBC', iv=None):
        """
        Encrypt a file and save the result.

        Args:
            input_file (str): Path to file to encrypt
            output_file (str): Path to save encrypted file
            key (bytes): Encryption key
            mode (str): Cipher mode
            iv (bytes): Initialization vector

        Returns:
            bytes: IV used (or None for ECB)
        """
        with open(input_file, 'rb') as f:
            plaintext = f.read()

        ciphertext, used_iv = self.encrypt(plaintext, key, mode, iv)

        with open(output_file, 'wb') as f:
            f.write(ciphertext)

        return used_iv

    def decrypt_file(self, input_file, output_file, key, mode='CBC', iv=None):
        """
        Decrypt a file and save the result.

        Args:
            input_file (str): Path to encrypted file
            output_file (str): Path to save decrypted file
            key (bytes): Decryption key
            mode (str): Cipher mode
            iv (bytes): Initialization vector
        """
        with open(input_file, 'rb') as f:
            ciphertext = f.read()

        plaintext = self.decrypt(ciphertext, key, mode, iv)

        with open(output_file, 'wb') as f:
            f.write(plaintext)


def main():
    """Example usage of the CryptoTool."""
    print("=" * 60)
    print("Symmetric Key Encryption Tool - Demo")
    print("=" * 60)

    # Initialize tool with AES
    tool = CryptoTool('AES')

    # Generate a key
    key = tool.generate_key(passphrase="SecurePassword123")
    print(f"\n[+] Generated key from passphrase (hex): {key.hex()}")

    # Test with text
    plaintext = b"This is a secret message for testing encryption!"
    print(f"\n[+] Original plaintext: {plaintext.decode()}")

    # Test different modes
    modes = ['ECB', 'CBC', 'CTR']
    print(f"\n{'='*60}")
    print("Testing different cipher modes:")
    print(f"{'='*60}")

    for mode in modes:
        print(f"\n--- Testing {mode} mode ---")
        ciphertext, iv = tool.encrypt(plaintext, key, mode)
        print(f"Ciphertext (hex): {ciphertext.hex()[:64]}...")
        if iv:
            print(f"IV (hex): {iv.hex()}")

        # Decrypt
        decrypted = tool.decrypt(ciphertext, key, mode, iv)
        print(f"Decrypted: {decrypted.decode()}")
        print(f" Decryption successful: {decrypted == plaintext}")


if __name__ == "__main__":
    main()
