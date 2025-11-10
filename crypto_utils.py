"""
Cryptography utilities for the secure messaging system.
Includes RSA, AES-GCM, Caesar cipher, and hybrid encryption.
"""

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
import base64
import json


class CryptoUtils:
    """Cryptography utility class with RSA, AES-GCM, and Caesar cipher support."""

    @staticmethod
    def generate_rsa_keypair(key_size=2048):
        """
        Generate an RSA public/private key pair.

        Args:
            key_size (int): Size of the RSA key in bits (default: 2048)

        Returns:
            tuple: (private_key, public_key) as RSA key objects
        """
        key = RSA.generate(key_size)
        private_key = key
        public_key = key.publickey()
        return private_key, public_key

    @staticmethod
    def export_public_key(public_key):
        """
        Export RSA public key to PEM format string.

        Args:
            public_key: RSA public key object

        Returns:
            str: PEM-formatted public key
        """
        return public_key.export_key().decode('utf-8')

    @staticmethod
    def import_public_key(pem_string):
        """
        Import RSA public key from PEM format string.

        Args:
            pem_string (str): PEM-formatted public key

        Returns:
            RSA public key object
        """
        return RSA.import_key(pem_string.encode('utf-8'))

    @staticmethod
    def rsa_encrypt(public_key, data):
        """
        Encrypt data using RSA-OAEP.

        Args:
            public_key: RSA public key object
            data (bytes): Data to encrypt

        Returns:
            bytes: Encrypted data
        """
        cipher_rsa = PKCS1_OAEP.new(public_key)
        return cipher_rsa.encrypt(data)

    @staticmethod
    def rsa_decrypt(private_key, encrypted_data):
        """
        Decrypt data using RSA-OAEP.

        Args:
            private_key: RSA private key object
            encrypted_data (bytes): Data to decrypt

        Returns:
            bytes: Decrypted data
        """
        cipher_rsa = PKCS1_OAEP.new(private_key)
        return cipher_rsa.decrypt(encrypted_data)

    @staticmethod
    def generate_aes_key(key_size=32):
        """
        Generate a random AES key.

        Args:
            key_size (int): Size of the key in bytes (16, 24, or 32 for AES-128/192/256)

        Returns:
            bytes: Random AES key
        """
        return get_random_bytes(key_size)

    @staticmethod
    def aes_gcm_encrypt(key, plaintext):
        """
        Encrypt data using AES-GCM.

        Args:
            key (bytes): AES key (16, 24, or 32 bytes)
            plaintext (bytes or str): Data to encrypt

        Returns:
            dict: Dictionary containing 'nonce', 'ciphertext', and 'tag' as base64 strings
        """
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')

        cipher = AES.new(key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)

        return {
            'nonce': base64.b64encode(cipher.nonce).decode('utf-8'),
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
            'tag': base64.b64encode(tag).decode('utf-8')
        }

    @staticmethod
    def aes_gcm_decrypt(key, encrypted_data):
        """
        Decrypt data using AES-GCM.

        Args:
            key (bytes): AES key
            encrypted_data (dict): Dictionary with 'nonce', 'ciphertext', and 'tag'

        Returns:
            bytes: Decrypted data
        """
        nonce = base64.b64decode(encrypted_data['nonce'])
        ciphertext = base64.b64decode(encrypted_data['ciphertext'])
        tag = base64.b64decode(encrypted_data['tag'])

        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)

        return plaintext

    @staticmethod
    def caesar_cipher_encrypt(plaintext, shift=3):
        """
        Encrypt text using Caesar cipher (decoy encryption).

        Args:
            plaintext (str): Text to encrypt
            shift (int): Number of positions to shift (default: 3)

        Returns:
            str: Caesar cipher encrypted text
        """
        result = []
        for char in plaintext:
            if char.isalpha():
                # Determine if uppercase or lowercase
                base = ord('A') if char.isupper() else ord('a')
                # Shift character and wrap around
                shifted = (ord(char) - base + shift) % 26 + base
                result.append(chr(shifted))
            else:
                # Keep non-alphabetic characters as-is
                result.append(char)
        return ''.join(result)

    @staticmethod
    def caesar_cipher_decrypt(ciphertext, shift=3):
        """
        Decrypt text using Caesar cipher.

        Args:
            ciphertext (str): Text to decrypt
            shift (int): Number of positions to shift (default: 3)

        Returns:
            str: Decrypted text
        """
        # Decryption is just encryption with negative shift
        return CryptoUtils.caesar_cipher_encrypt(ciphertext, -shift)

    @staticmethod
    def hybrid_encrypt(recipient_public_key, plaintext, decoy_message=None):
        """
        Hybrid encryption: Generate AES key, encrypt plaintext with AES-GCM,
        encrypt AES key with RSA, and create Caesar cipher decoy.

        Args:
            recipient_public_key: RSA public key of the recipient
            plaintext (str): Message to encrypt
            decoy_message (str, optional): Decoy message for Caesar cipher

        Returns:
            dict: Contains 'encrypted_aes_key' (base64), 'encrypted_message' (dict),
                  and 'caesar_decoy' (str)
        """
        # Generate random AES key
        aes_key = CryptoUtils.generate_aes_key()

        # Encrypt the plaintext with AES-GCM
        encrypted_message = CryptoUtils.aes_gcm_encrypt(aes_key, plaintext)

        # Encrypt the AES key with RSA
        encrypted_aes_key = CryptoUtils.rsa_encrypt(recipient_public_key, aes_key)

        # Create Caesar cipher decoy
        if decoy_message is None:
            decoy_message = "This is a harmless message"
        caesar_decoy = CryptoUtils.caesar_cipher_encrypt(decoy_message)

        return {
            'encrypted_aes_key': base64.b64encode(encrypted_aes_key).decode('utf-8'),
            'encrypted_message': encrypted_message,
            'caesar_decoy': caesar_decoy
        }

    @staticmethod
    def hybrid_decrypt(private_key, encrypted_data):
        """
        Hybrid decryption: Decrypt AES key with RSA, then decrypt message with AES-GCM.

        Args:
            private_key: RSA private key
            encrypted_data (dict): Dictionary with 'encrypted_aes_key' and 'encrypted_message'

        Returns:
            str: Decrypted plaintext message
        """
        # Decrypt the AES key using RSA
        encrypted_aes_key = base64.b64decode(encrypted_data['encrypted_aes_key'])
        aes_key = CryptoUtils.rsa_decrypt(private_key, encrypted_aes_key)

        # Decrypt the message using AES-GCM
        plaintext = CryptoUtils.aes_gcm_decrypt(aes_key, encrypted_data['encrypted_message'])

        return plaintext.decode('utf-8')


def demo():
    """Demonstration of the crypto utilities."""
    print("=== Cryptography Utilities Demo ===\n")

    # 1. RSA Key Generation
    print("1. Generating RSA key pairs for Alice and Bob...")
    alice_private, alice_public = CryptoUtils.generate_rsa_keypair()
    bob_private, bob_public = CryptoUtils.generate_rsa_keypair()
    print("   Keys generated!\n")

    # 2. Caesar Cipher (Decoy)
    print("2. Caesar Cipher (Decoy):")
    decoy = "Hello World"
    encrypted_decoy = CryptoUtils.caesar_cipher_encrypt(decoy)
    print(f"   Original: {decoy}")
    print(f"   Encrypted: {encrypted_decoy}")
    print(f"   Decrypted: {CryptoUtils.caesar_cipher_decrypt(encrypted_decoy)}\n")

    # 3. Hybrid Encryption
    print("3. Hybrid Encryption (Alice -> Bob):")
    secret_message = "This is the real secret message!"
    decoy_message = "Just a simple greeting"

    encrypted_package = CryptoUtils.hybrid_encrypt(
        bob_public,
        secret_message,
        decoy_message
    )

    print(f"   Secret message: {secret_message}")
    print(f"   Decoy message: {decoy_message}")
    print(f"   Caesar decoy: {encrypted_package['caesar_decoy']}")
    print(f"   Encrypted AES key (base64): {encrypted_package['encrypted_aes_key'][:50]}...")

    # 4. Hybrid Decryption
    print("\n4. Hybrid Decryption (Bob receives):")
    decrypted_message = CryptoUtils.hybrid_decrypt(bob_private, encrypted_package)
    print(f"   Decrypted message: {decrypted_message}")
    print(f"   Match: {decrypted_message == secret_message}\n")


if __name__ == "__main__":
    demo()
