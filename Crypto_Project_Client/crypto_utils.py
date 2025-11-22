"""
Cryptography utilities for the secure messaging system.
Uses Diffie-Hellman for key exchange, AES-GCM for encryption, and Caesar cipher for decoy.
"""

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256
import base64
import json


class CryptoUtils:
    """Cryptography utility class with Diffie-Hellman, AES-GCM, and Caesar cipher."""

    # Standard 2048-bit MODP Group (RFC 3526)
    DH_PRIME = int(
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
        "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
        "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
        "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
        "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
        "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
        "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
        "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
        "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
        "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16
    )
    DH_GENERATOR = 2

    @staticmethod
    def generate_dh_keypair():
        """
        Generate Diffie-Hellman private and public keys.

        Returns:
            tuple: (private_key, public_key) as integers
        """
        private_key = int.from_bytes(get_random_bytes(32), byteorder='big')
        public_key = pow(CryptoUtils.DH_GENERATOR, private_key, CryptoUtils.DH_PRIME)
        return private_key, public_key

    @staticmethod
    def compute_dh_shared_secret(private_key, other_public_key):
        """
        Compute shared secret using Diffie-Hellman.

        Args:
            private_key (int): Your private key
            other_public_key (int): Other party's public key

        Returns:
            bytes: 32-byte shared secret (derived using HKDF)
        """
        shared_secret = pow(other_public_key, private_key, CryptoUtils.DH_PRIME)
        shared_bytes = shared_secret.to_bytes(256, byteorder='big')

        # Derive a proper AES key using HKDF
        aes_key = HKDF(shared_bytes, 32, b'', SHA256)
        return aes_key

    @staticmethod
    def aes_gcm_encrypt(key, plaintext):
        """
        Encrypt data using AES-GCM.

        Args:
            key (bytes): AES key (32 bytes for AES-256)
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
                base = ord('A') if char.isupper() else ord('a')
                shifted = (ord(char) - base + shift) % 26 + base
                result.append(chr(shifted))
            else:
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
        return CryptoUtils.caesar_cipher_encrypt(ciphertext, -shift)
