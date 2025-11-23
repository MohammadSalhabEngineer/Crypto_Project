"""
Steganography utilities for hiding encrypted messages in images.
Uses LSB (Least Significant Bit) technique to embed data in image pixels.
"""

from PIL import Image
import numpy as np
import json


class StegoUtils:
    """Steganography utility class for LSB image steganography."""

    @staticmethod
    def text_to_bits(text):
        """
        Convert text to binary string.

        Args:
            text (str): Text to convert

        Returns:
            str: Binary representation of the text
        """
        if isinstance(text, str):
            text = text.encode('utf-8')
        bits = ''.join(format(byte, '08b') for byte in text)
        return bits

    @staticmethod
    def bits_to_text(bits):
        """
        Convert binary string to text.

        Args:
            bits (str): Binary string

        Returns:
            str: Decoded text
        """
        # Ensure bits length is multiple of 8
        bits = bits[:len(bits) - (len(bits) % 8)]

        bytes_list = []
        for i in range(0, len(bits), 8):
            byte = bits[i:i+8]
            bytes_list.append(int(byte, 2))

        try:
            return bytes(bytes_list).decode('utf-8')
        except UnicodeDecodeError:
            return None

    @staticmethod
    def encode_message_in_image(image_path, message_data, output_path):
        """
        Hide a message in an image using LSB steganography.

        Args:
            image_path (str): Path to the cover image
            message_data (dict or str): Message data to hide (will be JSON-encoded)
            output_path (str): Path to save the stego image

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Load the image
            img = Image.open(image_path)
            img_array = np.array(img)

            # Convert message to JSON and then to binary
            if isinstance(message_data, dict):
                message = json.dumps(message_data)
            else:
                message = str(message_data)

            # Add delimiter to mark end of message
            message = message + "<<<END>>>"
            message_bits = StegoUtils.text_to_bits(message)

            # Check if image can hold the message
            total_pixels = img_array.shape[0] * img_array.shape[1]
            available_bits = total_pixels * 3  # RGB channels

            if len(message_bits) > available_bits:
                print(f"Error: Message too large for image. Need {len(message_bits)} bits, have {available_bits} bits")
                return False

            # Flatten the image array for easier bit manipulation
            flat_img = img_array.flatten()

            # Embed message bits into LSB of pixel values
            for i, bit in enumerate(message_bits):
                # Clear the LSB and set it to the message bit
                flat_img[i] = (flat_img[i] & 0xFE) | int(bit)

            # Reshape back to original dimensions
            stego_img_array = flat_img.reshape(img_array.shape)

            # Save the stego image
            stego_img = Image.fromarray(stego_img_array.astype('uint8'))
            stego_img.save(output_path)

            print(f"Message successfully hidden in image: {output_path}")
            print(f"Message size: {len(message_bits)} bits")
            return True

        except Exception as e:
            print(f"Error encoding message: {e}")
            return False

    @staticmethod
    def decode_message_from_image(image_path):
        """
        Extract hidden message from a stego image.

        Args:
            image_path (str): Path to the stego image

        Returns:
            dict or str or None: Extracted message data, or None if extraction fails
        """
        try:
            # Load the image
            img = Image.open(image_path)
            img_array = np.array(img)

            # Flatten the image array
            flat_img = img_array.flatten()

            # Extract LSBs
            extracted_bits = ''
            delimiter = StegoUtils.text_to_bits("<<<END>>>")

            for pixel_value in flat_img:
                extracted_bits += str(pixel_value & 1)

                # Check if we've found the delimiter
                if len(extracted_bits) >= len(delimiter):
                    # Try to decode and check for delimiter
                    if len(extracted_bits) % 8 == 0:
                        test_text = StegoUtils.bits_to_text(extracted_bits)
                        if test_text and "<<<END>>>" in test_text:
                            # Found the delimiter, extract the message
                            message = test_text.split("<<<END>>>")[0]

                            # Try to parse as JSON
                            try:
                                return json.loads(message)
                            except json.JSONDecodeError:
                                return message

            print("Error: Could not find message delimiter in image")
            return None

        except Exception as e:
            print(f"Error decoding message: {e}")
            return None

    @staticmethod
    def get_image_capacity(image_path):
        """
        Calculate how many bits can be stored in an image.

        Args:
            image_path (str): Path to the image

        Returns:
            int: Number of bits that can be stored
        """
        try:
            img = Image.open(image_path)
            img_array = np.array(img)
            total_pixels = img_array.shape[0] * img_array.shape[1]
            # Each pixel has 3 color channels (RGB), each can store 1 bit
            return total_pixels * 3
        except Exception as e:
            print(f"Error calculating capacity: {e}")
            return 0
