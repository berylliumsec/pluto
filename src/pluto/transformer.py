import logging
from typing import List

import cv2
import numpy as np


class ByteImageTransformer:
    transform_matrix = np.array([[1, 1], [0, 1]])
    inverse_matrix = np.linalg.inv(transform_matrix)
    key = 100

    def __init__(self, width: int = 1280, height: int = 720):
        self.width = width
        self.height = height

    def bytes_to_image(self, byte_data: bytes, file_path: str) -> tuple:
        data_length = len(byte_data)
        dimension = int(np.ceil(np.sqrt(data_length)))
        total_pixels = dimension * dimension
        image_data = np.frombuffer(byte_data, dtype=np.uint8)

        if total_pixels > data_length:
            padded_length = total_pixels - data_length
            image_data = np.pad(
                image_data, (0, padded_length), mode="constant", constant_values=0
            )

        image = image_data.reshape((dimension, dimension))
        cv2.imwrite(file_path, image)
        return image, data_length

    def image_to_bytes(self, image: np.ndarray, original_length: int) -> bytes:
        return image.flatten()[:original_length].tobytes()

    def embed_into_image(
        self, host_image: np.ndarray, secret_image: np.ndarray, channel: int = 0
    ) -> np.ndarray:
        host_image_copy = host_image.copy()
        for i in range(secret_image.shape[0]):
            for j in range(secret_image.shape[1]):
                host_image_copy[i, j, channel] = secret_image[i, j]
        return host_image_copy

    def extract_from_image(
        self, stego_image: np.ndarray, width: int, height: int, channel: int = 0
    ) -> np.ndarray:
        extracted_data = np.zeros((height, width), dtype=np.uint8)
        for i in range(height):
            for j in range(width):
                extracted_data[i, j] = stego_image[i, j, channel]
        return extracted_data

    @staticmethod
    def read_hex_from_file(file_path: str) -> List[str]:
        """
        Read lines from a file, each potentially containing hex values in various formats.
        """
        try:
            with open(file_path, "r") as file:
                return [line.strip() for line in file.readlines()]
        except FileNotFoundError as e:
            logging.error("File not found.")
            raise e

    @staticmethod
    def parse_hex_values(hex_string: str) -> List[int]:
        """
        Parse a string of hexadecimal values into a list of integers.
        """
        hex_values = hex_string.replace("\\x", "0x").split(",")
        return [int(val, 16) for val in hex_values if val]

    def transform_decimal(self, values: np.ndarray) -> np.ndarray:
        """
        Apply a linear transformation to a pair of decimal values using a predefined matrix.
        """
        return np.dot(self.transform_matrix, values).astype(int)

    def transform_hex_values(self, hex_values: List[int]) -> bytes:
        """
        Transform a list of hex values into a bytes object after applying a linear transformation.
        """
        transformed_results = []
        is_odd = len(hex_values) % 2 != 0

        for i in range(0, len(hex_values) - is_odd, 2):
            pair = np.array(hex_values[i : i + 2])
            transformed_pair = self.transform_decimal(pair)
            transformed_results.extend(transformed_pair)

        if is_odd:
            last_element = hex_values[-1]
            transformed_last_element = self.transform_last_element(last_element)
            transformed_results.append(transformed_last_element)

        return bytes([val % 256 for val in transformed_results])

    def reverse_transform_hex_values(self, transformed_bytes: bytes) -> List[str]:
        transformed_values = list(transformed_bytes)
        reversed_results = []
        is_odd = len(transformed_values) % 2 != 0

        for i in range(0, len(transformed_values) - is_odd, 2):
            pair = np.array(transformed_values[i : i + 2])
            reversed_pair = self.reverse_transform_decimal(pair)
            reversed_results.extend(
                [hex(val % 256) for val in reversed_pair]
            )  # Apply modulo after reversing

        if is_odd:
            last_element = transformed_values[-1]
            reversed_last_element = self.reverse_transform_last_element(last_element)
            reversed_results.append(
                hex(reversed_last_element % 256)
            )  # Ensure last element is also within range

        return reversed_results

    def reverse_transform_last_element(self, value: int) -> int:
        return value ^ self.key

    def reverse_transform_decimal(self, values: np.ndarray) -> np.ndarray:
        reversed_values = np.dot(self.inverse_matrix, values)
        # Here too, ensure values conform to expectations without modulo
        return reversed_values.astype(int)

    def transform_last_element(self, value: int) -> int:
        """
        Transform the last element if the list of values has an odd length.
        """
        return value ^ self.key
