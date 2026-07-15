"""
bitplanes.py

Извлечение битовых плоскостей изображения.
"""
from pathlib import Path
import os

import numpy as np

from .utils import ImageUtils


class BitPlaneAnalyzer:
    """
    Анализатор битовых плоскостей изображения.
    """

    CHANNEL_NAMES = ["B", "G", "R", "A"]

    def __init__(self, image_path: str):

        self.image_path = image_path

        self.image = ImageUtils.load_image(image_path)

        self.channels = ImageUtils.get_channels(self.image)

    def extract_planes(self, channel: np.ndarray):
        """
        Извлекает 8 битовых плоскостей одного канала.
        """

        planes = []

        for bit in range(8):
            plane = (channel >> bit) & 1
            planes.append(plane)

        return planes

    def save_planes(self, channel_name: str, planes):
        """
        Сохраняет битовые плоскости в папку output.
        """

        # Папка, где находится bitplanes.py
        base_dir = Path(__file__).parent

        output_folder = (
                base_dir /
                "output" /
                "bitplanes" /
                channel_name
        )

        output_folder.mkdir(parents=True, exist_ok=True)

        for bit, plane in enumerate(planes):
            filename = output_folder / f"bit{bit}.png"

            ImageUtils.save_image(
                filename,
                ImageUtils.normalize_binary(plane)
            )

            print(f"Сохранено: {filename}")

    def extract_all(self):
        """
        Извлекает все битовые плоскости всех каналов.
        """

        for channel_name, channel in zip(self.CHANNEL_NAMES, self.channels):

            planes = self.extract_planes(channel)

            self.save_planes(channel_name, planes)

        print("Битовые плоскости успешно сохранены.")