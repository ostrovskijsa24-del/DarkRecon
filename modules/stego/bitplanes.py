"""
Извлечение битовых плоскостей изображения.
"""

from pathlib import Path

import numpy as np

from modules.stego.utils import ImageUtils


class BitPlaneAnalyzer:

    CHANNELS = ("B", "G", "R", "A")

    def __init__(self, file_path):

        self.file_path = file_path

        self.image = ImageUtils.load_image(file_path)

        self.channels = ImageUtils.get_channels(self.image)

    def extract_channel(self, channel: np.ndarray):

        planes = []

        for bit in range(8):

            plane = (channel >> bit) & 1

            planes.append(plane)

        return planes

    def save_planes(self,
                    channel_name,
                    planes,
                    output_dir="output/bitplanes"):

        output = Path(output_dir) / channel_name

        output.mkdir(parents=True, exist_ok=True)

        for bit, plane in enumerate(planes):

            ImageUtils.save_image(
                output / f"bit{bit}.png",
                ImageUtils.normalize_binary(plane)
            )

    def extract_all(self):

        for name, channel in zip(self.CHANNELS, self.channels):

            planes = self.extract_channel(channel)

            self.save_planes(name, planes)

        print("Анализ завершён.")